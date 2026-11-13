//! Host-approved launch profiles, directed-work routes and durable outcomes.
use anyhow::{Context, Result, anyhow, bail};
use atem_client::principal::{Authority, Need, Op};
use atem_client::session::host_work::{
    ContextKind, ContextSnapshot, HostTarget, LaunchState, LaunchStatus, ProfileInfo, WorkState,
    WorkStatus, WorkTask,
};
use atem_client::session::messages::{Delivery, Message, MessageReceipt, RecipientReceipt};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs::OpenOptions;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::adopt::SpawnRequest;
use super::delegated::details::DEADLINE_PASSED_OUTCOME_UNKNOWN;
use super::protocol::LaunchEnv;

pub const CONFIG_FILE: &str = "runtime.toml";
/// The records of each table (`TRACKED`) open at once (`open_records`): a
/// record closed a day after it settled past its deadline
/// (`Store::drop_payloads`) is kept but no longer counts.
pub const MAX_RECORDS: usize = 4096;
/// Unfinished tasks (`UNFINISHED`): those that hold, or wait for, a place in
/// their session's queue. A task awaiting its result or with an unknown
/// outcome is not counted: `MAX_RECORDS` and its expiry bound it.
pub const MAX_QUEUED: usize = 256;
const UNFINISHED: &str =
    "SELECT count(*) FROM work WHERE state IN ('queued','blocked','submitting','submitted')";
/// The detail of a task that was still awaiting its result at its deadline.
pub const EXPIRED_AWAITING: &str = "expired awaiting a result";
/// The detail of a task whose outcome was still unknown at its deadline.
pub const EXPIRED_UNKNOWN: &str = "expired with its outcome unknown";
/// The detail of a task completed with an explicit result: its sender's
/// `work_complete`, or a `done` resolution (`work_resolve`, design I.4.6).
pub const RESULT_PUBLISHED: &str = "explicit correlated result published";
/// A task whose sender's authorization (a service or browser grant) expired
/// since it was accepted: a renewal or a new grant never revives it.
pub const AUTHORIZATION_EXPIRED: &str = "sender's authorization expired";
/// The detail of a task whose record this build can't read
/// (`Store::fail_unreadable`).
pub const RECORD_UNREADABLE: &str = "record unreadable";

#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u8,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub instance: Instance,
    #[serde(default)]
    pub collab: Collab,
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(default)]
    pub routes: Vec<Route>,
}

#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Instance {
    #[serde(default)]
    pub labels: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Collab {
    pub send: bool,
    pub per_hour: u32,
    pub per_workflow: u32,
    pub result_timeout: String,
}

impl Default for Collab {
    fn default() -> Self {
        Self {
            send: false,
            per_hour: 30,
            per_workflow: 8,
            result_timeout: "30m".into(),
        }
    }
}

/// Configuration and CLI durations have the same bounded seconds/minutes/hours syntax.
pub fn duration_ms(text: &str) -> Option<u64> {
    let (number, unit) = text.split_at_checked(text.len().checked_sub(1)?)?;
    if number.is_empty() || !number.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let multiplier = match unit {
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        _ => return None,
    };
    number
        .parse::<u64>()
        .ok()?
        .checked_mul(multiplier)
        .filter(|ms| (1_000..=86_400_000).contains(ms))
}

impl Collab {
    pub fn result_timeout_ms(&self) -> u64 {
        duration_ms(&self.result_timeout).expect("validated collaboration timeout")
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteLaunch {
    #[default]
    Off,
    OnMessage,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AutoReport {
    #[default]
    Status,
    FinalMessage,
}

pub fn label_problem(label: &str, owner: bool) -> Option<String> {
    let prefixes: &[&str] = if owner {
        &["project:", "tag:"]
    } else {
        &["self:"]
    };
    let Some(name) = prefixes
        .iter()
        .find_map(|prefix| label.strip_prefix(prefix))
    else {
        return Some(
            if owner {
                "owner labels are project: or tag:"
            } else {
                "agent labels are self:"
            }
            .into(),
        );
    };
    if name.is_empty()
        || name.len() > 32
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        Some("names are 1-32 of a-z, 0-9 and -".into())
    } else {
        None
    }
}

fn labels_problem(labels: &[String]) -> Option<String> {
    if labels.len() > 64 {
        return Some("at most 64 labels".into());
    }
    labels
        .iter()
        .find_map(|label| label_problem(label, true).map(|p| format!("label {label:?}: {p}")))
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub id: String,
    pub revision: u64,
    pub label: String,
    pub provider: String,
    pub cwd: PathBuf,
    /// Normalized Git project key pinned when this profile is approved.
    pub project: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// Explicitly approved principals, including the kind prefix; none: the
    /// paired Astation (`Config::load`).
    #[serde(default)]
    pub principals: Vec<String>,
    #[serde(default)]
    pub env_names: Vec<String>,
    /// Private JSON object of environment names to values. Never sourced.
    pub env_file: Option<PathBuf>,
}

#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub id: String,
    pub revision: u64,
    pub profile_id: String,
    /// None: the paired Astation (`Config::load`).
    #[serde(default)]
    pub principals: Vec<String>,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub launch: RouteLaunch,
    #[serde(default)]
    pub results: bool,
    #[serde(default)]
    pub auto_report: AutoReport,
}

fn principal_ok(principal: &str) -> bool {
    ["member:", "service:", "browser:"].iter().any(|prefix| {
        principal
            .strip_prefix(prefix)
            .is_some_and(atem_client::session::wire::is_opaque_id)
    })
}

/// What is wrong with a profile's or route's principals (after the paired
/// Astation filled an empty list), if anything.
fn principals_problem(principals: &[String], route: bool) -> Option<String> {
    if principals.is_empty() {
        return Some(
            "no principals: list them, or pair with Astation (`atem pair`) so the paired \
             Astation is the default"
                .into(),
        );
    }
    if principals.len() > 64 {
        return Some("at most 64 principals".into());
    }
    principals
        .iter()
        .find(|p| !(principal_ok(p) || route && p.as_str() == "local"))
        .map(|p| {
            format!(
                "`{p}` is not a principal: use {} (`atem runtime check` lists them)",
                if route {
                    "`member:<id>`, `service:<id>`, `browser:<id>` or `local` (this runtime's own agents)"
                } else {
                    "`member:<id>`, `service:<id>` or `browser:<id>`"
                }
            )
        })
}

/// `member:<id>` of the Astation the profile at `dir` is paired with (its
/// current binding), the default launch principal.
fn paired_member(dir: &Path) -> Option<String> {
    let paths = crate::paths::ProfilePaths::in_dir(dir).pairing;
    crate::records::PairingRecord::load(&paths)
        .ok()
        .flatten()
        .filter(|r| r.binding.is_some())
        .map(|r| format!("member:{}", r.astation_id))
}

/// The parser's own reason and line; never the file's text.
fn schema_error(text: &str, error: &toml::de::Error) -> anyhow::Error {
    match error.span() {
        Some(span) => {
            let line = text[..span.start.min(text.len())].matches('\n').count() + 1;
            anyhow!("invalid runtime.toml (line {line}): {}", error.message())
        }
        None => anyhow!("invalid runtime.toml: {}", error.message()),
    }
}

fn private_read(path: &Path, limit: u64) -> Result<Vec<u8>> {
    use std::io::Read;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::getuid() }
        || meta.mode() & 0o077 != 0
        || meta.len() > limit
    {
        bail!(
            "{} must be a bounded regular file owned by this user with mode 0600",
            path.display()
        );
    }
    let mut bytes = Vec::new();
    file.by_ref().take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("file exceeds size limit");
    }
    Ok(bytes)
}

impl Config {
    pub fn load(dir: &Path) -> Result<Self> {
        let path = dir.join(CONFIG_FILE);
        let bytes = match private_read(&path, 256 * 1024) {
            Ok(bytes) => bytes,
            Err(e)
                if e.downcast_ref::<std::io::Error>()
                    .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
            {
                return Ok(Self::default());
            }
            Err(e) => return Err(e).context("reading host configuration"),
        };
        let text = std::str::from_utf8(&bytes).context("runtime.toml is not UTF-8")?;
        let mut config: Self = toml::from_str(text).map_err(|e| schema_error(text, &e))?;
        config.inherit(paired_member(dir));
        config.validate()?;
        Ok(config)
    }

    /// Profiles and routes that name no principals are open to `paired`,
    /// the paired Astation's member (none when not paired).
    fn inherit(&mut self, paired: Option<String>) {
        let default: Vec<String> = paired.into_iter().collect();
        for p in self.profiles.iter_mut().filter(|p| p.principals.is_empty()) {
            p.principals = default.clone();
        }
        for r in self.routes.iter_mut().filter(|r| r.principals.is_empty()) {
            r.principals = default.clone();
        }
    }

    pub fn validate(&self) -> Result<()> {
        use atem_client::session::wire::is_opaque_id;
        if self.version != 1 || self.profiles.len() > 64 || self.routes.len() > 64 {
            bail!("host config needs version = 1 and at most 64 profiles/routes");
        }
        if let Some(problem) = labels_problem(&self.instance.labels) {
            bail!("[instance]: {problem}");
        }
        if self.collab.per_hour == 0 || self.collab.per_workflow == 0 {
            bail!("[collab]: per_hour and per_workflow must be at least 1");
        }
        if duration_ms(&self.collab.result_timeout).is_none() {
            bail!("[collab]: result_timeout must be 1s-24h, using s, m or h");
        }
        let mut profiles = BTreeSet::new();
        for p in &self.profiles {
            let problem = if !is_opaque_id(&p.id) {
                Some("id must be 1-64 letters, digits, `.`, `_`, `:` or `-`".to_string())
            } else if !profiles.insert(p.id.clone()) {
                Some("id is used by another profile".into())
            } else if p.revision == 0 {
                Some("revision must be at least 1".into())
            } else if p.label.is_empty()
                || p.label.len() > 128
                || p.label.chars().any(char::is_control)
            {
                Some("label must be 1-128 printable characters".into())
            } else if !matches!(p.provider.as_str(), "claude" | "codex") {
                Some("provider must be `claude` or `codex`".into())
            } else if !p.cwd.is_absolute() {
                Some("cwd must be an absolute path".into())
            } else if p.project.is_empty() {
                Some(
                    "project must name the cwd's project (its Git remote, else `local:<folder>`)"
                        .into(),
                )
            } else if let Some(problem) = principals_problem(&p.principals, false) {
                Some(problem)
            } else if p.args.len() > super::protocol::MAX_ARGS
                || p.args.iter().map(String::len).sum::<usize>() > super::protocol::MAX_ARGS_BYTES
                || p.args.iter().any(|a| a.contains('\0'))
            {
                Some("args are too many or too long".into())
            } else if p.env_file.as_ref().is_some_and(|p| !p.is_absolute()) {
                Some("env_file must be an absolute path".into())
            } else if p.env_names.len() > 128
                || p.env_names
                    .iter()
                    .any(|n| n.is_empty() || n.contains(['=', '\0']))
            {
                Some("env_names must be at most 128 variable names".into())
            } else {
                None
            };
            if let Some(problem) = problem {
                bail!("profile `{}`: {problem}", p.id);
            }
        }
        let mut routes = BTreeSet::new();
        for r in &self.routes {
            let problem = if !is_opaque_id(&r.id) {
                Some("id must be 1-64 letters, digits, `.`, `_`, `:` or `-`".to_string())
            } else if !routes.insert(&r.id) {
                Some("id is used by another route".into())
            } else if r.revision == 0 {
                Some("revision must be at least 1".into())
            } else if !profiles.contains(&r.profile_id) {
                Some(format!("profile_id `{}` names no profile", r.profile_id))
            } else if r.launch == RouteLaunch::OnMessage
                && self
                    .profile(&r.profile_id)
                    .is_some_and(|p| p.provider != "claude")
            {
                // Codex reports nothing until a first prompt is typed in its
                // terminal, so a launched one would never become ready.
                Some("launch on message supports Claude Code profiles only for now".into())
            } else if let Some(problem) = labels_problem(&r.labels) {
                Some(problem)
            } else {
                principals_problem(&r.principals, true)
            };
            if let Some(problem) = problem {
                bail!("route `{}`: {problem}", r.id);
            }
        }
        Ok(())
    }

    pub fn profile(&self, id: &str) -> Option<&Profile> {
        self.profiles.iter().find(|p| p.id == id)
    }
    pub fn route(&self, id: &str) -> Option<&Route> {
        self.routes.iter().find(|r| r.id == id)
    }

    /// The route or profile approval a task was accepted under (`a`) is no
    /// longer this one: the route is gone or has another revision or
    /// profile, no longer names the task's principal, or its profile has
    /// another revision or project (host-work v1, and the delegated start
    /// check's condition 4).
    pub fn route_changed(&self, a: &Accepted) -> bool {
        let Some(route) = self.route(&a.route_id) else {
            return true;
        };
        let Some(profile) = self.profile(&route.profile_id) else {
            return true;
        };
        route.revision != a.route_revision
            || !route.principals.contains(&a.principal)
            || profile.id != a.profile_id
            || profile.revision != a.profile_revision
            || profile.project != a.project
    }
}

impl Profile {
    pub fn scope_key(&self) -> String {
        format!(
            "profile:{}:{}:{}",
            self.id,
            self.revision,
            atem_client::session::host_work::digest(self.project.as_bytes())
        )
    }

    pub fn permits(&self, authority: &Authority) -> bool {
        authority.allows(Need::Op(Op::Launch))
            && authority
                .scope
                .as_ref()
                .is_none_or(|s| s.sessions.is_none())
            && self.principals.contains(&authority.name())
    }

    pub fn info(&self) -> ProfileInfo {
        ProfileInfo {
            id: self.id.clone(),
            revision: self.revision,
            label: self.label.clone(),
            provider: self.provider.clone(),
        }
    }

    pub fn launch(
        &self,
        session_id: String,
        process_gen: String,
    ) -> Result<(SpawnRequest, LaunchEnv)> {
        let cwd = self
            .cwd
            .canonicalize()
            .context("approved project directory is unavailable")?;
        if cwd != self.cwd || !cwd.is_dir() {
            bail!("approved project directory changed; reapprove its canonical path");
        }
        if crate::memory::project::project_key_for(&cwd) != self.project {
            bail!("approved Git project changed");
        }
        let mut env = BTreeMap::new();
        for name in [
            "HOME",
            "PATH",
            "USER",
            "LOGNAME",
            "SHELL",
            "LANG",
            "LC_ALL",
            "TERM",
            "TMPDIR",
            "XDG_RUNTIME_DIR",
            "XDG_CONFIG_HOME",
        ]
        .into_iter()
        .chain(self.env_names.iter().map(String::as_str))
        {
            if let Ok(value) = std::env::var(name) {
                env.insert(name.to_owned(), value);
            }
        }
        if let Some(path) = &self.env_file {
            let bytes =
                private_read(path, 256 * 1024).context("reading profile environment file")?;
            let values: BTreeMap<String, String> =
                serde_json::from_slice(&bytes).map_err(|_| {
                    anyhow!("profile environment file must be a JSON object of string values")
                })?;
            for (name, value) in values {
                if !self.env_names.contains(&name) {
                    bail!("profile environment file contains an unapproved variable name");
                }
                env.insert(name, value);
            }
        }
        let env = LaunchEnv(env.into_iter().collect());
        crate::session::check_env(&env.to_os())
            .map_err(|_| anyhow!("profile environment is invalid or too large"))?;
        Ok((
            SpawnRequest {
                session_id: crate::session::SessionId::parse(&session_id)
                    .ok_or_else(|| anyhow!("invalid reserved session id"))?,
                process_gen,
                provider: crate::session::Provider::from_alias(&self.provider)
                    .ok_or_else(|| anyhow!("unknown provider"))?,
                args: self.args.clone(),
                cwd,
                rows: 24,
                cols: 100,
            },
            env,
        ))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LaunchRecord {
    pub principal: String,
    pub profile_id: String,
    pub profile_revision: u64,
    pub expires_at: u64,
    pub digest: String,
    pub status: LaunchStatus,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WorkRecord {
    pub principal: String,
    #[serde(default)]
    pub attachment_owner: String,
    pub control_gen: u64,
    pub route_id: String,
    pub route_revision: u64,
    pub profile_id: String,
    pub profile_revision: u64,
    pub project: String,
    pub digest: String,
    pub task: WorkTask,
    pub status: WorkStatus,
    /// The provider turn the task's prompt became, stored once the runtime
    /// saw the prompt accepted: a reply is bound to it, after a restart too.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub turn_id: Option<String>,
    /// When the authorization the task was accepted under expires (a
    /// service or browser grant's expiry); none for a native member and
    /// `local`, whose authority doesn't expire, and in records written
    /// before it was kept. Past it the task's sender has no authority over
    /// it, whatever renews the grant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authorization_expires_at: Option<u64>,
    /// The message a remote sender's task came from (`message_publish`):
    /// Atem's lines around its text name it, and its mark is rendered with
    /// it, at dispatch (delegated host-work design III.2). None for a
    /// `work_enqueue` task and for the runtime's own local tasks, whose
    /// lines come from the outbox.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<MessageFrame>,
    /// A delegated sender's task (design I.1.3, I.4.1): what it was
    /// admitted under, frozen before the enqueue was answered. None for a
    /// v1 task (`local`, a browser grant, a service no feed covers, every
    /// sender while `host.delegated` is off), whose record is as before.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delegated: Option<crate::runtime::delegated::Admission>,
    /// A delegated task of unknown outcome whose deadline passed
    /// unresolved (design I.4.6, host-work-v1 §11.6 "Unknown outcomes"):
    /// it stays `outcome_unknown`, with its alert, until it is resolved (no
    /// reply moves it any more: `apply_reply`, and a reply then is refused
    /// `expired`), and no longer holds its session (`work_waits` has no row
    /// for it, so no pass reads it again). Set once, by `Store::settle_due`,
    /// and kept as a fact of its history once the task is resolved (the
    /// triggers read it only with `outcome_unknown`); never on a v1 task,
    /// whose record is as before.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub deadline_passed: bool,
}

/// What a message's task renders around its text: the message's id and
/// its mark. The sender is the task's own principal (a publisher can only
/// send as itself).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageFrame {
    pub message_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mark: Option<atem_client::session::mark::MarkTask>,
}

/// What a task was accepted under: its sender's principal, control
/// generation and authorization expiry, and the route and profile approval.
/// A task under any other is never dispatched, completed or answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    pub principal: String,
    pub control_gen: u64,
    pub authorization_expires_at: Option<u64>,
    pub route_id: String,
    pub route_revision: u64,
    pub profile_id: String,
    pub profile_revision: u64,
    pub project: String,
}

impl WorkRecord {
    pub fn accepted(&self) -> Accepted {
        Accepted {
            principal: self.principal.clone(),
            control_gen: self.control_gen,
            authorization_expires_at: self.authorization_expires_at,
            route_id: self.route_id.clone(),
            route_revision: self.route_revision,
            profile_id: self.profile_id.clone(),
            profile_revision: self.profile_revision,
            project: self.project.clone(),
        }
    }

    /// Drops what the task carried (`Store::drop_payloads`): its prompt,
    /// its context's text, its mark, and the copy of a reply its result is
    /// (a local task's). Every id, digest, state and detail stays, the attachment
    /// descriptors too, and a remote sender's explicit result
    /// (`work_complete`), which `work_query` answers whole.
    fn drop_payload(&mut self) {
        self.task.prompt.clear();
        drop_context(&mut self.task.context);
        // A mark's URL, title and annotations are the sender's text too
        // (the message's record keeps them, as it keeps its mark).
        if let Some(message) = self.message.as_mut() {
            message.mark = None;
        }
        if let Some(result) = self
            .status
            .result
            .as_mut()
            .filter(|r| r.kind == ContextKind::Result)
        {
            result.text.clear();
        }
    }
}

/// The text of each snapshot goes; its kind, id, version and digest stay.
pub(super) fn drop_context(context: &mut [ContextSnapshot]) {
    for snapshot in context {
        snapshot.text.clear();
    }
}

/// A message's inline text and its context's text go; its ids, sender,
/// recipients, times and mark stay.
fn drop_message_payload(message: &mut Message) {
    message.text.clear();
    drop_context(&mut message.context);
}

/// How long a settled record keeps its payloads past its deadline
/// (`Store::drop_payloads`); the record itself is never removed.
pub const PAYLOAD_RETENTION_MS: u64 = 86_400_000;

/// Whose payloads `Store::drop_payloads` dropped (their records stay).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Dropped {
    pub tasks: usize,
    pub messages: usize,
    pub uploads: usize,
}

/// How long a delegated task's reply text and context are kept after the
/// task settles (design I.4.7: a reply outlives a renewal that comes days
/// later), past the day after its deadline when its task's own payloads go.
pub const KEPT_REPLY_MS: u64 = 30 * PAYLOAD_RETENTION_MS;

/// The bytes the replies kept past that day may hold on a host (I.4.7's
/// "own bytes budget"; step 4's open question 3, owner-approved): over it
/// the oldest go first, before their 30 days.
pub const KEPT_REPLY_BUDGET: u64 = 64 * 1024 * 1024;

/// What `Store::drop_kept_replies` dropped: kept replies whose 30 days
/// passed, and those that went early, over the budget.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct KeptDropped {
    pub expired: usize,
    pub early: usize,
}

/// The records due to close (`Store::payloads_due`): ids of tasks, of
/// messages (remote or local; a local send never accepted has only its
/// outbox row) and of launches.
#[derive(Debug, Default, PartialEq, Eq)]
struct Due {
    tasks: Vec<String>,
    messages: Vec<String>,
    launches: Vec<String>,
}

/// The tables whose records count toward `MAX_RECORDS` while open, with
/// their id column.
const TRACKED: [(&str, &str); 4] = [
    ("work", "id"),
    ("messages", "id"),
    ("outbox", "message_id"),
    ("launches", "id"),
];

/// The records of `table` (`TRACKED`) that count toward `MAX_RECORDS`:
/// those not closed yet. Read from `open_records` by its key, so closed
/// records are never stepped over.
pub(super) fn open_records(db: &Connection, table: &str) -> Result<usize> {
    Ok(db.query_row(OPEN_COUNT, [table], |r| r.get(0))?)
}

const OPEN_COUNT: &str = "SELECT count(*) FROM open_records WHERE kind=?1";

// The queries of `Store::payloads_due`. Each reads `open_records` first
// (`CROSS JOIN` keeps that order) and the record tables only by their
// primary key, so what is closed is never read again.

/// Settled tasks past the cutoff whose reply is no longer publishing and
/// whose reply's carrier (the task delivering it to its local sender), if
/// any, settled too. A record that isn't JSON is due at once (it is closed
/// as it is, `Store::fail_unreadable`). A delegated task of unknown outcome
/// counts as settled here (design I.4.6, "Capacity"): unresolved, it never
/// expires, and drops its payloads a day after its deadline all the same.
const DUE_TASKS: &str = "SELECT w.id FROM open_records o CROSS JOIN work w ON w.id=o.id
    WHERE o.kind='work' AND (w.state IN ('completed','failed','cancelled','expired')
        OR w.state='outcome_unknown' AND json_valid(w.record)
        AND json_extract(w.record,'$.delegated') IS NOT NULL)
    AND CASE WHEN json_valid(w.record) THEN json_extract(w.record,'$.task.expires_at')
        ELSE 0 END<=?1
    AND NOT EXISTS(SELECT 1 FROM results r LEFT JOIN work c ON c.id=r.work_id
        WHERE r.task_id=w.id AND (r.state='publishing'
        OR c.state NOT IN ('completed','failed','cancelled','expired')))
    ORDER BY w.rowid";

/// Messages past the cutoff whose tasks all settled (a delegated task of
/// unknown outcome counting as settled, as in `DUE_TASKS`).
const DUE_MESSAGES: &str = "SELECT m.id FROM open_records o CROSS JOIN messages m ON m.id=o.id
    WHERE o.kind='messages' AND json_extract(m.record,'$.message.expires_at')<=?1
    AND NOT EXISTS(SELECT 1 FROM json_each(m.record,'$.receipt.recipients') r
        JOIN work w ON w.id=json_extract(r.value,'$.recipient_id')
        WHERE json_extract(r.value,'$.delivery.state')='work'
        AND w.state NOT IN ('completed','failed','cancelled','expired')
        AND NOT (w.state='outcome_unknown' AND json_valid(w.record)
            AND json_extract(w.record,'$.delegated') IS NOT NULL))
    ORDER BY m.rowid";

/// Local sends never accepted (refused or expired) past the cutoff.
const DUE_SENDS: &str = "SELECT x.message_id FROM open_records o
    CROSS JOIN outbox x ON x.message_id=o.id
    WHERE o.kind='outbox' AND x.state!='publishing'
    AND NOT EXISTS(SELECT 1 FROM messages m WHERE m.id=x.message_id)
    AND json_extract(x.envelope,'$.expires_at')<=?1
    ORDER BY x.rowid";

/// Launches no longer starting past the cutoff.
const DUE_LAUNCHES: &str = "SELECT l.id FROM open_records o CROSS JOIN launches l ON l.id=o.id
    WHERE o.kind='launches' AND json_extract(l.record,'$.status.state')!='starting'
    AND json_extract(l.record,'$.expires_at')<=?1
    ORDER BY l.rowid";

// The queries of `Store::drop_kept_replies`, through the kept replies'
// index (`result_kept`): what is not kept is never read.

/// Kept replies whose 30 days passed.
const KEPT_DUE: &str = "SELECT task_id,kept_bytes FROM results
    WHERE kept_bytes IS NOT NULL AND retain_until_ms<=?1 ORDER BY retain_until_ms";
/// The bytes the kept replies hold (kept by a trigger).
const KEPT_TOTAL: &str = "SELECT bytes FROM kept_replies WHERE id=1";
/// The oldest kept reply (the earliest settled).
const KEPT_OLDEST: &str = "SELECT task_id,kept_bytes FROM results
    WHERE kept_bytes IS NOT NULL ORDER BY retain_until_ms,rowid LIMIT 1";

/// `work_waits` rows due by the wall clock (`Store::settle_due`), through
/// the due index.
const DUE_BY_WALL: &str = "SELECT id,expires_at,authorization_expires_at,delegated,state
    FROM work_waits WHERE due_ms<=?1";

/// Delegated `work_waits` rows due between the wall clock and `D`
/// (`Store::settle_due`), through the delegated rows' due index.
const DUE_BY_D: &str =
    "SELECT id,expires_at,authorization_expires_at,delegated,state FROM work_waits
    WHERE delegated=1 AND due_ms>?1 AND due_ms<=?2";

/// The open launches and tasks (`Store::open_launches`, `open_tasks`).
const OPEN_LAUNCHES: &str = "SELECT l.record FROM open_records o
    CROSS JOIN launches l ON l.id=o.id WHERE o.kind='launches' ORDER BY l.rowid";
const OPEN_TASKS: &str = "SELECT w.id,w.record FROM open_records o
    CROSS JOIN work w ON w.id=o.id WHERE o.kind='work' ORDER BY w.rowid";

/// The tasks in one state (`Store::tasks_in`).
const TASKS_IN: &str = "SELECT id,record FROM work WHERE state=?1 ORDER BY rowid";

/// The principals of unsettled tasks (`Store::named_principals_at`).
const NAMED_PRINCIPALS: &str = "SELECT DISTINCT json_extract(record,'$.principal') FROM work
    WHERE state IN ('queued','blocked','submitting','submitted','awaiting_result','outcome_unknown')";

/// An open task names upload `?2` of owner `?1`.
const NAMED_UPLOAD: &str = "SELECT EXISTS(SELECT 1 FROM open_records o
    CROSS JOIN work w ON w.id=o.id CROSS JOIN json_each(w.record,'$.task.attachments') a
    WHERE o.kind='work' AND json_extract(w.record,'$.attachment_owner')=?1
    AND json_extract(a.value,'$.attachment_id')=?2)";

/// The tables whose rows are kept for good (the records and what belongs
/// to them): no recurring or per-request query may scan one.
#[cfg(test)]
const KEPT: [&str; 10] = [
    "work",
    "messages",
    "outbox",
    "launches",
    "results",
    "return_grants",
    "resolutions",
    "origins",
    "publications",
    "closed_records",
];

/// The query plan of `sql` on `db` (any parameter bound to `'x'`), and
/// those of its steps that scan a `KEPT` table, by its name or an alias.
/// A walk of an index in the order a `LIMIT` stops (`atem message
/// status`'s newest first) is no scan; the VM-step test bounds it.
#[cfg(test)]
pub(super) fn kept_table_scans(db: &Connection, sql: &str) -> (Vec<String>, Vec<String>) {
    let mut q = db.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
    let n = q.parameter_count();
    let steps: Vec<String> = q
        .query_map(
            rusqlite::params_from_iter(std::iter::repeat_n("x", n)),
            |r| r.get(3),
        )
        .unwrap()
        .collect::<rusqlite::Result<_>>()
        .unwrap();
    // A kept table's name, and the word after it unless a keyword (an
    // alias: `FROM work w`).
    let words: Vec<&str> = sql
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .collect();
    let mut names: HashSet<&str> = KEPT.into_iter().collect();
    for pair in words.windows(2) {
        if KEPT.contains(&pair[0]) && pair[1].chars().any(|c| c.is_ascii_lowercase()) {
            names.insert(pair[1]);
        }
    }
    let limited = sql.contains("ORDER BY") && sql.contains(" LIMIT ");
    let scans = steps
        .iter()
        .filter(|step| {
            step.strip_prefix("SCAN ")
                .and_then(|rest| rest.split(' ').next())
                .is_some_and(|name| names.contains(name))
                && !step.contains("VIRTUAL TABLE")
                && !(limited && step.contains(" USING INDEX "))
        })
        .cloned()
        .collect();
    (steps, scans)
}

pub struct Store {
    pub(super) db: Connection,
    pub(super) state: PathBuf,
    /// What the alerts' push hints still have to look at, in memory for
    /// this store's run (`delegated::alerts::HintWatch`).
    pub(super) hints: crate::runtime::delegated::alerts::HintWatch,
}

/// How many damaged clock records `clock_aside` keeps (the latest).
const CLOCK_ASIDE_KEPT: u32 = 8;

pub(super) fn valid_owner(owner: &str) -> bool {
    atem_client::session::wire::is_digest(owner)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageRecord {
    pub sender_key: serde_json::Value,
    pub message: Message,
    pub receipt: MessageReceipt,
}

/// The columns a delegated task's kept reply needs (design I.4.7):
/// `retain_until_ms`, when its text and context may drop (30 days after its
/// task settled, `Store::write_work`), and `kept_bytes`, the bytes it holds
/// past its task's payload drop (none: not kept, or dropped since). Its
/// index holds the kept replies only, in the order they drop, and a trigger
/// keeps their total in `kept_replies` (`Store::drop_kept_replies` reads
/// one row, never the kept table). Additive: a table without them gets
/// them (no reply of a database from before has either: a v1 reply never
/// does), and the total starts at what is kept.
fn track_kept_replies(db: &Connection) -> Result<()> {
    for column in ["retain_until_ms", "kept_bytes"] {
        let present: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('results') WHERE name=?1)",
            [column],
            |r| r.get(0),
        )?;
        if !present {
            db.execute_batch(&format!("ALTER TABLE results ADD COLUMN {column} INTEGER"))?;
        }
    }
    let counted: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='kept_replies')",
        [],
        |r| r.get(0),
    )?;
    db.execute_batch(
        "CREATE INDEX IF NOT EXISTS result_kept ON results(retain_until_ms)
            WHERE kept_bytes IS NOT NULL;
        CREATE TABLE IF NOT EXISTS kept_replies (id INTEGER PRIMARY KEY CHECK (id = 1),
            bytes INTEGER NOT NULL);
        CREATE TRIGGER IF NOT EXISTS kept_replies_bytes AFTER UPDATE OF kept_bytes ON results
        BEGIN
            UPDATE kept_replies SET bytes=bytes-coalesce(OLD.kept_bytes,0)
                +coalesce(NEW.kept_bytes,0) WHERE id=1;
        END;",
    )?;
    if !counted {
        db.execute(
            "INSERT OR REPLACE INTO kept_replies(id,bytes) SELECT 1,coalesce(sum(kept_bytes),0)
            FROM results WHERE kept_bytes IS NOT NULL",
            [],
        )?;
    }
    Ok(())
}

/// `open_records` holds one row per record of a `TRACKED` table not closed
/// yet: what the record caps count and what the payload pass reads, so
/// neither steps over a closed record. An insert trigger on each table
/// adds every record, whoever inserts it (a v0.8.2 binary too: triggers
/// and the table change no v0.8.2 table, and its statements run as
/// before), and a delete trigger takes out a record deleted (none is
/// today). A database without the table (v0.8.2's, or a new one) gets it,
/// filled once with what it holds and has not closed.
fn track_open_records(db: &Connection) -> Result<()> {
    let tracked: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='open_records')",
        [],
        |r| r.get(0),
    )?;
    if tracked {
        return Ok(());
    }
    let tx = db.unchecked_transaction()?;
    tx.execute_batch(
        "CREATE TABLE open_records (kind TEXT NOT NULL, id TEXT NOT NULL,
        PRIMARY KEY(kind,id)) WITHOUT ROWID;",
    )?;
    for (table, id) in TRACKED {
        tx.execute_batch(&format!(
            "INSERT INTO open_records(kind,id) SELECT '{table}',t.{id} FROM {table} t
            WHERE NOT EXISTS(SELECT 1 FROM closed_records c WHERE c.kind='{table}' AND c.id=t.{id});
            CREATE TRIGGER {table}_opened AFTER INSERT ON {table} BEGIN
                INSERT OR IGNORE INTO open_records(kind,id) VALUES('{table}',NEW.{id});
            END;
            CREATE TRIGGER {table}_deleted AFTER DELETE ON {table} BEGIN
                DELETE FROM open_records WHERE kind='{table}' AND id=OLD.{id};
            END;"
        ))?;
    }
    tx.commit()?;
    Ok(())
}

/// The columns of a `work_waits` row, from `{r}` (a task record's JSON; a
/// record that isn't JSON gives NULLs, due at once) for task `{t}`. A
/// delegated task (one with an admission record) is due at its deadline
/// only: no authorization expiry ends it (design I.2), and its deadline is
/// compared with the delegated clock (`settle_due`).
fn wait_columns(t: &str, r: &str) -> String {
    let field = |path: &str| format!("json_extract({r},'$.{path}')");
    format!(
        "{t}.id,{t}.state,CASE WHEN {delegated} THEN coalesce({expires},0) \
        ELSE min(coalesce({expires},0),coalesce({auth},{expires},0)) END,\
        {expires},{auth},{session},{principal},{gen},{route},{route_rev},{profile},{profile_rev},{project},\
        {delegated}",
        delegated = format!("({} IS NOT NULL)", field("delegated")),
        expires = field("task.expires_at"),
        auth = field("authorization_expires_at"),
        session = field("task.target.session_id"),
        principal = field("principal"),
        gen = field("control_gen"),
        route = field("route_id"),
        route_rev = field("route_revision"),
        profile = field("profile_id"),
        profile_rev = field("profile_revision"),
        project = field("project"),
    )
}

/// A `record` column's text; anything else (a BLOB, NULL) as no text,
/// which no record parses from.
fn record_text(row: &rusqlite::Row, i: usize) -> rusqlite::Result<String> {
    Ok(row.get_ref(i)?.as_str().unwrap_or_default().to_string())
}

/// A `work_waits` row's columns after its id, from `settle_due` (2) or
/// `settle_lost` (9): its deadline and what it was accepted under. `None`
/// when one isn't of its type (its record isn't JSON, or lacks it).
fn waiting(values: Vec<rusqlite::types::Value>) -> Option<(u64, Accepted)> {
    use rusqlite::types::Value;
    let int = |v: &Value| match v {
        Value::Integer(i) => u64::try_from(*i).ok(),
        _ => None,
    };
    let text = |v: &Value| match v {
        Value::Text(t) => Some(t.clone()),
        _ => None,
    };
    let deadline = int(values.first()?)?;
    let authorization_expires_at = match values.get(1)? {
        Value::Null => None,
        other => Some(int(other)?),
    };
    let mut accepted = Accepted {
        principal: String::new(),
        control_gen: 0,
        authorization_expires_at,
        route_id: String::new(),
        route_revision: 0,
        profile_id: String::new(),
        profile_revision: 0,
        project: String::new(),
    };
    if values.len() > 2 {
        accepted.principal = text(values.get(2)?)?;
        accepted.control_gen = int(values.get(3)?)?;
        accepted.route_id = text(values.get(4)?)?;
        accepted.route_revision = int(values.get(5)?)?;
        accepted.profile_id = text(values.get(6)?)?;
        accepted.profile_revision = int(values.get(7)?)?;
        accepted.project = text(values.get(8)?)?;
    }
    Some((deadline, accepted))
}

/// `work_waits` holds one row per task awaiting its result or of unknown
/// outcome: when it is next due (`due_ms`: its deadline, or its sender's
/// authorization expiry if sooner), its target session, and what it was
/// accepted under. Triggers on `work` keep it, whoever writes the task (a
/// v0.8.2 binary too: they change no v0.8.2 table), so the scheduling
/// passes read these columns through their indexes and never a task's
/// record (`Store::settle_due`, `settle_lost`, `holds_unknown_outcome`). A
/// database without the table gets it, filled once.
///
/// Its `delegated` column (a task with an admission record, step 4) has
/// its own index with the due time, so `settle_due` reads v1 rows by the
/// wall clock and delegated ones by the delegated clock. It is additive: a
/// table without it gets it (`ALTER TABLE … ADD COLUMN`, guarded by
/// `pragma table_info`), the two triggers that fill rows are made again
/// with it, and the rows are filled again from the records once.
///
/// A delegated task of unknown outcome whose deadline passed
/// (`WorkRecord::deadline_passed`, design I.4.6) has no row: it is due for
/// nothing and holds no session, so no pass reads it again. Triggers made
/// before that rule ([`WAITS_RULE`] not in their text) are made again the
/// same way, once.
fn track_waits(db: &Connection) -> Result<()> {
    let tracked: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='work_waits')",
        [],
        |r| r.get(0),
    )?;
    let waiting = "('awaiting_result','outcome_unknown')";
    let checked = "(SELECT CASE WHEN json_valid(NEW.record) THEN NEW.record ELSE '{}' END AS r)";
    let new = wait_columns("NEW", "r");
    let existing_record = "(CASE WHEN json_valid(w.record) THEN w.record ELSE '{}' END)";
    let existing = wait_columns("w", existing_record);
    let held_new = holds_a_wait("NEW.state", "r");
    let held_existing = holds_a_wait("w.state", existing_record);
    let fills = format!(
        "CREATE TRIGGER work_waits_opened AFTER INSERT ON work
            WHEN NEW.state IN {waiting} BEGIN
            INSERT OR REPLACE INTO work_waits SELECT {new} FROM {checked} WHERE {held_new};
        END;
        CREATE TRIGGER work_waits_changed AFTER UPDATE ON work BEGIN
            DELETE FROM work_waits WHERE id=OLD.id;
            INSERT INTO work_waits SELECT {new} FROM {checked}
                WHERE NEW.state IN {waiting} AND {held_new};
        END;
        CREATE INDEX IF NOT EXISTS work_waits_delegated ON work_waits(delegated, due_ms);
        INSERT INTO work_waits SELECT {existing} FROM work w
            WHERE w.state IN {waiting} AND {held_existing};"
    );
    if tracked {
        let delegated: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('work_waits') WHERE name='delegated')",
            [],
            |r| r.get(0),
        )?;
        let current: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='trigger'
                AND name='work_waits_changed' AND instr(sql,?1)>0)",
            [WAITS_RULE],
            |r| r.get(0),
        )?;
        if delegated && current {
            return Ok(());
        }
        let column = if delegated {
            ""
        } else {
            "ALTER TABLE work_waits ADD COLUMN delegated INTEGER NOT NULL DEFAULT 0;"
        };
        let tx = db.unchecked_transaction()?;
        tx.execute_batch(&format!(
            "{column}
            DROP TRIGGER IF EXISTS work_waits_opened;
            DROP TRIGGER IF EXISTS work_waits_changed;
            DELETE FROM work_waits;
            {fills}"
        ))?;
        tx.commit()?;
        return Ok(());
    }
    let tx = db.unchecked_transaction()?;
    tx.execute_batch(&format!(
        "CREATE TABLE work_waits (id TEXT PRIMARY KEY, state TEXT NOT NULL, due_ms INTEGER,
            expires_at INTEGER, authorization_expires_at INTEGER, session_id TEXT,
            principal TEXT, control_gen INTEGER, route_id TEXT, route_revision INTEGER,
            profile_id TEXT, profile_revision INTEGER, project TEXT,
            delegated INTEGER NOT NULL DEFAULT 0) WITHOUT ROWID;
        CREATE INDEX work_waits_due ON work_waits(due_ms);
        CREATE INDEX work_waits_session ON work_waits(session_id, state);
        CREATE TRIGGER work_waits_deleted AFTER DELETE ON work BEGIN
            DELETE FROM work_waits WHERE id=OLD.id;
        END;
        {fills}"
    ))?;
    tx.commit()?;
    Ok(())
}

/// The record field that keeps a task out of `work_waits`
/// (`WorkRecord::deadline_passed`), as the triggers name it: their text
/// says whether they know the rule ([`track_waits`]).
const WAITS_RULE: &str = "$.deadline_passed";

/// Whether a task in `state` (a column) with the record `r` (JSON) has a
/// `work_waits` row, given its state is one that waits: not a delegated
/// task of unknown outcome whose deadline passed (design I.4.6).
fn holds_a_wait(state: &str, r: &str) -> String {
    format!("NOT ({state}='outcome_unknown' AND json_extract({r},'{WAITS_RULE}') IS 1)")
}

impl Store {
    pub fn open(state: &Path) -> Result<Self> {
        super::worker::private_dir(state)?;
        let path = state.join("host-work.sqlite");
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&path)?;
        let meta = file.metadata()?;
        if !meta.is_file() || meta.uid() != unsafe { libc::getuid() } || meta.mode() & 0o077 != 0 {
            bail!("host work database is not private");
        }
        let db = Connection::open(&path)?;
        db.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS identity (id INTEGER PRIMARY KEY CHECK(id=1), host TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS launches (id TEXT PRIMARY KEY, record TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS work (id TEXT PRIMARY KEY, record TEXT NOT NULL, state TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS work_state ON work(state);
            CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, record TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS outbox (
                message_id TEXT PRIMARY KEY, envelope TEXT NOT NULL, state TEXT NOT NULL,
                detail TEXT NOT NULL, next_try_ms INTEGER NOT NULL, created_ms INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS outbox_state ON outbox(state);
            CREATE INDEX IF NOT EXISTS outbox_created ON outbox(created_ms);
            CREATE TABLE IF NOT EXISTS resolutions (
                message_id TEXT NOT NULL, recipient_id TEXT NOT NULL, task_id TEXT PRIMARY KEY,
                route_id TEXT NOT NULL, session_id TEXT NOT NULL, process_gen TEXT NOT NULL,
                launch_request_id TEXT, record TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS resolution_message ON resolutions(message_id);
            CREATE INDEX IF NOT EXISTS resolution_session ON resolutions(session_id);
            CREATE TABLE IF NOT EXISTS publications (
                message_id TEXT PRIMARY KEY, record TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS origins (message_id TEXT PRIMARY KEY, record TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS return_grants (task_id TEXT PRIMARY KEY, record TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'open', awaiting_since_ms INTEGER);
            CREATE INDEX IF NOT EXISTS grant_state ON return_grants(state);
            CREATE TABLE IF NOT EXISTS grant_dues (task_id TEXT PRIMARY KEY, due_ms INTEGER NOT NULL)
                WITHOUT ROWID;
            CREATE INDEX IF NOT EXISTS grant_due ON grant_dues(due_ms);
            CREATE TABLE IF NOT EXISTS results (
                task_id TEXT PRIMARY KEY, result_id TEXT NOT NULL UNIQUE, state TEXT NOT NULL,
                detail TEXT NOT NULL, digest TEXT NOT NULL, created_ms INTEGER NOT NULL,
                submitted_at INTEGER, record TEXT NOT NULL, next_try_ms INTEGER NOT NULL,
                attempts INTEGER NOT NULL, work_id TEXT);
            CREATE INDEX IF NOT EXISTS result_state ON results(state);
            CREATE INDEX IF NOT EXISTS result_work ON results(work_id);
            CREATE INDEX IF NOT EXISTS result_digest ON results(digest);
            CREATE TABLE IF NOT EXISTS counters (
                key TEXT NOT NULL, window_start_ms INTEGER NOT NULL, count INTEGER NOT NULL,
                PRIMARY KEY(key,window_start_ms));
            CREATE TABLE IF NOT EXISTS attachments (
                owner TEXT NOT NULL, id TEXT NOT NULL, descriptor TEXT NOT NULL,
                size INTEGER NOT NULL, bytes BLOB NOT NULL, PRIMARY KEY(owner,id));
            CREATE TABLE IF NOT EXISTS closed_records (
                kind TEXT NOT NULL, id TEXT NOT NULL, at_ms INTEGER NOT NULL,
                PRIMARY KEY(kind,id)) WITHOUT ROWID;
            CREATE TABLE IF NOT EXISTS clock (id INTEGER PRIMARY KEY CHECK (id = 1), state TEXT);
            CREATE TABLE IF NOT EXISTS attempts (
                task_id TEXT NOT NULL, attempt_id TEXT PRIMARY KEY, n INTEGER NOT NULL,
                \"end\" TEXT, counted INTEGER NOT NULL, created_ms INTEGER NOT NULL);
            CREATE INDEX IF NOT EXISTS attempts_task ON attempts(task_id);
            CREATE UNIQUE INDEX IF NOT EXISTS attempts_live ON attempts(task_id)
                WHERE \"end\" IS NULL;")?;
        db.execute_batch(crate::runtime::delegated::alerts::SCHEMA)?;
        track_kept_replies(&db)?;
        track_open_records(&db)?;
        track_waits(&db)?;
        std::fs::File::open(state)?.sync_all()?;
        let hints = crate::runtime::delegated::alerts::HintWatch::open(&db)?;
        Ok(Self {
            db,
            state: state.to_path_buf(),
            hints,
        })
    }

    pub fn bind(&self, host: &HostTarget) -> Result<()> {
        let identity = serde_json::to_string(host)?;
        self.db.execute(
            "INSERT OR IGNORE INTO identity(id,host) VALUES(1,?1)",
            [&identity],
        )?;
        if self.bound()?.as_ref() != Some(host) {
            bail!("host work database belongs to another account or trust generation");
        }
        Ok(())
    }

    /// The delegated clock's record as stored (`host_clock::HostClock`
    /// reads it): none before its first write, else the value as it is,
    /// whatever its type, so a damaged one is never taken for none.
    pub fn load_clock(&self) -> Result<Option<rusqlite::types::Value>> {
        Ok(self
            .db
            .query_row("SELECT state FROM clock WHERE id=1", [], |r| r.get(0))
            .optional()?)
    }

    /// Writes the delegated clock's record.
    pub fn save_clock(&self, state: &crate::runtime::host_clock::state::ClockState) -> Result<()> {
        self.put_clock(&rusqlite::types::Value::Text(state.to_json()))
    }

    /// Writes `value` as the clock's record as it is (a damaged one carried
    /// into a new store stays damaged).
    pub fn put_clock(&self, value: &rusqlite::types::Value) -> Result<()> {
        self.db.execute(
            "INSERT INTO clock(id,state) VALUES(1,?1)
            ON CONFLICT(id) DO UPDATE SET state=excluded.state",
            [value],
        )?;
        Ok(())
    }

    /// Keeps the clock's stored record aside (`clock_aside`, found at
    /// `at_ms`), as it is, never read again: once, while it is the latest
    /// copy, and only the latest `CLOCK_ASIDE_KEPT` copies. The table is made
    /// with the first copy, so a store whose clock never kept one has only
    /// `clock`.
    pub fn keep_clock_aside(&self, at_ms: u64) -> Result<()> {
        let tx = self.db.unchecked_transaction()?;
        tx.execute_batch("CREATE TABLE IF NOT EXISTS clock_aside (at_ms INTEGER NOT NULL, state)")?;
        tx.execute(
            "INSERT INTO clock_aside(at_ms,state) SELECT ?1,c.state FROM clock c
            WHERE c.id=1 AND NOT EXISTS(SELECT 1 FROM clock_aside a
                WHERE a.rowid=(SELECT max(rowid) FROM clock_aside) AND a.state IS c.state)",
            [at_ms],
        )?;
        tx.execute(
            "DELETE FROM clock_aside WHERE rowid NOT IN
            (SELECT rowid FROM clock_aside ORDER BY rowid DESC LIMIT ?1)",
            [CLOCK_ASIDE_KEPT],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// The clock's record of the newest retired store that has one
    /// (`retire`), and that store's path, read only: the record is the
    /// host's, not the identity's, so a new store that has none yet (a crash
    /// between the retire and the clock's first write there) takes it.
    pub fn retired_clock(&self) -> Result<Option<(rusqlite::types::Value, PathBuf)>> {
        let mut retired: Vec<(u64, PathBuf)> = std::fs::read_dir(&self.state)?
            .filter_map(|entry| {
                let entry = entry.ok()?;
                let name = entry.file_name().into_string().ok()?;
                let at_ms = name
                    .strip_prefix("host-work.sqlite.retired-")?
                    .parse()
                    .ok()?;
                Some((at_ms, entry.path()))
            })
            .collect();
        retired.sort_by(|a, b| b.0.cmp(&a.0));
        for (_, path) in retired {
            // An error names the retired file (PR 4 re-review N1).
            let read = || -> Result<Option<rusqlite::types::Value>> {
                let db = Connection::open_with_flags(
                    &path,
                    rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY
                        | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
                )?;
                let has_table: bool = db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='clock')",
                    [],
                    |r| r.get(0),
                )?;
                if !has_table {
                    return Ok(None);
                }
                Ok(db
                    .query_row("SELECT state FROM clock WHERE id=1", [], |r| r.get(0))
                    .optional()?)
            };
            let value = read().with_context(|| path.display().to_string())?;
            if let Some(value) = value {
                return Ok(Some((value, path)));
            }
        }
        Ok(None)
    }

    /// The host these records belong to; none before the first `bind`.
    pub fn bound(&self) -> Result<Option<HostTarget>> {
        let text: Option<String> = self
            .db
            .query_row("SELECT host FROM identity WHERE id=1", [], |r| r.get(0))
            .optional()?;
        Ok(text.map(|t| serde_json::from_str(&t)).transpose()?)
    }

    /// Moves the database aside as `host-work.sqlite.retired-<at_ms>`,
    /// kept and never read again, for a host whose identity changed (a
    /// verification, a new pairing): every request names the current host,
    /// so none of its records can be honored again. A hard link, so an
    /// existing file is never replaced.
    pub fn retire(self, at_ms: u64) -> Result<PathBuf> {
        let Self { db, state, .. } = self;
        db.close().map_err(|(_, e)| e)?;
        let path = state.join("host-work.sqlite");
        let aside = state.join(format!("host-work.sqlite.retired-{at_ms}"));
        std::fs::hard_link(&path, &aside)?;
        std::fs::remove_file(&path)?;
        // A hot journal belongs to the retired file, never to the next one.
        let journal = state.join("host-work.sqlite-journal");
        if journal.exists() {
            std::fs::rename(
                &journal,
                state.join(format!("host-work.sqlite.retired-{at_ms}-journal")),
            )?;
        }
        std::fs::File::open(&state)?.sync_all()?;
        Ok(aside)
    }

    pub fn launch(&self, id: &str) -> Result<Option<LaunchRecord>> {
        let text: Option<String> = self
            .db
            .query_row("SELECT record FROM launches WHERE id=?1", [id], |r| {
                r.get(0)
            })
            .optional()?;
        text.map(|s| serde_json::from_str(&s).context("invalid launch record"))
            .transpose()
    }

    pub fn work(&self, id: &str) -> Result<Option<WorkRecord>> {
        let text: Option<String> = self
            .db
            .query_row("SELECT record FROM work WHERE id=?1", [id], |r| r.get(0))
            .optional()?;
        text.map(|s| serde_json::from_str(&s).context("invalid work record"))
            .transpose()
    }

    pub fn message(&self, id: &str) -> Result<Option<MessageRecord>> {
        let text: Option<String> = self
            .db
            .query_row("SELECT record FROM messages WHERE id=?1", [id], |r| {
                r.get(0)
            })
            .optional()?;
        text.map(|s| serde_json::from_str(&s).context("invalid message record"))
            .transpose()
    }

    /// Progress is recovered from the same work records the scheduler updates.
    pub fn message_receipt(&self, record: &MessageRecord) -> Result<MessageReceipt> {
        let mut receipt = record.receipt.clone();
        for RecipientReceipt {
            recipient_id,
            delivery,
        } in &mut receipt.recipients
        {
            if matches!(delivery, Delivery::Work { .. }) {
                let work = self
                    .work(recipient_id)?
                    .ok_or_else(|| anyhow!("missing message work"))?;
                *delivery = Delivery::Work {
                    work: (&work.status).into(),
                };
            }
        }
        Ok(receipt)
    }

    /// The immutable envelope, local recipient decisions and all executable
    /// deliveries become durable together. No acknowledgment precedes commit.
    pub fn accept_message(&self, record: &MessageRecord, work: &[WorkRecord]) -> Result<()> {
        self.accept_message_with(record, work, |_| Ok(()))
    }

    pub(super) fn accept_message_with(
        &self,
        record: &MessageRecord,
        work: &[WorkRecord],
        extra: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<()>,
    ) -> Result<()> {
        let tx = self.db.unchecked_transaction()?;
        let count = open_records(&tx, "messages")?;
        let tasks = open_records(&tx, "work")?;
        let active: usize = tx.query_row(UNFINISHED, [], |r| r.get(0))?;
        if count >= MAX_RECORDS
            || tasks + work.len() > MAX_RECORDS
            || active + work.len() > MAX_QUEUED
        {
            bail!("message receipt capacity reached");
        }
        tx.execute(
            "INSERT INTO messages(id,record) VALUES(?1,?2)",
            params![record.message.message_id, serde_json::to_string(record)?],
        )?;
        for r in work {
            tx.execute(
                "INSERT INTO work(id,record,state) VALUES(?1,?2,'queued')",
                params![r.task.task_id, serde_json::to_string(r)?],
            )?;
        }
        extra(&tx)?;
        tx.commit()?;
        Ok(())
    }

    /// The records `sql` reads (one `record` column; `params`).
    fn records<T: serde::de::DeserializeOwned>(
        &self,
        sql: &str,
        params: impl rusqlite::Params,
    ) -> Result<Vec<T>> {
        let mut q = self.db.prepare(sql)?;
        q.query_map(params, |r| r.get::<_, String>(0))?
            .map(|r| Ok(serde_json::from_str(&r?)?))
            .collect()
    }

    /// The launches still open (`open_records`), oldest first: every one
    /// still starting among them.
    pub fn open_launches(&self) -> Result<Vec<LaunchRecord>> {
        self.records(OPEN_LAUNCHES, [])
    }

    /// The tasks `sql` reads (an `id` and a `record` column; `params`), in
    /// its order. One whose record can't be read is left out
    /// (`fail_unreadable`).
    fn tasks(&self, sql: &str, params: impl rusqlite::Params) -> Result<Vec<WorkRecord>> {
        let rows: Vec<(String, String)> = {
            let mut q = self.db.prepare(sql)?;
            q.query_map(params, |r| Ok((r.get(0)?, record_text(r, 1)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        let mut tasks = Vec::with_capacity(rows.len());
        for (id, text) in rows {
            match serde_json::from_str(&text) {
                Ok(task) => tasks.push(task),
                Err(_) => self.fail_unreadable(&id)?,
            }
        }
        Ok(tasks)
    }

    /// Task `id`'s record; `None` when it can't be read
    /// (`fail_unreadable`).
    fn readable_work(&self, id: &str) -> Result<Option<WorkRecord>> {
        let text = self
            .db
            .query_row("SELECT record FROM work WHERE id=?1", [id], |r| {
                record_text(r, 0)
            })
            .optional()?
            .ok_or_else(|| anyhow!("missing work record"))?;
        match serde_json::from_str(&text) {
            Ok(task) => Ok(Some(task)),
            Err(_) => {
                self.fail_unreadable(id)?;
                Ok(None)
            }
        }
    }

    /// A task whose record this build can't read (not JSON, or not a task
    /// it knows: damage, or another build's record) never fails a pass.
    /// Unsettled, it fails (`RECORD_UNREADABLE`, in its record's `status`
    /// when the record is a JSON object; other bytes stay as they are) and
    /// its return grant ends. Settled or not, it is closed at once
    /// (`closed_records`), so no pass reads it again, and its row stays.
    /// One runtime.log line names it.
    pub(super) fn fail_unreadable(&self, id: &str) -> Result<()> {
        let tx = self
            .db
            .is_autocommit()
            .then(|| self.db.unchecked_transaction())
            .transpose()?;
        let failed = self.db.execute(
            "UPDATE work SET state='failed', record=CASE
                WHEN json_valid(record) AND json_type(record)='object'
                THEN json_set(record,'$.status.state','failed','$.status.detail',?2)
                ELSE record END
            WHERE id=?1 AND state IN
            ('queued','blocked','submitting','submitted','awaiting_result','outcome_unknown')",
            params![id, RECORD_UNREADABLE],
        )? == 1;
        if failed {
            self.db.execute(
                "UPDATE return_grants SET state='ended' WHERE task_id=?1 AND state IN ('open','consumed')",
                [id],
            )?;
            // A delegated task's alert ends with it (`failed`).
            self.end_alert(&self.db, id)?;
        }
        self.db
            .execute("DELETE FROM grant_dues WHERE task_id=?1", [id])?;
        let closed = self
            .db
            .execute("DELETE FROM open_records WHERE kind='work' AND id=?1", [id])?
            == 1;
        self.db.execute(
            "INSERT OR IGNORE INTO closed_records(kind,id,at_ms) VALUES('work',?1,?2)",
            params![id, crate::session_protocol::membership::host_now().wall_ms],
        )?;
        if let Some(tx) = tx {
            tx.commit()?;
        }
        if failed || closed {
            eprintln!(
                "atem runtime: host work: task {id}: its record can't be read; {} (record kept)",
                if failed {
                    "failed, \"record unreadable\""
                } else {
                    "closed"
                }
            );
        }
        Ok(())
    }

    /// The tasks still open (`open_records`), oldest first: every one not
    /// settled, and those settled less than a day past their deadline.
    pub fn open_tasks(&self) -> Result<Vec<WorkRecord>> {
        self.tasks(OPEN_TASKS, [])
    }

    /// The tasks in `state`, oldest first, through the `work_state` index.
    pub fn tasks_in(&self, state: WorkState) -> Result<Vec<WorkRecord>> {
        let state = serde_json::to_value(state)?;
        self.tasks(TASKS_IN, [state.as_str()])
    }

    /// The tasks that hold, or wait for, a place in their session's queue
    /// (`UNFINISHED`, at most `MAX_QUEUED`), oldest first. A task of unknown
    /// outcome holds its session's queue too, but isn't read here: there may
    /// be thousands (`holds_unknown_outcome`).
    pub fn active_tasks(&self) -> Result<Vec<WorkRecord>> {
        self.tasks(
            "SELECT id,record FROM work WHERE state IN ('queued','blocked','submitting','submitted') ORDER BY rowid",
            [],
        )
    }

    /// A task of unknown outcome holds `session_id`'s queue (until it
    /// expires or a reply proves its turn ran; a delegated one until its
    /// deadline, design I.4.6), through `work_waits`.
    pub fn holds_unknown_outcome(&self, session_id: &str) -> Result<bool> {
        Ok(self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM work_waits WHERE session_id=?1 AND state='outcome_unknown')",
            [session_id],
            |r| r.get(0),
        )?)
    }

    fn capacity(&self, table: &str) -> Result<()> {
        if open_records(&self.db, table)? >= MAX_RECORDS {
            bail!("host work receipt capacity reached");
        }
        Ok(())
    }

    pub fn reserve_launch(&self, record: &LaunchRecord) -> Result<bool> {
        if let Some(old) = self.launch(&record.status.request_id)? {
            if old.principal != record.principal || old.digest != record.digest {
                bail!("request_id_reused");
            }
            return Ok(false);
        }
        self.capacity("launches")?;
        self.db.execute(
            "INSERT INTO launches(id,record) VALUES(?1,?2)",
            params![record.status.request_id, serde_json::to_string(record)?],
        )?;
        Ok(true)
    }

    pub fn save_launch(&self, record: &LaunchRecord) -> Result<()> {
        if self.db.execute(
            "UPDATE launches SET record=?2 WHERE id=?1",
            params![record.status.request_id, serde_json::to_string(record)?],
        )? != 1
        {
            bail!("missing launch reservation");
        }
        Ok(())
    }

    /// Another task fits: within the record and the active queue capacity.
    pub fn has_room(&self) -> Result<bool> {
        let tasks = open_records(&self.db, "work")?;
        let active: usize = self.db.query_row(UNFINISHED, [], |r| r.get(0))?;
        Ok(tasks < MAX_RECORDS && active < MAX_QUEUED)
    }

    pub fn enqueue(&self, record: &WorkRecord) -> Result<bool> {
        if let Some(old) = self.work(&record.task.task_id)? {
            if old.principal != record.principal || old.digest != record.digest {
                bail!("request_id_reused");
            }
            return Ok(false);
        }
        self.capacity("work")?;
        let active: usize = self.db.query_row(UNFINISHED, [], |r| r.get(0))?;
        if active >= MAX_QUEUED {
            bail!("task queue is full");
        }
        let state = serde_json::to_value(record.status.state)?;
        self.db.execute(
            "INSERT INTO work(id,record,state) VALUES(?1,?2,?3)",
            params![
                record.task.task_id,
                serde_json::to_string(record)?,
                state.as_str().unwrap()
            ],
        )?;
        Ok(true)
    }

    /// Tasks awaiting their result or whose outcome is unknown expire at
    /// their deadline, whoever sent them and whatever became of their reply
    /// or return grant (spec section 10), so none waits, or holds its
    /// session's queue, forever; before it, one whose sender's authorization
    /// expired fails (`AUTHORIZATION_EXPIRED`). Read by `work_waits`' due
    /// time, so a pass reads only what is due. A record that can't be read
    /// (`work_waits` has no deadline for it, so it is due at once) is
    /// settled as such (`fail_unreadable`). Returns how many settled.
    ///
    /// A delegated task (one with an admission record) compares its deadline
    /// with the delegated clock instead (`now_d`, §11.6 "Deadline
    /// comparisons"; without a reading, the wall clock, which `D` never
    /// trails), and no authorization expiry fails it (design I.2: expiry
    /// stops new requests only). v1 rows are read by the wall clock and
    /// delegated ones by `D`, each through an index on its due time
    /// (`work_waits.delegated`), so a pass with `D` ahead reads no v1 row
    /// before its time. A delegated task of unknown outcome doesn't expire
    /// (design I.4.6, §11.6 "Unknown outcomes"): at its deadline it stops
    /// holding its session, its detail `deadline passed; outcome unknown`,
    /// and stays `outcome_unknown`, unresolved, with its alert, until it is
    /// resolved or a reply moves it (`deadline_passed`: its `work_waits` row
    /// goes, so no pass reads it again).
    pub fn settle_due(&self, now: u64, now_d: Option<u64>) -> Result<usize> {
        let d = now_d.unwrap_or(now);
        let mut due = Vec::new();
        let mut take = |sql: &str, params: &[&dyn rusqlite::ToSql]| -> Result<()> {
            let mut q = self.db.prepare(sql)?;
            let rows = q.query_map(params, |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    vec![r.get(1)?, r.get(2)?],
                    r.get::<_, bool>(3)?,
                    r.get::<_, String>(4)?,
                ))
            })?;
            for row in rows {
                let (id, values, delegated, state) = row?;
                match waiting(values) {
                    None => due.push((id, Some(RECORD_UNREADABLE))),
                    Some((deadline, _)) if delegated => {
                        if d >= deadline {
                            let unknown = state == "outcome_unknown";
                            due.push((id, unknown.then_some(DEADLINE_PASSED_OUTCOME_UNKNOWN)));
                        }
                    }
                    Some((deadline, _)) if now >= deadline => due.push((id, None)),
                    Some((_, accepted))
                        if accepted
                            .authorization_expires_at
                            .is_some_and(|at| now >= at) =>
                    {
                        due.push((id, Some(AUTHORIZATION_EXPIRED)))
                    }
                    Some(_) => {}
                }
            }
            Ok(())
        };
        // Due by the wall clock: v1's rows, and delegated ones `D` (never
        // behind the wall clock) settles too.
        take(DUE_BY_WALL, &[&now])?;
        // Delegated rows due by `D` only, through their own index: no v1 row
        // due between the wall clock and `D` is read.
        if d > now {
            take(DUE_BY_D, &[&now, &d])?;
        }
        self.settle(due)
    }

    /// Delegated tasks awaiting their result whose deadline `D` reached
    /// (design I.6.2 step 6, at a start's recovery): expired, as
    /// `settle_due` expires them, through the delegated rows' due index.
    /// The tasks it expired.
    pub fn settle_awaiting_delegated(&self, d: u64) -> Result<Vec<String>> {
        let mut q = self.db.prepare(
            "SELECT id,expires_at,authorization_expires_at FROM work_waits
            WHERE delegated=1 AND due_ms<=?1 AND state='awaiting_result'",
        )?;
        let rows = q.query_map([d], |r| {
            Ok((r.get::<_, String>(0)?, vec![r.get(1)?, r.get(2)?]))
        })?;
        let mut due = Vec::new();
        for row in rows {
            let (id, values) = row?;
            match waiting(values) {
                None => due.push((id, Some(RECORD_UNREADABLE))),
                Some((deadline, _)) if d >= deadline => due.push((id, None)),
                Some(_) => {}
            }
        }
        let expired = due
            .iter()
            .filter(|(_, why)| why.is_none())
            .map(|(id, _)| id.clone())
            .collect();
        self.settle(due)?;
        Ok(expired)
    }

    /// Whether an open task is a delegated sender's: the store then needs
    /// the delegated clock, whatever the hook says now (step 4, Decision
    /// 10). Read through `open_records`, so closed records cost nothing.
    pub fn has_delegated(&self) -> Result<bool> {
        Ok(self.db.query_row(
            "SELECT EXISTS(SELECT 1 FROM open_records o CROSS JOIN work w ON w.id=o.id
            WHERE o.kind='work' AND json_extract(w.record,'$.delegated') IS NOT NULL)",
            [],
            |r| r.get(0),
        )?)
    }

    /// Before its deadline, a task awaiting its result or of unknown
    /// outcome that `lost` names a reason for (from what it was accepted
    /// under: its sender's authority, its route and profile approval) fails
    /// with it, and its return grant ends: its sender can't complete it, nor
    /// its agent answer it. Nothing is resubmitted. It reads every such task
    /// (the columns `work_waits` keeps, never a record), so it runs only
    /// when what `lost` depends on changed. Returns how many settled.
    pub fn settle_lost(
        &self,
        now: u64,
        mut lost: impl FnMut(&Accepted) -> Option<&'static str>,
    ) -> Result<usize> {
        let mut due = Vec::new();
        {
            // A delegated task has its own rules (design I.3.3: awaiting and
            // unknown ones are kept) and its deadline is `settle_due`'s, on
            // the delegated clock: never v1's.
            let mut q = self.db.prepare(
                "SELECT id,expires_at,principal,control_gen,authorization_expires_at,
                route_id,route_revision,profile_id,profile_revision,project FROM work_waits
                WHERE delegated=0",
            )?;
            let rows = q.query_map([], |r| {
                let values = [1, 4, 2, 3, 5, 6, 7, 8, 9]
                    .into_iter()
                    .map(|i| r.get(i))
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                Ok((r.get::<_, String>(0)?, values))
            })?;
            for row in rows {
                let (id, values) = row?;
                match waiting(values) {
                    None => due.push((id, Some(RECORD_UNREADABLE))),
                    Some((deadline, _)) if now >= deadline => due.push((id, None)),
                    Some((_, accepted)) => {
                        if let Some(why) = lost(&accepted) {
                            due.push((id, Some(why)));
                        }
                    }
                }
            }
        }
        self.settle(due)
    }

    /// `settle_due`, then `settle_lost`.
    #[cfg(test)]
    pub fn settle_overdue(
        &self,
        now: u64,
        lost: impl FnMut(&Accepted) -> Option<&'static str>,
    ) -> Result<usize> {
        Ok(self.settle_due(now, None)? + self.settle_lost(now, lost)?)
    }

    /// Expires each of `due` (no reason) or fails it with its reason; an
    /// open return grant ends with an expired task, an open or consumed one
    /// with a failed task; a record that can't be read is settled as such
    /// (`fail_unreadable`). A delegated task of unknown outcome at its
    /// deadline (`DEADLINE_PASSED_OUTCOME_UNKNOWN`) settles nothing: it
    /// stops holding its session, with that detail, and stays
    /// `outcome_unknown` with its alert (design I.4.6). Writes only what is
    /// due; returns how many.
    fn settle(&self, due: Vec<(String, Option<&'static str>)>) -> Result<usize> {
        if due.is_empty() {
            return Ok(0);
        }
        let tx = self.db.unchecked_transaction()?;
        for (id, why) in &due {
            if *why == Some(RECORD_UNREADABLE) {
                self.fail_unreadable(id)?;
                continue;
            }
            let Some(mut record) = self.readable_work(id)? else {
                continue;
            };
            if *why == Some(DEADLINE_PASSED_OUTCOME_UNKNOWN) {
                record.deadline_passed = true;
                record.status.detail = DEADLINE_PASSED_OUTCOME_UNKNOWN.into();
                self.save_work(&record)?;
                continue;
            }
            let end = match why {
                Some(why) => {
                    record.status.state = WorkState::Failed;
                    record.status.detail = (*why).into();
                    "UPDATE return_grants SET state='ended'
                    WHERE task_id=?1 AND state IN ('open','consumed')"
                }
                None => {
                    record.status.detail = if record.status.state == WorkState::OutcomeUnknown {
                        EXPIRED_UNKNOWN
                    } else {
                        EXPIRED_AWAITING
                    }
                    .into();
                    record.status.state = WorkState::Expired;
                    "UPDATE return_grants SET state='ended' WHERE task_id=?1 AND state='open'"
                }
            };
            self.save_work(&record)?;
            tx.execute(end, [id])?;
        }
        tx.commit()?;
        Ok(due.len())
    }

    /// The principals of every task in the store in `state` not settled yet
    /// (its sender's authority over it still matters), read without opening
    /// it for writing; none when there is no store yet.
    pub fn named_principals_at(state: &Path) -> Result<HashSet<String>> {
        let path = state.join("host-work.sqlite");
        if !path.exists() {
            return Ok(HashSet::new());
        }
        let db = Connection::open_with_flags(
            &path,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        let mut q = db.prepare(NAMED_PRINCIPALS)?;
        q.query_map([], |r| r.get::<_, String>(0))?
            .map(|r| Ok(r?))
            .collect()
    }

    /// The open records due to close at `cutoff` (`open_records`; a closed
    /// one is never read again): tasks completed, failed, cancelled or
    /// expired whose reply is no longer publishing and whose reply's
    /// carrier (the task delivering it to its local sender) settled too;
    /// messages whose tasks all settled; local sends never accepted
    /// (refused or expired); launches no longer starting. Every task of a
    /// message has the message's deadline (`Message::task`, the local
    /// `local_task`), and a reply's carrier its task's.
    fn payloads_due(&self, cutoff: u64) -> Result<Due> {
        let ids = |sql: &str| -> Result<Vec<String>> {
            let mut q = self.db.prepare(sql)?;
            let ids = q
                .query_map([cutoff], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            Ok(ids)
        };
        let mut messages = ids(DUE_MESSAGES)?;
        messages.extend(ids(DUE_SENDS)?);
        Ok(Due {
            tasks: ids(DUE_TASKS)?,
            messages,
            launches: ids(DUE_LAUNCHES)?,
        })
    }

    /// Closes what settled a day past its deadline (`PAYLOAD_RETENTION_MS`,
    /// `payloads_due`): its payloads go and every record stays, so every
    /// query and retry is answered as before, but it no longer counts
    /// toward `MAX_RECORDS`. Payloads: a task's prompt and context text
    /// (`WorkRecord::drop_payload`) with its reply's text and context
    /// (`Reply::drop_payload`), except a delegated task's reply once its
    /// task settled: that is kept 30 days after the settling, in its own
    /// budget (design I.4.7; `kept_bytes`, `drop_kept_replies`), the task
    /// closed all the same; a message's text and context text, and those
    /// of its local outbox envelope and publication; the uploads that only
    /// closed tasks name (their bytes and cached PNG; the tasks keep their
    /// descriptors). A launch carries none. Each record leaves
    /// `open_records` and gets its `closed_records` marker in the same
    /// transaction. A live task is never touched, nor what it needs; an
    /// upload no task ever named stays (its own bound holds it). Returns
    /// whose payloads it dropped.
    pub fn drop_payloads(&self, now: u64) -> Result<Dropped> {
        let due = self.payloads_due(now.saturating_sub(PAYLOAD_RETENTION_MS))?;
        if due == Due::default() {
            return Ok(Dropped::default());
        }
        // `self.work`, `self.save_work` and `self.message` run on the same
        // connection, inside this transaction.
        let tx = self.db.unchecked_transaction()?;
        let text = |sql: &str, id: &str| -> Result<Option<String>> {
            Ok(tx.query_row(sql, [id], |r| r.get(0)).optional()?)
        };
        let close = |table: &str, id: &str| -> Result<()> {
            tx.execute(
                "DELETE FROM open_records WHERE kind=?1 AND id=?2",
                params![table, id],
            )?;
            tx.execute(
                "INSERT OR IGNORE INTO closed_records(kind,id,at_ms) VALUES(?1,?2,?3)",
                params![table, id, now],
            )?;
            Ok(())
        };
        let mut uploads = BTreeSet::new();
        for id in &due.tasks {
            // One that can't be read is closed as it is.
            let Some(mut record) = self.readable_work(id)? else {
                continue;
            };
            record.drop_payload();
            self.save_work(&record)?;
            let reply = tx
                .query_row(
                    "SELECT record,retain_until_ms FROM results WHERE task_id=?1",
                    [id],
                    |r| Ok((r.get::<_, String>(0)?, r.get::<_, Option<u64>>(1)?)),
                )
                .optional()?;
            if let Some((reply, until)) = reply {
                let mut reply: super::collab::results::Reply = serde_json::from_str(&reply)?;
                if record.delegated.is_some() && until.is_some_and(|u| u > now) && !reply.dropped {
                    // A delegated task's reply, its task settled: kept 30
                    // days after that (design I.4.7), in the kept replies'
                    // own budget (`drop_kept_replies`).
                    tx.execute(
                        "UPDATE results SET kept_bytes=?2 WHERE task_id=?1",
                        params![id, reply.payload_bytes()],
                    )?;
                } else {
                    reply.drop_payload();
                    tx.execute(
                        "UPDATE results SET record=?2 WHERE task_id=?1",
                        params![id, serde_json::to_string(&reply)?],
                    )?;
                }
            }
            for a in &record.task.attachments {
                uploads.insert((record.attachment_owner.clone(), a.attachment_id.clone()));
            }
            close("work", id)?;
        }
        for id in &due.messages {
            if let Some(mut record) = self.message(id)? {
                drop_message_payload(&mut record.message);
                tx.execute(
                    "UPDATE messages SET record=?2 WHERE id=?1",
                    params![id, serde_json::to_string(&record)?],
                )?;
                close("messages", id)?;
            }
            if let Some(envelope) = text("SELECT envelope FROM outbox WHERE message_id=?1", id)? {
                let mut envelope: Message = serde_json::from_str(&envelope)?;
                drop_message_payload(&mut envelope);
                tx.execute(
                    "UPDATE outbox SET envelope=?2 WHERE message_id=?1",
                    params![id, serde_json::to_string(&envelope)?],
                )?;
                close("outbox", id)?;
            }
            if let Some(publication) =
                text("SELECT record FROM publications WHERE message_id=?1", id)?
            {
                let mut publication: super::collab::Publication =
                    serde_json::from_str(&publication)?;
                publication.drop_payload();
                tx.execute(
                    "UPDATE publications SET record=?2 WHERE message_id=?1",
                    params![id, serde_json::to_string(&publication)?],
                )?;
            }
        }
        for id in &due.launches {
            close("launches", id)?;
        }
        // An upload goes once no open task names it.
        let mut removed = Vec::new();
        for (owner, id) in uploads {
            let named: bool = tx.query_row(NAMED_UPLOAD, params![owner, id], |r| r.get(0))?;
            if !named
                && tx.execute(
                    "DELETE FROM attachments WHERE owner=?1 AND id=?2",
                    params![owner, id],
                )? == 1
            {
                removed.push((owner, id));
            }
        }
        // The verified cache files of removed uploads go first, so no crash
        // leaves one behind (a prompt that needs one rebuilds it from the
        // database).
        for (owner, id) in &removed {
            if valid_owner(owner) && atem_client::session::wire::is_uuid_v4(id) {
                let _ = std::fs::remove_file(
                    self.state
                        .join("attachments")
                        .join(owner)
                        .join(format!("{id}.png")),
                );
            }
        }
        tx.commit()?;
        Ok(Dropped {
            tasks: due.tasks.len(),
            messages: due.messages.len(),
            uploads: removed.len(),
        })
    }

    /// The delegated replies kept past their task's payload drop
    /// (`drop_payloads`, design I.4.7): those whose 30 days after their task
    /// settled passed (`KEPT_REPLY_MS`) drop their text and context, as a
    /// v1 reply's drop; then, while the rest hold more than `budget` bytes,
    /// the oldest go first, before their time. Records, digests and states
    /// stay.
    pub fn drop_kept_replies(&self, now: u64, budget: u64) -> Result<KeptDropped> {
        let tx = self.db.unchecked_transaction()?;
        let drop = |id: &str| -> Result<()> {
            let record: String =
                tx.query_row("SELECT record FROM results WHERE task_id=?1", [id], |r| {
                    r.get(0)
                })?;
            let mut reply: super::collab::results::Reply = serde_json::from_str(&record)?;
            reply.drop_payload();
            tx.execute(
                "UPDATE results SET record=?2,kept_bytes=NULL WHERE task_id=?1",
                params![id, serde_json::to_string(&reply)?],
            )?;
            Ok(())
        };
        let kept = |sql: &str, values: &[u64]| -> Result<Vec<(String, u64)>> {
            let mut q = tx.prepare(sql)?;
            let rows = q.query_map(rusqlite::params_from_iter(values), |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?;
            Ok(rows.collect::<rusqlite::Result<_>>()?)
        };
        let expired = kept(KEPT_DUE, &[now])?;
        for (id, _) in &expired {
            drop(id)?;
        }
        let mut total: u64 = tx.query_row(KEPT_TOTAL, [], |r| r.get(0))?;
        let mut early = 0;
        while total > budget {
            let Some((id, bytes)) = kept(KEPT_OLDEST, &[])?.pop() else {
                break;
            };
            drop(&id)?;
            total = total.saturating_sub(bytes);
            early += 1;
        }
        tx.commit()?;
        Ok(KeptDropped {
            expired: expired.len(),
            early,
        })
    }

    /// Writes the task. Its return grant, if it has one the change may
    /// concern (open or consumed, or ended while the task waits for its
    /// result), is due at once (`grant_dues`: `collab_result_pass` takes it
    /// on its next pass), so no pass has to read grants nothing happened to.
    /// A delegated task's alert follows its state in the same transaction
    /// (`track_alert`: raised when it becomes `outcome_unknown`, ended when
    /// it leaves it or is resolved; host-work-v1 §11.3), in the caller's
    /// transaction or, without one, in its own.
    pub fn save_work(&self, record: &WorkRecord) -> Result<()> {
        let tx = (record.delegated.is_some() && self.db.is_autocommit())
            .then(|| self.db.unchecked_transaction())
            .transpose()?;
        self.write_work(record)?;
        if let Some(tx) = tx {
            tx.commit()?;
        }
        Ok(())
    }

    fn write_work(&self, record: &WorkRecord) -> Result<()> {
        let state = serde_json::to_value(record.status.state)?;
        if self.db.execute(
            "UPDATE work SET record=?2,state=?3 WHERE id=?1",
            params![
                record.task.task_id,
                serde_json::to_string(record)?,
                state.as_str().unwrap()
            ],
        )? != 1
        {
            bail!("missing work reservation");
        }
        let waits = matches!(
            record.status.state,
            WorkState::AwaitingResult | WorkState::OutcomeUnknown
        );
        self.db.execute(
            "INSERT OR REPLACE INTO grant_dues(task_id,due_ms) SELECT task_id,0 FROM return_grants
            WHERE task_id=?1 AND (state IN ('open','consumed') OR ?2)",
            params![record.task.task_id, waits],
        )?;
        // A delegated task settled: its reply, if it has one (or once it
        // has: a reply after a `failed` resolution is written with its
        // task), is kept 30 days from now (design I.4.7). Once only.
        if record.delegated.is_some()
            && matches!(
                record.status.state,
                WorkState::Completed
                    | WorkState::Failed
                    | WorkState::Cancelled
                    | WorkState::Expired
            )
        {
            self.db.execute(
                "UPDATE results SET retain_until_ms=?2 WHERE task_id=?1 AND retain_until_ms IS NULL",
                params![
                    record.task.task_id,
                    crate::session_protocol::membership::host_now()
                        .wall_ms
                        .saturating_add(KEPT_REPLY_MS)
                ],
            )?;
        }
        self.track_alert(&self.db, record)
    }

    /// At a start: a launch still starting is started (its worker is
    /// live) or of unknown outcome, and a task found submitting is of unknown
    /// outcome; neither is ever retried. Identities stay for the life of
    /// the database (`drop_payloads` drops payloads only), so a retry is
    /// always answered from its record, never turned into new work. A
    /// delegated task (one with an admission record) is left to its own
    /// recovery, by its attempt's receipt (design I.6.3, the bridge's
    /// `recover_delegated`): its attempt may be proven never run.
    pub fn recover(
        &self,
        sessions: &BTreeMap<crate::session::SessionId, super::broker::BrokerSession>,
    ) -> Result<()> {
        // A launch still starting is open (it closes only once settled).
        for mut record in self.open_launches()? {
            if record.status.state != LaunchState::Starting {
                continue;
            }
            let session = crate::session::SessionId::parse(&record.status.session_id)
                .and_then(|id| sessions.get(&id));
            record.status.state = if session
                .is_some_and(|s| s.process_gen == record.status.process_gen && s.is_live())
            {
                LaunchState::Started
            } else {
                LaunchState::OutcomeUnknown
            };
            self.save_launch(&record)?;
        }
        for mut record in self.tasks_in(WorkState::Submitting)? {
            if record.delegated.is_some() {
                continue;
            }
            record.status.state = WorkState::OutcomeUnknown;
            record.status.detail =
                "submission interrupted; recover its receipt before any further action".into();
            self.save_work(&record)?;
        }
        Ok(())
    }
}

pub const EXAMPLE: &str = include_str!("../../configs/runtime.example.toml");

/// Create the disabled configuration once, without replacing existing approvals.
pub fn ensure_config(dir: &Path) -> Result<bool> {
    use std::io::Write;
    super::worker::private_dir(dir)?;
    let path = dir.join(CONFIG_FILE);
    match std::fs::symlink_metadata(&path) {
        Ok(_) => {
            Config::load(dir)?;
            return Ok(false);
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let mut file = tempfile::NamedTempFile::new_in(dir)?;
    file.write_all(EXAMPLE.as_bytes())?;
    file.as_file().sync_all()?;
    // Publish the complete file atomically; concurrent starts keep the winner.
    let created = match file.persist_noclobber(&path) {
        Ok(_) => true,
        Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => false,
        Err(error) => return Err(error.error.into()),
    };
    if created {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Config::load(dir)?;
    Ok(created)
}

/// What `atem runtime check` checks, as this build reads it: the file, then
/// each profile's directory, project and environment file. Prints nothing;
/// `atem runtime restart` and a replacement by another build run it first.
pub fn validate(dir: &Path) -> Result<Config> {
    let config = Config::load(dir)?;
    for profile in &config.profiles {
        profile
            .launch(
                crate::session::SessionId::new().to_string(),
                uuid::Uuid::new_v4().to_string(),
            )
            .with_context(|| format!("checking profile `{}`", profile.id))?;
    }
    Ok(config)
}

pub fn check(dir: &Path) -> Result<()> {
    let paired = paired_member(dir);
    let config = validate(dir)?;
    println!("Instance labels: {}", config.instance.labels.join(", "));
    println!(
        "Collaboration: {}; per_hour = {}; per_workflow = {}; result_timeout = {}",
        if !config.enabled {
            "inactive (agent hosting is disabled)"
        } else if config.collab.send {
            "enabled"
        } else {
            "disabled"
        },
        config.collab.per_hour,
        config.collab.per_workflow,
        config.collab.result_timeout
    );
    println!(
        "Agent hosting: {}",
        if config.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    let named = |list: &[String]| -> String {
        list.iter()
            .map(|p| {
                if Some(p) == paired.as_ref() {
                    format!("{p} (paired Astation)")
                } else {
                    p.clone()
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    };
    for profile in &config.profiles {
        println!(
            "  {}: {} in {} (revision {}); may launch: {}",
            profile.id,
            profile.provider,
            profile.cwd.display(),
            profile.revision,
            named(&profile.principals)
        );
    }
    println!("{} notification route(s).", config.routes.len());
    for route in &config.routes {
        println!(
            "  {} -> {}; may send: {}",
            route.id,
            route.profile_id,
            named(&route.principals)
        );
        println!(
            "    labels: {}; launch: {}; results: {}; auto_report: {}",
            route.labels.join(", "),
            match route.launch {
                RouteLaunch::Off => "off",
                RouteLaunch::OnMessage => "on_message",
            },
            route.results,
            match route.auto_report {
                AutoReport::Status => "status",
                AutoReport::FinalMessage => "final_message",
            }
        );
    }
    let pairing = crate::paths::ProfilePaths::in_dir(dir).pairing;
    match crate::session_protocol::membership::passive_principals(&pairing) {
        Some(principals) => {
            println!("Principals in this account's device list:");
            for (principal, what, launch) in principals {
                let note = if Some(&principal) == paired.as_ref() {
                    "; the paired Astation"
                } else {
                    ""
                };
                println!(
                    "  {principal}  {what}; {}{note}",
                    if launch {
                        "may launch"
                    } else {
                        "may not launch"
                    }
                );
            }
        }
        None => println!("No device list on this host yet (pair and verify with Astation)."),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use atem_client::session::host_work::digest;
    use atem_client::session::wire::Target;
    use std::os::unix::fs::{PermissionsExt, symlink};

    fn host() -> HostTarget {
        HostTarget {
            account_id: "account".into(),
            atem_device_id: "host".into(),
            host_trust_gen: 1,
        }
    }
    fn launch() -> LaunchRecord {
        LaunchRecord {
            principal: "member:phone".into(),
            profile_id: "backend".into(),
            profile_revision: 1,
            expires_at: 100,
            digest: digest(b"request"),
            status: LaunchStatus {
                request_id: uuid::Uuid::new_v4().to_string(),
                session_id: crate::session::SessionId::new().to_string(),
                process_gen: uuid::Uuid::new_v4().to_string(),
                state: LaunchState::Starting,
            },
        }
    }
    fn task() -> WorkRecord {
        let task_id = uuid::Uuid::new_v4().to_string();
        WorkRecord {
            delegated: None,
            deadline_passed: false,
            principal: "member:phone".into(),
            attachment_owner: String::new(),
            control_gen: 1,
            authorization_expires_at: None,
            message: None,
            route_id: "backend".into(),
            route_revision: 1,
            profile_id: "backend".into(),
            profile_revision: 1,
            project: "local:home".into(),
            digest: digest(b"task"),
            task: WorkTask {
                attachments: vec![],
                task_id: task_id.clone(),
                workflow_id: uuid::Uuid::new_v4().to_string(),
                target: Target {
                    account_id: "account".into(),
                    atem_device_id: "host".into(),
                    host_trust_gen: 1,
                    session_id: crate::session::SessionId::new().to_string(),
                    process_gen: uuid::Uuid::new_v4().to_string(),
                },
                expires_at: 100,
                prompt: "build API".into(),
                context: vec![ContextSnapshot {
                    kind: ContextKind::Vault,
                    id: "contract".into(),
                    version: 1,
                    digest: digest(b"API"),
                    text: "API".into(),
                }],
            },
            status: WorkStatus {
                task_id,
                receipt_id: uuid::Uuid::new_v4().to_string(),
                state: WorkState::Queued,
                detail: String::new(),
                result: None,
                resolved: None,
            },
            turn_id: None,
        }
    }

    #[test]
    fn launch_reservation_survives_reopen_and_conflicting_retries_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let record = launch();
        let store = Store::open(dir.path()).unwrap();
        store.bind(&host()).unwrap();
        assert!(store.reserve_launch(&record).unwrap());
        assert!(!store.reserve_launch(&record).unwrap());
        let mut changed = record.clone();
        changed.digest = digest(b"changed");
        assert!(store.reserve_launch(&changed).is_err());
        changed = record.clone();
        changed.principal = "service:other".into();
        assert!(store.reserve_launch(&changed).is_err());
        drop(store);
        let store = Store::open(dir.path()).unwrap();
        assert!(!store.reserve_launch(&record).unwrap());
        store.recover(&BTreeMap::new()).unwrap();
        assert_eq!(
            store
                .launch(&record.status.request_id)
                .unwrap()
                .unwrap()
                .status
                .state,
            LaunchState::OutcomeUnknown
        );
        assert!(!store.reserve_launch(&record).unwrap());
        let mut other = host();
        other.host_trust_gen += 1;
        assert!(store.bind(&other).is_err());
    }

    #[test]
    fn a_database_of_another_host_identity_is_moved_aside_and_kept() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(store.bound().unwrap(), None);
        store.bind(&host()).unwrap();
        assert!(store.enqueue(&task()).unwrap());
        assert_eq!(store.bound().unwrap(), Some(host()));
        let aside = store.retire(1).unwrap();
        assert_eq!(aside.parent(), Some(dir.path()));
        assert_eq!(
            std::fs::metadata(&aside).unwrap().permissions().mode() & 0o777,
            0o600
        );

        let mut other = host();
        other.host_trust_gen += 1;
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(store.bound().unwrap(), None);
        store.bind(&other).unwrap();
        assert!(store.open_tasks().unwrap().is_empty());

        let kept = Connection::open(&aside).unwrap();
        let identity: String = kept
            .query_row("SELECT host FROM identity WHERE id=1", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            serde_json::from_str::<HostTarget>(&identity).unwrap(),
            host()
        );
        let tasks: i64 = kept
            .query_row("SELECT count(*) FROM work", [], |r| r.get(0))
            .unwrap();
        assert_eq!(tasks, 1);
    }

    #[test]
    fn queue_deduplicates_and_never_replays_interrupted_dispatch_intent() {
        let dir = tempfile::tempdir().unwrap();
        let mut record = task();
        let store = Store::open(dir.path()).unwrap();
        assert!(store.enqueue(&record).unwrap());
        assert!(!store.enqueue(&record).unwrap());
        let mut changed = record.clone();
        changed.digest = digest(b"different task");
        assert!(store.enqueue(&changed).is_err());
        record.status.state = WorkState::Submitting;
        store.save_work(&record).unwrap();
        drop(store);
        let store = Store::open(dir.path()).unwrap();
        store.recover(&BTreeMap::new()).unwrap();
        assert_eq!(
            store
                .work(&record.task.task_id)
                .unwrap()
                .unwrap()
                .status
                .state,
            WorkState::OutcomeUnknown
        );
        assert!(!store.enqueue(&record).unwrap());
    }

    /// `n` tasks awaiting their result, written directly (the queue's own
    /// bound plays no part in making them).
    fn awaiting(store: &Store, n: usize) -> Vec<String> {
        (0..n)
            .map(|_| {
                let mut r = task();
                r.status.state = WorkState::AwaitingResult;
                store
                    .db
                    .execute(
                        "INSERT INTO work(id,record,state) VALUES(?1,?2,'awaiting_result')",
                        params![r.task.task_id, serde_json::to_string(&r).unwrap()],
                    )
                    .unwrap();
                r.task.task_id
            })
            .collect()
    }

    /// A task awaiting its result holds no session, agent or queue slot
    /// (spec section 10): more of them than the queue takes still leave room
    /// for a remote enqueue, a local send and a result delivery. The record
    /// bound and their expiry bound them.
    #[test]
    fn tasks_awaiting_a_result_hold_no_queue_slot() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store.bind(&host()).unwrap();
        awaiting(&store, MAX_QUEUED + 1);
        assert!(store.has_room().unwrap(), "a result delivery fits");
        assert!(store.enqueue(&task()).unwrap(), "a remote enqueue fits");
        let work = task();
        let message = Message {
            kind: Default::default(),
            reply_to: None,
            from_session: Some(crate::session::SessionId::new().to_string()),
            mark: None,
            message_id: uuid::Uuid::new_v4().to_string(),
            workflow_id: work.task.workflow_id.clone(),
            sender: "local".into(),
            created_at: 1,
            expires_at: 100,
            text: "a local send".into(),
            context: vec![],
            recipients: vec![],
        };
        let record = MessageRecord {
            sender_key: serde_json::json!("local"),
            message: message.clone(),
            receipt: MessageReceipt {
                message_id: message.message_id.clone(),
                digest: message.digest(),
                sender: "local".into(),
                recipients: vec![],
            },
        };
        store.accept_message(&record, &[work]).unwrap();
        // Unfinished work still has its bound.
        for _ in 2..MAX_QUEUED {
            assert!(store.enqueue(&task()).unwrap());
        }
        assert!(!store.has_room().unwrap());
        assert!(store.enqueue(&task()).is_err());
    }

    /// Every task awaiting its result expires at its deadline, whoever sent
    /// it and whatever became of its return grant (open, consumed by a
    /// delivery, or ended).
    #[test]
    fn tasks_awaiting_a_result_expire_at_their_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let grants = ["open", "consumed", "ended"];
        let mut ids = Vec::new();
        for n in 0..MAX_QUEUED {
            let mut r = task();
            if n % 4 > 0 {
                r.principal = "local".into();
            }
            // One waits longer than the others.
            r.task.expires_at = if n == 7 { 2_000 } else { 1_000 };
            assert!(store.enqueue(&r).unwrap());
            r.status.state = WorkState::AwaitingResult;
            r.status.detail = "reply submitted".into();
            store.save_work(&r).unwrap();
            if n % 4 > 0 {
                store
                    .db
                    .execute(
                        "INSERT INTO return_grants(task_id,record,state) VALUES(?1,'{}',?2)",
                        params![r.task.task_id, grants[n % 4 - 1]],
                    )
                    .unwrap();
            }
            ids.push(r.task.task_id);
        }
        assert_eq!(store.settle_overdue(999, |_| None).unwrap(), 0);
        assert_eq!(
            store.settle_overdue(1_000, |_| None).unwrap(),
            MAX_QUEUED - 1
        );
        for (n, id) in ids.iter().enumerate() {
            let r = store.work(id).unwrap().unwrap();
            if n == 7 {
                assert_eq!(r.status.state, WorkState::AwaitingResult);
                continue;
            }
            assert_eq!(
                (r.status.state, r.status.detail.as_str()),
                (WorkState::Expired, "expired awaiting a result"),
                "task {n}"
            );
        }
        // An open grant ends with its task; the others stay as they were.
        let grant = |id: &str| -> String {
            store
                .db
                .query_row(
                    "SELECT state FROM return_grants WHERE task_id=?1",
                    [id],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert_eq!(grant(&ids[1]), "ended");
        assert_eq!(grant(&ids[2]), "consumed");
        assert_eq!(grant(&ids[3]), "ended");
        assert!(store.enqueue(&task()).unwrap());
        // Nothing more is due: nothing is written.
        assert_eq!(store.settle_overdue(1_999, |_| None).unwrap(), 0);
        assert_eq!(store.settle_overdue(2_000, |_| None).unwrap(), 1);
    }

    /// The admission record of a task of [`task`]'s sender, a native
    /// member: a delegated sender's.
    fn admission() -> crate::runtime::delegated::Admission {
        use crate::runtime::delegated::{Admission, DelegatedSender};
        Admission {
            principal: "member:phone".into(),
            principal_key: "ab".repeat(32),
            sender: DelegatedSender::Native {
                device_id: "phone".into(),
            },
            feed: None,
            route_id: "backend".into(),
            route_revision: 1,
            ops_at_admission: vec!["notify".into(), "prompt".into()],
            scope_at_admission: serde_json::Value::Null,
            grant_expires_at: None,
            device_list_seq: 3,
            projects_matched: vec![],
        }
    }

    /// A task awaiting its result, delegated or not, due at `expires_at`
    /// (its authorization expiring at `auth`), written directly.
    fn waiting_task(store: &Store, delegated: bool, expires_at: u64, auth: Option<u64>) -> String {
        let mut r = task();
        r.task.expires_at = expires_at;
        r.authorization_expires_at = auth;
        r.status.state = WorkState::AwaitingResult;
        r.delegated = delegated.then(admission);
        store
            .db
            .execute(
                "INSERT INTO work(id,record,state) VALUES(?1,?2,'awaiting_result')",
                params![r.task.task_id, serde_json::to_string(&r).unwrap()],
            )
            .unwrap();
        r.task.task_id
    }

    /// Task 19 review M7: `work_waits` keeps whether a task is delegated,
    /// so `settle_due` takes v1 rows by the wall clock and delegated rows by
    /// the delegated clock's `D`, each through an index on its due time: with
    /// `D` ahead, a v1 row due between the wall clock and `D` is never read,
    /// and a delegated row is due at its deadline only (its authorization
    /// expiry ends nothing, design I.2).
    #[test]
    fn settle_due_takes_v1_rows_by_the_wall_clock_and_delegated_rows_by_d() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let v1 = [
            waiting_task(&store, false, 1_500, None),
            waiting_task(&store, false, 1_500, None),
        ];
        let delegated = waiting_task(&store, true, 1_500, Some(900));
        let state = |id: &str| store.work(id).unwrap().unwrap().status.state;
        let due: Vec<(String, i64, i64)> = {
            let mut q = store
                .db
                .prepare("SELECT id,due_ms,delegated FROM work_waits ORDER BY id")
                .unwrap();
            q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        for (id, due_ms, flag) in due {
            assert_eq!(due_ms, 1_500, "{id}: its deadline");
            assert_eq!(flag == 1, id == delegated, "{id}");
        }
        // Both statements read through an index, never the whole table.
        for sql in [DUE_BY_WALL, DUE_BY_D] {
            let plan: Vec<String> = store
                .db
                .prepare(&format!("EXPLAIN QUERY PLAN {sql}"))
                .unwrap()
                .query_map(
                    rusqlite::params_from_iter(std::iter::repeat_n(0, sql.matches('?').count())),
                    |r| r.get(3),
                )
                .unwrap()
                .map(Result::unwrap)
                .collect();
            assert!(
                plan.iter().all(|step| step.starts_with("SEARCH")),
                "{sql}: {plan:?}"
            );
        }
        assert_eq!(store.settle_due(1_000, Some(1_400)).unwrap(), 0);
        assert_eq!(store.settle_due(1_000, Some(2_000)).unwrap(), 1);
        assert_eq!(state(&delegated), WorkState::Expired);
        assert!(v1.iter().all(|id| state(id) == WorkState::AwaitingResult));
        assert_eq!(store.settle_due(1_500, None).unwrap(), 2);
    }

    /// The `delegated` column is additive: a store whose `work_waits` has
    /// none (this branch before Task 19's review) gets it when it opens,
    /// filled from the records, and its triggers keep it from then on.
    #[test]
    fn work_waits_gains_its_delegated_column_when_a_store_opens() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let delegated = waiting_task(&store, true, 1_500, Some(900));
        store
            .db
            .execute_batch(
                "DROP INDEX work_waits_delegated;
                DROP TRIGGER work_waits_opened;
                DROP TRIGGER work_waits_changed;
                ALTER TABLE work_waits DROP COLUMN delegated;
                UPDATE work_waits SET due_ms=900;",
            )
            .unwrap();
        drop(store);
        let store = Store::open(dir.path()).unwrap();
        let row = |id: &str| -> (i64, i64) {
            store
                .db
                .query_row(
                    "SELECT due_ms,delegated FROM work_waits WHERE id=?1",
                    [id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .unwrap()
        };
        assert_eq!(row(&delegated), (1_500, 1));
        let v1 = waiting_task(&store, false, 1_500, Some(900));
        assert_eq!(row(&v1), (900, 0));
    }

    /// A task whose outcome is unknown (a restart in its turn, a launch of
    /// unknown outcome) expires at its deadline too: it holds its session's
    /// queue until then, never for good, and nothing is resubmitted. Its
    /// open return grant ends with it.
    #[test]
    fn a_task_with_an_unknown_outcome_expires_at_its_deadline() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let mut r = task();
        r.principal = "local".into();
        r.task.expires_at = 1_000;
        assert!(store.enqueue(&r).unwrap());
        r.status.state = WorkState::OutcomeUnknown;
        r.status.detail = "submission interrupted".into();
        store.save_work(&r).unwrap();
        store
            .db
            .execute(
                "INSERT INTO return_grants(task_id,record,state) VALUES(?1,'{}','open')",
                [&r.task.task_id],
            )
            .unwrap();
        assert_eq!(store.settle_overdue(999, |_| None).unwrap(), 0);
        let session = r.task.target.session_id.clone();
        assert!(store.holds_unknown_outcome(&session).unwrap());
        assert!(
            store.active_tasks().unwrap().is_empty(),
            "none read per pass"
        );
        assert_eq!(store.settle_due(999, None).unwrap(), 0);
        assert_eq!(store.settle_due(1_000, None).unwrap(), 1);
        let expired = store.work(&r.task.task_id).unwrap().unwrap();
        assert_eq!(
            (expired.status.state, expired.status.detail.as_str()),
            (WorkState::Expired, "expired with its outcome unknown")
        );
        assert!(!store.holds_unknown_outcome(&session).unwrap());
        let grant: String = store
            .db
            .query_row(
                "SELECT state FROM return_grants WHERE task_id=?1",
                [&r.task.task_id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(grant, "ended");
    }

    /// A delegated task (or a v1 one) of unknown outcome on `session`, its
    /// deadline `expires_at`, its detail `write interrupted`: its id.
    fn unknown_on(store: &Store, session: &str, delegated: bool, expires_at: u64) -> String {
        let mut r = task();
        r.task.target.session_id = session.into();
        r.task.expires_at = expires_at;
        r.delegated = delegated.then(admission);
        assert!(store.enqueue(&r).unwrap());
        r.status.state = WorkState::OutcomeUnknown;
        r.status.detail = "write interrupted".into();
        store.save_work(&r).unwrap();
        r.task.task_id
    }

    /// The ids `work_waits` has a row for.
    fn wait_rows(store: &Store) -> Vec<String> {
        let mut q = store
            .db
            .prepare("SELECT id FROM work_waits ORDER BY id")
            .unwrap();
        q.query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    /// Design I.4.6, host-work-v1 §11.6 ("Unknown outcomes"): at its
    /// deadline on the delegated clock, a delegated task of unknown outcome
    /// doesn't expire: it stops holding its session (`work_waits` has no row
    /// for it any more), its detail `deadline passed; outcome unknown`,
    /// written once; no later pass reads or writes it. A v1 task of unknown
    /// outcome on the same session expires at its deadline on the wall
    /// clock, as before.
    #[test]
    fn a_delegated_unknown_outcome_stops_holding_at_its_deadline_a_v1_one_expires() {
        use crate::runtime::delegated::details::DEADLINE_PASSED_OUTCOME_UNKNOWN;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let session = crate::session::SessionId::new().to_string();
        let delegated = unknown_on(&store, &session, true, 1_500);
        let v1 = unknown_on(&store, &session, false, 1_500);
        let state = |id: &str| {
            let r = store.work(id).unwrap().unwrap();
            (r.status.state, r.status.detail)
        };
        let mut both = vec![delegated.clone(), v1.clone()];
        both.sort();
        assert_eq!(wait_rows(&store), both);
        assert!(store.holds_unknown_outcome(&session).unwrap());
        // `D` reaches the deadline, the wall clock doesn't.
        assert_eq!(store.settle_due(1_000, Some(1_500)).unwrap(), 1);
        assert_eq!(
            state(&delegated),
            (
                WorkState::OutcomeUnknown,
                DEADLINE_PASSED_OUTCOME_UNKNOWN.into()
            )
        );
        assert!(store.work(&delegated).unwrap().unwrap().deadline_passed);
        assert_eq!(
            state(&v1),
            (WorkState::OutcomeUnknown, "write interrupted".into())
        );
        assert_eq!(wait_rows(&store), vec![v1.clone()]);
        assert!(store.holds_unknown_outcome(&session).unwrap(), "the v1 one");
        // The wall clock reaches it: the v1 one expires; the delegated one
        // isn't read again.
        let before: String = store
            .db
            .query_row("SELECT record FROM work WHERE id=?1", [&delegated], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(store.settle_due(1_500, Some(9_000)).unwrap(), 1);
        assert_eq!(state(&v1), (WorkState::Expired, EXPIRED_UNKNOWN.into()));
        assert!(!store.holds_unknown_outcome(&session).unwrap());
        assert!(wait_rows(&store).is_empty());
        assert_eq!(store.settle_due(9_000, Some(9_000)).unwrap(), 0);
        let after: String = store
            .db
            .query_row("SELECT record FROM work WHERE id=?1", [&delegated], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(after, before);
        // A v1 record is written as before: no new field.
        assert!(!after.is_empty());
        let v1_record: String = store
            .db
            .query_row("SELECT record FROM work WHERE id=?1", [&v1], |r| r.get(0))
            .unwrap();
        assert!(!v1_record.contains("deadline_passed"), "{v1_record}");
    }

    /// `work_waits`' triggers change additively too: a store whose triggers
    /// keep a row for a delegated task of unknown outcome past its deadline
    /// (this branch before Task 23) gets them made again when it opens, and
    /// its rows refilled from the records, once.
    #[test]
    fn work_waits_triggers_without_the_deadline_rule_are_made_again() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let session = crate::session::SessionId::new().to_string();
        let id = unknown_on(&store, &session, true, 1_500);
        assert_eq!(store.settle_due(1_000, Some(1_500)).unwrap(), 1);
        assert!(wait_rows(&store).is_empty());
        // The update trigger as it was: every task awaiting its result or of
        // unknown outcome gets a row.
        store
            .db
            .execute_batch(
                "DROP TRIGGER work_waits_changed;
                CREATE TRIGGER work_waits_changed AFTER UPDATE ON work BEGIN
                    DELETE FROM work_waits WHERE id=OLD.id;
                    INSERT INTO work_waits(id,state,due_ms,session_id,delegated)
                    SELECT NEW.id,NEW.state,1500,json_extract(NEW.record,'$.task.target.session_id'),1
                    WHERE NEW.state IN ('awaiting_result','outcome_unknown');
                END;",
            )
            .unwrap();
        store.save_work(&store.work(&id).unwrap().unwrap()).unwrap();
        assert_eq!(wait_rows(&store), vec![id.clone()]);
        assert!(store.holds_unknown_outcome(&session).unwrap());
        drop(store);
        let store = Store::open(dir.path()).unwrap();
        assert!(wait_rows(&store).is_empty());
        assert!(!store.holds_unknown_outcome(&session).unwrap());
        store.save_work(&store.work(&id).unwrap().unwrap()).unwrap();
        assert!(wait_rows(&store).is_empty());
        // Opened again: nothing to make again.
        drop(store);
        let store = Store::open(dir.path()).unwrap();
        assert!(wait_rows(&store).is_empty());
    }

    /// Design I.4.6 ("Capacity"), host-work-v1 §11.6: a delegated task of
    /// unknown outcome that nobody resolved drops its prompt and context a
    /// day after its deadline, with the upload only it names, and stops
    /// being an open record (it no longer counts toward `MAX_RECORDS`). It
    /// stays `outcome_unknown`, unresolved, with its alert, and can still be
    /// resolved. A day less a millisecond after it, nothing goes.
    #[test]
    fn an_unresolved_task_drops_payloads_a_day_after_its_deadline_and_keeps_its_alert() {
        use crate::runtime::delegated::details;
        use crate::runtime::delegated::resolve::resolve;
        use atem_client::session::attachments::Attachment;
        use atem_client::session::host_work::Resolution;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let owner = digest(b"phone");
        let upload = Attachment {
            attachment_id: uuid::Uuid::new_v4().to_string(),
            digest: digest(b"png"),
            size: 68,
            media_type: "image/png".into(),
        };
        let mut r = task();
        r.delegated = Some(admission());
        r.attachment_owner = owner.clone();
        r.task.attachments = vec![upload.clone()];
        r.task.expires_at = 1_000;
        assert!(store.enqueue(&r).unwrap());
        store
            .db
            .execute(
                "INSERT INTO attachments(owner,id,descriptor,size,bytes) VALUES(?1,?2,?3,68,x'00')",
                params![
                    owner,
                    upload.attachment_id,
                    serde_json::to_string(&upload).unwrap()
                ],
            )
            .unwrap();
        r.status.state = WorkState::OutcomeUnknown;
        r.status.detail = details::AGENT_EXITED.into();
        store.save_work(&r).unwrap();
        let id = r.task.task_id.clone();
        let unresolved = (
            WorkState::OutcomeUnknown,
            details::DEADLINE_PASSED_OUTCOME_UNKNOWN.to_string(),
            None,
        );
        let now = |store: &Store| {
            let w = store.work(&id).unwrap().unwrap();
            (w.status.state, w.status.detail, w.status.resolved)
        };
        let uploads = |store: &Store| -> u32 {
            store
                .db
                .query_row("SELECT count(*) FROM attachments", [], |r| r.get(0))
                .unwrap()
        };
        // Its deadline, on the delegated clock: unresolved, holding nothing.
        assert_eq!(store.settle_due(900, Some(1_000)).unwrap(), 1);
        assert_eq!(now(&store), unresolved);
        // A day after it, less a millisecond: nothing goes.
        assert_eq!(
            store
                .drop_payloads(1_000 + PAYLOAD_RETENTION_MS - 1)
                .unwrap(),
            Dropped::default()
        );
        assert_eq!(store.work(&id).unwrap().unwrap().task.prompt, "build API");
        assert_eq!(open_records(&store.db, "work").unwrap(), 1);
        // A day after it.
        assert_eq!(
            store.drop_payloads(1_000 + PAYLOAD_RETENTION_MS).unwrap(),
            Dropped {
                tasks: 1,
                messages: 0,
                uploads: 1,
            }
        );
        let kept = store.work(&id).unwrap().unwrap();
        assert_eq!(kept.task.prompt, "");
        assert_eq!(kept.task.context[0].text, "");
        assert_eq!(kept.task.context[0].digest, digest(b"API"));
        assert_eq!(kept.task.attachments, vec![upload]);
        assert_eq!(uploads(&store), 0);
        assert_eq!(open_records(&store.db, "work").unwrap(), 0);
        assert_eq!(now(&store), unresolved);
        // Its alert stays, with its reason.
        assert_eq!(
            store.unresolved().unwrap(),
            (1, BTreeMap::from([("member:phone".to_string(), 1)]))
        );
        let (alerts, more) = store.alert_page(None, 64).unwrap();
        assert!(!more);
        assert_eq!(
            alerts
                .iter()
                .map(|a| (a.task_id.as_str(), a.reason.as_str()))
                .collect::<Vec<_>>(),
            [(id.as_str(), details::AGENT_EXITED)]
        );
        // Later passes leave it so.
        assert_eq!(
            store.drop_payloads(5 * PAYLOAD_RETENTION_MS).unwrap(),
            Dropped::default()
        );
        assert_eq!(store.settle_due(5 * PAYLOAD_RETENTION_MS, None).unwrap(), 0);
        assert_eq!(now(&store), unresolved);
        // It can still be resolved, which ends its alert.
        let tx = store.immediate().unwrap();
        let resolved = resolve(
            &store,
            &tx,
            &id,
            "member:phone",
            &Resolution::Failed {
                detail: "given up".into(),
            },
            2_000,
        )
        .unwrap();
        tx.commit().unwrap();
        assert_eq!(
            (resolved.state, resolved.detail.as_str()),
            (WorkState::Failed, "given up")
        );
        assert_eq!(store.unresolved().unwrap().0, 0);
    }

    /// A task of `delegated` (or a v1 one) whose deadline is at 1 000, with
    /// the reply `text` its agent submitted, its memory reference and its
    /// published context, as `collab_reply` and the publication pass commit
    /// it; the task then awaits its result. Its id.
    fn replied(store: &Store, delegated: bool, text: &str) -> String {
        use crate::runtime::collab::results::{self, Binding, Reply, ResultRow, Submission};
        use crate::runtime::collab_context::ContextSpec;
        let mut r = task();
        r.task.expires_at = 1_000;
        r.delegated = delegated.then(admission);
        assert!(store.enqueue(&r).unwrap());
        let reply = Reply {
            binding: Binding {
                task_id: r.task.task_id.clone(),
                session_id: r.task.target.session_id.clone(),
                process_gen: r.task.target.process_gen.clone(),
                turn_id: "turn-1".into(),
            },
            text: text.into(),
            references: vec![ContextSpec::Memory {
                memory: Box::new(memory()),
            }],
            context: vec![],
            dropped: false,
        };
        let tx = store.db.unchecked_transaction().unwrap();
        let row = ResultRow::new(reply, 500);
        assert!(matches!(
            results::submit(&tx, &row).unwrap(),
            Submission::Stored(_)
        ));
        results::published(
            &tx,
            &r.task.task_id,
            vec![snapshot("the reply's context")],
            600,
        )
        .unwrap();
        r.status.state = WorkState::AwaitingResult;
        store.save_work(&r).unwrap();
        tx.commit().unwrap();
        r.task.task_id
    }

    /// The task `id` written `state`, as the lifecycle writes it (its
    /// sender's `work_complete`, a resolution, its expiry).
    fn settle_as(store: &Store, id: &str, state: WorkState) {
        let mut r = store.work(id).unwrap().unwrap();
        r.status.state = state;
        store.save_work(&r).unwrap();
    }

    /// When the reply of `id` may drop (`results.retain_until_ms`).
    fn retain_until(store: &Store, id: &str) -> Option<u64> {
        store
            .db
            .query_row(
                "SELECT retain_until_ms FROM results WHERE task_id=?1",
                [id],
                |r| r.get(0),
            )
            .unwrap()
    }

    /// The reply of `id` as stored: its text, its context's text, its
    /// memory reference's text, whether it was dropped, its digest, state.
    fn reply_of(store: &Store, id: &str) -> (String, String, String, bool, String, String) {
        use crate::runtime::collab::results;
        use crate::runtime::collab_context::ContextSpec;
        let row = results::load(&store.db, id).unwrap().unwrap();
        let memory = match &row.reply.references[0] {
            ContextSpec::Memory { memory } => memory.content.clone(),
            other => panic!("{other:?}"),
        };
        (
            row.reply.text.clone(),
            row.reply.context[0].text.clone(),
            memory,
            row.reply.dropped,
            row.digest.clone(),
            row.state.as_str().to_string(),
        )
    }

    /// Design I.4.7 ("Retention"): a delegated task's reply text and context
    /// are kept 30 days after the task settles, past the day after its
    /// deadline when its task's own payloads go and the task closes (it is
    /// no open record then). A reply stored after its task settled (one
    /// after a `failed` resolution) is kept 30 days from then. Then they
    /// drop as a v1 reply's: its binding, digest and state stay. A v1
    /// task's reply goes with its task, as before; so does the reply of a
    /// delegated task not settled yet (unresolved), as today.
    #[test]
    fn delegated_reply_text_kept_30_days_after_settling() {
        use crate::runtime::delegated::details;
        use crate::session_protocol::membership::host_now;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let v1 = replied(&store, false, "the v1 reply");
        let delegated = replied(&store, true, "the delegated reply");
        let unresolved = replied(&store, true, "the unresolved one's reply");
        // Settled: completed by their senders; the unresolved one's outcome
        // became unknown (a reply refused at publication would leave it so).
        let before = host_now().wall_ms;
        settle_as(&store, &v1, WorkState::Completed);
        settle_as(&store, &delegated, WorkState::Completed);
        let after = host_now().wall_ms;
        let mut r = store.work(&unresolved).unwrap().unwrap();
        r.status.state = WorkState::OutcomeUnknown;
        r.status.detail = details::AGENT_EXITED.into();
        store.save_work(&r).unwrap();
        // A delegated task resolved `failed`, and the reply its agent
        // stored after that (design I.4.6): kept from when it was stored.
        let mut late = task();
        late.task.expires_at = 1_000;
        late.delegated = Some(admission());
        assert!(store.enqueue(&late).unwrap());
        late.status.state = WorkState::Failed;
        store.save_work(&late).unwrap();
        let late_id = late.task.task_id.clone();
        let stored_from = host_now().wall_ms;
        {
            use crate::runtime::collab::results::{self, Binding, Reply, ResultRow};
            let reply = Reply {
                binding: Binding {
                    task_id: late_id.clone(),
                    session_id: late.task.target.session_id.clone(),
                    process_gen: late.task.target.process_gen.clone(),
                    turn_id: "turn-1".into(),
                },
                text: "a reply after the resolution".into(),
                references: vec![],
                context: vec![],
                dropped: false,
            };
            let tx = store.db.unchecked_transaction().unwrap();
            results::submit(&tx, &ResultRow::new(reply, stored_from)).unwrap();
            store.save_work(&late).unwrap();
            tx.commit().unwrap();
        }
        let stored_to = host_now().wall_ms;
        // A v1 reply has no retention of its own, nor has an unsettled one.
        assert_eq!(retain_until(&store, &v1), None);
        assert_eq!(retain_until(&store, &unresolved), None);
        let until = retain_until(&store, &delegated).expect("kept from its settling");
        assert!(
            (before + KEPT_REPLY_MS..=after + KEPT_REPLY_MS).contains(&until),
            "{until}"
        );
        let late_until = retain_until(&store, &late_id).expect("kept from its storing");
        assert!(
            (stored_from + KEPT_REPLY_MS..=stored_to + KEPT_REPLY_MS).contains(&late_until),
            "{late_until}"
        );
        let delegated_digest = reply_of(&store, &delegated).4;
        // A day after their deadline: every task's own payloads go and the
        // tasks close; the v1 reply and the unresolved one's go with them,
        // the settled delegated replies stay whole.
        assert_eq!(
            store.drop_payloads(1_000 + PAYLOAD_RETENTION_MS).unwrap(),
            Dropped {
                tasks: 4,
                messages: 0,
                uploads: 0,
            }
        );
        assert_eq!(open_records(&store.db, "work").unwrap(), 0);
        for id in [&v1, &delegated, &unresolved, &late_id] {
            assert_eq!(store.work(id).unwrap().unwrap().task.prompt, "");
        }
        assert_eq!(
            reply_of(&store, &v1),
            (
                String::new(),
                String::new(),
                String::new(),
                true,
                reply_of(&store, &v1).4,
                "submitted".into()
            )
        );
        assert!(reply_of(&store, &unresolved).3, "dropped as today");
        let kept = (
            "the delegated reply".to_string(),
            "the reply's context".to_string(),
            "a remembered fact".to_string(),
            false,
            delegated_digest.clone(),
            "submitted".to_string(),
        );
        assert_eq!(reply_of(&store, &delegated), kept);
        let late_text = || {
            crate::runtime::collab::results::load(&store.db, &late_id)
                .unwrap()
                .unwrap()
                .reply
        };
        assert_eq!(late_text().text, "a reply after the resolution");
        // Until its 30 days pass, nothing more goes.
        assert_eq!(
            store
                .drop_kept_replies(until - 1, KEPT_REPLY_BUDGET)
                .unwrap(),
            KeptDropped::default()
        );
        assert_eq!(reply_of(&store, &delegated), kept);
        // Then it goes, as a v1 reply goes: its digest and state stay.
        assert_eq!(
            store.drop_kept_replies(until, KEPT_REPLY_BUDGET).unwrap(),
            KeptDropped {
                expired: usize::from(late_until <= until) + 1,
                early: 0,
            }
        );
        assert_eq!(
            reply_of(&store, &delegated),
            (
                String::new(),
                String::new(),
                String::new(),
                true,
                delegated_digest,
                "submitted".into()
            )
        );
        // The late one at its own time.
        store
            .drop_kept_replies(late_until, KEPT_REPLY_BUDGET)
            .unwrap();
        assert!(late_text().dropped);
        // Nothing is read again.
        assert_eq!(
            store
                .drop_kept_replies(late_until + KEPT_REPLY_MS, KEPT_REPLY_BUDGET)
                .unwrap(),
            KeptDropped::default()
        );
    }

    /// Design I.4.7 ("in their own bytes budget"), step 4's open question 3
    /// (64 MiB per host, the oldest dropped first): while the kept replies
    /// hold more than the budget, the oldest (the earliest settled) go
    /// first, before their 30 days, as many as it takes, and the drop says
    /// how many went early. Insertion order doesn't count: a reply stored
    /// first but settled later goes later. One whose 30 days passed counts
    /// as expired, never as early.
    #[test]
    fn retention_budget_drops_the_oldest_first() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let text = |c: char| c.to_string().repeat(10_000);
        // Stored a, b, c; settled b, c, a (oldest first: b).
        let (a, b, c) = (
            replied(&store, true, &text('a')),
            replied(&store, true, &text('b')),
            replied(&store, true, &text('c')),
        );
        for id in [&a, &b, &c] {
            settle_as(&store, id, WorkState::Completed);
        }
        let base = 50 * PAYLOAD_RETENTION_MS;
        for (id, at) in [(&b, base), (&c, base + 1), (&a, base + 2)] {
            store
                .db
                .execute(
                    "UPDATE results SET retain_until_ms=?2 WHERE task_id=?1",
                    params![id, at],
                )
                .unwrap();
        }
        store.drop_payloads(1_000 + PAYLOAD_RETENTION_MS).unwrap();
        let kept = |id: &str| !reply_of(&store, id).3;
        assert!(kept(&a) && kept(&b) && kept(&c));
        // Each holds a little over 10 000 bytes (its text, its context's
        // and its memory reference's): 25 000 holds two of them.
        let now = 2 * PAYLOAD_RETENTION_MS;
        assert_eq!(
            store.drop_kept_replies(now, 25_000).unwrap(),
            KeptDropped {
                expired: 0,
                early: 1
            }
        );
        assert!(!kept(&b) && kept(&c) && kept(&a), "the oldest went first");
        let gone = reply_of(&store, &b);
        assert_eq!((gone.0.as_str(), gone.5.as_str()), ("", "submitted"));
        // Within the budget: nothing more.
        assert_eq!(
            store.drop_kept_replies(now, 25_000).unwrap(),
            KeptDropped::default()
        );
        // A smaller budget: the next oldest.
        assert_eq!(
            store.drop_kept_replies(now, 15_000).unwrap(),
            KeptDropped {
                expired: 0,
                early: 1
            }
        );
        assert!(!kept(&c) && kept(&a));
        // Its 30 days passed: expired, not early.
        assert_eq!(
            store.drop_kept_replies(base + 2, 15_000).unwrap(),
            KeptDropped {
                expired: 1,
                early: 0
            }
        );
        assert!(!kept(&a));
        let total: u64 = store.db.query_row(KEPT_TOTAL, [], |r| r.get(0)).unwrap();
        assert_eq!(total, 0, "the kept total follows every drop");
        // None of its queries scans the kept table (the kept replies' own
        // index, the oldest by a walk a `LIMIT` stops).
        for sql in [KEPT_DUE, KEPT_TOTAL, KEPT_OLDEST] {
            let (steps, scans) = kept_table_scans(&store.db, sql);
            assert!(scans.is_empty(), "{sql}: {steps:?}");
        }
    }

    /// A task whose record this build can't read never fails a pass: it is
    /// settled once (failed, "record unreadable", in its status when the
    /// record is a JSON object, other bytes kept as they are), its return
    /// grant ends and it is closed, so nothing reads it again. Not JSON, or
    /// an object without a deadline: at once; a shape this build doesn't
    /// know: at its deadline, or when the queue reads it. One that settled
    /// before it became unreadable is closed as it is when its payloads
    /// are due.
    #[test]
    fn a_task_whose_record_cant_be_read_is_settled_once() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        let mut ids = Vec::new();
        for (state, record) in [
            (WorkState::AwaitingResult, "'{not json'"),
            (WorkState::OutcomeUnknown, "'{\"x\":1}'"),
            (
                WorkState::AwaitingResult,
                "json_set(record,'$.status.state','nonsense')",
            ),
            (
                WorkState::Queued,
                "json_set(record,'$.status.state','nonsense')",
            ),
            (
                WorkState::Completed,
                "json_set(record,'$.status.state','nonsense')",
            ),
            (WorkState::Expired, "'{not json'"),
        ] {
            let mut r = task();
            r.task.expires_at = 1_000;
            assert!(store.enqueue(&r).unwrap());
            r.status.state = state;
            store.save_work(&r).unwrap();
            store
                .db
                .execute(
                    "INSERT INTO return_grants(task_id,record,state) VALUES(?1,'{}','open')",
                    [&r.task.task_id],
                )
                .unwrap();
            store
                .db
                .execute(
                    &format!("UPDATE work SET record={record} WHERE id=?1"),
                    [&r.task.task_id],
                )
                .unwrap();
            ids.push(r.task.task_id);
        }
        let column = |sql: &str, id: &str| -> Option<String> {
            store
                .db
                .query_row(sql, [id], |r| r.get(0))
                .optional()
                .unwrap()
        };
        let state = |id: &str| column("SELECT state FROM work WHERE id=?1", id).unwrap();
        let record = |id: &str| column("SELECT record FROM work WHERE id=?1", id).unwrap();
        let grant =
            |id: &str| column("SELECT state FROM return_grants WHERE task_id=?1", id).unwrap();
        let open = |id: &str| {
            column(
                "SELECT id FROM open_records WHERE kind='work' AND id=?1",
                id,
            )
            .is_some()
        };
        let detail = |id: &str| {
            let record: serde_json::Value = serde_json::from_str(&record(id)).unwrap();
            (
                record["status"]["state"].as_str().unwrap().to_string(),
                record["status"]["detail"].as_str().unwrap().to_string(),
            )
        };
        let unreadable = ("failed".to_string(), RECORD_UNREADABLE.to_string());
        // A reply still publishing for one that isn't JSON: the publication
        // pass reads past it.
        store
            .db
            .execute(
                "INSERT INTO results(task_id,result_id,state,detail,digest,created_ms,
                record,next_try_ms,attempts) VALUES(?1,?2,'publishing','','d',0,'{}',0,0)",
                params![ids[0], uuid::Uuid::new_v4().to_string()],
            )
            .unwrap();
        assert!(
            crate::runtime::collab::results::publishing_due(&store.db, 1, false)
                .unwrap()
                .is_empty()
        );
        // Not JSON, or an object without a deadline: at once, and once.
        assert_eq!(store.settle_overdue(999, |_| None).unwrap(), 2);
        assert_eq!(store.settle_overdue(999, |_| None).unwrap(), 0);
        for id in &ids[..2] {
            assert_eq!((state(id), grant(id)), ("failed".into(), "ended".into()));
            assert!(!open(id), "closed");
        }
        assert_eq!(record(&ids[0]), "{not json", "kept as it is");
        assert_eq!(detail(&ids[1]), unreadable);
        // A shape this build doesn't know, queued: when the queue is read.
        assert!(store.active_tasks().unwrap().is_empty());
        assert_eq!(
            (state(&ids[3]), grant(&ids[3])),
            ("failed".into(), "ended".into())
        );
        assert_eq!(detail(&ids[3]), unreadable);
        assert!(!open(&ids[3]));
        // Awaiting its result: at its deadline.
        assert_eq!(state(&ids[2]), "awaiting_result");
        assert_eq!(store.settle_due(1_000, None).unwrap(), 1);
        assert_eq!(detail(&ids[2]), unreadable);
        assert_eq!(grant(&ids[2]), "ended");
        // Settled before: closed as it is when its payloads are due (or
        // when the open tasks are read).
        assert!(open(&ids[4]) && open(&ids[5]));
        let before = record(&ids[4]);
        store.drop_payloads(1_000 + PAYLOAD_RETENTION_MS).unwrap();
        assert!(!open(&ids[4]) && !open(&ids[5]));
        assert_eq!(
            (state(&ids[4]), record(&ids[4]), grant(&ids[4])),
            ("completed".into(), before, "open".into())
        );
        assert_eq!(
            (state(&ids[5]), record(&ids[5])),
            ("expired".into(), "{not json".into())
        );
        assert!(store.open_tasks().unwrap().is_empty());
        assert_eq!(store.settle_overdue(2_000, |_| None).unwrap(), 0);
    }

    /// Before its deadline, a task awaiting its result or of unknown outcome
    /// whose sender's authority is gone fails with the reason given, its
    /// return grant ended whether open or consumed; the others stay. What
    /// the unsettled tasks name is read without opening the store for
    /// writing.
    #[test]
    fn tasks_whose_senders_authority_is_gone_fail() {
        let dir = tempfile::tempdir().unwrap();
        assert!(Store::named_principals_at(dir.path()).unwrap().is_empty());
        let store = Store::open(dir.path()).unwrap();
        let mut ids = Vec::new();
        for (principal, state, grant) in [
            ("service:gone", WorkState::AwaitingResult, "consumed"),
            ("service:gone", WorkState::OutcomeUnknown, "open"),
            ("member:kept", WorkState::AwaitingResult, "open"),
        ] {
            let mut r = task();
            r.principal = principal.into();
            assert!(store.enqueue(&r).unwrap());
            r.status.state = state;
            store.save_work(&r).unwrap();
            store
                .db
                .execute(
                    "INSERT INTO return_grants(task_id,record,state) VALUES(?1,'{}',?2)",
                    params![r.task.task_id, grant],
                )
                .unwrap();
            ids.push(r.task.task_id);
        }
        let mut asked = Vec::new();
        let settled = store
            .settle_overdue(99, |accepted| {
                asked.push(accepted.clone());
                (accepted.principal == "service:gone").then_some("gone")
            })
            .unwrap();
        assert_eq!(settled, 2);
        assert_eq!(asked.len(), 3);
        assert!(asked.contains(&store.work(&ids[2]).unwrap().unwrap().accepted()));
        for (n, id) in ids.iter().enumerate() {
            let r = store.work(id).unwrap().unwrap();
            let grant: String = store
                .db
                .query_row(
                    "SELECT state FROM return_grants WHERE task_id=?1",
                    [id],
                    |r| r.get(0),
                )
                .unwrap();
            if n < 2 {
                assert_eq!(
                    (r.status.state, r.status.detail.as_str()),
                    (WorkState::Failed, "gone")
                );
                assert_eq!(grant, "ended");
            } else {
                assert_eq!(r.status.state, WorkState::AwaitingResult);
                assert_eq!(grant, "open");
            }
        }
        assert_eq!(
            Store::named_principals_at(dir.path()).unwrap(),
            HashSet::from(["member:kept".to_string()])
        );
    }

    fn snapshot(text: &str) -> ContextSnapshot {
        ContextSnapshot {
            kind: ContextKind::Vault,
            id: "contract".into(),
            version: 1,
            digest: digest(text.as_bytes()),
            text: text.into(),
        }
    }

    fn memory() -> crate::memory::model::Memory {
        crate::memory::model::Memory {
            id: "mem_f00dbabe".into(),
            content: "a remembered fact".into(),
            content_hash: digest(b"a remembered fact"),
            ..Default::default()
        }
    }

    /// A message from `local`, to nobody in particular.
    fn envelope(expires_at: u64) -> Message {
        Message {
            kind: Default::default(),
            reply_to: None,
            from_session: Some(crate::session::SessionId::new().to_string()),
            mark: None,
            message_id: uuid::Uuid::new_v4().to_string(),
            workflow_id: uuid::Uuid::new_v4().to_string(),
            sender: "local".into(),
            created_at: 1,
            expires_at,
            text: "the message's text".into(),
            context: vec![snapshot("the message's context")],
            recipients: vec![],
        }
    }

    /// Rows a day past their deadline keep everything but their payloads
    /// once settled: a task's prompt and context text with its reply's
    /// text and context, a message's text and context text with its outbox
    /// envelope's and publication's, and the uploads that only such tasks
    /// name (bytes and cached PNG). Rows inside the margin, live tasks and
    /// what a live task needs (an upload, the reply its delivery carries) keep
    /// theirs. Nothing is deleted but upload bytes, and a second pass reads
    /// nothing it already dropped.
    #[test]
    fn settled_records_keep_everything_but_their_payloads_a_day_past_their_deadline() {
        use crate::runtime::collab::results::{self, Binding, Origin, Reply};
        use crate::runtime::collab_context::ContextSpec;
        use atem_client::session::attachments::Attachment;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store.bind(&host()).unwrap();
        let now = 10 * PAYLOAD_RETENTION_MS;
        let (old, recent) = (now - PAYLOAD_RETENTION_MS, now - PAYLOAD_RETENTION_MS + 1);
        let owner = digest(b"sender");
        let upload = |name: &[u8]| Attachment {
            attachment_id: uuid::Uuid::new_v4().to_string(),
            digest: digest(name),
            size: 68,
            media_type: "image/png".into(),
        };
        let put = |task: WorkRecord, state: WorkState| -> WorkRecord {
            let mut r = task;
            r.attachment_owner = owner.clone();
            r.status.state = state;
            let text = serde_json::to_value(state).unwrap();
            store
                .db
                .execute(
                    "INSERT INTO work(id,record,state) VALUES(?1,?2,?3)",
                    params![
                        r.task.task_id,
                        serde_json::to_string(&r).unwrap(),
                        text.as_str().unwrap()
                    ],
                )
                .unwrap();
            for a in &r.task.attachments {
                store
                    .db
                    .execute(
                        "INSERT OR IGNORE INTO attachments(owner,id,descriptor,size,bytes)
                        VALUES(?1,?2,?3,68,x'00')",
                        params![owner, a.attachment_id, serde_json::to_string(a).unwrap()],
                    )
                    .unwrap();
            }
            r
        };
        let due = |expires_at: u64, attachments: Vec<Attachment>| {
            let mut r = task();
            r.task.expires_at = expires_at;
            r.task.attachments = attachments;
            r
        };
        // A task's reply, as `atem message reply` commits it; its digest.
        let reply = |task: &WorkRecord, state: &str, carrier: Option<&str>| -> String {
            let reply = Reply {
                binding: Binding {
                    task_id: task.task.task_id.clone(),
                    session_id: task.task.target.session_id.clone(),
                    process_gen: task.task.target.process_gen.clone(),
                    turn_id: "turn-1".into(),
                },
                text: "the reply".into(),
                references: vec![ContextSpec::Memory {
                    memory: Box::new(memory()),
                }],
                context: vec![snapshot("the reply's context")],
                dropped: false,
            };
            store
                .db
                .execute(
                    "INSERT INTO results(task_id,result_id,state,detail,digest,created_ms,
                    submitted_at,record,next_try_ms,attempts,work_id)
                    VALUES(?1,?2,?3,'',?4,0,iif(?3='submitted',1,NULL),?5,0,0,?6)",
                    params![
                        task.task.task_id,
                        results::result_id(&task.task.task_id),
                        state,
                        reply.digest(),
                        serde_json::to_string(&reply).unwrap(),
                        carrier
                    ],
                )
                .unwrap();
            reply.digest()
        };
        let count = |table: &str| -> i64 {
            store
                .db
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                .unwrap()
        };
        let (gone_upload, kept_upload, unnamed_upload) =
            (upload(b"gone"), upload(b"kept"), upload(b"unnamed"));
        store
            .db
            .execute(
                "INSERT INTO attachments(owner,id,descriptor,size,bytes) VALUES(?1,?2,?3,68,x'00')",
                params![
                    owner,
                    unnamed_upload.attachment_id,
                    serde_json::to_string(&unnamed_upload).unwrap()
                ],
            )
            .unwrap();
        // Settled, a day past its deadline: its payloads go, its reply's
        // too, and the upload only it names.
        let settled = put(
            WorkRecord {
                // A message's task: its mark is the sender's text too.
                message: Some(MessageFrame {
                    message_id: uuid::Uuid::new_v4().to_string(),
                    mark: Some(atem_client::session::mark::MarkTask {
                        mark_id: "mark_1".into(),
                        url: "http://localhost:3000/".into(),
                        title: "the sender's title".into(),
                        screenshot: gone_upload.clone(),
                        annotations: vec![],
                    }),
                }),
                ..due(old, vec![gone_upload.clone(), kept_upload.clone()])
            },
            WorkState::Completed,
        );
        let id = settled.task.task_id.clone();
        let replied = reply(&settled, "submitted", None);
        for sql in [
            "INSERT INTO return_grants(task_id,record,state) VALUES(?1,'{}','ended')",
            "INSERT INTO resolutions(message_id,recipient_id,task_id,route_id,session_id,process_gen,record)
            VALUES('none','none',?1,'r','s','p','{}')",
        ] {
            store.db.execute(sql, [&id]).unwrap();
        }
        // Inside the margin, or live: kept. A live task keeps its upload.
        let inside = put(due(recent, vec![]), WorkState::Failed);
        let live = put(due(old, vec![kept_upload.clone()]), WorkState::Submitted);
        // Settled, but its reply still publishing, or carried by a delivery
        // still queued: kept.
        let publishing = put(due(old, vec![]), WorkState::Expired);
        reply(&publishing, "publishing", None);
        let carried = put(due(old, vec![]), WorkState::Expired);
        let delivery = put(due(old, vec![]), WorkState::Queued);
        reply(&carried, "submitted", Some(&delivery.task.task_id));
        // Messages: one whose tasks all settled loses its payload (its
        // outbox envelope's too); one with a live task keeps it. Their
        // settled tasks lose theirs either way.
        let message = |tasks: &[&WorkRecord]| -> String {
            let mut message = envelope(old);
            message.recipients = tasks
                .iter()
                .map(|t| atem_client::session::messages::Recipient {
                    recipient_id: t.task.task_id.clone(),
                    host: host(),
                    destination: atem_client::session::messages::Destination::Agent {
                        route_id: "backend".into(),
                        route_revision: 1,
                        target: t.task.target.clone(),
                    },
                })
                .collect();
            let record = MessageRecord {
                sender_key: serde_json::json!("local"),
                receipt: MessageReceipt {
                    message_id: message.message_id.clone(),
                    digest: message.digest(),
                    sender: "local".into(),
                    recipients: tasks
                        .iter()
                        .map(|t| RecipientReceipt {
                            recipient_id: t.task.task_id.clone(),
                            delivery: Delivery::Work {
                                work: (&t.status).into(),
                            },
                        })
                        .collect(),
                },
                message,
            };
            let id = record.message.message_id.clone();
            store
                .db
                .execute(
                    "INSERT INTO messages(id,record) VALUES(?1,?2)",
                    params![id, serde_json::to_string(&record).unwrap()],
                )
                .unwrap();
            store
                .db
                .execute(
                    "INSERT INTO outbox(message_id,envelope,state,detail,next_try_ms,created_ms)
                    VALUES(?1,?2,'accepted','',0,0)",
                    params![id, serde_json::to_string(&record.message).unwrap()],
                )
                .unwrap();
            store
                .db
                .execute(
                    "INSERT INTO origins(message_id,record) VALUES(?1,'{}')",
                    [&id],
                )
                .unwrap();
            for t in tasks {
                store
                    .db
                    .execute(
                        "INSERT INTO resolutions(message_id,recipient_id,task_id,route_id,
                        session_id,process_gen,record) VALUES(?1,'r',?2,'backend',?3,'p','{}')",
                        params![id, t.task.task_id, t.task.target.session_id],
                    )
                    .unwrap();
            }
            id
        };
        let finished = [
            put(due(old, vec![]), WorkState::Completed),
            put(due(old, vec![]), WorkState::Cancelled),
        ];
        reply(&finished[0], "submitted", None);
        let done = message(&[&finished[0], &finished[1]]);
        let held = [
            put(due(old, vec![]), WorkState::Expired),
            put(due(old, vec![]), WorkState::AwaitingResult),
        ];
        let waiting = message(&[&held[0], &held[1]]);
        // Local sends never accepted: a refused one loses its payload (its
        // publication's memory text too), one still publishing keeps it.
        let mut sends = Vec::new();
        for state in ["refused", "publishing"] {
            let message = envelope(old);
            let publication = crate::runtime::collab::Publication {
                atem_id: "atem-host".into(),
                origin: Origin {
                    target: settled.task.target.clone(),
                    control_gen: 1,
                    route: None,
                },
                launch: false,
                context: vec![ContextSpec::Memory {
                    memory: Box::new(memory()),
                }],
            };
            store
                .db
                .execute(
                    "INSERT INTO outbox(message_id,envelope,state,detail,next_try_ms,created_ms)
                    VALUES(?1,?2,?3,'',0,0)",
                    params![
                        message.message_id,
                        serde_json::to_string(&message).unwrap(),
                        state
                    ],
                )
                .unwrap();
            store
                .db
                .execute(
                    "INSERT INTO publications(message_id,record) VALUES(?1,?2)",
                    params![
                        message.message_id,
                        serde_json::to_string(&publication).unwrap()
                    ],
                )
                .unwrap();
            sends.push(message.message_id);
        }
        let mut l = launch();
        l.expires_at = old;
        l.status.state = LaunchState::Failed;
        assert!(store.reserve_launch(&l).unwrap());

        let receipt = store.message(&done).unwrap().unwrap().receipt;
        // The verified cache files of the uploads.
        let cache = |a: &Attachment| {
            let dir = dir.path().join("attachments").join(&owner);
            std::fs::create_dir_all(&dir).unwrap();
            dir.join(format!("{}.png", a.attachment_id))
        };
        for a in [&gone_upload, &kept_upload] {
            std::fs::write(cache(a), b"png").unwrap();
        }
        let tables = [
            "work",
            "results",
            "return_grants",
            "resolutions",
            "messages",
            "outbox",
            "origins",
            "publications",
            "launches",
        ];
        let rows: Vec<i64> = tables.iter().map(|t| count(t)).collect();
        // Nothing is due a millisecond earlier.
        assert_eq!(store.drop_payloads(now - 1).unwrap(), Dropped::default());
        assert_eq!(
            store.drop_payloads(now).unwrap(),
            Dropped {
                tasks: 4,
                messages: 2,
                uploads: 1,
            }
        );
        // Every record stays.
        assert_eq!(rows, tables.iter().map(|t| count(t)).collect::<Vec<_>>());
        let work = |r: &WorkRecord| store.work(&r.task.task_id).unwrap().unwrap();
        assert_eq!(
            work(&settled).message,
            Some(MessageFrame {
                message_id: settled.message.as_ref().unwrap().message_id.clone(),
                mark: None,
            }),
            "the mark goes, the message id stays"
        );
        for gone in [&settled, &finished[0], &finished[1], &held[0]] {
            let kept = work(gone);
            assert_eq!(kept.task.prompt, "", "{}", gone.task.task_id);
            assert_eq!(kept.task.context[0].text, "");
            assert_eq!(kept.task.context[0].digest, gone.task.context[0].digest);
            assert_eq!(kept.task.attachments, gone.task.attachments);
            assert_eq!(kept.status, gone.status);
            assert_eq!(kept.digest, gone.digest);
        }
        for kept in [&inside, &live, &publishing, &carried, &delivery, &held[1]] {
            assert_eq!(work(kept).task, kept.task, "{}", kept.task.task_id);
        }
        let stored_reply =
            |r: &WorkRecord| results::load(&store.db, &r.task.task_id).unwrap().unwrap();
        let row = stored_reply(&settled);
        assert!(row.reply.dropped);
        assert_eq!(
            (row.reply.text.as_str(), row.digest.as_str(), row.state),
            ("", replied.as_str(), results::ReplyState::Submitted)
        );
        assert_eq!(row.reply.context[0].text, "");
        assert_eq!(row.reply.context[0].digest, digest(b"the reply's context"));
        let ContextSpec::Memory { memory: m } = &row.reply.references[0] else {
            panic!("a memory reference");
        };
        assert_eq!(
            (m.content.as_str(), m.content_hash.as_str()),
            ("", memory().content_hash.as_str())
        );
        let wire = row.wire();
        assert!(wire.dropped && wire.text.is_empty() && wire.context.is_empty());
        assert!(wire.valid());
        for kept in [&publishing, &carried] {
            let row = stored_reply(kept);
            assert!(!row.reply.dropped);
            assert_eq!(row.reply.text, "the reply");
        }
        let message_text = |id: &str| {
            let record = store.message(id).unwrap().unwrap();
            (record.message.text, record.message.context[0].text.clone())
        };
        assert_eq!(message_text(&done), (String::new(), String::new()));
        assert_eq!(store.message(&done).unwrap().unwrap().receipt, receipt);
        // `atem message status` says so, and still lists the context.
        let view = &crate::runtime::collab::views(&store, Some(&done), None).unwrap()[0];
        let result = view.tasks[0].result.as_ref().unwrap();
        assert!(result.dropped && result.text.is_empty());
        assert_eq!(result.context[0].digest, digest(b"the reply's context"));
        assert_eq!(
            message_text(&waiting),
            ("the message's text".into(), "the message's context".into())
        );
        let outbox = |id: &str| -> Message {
            serde_json::from_str(
                &store
                    .db
                    .query_row(
                        "SELECT envelope FROM outbox WHERE message_id=?1",
                        [id],
                        |r| r.get::<_, String>(0),
                    )
                    .unwrap(),
            )
            .unwrap()
        };
        let publication = |id: &str| -> crate::runtime::collab::Publication {
            serde_json::from_str(
                &store
                    .db
                    .query_row(
                        "SELECT record FROM publications WHERE message_id=?1",
                        [id],
                        |r| r.get::<_, String>(0),
                    )
                    .unwrap(),
            )
            .unwrap()
        };
        let memory_text = |id: &str| match &publication(id).context[0] {
            ContextSpec::Memory { memory } => memory.content.clone(),
            ContextSpec::Vault { .. } => unreachable!(),
        };
        for (id, text, memory) in [
            (&done, "", None),
            (&waiting, "the message's text", None),
            (&sends[0], "", Some("")),
            (&sends[1], "the message's text", Some("a remembered fact")),
        ] {
            assert_eq!(outbox(id).text, text, "{id}");
            if let Some(memory) = memory {
                assert_eq!(memory_text(id), memory, "{id}");
            }
        }
        let uploads = |a: &Attachment| -> i64 {
            store
                .db
                .query_row(
                    "SELECT count(*) FROM attachments WHERE id=?1",
                    [&a.attachment_id],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert_eq!(uploads(&gone_upload), 0);
        assert_eq!(uploads(&kept_upload), 1);
        assert_eq!(uploads(&unnamed_upload), 1);
        assert!(!cache(&gone_upload).exists());
        assert!(cache(&kept_upload).exists());
        // A second pass reads nothing it already dropped, and drops nothing.
        assert_eq!(
            store.payloads_due(now - PAYLOAD_RETENTION_MS).unwrap(),
            Due::default()
        );
        assert_eq!(store.drop_payloads(now).unwrap(), Dropped::default());
        // Once the live task and the delivery settled, theirs go too (and
        // with the delivery, the reply it carried), and the last upload.
        for (r, state) in [(&live, "failed"), (&delivery, "cancelled")] {
            store
                .db
                .execute(
                    "UPDATE work SET state=?2 WHERE id=?1",
                    params![r.task.task_id, state],
                )
                .unwrap();
        }
        assert_eq!(
            store.payloads_due(now - PAYLOAD_RETENTION_MS).unwrap(),
            Due {
                tasks: vec![
                    live.task.task_id.clone(),
                    carried.task.task_id.clone(),
                    delivery.task.task_id.clone()
                ],
                messages: vec![],
                launches: vec![],
            }
        );
        assert_eq!(
            store.drop_payloads(now).unwrap(),
            Dropped {
                tasks: 3,
                messages: 0,
                uploads: 1,
            }
        );
        assert!(stored_reply(&carried).reply.dropped);
        assert!(!cache(&kept_upload).exists());
        assert_eq!(rows, tables.iter().map(|t| count(t)).collect::<Vec<_>>());
    }

    /// A send never accepted, with its publication.
    fn publication() -> crate::runtime::collab::Publication {
        crate::runtime::collab::Publication {
            atem_id: "atem-host".into(),
            origin: crate::runtime::collab::results::Origin {
                target: task().task.target,
                control_gen: 1,
                route: None,
            },
            launch: false,
            context: vec![crate::runtime::collab_context::ContextSpec::Memory {
                memory: Box::new(memory()),
            }],
        }
    }

    /// The record caps count open records only: a store holding
    /// `MAX_RECORDS` tasks, messages, local sends and launches settled a
    /// day past their deadline refuses each new one until the pass closes
    /// them, then takes it again (and counts it while it is open).
    #[test]
    fn the_record_caps_count_open_records_only() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store.bind(&host()).unwrap();
        let now = 10 * PAYLOAD_RETENTION_MS;
        let old = now - PAYLOAD_RETENTION_MS;
        let receipt = |message: &Message| MessageRecord {
            sender_key: serde_json::json!("local"),
            receipt: MessageReceipt {
                message_id: message.message_id.clone(),
                digest: digest(b"message"),
                sender: "local".into(),
                recipients: vec![],
            },
            message: message.clone(),
        };
        let tx = store.db.unchecked_transaction().unwrap();
        for _ in 0..MAX_RECORDS {
            let mut t = task();
            t.task.expires_at = old;
            t.status.state = WorkState::Completed;
            let m = envelope(old);
            let send = envelope(old);
            let mut l = launch();
            l.expires_at = old;
            l.status.state = LaunchState::Failed;
            for (sql, id, record) in [
                (
                    "INSERT INTO work(id,record,state) VALUES(?1,?2,'completed')",
                    &t.task.task_id,
                    serde_json::to_string(&t).unwrap(),
                ),
                (
                    "INSERT INTO messages(id,record) VALUES(?1,?2)",
                    &m.message_id,
                    serde_json::to_string(&receipt(&m)).unwrap(),
                ),
                (
                    "INSERT INTO outbox(message_id,envelope,state,detail,next_try_ms,created_ms)
                    VALUES(?1,?2,'refused','',0,0)",
                    &send.message_id,
                    serde_json::to_string(&send).unwrap(),
                ),
                (
                    "INSERT INTO launches(id,record) VALUES(?1,?2)",
                    &l.status.request_id,
                    serde_json::to_string(&l).unwrap(),
                ),
            ] {
                tx.execute(sql, params![id, record]).unwrap();
            }
        }
        tx.commit().unwrap();
        let config = Collab::default();
        let open = || -> Vec<usize> {
            ["work", "messages", "outbox", "launches"]
                .iter()
                .map(|t| open_records(&store.db, t).unwrap())
                .collect()
        };
        let take = || -> Vec<Result<()>> {
            let m = envelope(now + 60_000);
            let send = envelope(now + 60_000);
            vec![
                store.enqueue(&task()).map(drop),
                store.accept_message(&receipt(&m), &[]),
                crate::runtime::collab::reserve_context(&store, &config, &send, &publication()),
                store.reserve_launch(&launch()).map(drop),
            ]
        };
        assert_eq!(open(), [MAX_RECORDS; 4]);
        assert!(!store.has_room().unwrap());
        for refused in take() {
            assert!(
                refused
                    .unwrap_err()
                    .to_string()
                    .contains("capacity reached"),
                "full"
            );
        }
        assert_eq!(
            store.drop_payloads(now).unwrap(),
            Dropped {
                tasks: MAX_RECORDS,
                messages: 2 * MAX_RECORDS,
                uploads: 0,
            }
        );
        assert_eq!(open(), [0; 4]);
        assert!(store.has_room().unwrap());
        for taken in take() {
            taken.unwrap();
        }
        assert_eq!(open(), [1; 4]);
    }

    /// The payload pass, the cap counts and the open-record readers read
    /// `open_records` first and the record tables only by their primary
    /// key: a closed record is never stepped over or parsed again, however
    /// many there are. The readers of one state go through `work_state`.
    #[test]
    fn closed_records_are_never_stepped_over() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        for sql in [TASKS_IN, NAMED_PRINCIPALS] {
            let (steps, scans) = kept_table_scans(&store.db, sql);
            assert!(scans.is_empty(), "{sql}: {steps:?}");
            assert!(
                steps
                    .iter()
                    .any(|s| s == "SEARCH work USING INDEX work_state (state=?)"),
                "{sql}: {steps:?}"
            );
        }
        for sql in [
            DUE_TASKS,
            DUE_MESSAGES,
            DUE_SENDS,
            DUE_LAUNCHES,
            NAMED_UPLOAD,
            OPEN_COUNT,
            OPEN_LAUNCHES,
            OPEN_TASKS,
        ] {
            let (steps, scans) = kept_table_scans(&store.db, sql);
            assert!(scans.is_empty(), "{sql}: {steps:?}");
            let first = steps
                .iter()
                .find(|s| s.starts_with("SEARCH"))
                .unwrap_or_else(|| panic!("{sql}: {steps:?}"));
            assert!(
                first == "SEARCH o USING PRIMARY KEY (kind=?)"
                    || first == "SEARCH open_records USING PRIMARY KEY (kind=?)",
                "{sql}: {steps:?}"
            );
            for step in &steps {
                assert!(
                    step.starts_with("SEARCH")
                        || step == "SCAN CONSTANT ROW"
                        || step.contains("VIRTUAL TABLE")
                        || step.contains("SUBQUERY")
                        || step.starts_with("USE TEMP B-TREE"),
                    "{sql}: {step}"
                );
                assert!(!step.contains("work_state"), "{sql}: {step}");
            }
        }
    }

    /// The cached PNG of an upload a pass drops (`cache_seen_at_commit`).
    static CACHED: std::sync::Mutex<Option<PathBuf>> = std::sync::Mutex::new(None);
    /// Whether it still existed when the pass committed.
    static CACHED_AT_COMMIT: std::sync::Mutex<Option<bool>> = std::sync::Mutex::new(None);

    fn cache_seen_at_commit(sql: &str) {
        if sql.trim() == "COMMIT"
            && let Some(path) = CACHED.lock().unwrap().as_ref()
        {
            *CACHED_AT_COMMIT.lock().unwrap() = Some(path.exists());
        }
    }

    /// A dropped upload's cached PNG is gone before the pass commits, so
    /// no crash leaves it behind with its row gone.
    #[test]
    fn a_dropped_uploads_cache_file_goes_before_the_commit() {
        use atem_client::session::attachments::Attachment;
        let dir = tempfile::tempdir().unwrap();
        let mut store = Store::open(dir.path()).unwrap();
        let owner = digest(b"sender");
        let upload = Attachment {
            attachment_id: uuid::Uuid::new_v4().to_string(),
            digest: digest(b"png"),
            size: 68,
            media_type: "image/png".into(),
        };
        let mut r = task();
        r.attachment_owner = owner.clone();
        r.task.attachments = vec![upload.clone()];
        r.task.expires_at = 1;
        r.status.state = WorkState::Cancelled;
        store
            .db
            .execute(
                "INSERT INTO work(id,record,state) VALUES(?1,?2,'cancelled')",
                params![r.task.task_id, serde_json::to_string(&r).unwrap()],
            )
            .unwrap();
        store
            .db
            .execute(
                "INSERT INTO attachments(owner,id,descriptor,size,bytes) VALUES(?1,?2,?3,68,x'00')",
                params![
                    owner,
                    upload.attachment_id,
                    serde_json::to_string(&upload).unwrap()
                ],
            )
            .unwrap();
        let cache = dir.path().join("attachments").join(&owner);
        std::fs::create_dir_all(&cache).unwrap();
        let cache = cache.join(format!("{}.png", upload.attachment_id));
        std::fs::write(&cache, b"png").unwrap();
        *CACHED.lock().unwrap() = Some(cache.clone());
        store.db.trace(Some(cache_seen_at_commit));
        let dropped = store.drop_payloads(1 + PAYLOAD_RETENTION_MS).unwrap();
        store.db.trace(None);
        assert_eq!(dropped.uploads, 1);
        assert_eq!(*CACHED_AT_COMMIT.lock().unwrap(), Some(false));
        assert!(!cache.exists());
    }

    /// A tracked record deleted (nothing deletes one today) leaves no open
    /// record behind to count toward a cap forever.
    #[test]
    fn a_deleted_record_is_no_longer_open() {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        for (table, sql) in [
            (
                "work",
                "INSERT INTO work(id,record,state) VALUES('x','{}','queued')",
            ),
            (
                "messages",
                "INSERT INTO messages(id,record) VALUES('x','{}')",
            ),
            (
                "outbox",
                "INSERT INTO outbox(message_id,envelope,state,detail,next_try_ms,created_ms)
                VALUES('x','{}','publishing','',0,0)",
            ),
            (
                "launches",
                "INSERT INTO launches(id,record) VALUES('x','{}')",
            ),
        ] {
            store.db.execute(sql, []).unwrap();
            assert_eq!(open_records(&store.db, table).unwrap(), 1, "{table}");
            let id = if table == "outbox" {
                "message_id"
            } else {
                "id"
            };
            store
                .db
                .execute(&format!("DELETE FROM {table} WHERE {id}='x'"), [])
                .unwrap();
            assert_eq!(open_records(&store.db, table).unwrap(), 0, "{table}");
        }
    }

    /// A v0.8.2 `host-work.sqlite` (its five tables and rows as v0.8.2
    /// wrote them) opens and works unchanged: its records load and answer,
    /// a retry is deduplicated, their payloads go a day past their deadline
    /// with every key of each record kept, and no v0.8.2 table changes.
    #[test]
    fn a_v082_database_opens_and_works_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host-work.sqlite");
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        // v0.8.2's `Store::open`, statement for statement.
        const V082_OPEN: &str = "PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL;
            CREATE TABLE IF NOT EXISTS identity (id INTEGER PRIMARY KEY CHECK(id=1), host TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS launches (id TEXT PRIMARY KEY, record TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS work (id TEXT PRIMARY KEY, record TEXT NOT NULL, state TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS work_state ON work(state);
            CREATE TABLE IF NOT EXISTS messages (id TEXT PRIMARY KEY, record TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS attachments (
                owner TEXT NOT NULL, id TEXT NOT NULL, descriptor TEXT NOT NULL,
                size INTEGER NOT NULL, bytes BLOB NOT NULL, PRIMARY KEY(owner,id));";
        let v082 = Connection::open(&path).unwrap();
        v082.execute_batch(V082_OPEN).unwrap();
        let (task, message, launch, upload) = (
            "11111111-1111-4111-8111-111111111111",
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
            "44444444-4444-4444-8444-444444444444",
        );
        let owner = digest(b"sender");
        let target = serde_json::json!({"account_id":"account","atem_device_id":"host",
            "host_trust_gen":1,"session_id":"ses-aaaaaaaaaaaa",
            "process_gen":"55555555-5555-4555-8555-555555555555"});
        let attachment = serde_json::json!({"attachment_id":upload,"digest":digest(b"png"),
            "size":68,"media_type":"image/png"});
        let status = serde_json::json!({"task_id":task,"receipt_id":"66666666-6666-4666-8666-666666666666",
            "state":"completed","detail":"explicit correlated result published",
            "result":{"kind":"vault","id":"result","version":1,"digest":digest(b"done"),"text":"done"}});
        let work = serde_json::json!({"principal":"member:phone","attachment_owner":owner,
            "control_gen":1,"route_id":"backend","route_revision":1,"profile_id":"backend",
            "profile_revision":1,"project":"local:home","digest":digest(b"task"),
            "task":{"task_id":task,"workflow_id":"77777777-7777-4777-8777-777777777777",
                "target":target,"expires_at":100,"prompt":"build the API",
                "context":[{"kind":"vault","id":"contract","version":1,"digest":digest(b"API"),"text":"API"}],
                "attachments":[attachment]},
            "status":status});
        let sent = serde_json::json!({"message_id":message,"workflow_id":"77777777-7777-4777-8777-777777777777",
            "sender":"member:phone","created_at":1,"expires_at":100,
            "recipients":[{"recipient_id":task,"host":host(),
                "destination":{"kind":"agent","route_id":"backend","route_revision":1,"target":target}}],
            "text":"build the API","context":[]});
        let record = serde_json::json!({"sender_key":{"kty":"test"},"message":sent,
            "receipt":{"message_id":message,"digest":digest(b"message"),"sender":"member:phone",
                "recipients":[{"recipient_id":task,"delivery":{"state":"work","work":{
                    "task_id":task,"receipt_id":status["receipt_id"],"state":"queued",
                    "detail":"waiting for a ready agent","result":null}}}]}});
        let launched = serde_json::json!({"principal":"member:phone","profile_id":"backend",
            "profile_revision":1,"expires_at":100,"digest":digest(b"launch"),
            "status":{"request_id":launch,"session_id":"ses-aaaaaaaaaaaa",
                "process_gen":target["process_gen"],"state":"started"}});
        v082.execute(
            "INSERT INTO identity(id,host) VALUES(1,?1)",
            [serde_json::to_string(&host()).unwrap()],
        )
        .unwrap();
        for (sql, id, value) in [
            (
                "INSERT INTO work(id,record,state) VALUES(?1,?2,'completed')",
                task,
                &work,
            ),
            (
                "INSERT INTO messages(id,record) VALUES(?1,?2)",
                message,
                &record,
            ),
            (
                "INSERT INTO launches(id,record) VALUES(?1,?2)",
                launch,
                &launched,
            ),
        ] {
            v082.execute(sql, params![id, value.to_string()]).unwrap();
        }
        v082.execute(
            "INSERT INTO attachments(owner,id,descriptor,size,bytes) VALUES(?1,?2,?3,68,x'00')",
            params![owner, upload, attachment.to_string()],
        )
        .unwrap();
        let schema = |db: &Connection| -> Vec<(String, String)> {
            db.prepare(
                "SELECT name,sql FROM sqlite_master WHERE name IN
                ('identity','launches','work','work_state','messages','attachments') ORDER BY name",
            )
            .unwrap()
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .collect::<rusqlite::Result<_>>()
            .unwrap()
        };
        let before = schema(&v082);
        assert_eq!(before.len(), 6);
        drop(v082);

        let store = Store::open(dir.path()).unwrap();
        store.bind(&host()).unwrap();
        // What it holds counts toward the caps until it is closed.
        let open = |db: &Connection| -> Vec<usize> {
            ["work", "messages", "outbox", "launches"]
                .iter()
                .map(|t| open_records(db, t).unwrap())
                .collect()
        };
        assert_eq!(open(&store.db), [1, 1, 0, 1]);
        let stored = store.work(task).unwrap().unwrap();
        assert_eq!(stored.task.prompt, "build the API");
        let receipt = store
            .message_receipt(&store.message(message).unwrap().unwrap())
            .unwrap();
        assert!(matches!(&receipt.recipients[0].delivery,
            Delivery::Work { work } if work.state == WorkState::Completed));
        assert_eq!(
            store.launch(launch).unwrap().unwrap().status.state,
            LaunchState::Started
        );
        // A retry: the same task is the recorded one; another is refused.
        assert!(!store.enqueue(&stored).unwrap());
        let mut other = stored.clone();
        other.digest = digest(b"another task");
        assert!(store.enqueue(&other).is_err());
        assert_eq!(
            store.drop_payloads(100 + PAYLOAD_RETENTION_MS).unwrap(),
            Dropped {
                tasks: 1,
                messages: 1,
                uploads: 1,
            }
        );
        // Each record keeps every key it had; only the payloads are empty.
        let raw = |sql: &str, id: &str| -> serde_json::Value {
            serde_json::from_str(
                &store
                    .db
                    .query_row(sql, [id], |r| r.get::<_, String>(0))
                    .unwrap(),
            )
            .unwrap()
        };
        let mut expected = work.clone();
        expected["task"]["prompt"] = "".into();
        expected["task"]["context"][0]["text"] = "".into();
        assert_eq!(raw("SELECT record FROM work WHERE id=?1", task), expected);
        let mut expected = record.clone();
        expected["message"]["text"] = "".into();
        assert_eq!(
            raw("SELECT record FROM messages WHERE id=?1", message),
            expected
        );
        assert_eq!(
            raw("SELECT record FROM launches WHERE id=?1", launch),
            launched
        );
        assert!(!store.enqueue(&stored).unwrap());
        assert!(store.enqueue(&other).is_err());
        assert_eq!(open(&store.db), [0, 0, 0, 0], "closed");
        assert_eq!(schema(&store.db), before);
        drop(store);
        // v0.8.2 still opens, reads and writes it with its own statements,
        // and what it writes is counted (the insert triggers).
        let v082 = Connection::open(&path).unwrap();
        v082.execute_batch(V082_OPEN).unwrap();
        let mut later = work.clone();
        later["task"]["task_id"] = "88888888-8888-4888-8888-888888888888".into();
        later["status"]["task_id"] = later["task"]["task_id"].clone();
        let id = later["task"]["task_id"].as_str().unwrap();
        let writes: [(&str, &[&dyn rusqlite::ToSql]); 6] = [
            (
                "INSERT INTO work(id,record,state) VALUES(?1,?2,?3)",
                params![id, later.to_string(), "queued"],
            ),
            (
                "UPDATE work SET record=?2,state=?3 WHERE id=?1",
                params![id, later.to_string(), "completed"],
            ),
            (
                "INSERT INTO messages(id,record) VALUES(?1,?2)",
                params!["99999999-9999-4999-8999-999999999999", record.to_string()],
            ),
            (
                "INSERT INTO launches(id,record) VALUES(?1,?2)",
                params!["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", launched.to_string()],
            ),
            (
                "UPDATE launches SET record=?2 WHERE id=?1",
                params!["aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", launched.to_string()],
            ),
            (
                "INSERT INTO attachments(owner,id,descriptor,size,bytes) VALUES(?1,?2,?3,68,x'00')",
                params![owner, upload, attachment.to_string()],
            ),
        ];
        for (sql, params) in writes {
            assert_eq!(v082.execute(sql, params).unwrap(), 1, "{sql}");
        }
        let read: String = v082
            .query_row("SELECT record FROM work WHERE id=?1", [id], |r| r.get(0))
            .unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&read).unwrap(),
            later
        );
        let check: String = v082
            .query_row("PRAGMA integrity_check", [], |r| r.get(0))
            .unwrap();
        assert_eq!(check, "ok");
        assert_eq!(schema(&v082), before);
        drop(v082);
        let store = Store::open(dir.path()).unwrap();
        assert_eq!(open(&store.db), [1, 1, 0, 1]);
        assert_eq!(
            store.work(id).unwrap().unwrap().task.prompt,
            "build the API"
        );
    }

    #[test]
    fn config_and_environment_require_private_regular_files() {
        let dir = tempfile::tempdir().unwrap();
        assert!(!Config::load(dir.path()).unwrap().enabled);
        assert!(ensure_config(dir.path()).unwrap());
        assert!(!Config::load(dir.path()).unwrap().enabled);
        assert!(!ensure_config(dir.path()).unwrap());
        let config = dir.path().join(CONFIG_FILE);
        std::fs::set_permissions(&config, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Config::load(dir.path()).is_err());
        let link = dir.path().join("link");
        symlink(&config, &link).unwrap();
        assert!(private_read(&link, 10_000).is_err());
        assert!(private_read(dir.path(), 10_000).is_err());
    }

    #[test]
    fn message_and_work_commit_atomically_and_survive_recovery() {
        use atem_client::session::messages::{Destination, Recipient};
        let dir = tempfile::tempdir().unwrap();
        let first = task();
        let mut second = task();
        let mut message = Message {
            kind: Default::default(),
            reply_to: None,
            from_session: None,
            mark: None,
            message_id: uuid::Uuid::new_v4().to_string(),
            workflow_id: first.task.workflow_id.clone(),
            sender: first.principal.clone(),
            created_at: 1,
            expires_at: 100,
            text: "do the work".into(),
            context: vec![],
            recipients: vec![Recipient {
                recipient_id: first.task.task_id.clone(),
                host: host(),
                destination: Destination::Agent {
                    route_id: "backend".into(),
                    route_revision: 1,
                    target: first.task.target.clone(),
                },
            }],
        };
        let mut record = MessageRecord {
            sender_key: serde_json::json!({}),
            message: message.clone(),
            receipt: MessageReceipt {
                message_id: message.message_id.clone(),
                digest: message.digest(),
                sender: message.sender.clone(),
                recipients: vec![RecipientReceipt {
                    recipient_id: first.task.task_id.clone(),
                    delivery: Delivery::Work {
                        work: (&first.status).into(),
                    },
                }],
            },
        };
        let store = Store::open(dir.path()).unwrap();
        store.bind(&host()).unwrap();
        // A conflicting task halfway through the transaction rolls back the
        // envelope and every earlier recipient, so a retry can still succeed.
        second.task.task_id = first.task.task_id.clone();
        assert!(
            store
                .accept_message(&record, &[first.clone(), second])
                .is_err()
        );
        assert!(store.message(&message.message_id).unwrap().is_none());
        assert!(store.work(&first.task.task_id).unwrap().is_none());
        store
            .accept_message(&record, std::slice::from_ref(&first))
            .unwrap();
        let mut submitted = first;
        submitted.status.state = WorkState::Submitting;
        store.save_work(&submitted).unwrap();
        drop(store);
        let store = Store::open(dir.path()).unwrap();
        store.recover(&BTreeMap::new()).unwrap();
        record = store.message(&message.message_id).unwrap().unwrap();
        let receipt = store.message_receipt(&record).unwrap();
        assert!(
            matches!(&receipt.recipients[0].delivery, Delivery::Work { work } if work.state == WorkState::OutcomeUnknown)
        );
        message.text.push('!');
        assert_ne!(record.receipt.digest, message.digest());
    }

    #[test]
    fn approved_arguments_and_environment_are_preserved_but_extra_names_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let cwd = dir.path().canonicalize().unwrap();
        let env_file = cwd.join("provider.json");
        std::fs::write(&env_file, r#"{"CUSTOM_BASE_URL":"http://127.0.0.1:9000"}"#).unwrap();
        std::fs::set_permissions(&env_file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let p = Profile {
            id: "backend".into(),
            revision: 1,
            label: "Backend".into(),
            provider: "codex".into(),
            project: crate::memory::project::project_key_for(&cwd),
            cwd: cwd.clone(),
            args: vec!["--profile".into(), "oss".into()],
            principals: vec!["member:phone".into()],
            env_names: vec!["CUSTOM_BASE_URL".into()],
            env_file: Some(env_file.clone()),
        };
        let (request, env) = p
            .launch(
                crate::session::SessionId::new().to_string(),
                uuid::Uuid::new_v4().to_string(),
            )
            .unwrap();
        assert_eq!(request.args, vec!["--profile", "oss"]);
        assert!(
            env.0
                .iter()
                .any(|(k, v)| k == "CUSTOM_BASE_URL" && v == "http://127.0.0.1:9000")
        );
        std::fs::write(env_file, r#"{"UNAPPROVED":"value"}"#).unwrap();
        assert!(
            p.launch(
                crate::session::SessionId::new().to_string(),
                uuid::Uuid::new_v4().to_string()
            )
            .is_err()
        );
        let mut p = p;
        p.project = "different/project".into();
        assert!(
            p.launch(
                crate::session::SessionId::new().to_string(),
                uuid::Uuid::new_v4().to_string()
            )
            .is_err()
        );
    }

    fn load_error(dir: &Path) -> String {
        match Config::load(dir) {
            Ok(_) => panic!("the configuration loaded"),
            Err(error) => error.to_string(),
        }
    }

    fn write_config(dir: &Path, text: &str) {
        let path = dir.join(CONFIG_FILE);
        std::fs::write(&path, text).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    const PROFILE: &str = r#"
version = 1
enabled = true

[[profiles]]
id = "backend-codex"
revision = 1
label = "Backend Codex"
provider = "codex"
cwd = "/tmp/backend"
project = "local:backend"

[[routes]]
id = "backend"
revision = 1
profile_id = "backend-codex"
"#;

    /// A profile or route that names no principals is open to the paired
    /// Astation; unpaired, it names what to do.
    #[test]
    fn principals_default_to_the_paired_astation() {
        let dir = tempfile::tempdir().unwrap();
        write_config(dir.path(), PROFILE);
        let error = load_error(dir.path());
        assert!(
            error.starts_with("profile `backend-codex`: no principals")
                && error.contains("atem pair"),
            "{error}"
        );
        crate::pairing::tests::write_bound(dir.path(), "astation-X1", 2, "binding-1", ("s", "t"));
        let config = Config::load(dir.path()).unwrap();
        assert_eq!(config.profiles[0].principals, ["member:astation-X1"]);
        assert_eq!(config.routes[0].principals, ["member:astation-X1"]);
        // A list of its own replaces the default.
        write_config(
            dir.path(),
            &PROFILE.replace(
                "project = \"local:backend\"\n",
                "project = \"local:backend\"\nprincipals = [\"service:svc-1\"]\n",
            ),
        );
        let config = Config::load(dir.path()).unwrap();
        assert_eq!(config.profiles[0].principals, ["service:svc-1"]);
        assert_eq!(config.routes[0].principals, ["member:astation-X1"]);
    }

    /// The parser's own reason with its line; a broken rule names the
    /// profile and the rule.
    #[test]
    fn invalid_files_say_what_and_where() {
        let dir = tempfile::tempdir().unwrap();
        crate::pairing::tests::write_bound(dir.path(), "astation-X1", 2, "binding-1", ("s", "t"));
        write_config(
            dir.path(),
            &PROFILE.replace("project = \"local:backend\"\n", ""),
        );
        let error = load_error(dir.path());
        assert!(error.starts_with("invalid runtime.toml (line "), "{error}");
        assert!(error.contains("missing field `project`"), "{error}");
        write_config(
            dir.path(),
            &PROFILE.replace(
                "project = \"local:backend\"\n",
                "project = \"local:backend\"\nprincipals = [\"member:YOUR ASTATION\"]\n",
            ),
        );
        let error = load_error(dir.path());
        assert!(
            error.starts_with("profile `backend-codex`: `member:YOUR ASTATION` is not a principal"),
            "{error}"
        );
        write_config(
            dir.path(),
            &PROFILE.replace("provider = \"codex\"", "provider = \"vim\""),
        );
        let error = load_error(dir.path());
        assert_eq!(
            error,
            "profile `backend-codex`: provider must be `claude` or `codex`"
        );
        write_config(
            dir.path(),
            &PROFILE.replace("profile_id = \"backend-codex\"", "profile_id = \"nope\""),
        );
        let error = load_error(dir.path());
        assert_eq!(error, "route `backend`: profile_id `nope` names no profile");
    }

    #[test]
    fn labels_and_collab_parse_with_defaults() {
        let mut config: Config = toml::from_str(PROFILE).unwrap();
        config.inherit(Some("member:owner".into()));
        config.validate().unwrap();
        assert!(!config.collab.send);
        assert_eq!(config.collab.per_hour, 30);
        assert_eq!(config.collab.per_workflow, 8);
        assert_eq!(config.collab.result_timeout_ms(), 1_800_000);
        assert!(config.instance.labels.is_empty());
        let route = &config.routes[0];
        assert!(route.labels.is_empty());
        assert!(route.launch == RouteLaunch::Off);
        assert!(!route.results);
        assert!(route.auto_report == AutoReport::Status);
    }

    fn collaboration_error(extra: &str) -> String {
        let mut config: Config = toml::from_str(&format!("{PROFILE}{extra}")).unwrap();
        config.inherit(Some("member:owner".into()));
        config.validate().err().unwrap().to_string()
    }

    #[test]
    fn labels_say_what_and_where() {
        assert_eq!(
            collaboration_error("labels = [\"tag:Auth\"]"),
            "route `backend`: label \"tag:Auth\": names are 1-32 of a-z, 0-9 and -"
        );
        assert!(
            collaboration_error("labels = [\"self:x\"]")
                .contains("owner labels are project: or tag:")
        );
        let labels = (0..65)
            .map(|i| format!("\"tag:t{i}\""))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            collaboration_error(&format!("labels = [{labels}]")),
            "route `backend`: at most 64 labels"
        );
        assert!(
            collaboration_error("\n[instance]\nlabels = [\"tag:Auth\"]")
                .starts_with("[instance]: label")
        );
        assert!(label_problem("self:reviewer", false).is_none());
        assert!(
            label_problem("tag:reviewer", false)
                .unwrap()
                .contains("agent labels are self:")
        );
    }

    /// Spec section 5: stage 1 launches only Claude Code sessions. Codex
    /// reports nothing before a first prompt is typed, so a launched one
    /// would never become ready; a route that asks for it is refused at
    /// load (and a Codex route that doesn't is fine).
    #[test]
    fn launch_on_message_supports_claude_profiles_only() {
        assert_eq!(
            collaboration_error("launch = \"on_message\""),
            "route `backend`: launch on message supports Claude Code profiles only for now"
        );
        let mut config: Config = toml::from_str(&format!(
            "{}launch = \"on_message\"",
            PROFILE.replace("provider = \"codex\"", "provider = \"claude\"")
        ))
        .unwrap();
        config.inherit(Some("member:owner".into()));
        config.validate().unwrap();
        assert!(config.routes[0].launch == RouteLaunch::OnMessage);
        let mut config: Config = toml::from_str(&format!("{PROFILE}launch = \"off\"")).unwrap();
        config.inherit(Some("member:owner".into()));
        config.validate().unwrap();
    }

    #[test]
    fn local_is_a_route_principal_only() {
        let mut config: Config =
            toml::from_str(&format!("{PROFILE}principals = [\"local\"]")).unwrap();
        config.inherit(Some("member:owner".into()));
        config.validate().unwrap();
        config.profiles[0].principals = vec!["local".into()];
        assert!(
            config
                .validate()
                .err()
                .unwrap()
                .to_string()
                .starts_with("profile `backend-codex`: `local` is not a principal")
        );
    }

    /// A route's principal error names `local` among the valid ones; a
    /// profile's (which never takes `local`) does not.
    #[test]
    fn the_route_principal_error_lists_local() {
        let error = collaboration_error("principals = [\"anyone\"]");
        assert!(
            error.starts_with("route `backend`: `anyone` is not a principal"),
            "{error}"
        );
        assert!(
            error.contains("`member:<id>`, `service:<id>`, `browser:<id>` or `local`"),
            "{error}"
        );
        let mut config: Config = toml::from_str(PROFILE).unwrap();
        config.inherit(Some("member:owner".into()));
        config.profiles[0].principals = vec!["anyone".into()];
        let error = config.validate().err().unwrap().to_string();
        assert!(!error.contains("`local`"), "{error}");
    }

    #[test]
    fn result_timeout_parses() {
        for (value, expected) in [("30m", 1_800_000), ("90s", 90_000), ("2h", 7_200_000)] {
            let mut config: Config =
                toml::from_str(&format!("{PROFILE}\n[collab]\nresult_timeout = {value:?}"))
                    .unwrap();
            config.inherit(Some("member:owner".into()));
            config.validate().unwrap();
            assert_eq!(config.collab.result_timeout_ms(), expected);
        }
        for value in ["0s", "25h", "999999999999999999999999h", "1", "-1s"] {
            assert!(
                collaboration_error(&format!("\n[collab]\nresult_timeout = {value:?}"))
                    .starts_with("[collab]: result_timeout")
            );
        }
        for key in ["per_hour", "per_workflow"] {
            assert!(
                collaboration_error(&format!("\n[collab]\n{key} = 0")).starts_with("[collab]:")
            );
        }
    }

    /// `atem runtime check` lists the device list's members and services
    /// with their principal IDs and whether each may launch: natives with
    /// `control`; services with `launch` and an unexpired grant (a signed
    /// scope never pairs `launch` with a session restriction).
    #[test]
    fn check_lists_who_may_launch() {
        use crate::session_protocol::membership::r9log::{MAC, TestLog, secret};
        use crate::session_protocol::membership::{HostPin, MembershipHost, passive_principals};
        let dir = tempfile::tempdir().unwrap();
        let paths = crate::paths::ProfilePaths::in_dir(dir.path());
        assert_eq!(passive_principals(&paths.pairing), None);
        let mut log = TestLog::genesis("acct-w", &secret("w astation"));
        log.add_host("host-w", 1, &secret("w host"));
        log.add_native("dev-view", &["view"]);
        let later = crate::session_protocol::membership::r9log::host_now().wall_ms + 3_600_000;
        log.add_service("svc-launch", &["host-w"], None, &["launch", "view"], later);
        log.add_service("svc-prompt", &["host-w"], None, &["prompt", "view"], later);
        let journal = crate::runtime::state_dir(dir.path()).join("journal");
        crate::session_protocol::membership::store::private_dir(&journal).unwrap();
        let pin = HostPin {
            host_id: "host-w".into(),
            host_trust_gen: 1,
        };
        MembershipHost::pin(&paths.pairing, &journal, &pin, &log.log, &secret("w host")).unwrap();
        let mut got = passive_principals(&paths.pairing).unwrap();
        got.sort();
        let may: Vec<(String, bool)> = got.iter().map(|(p, _, m)| (p.clone(), *m)).collect();
        assert_eq!(
            may,
            vec![
                (format!("member:{MAC}"), true),
                ("member:dev-view".to_string(), false),
                ("service:svc-launch".to_string(), true),
                ("service:svc-prompt".to_string(), false),
            ]
        );
        assert!(
            got[0].1.starts_with("device (") && got[0].1.contains("control"),
            "{got:?}"
        );
    }
}

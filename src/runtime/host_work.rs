//! Host-approved launch profiles, directed-work routes and durable outcomes.
use anyhow::{Context, Result, anyhow, bail};
use atem_client::principal::{Authority, Need, Op};
use atem_client::session::host_work::{
    HostTarget, LaunchState, LaunchStatus, ProfileInfo, WorkState, WorkStatus, WorkTask,
};
use atem_client::session::messages::{Delivery, Message, MessageReceipt, RecipientReceipt};
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::OpenOptions;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use super::adopt::SpawnRequest;
use super::protocol::LaunchEnv;

pub const CONFIG_FILE: &str = "runtime.toml";
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
}

/// How long a settled record is kept past its deadline. A retry of a pruned
/// request names a deadline that passed, so it is refused, never new work;
/// the day covers a host clock that was set back.
pub const PRUNE_MARGIN_MS: u64 = 86_400_000;

/// What `Store::prune` removed.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Pruned {
    pub tasks: usize,
    pub messages: usize,
    pub launches: usize,
    pub attachments: usize,
}

pub struct Store {
    pub(super) db: Connection,
    pub(super) state: PathBuf,
}

pub(super) fn valid_owner(owner: &str) -> bool {
    atem_client::session::wire::is_digest(owner)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageRecord {
    pub sender_key: serde_json::Value,
    pub message: Message,
    pub receipt: MessageReceipt,
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
            CREATE TABLE IF NOT EXISTS resolutions (
                message_id TEXT NOT NULL, recipient_id TEXT NOT NULL, task_id TEXT PRIMARY KEY,
                route_id TEXT NOT NULL, session_id TEXT NOT NULL, process_gen TEXT NOT NULL,
                launch_request_id TEXT, record TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS resolution_message ON resolutions(message_id);
            CREATE TABLE IF NOT EXISTS publications (
                message_id TEXT PRIMARY KEY, record TEXT NOT NULL, attempts INTEGER NOT NULL DEFAULT 0);
            CREATE TABLE IF NOT EXISTS origins (message_id TEXT PRIMARY KEY, record TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS return_grants (task_id TEXT PRIMARY KEY, record TEXT NOT NULL,
                state TEXT NOT NULL DEFAULT 'open', awaiting_since_ms INTEGER);
            CREATE TABLE IF NOT EXISTS results (
                task_id TEXT PRIMARY KEY, result_id TEXT NOT NULL UNIQUE, state TEXT NOT NULL,
                detail TEXT NOT NULL, digest TEXT NOT NULL, created_ms INTEGER NOT NULL,
                submitted_at INTEGER, record TEXT NOT NULL, next_try_ms INTEGER NOT NULL,
                attempts INTEGER NOT NULL, work_id TEXT);
            CREATE INDEX IF NOT EXISTS result_state ON results(state);
            CREATE INDEX IF NOT EXISTS result_work ON results(work_id);
            CREATE TABLE IF NOT EXISTS counters (
                key TEXT NOT NULL, window_start_ms INTEGER NOT NULL, count INTEGER NOT NULL,
                PRIMARY KEY(key,window_start_ms));
            CREATE TABLE IF NOT EXISTS attachments (
                owner TEXT NOT NULL, id TEXT NOT NULL, descriptor TEXT NOT NULL,
                size INTEGER NOT NULL, bytes BLOB NOT NULL, PRIMARY KEY(owner,id));")?;
        std::fs::File::open(state)?.sync_all()?;
        Ok(Self {
            db,
            state: state.to_path_buf(),
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
        let Self { db, state } = self;
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
        let count: usize = tx.query_row("SELECT count(*) FROM messages", [], |r| r.get(0))?;
        let tasks: usize = tx.query_row("SELECT count(*) FROM work", [], |r| r.get(0))?;
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

    pub fn launches(&self) -> Result<Vec<LaunchRecord>> {
        let mut q = self
            .db
            .prepare("SELECT record FROM launches ORDER BY rowid")?;
        q.query_map([], |r| r.get::<_, String>(0))?
            .map(|r| Ok(serde_json::from_str(&r?)?))
            .collect()
    }

    pub fn tasks(&self) -> Result<Vec<WorkRecord>> {
        let mut q = self.db.prepare("SELECT record FROM work ORDER BY rowid")?;
        q.query_map([], |r| r.get::<_, String>(0))?
            .map(|r| Ok(serde_json::from_str(&r?)?))
            .collect()
    }

    pub fn active_tasks(&self) -> Result<Vec<WorkRecord>> {
        let mut q = self.db.prepare("SELECT record FROM work WHERE state IN ('queued','blocked','submitting','submitted','outcome_unknown') ORDER BY rowid")?;
        q.query_map([], |r| r.get::<_, String>(0))?
            .map(|r| Ok(serde_json::from_str(&r?)?))
            .collect()
    }

    fn capacity(&self, table: &str) -> Result<()> {
        let sql = match table {
            "launches" => "SELECT count(*) FROM launches",
            _ => "SELECT count(*) FROM work",
        };
        let count: usize = self.db.query_row(sql, [], |r| r.get(0))?;
        if count >= MAX_RECORDS {
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
        let tasks: usize = self
            .db
            .query_row("SELECT count(*) FROM work", [], |r| r.get(0))?;
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
    /// session's queue, forever. Nothing is resubmitted. An open grant ends
    /// with its task. Writes only what is due; returns how many expired.
    pub fn expire_overdue(&self, now: u64) -> Result<usize> {
        let due: Vec<WorkRecord> = {
            let mut q = self.db.prepare(
                "SELECT record FROM work WHERE state IN ('awaiting_result','outcome_unknown')
                AND json_extract(record,'$.task.expires_at')<=?1 ORDER BY rowid",
            )?;
            q.query_map([now], |r| r.get::<_, String>(0))?
                .map(|r| Ok(serde_json::from_str(&r?)?))
                .collect::<Result<_>>()?
        };
        if due.is_empty() {
            return Ok(0);
        }
        let tx = self.db.unchecked_transaction()?;
        for mut record in due.iter().cloned() {
            record.status.detail = if record.status.state == WorkState::OutcomeUnknown {
                EXPIRED_UNKNOWN
            } else {
                EXPIRED_AWAITING
            }
            .into();
            record.status.state = WorkState::Expired;
            self.save_work(&record)?;
            tx.execute(
                "UPDATE return_grants SET state='ended' WHERE task_id=?1 AND state='open'",
                [&record.task.task_id],
            )?;
        }
        tx.commit()?;
        Ok(due.len())
    }

    /// Removes what is settled and a day past its deadline
    /// (`PRUNE_MARGIN_MS`): tasks completed, failed, cancelled or expired,
    /// with their reply, return grant and resolution; messages whose tasks
    /// all go, with their outbox, origin and resolution rows; local sends
    /// never accepted (refused or expired); launches no longer starting that
    /// no remaining task waits for; uploads no remaining task names. A live
    /// task is never removed, nor what it needs: its message (and so the
    /// message's other tasks), its launch, its uploads, a result its delivery
    /// still carries. An upload no task ever named stays (its own bound
    /// holds it). Every task of a message has the message's deadline
    /// (`Message::task`, the local `local_task`), so only messages past the
    /// margin are read. Returns what it removed.
    pub fn prune(&self, now: u64) -> Result<Pruned> {
        let cutoff = now.saturating_sub(PRUNE_MARGIN_MS);
        let tx = self.db.unchecked_transaction()?;
        let mut tasks: BTreeMap<String, WorkRecord> = {
            let mut q = tx.prepare(
                "SELECT id,record FROM work WHERE state IN ('completed','failed','cancelled','expired')
                AND json_extract(record,'$.task.expires_at')<=?1",
            )?;
            q.query_map([cutoff], |r| {
                Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
            })?
            .map(|r| {
                let (id, record) = r?;
                Ok((id, serde_json::from_str(&record)?))
            })
            .collect::<Result<_>>()?
        };
        // A reply stays while the task delivering it stays.
        let carried: Vec<(String, String)> = {
            let mut q = tx.prepare(
                "SELECT r.task_id,r.work_id FROM results r JOIN work d ON d.id=r.work_id",
            )?;
            q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        for (task, delivery) in carried {
            if !tasks.contains_key(&delivery) {
                tasks.remove(&task);
            }
        }
        // A message goes with all of its tasks, or stays with all of them.
        let expired: Vec<(String, String)> = {
            let mut q = tx.prepare(
                "SELECT id,record FROM messages WHERE json_extract(record,'$.message.expires_at')<=?1",
            )?;
            q.query_map([cutoff], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        let mut messages = Vec::new();
        for (id, record) in expired {
            let record: serde_json::Value = serde_json::from_str(&record)?;
            let work: Vec<String> = record["receipt"]["recipients"]
                .as_array()
                .into_iter()
                .flatten()
                .filter(|r| r["delivery"]["state"] == "work")
                .filter_map(|r| r["recipient_id"].as_str().map(str::to_string))
                .collect();
            let mut stays = false;
            for task in &work {
                stays |= !tasks.contains_key(task) && self.work(task)?.is_some();
            }
            if stays {
                for task in &work {
                    tasks.remove(task);
                }
            } else {
                messages.push(id);
            }
        }
        let mut uploads = BTreeSet::new();
        for (id, record) in &tasks {
            for table in [
                "work WHERE id",
                "results WHERE task_id",
                "return_grants WHERE task_id",
                "resolutions WHERE task_id",
            ] {
                tx.execute(&format!("DELETE FROM {table}=?1"), [id])?;
            }
            for a in &record.task.attachments {
                uploads.insert((record.attachment_owner.clone(), a.attachment_id.clone()));
            }
        }
        for id in &messages {
            for table in [
                "messages WHERE id",
                "outbox WHERE message_id",
                "origins WHERE message_id",
                "publications WHERE message_id",
                "resolutions WHERE message_id",
            ] {
                tx.execute(&format!("DELETE FROM {table}=?1"), [id])?;
            }
        }
        tx.execute(
            "DELETE FROM outbox WHERE state!='publishing' AND message_id NOT IN (SELECT id FROM messages)
            AND json_extract(envelope,'$.expires_at')<=?1",
            [cutoff],
        )?;
        tx.execute(
            "DELETE FROM publications WHERE message_id NOT IN (SELECT message_id FROM outbox)",
            [],
        )?;
        let launches = tx.execute(
            "DELETE FROM launches WHERE json_extract(record,'$.status.state')!='starting'
            AND json_extract(record,'$.expires_at')<=?1 AND id NOT IN
            (SELECT launch_request_id FROM resolutions WHERE launch_request_id IS NOT NULL)",
            [cutoff],
        )?;
        let mut removed = Vec::new();
        for (owner, id) in uploads {
            let named: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM work w, json_each(w.record,'$.task.attachments') a
                WHERE json_extract(w.record,'$.attachment_owner')=?1
                AND json_extract(a.value,'$.attachment_id')=?2)",
                params![owner, id],
                |r| r.get(0),
            )?;
            if !named
                && tx.execute(
                    "DELETE FROM attachments WHERE owner=?1 AND id=?2",
                    params![owner, id],
                )? == 1
            {
                removed.push((owner, id));
            }
        }
        tx.commit()?;
        // The verified cache files of removed uploads (rebuilt from the
        // database whenever a prompt needs one).
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
        Ok(Pruned {
            tasks: tasks.len(),
            messages: messages.len(),
            launches,
            attachments: removed.len(),
        })
    }

    pub fn save_work(&self, record: &WorkRecord) -> Result<()> {
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
        Ok(())
    }

    /// At a start: a launch still starting is started (its worker is
    /// live) or of unknown outcome, and a task found submitting is of unknown
    /// outcome; neither is ever retried. Identities stay until `prune`
    /// removes them a day past their deadline, when a retry is refused
    /// anyway: deleting a record never turns an old retry into work.
    pub fn recover(
        &self,
        sessions: &BTreeMap<crate::session::SessionId, super::broker::BrokerSession>,
    ) -> Result<()> {
        for mut record in self.launches()? {
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
        for mut record in self.tasks()? {
            if record.status.state == WorkState::Submitting {
                record.status.state = WorkState::OutcomeUnknown;
                record.status.detail =
                    "submission interrupted; recover its receipt before any further action".into();
                self.save_work(&record)?;
            }
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
    use atem_client::session::host_work::{ContextKind, ContextSnapshot, digest};
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
            principal: "member:phone".into(),
            attachment_owner: String::new(),
            control_gen: 1,
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
        assert!(store.tasks().unwrap().is_empty());

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
        assert_eq!(store.expire_overdue(999).unwrap(), 0);
        assert_eq!(store.expire_overdue(1_000).unwrap(), MAX_QUEUED - 1);
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
        assert_eq!(store.expire_overdue(1_999).unwrap(), 0);
        assert_eq!(store.expire_overdue(2_000).unwrap(), 1);
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
        assert_eq!(store.expire_overdue(999).unwrap(), 0);
        assert_eq!(store.active_tasks().unwrap().len(), 1);
        assert_eq!(store.expire_overdue(1_000).unwrap(), 1);
        let expired = store.work(&r.task.task_id).unwrap().unwrap();
        assert_eq!(
            (expired.status.state, expired.status.detail.as_str()),
            (WorkState::Expired, "expired with its outcome unknown")
        );
        assert!(store.active_tasks().unwrap().is_empty());
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

    /// Rows a day past their deadline go once settled, with what belongs to
    /// them; rows inside the margin, live tasks and whatever a live task
    /// needs (its message, launch, upload, the result its delivery carries)
    /// stay.
    #[test]
    fn settled_records_are_pruned_a_day_past_their_deadline() {
        use atem_client::session::attachments::Attachment;
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(dir.path()).unwrap();
        store.bind(&host()).unwrap();
        let now = 10 * PRUNE_MARGIN_MS;
        let (old, recent) = (now - PRUNE_MARGIN_MS, now - PRUNE_MARGIN_MS + 1);
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
        let rows = |table: &str, column: &str, id: &str| -> i64 {
            store
                .db
                .query_row(
                    &format!("SELECT count(*) FROM {table} WHERE {column}=?1"),
                    [id],
                    |r| r.get(0),
                )
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
        // Settled, a day past its deadline: goes, with its reply, grant,
        // resolution and its upload.
        let settled = put(due(old, vec![gone_upload.clone()]), WorkState::Completed);
        let id = settled.task.task_id.clone();
        for sql in [
            "INSERT INTO results(task_id,result_id,state,detail,digest,created_ms,record,next_try_ms,attempts)
            VALUES(?1,?1,'submitted','','d',0,'{}',0,0)",
            "INSERT INTO return_grants(task_id,record,state) VALUES(?1,'{}','ended')",
            "INSERT INTO resolutions(message_id,recipient_id,task_id,route_id,session_id,process_gen,record)
            VALUES('none','none',?1,'r','s','p','{}')",
        ] {
            store.db.execute(sql, [&id]).unwrap();
        }
        // Inside the margin, or live: stay. A live task keeps its upload.
        let inside = put(due(recent, vec![]), WorkState::Failed);
        let live = put(due(old, vec![kept_upload.clone()]), WorkState::Submitted);
        // A settled task whose result is carried by a delivery still queued.
        let carried = put(due(old, vec![]), WorkState::Expired);
        let delivery = put(due(old, vec![]), WorkState::Queued);
        store
            .db
            .execute(
                "INSERT INTO results(task_id,result_id,state,detail,digest,created_ms,record,next_try_ms,attempts,work_id)
                VALUES(?1,?1,'submitted','','d',0,'{}',0,0,?2)",
                params![carried.task.task_id, delivery.task.task_id],
            )
            .unwrap();
        // Messages: one whose tasks are all settled goes with its outbox,
        // origin and resolutions; one with a live task keeps every task.
        let message = |tasks: &[&WorkRecord]| -> String {
            let id = uuid::Uuid::new_v4().to_string();
            let record = serde_json::json!({
                "sender_key": "local",
                "message": {"expires_at": old},
                "receipt": {"recipients": tasks.iter().map(|t| serde_json::json!({
                    "recipient_id": t.task.task_id, "delivery": {"state": "work"}
                })).chain([serde_json::json!({"recipient_id": "x", "delivery": {"state": "stored"}})])
                .collect::<Vec<_>>()},
            });
            store
                .db
                .execute(
                    "INSERT INTO messages(id,record) VALUES(?1,?2)",
                    params![id, record.to_string()],
                )
                .unwrap();
            for sql in [
                "INSERT INTO outbox(message_id,envelope,state,detail,next_try_ms,created_ms)
                VALUES(?1,'{}','accepted','',0,0)",
                "INSERT INTO origins(message_id,record) VALUES(?1,'{}')",
            ] {
                store.db.execute(sql, [&id]).unwrap();
            }
            for t in tasks {
                store
                    .db
                    .execute(
                        "INSERT INTO resolutions(message_id,recipient_id,task_id,route_id,session_id,process_gen,record)
                        VALUES(?1,'r',?2,'r','s','p','{}')",
                        params![id, t.task.task_id],
                    )
                    .unwrap();
            }
            id
        };
        let finished = [
            put(due(old, vec![]), WorkState::Completed),
            put(due(old, vec![]), WorkState::Cancelled),
        ];
        let done = message(&[&finished[0], &finished[1]]);
        let held = [
            put(due(old, vec![]), WorkState::Expired),
            put(due(old, vec![]), WorkState::AwaitingResult),
        ];
        let waiting = message(&[&held[0], &held[1]]);
        // Local sends never accepted: a refused one goes, one still
        // publishing stays.
        for (state, id) in [("refused", "unsent"), ("publishing", "sending")] {
            store
                .db
                .execute(
                    "INSERT INTO outbox(message_id,envelope,state,detail,next_try_ms,created_ms)
                    VALUES(?1,?2,?3,'',0,0)",
                    params![
                        id,
                        serde_json::json!({"expires_at": old}).to_string(),
                        state
                    ],
                )
                .unwrap();
            store
                .db
                .execute(
                    "INSERT INTO publications(message_id,record) VALUES(?1,'{}')",
                    [id],
                )
                .unwrap();
        }
        // Launches: a settled one goes; one still starting, one inside the
        // margin and one a remaining task waits for stay.
        let mut launches = Vec::new();
        for (state, expires_at) in [
            (LaunchState::Started, old),
            (LaunchState::Starting, old),
            (LaunchState::Failed, recent),
            (LaunchState::OutcomeUnknown, old),
        ] {
            let mut l = launch();
            l.expires_at = expires_at;
            l.status.state = state;
            assert!(store.reserve_launch(&l).unwrap());
            launches.push(l.status.request_id);
        }
        store
            .db
            .execute(
                "UPDATE resolutions SET launch_request_id=?2 WHERE task_id=?1",
                params![held[1].task.task_id, launches[3]],
            )
            .unwrap();

        // The verified cache files of the uploads.
        let cache = |a: &Attachment| {
            let dir = dir.path().join("attachments").join(&owner);
            std::fs::create_dir_all(&dir).unwrap();
            dir.join(format!("{}.png", a.attachment_id))
        };
        for a in [&gone_upload, &kept_upload] {
            std::fs::write(cache(a), b"png").unwrap();
        }
        // Nothing is due a millisecond earlier.
        let pruned = store.prune(now - 1).unwrap();
        assert_eq!(pruned, Pruned::default());
        let pruned = store.prune(now).unwrap();
        assert_eq!(
            pruned,
            Pruned {
                tasks: 3,
                messages: 1,
                launches: 1,
                attachments: 1,
            }
        );
        for gone in [&settled, &finished[0], &finished[1]] {
            assert!(store.work(&gone.task.task_id).unwrap().is_none());
        }
        for table in ["results", "return_grants", "resolutions"] {
            assert_eq!(rows(table, "task_id", &id), 0, "{table}");
        }
        for kept in [&inside, &live, &carried, &delivery, &held[0], &held[1]] {
            assert!(store.work(&kept.task.task_id).unwrap().is_some());
        }
        assert_eq!(rows("results", "task_id", &carried.task.task_id), 1);
        assert_eq!(rows("messages", "id", &done), 0);
        for (table, count) in [("outbox", 1), ("origins", 1), ("resolutions", 2)] {
            assert_eq!(rows(table, "message_id", &done), 0, "{table}");
            assert_eq!(rows(table, "message_id", &waiting), count, "{table}");
        }
        assert_eq!(rows("messages", "id", &waiting), 1);
        for (id, kept) in [("unsent", 0), ("sending", 1)] {
            assert_eq!(rows("outbox", "message_id", id), kept, "{id}");
            assert_eq!(rows("publications", "message_id", id), kept, "{id}");
        }
        let kept: Vec<bool> = launches
            .iter()
            .map(|id| store.launch(id).unwrap().is_some())
            .collect();
        assert_eq!(kept, [false, true, true, true]);
        let uploads = |a: &Attachment| rows("attachments", "id", &a.attachment_id);
        assert_eq!(uploads(&gone_upload), 0);
        assert_eq!(uploads(&kept_upload), 1);
        assert_eq!(uploads(&unnamed_upload), 1);
        assert!(!cache(&gone_upload).exists());
        assert!(cache(&kept_upload).exists());
        // Again: nothing more.
        assert_eq!(store.prune(now).unwrap(), Pruned::default());
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

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
pub const MAX_QUEUED: usize = 256;

#[derive(Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u8,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub profiles: Vec<Profile>,
    #[serde(default)]
    pub routes: Vec<Route>,
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
    /// Explicitly approved principals, including the kind prefix.
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
    pub principals: Vec<String>,
}

fn principal_ok(principal: &str) -> bool {
    ["member:", "service:", "browser:"].iter().any(|prefix| {
        principal
            .strip_prefix(prefix)
            .is_some_and(atem_client::session::wire::is_opaque_id)
    })
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
        let config: Self = toml::from_str(std::str::from_utf8(&bytes)?)
            .map_err(|_| anyhow!("invalid runtime.toml; check the configuration schema"))?;
        config.validate()?;
        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        use atem_client::session::wire::is_opaque_id;
        if self.version != 1 || self.profiles.len() > 64 || self.routes.len() > 64 {
            bail!("host config needs version = 1 and at most 64 profiles/routes");
        }
        let mut profiles = BTreeSet::new();
        for p in &self.profiles {
            if !is_opaque_id(&p.id)
                || p.revision == 0
                || !profiles.insert(p.id.clone())
                || p.label.is_empty()
                || p.label.len() > 128
                || p.label.chars().any(char::is_control)
                || !matches!(p.provider.as_str(), "claude" | "codex")
                || !p.cwd.is_absolute()
                || p.project.is_empty()
                || p.principals.is_empty()
                || p.principals.len() > 64
                || !p.principals.iter().all(|s| principal_ok(s))
                || p.args.len() > super::protocol::MAX_ARGS
                || p.args.iter().map(String::len).sum::<usize>() > super::protocol::MAX_ARGS_BYTES
                || p.args.iter().any(|a| a.contains('\0'))
                || p.env_file.as_ref().is_some_and(|p| !p.is_absolute())
                || p.env_names.len() > 128
                || p.env_names
                    .iter()
                    .any(|n| n.is_empty() || n.contains(['=', '\0']))
            {
                bail!("invalid host launch profile");
            }
        }
        let mut routes = BTreeSet::new();
        for r in &self.routes {
            if !is_opaque_id(&r.id)
                || r.revision == 0
                || !routes.insert(&r.id)
                || !profiles.contains(&r.profile_id)
                || r.principals.is_empty()
                || r.principals.len() > 64
                || !r.principals.iter().all(|s| principal_ok(s))
            {
                bail!("invalid host work route");
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
        self.check_binding(host)
    }

    pub fn check_binding(&self, host: &HostTarget) -> Result<()> {
        let identity = serde_json::to_string(host)?;
        let actual: String =
            self.db
                .query_row("SELECT host FROM identity WHERE id=1", [], |r| r.get(0))?;
        if actual != identity {
            bail!("host work database belongs to another account or trust generation");
        }
        Ok(())
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
        let tx = self.db.unchecked_transaction()?;
        let count: usize = tx.query_row("SELECT count(*) FROM messages", [], |r| r.get(0))?;
        let tasks: usize = tx.query_row("SELECT count(*) FROM work", [], |r| r.get(0))?;
        let active: usize = tx.query_row("SELECT count(*) FROM work WHERE state IN ('queued','blocked','submitting','submitted','awaiting_result')", [], |r| r.get(0))?;
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

    pub fn enqueue(&self, record: &WorkRecord) -> Result<bool> {
        if let Some(old) = self.work(&record.task.task_id)? {
            if old.principal != record.principal || old.digest != record.digest {
                bail!("request_id_reused");
            }
            return Ok(false);
        }
        self.capacity("work")?;
        let active: usize = self.db.query_row("SELECT count(*) FROM work WHERE state IN ('queued','blocked','submitting','submitted','awaiting_result')", [], |r| r.get(0))?;
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

    /// No retention pruning: identities remain tombstones at a bounded
    /// capacity. Deleting a result must never turn an old retry into work.
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

pub fn check(dir: &Path) -> Result<()> {
    let config = Config::load(dir)?;
    println!(
        "Agent hosting: {}",
        if config.enabled {
            "enabled"
        } else {
            "disabled"
        }
    );
    for profile in &config.profiles {
        profile
            .launch(
                crate::session::SessionId::new().to_string(),
                uuid::Uuid::new_v4().to_string(),
            )
            .with_context(|| format!("checking profile {}", profile.id))?;
        println!(
            "  {}: {} (revision {})",
            profile.id, profile.provider, profile.revision
        );
    }
    println!("{} notification route(s).", config.routes.len());
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
}

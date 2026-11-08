//! End-to-end encryption for relay-backed memory, skills, and vaults.
//! Local knowledge.db remains plaintext; transforms happen only at HTTP edges.
//! `K` lives only in the cred agent: `EncryptionContext` reads
//! the mode from the signed account state and asks the agent to seal, open
//! and hash. Also: private atomic file writes for every key file.

use anyhow::{anyhow, bail, Context, Result};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::memory::account_keys::{CryptOp, CryptOut};
use crate::memory::cred_agent::CredAgentApi;
use crate::memory::model::{content_hash, skill_hash, Memory, Skill};
use crate::paths::CredPaths;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EncryptionMode {
    #[default]
    Off,
    Enabling,
    On,
    Disabling,
}

impl EncryptionMode {
    pub fn parse(value: &str) -> Result<Self> {
        match value {
            "off" => Ok(Self::Off),
            "enabling" => Ok(Self::Enabling),
            "on" => Ok(Self::On),
            "disabling" => Ok(Self::Disabling),
            _ => bail!("unknown encryption mode {value:?}"),
        }
    }

    /// The statement spelling; atem only parses modes, so tests alone encode.
    #[cfg(test)]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Enabling => "enabling",
            Self::On => "on",
            Self::Disabling => "disabling",
        }
    }

    pub fn requires_key(self) -> bool {
        self != Self::Off
    }
}


#[cfg(unix)]
fn set_mode_600(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_mode_600(_path: &Path) -> Result<()> { Ok(()) }

/// A temp name beside `path` that no other writer (thread or process) uses:
/// `.<name>.<pid>.<counter>.<random>.tmp`.
fn unique_temp(path: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let random = rand::RngCore::next_u32(&mut OsRng);
    let name = path.file_name().map(|name| name.to_string_lossy().into_owned()).unwrap_or_default();
    path.with_file_name(format!(
        ".{name}.{}.{}.{random:08x}.tmp",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
    ))
}

/// A temp of `path` (see `unique_temp`) that its writer left behind: the
/// writer's process is gone, or the temp is over an hour old (a write takes
/// milliseconds; the pid may have been reused). Not followed if a symlink.
#[cfg(unix)]
fn is_stale_temp(path: &Path, entry: &fs::DirEntry) -> bool {
    use std::os::unix::fs::MetadataExt;
    let Some(name) = path.file_name().map(|name| name.to_string_lossy().into_owned()) else { return false };
    let entry_name = entry.file_name().to_string_lossy().into_owned();
    let Some(rest) = entry_name.strip_prefix(&format!(".{name}.")).and_then(|rest| rest.strip_suffix(".tmp")) else {
        return false;
    };
    // `<pid>.<counter>.<random>`
    let parts: Vec<&str> = rest.split('.').collect();
    let [pid, counter, random] = parts[..] else { return false };
    let (Ok(pid), true, true) = (
        pid.parse::<u32>(),
        !counter.is_empty() && counter.bytes().all(|byte| byte.is_ascii_digit()),
        random.len() == 8 && random.bytes().all(|byte| byte.is_ascii_hexdigit()),
    ) else {
        return false;
    };
    let Ok(meta) = entry.path().symlink_metadata() else { return false };
    if meta.uid() != unsafe { libc::getuid() } || meta.is_dir() {
        return false;
    }
    let gone = pid == 0
        || i32::try_from(pid).is_err()
        || (unsafe { libc::kill(pid as libc::pid_t, 0) } != 0
            && std::io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH));
    let old = meta.modified().ok().and_then(|time| time.elapsed().ok())
        .is_some_and(|age| age > std::time::Duration::from_secs(3600));
    gone || old
}

/// Deletes the temps of `path` that crashed writers left behind (they can
/// hold secrets: a sealed file's or a plain key file's bytes). Best effort.
pub(crate) fn sweep_stale_temps(path: &Path) {
    #[cfg(unix)]
    {
        let dir = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        let Ok(entries) = fs::read_dir(dir) else { return };
        for entry in entries.flatten() {
            if is_stale_temp(path, &entry) {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
    #[cfg(not(unix))]
    let _ = path;
}

#[cfg(test)]
thread_local! {
    static FAILING_WRITES: std::cell::RefCell<Vec<PathBuf>> = const { std::cell::RefCell::new(Vec::new()) };
    static FAILING_AFTER_RENAME: std::cell::RefCell<Vec<PathBuf>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Test hook: `write_private` to `path` renames the new bytes into place,
/// then fails (as a failed directory fsync would: the outcome on disk is
/// uncertain), on this thread until the guard is dropped.
#[cfg(test)]
pub(crate) fn fail_after_rename(path: &Path) -> FailingAfterRename {
    FAILING_AFTER_RENAME.with(|failing| failing.borrow_mut().push(path.to_path_buf()));
    FailingAfterRename(path.to_path_buf())
}

#[cfg(test)]
pub(crate) struct FailingAfterRename(PathBuf);

#[cfg(test)]
impl Drop for FailingAfterRename {
    fn drop(&mut self) {
        FAILING_AFTER_RENAME.with(|failing| failing.borrow_mut().retain(|path| *path != self.0));
    }
}

/// Test hook: `write_private` to `path` fails on this thread until the
/// guard is dropped.
#[cfg(test)]
pub(crate) fn fail_writes_to(path: &Path) -> FailingWrite {
    FAILING_WRITES.with(|failing| failing.borrow_mut().push(path.to_path_buf()));
    FailingWrite(path.to_path_buf())
}

#[cfg(test)]
pub(crate) struct FailingWrite(PathBuf);

#[cfg(test)]
impl Drop for FailingWrite {
    fn drop(&mut self) {
        FAILING_WRITES.with(|failing| failing.borrow_mut().retain(|path| *path != self.0));
    }
}

/// Writes `bytes` to `path` as a 0600 file: a fresh temp file with a name of
/// its own (never a stale one or a symlink, never another writer's), fsync,
/// rename, then fsync the directory.
pub(crate) fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    use std::io::Write;
    #[cfg(test)]
    if FAILING_WRITES.with(|failing| failing.borrow().iter().any(|failing| failing == path)) {
        bail!("injected write failure for {}", path.display());
    }
    if let Some(parent) = path.parent() { crate::paths::create_private_dir(parent)?; }
    sweep_stale_temps(path);
    let temp = unique_temp(path);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options.open(&temp)?;
    if let Err(error) = file.write_all(bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&temp);
        return Err(error.into());
    }
    drop(file);
    if let Err(error) = fs::rename(&temp, path) {
        let _ = fs::remove_file(&temp);
        return Err(error.into());
    }
    set_mode_600(path)?;
    #[cfg(test)]
    if FAILING_AFTER_RENAME.with(|failing| failing.borrow().iter().any(|failing| failing == path)) {
        bail!("injected directory fsync failure for {}", path.display());
    }
    #[cfg(unix)]
    {
        let parent = match path.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent,
            _ => Path::new("."),
        };
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

pub(crate) fn valid_kid(kid: &str) -> bool {
    kid.len() == 8 && kid.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Most bytes and operations one `Crypt` request carries; bigger batches are
/// split. One skill (at most `MAX_SKILL_BYTES`, 1 MiB) always fits. The
/// agent's frames are bounded by the same numbers (agent_frame.rs).
pub(crate) const CRYPT_BATCH_BYTES: usize = 2 << 20;
pub(crate) const CRYPT_BATCH_OPS: usize = 1024;
/// Most bytes one op may carry (`wire_len`, request and reply): well below
/// the agent's 8 MiB line limit, so a field never makes the agent hang up.
pub(crate) const CRYPT_OP_MAX_BYTES: usize = 6 << 20;

const UNKNOWN_PROJECT: &str = "encrypted project name is unknown on this Atem; sync from a device that used it first";

/// What a batch adds to one step of its `Crypt` work: its ops, their bytes
/// as `run` counts them (`CryptOp::wire_len`), and its largest op. For
/// planning batches only: `run` splits at the limits itself, so a wrong
/// estimate costs a request, never a result.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Cost {
    pub ops: usize,
    pub bytes: usize,
    pub largest: usize,
}

impl Cost {
    fn one(bytes: usize) -> Self {
        Self { ops: 1, bytes, largest: bytes }
    }

    fn seal(record: &str, field: usize, plain: usize) -> Self {
        if plain == 0 { return Self::default(); }
        Self::one(CryptOp::seal_wire_len(record.len(), field, plain))
    }

    fn open(record: &str, field: usize, value: usize) -> Self {
        if value == 0 { return Self::default(); }
        Self::one(CryptOp::open_wire_len(record.len(), field, value))
    }

    fn hash(value: usize) -> Self {
        Self::one(CryptOp::keyed_hash_wire_len(value))
    }
}

impl std::ops::Add for Cost {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        Self { ops: self.ops + other.ops, bytes: self.bytes + other.bytes, largest: self.largest.max(other.largest) }
    }
}

impl std::ops::AddAssign for Cost {
    fn add_assign(&mut self, other: Self) {
        *self = *self + other;
    }
}

/// An item's cost in each dependent `Crypt` step of its batch, in order:
/// opening, then sealing (paths and hashes), then a skill's files (sealed
/// under their sealed paths, so after the paths).
pub(crate) type Steps = [Cost; 3];

/// Most `Crypt` requests' worth a planned group holds per step: what a
/// group of relay chunks may be sealed or opened together in (and so how
/// far sealing runs ahead of the relay).
pub(crate) const GROUP_REQUESTS: usize = 4;

/// Whether some op of `steps` is over the agent's limit for one op: `run`
/// refuses the whole batch holding it.
pub(crate) fn too_large(steps: &Steps) -> bool {
    steps.iter().any(|step| step.largest > CRYPT_OP_MAX_BYTES)
}

/// Whole relay chunks gathered into one group of `Crypt` work (F2): each
/// step stays within `GROUP_REQUESTS` requests' worth (ops, bytes, and
/// items: an op with no sealed field costs nothing), the first chunk always
/// fits, and a chunk with an op over the agent's limit is a group of its own
/// (so it fails alone, as it did when each chunk was sealed alone).
///
/// `run` splits each step of a group at the agent's limits, op by op, in
/// order. Sealing whole chunks together this way never takes more requests
/// than sealing each chunk alone: packing ops in order into requests, a
/// sequence never needs more requests than its parts packed apart.
#[derive(Debug, Default)]
struct Budget {
    steps: Steps,
    items: usize,
}

impl Budget {
    fn fits(&self, chunk: &Steps, items: usize) -> bool {
        self.items == 0
            || (!too_large(chunk)
                && self.items + items <= GROUP_REQUESTS * CRYPT_BATCH_OPS
                && self.steps.iter().zip(chunk).all(|(used, more)| {
                    used.ops + more.ops <= GROUP_REQUESTS * CRYPT_BATCH_OPS
                        && used.bytes + more.bytes <= GROUP_REQUESTS * CRYPT_BATCH_BYTES
                }))
    }

    fn add(&mut self, chunk: &Steps, items: usize) {
        for (used, more) in self.steps.iter_mut().zip(chunk) {
            *used += *more;
        }
        self.items += items;
    }

    /// No chunk may join after one with an op over the agent's limit.
    fn closed(&self) -> bool {
        too_large(&self.steps)
    }
}

/// The one rule that plans a group, a relay chunk at a time (F2): the push
/// (`sync::read_group`) and the migration (`plan_groups`) both use it. A
/// group takes whole chunks within its `Budget`; a run's first group is its
/// first chunk alone, so the first POST starts as soon as it is sealed (wall
/// time first: this can cost one request more than packing it with the next
/// chunks).
#[derive(Debug, Default)]
pub(crate) struct Planner {
    budget: Budget,
    chunks: usize,
    one_chunk: bool,
}

impl Planner {
    /// A group's planner; `first`: the run's first group (one chunk).
    pub(crate) fn new(first: bool) -> Self {
        Self { one_chunk: first, ..Self::default() }
    }

    /// Whether the next chunk (its steps and its item count) joins this
    /// group; it is counted in when it does.
    pub(crate) fn take(&mut self, chunk: &Steps, items: usize) -> bool {
        let joins = self.chunks == 0
            || (!self.one_chunk && !self.budget.closed() && self.budget.fits(chunk, items));
        if joins {
            self.budget.add(chunk, items);
            self.chunks += 1;
        }
        joins
    }
}

/// The steps of `items` together.
pub(crate) fn total<T>(items: &[T], cost: impl Fn(&T) -> Steps) -> Steps {
    items.iter().map(cost).fold(Steps::default(), |mut sum, item| {
        for (sum, more) in sum.iter_mut().zip(item) {
            *sum += more;
        }
        sum
    })
}

/// `items`, sent to the relay `chunk` at a time, in groups of whole chunks
/// planned by `Planner` (F2): never more `Crypt` requests than sealing each
/// chunk alone, and the first chunk alone.
pub(crate) fn plan_groups<T>(items: &[T], chunk: usize, cost: impl Fn(&T) -> Steps) -> Vec<std::ops::Range<usize>> {
    let mut groups = Vec::new();
    let (mut start, mut planner) = (0, Planner::new(true));
    for (index, part) in items.chunks(chunk.max(1)).enumerate() {
        let at = index * chunk.max(1);
        let part_cost = total(part, &cost);
        if !planner.take(&part_cost, part.len()) {
            groups.push(start..at);
            (start, planner) = (at, Planner::new(false));
            planner.take(&part_cost, part.len());
        }
    }
    if start < items.len() {
        groups.push(start..items.len());
    }
    groups
}

/// What `encrypt_memories` asks the agent for `memory`.
pub(crate) fn memory_seal_cost(memory: &Memory) -> Cost {
    let mut cost = Cost::default();
    if !memory.project.is_empty() { cost += Cost::hash(memory.project.len()); }
    if !memory.content.is_empty() {
        cost += Cost::hash(memory.content.len()) + Cost::seal(&memory.id, "content".len(), memory.content.len());
    }
    cost
}

/// What `decrypt_memories` asks the agent for `memory`.
pub(crate) fn memory_open_cost(memory: &Memory) -> Cost {
    if !memory.content.starts_with("e1.") { return Cost::default(); }
    Cost::open(&memory.id, "content".len(), memory.content.len())
}

/// A skill's content hash: hex SHA-256 (`skill_hash`).
const SKILL_HASH_LEN: usize = 64;

/// What `encrypt_skills` asks the agent for `skill`, in its two requests:
/// paths and hashes, then the files.
pub(crate) fn skill_seal_cost(skill: &Skill) -> [Cost; 2] {
    let record = skill_record(skill);
    let mut first = Cost::hash(SKILL_HASH_LEN) + project_hash_cost(&skill.project);
    let mut files = Cost::default();
    for (path, bytes) in &skill.files {
        first += Cost::seal(&record, "path".len(), path.len());
        files += Cost::seal(&record, "file:".len() + crate::memory::account_keys::sealed_len(path.len()), bytes.len());
    }
    [first, files]
}

/// What `decrypt_skills` asks the agent for `skill`.
pub(crate) fn skill_open_cost(skill: &Skill) -> Cost {
    if !skill.files.keys().any(|path| path.starts_with("e1.")) { return Cost::default(); }
    let record = skill_record(skill);
    skill.files.iter()
        .map(|(path, bytes)| Cost::open(&record, "path".len(), path.len()) + Cost::open(&record, "file:".len() + path.len(), bytes.len()))
        .fold(Cost::default(), |sum, cost| sum + cost)
}

/// What `wire_projects` asks the agent for `project`.
pub(crate) fn project_hash_cost(project: &str) -> Cost {
    if project.is_empty() { Cost::default() } else { Cost::hash(project.len()) }
}

/// One Astation's encryption mode, and a handle on the cred agent, which
/// holds `K` and does every seal, open and keyed hash: this process never
/// sees `K`. Mode and kid come from the latest signed account state; off
/// (and unverified) contexts never touch the agent. Methods that reach the
/// agent block on its socket: from async code run them inside `blocking`.
#[derive(Clone)]
pub struct EncryptionContext {
    pub mode: EncryptionMode,
    pub data_account: String,
    pub kid: Option<String>,
    astation_id: String,
    /// `None` while encryption is off.
    agent: Option<Arc<dyn CredAgentApi>>,
    names_path: PathBuf,
    remember_off_projects: bool,
}

impl std::fmt::Debug for EncryptionContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptionContext")
            .field("mode", &self.mode)
            .field("data_account", &self.data_account)
            .field("kid", &self.kid)
            .finish_non_exhaustive()
    }
}

fn next_text(results: &mut impl Iterator<Item = CryptOut>) -> Result<String> {
    results.next().ok_or_else(|| anyhow!("the cred agent answered too few operations"))?.into_text()
}

fn next_plain(results: &mut impl Iterator<Item = CryptOut>) -> Result<Vec<u8>> {
    Ok(results.next().ok_or_else(|| anyhow!("the cred agent answered too few operations"))?.into_plain()?.to_vec())
}

#[cfg(test)]
fn one<T>(items: Vec<T>) -> Result<T> {
    items.into_iter().next().ok_or_else(|| anyhow!("encryption returned nothing"))
}

impl EncryptionContext {
    pub fn for_astation(astation_id: &str) -> Result<Self> {
        Self::for_astation_with(
            astation_id,
            &CredPaths::default_paths(),
            crate::memory::cred_agent::default_agent(),
        )
    }

    pub(crate) fn for_astation_with(astation_id: &str, paths: &CredPaths, agent: Arc<dyn CredAgentApi>) -> Result<Self> {
        let state = crate::memory::verification::account_mode(&paths.trust, astation_id)?;
        let remember_off_projects = crate::memory::trust::TrustStore::load_from(&paths.trust)?
            .verified(astation_id).is_some_and(|entry| entry.data_account == state.data_account);
        Ok(Self {
            mode: state.mode,
            data_account: state.data_account,
            kid: state.kid,
            astation_id: astation_id.into(),
            agent: state.mode.requires_key().then_some(agent),
            names_path: paths.project_names.clone(),
            remember_off_projects,
        })
    }

    /// Runs `work` on a blocking thread when it may reach the cred agent
    /// (socket I/O and autostart must not stall the runtime); inline
    /// when encryption is off.
    pub async fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce(&Self) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        if self.agent.is_none() {
            return work(self);
        }
        let context = self.clone();
        crate::memory::cred_agent::blocking(move || work(&context)).await
    }

    /// `ops` in as few `Crypt` requests as the budget allows, results in order.
    fn run(&self, ops: Vec<CryptOp>) -> Result<Vec<CryptOut>> {
        if ops.is_empty() {
            return Ok(Vec::new());
        }
        let agent = self.agent.as_deref().ok_or_else(|| anyhow!(crate::memory::account_keys::ENCRYPTION_OFF))?;
        if let Some(op) = ops.iter().find(|op| op.wire_len() > CRYPT_OP_MAX_BYTES) {
            bail!("a field is too large to encrypt ({} bytes)", op.field_len());
        }
        let mut results = Vec::with_capacity(ops.len());
        let mut batch = Vec::new();
        let mut bytes = 0;
        for op in ops {
            let size = op.wire_len();
            if !batch.is_empty() && (bytes + size > CRYPT_BATCH_BYTES || batch.len() >= CRYPT_BATCH_OPS) {
                results.extend(agent.crypt(&self.astation_id, std::mem::take(&mut batch))?);
                bytes = 0;
            }
            bytes += size;
            batch.push(op);
        }
        results.extend(agent.crypt(&self.astation_id, batch)?);
        Ok(results)
    }

    /// Fails as a locked agent's `Crypt` does while the cred agent is locked;
    /// nothing to confirm without an agent (encryption off).
    pub fn confirm_unlocked(&self) -> Result<()> {
        let Some(agent) = &self.agent else { return Ok(()) };
        if !agent.status()?.unlocked {
            bail!(crate::memory::cred_agent::LOCKED);
        }
        Ok(())
    }

    pub fn should_encrypt(&self) -> bool {
        matches!(self.mode, EncryptionMode::Enabling | EncryptionMode::On)
    }

    pub fn wire_project(&self, project: &str) -> Result<String> {
        if project.is_empty() { return Ok(project.to_string()); }
        Ok(self.wire_projects(&[project.to_string()])?.remove(0))
    }

    /// Project keys as the relay sees them (`h1.` hashes while encrypting),
    /// remembered in project_names.json. Empty stays empty.
    pub fn wire_projects(&self, projects: &[String]) -> Result<Vec<String>> {
        if !self.should_encrypt() {
            if self.remember_off_projects {
                let _ = self.remember(projects.iter().filter(|project| !project.is_empty()).map(|project| (project.clone(), project.clone())).collect());
            }
            return Ok(projects.to_vec());
        }
        let ops = projects.iter()
            .filter(|project| !project.is_empty())
            .map(|project| CryptOp::keyed_hash(project.as_bytes()))
            .collect();
        let mut results = self.run(ops)?.into_iter();
        let mut names = Vec::new();
        let wire = projects.iter()
            .map(|project| {
                if project.is_empty() { return Ok(String::new()); }
                let hash = next_text(&mut results)?;
                names.push((hash.clone(), project.clone()));
                Ok(hash)
            })
            .collect::<Result<Vec<_>>>()?;
        self.remember(names)?;
        Ok(wire)
    }

    pub fn seal(&self, record: &str, field: &str, plain: &[u8]) -> Result<String> {
        Ok(self.seal_many(&[(record, field, plain)])?.remove(0))
    }

    /// `e1.` fields for `(record, field, plain)`; empty plain text stays empty.
    pub fn seal_many(&self, items: &[(&str, &str, &[u8])]) -> Result<Vec<String>> {
        let ops = items.iter()
            .filter(|(_, _, plain)| !plain.is_empty())
            .map(|(record, field, plain)| CryptOp::seal(record, field, plain))
            .collect();
        let mut results = self.run(ops)?.into_iter();
        items.iter()
            .map(|(_, _, plain)| if plain.is_empty() { Ok(String::new()) } else { next_text(&mut results) })
            .collect()
    }

    #[cfg(test)]
    pub fn open(&self, record: &str, field: &str, value: &str) -> Result<Vec<u8>> {
        Ok(self.open_many(&[(record, field, value)])?.remove(0))
    }

    /// The bytes of `(record, field, e1. value)`; an empty value stays empty.
    pub fn open_many(&self, items: &[(&str, &str, &str)]) -> Result<Vec<Vec<u8>>> {
        let ops = items.iter()
            .filter(|(_, _, value)| !value.is_empty())
            .map(|(record, field, value)| CryptOp::open(record, field, value))
            .collect();
        let mut results = self.run(ops)?.into_iter();
        items.iter()
            .map(|(_, _, value)| if value.is_empty() { Ok(Vec::new()) } else { next_plain(&mut results) })
            .collect()
    }

    #[cfg(test)]
    pub fn keyed_hash(&self, value: &[u8]) -> Result<String> {
        let mut results = self.run(vec![CryptOp::keyed_hash(value)])?.into_iter();
        next_text(&mut results)
    }

    #[cfg(test)]
    pub fn encrypt_memory(&self, memory: Memory) -> Result<Memory> {
        one(self.encrypt_memories(vec![memory])?)
    }

    /// Every memory's project and content hash and sealed content, in one
    /// batch of agent requests.
    pub fn encrypt_memories(&self, memories: Vec<Memory>) -> Result<Vec<Memory>> {
        if !self.should_encrypt() { return Ok(memories); }
        let mut ops = Vec::new();
        for memory in &memories {
            if !memory.project.is_empty() { ops.push(CryptOp::keyed_hash(memory.project.as_bytes())); }
            if !memory.content.is_empty() {
                ops.push(CryptOp::keyed_hash(memory.content.as_bytes()));
                ops.push(CryptOp::seal(&memory.id, "content", memory.content.as_bytes()));
            }
        }
        let mut results = self.run(ops)?.into_iter();
        let mut names = Vec::new();
        let mut encrypted = Vec::with_capacity(memories.len());
        for mut memory in memories {
            if !memory.project.is_empty() {
                let hash = next_text(&mut results)?;
                names.push((hash.clone(), std::mem::replace(&mut memory.project, hash)));
            }
            if memory.content.is_empty() {
                memory.content_hash = String::new();
            } else {
                memory.content_hash = next_text(&mut results)?;
                memory.content = next_text(&mut results)?;
            }
            encrypted.push(memory);
        }
        self.remember(names)?;
        Ok(encrypted)
    }

    /// While encryption is on, every non-empty field from the relay must be
    /// sealed (`e1.`) or keyed (`h1.`). Plain text would let the relay inject
    /// instructions into the managed blocks agents read. Checked before any
    /// agent call.
    pub fn require_sealed(&self, value: &str, prefix: &str, what: &str) -> Result<()> {
        if self.mode == EncryptionMode::On && !value.is_empty() && !value.starts_with(prefix) {
            bail!("relay sent plain-text {what} while encryption is on; refusing it");
        }
        Ok(())
    }

    #[cfg(test)]
    pub fn decrypt_memory(&self, memory: Memory) -> Result<Memory> {
        one(self.decrypt_memories(vec![memory])?)
    }

    pub fn decrypt_memories(&self, memories: Vec<Memory>) -> Result<Vec<Memory>> {
        if self.mode == EncryptionMode::Off { return Ok(memories); }
        for memory in &memories {
            self.require_sealed(&memory.content, "e1.", "memory content")?;
            self.require_sealed(&memory.project, "h1.", "memory project")?;
        }
        let names = if memories.iter().any(|memory| memory.project.starts_with("h1.")) { Some(self.names()?) } else { None };
        let ops = memories.iter()
            .filter(|memory| memory.content.starts_with("e1."))
            .map(|memory| CryptOp::open(&memory.id, "content", &memory.content))
            .collect();
        let mut results = self.run(ops)?.into_iter();
        memories.into_iter()
            .map(|mut memory| {
                if memory.project.starts_with("h1.") {
                    memory.project = names.as_ref()
                        .and_then(|names| names.name(&self.data_account, &memory.project))
                        .map(str::to_string)
                        .ok_or_else(|| anyhow!(UNKNOWN_PROJECT))?;
                }
                if memory.content.starts_with("e1.") {
                    memory.content = String::from_utf8(next_plain(&mut results)?)
                        .context("memory content is not UTF-8")?;
                }
                if memory.content_hash.starts_with("h1.") {
                    memory.content_hash = content_hash(&memory.content);
                }
                Ok(memory)
            })
            .collect()
    }

    #[cfg(test)]
    pub fn encrypt_skill(&self, skill: Skill) -> Result<Skill> {
        one(self.encrypt_skills(vec![skill])?)
    }

    /// Two batches: every file path with the project and content hashes,
    /// then every file's bytes bound to its encrypted path.
    pub fn encrypt_skills(&self, skills: Vec<Skill>) -> Result<Vec<Skill>> {
        Ok(self.encrypt_skills_with_projects(skills, &[])?.0)
    }

    /// `encrypt_skills`, and `projects` as `wire_projects` makes them, with
    /// their hashes in the skills' first batch: a push of skills with their
    /// deletes and purges is two agent requests, not three.
    pub fn encrypt_skills_with_projects(&self, skills: Vec<Skill>, projects: &[String]) -> Result<(Vec<Skill>, Vec<String>)> {
        if !self.should_encrypt() { return Ok((skills, self.wire_projects(projects)?)); }
        let mut ops = Vec::new();
        for skill in &skills {
            let record = skill_record(skill);
            for path in skill.files.keys() {
                if !path.is_empty() { ops.push(CryptOp::seal(&record, "path", path.as_bytes())); }
            }
            if !skill.project.is_empty() { ops.push(CryptOp::keyed_hash(skill.project.as_bytes())); }
            ops.push(CryptOp::keyed_hash(skill_hash(&skill.files).as_bytes()));
        }
        ops.extend(projects.iter().filter(|project| !project.is_empty()).map(|project| CryptOp::keyed_hash(project.as_bytes())));
        let mut results = self.run(ops)?.into_iter();
        let mut names = Vec::new();
        let mut staged = Vec::with_capacity(skills.len());
        for skill in skills {
            let paths = skill.files.keys()
                .map(|path| if path.is_empty() { Ok(String::new()) } else { next_text(&mut results) })
                .collect::<Result<Vec<_>>>()?;
            let project = if skill.project.is_empty() {
                String::new()
            } else {
                let hash = next_text(&mut results)?;
                names.push((hash.clone(), skill.project.clone()));
                hash
            };
            let hash = next_text(&mut results)?;
            staged.push((skill, paths, project, hash));
        }
        let wire = projects.iter()
            .map(|project| {
                if project.is_empty() { return Ok(String::new()); }
                let hash = next_text(&mut results)?;
                names.push((hash.clone(), project.clone()));
                Ok(hash)
            })
            .collect::<Result<Vec<_>>>()?;
        let mut ops = Vec::new();
        for (skill, paths, _, _) in &staged {
            let record = skill_record(skill);
            for ((_, bytes), path) in skill.files.iter().zip(paths) {
                if !bytes.is_empty() { ops.push(CryptOp::seal(&record, &format!("file:{path}"), bytes)); }
            }
        }
        let mut results = self.run(ops)?.into_iter();
        let mut encrypted = Vec::with_capacity(staged.len());
        for (mut skill, paths, project, hash) in staged {
            let mut files = std::collections::BTreeMap::new();
            for ((_, bytes), path) in skill.files.iter().zip(paths) {
                let sealed = if bytes.is_empty() { String::new() } else { next_text(&mut results)? };
                files.insert(path, sealed.into_bytes());
            }
            skill.files = files;
            skill.project = project;
            skill.content_hash = hash;
            encrypted.push(skill);
        }
        self.remember(names)?;
        Ok((encrypted, wire))
    }

    pub fn decrypt_skill(&self, skill: Skill) -> Result<Skill> {
        self.decrypt_skills(vec![skill])?.into_iter().next().ok_or_else(|| anyhow!("decryption returned nothing"))
    }

    pub fn decrypt_skills(&self, skills: Vec<Skill>) -> Result<Vec<Skill>> {
        if self.mode == EncryptionMode::Off { return Ok(skills); }
        for skill in &skills {
            self.require_sealed(&skill.project, "h1.", "skill project")?;
            for path in skill.files.keys() {
                self.require_sealed(path, "e1.", "skill file path")?;
            }
        }
        let names = if skills.iter().any(|skill| skill.project.starts_with("h1.")) { Some(self.names()?) } else { None };
        let sealed = |skill: &Skill| skill.files.keys().any(|path| path.starts_with("e1."));
        let mut ops = Vec::new();
        for skill in skills.iter().filter(|skill| sealed(skill)) {
            let record = skill_record(skill);
            for (path, bytes) in &skill.files {
                if !path.is_empty() { ops.push(CryptOp::open(&record, "path", path)); }
                let envelope = std::str::from_utf8(bytes).context("skill ciphertext is not UTF-8")?;
                if !envelope.is_empty() { ops.push(CryptOp::open(&record, &format!("file:{path}"), envelope)); }
            }
        }
        let mut results = self.run(ops)?.into_iter();
        skills.into_iter()
            .map(|mut skill| {
                if skill.project.starts_with("h1.") {
                    skill.project = names.as_ref()
                        .and_then(|names| names.name(&self.data_account, &skill.project))
                        .map(str::to_string)
                        .ok_or_else(|| anyhow!(UNKNOWN_PROJECT))?;
                }
                if sealed(&skill) {
                    let mut files = std::collections::BTreeMap::new();
                    for (path, bytes) in &skill.files {
                        let plain_path = if path.is_empty() { Vec::new() } else { next_plain(&mut results)? };
                        let plain_path = String::from_utf8(plain_path).context("skill path is not UTF-8")?;
                        let plain = if bytes.is_empty() { Vec::new() } else { next_plain(&mut results)? };
                        files.insert(plain_path, plain);
                    }
                    skill.files = files;
                }
                if skill.content_hash.starts_with("h1.") {
                    skill.content_hash = skill_hash(&skill.files);
                }
                Ok(skill)
            })
            .collect()
    }

    fn remember(&self, names: Vec<(String, String)>) -> Result<()> {
        crate::memory::project_names::remember(&self.names_path, &self.data_account, names)
    }

    fn names(&self) -> Result<crate::memory::project_names::ProjectNames> {
        crate::memory::project_names::ProjectNames::load_from(&self.names_path)
    }
}

fn skill_record(skill: &Skill) -> String {
    format!("{}:{}:{}", skill.scope.as_str(), skill.name, skill.version)
}

/// Migrates `astation_id`'s relay data (memory, skills, vault) to the
/// signed state's mode for the profile `src`, with `agent`; the target mode
/// once read back, `None` when no migration is pending.
pub async fn migrate_account_in(
    astation_id: &str,
    src: &crate::profile::Sources,
    agent: Arc<dyn CredAgentApi>,
) -> Result<Option<&'static str>> {
    let encryption = EncryptionContext::for_astation_with(astation_id, &src.paths.cred, agent.clone())?;
    let target = match encryption.mode {
        EncryptionMode::Enabling => "on",
        EncryptionMode::Disabling => "off",
        _ => return Ok(None),
    };
    let paired = crate::auth::pairing_session_in(src)
        .map_err(|_| anyhow!(crate::auth::pairing_gate_message("Encryption migration")))?;
    if paired.astation_id != astation_id {
        bail!("the active pairing does not match the encryption account");
    }
    let client_id = src
        .config
        .instance_id
        .clone()
        .filter(|id| !id.is_empty())
        .unwrap_or_else(crate::config::AtemConfig::ensure_instance_id);
    let knowledge = crate::memory::api::KnowledgeClient::new(
        paired.relay_base.clone(),
        client_id.clone(),
        paired.session_id.clone(),
        paired.astation_id.clone(),
    )
    .with_encryption(src.paths.cred.clone(), agent.clone());
    let vault = crate::vault_client::VaultClient::new(
        paired.relay_base,
        client_id,
        paired.session_id,
        paired.astation_id,
    )
    .with_encryption(src.paths.cred.clone(), agent);
    knowledge.migrate_encryption().await
        .map_err(|error| anyhow!(error.to_string()))?;
    vault.migrate_encryption().await?;
    knowledge.verify_encryption_migration().await.map_err(|error| anyhow!(error.to_string()))?;
    vault.verify_encryption_migration().await?;
    Ok(Some(target))
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use crate::memory::fake_astation::{ASTATION_ID, UnlockedDevice};
    use crate::memory::cred_agent::{Reply, Request};

    /// An agent an off context must never reach.
    struct NoAgent;

    impl CredAgentApi for NoAgent {
        fn call(&self, _request: Request) -> Result<Reply> {
            panic!("an off or unverified context must not call the cred agent")
        }
    }

    /// An unlocked device holding K = [7; 32] (kid 0123abcd) in `mode`.
    fn device(dir: &Path, mode: EncryptionMode) -> (UnlockedDevice, EncryptionContext) {
        let mut device = UnlockedDevice::new(dir);
        device.set_key(mode, "0123abcd", [7; 32]);
        let context = EncryptionContext::for_astation_with(ASTATION_ID, &device.paths, device.agent.clone()).unwrap();
        (device, context)
    }

    fn memory(id: &str, project: &str, content: &str) -> Memory {
        Memory {
            id: id.into(),
            scope: crate::memory::model::Scope::Project,
            project: project.into(),
            content: content.into(),
            content_hash: content_hash(content),
            confidence: "high".into(),
            source_agent: "test".into(),
            source_machine: "mac".into(),
            created_at: 1,
            ..Memory::default()
        }
    }

    #[test]
    fn envelope_round_trip_and_tamper_failure() {
        let dir = tempfile::tempdir().unwrap();
        let (_device, context) = device(dir.path(), EncryptionMode::On);
        let sealed = context.seal("mem-1", "content", b"hello").unwrap();
        assert!(sealed.starts_with("e1.0123abcd."));
        assert_eq!(context.open("mem-1", "content", &sealed).unwrap(), b"hello");
        assert!(context.open("mem-2", "content", &sealed).is_err());
        let mut bad = sealed.into_bytes();
        let last = bad.len() - 2;
        bad[last] = if bad[last] == b'A' { b'B' } else { b'A' };
        assert!(context.open("mem-1", "content", std::str::from_utf8(&bad).unwrap()).is_err());
        assert!(context.keyed_hash(b"x").unwrap().starts_with("h1.0123abcd."));
    }

    #[test]
    fn memory_and_binary_skill_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let (_device, context) = device(dir.path(), EncryptionMode::On);
        let plain = memory("mem-1", "github.com/agora/atem", "use port 27183");
        let encrypted = context.encrypt_memory(plain.clone()).unwrap();
        assert!(encrypted.content.starts_with("e1.0123abcd."));
        assert!(encrypted.project.starts_with("h1.0123abcd."));
        assert_eq!(context.decrypt_memory(encrypted).unwrap(), plain);

        let files = BTreeMap::from([
            ("SKILL.md".to_string(), b"hello".to_vec()),
            ("asset.bin".to_string(), vec![0, 159, 146, 150]),
            ("empty.txt".to_string(), Vec::new()),
        ]);
        let skill = Skill {
            scope: crate::memory::model::Scope::Global,
            project: String::new(),
            name: "sample".into(),
            version: 1,
            content_hash: skill_hash(&files),
            files,
            source_agent: "test".into(),
            source_machine: "mac".into(),
            created_at: 1,
            deleted: false,
            seq: 1,
        };
        let encrypted = context.encrypt_skill(skill.clone()).unwrap();
        assert!(encrypted.files.keys().all(|path| path.starts_with("e1.0123abcd.")));
        assert_eq!(context.decrypt_skill(encrypted).unwrap(), skill);
    }

    #[test]
    fn batches_keep_order_and_empty_fields() {
        let dir = tempfile::tempdir().unwrap();
        let (_device, context) = device(dir.path(), EncryptionMode::On);
        let plain = vec![
            memory("mem-1", "github.com/agora/atem", "first"),
            Memory { content_hash: String::new(), ..memory("mem-2", "", "") },
            memory("mem-3", "github.com/agora/dialf", "third"),
        ];
        let encrypted = context.encrypt_memories(plain.clone()).unwrap();
        assert_eq!(encrypted[1].content, "");
        assert_eq!(encrypted[1].content_hash, "");
        assert_eq!(encrypted[1].project, "");
        assert_eq!(context.decrypt_memories(encrypted).unwrap(), plain);
        let sealed = context.seal_many(&[("v", "summary", b"s"), ("v", "content", b""), ("v", "content", b"c")]).unwrap();
        assert_eq!(sealed[1], "");
        let items: Vec<(&str, &str, &str)> = vec![("v", "summary", &sealed[0]), ("v", "content", &sealed[1]), ("v", "content", &sealed[2])];
        assert_eq!(context.open_many(&items).unwrap(), vec![b"s".to_vec(), Vec::new(), b"c".to_vec()]);
    }

    #[test]
    fn project_names_are_remembered_locally_and_resolved() {
        let dir = tempfile::tempdir().unwrap();
        let (device, context) = device(dir.path(), EncryptionMode::On);
        let wire = context.wire_project("github.com/agora/atem").unwrap();
        let names = crate::memory::project_names::ProjectNames::load_from(&device.paths.project_names).unwrap();
        assert_eq!(names.name("acct", &wire), Some("github.com/agora/atem"));
        let unknown = Memory { id: "mem-9".into(), project: "h1.0123abcd.ff".into(), ..Memory::default() };
        let error = context.decrypt_memory(unknown).unwrap_err().to_string();
        assert!(error.contains("unknown on this Atem"), "{error}");
    }

    #[test]
    fn verified_off_projects_are_remembered_without_making_metadata_failures_fatal() {
        let dir = tempfile::tempdir().unwrap();
        let mut device = UnlockedDevice::new(dir.path());
        device.state(EncryptionMode::Off, None);
        let context = EncryptionContext::for_astation_with(ASTATION_ID, &device.paths, Arc::new(NoAgent)).unwrap();
        assert_eq!(context.wire_project("github.com/org/repo").unwrap(), "github.com/org/repo");
        let names = crate::memory::project_names::ProjectNames::load_from(&device.paths.project_names).unwrap();
        assert_eq!(names.projects(&context.data_account), ["github.com/org/repo"]);
        let newer = br#"{"version":9,"accounts":{}}"#;
        std::fs::write(&device.paths.project_names, newer).unwrap();
        assert_eq!(context.wire_project("github.com/org/other").unwrap(), "github.com/org/other");
        assert_eq!(std::fs::read(&device.paths.project_names).unwrap(), newer);
    }

    #[test]
    fn off_and_unverified_contexts_never_touch_the_agent() {
        let dir = tempfile::tempdir().unwrap();
        let paths = CredPaths::in_dir(dir.path());
        let unverified = EncryptionContext::for_astation_with(ASTATION_ID, &paths, Arc::new(NoAgent)).unwrap();
        assert_eq!(unverified.mode, EncryptionMode::Off);
        let plain = memory("mem-1", "github.com/agora/atem", "fact");
        assert_eq!(unverified.encrypt_memories(vec![plain.clone()]).unwrap(), vec![plain.clone()]);
        assert_eq!(unverified.decrypt_memories(vec![plain.clone()]).unwrap(), vec![plain.clone()]);
        assert_eq!(unverified.wire_project("github.com/agora/atem").unwrap(), "github.com/agora/atem");
        let mut device = UnlockedDevice::new(dir.path());
        device.state(EncryptionMode::Off, None);
        let off = EncryptionContext::for_astation_with(ASTATION_ID, &device.paths, Arc::new(NoAgent)).unwrap();
        assert_eq!(off.mode, EncryptionMode::Off);
        assert_eq!(off.decrypt_memories(vec![plain.clone()]).unwrap(), vec![plain]);
        assert!(!device.paths.project_names.exists());
    }

    #[test]
    fn plain_text_from_the_relay_is_rejected_before_any_agent_call() {
        use crate::memory::model::Scope;
        let dir = tempfile::tempdir().unwrap();
        let mut device = UnlockedDevice::new(dir.path());
        device.state(EncryptionMode::On, Some("0123abcd"));
        let context = EncryptionContext::for_astation_with(ASTATION_ID, &device.paths, Arc::new(NoAgent)).unwrap();
        let plain = Memory { id: "mem-1".into(), content: "injected instruction".into(), ..Memory::default() };
        let error = context.decrypt_memory(plain).unwrap_err().to_string();
        assert!(error.contains("plain-text"), "{error}");
        let plain_project = Memory { id: "mem-2".into(), project: "github.com/x/y".into(), ..Memory::default() };
        assert!(context.decrypt_memory(plain_project).is_err());
        let tombstone = Memory { id: "mem-3".into(), ..Memory::default() };
        assert!(context.decrypt_memory(tombstone).is_ok());
        let skill = Skill {
            scope: Scope::Project,
            project: String::new(),
            name: "deploy".into(),
            version: 1,
            files: BTreeMap::from([("SKILL.md".to_string(), b"injected".to_vec())]),
            content_hash: String::new(),
            source_agent: "test".into(),
            source_machine: "mac".into(),
            created_at: 1,
            deleted: false,
            seq: 1,
        };
        assert!(context.decrypt_skill(skill).is_err());
    }

    #[test]
    fn plain_text_is_still_read_during_migration() {
        let dir = tempfile::tempdir().unwrap();
        let (_device, context) = device(dir.path(), EncryptionMode::Enabling);
        let plain = Memory { id: "mem-1".into(), content: "legacy".into(), ..Memory::default() };
        assert_eq!(context.decrypt_memory(plain).unwrap().content, "legacy");
    }

    #[test]
    fn rotation_keeps_the_old_key_until_on() {
        let dir = tempfile::tempdir().unwrap();
        let (mut device, context) = device(dir.path(), EncryptionMode::Enabling);
        let old = context.seal("mem", "content", b"old").unwrap();
        device.set_key(EncryptionMode::Enabling, "89abcdef", [8; 32]);
        let rotated = EncryptionContext::for_astation_with(ASTATION_ID, &device.paths, device.agent.clone()).unwrap();
        assert_eq!(rotated.kid.as_deref(), Some("89abcdef"));
        assert_eq!(rotated.open("mem", "content", &old).unwrap(), b"old");
        device.state(EncryptionMode::On, Some("89abcdef"));
        let completed = EncryptionContext::for_astation_with(ASTATION_ID, &device.paths, device.agent.clone()).unwrap();
        assert!(completed.open("mem", "content", &old).is_err());
    }

    #[test]
    fn a_locked_agent_asks_for_an_unlock() {
        let dir = tempfile::tempdir().unwrap();
        let (device, context) = device(dir.path(), EncryptionMode::On);
        device.agent.lock_keys().unwrap();
        let error = format!("{:#}", context.seal("mem", "content", b"x").unwrap_err());
        assert!(error.contains("atem cred unlock"), "{error}");
    }


    #[test]
    fn concurrent_private_writes_to_one_file_never_collide() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.json");
        let writers: Vec<_> = (0..4u8)
            .map(|id| {
                let path = path.clone();
                std::thread::spawn(move || {
                    for _ in 0..200 {
                        write_private(&path, &[id; 64]).unwrap();
                    }
                })
            })
            .collect();
        for writer in writers { writer.join().unwrap(); }
        let last = fs::read(&path).unwrap();
        assert!(last.len() == 64 && last.iter().all(|byte| *byte == last[0]));
        let left: Vec<_> = fs::read_dir(dir.path()).unwrap().map(|entry| entry.unwrap().file_name()).collect();
        assert_eq!(left, vec![std::ffi::OsString::from("store.json")], "no temp files left");
    }

    #[cfg(unix)]
    #[test]
    fn write_private_replaces_a_stale_temp_without_following_it() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.json");
        let victim = dir.path().join("victim");
        fs::write(&victim, b"untouched").unwrap();
        std::os::unix::fs::symlink(&victim, path.with_extension("tmp")).unwrap();
        write_private(&path, b"fresh").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"fresh");
        assert_eq!(fs::read(&victim).unwrap(), b"untouched");
        // Not its temp name: left alone.
        assert!(path.with_extension("tmp").symlink_metadata().is_ok());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    }

    /// A pid no process has (above Linux's and macOS's pid limits).
    #[cfg(unix)]
    const DEAD_PID: u32 = 999_999_999;

    #[cfg(unix)]
    #[test]
    fn write_private_sweeps_temps_left_by_a_crashed_writer() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("store.json");
        let crashed = dir.path().join(format!(".store.json.{DEAD_PID}.3.0badf00d.tmp"));
        fs::write(&crashed, b"half a secret").unwrap();
        // A crashed writer's temp that is a symlink: the link goes, never its target.
        let victim = dir.path().join("victim");
        fs::write(&victim, b"untouched").unwrap();
        let linked = dir.path().join(format!(".store.json.{DEAD_PID}.4.0badf00e.tmp"));
        std::os::unix::fs::symlink(&victim, &linked).unwrap();
        // A live writer's temp (this process: another thread may be writing) stays.
        let live = dir.path().join(format!(".store.json.{}.9.0badf00f.tmp", std::process::id()));
        fs::write(&live, b"in flight").unwrap();
        // Another file's temp, and names that only look alike, stay.
        let other = dir.path().join(format!(".other.json.{DEAD_PID}.1.0badf010.tmp"));
        let unlike = dir.path().join(".store.json.notapid.tmp");
        fs::write(&other, b"x").unwrap();
        fs::write(&unlike, b"x").unwrap();

        write_private(&path, b"fresh").unwrap();
        assert_eq!(fs::read(&path).unwrap(), b"fresh");
        assert!(crashed.symlink_metadata().is_err(), "the crashed writer's temp is swept");
        assert!(linked.symlink_metadata().is_err(), "the stale symlink is swept");
        assert_eq!(fs::read(&victim).unwrap(), b"untouched");
        assert!(live.exists(), "a live writer's temp is left alone");
        assert!(other.exists() && unlike.exists(), "other files' temps are left alone");
    }

    #[test]
    fn group_plans_fill_each_request() {
        let cost = |ops: usize, bytes: usize| [Cost { ops, bytes, largest: bytes / ops.max(1) }, Cost::default(), Cost::default()];
        // 3-op items, 50 per chunk: the first chunk alone, then 27 chunks
        // (4,050 ops) per group.
        let items = vec![3usize; 3000];
        assert_eq!(plan_groups(&items, 50, |&n| cost(n, n * 100)), vec![0..50, 50..1400, 1400..2750, 2750..3000]);
        // Bytes bind first: chunks of 3.2 MiB, two per group; a bigger
        // chunk alone.
        let items = vec![400usize << 10; 48];
        assert_eq!(plan_groups(&items, 8, |&n| cost(1, n)), vec![0..8, 8..24, 24..40, 40..48]);
        let items: Vec<usize> = [vec![1 << 10; 8], vec![2 << 20; 8], vec![1 << 10; 8]].concat();
        assert_eq!(plan_groups(&items, 8, |&n| cost(1, n)), vec![0..8, 8..16, 16..24]);
        // A chunk with an op over the agent's limit is a group of its own.
        let mut items = vec![1usize << 10; 32];
        items[20] = 7 << 20;
        assert_eq!(plan_groups(&items, 8, |&n| cost(1, n)), vec![0..8, 8..16, 16..24, 24..32]);
        // Free items (an invalidation) still close a group.
        let items = vec![0usize; 5000];
        assert_eq!(plan_groups(&items, 50, |&n| cost(n, 0)), vec![0..50, 50..4100, 4100..5000]);
    }

    /// The requests `run` splits `sizes` (each op's `wire_len`, in order) into.
    fn requests(sizes: &[usize]) -> usize {
        let (mut count, mut ops, mut bytes) = (0, 0, 0);
        for &size in sizes {
            if ops > 0 && (bytes + size > CRYPT_BATCH_BYTES || ops >= CRYPT_BATCH_OPS) {
                (count, ops, bytes) = (count + 1, 0, 0);
            }
            (ops, bytes) = (ops + 1, bytes + size);
        }
        count + usize::from(ops > 0)
    }

    #[test]
    fn planned_groups_never_take_more_requests_than_their_chunks_alone() {
        // Items of one to three ops, from tiny to over 1 MiB, in random orders.
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move |below: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % below
        };
        for round in 0..200 {
            let chunk = [8usize, 50, 64][round % 3];
            let big = round % 4 == 0;
            let items: Vec<Vec<usize>> = (0..(50 + next(500)) as usize)
                .map(|_| (0..1 + next(3)).map(|_| if big { 1 + next(1_600_000) as usize } else { 100 + next(1900) as usize }).collect())
                .collect();
            let cost = |item: &Vec<usize>| {
                let step = item.iter().fold(Cost::default(), |sum, &bytes| sum + Cost::one(bytes));
                [step, Cost::default(), Cost::default()]
            };
            let sizes = |range: std::ops::Range<usize>| items[range].iter().flatten().copied().collect::<Vec<_>>();
            let grouped: usize = plan_groups(&items, chunk, cost).into_iter().map(|g| requests(&sizes(g))).sum();
            let alone: usize = (0..items.len()).step_by(chunk).map(|at| requests(&sizes(at..(at + chunk).min(items.len())))).sum();
            assert!(grouped <= alone, "round {round}: {grouped} > {alone}");
            let ops: usize = items.iter().map(Vec::len).sum();
            if !big {
                // Small ops (1,024 of them stay under 2 MiB): at most one
                // request per 1,024 ops, plus one per group.
                let groups = plan_groups(&items, chunk, cost).len();
                assert!(grouped < ops.div_ceil(CRYPT_BATCH_OPS) + groups, "round {round}");
            }
        }
    }

    /// The requests `plan_groups` and `run` take for `items` sent `chunk` at a
    /// time (each item's ops per step, by wire size), and the groups.
    fn planned_requests(items: &[[Vec<usize>; 3]], chunk: usize) -> (usize, usize) {
        let cost = |item: &[Vec<usize>; 3]| item.clone().map(|ops| ops.iter().fold(Cost::default(), |sum, &bytes| sum + Cost::one(bytes)));
        let groups = plan_groups(items, chunk, cost);
        let requests = groups.iter()
            .map(|g| (0..3).map(|step| requests(&items[g.clone()].iter().flat_map(|item| item[step].clone()).collect::<Vec<_>>())).sum::<usize>())
            .sum();
        (requests, groups.len())
    }

    /// The bound designs/e2e-encryption.md "Performance" states for a push or
    /// a rewrite of small ops (each at most 2 KiB on the wire, so only the
    /// 1,024-op limit splits a request). With `ops` `Crypt` ops, `groups`
    /// planned groups and `steps` dependent steps: at most
    /// ⌈ops / 1,024⌉ + steps × groups − 1 requests (each group's last request
    /// per step may be partly filled). With one step and an op in every item
    /// (a push of facts): at most ⌈ops / 1,024⌉ + 1 + ⌈(groups − 2) × (k − 1)
    /// / 1,024⌉, `k` the most ops one chunk carries (a group ends only when
    /// the next chunk would pass 4,096 ops, so it leaves fewer than `k`
    /// unused). And the examples the design names.
    #[test]
    fn planned_requests_stay_within_the_documented_bound() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move |below: u64| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state % below
        };
        for round in 0..60 {
            let chunk = [8usize, 50, 64][round % 3];
            let one_step = round % 2 == 0;
            let count = 500 + next(30_000) as usize;
            let items: Vec<[Vec<usize>; 3]> = (0..count)
                .map(|_| {
                    let counts = if one_step {
                        // A fact: 1 to 3 ops in one step.
                        [1 + next(3), 0, 0]
                    } else if next(4) == 0 {
                        // A delete or an invalidation: no op at all.
                        [0, 0, 0]
                    } else {
                        // A skill or a rewritten row: 0 to 3 ops in each step.
                        [next(4), next(4), next(4)]
                    };
                    // Each op 100 to 1,999 bytes on the wire.
                    counts.map(|n| (0..n).map(|_| 100 + next(1_900) as usize).collect())
                })
                .collect();
            let ops: usize = items.iter().flatten().map(Vec::len).sum();
            let (planned, groups) = planned_requests(&items, chunk);
            let steps = if one_step { 1 } else { 3 };
            assert!(planned < ops.div_ceil(CRYPT_BATCH_OPS) + steps * groups, "round {round}: {planned} requests, {ops} ops, {groups} groups");
            if one_step {
                let k = items.chunks(chunk).map(|part| part.iter().map(|item| item[0].len()).sum::<usize>()).max().unwrap();
                let extra = (groups.saturating_sub(2) * (k - 1)).div_ceil(CRYPT_BATCH_OPS);
                assert!(planned <= ops.div_ceil(CRYPT_BATCH_OPS) + 1 + extra, "round {round}: {planned} > {} + 1 + {extra}", ops.div_ceil(CRYPT_BATCH_OPS));
                // So the groups: the first chunk, then groups of more than
                // 4,096 − k ops each but the last.
                let planned_groups = plan_groups(&items, chunk, |item| [total(&item[0], |&bytes| [Cost::one(bytes), Cost::default(), Cost::default()])[0], Cost::default(), Cost::default()]);
                assert_eq!(planned_groups[0], 0..chunk.min(items.len()));
                for group in planned_groups.iter().skip(1).rev().skip(1) {
                    let group_ops: usize = items[group.clone()].iter().map(|item| item[0].len()).sum();
                    assert!(group_ops > GROUP_REQUESTS * CRYPT_BATCH_OPS - k, "round {round}: a group of {group_ops} ops");
                }
            }
        }
        // Uniform facts of two or three ops, 50 per relay chunk: "1 per 1,024
        // ops plus one for the first chunk" holds up to 4,562 and 5,791
        // facts, then takes a request more now and then.
        let facts = |count: usize, ops: usize| planned_requests(&vec![[vec![200; ops], Vec::new(), Vec::new()]; count], 50).0;
        let wording = |count: usize, ops: usize| (count * ops).div_ceil(CRYPT_BATCH_OPS) + 1;
        for (count, ops, over) in [(4_562, 2, 0), (4_563, 2, 1), (5_791, 3, 0), (5_792, 3, 1), (30_000, 3, 1), (100_000, 3, 4), (100_000, 2, 4)] {
            assert_eq!(facts(count, ops), wording(count, ops) + over, "{count} facts of {ops} ops");
        }
    }

    /// Records each `Crypt` request's op count and bytes.
    struct Sizes {
        inner: Arc<std::sync::Mutex<crate::memory::cred_agent::CredAgent>>,
        seen: std::sync::Mutex<Vec<Cost>>,
    }

    impl CredAgentApi for Sizes {
        fn call(&self, request: Request) -> Result<Reply> {
            if let Request::Crypt { ops, .. } = &request {
                let sizes: Vec<usize> = ops.iter().map(CryptOp::wire_len).collect();
                self.seen.lock().unwrap().push(Cost { ops: ops.len(), bytes: sizes.iter().sum(), largest: sizes.iter().copied().max().unwrap_or(0) });
            }
            self.inner.call(request)
        }
    }

    #[test]
    fn planned_costs_are_the_requests_the_agent_sees() {
        let dir = tempfile::tempdir().unwrap();
        let (device, _) = device(dir.path(), EncryptionMode::On);
        let sizes = Arc::new(Sizes { inner: device.agent.clone(), seen: Default::default() });
        let context = EncryptionContext::for_astation_with(ASTATION_ID, &device.paths, sizes.clone()).unwrap();
        let take = || std::mem::take(&mut *sizes.seen.lock().unwrap());
        let sum = |costs: Vec<Cost>| costs.into_iter().fold(Cost::default(), |a, b| a + b);

        let memories: Vec<Memory> = (0..40).map(|i| {
            let project = if i % 2 == 0 { "github.com/agora/atem" } else { "" };
            memory(&format!("mem-{i}"), project, &"fact ".repeat(i + 1))
        }).collect();
        let sealed = context.encrypt_memories(memories.clone()).unwrap();
        assert_eq!(take(), vec![sum(memories.iter().map(memory_seal_cost).collect())]);
        context.decrypt_memories(sealed.clone()).unwrap();
        assert_eq!(take(), vec![sum(sealed.iter().map(memory_open_cost).collect())]);

        let skills: Vec<Skill> = (0..5).map(|i| {
            let mut files = BTreeMap::new();
            files.insert("SKILL.md".to_string(), format!("# skill {i}").into_bytes());
            files.insert(format!("ref/part-{i}.md"), vec![b'x'; 100 * i]);
            files.insert("empty.md".to_string(), Vec::new());
            Skill {
                scope: crate::memory::model::Scope::Project, project: if i % 2 == 0 { "github.com/agora/atem".into() } else { String::new() },
                name: format!("skill-{i}"), version: 3, content_hash: skill_hash(&files), files,
                source_agent: "test".into(), source_machine: "mac".into(), created_at: 1, deleted: false, seq: 0,
            }
        }).collect();
        let projects = vec!["github.com/agora/atem".to_string(), String::new(), "github.com/agora/other".to_string()];
        let (sealed, wire) = context.encrypt_skills_with_projects(skills.clone(), &projects).unwrap();
        let [first, files] = skills.iter().map(skill_seal_cost)
            .fold([Cost::default(); 2], |[a, b], [c, d]| [a + c, b + d]);
        let first = first + sum(projects.iter().map(|p| project_hash_cost(p)).collect());
        assert_eq!(take(), vec![first, files]);
        assert_eq!(wire, context.wire_projects(&projects).unwrap());
        take();
        context.decrypt_skills(sealed.clone()).unwrap();
        assert_eq!(take(), vec![sum(sealed.iter().map(skill_open_cost).collect())]);
        // The same skills sealed with and without the projects.
        let alone = context.decrypt_skills(context.encrypt_skills(skills.clone()).unwrap()).unwrap();
        assert_eq!(alone, context.decrypt_skills(sealed).unwrap());
        assert_eq!(alone, skills);
    }
}

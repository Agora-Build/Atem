//! `FileJournal`: the host's durable receipt journal on disk (§6).
//!
//! Layout, under a private state directory (0700, owned by this user, never a
//! symlink):
//!
//! ```text
//! <state>/journal.lock          flock held for the journal's life (one writer)
//! <state>/floors                0600, lease-epoch floors of every session
//! <state>/principals            0600, each principal's control state (r8 §H)
//! <state>/refused               0600, the refusal list (r8 §I.2)
//! <state>/clean_close           0600, `{"runtime_epoch": n}` after an orderly stop (r8 §H)
//! <state>/receipts/             0700
//! <state>/receipts/<sid>.log    0600, append-only, one per session with live receipts
//! ```
//!
//! A session's log holds its `Accepted` records (the target names the
//! session) and their `Transition`/`Evicted` records (routed by request id).
//! Lease-epoch floors (`LeaseEpochs`) live in the shared `floors` file, one
//! framed record replaced atomically (temp, fsync, rename, directory fsync)
//! whenever a floor rises; a damaged floors file is refused, never guessed.
//! Floors are kept for every session ever seen (one small entry each, also in
//! `SessionHost`'s in-memory map): a session id is never reused. Principals'
//! control states (`Control`) live the same way in `principals`; a control
//! generation never goes down. The refusal list and the clean-close record
//! are replaced the same way (temp, fsync, rename, directory fsync) and are
//! not appends: they are written after a failed append too (the refusal
//! list) or only with a healthy journal (the clean close, refused once an
//! append failed).
//!
//! Each record is one line, `<len> <crc32> <json>\n`: `len` is the JSON's
//! byte length in decimal, `crc32` the IEEE CRC-32 of those bytes in 8 lower
//! hex digits, `json` `{"seq":N,"t":...}` where `seq` is a journal-wide
//! sequence number (it restores the append order across sessions on `load`).
//! A torn or corrupted record fails the length, checksum, JSON or coherence
//! check (including the §6 transition table); opening the journal truncates
//! the log to the last valid record before it (and warns, without content),
//! and nothing past a bad record is ever trusted.
//!
//! Durability: `append` writes the line and `fdatasync`s it before returning
//! `Ok` (a new log also fsyncs the directory). After any write or sync error
//! the journal cuts the log back to its previous length and fails: every
//! later `append` returns `Err` until the process restarts and reopens it
//! (`SessionHost` halts: a failed `accepted` write is answered `busy` and
//! put on the refusal list, r8 §I). If the cut itself fails it is retried on
//! every refused append, on `reopen` and on drop; after such a double failure
//! the refused request's record may still be on disk, which the refusal list
//! resolves at restart.
//!
//! Compaction rewrites a log with only its live state — the current receipts
//! with their latest state (a payload only while `accepted`; the digest
//! always), no evicted receipts — to `<sid>.log.tmp`, which is fsynced,
//! renamed over the log, and the directory fsynced; a log with nothing live
//! is removed (and its handle dropped). It runs when a request carrying a
//! payload leaves `accepted` (so finished prompt text doesn't stay on disk),
//! when a session's last receipt is evicted, when a log grows past
//! max(threshold (1 MiB by default), 2 × its size after the last compaction),
//! at open for logs with such leftovers, and on `compact_all`. A crash at any
//! point leaves the old or the new log, both valid and replaying to the same
//! state; leftover temp files are removed on open.
//!
//! Prompt payloads are user content: the files are private and nothing here
//! logs a payload.

use super::journal::{self, Journal, JournalError, Record, Refusal, TurnIds};
use super::wire::{self, ReceiptKind, ReceiptState, Target};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Default size past which a session log is compacted.
pub const COMPACT_BYTES: u64 = 1 << 20;
/// Largest record accepted on load (a payload is far smaller).
const MAX_RECORD_BYTES: usize = 8 << 20;
/// Largest `principals` file read on load (see `load_principals`).
const MAX_PRINCIPALS_BYTES: usize = 64 << 20;
const LOG_SUFFIX: &str = ".log";
const TMP_SUFFIX: &str = ".log.tmp";
const FLOORS: &str = "floors";
const PRINCIPALS: &str = "principals";
const REFUSED: &str = "refused";
const CLEAN_CLOSE: &str = "clean_close";

#[derive(Serialize, Deserialize)]
struct FloorsFile {
    floors: BTreeMap<String, u64>,
}

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskControl {
    control: bool,
    control_gen: u64,
    /// r9: the newest membership entry that fenced the principal.
    #[serde(default, skip_serializing_if = "is_zero")]
    fence_seq: u64,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct PrincipalsFile {
    principals: BTreeMap<String, DiskControl>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RefusedFile {
    refused: Vec<Refusal>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CleanClose {
    runtime_epoch: u64,
}

// ── CRC-32 (IEEE 802.3, reflected) ──

const fn crc_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        let mut c = i as u32;
        let mut k = 0;
        while k < 8 {
            c = if c & 1 != 0 {
                0xEDB8_8320 ^ (c >> 1)
            } else {
                c >> 1
            };
            k += 1;
        }
        table[i] = c;
        i += 1;
    }
    table
}

static CRC_TABLE: [u32; 256] = crc_table();

fn crc32(bytes: &[u8]) -> u32 {
    let mut c = !0u32;
    for &b in bytes {
        c = CRC_TABLE[((c ^ b as u32) & 0xff) as usize] ^ (c >> 8);
    }
    !c
}

// ── On-disk record ──

#[derive(Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
enum Disk {
    Accepted {
        seq: u64,
        request_id: String,
        target: Target,
        kind: ReceiptKind,
        payload_digest: String,
        payload: Value,
        updated_at: u64,
        /// r8 §H. A record from before r8 has neither: its principal is
        /// unknown (empty) and it is resolved at the first r8 start, which
        /// never follows a clean close.
        #[serde(default)]
        principal: String,
        #[serde(default)]
        control_gen: u64,
    },
    Rejected {
        seq: u64,
        request_id: String,
        target: Target,
        kind: ReceiptKind,
        payload_digest: String,
        detail: String,
        updated_at: u64,
    },
    Transition {
        seq: u64,
        request_id: String,
        state: ReceiptState,
        detail: Option<String>,
        updated_at: u64,
        /// r8 §D: a completed prompt's turn ids.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        result: Option<TurnIds>,
    },
    Evicted {
        seq: u64,
        request_id: String,
    },
    LeaseEpochs {
        seq: u64,
        session_id: String,
        reserved: u64,
    },
}

impl Disk {
    fn new(seq: u64, record: Record) -> Self {
        match record {
            Record::Accepted {
                request_id,
                target,
                kind,
                payload_digest,
                payload,
                updated_at,
                principal,
                control_gen,
            } => Disk::Accepted {
                seq,
                request_id,
                target,
                kind,
                payload_digest,
                payload,
                updated_at,
                principal,
                control_gen,
            },
            Record::Rejected {
                request_id,
                target,
                kind,
                payload_digest,
                detail,
                updated_at,
            } => Disk::Rejected {
                seq,
                request_id,
                target,
                kind,
                payload_digest,
                detail,
                updated_at,
            },
            Record::Transition {
                request_id,
                state,
                detail,
                updated_at,
                result,
            } => Disk::Transition {
                seq,
                request_id,
                state,
                detail,
                updated_at,
                result,
            },
            Record::Evicted { request_id } => Disk::Evicted { seq, request_id },
            Record::LeaseEpochs {
                session_id,
                reserved,
            } => Disk::LeaseEpochs {
                seq,
                session_id,
                reserved,
            },
            Record::Control { .. } => unreachable!("control states live in the principals file"),
        }
    }

    fn into_parts(self) -> (u64, Record) {
        match self {
            Disk::Accepted {
                seq,
                request_id,
                target,
                kind,
                payload_digest,
                payload,
                updated_at,
                principal,
                control_gen,
            } => (
                seq,
                Record::Accepted {
                    request_id,
                    target,
                    kind,
                    payload_digest,
                    payload,
                    updated_at,
                    principal,
                    control_gen,
                },
            ),
            Disk::Rejected {
                seq,
                request_id,
                target,
                kind,
                payload_digest,
                detail,
                updated_at,
            } => (
                seq,
                Record::Rejected {
                    request_id,
                    target,
                    kind,
                    payload_digest,
                    detail,
                    updated_at,
                },
            ),
            Disk::Transition {
                seq,
                request_id,
                state,
                detail,
                updated_at,
                result,
            } => (
                seq,
                Record::Transition {
                    request_id,
                    state,
                    detail,
                    updated_at,
                    result,
                },
            ),
            Disk::Evicted { seq, request_id } => (seq, Record::Evicted { request_id }),
            Disk::LeaseEpochs {
                seq,
                session_id,
                reserved,
            } => (
                seq,
                Record::LeaseEpochs {
                    session_id,
                    reserved,
                },
            ),
        }
    }
}

/// `<len> <crc32> <json>\n`.
fn frame(json: &[u8]) -> Vec<u8> {
    let mut line = format!("{} {:08x} ", json.len(), crc32(json)).into_bytes();
    line.extend_from_slice(json);
    line.push(b'\n');
    line
}

fn encode(seq: u64, record: Record) -> Result<Vec<u8>, JournalError> {
    let json = serde_json::to_vec(&Disk::new(seq, record))
        .map_err(|e| JournalError(format!("cannot encode a journal record: {e}")))?;
    Ok(frame(&json))
}

/// One record line at the start of `bytes`: the record and the line's length.
fn decode_line(bytes: &[u8]) -> Option<(u64, Record, usize)> {
    let (json, used) = unframe(bytes)?;
    let disk: Disk = serde_json::from_slice(json).ok()?;
    let (seq, record) = disk.into_parts();
    Some((seq, record, used))
}

/// The checked JSON of the frame at the start of `bytes`, and its length.
fn unframe(bytes: &[u8]) -> Option<(&[u8], usize)> {
    unframe_within(bytes, MAX_RECORD_BYTES)
}

/// [`unframe`] with a record of at most `max` bytes.
fn unframe_within(bytes: &[u8], max: usize) -> Option<(&[u8], usize)> {
    let space = bytes.iter().take(21).position(|&b| b == b' ')?;
    let digits = &bytes[..space];
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let len: usize = std::str::from_utf8(digits).ok()?.parse().ok()?;
    if len > max {
        return None;
    }
    let rest = &bytes[space + 1..];
    let hex = rest.get(..8)?;
    if rest.get(8) != Some(&b' ') || !hex.iter().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    let crc = u32::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?;
    let json = rest.get(9..9 + len)?;
    if rest.get(9 + len) != Some(&b'\n') || crc32(json) != crc {
        return None;
    }
    Some((json, space + 1 + 9 + len + 1))
}

/// A session log read up to its first invalid record.
struct Parsed {
    records: Vec<(u64, Record)>,
    /// Bytes up to the end of the last valid record.
    valid_len: u64,
    total_len: u64,
}

/// Reads records while they are well formed and coherent: the session they
/// name is this log's, `seq` never goes back, a transition follows the §6
/// table from the request's current state, an eviction names a live request,
/// and no lease floor or control state appears (those live in their files).
fn parse_log(bytes: &[u8], sid: &str) -> Parsed {
    let mut records = Vec::new();
    let mut at = 0usize;
    let mut last_seq = 0u64;
    let mut live: HashMap<String, ReceiptState> = HashMap::new();
    while at < bytes.len() {
        let Some((seq, record, used)) = decode_line(&bytes[at..]) else {
            break;
        };
        if seq < last_seq {
            break;
        }
        let coherent = match &record {
            Record::Accepted {
                request_id, target, ..
            } => {
                target.session_id == sid
                    && live
                        .insert(request_id.clone(), ReceiptState::Accepted)
                        .is_none()
            }
            Record::Transition {
                request_id, state, ..
            } => match live.get_mut(request_id) {
                Some(current) if journal::valid_transition(*current, *state) => {
                    *current = *state;
                    true
                }
                _ => false,
            },
            Record::Rejected {
                request_id, target, ..
            } => {
                target.session_id == sid
                    && live
                        .insert(request_id.clone(), ReceiptState::Rejected)
                        .is_none()
            }
            Record::Evicted { request_id } => live.remove(request_id).is_some(),
            Record::LeaseEpochs { .. } | Record::Control { .. } => false,
        };
        if !coherent {
            break;
        }
        last_seq = seq;
        records.push((seq, record));
        at += used;
    }
    Parsed {
        records,
        valid_len: at as u64,
        total_len: bytes.len() as u64,
    }
}

// ── Private files ──

fn io_err(what: &str, path: &Path, e: io::Error) -> JournalError {
    JournalError(format!("{what} {}: {e}", path.display()))
}

fn euid() -> u32 {
    unsafe { libc::geteuid() }
}

/// `dir` exists (created 0700 if missing), is a real directory owned by this
/// user that nobody else can write to, and is 0700.
fn private_dir(dir: &Path) -> Result<(), JournalError> {
    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(JournalError(format!(
                    "{} is not a directory (a symlink is refused)",
                    dir.display()
                )));
            }
            if meta.uid() != euid() {
                return Err(JournalError(format!(
                    "{} is owned by another user",
                    dir.display()
                )));
            }
            if meta.mode() & 0o022 != 0 {
                return Err(JournalError(format!(
                    "{} can be written by other users",
                    dir.display()
                )));
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = dir.parent() {
                fs::create_dir_all(parent).map_err(|e| io_err("cannot create", parent, e))?;
            }
            fs::DirBuilder::new()
                .mode(0o700)
                .create(dir)
                .map_err(|e| io_err("cannot create", dir, e))?;
        }
        Err(e) => return Err(io_err("cannot inspect", dir, e)),
    }
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
        .map_err(|e| io_err("cannot restrict", dir, e))
}

/// Opens an existing private file (never through a symlink) and checks it is
/// a regular file of this user; tightens it to 0600.
fn open_private(path: &Path, options: &mut OpenOptions) -> io::Result<File> {
    let file = options.custom_flags(libc::O_NOFOLLOW).open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != euid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "not a regular file of this user",
        ));
    }
    if meta.mode() & 0o777 != 0o600 {
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

/// Creates a new private file (0600, `O_EXCL`, never through a symlink).
fn create_private(path: &Path, append: bool) -> io::Result<File> {
    OpenOptions::new()
        .write(true)
        .append(append)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

fn sync_dir(dir: &Path) -> io::Result<()> {
    File::open(dir)?.sync_all()
}

/// Removes a file without following a symlink there.
fn remove_entry(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

// ── The journal ──

/// Failure injection for tests: the next matching step fails.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The write stops half way through the line.
    Write,
    /// The line is written but its fsync fails.
    Fsync,
    /// The fsync fails and so does the first attempt to undo the write.
    FsyncAndUndo,
    /// Compaction "crashes" after the temp file is synced, before the rename.
    CrashBeforeRename,
    /// Compaction "crashes" after the rename, before the directory fsync.
    CrashAfterRename,
}

/// Failure injection for the shared fixtures' steps (r8), counted in
/// appends of any record (the refusal list and the clean close are not
/// appends).
#[cfg(test)]
#[derive(Debug, Default)]
struct Plan {
    /// Appends left before the one that fails, and whether its rollback
    /// fails too (the record is durable although the append failed).
    fail_in: Option<(u64, bool)>,
    /// The next `Accepted` becomes durable, then the process "dies": every
    /// later write fails until `reopen`.
    crash_after_accepted: bool,
    crashed: bool,
    fail_refusal: bool,
    /// Every rollback attempt fails (a log that can't be cut back).
    undo_stuck: bool,
}

struct SessionLog {
    file: File,
    len: u64,
}

pub struct FileJournal {
    state: PathBuf,
    logs: PathBuf,
    /// Append handles, only for sessions with live receipts.
    open: HashMap<String, SessionLog>,
    /// request_id → session_id, for every admitted and not evicted request.
    owner: HashMap<String, String>,
    /// session_id → live (admitted, not evicted) receipts.
    live: HashMap<String, usize>,
    /// Requests whose payload is on disk and that are still `accepted`.
    with_payload: HashSet<String>,
    /// session_id → size of its log right after the last compaction.
    compacted_len: HashMap<String, u64>,
    /// The lease-epoch floors, as in the `floors` file.
    floors: BTreeMap<String, u64>,
    /// The principals' control states, as in the `principals` file.
    principals: BTreeMap<String, DiskControl>,
    /// Logs whose failed append could not be undone yet: handle and the
    /// length before that append. Retried on every refused append and on drop.
    undo: HashMap<String, SessionLog>,
    next_seq: u64,
    compact_bytes: u64,
    compactions: u64,
    /// Set by a write/sync error: no more appends in this process.
    failed: Option<String>,
    _lock: crate::daemon::HeldLock,
    #[cfg(test)]
    fault: Option<Fault>,
    #[cfg(test)]
    plan: Plan,
}

impl std::fmt::Debug for FileJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileJournal")
            .field("logs", &self.logs)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

/// A payload worth taking off the disk once its request leaves `accepted`.
fn has_content(payload: &Value) -> bool {
    match payload {
        Value::Null => false,
        Value::Object(map) => !map.is_empty(),
        _ => true,
    }
}

impl FileJournal {
    /// Opens (or creates) the journal under `state_dir`: truncates every
    /// session log to its last valid record, removes compaction leftovers,
    /// and rewrites logs that still hold a finished request's payload or
    /// nothing live. Fails if another journal holds the directory or the
    /// floors file is damaged.
    pub fn open(state_dir: &Path) -> Result<Self, JournalError> {
        private_dir(state_dir)?;
        let lock_path = state_dir.join("journal.lock");
        // A process forked by another thread can share the lock's open file
        // description until its exec closes it (O_CLOEXEC); a broker that has
        // just exited may still be releasing it. Wait briefly before
        // concluding that another journal holds the directory.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let lock = loop {
            if let Some(lock) = crate::daemon::lock_exclusive_with_pid(&lock_path)
                .map_err(|e| io_err("cannot lock", &lock_path, e))?
            {
                break lock;
            }
            if std::time::Instant::now() >= deadline {
                return Err(JournalError(format!(
                    "{} is used by another process",
                    state_dir.display()
                )));
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
        };
        let logs = state_dir.join("receipts");
        private_dir(&logs)?;
        let mut journal = Self {
            state: state_dir.to_path_buf(),
            logs,
            open: HashMap::new(),
            owner: HashMap::new(),
            live: HashMap::new(),
            with_payload: HashSet::new(),
            compacted_len: HashMap::new(),
            floors: BTreeMap::new(),
            principals: BTreeMap::new(),
            undo: HashMap::new(),
            next_seq: 1,
            compact_bytes: COMPACT_BYTES,
            compactions: 0,
            failed: None,
            _lock: lock,
            #[cfg(test)]
            fault: None,
            #[cfg(test)]
            plan: Plan::default(),
        };
        journal.load_state()?;
        Ok(journal)
    }

    /// Reads the floors and principals and recovers the session logs.
    fn load_state(&mut self) -> Result<(), JournalError> {
        self.load_floors()?;
        self.load_principals()?;
        self.recover_files()
    }

    /// Compacts a log once it is larger than `bytes` (and than twice its
    /// size after the last compaction).
    pub fn with_compact_threshold(mut self, bytes: u64) -> Self {
        self.compact_bytes = bytes;
        self
    }

    /// Why appends are refused, after a write or sync error.
    pub fn failed(&self) -> Option<&str> {
        self.failed.as_deref()
    }

    #[cfg(test)]
    pub fn open_handles(&self) -> usize {
        self.open.len()
    }

    #[cfg(test)]
    pub fn compactions(&self) -> u64 {
        self.compactions
    }

    #[cfg(test)]
    pub fn inject(&mut self, fault: Fault) {
        self.fault = Some(fault);
    }

    /// The `n`-th next append fails (its record lost, or kept when
    /// `undo_fails`: the worst case of a failed rollback).
    #[cfg(test)]
    pub fn fail_append_of(&mut self, n: u64, undo_fails: bool) {
        self.plan.fail_in = Some((n.saturating_sub(1), undo_fails));
    }

    /// The next `Accepted` becomes durable, then every write fails until
    /// `reopen` (a crash right after the durable acceptance).
    #[cfg(test)]
    pub fn crash_after_accepted(&mut self) {
        self.plan.crash_after_accepted = true;
    }

    #[cfg(test)]
    pub fn crashed(&self) -> bool {
        self.plan.crashed
    }

    /// Rollbacks fail until `false` (survives `reopen`, which is refused
    /// while one is pending).
    #[cfg(test)]
    pub fn set_undo_stuck(&mut self, stuck: bool) {
        self.plan.undo_stuck = stuck;
    }

    /// The next refusal-list write fails.
    #[cfg(test)]
    pub fn fail_next_refusal(&mut self) {
        self.plan.fail_refusal = true;
    }

    #[cfg(test)]
    fn take_fault(&mut self, which: Fault) -> bool {
        if self.fault == Some(which) {
            self.fault = None;
            true
        } else {
            false
        }
    }

    fn log_path(&self, sid: &str) -> PathBuf {
        self.logs.join(format!("{sid}{LOG_SUFFIX}"))
    }

    fn floors_path(&self) -> PathBuf {
        self.state.join(FLOORS)
    }

    /// Session ids with a log, sorted.
    fn session_ids(&self) -> Result<Vec<String>, JournalError> {
        let mut ids = Vec::new();
        let entries = fs::read_dir(&self.logs).map_err(|e| io_err("cannot read", &self.logs, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| io_err("cannot read", &self.logs, e))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if let Some(sid) = name.strip_suffix(LOG_SUFFIX)
                && wire::is_session_id(sid)
            {
                ids.push(sid.to_string());
            }
        }
        ids.sort();
        Ok(ids)
    }

    fn read_private(path: &Path) -> Result<Vec<u8>, JournalError> {
        let mut file = open_private(path, OpenOptions::new().read(true))
            .map_err(|e| io_err("cannot open", path, e))?;
        let mut bytes = Vec::new();
        io::Read::read_to_end(&mut file, &mut bytes).map_err(|e| io_err("cannot read", path, e))?;
        Ok(bytes)
    }

    fn read_log(&self, sid: &str) -> Result<Parsed, JournalError> {
        Ok(parse_log(&Self::read_private(&self.log_path(sid))?, sid))
    }

    /// Reads the floors file (a single framed record, replaced atomically).
    /// A damaged one is refused: forgetting a floor could reissue an epoch.
    fn load_floors(&mut self) -> Result<(), JournalError> {
        let path = self.floors_path();
        let tmp = self.state.join(format!("{FLOORS}.tmp"));
        remove_entry(&tmp).map_err(|e| io_err("cannot remove", &tmp, e))?;
        if fs::symlink_metadata(&path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound) {
            return Ok(());
        }
        let bytes = Self::read_private(&path)?;
        let floors = unframe(&bytes)
            .filter(|(_, used)| *used == bytes.len())
            .and_then(|(json, _)| serde_json::from_slice::<FloorsFile>(json).ok())
            .filter(|f| f.floors.keys().all(|sid| wire::is_session_id(sid)))
            .ok_or_else(|| JournalError(format!("{} is damaged", path.display())))?;
        self.floors = floors.floors;
        Ok(())
    }

    /// Replaces the floors file with `floors` (temp, fsync, rename, dir fsync).
    fn write_floors(&mut self, floors: &BTreeMap<String, u64>) -> Result<(), JournalError> {
        let json = serde_json::to_vec(&FloorsFile {
            floors: floors.clone(),
        })
        .map_err(|e| JournalError(format!("cannot encode the floors: {e}")))?;
        self.replace_file(FLOORS, &frame(&json))
            .map_err(|e| self.fail(e.0))
    }

    /// Atomically replaces `<state>/<name>` with `bytes` (temp, fsync,
    /// rename, directory fsync); the old file or the new one is there after
    /// a crash at any point.
    fn replace_file(&self, name: &str, bytes: &[u8]) -> Result<(), JournalError> {
        let path = self.state.join(name);
        let tmp = self.state.join(format!("{name}.tmp"));
        let state = self.state.clone();
        let written = (|| {
            remove_entry(&tmp)?;
            let mut f = create_private(&tmp, false)?;
            f.write_all(bytes)?;
            f.sync_all()?;
            drop(f);
            fs::rename(&tmp, &path)?;
            sync_dir(&state)
        })();
        written.map_err(|e| {
            let _ = remove_entry(&tmp);
            JournalError(format!("cannot write {}: {e}", path.display()))
        })
    }

    /// A small framed file (`<len> <crc> <json>\n`) that must parse whole,
    /// or `None` when it doesn't exist. A damaged one is an error.
    fn read_framed<T: serde::de::DeserializeOwned>(
        &self,
        name: &str,
    ) -> Result<Option<T>, JournalError> {
        self.read_framed_within(name, MAX_RECORD_BYTES)
    }

    /// [`FileJournal::read_framed`] with a record of at most `max` bytes.
    fn read_framed_within<T: serde::de::DeserializeOwned>(
        &self,
        name: &str,
        max: usize,
    ) -> Result<Option<T>, JournalError> {
        let path = self.state.join(name);
        let tmp = self.state.join(format!("{name}.tmp"));
        remove_entry(&tmp).map_err(|e| io_err("cannot remove", &tmp, e))?;
        if fs::symlink_metadata(&path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound) {
            return Ok(None);
        }
        let bytes = Self::read_private(&path)?;
        unframe_within(&bytes, max)
            .filter(|(_, used)| *used == bytes.len())
            .and_then(|(json, _)| serde_json::from_slice::<T>(json).ok())
            .map(Some)
            .ok_or_else(|| JournalError(format!("{} is damaged", path.display())))
    }

    /// Reads the principals file. A damaged one is refused: forgetting a
    /// control generation could let revoked work run.
    ///
    /// Its own, larger bound: a file grown before browser principals were
    /// pruned (`SessionHost::prune_principals`) is read whole and shrinks
    /// at the next control write, never refused for its size.
    fn load_principals(&mut self) -> Result<(), JournalError> {
        let file: Option<PrincipalsFile> =
            self.read_framed_within(PRINCIPALS, MAX_PRINCIPALS_BYTES)?;
        self.principals = file.map(|f| f.principals).unwrap_or_default();
        Ok(())
    }

    fn append_control(
        &mut self,
        principal: String,
        state: DiskControl,
    ) -> Result<(), JournalError> {
        if principal.is_empty() || principal.len() > wire::MAX_OPAQUE_ID_BYTES {
            return Err(JournalError("invalid principal".into()));
        }
        let current = self.principals.get(&principal).copied();
        if current.is_some_and(|c| c.control_gen > state.control_gen) {
            return Err(JournalError("a control generation never goes down".into()));
        }
        // The fenced entry never goes down either.
        let state = DiskControl {
            fence_seq: state.fence_seq.max(current.map_or(0, |c| c.fence_seq)),
            ..state
        };
        if current == Some(state) {
            return Ok(()); // already durable
        }
        let mut principals = self.principals.clone();
        principals.insert(principal, state);
        let json = serde_json::to_vec(&PrincipalsFile {
            principals: principals.clone(),
        })
        .map_err(|e| JournalError(format!("cannot encode the principals: {e}")))?;
        self.replace_file(PRINCIPALS, &frame(&json))
            .map_err(|e| self.fail(e.0))?;
        self.principals = principals;
        Ok(())
    }

    /// Open-time recovery: drop compaction temps, truncate torn tails, learn
    /// the request owners and the next sequence number, and rewrite logs that
    /// hold a finished request's payload or nothing live.
    fn recover_files(&mut self) -> Result<(), JournalError> {
        let entries = fs::read_dir(&self.logs).map_err(|e| io_err("cannot read", &self.logs, e))?;
        for entry in entries {
            let entry = entry.map_err(|e| io_err("cannot read", &self.logs, e))?;
            if entry
                .file_name()
                .to_str()
                .is_some_and(|n| n.ends_with(TMP_SUFFIX))
            {
                let path = entry.path();
                remove_entry(&path).map_err(|e| io_err("cannot remove", &path, e))?;
            }
        }
        let mut rewrite = Vec::new();
        for sid in self.session_ids()? {
            let parsed = self.read_log(&sid)?;
            if parsed.valid_len < parsed.total_len {
                let path = self.log_path(&sid);
                crate::diagnostics::warn(format!(
                    "atem: session journal {}: invalid record at byte {}; dropped the last {} bytes",
                    path.display(),
                    parsed.valid_len,
                    parsed.total_len - parsed.valid_len
                ));
                let file = open_private(&path, OpenOptions::new().write(true))
                    .map_err(|e| io_err("cannot open", &path, e))?;
                file.set_len(parsed.valid_len)
                    .and_then(|()| file.sync_all())
                    .map_err(|e| io_err("cannot truncate", &path, e))?;
            }
            let mut stale_payload = false;
            for (seq, record) in parsed.records {
                self.next_seq = self.next_seq.max(seq + 1);
                match record {
                    Record::Accepted {
                        request_id,
                        payload,
                        ..
                    } => {
                        if has_content(&payload) {
                            self.with_payload.insert(request_id.clone());
                        }
                        *self.live.entry(sid.clone()).or_default() += 1;
                        self.owner.insert(request_id.clone(), sid.clone());
                    }
                    Record::Rejected { request_id, .. } => {
                        *self.live.entry(sid.clone()).or_default() += 1;
                        self.owner.insert(request_id.clone(), sid.clone());
                    }
                    Record::Transition { request_id, .. } => {
                        stale_payload |= self.with_payload.remove(&request_id);
                    }
                    Record::Evicted { request_id } => {
                        stale_payload |= self.with_payload.remove(&request_id);
                        self.owner.remove(&request_id);
                        *self.live.entry(sid.clone()).or_default() -= 1;
                    }
                    Record::LeaseEpochs { .. } | Record::Control { .. } => {}
                }
            }
            if self.live.get(&sid).is_none_or(|n| *n == 0) {
                self.live.remove(&sid);
                stale_payload = true;
            }
            if stale_payload {
                rewrite.push(sid);
            }
        }
        for sid in rewrite {
            self.compact(&sid)?;
        }
        Ok(())
    }

    fn fail(&mut self, why: String) -> JournalError {
        let message = format!("session journal failed: {why}; restart to reload it");
        self.failed = Some(message.clone());
        JournalError(message)
    }

    /// Cuts logs back to their length before a failed append, where the
    /// first attempt failed. Safe only because nothing is appended while a
    /// rollback is pending (the journal stays failed, `reopen` included).
    fn retry_undo(&mut self) {
        #[cfg(test)]
        if self.plan.undo_stuck {
            return;
        }
        self.undo.retain(|_, log| {
            log.file
                .set_len(log.len)
                .and_then(|()| log.file.sync_all())
                .is_err()
        });
    }

    /// The append handle of `sid`'s log, creating the log (and making its
    /// directory entry durable) if needed.
    fn log_for(&mut self, sid: &str) -> Result<&mut SessionLog, JournalError> {
        if !self.open.contains_key(sid) {
            let path = self.log_path(sid);
            let log = match open_private(&path, OpenOptions::new().append(true)) {
                Ok(file) => {
                    let len = file
                        .metadata()
                        .map_err(|e| io_err("cannot inspect", &path, e))?
                        .len();
                    SessionLog { file, len }
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {
                    let file = create_private(&path, true)
                        .map_err(|e| io_err("cannot create", &path, e))?;
                    if let Err(e) = sync_dir(&self.logs) {
                        drop(file);
                        let _ = remove_entry(&path);
                        return Err(self.fail(format!("cannot sync {}: {e}", self.logs.display())));
                    }
                    SessionLog { file, len: 0 }
                }
                Err(e) => return Err(io_err("cannot open", &path, e)),
            };
            self.open.insert(sid.to_string(), log);
        }
        Ok(self.open.get_mut(sid).unwrap())
    }

    fn session_of(&self, record: &Record) -> Result<String, JournalError> {
        let sid = match record {
            Record::Accepted {
                request_id, target, ..
            }
            | Record::Rejected {
                request_id, target, ..
            } => {
                if self.owner.contains_key(request_id) {
                    return Err(JournalError(format!("request {request_id} admitted twice")));
                }
                target.session_id.clone()
            }
            Record::LeaseEpochs { session_id, .. } => session_id.clone(),
            Record::Control { .. } => unreachable!("control states are not logged"),
            Record::Transition { request_id, .. } | Record::Evicted { request_id } => self
                .owner
                .get(request_id)
                .cloned()
                .ok_or_else(|| JournalError(format!("unknown request {request_id}")))?,
        };
        if !wire::is_session_id(&sid) {
            return Err(JournalError("invalid session id".into()));
        }
        Ok(sid)
    }

    /// Writes `line` at the end of `sid`'s log and syncs it.
    fn write_line(&mut self, sid: &str, line: &[u8]) -> Result<(), JournalError> {
        #[cfg(test)]
        let (torn, sync_fails, undo_fails) = {
            let torn = self.take_fault(Fault::Write);
            let both = self.take_fault(Fault::FsyncAndUndo);
            (torn, both || self.take_fault(Fault::Fsync), both)
        };
        #[cfg(not(test))]
        let (torn, sync_fails, undo_fails) = (false, false, false);
        let log = self.log_for(sid)?;
        let before = log.len;
        let written = if torn {
            log.file
                .write_all(&line[..line.len() / 2])
                .and_then(|()| Err(io::Error::other("injected write failure")))
        } else {
            log.file.write_all(line)
        };
        let synced = written.and_then(|()| {
            if sync_fails {
                Err(io::Error::other("injected fsync failure"))
            } else {
                log.file.sync_data()
            }
        });
        match synced {
            Ok(()) => {
                log.len += line.len() as u64;
                Ok(())
            }
            Err(e) => {
                // Cut the log back so a restart doesn't find a record the
                // host was told is not written; retried until it works.
                let mut log = self.open.remove(sid).unwrap();
                log.len = before;
                let undone = !undo_fails
                    && log
                        .file
                        .set_len(before)
                        .and_then(|()| log.file.sync_all())
                        .is_ok();
                if !undone {
                    self.undo.insert(sid.to_string(), log);
                }
                Err(self.fail(format!("cannot write the {sid} log: {e}")))
            }
        }
    }

    /// Compacts every session log now.
    pub fn compact_all(&mut self) -> Result<(), JournalError> {
        if let Some(f) = &self.failed {
            return Err(JournalError(f.clone()));
        }
        for sid in self.session_ids()? {
            self.compact(&sid)?;
        }
        Ok(())
    }

    /// Rewrites `sid`'s log with only its live state (see the module docs);
    /// a log with nothing live is removed.
    fn compact(&mut self, sid: &str) -> Result<(), JournalError> {
        self.compactions += 1;
        let parsed = self.read_log(sid)?;
        let seq_of: Vec<u64> = parsed.records.iter().map(|(s, _)| *s).collect();
        let replayed = journal::replay(parsed.records.into_iter().map(|(_, r)| r).collect())?;
        let mut stored: Vec<_> = replayed.receipts.into_values().collect();
        stored.sort_by_key(|s| s.order);
        let mut out = Vec::new();
        for s in stored {
            let seq = seq_of[s.order as usize];
            let accepted = s.state == ReceiptState::Accepted;
            out.extend(encode(
                seq,
                Record::Accepted {
                    request_id: s.request_id.clone(),
                    target: s.target,
                    kind: s.kind,
                    payload_digest: s.payload_digest,
                    payload: if accepted {
                        s.payload.unwrap_or(Value::Null)
                    } else {
                        Value::Null
                    },
                    updated_at: s.updated_at,
                    principal: s.principal,
                    control_gen: s.control_gen,
                },
            )?);
            let mut step =
                |state: ReceiptState, detail: Option<String>, result: Option<TurnIds>| {
                    encode(
                        seq,
                        Record::Transition {
                            request_id: s.request_id.clone(),
                            state,
                            detail,
                            updated_at: s.updated_at,
                            result,
                        },
                    )
                    .map(|line| out.extend(line))
                };
            match s.state {
                ReceiptState::Accepted => {}
                ReceiptState::Executing | ReceiptState::Rejected => step(s.state, s.detail, None)?,
                final_state => {
                    step(ReceiptState::Executing, None, None)?;
                    step(final_state, s.detail, s.result)?;
                }
            }
        }
        if out.is_empty() {
            // Nothing live: the log goes (the old one or none is valid).
            self.open.remove(sid);
            self.compacted_len.remove(sid);
            let path = self.log_path(sid);
            remove_entry(&path).map_err(|e| io_err("cannot remove", &path, e))?;
            if let Err(e) = sync_dir(&self.logs) {
                return Err(self.fail(format!("cannot sync {}: {e}", self.logs.display())));
            }
            return Ok(());
        }
        self.replace_log(sid, &out)?;
        self.compacted_len.insert(sid.to_string(), out.len() as u64);
        Ok(())
    }

    /// Atomically replaces `sid`'s log with `bytes`.
    fn replace_log(&mut self, sid: &str, bytes: &[u8]) -> Result<(), JournalError> {
        let path = self.log_path(sid);
        let tmp = self.logs.join(format!("{sid}{TMP_SUFFIX}"));
        // Before the rename the old log is untouched: a failure here only
        // leaves a temp file, removed now or on the next open.
        remove_entry(&tmp).map_err(|e| io_err("cannot remove", &tmp, e))?;
        let written = create_private(&tmp, false).and_then(|mut f| {
            f.write_all(bytes)?;
            f.sync_all()
        });
        if let Err(e) = written {
            let _ = remove_entry(&tmp);
            return Err(io_err("cannot write", &tmp, e));
        }
        #[cfg(test)]
        if self.take_fault(Fault::CrashBeforeRename) {
            return Err(self.fail("simulated crash before the rename".into()));
        }
        self.open.remove(sid);
        if let Err(e) = fs::rename(&tmp, &path) {
            let _ = remove_entry(&tmp);
            return Err(io_err("cannot rename", &tmp, e));
        }
        // From here the old or the new log may be the durable one until the
        // directory is synced; both are valid, but appends must go to the
        // durable one, so a failure stops the journal.
        #[cfg(test)]
        if self.take_fault(Fault::CrashAfterRename) {
            return Err(self.fail("simulated crash after the rename".into()));
        }
        if let Err(e) = sync_dir(&self.logs) {
            return Err(self.fail(format!("cannot sync {}: {e}", self.logs.display())));
        }
        Ok(())
    }

    fn append_floor(&mut self, sid: String, reserved: u64) -> Result<(), JournalError> {
        if !wire::is_session_id(&sid) {
            return Err(JournalError("invalid session id".into()));
        }
        if self.floors.get(&sid).is_some_and(|f| *f >= reserved) {
            return Ok(()); // already durable: floors never go down
        }
        let mut floors = self.floors.clone();
        floors.insert(sid, reserved);
        self.write_floors(&floors)?;
        self.floors = floors;
        Ok(())
    }
}

impl Drop for FileJournal {
    fn drop(&mut self) {
        self.retry_undo();
    }
}

impl FileJournal {
    fn append_now(&mut self, record: Record) -> Result<(), JournalError> {
        if let Some(f) = &self.failed {
            let f = f.clone();
            self.retry_undo();
            return Err(JournalError(f));
        }
        if let Record::LeaseEpochs {
            session_id,
            reserved,
        } = record
        {
            return self.append_floor(session_id, reserved);
        }
        if let Record::Control {
            principal,
            control,
            control_gen,
            fence_seq,
        } = record
        {
            let state = DiskControl {
                control,
                control_gen,
                fence_seq,
            };
            return self.append_control(principal, state);
        }
        let sid = self.session_of(&record)?;
        let request_id = match &record {
            Record::Accepted { request_id, .. }
            | Record::Rejected { request_id, .. }
            | Record::Transition { request_id, .. }
            | Record::Evicted { request_id } => request_id.clone(),
            Record::LeaseEpochs { .. } | Record::Control { .. } => unreachable!("handled above"),
        };
        let with_content =
            matches!(&record, Record::Accepted { payload, .. } if has_content(payload));
        let is_accepted = matches!(record, Record::Accepted { .. } | Record::Rejected { .. });
        let is_evicted = matches!(record, Record::Evicted { .. });
        self.write_line(&sid, &encode(self.next_seq, record)?)?;
        let mut rewrite = false;
        if is_accepted {
            if with_content {
                self.with_payload.insert(request_id.clone());
            }
            self.owner.insert(request_id.clone(), sid.clone());
            *self.live.entry(sid.clone()).or_default() += 1;
        } else {
            // Its payload is no longer needed: take it off the disk.
            rewrite = self.with_payload.remove(&request_id);
        }
        if is_evicted {
            self.owner.remove(&request_id);
            let live = self.live.entry(sid.clone()).or_default();
            *live = live.saturating_sub(1);
            if *live == 0 {
                self.live.remove(&sid);
                rewrite = true; // the log and its handle go
            }
        }
        self.next_seq += 1;
        let len = self.open.get(&sid).map_or(0, |l| l.len);
        let limit = self
            .compact_bytes
            .max(2 * self.compacted_len.get(&sid).copied().unwrap_or(0));
        if (rewrite || len > limit)
            && let Err(e) = self.compact(&sid)
        {
            // The record itself is durable; a failed compaction only leaves
            // the log longer (or, after the rename, stops later appends).
            crate::diagnostics::warn(format!("atem: session journal compaction: {}", e.0));
        }
        Ok(())
    }
}

impl Journal for FileJournal {
    fn append(&mut self, record: Record) -> Result<(), JournalError> {
        #[cfg(test)]
        {
            if self.plan.crashed {
                return Err(JournalError("the process crashed".into()));
            }
            match self.plan.fail_in {
                Some((0, undo_fails)) => {
                    self.plan.fail_in = None;
                    if undo_fails && self.failed.is_none() {
                        // The write happened; its rollback didn't.
                        let _ = self.append_now(record);
                    }
                    return Err(self.fail("injected fsync failure".into()));
                }
                Some((n, undo_fails)) => self.plan.fail_in = Some((n - 1, undo_fails)),
                None => {}
            }
            let accepted = matches!(record, Record::Accepted { .. });
            let result = self.append_now(record);
            if result.is_ok() && accepted && std::mem::take(&mut self.plan.crash_after_accepted) {
                self.plan.crashed = true;
            }
            result
        }
        #[cfg(not(test))]
        self.append_now(record)
    }

    fn record_refusal(&mut self, refusal: Refusal) -> Result<(), JournalError> {
        #[cfg(test)]
        if std::mem::take(&mut self.plan.fail_refusal) || self.plan.crashed {
            return Err(JournalError("injected refusal-list failure".into()));
        }
        let mut refused = self.refusals()?;
        refused.retain(|r| r.request_id != refusal.request_id);
        refused.push(refusal);
        let json = serde_json::to_vec(&RefusedFile { refused })
            .map_err(|e| JournalError(format!("cannot encode the refusal list: {e}")))?;
        self.replace_file(REFUSED, &frame(&json))
    }

    fn refusals(&self) -> Result<Vec<Refusal>, JournalError> {
        let path = self.state.join(REFUSED);
        if fs::symlink_metadata(&path).is_err_and(|e| e.kind() == io::ErrorKind::NotFound) {
            return Ok(Vec::new());
        }
        let bytes = Self::read_private(&path)?;
        unframe(&bytes)
            .filter(|(_, used)| *used == bytes.len())
            .and_then(|(json, _)| serde_json::from_slice::<RefusedFile>(json).ok())
            .map(|f| f.refused)
            .ok_or_else(|| JournalError(format!("{} is damaged", path.display())))
    }

    fn clear_refusals(&mut self) -> Result<(), JournalError> {
        if let Some(f) = &self.failed {
            return Err(JournalError(f.clone()));
        }
        let path = self.state.join(REFUSED);
        remove_entry(&path).map_err(|e| io_err("cannot remove", &path, e))?;
        sync_dir(&self.state).map_err(|e| io_err("cannot sync", &self.state, e))
    }

    fn write_clean_close(&mut self, runtime_epoch: u64) -> Result<(), JournalError> {
        #[cfg(test)]
        if self.plan.crashed {
            return Err(JournalError("the process crashed".into()));
        }
        if let Some(f) = &self.failed {
            return Err(JournalError(f.clone()));
        }
        let json = serde_json::to_vec(&CleanClose { runtime_epoch })
            .map_err(|e| JournalError(format!("cannot encode the clean close: {e}")))?;
        self.replace_file(CLEAN_CLOSE, &json)
    }

    fn take_clean_close(&mut self) -> Option<u64> {
        let path = self.state.join(CLEAN_CLOSE);
        let _ = remove_entry(&self.state.join(format!("{CLEAN_CLOSE}.tmp")));
        let epoch = Self::read_private(&path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<CleanClose>(&bytes).ok())
            .map(|c| c.runtime_epoch);
        if remove_entry(&path).is_ok() {
            let _ = sync_dir(&self.state);
        }
        epoch
    }

    /// Refused while a failed append's rollback is still pending: the log
    /// may hold a record the host was told isn't written, and the rollback
    /// cuts it back to its old length, which would destroy anything durable
    /// written after it. The journal stays failed until a real process
    /// restart opens it from disk. A reload that fails leaves it failed too
    /// (its in-memory state is gone).
    fn forget_principals(&mut self, principals: &[String]) {
        for p in principals {
            self.principals.remove(p);
        }
    }

    fn reopen(&mut self) -> Result<(), JournalError> {
        self.retry_undo();
        if !self.undo.is_empty() {
            let why = "a failed write could not be rolled back; restart Atem".to_string();
            return Err(self.fail(why));
        }
        self.open.clear();
        self.owner.clear();
        self.live.clear();
        self.with_payload.clear();
        self.compacted_len.clear();
        self.floors.clear();
        self.principals.clear();
        self.next_seq = 1;
        self.failed = None;
        #[cfg(test)]
        {
            self.plan = Plan::default();
        }
        self.load_state()
            .map_err(|e| self.fail(format!("cannot reload: {}", e.0)))
    }

    fn load(&self) -> Result<Vec<Record>, JournalError> {
        let mut all: Vec<(u64, Record)> = self
            .floors
            .iter()
            .map(|(sid, reserved)| {
                let record = Record::LeaseEpochs {
                    session_id: sid.clone(),
                    reserved: *reserved,
                };
                (0, record)
            })
            .collect();
        all.extend(self.principals.iter().map(|(principal, c)| {
            let record = Record::Control {
                principal: principal.clone(),
                control: c.control,
                control_gen: c.control_gen,
                fence_seq: c.fence_seq,
            };
            (0, record)
        }));
        for sid in self.session_ids()? {
            all.extend(self.read_log(&sid)?.records);
        }
        // Stable: records sharing a `seq` (a compacted receipt) keep their
        // order within their log.
        all.sort_by_key(|(seq, _)| *seq);
        Ok(all.into_iter().map(|(_, r)| r).collect())
    }
}

#[cfg(test)]
#[path = "file_journal_tests.rs"]
mod tests;

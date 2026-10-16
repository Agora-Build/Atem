//! `FileJournal`: the host's durable receipt journal on disk (§6).
//!
//! Layout, under a private state directory (0700, owned by this user, never a
//! symlink):
//!
//! ```text
//! <state>/journal.lock          flock held for the journal's life (one writer)
//! <state>/receipts/             0700
//! <state>/receipts/<sid>.log    0600, append-only, one per session
//! ```
//!
//! A session's log holds every record of that session: its `Accepted`
//! records (the target names the session), their `Transition`/`Evicted`
//! records (routed by request id) and its `LeaseEpochs` reservations (the
//! lease-epoch floor lives in the session's own log, so it is compacted and
//! truncated with the receipts it protects).
//!
//! Each record is one line, `<len> <crc32> <json>\n`: `len` is the JSON's
//! byte length in decimal, `crc32` the IEEE CRC-32 of those bytes in 8 lower
//! hex digits, `json` `{"seq":N,"t":...}` where `seq` is a journal-wide
//! sequence number (it restores the append order across sessions on `load`).
//! A torn or corrupted record fails the length, checksum, JSON or coherence
//! check; opening the journal truncates the log to the last valid record
//! before it (and warns, without content), and nothing past a bad record is
//! ever trusted.
//!
//! Durability: `append` writes the line and `fdatasync`s it before returning
//! `Ok` (a new log also fsyncs the directory). After any write or sync error
//! the journal tries to cut the log back to its previous length and then
//! fails: every later `append` returns `Err` until the process restarts and
//! reopens it (`SessionHost` answers a failed `accepted` write with `busy`).
//!
//! Compaction: when a log grows past the threshold (1 MiB by default) or on
//! `compact_all`, it is rewritten with only its live state — the current
//! receipts with their latest state (a payload only while `accepted`; the
//! digest always), no evicted receipts, one `LeaseEpochs` with the floor — to
//! `<sid>.log.tmp`, which is fsynced, renamed over the log, and the directory
//! fsynced. A crash at any point leaves the old or the new log, both valid
//! and replaying to the same state; leftover temp files are removed on open.
//!
//! Prompt payloads are user content: the files are private and nothing here
//! logs a payload.

use super::journal::{self, Journal, JournalError, Record};
use super::wire::{self, ReceiptKind, ReceiptState, Target};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// Default size past which a session log is compacted.
pub const COMPACT_BYTES: u64 = 1 << 20;
/// Largest record accepted on load (a payload is far smaller).
const MAX_RECORD_BYTES: usize = 8 << 20;
const LOG_SUFFIX: &str = ".log";
const TMP_SUFFIX: &str = ".log.tmp";

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
    },
    Transition {
        seq: u64,
        request_id: String,
        state: ReceiptState,
        detail: Option<String>,
        updated_at: u64,
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
            } => Disk::Accepted {
                seq,
                request_id,
                target,
                kind,
                payload_digest,
                payload,
                updated_at,
            },
            Record::Transition {
                request_id,
                state,
                detail,
                updated_at,
            } => Disk::Transition {
                seq,
                request_id,
                state,
                detail,
                updated_at,
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
            } => (
                seq,
                Record::Accepted {
                    request_id,
                    target,
                    kind,
                    payload_digest,
                    payload,
                    updated_at,
                },
            ),
            Disk::Transition {
                seq,
                request_id,
                state,
                detail,
                updated_at,
            } => (
                seq,
                Record::Transition {
                    request_id,
                    state,
                    detail,
                    updated_at,
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

fn encode(seq: u64, record: Record) -> Result<Vec<u8>, JournalError> {
    let json = serde_json::to_vec(&Disk::new(seq, record))
        .map_err(|e| JournalError(format!("cannot encode a journal record: {e}")))?;
    let mut line = format!("{} {:08x} ", json.len(), crc32(&json)).into_bytes();
    line.extend_from_slice(&json);
    line.push(b'\n');
    Ok(line)
}

/// One record line at the start of `bytes`: the record and the line's length.
fn decode_line(bytes: &[u8]) -> Option<(u64, Record, usize)> {
    let space = bytes.iter().take(21).position(|&b| b == b' ')?;
    let digits = &bytes[..space];
    if digits.is_empty() || !digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let len: usize = std::str::from_utf8(digits).ok()?.parse().ok()?;
    if len > MAX_RECORD_BYTES {
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
    let disk: Disk = serde_json::from_slice(json).ok()?;
    let (seq, record) = disk.into_parts();
    Some((seq, record, space + 1 + 9 + len + 1))
}

/// A session log read up to its first invalid record.
struct Parsed {
    records: Vec<(u64, Record)>,
    /// Bytes up to the end of the last valid record.
    valid_len: u64,
    total_len: u64,
}

/// Reads records while they are well formed and coherent: the session they
/// name is this log's, `seq` never goes back, and a transition or eviction
/// names a request admitted earlier in this log.
fn parse_log(bytes: &[u8], sid: &str) -> Parsed {
    let mut records = Vec::new();
    let mut at = 0usize;
    let mut last_seq = 0u64;
    let mut live: HashSet<String> = HashSet::new();
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
            } => target.session_id == sid && live.insert(request_id.clone()),
            Record::Transition { request_id, .. } => live.contains(request_id),
            Record::Evicted { request_id } => live.remove(request_id),
            Record::LeaseEpochs { session_id, .. } => session_id == sid,
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
    /// Compaction "crashes" after the temp file is synced, before the rename.
    CrashBeforeRename,
    /// Compaction "crashes" after the rename, before the directory fsync.
    CrashAfterRename,
}

struct SessionLog {
    file: File,
    len: u64,
}

pub struct FileJournal {
    logs: PathBuf,
    open: HashMap<String, SessionLog>,
    /// request_id → session_id, for every admitted and not evicted request.
    owner: HashMap<String, String>,
    next_seq: u64,
    compact_bytes: u64,
    /// Set by a write/sync error: no more appends in this process.
    failed: Option<String>,
    _lock: crate::daemon::HeldLock,
    #[cfg(test)]
    fault: Option<Fault>,
}

impl std::fmt::Debug for FileJournal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FileJournal")
            .field("logs", &self.logs)
            .field("failed", &self.failed)
            .finish_non_exhaustive()
    }
}

impl FileJournal {
    /// Opens (or creates) the journal under `state_dir`, truncating every
    /// session log to its last valid record and removing compaction leftovers.
    /// Fails if another journal holds the directory.
    pub fn open(state_dir: &Path) -> Result<Self, JournalError> {
        private_dir(state_dir)?;
        let lock_path = state_dir.join("journal.lock");
        let lock = crate::daemon::lock_exclusive_with_pid(&lock_path)
            .map_err(|e| io_err("cannot lock", &lock_path, e))?
            .ok_or_else(|| {
                JournalError(format!(
                    "{} is used by another process",
                    state_dir.display()
                ))
            })?;
        let logs = state_dir.join("receipts");
        private_dir(&logs)?;
        let mut journal = Self {
            logs,
            open: HashMap::new(),
            owner: HashMap::new(),
            next_seq: 1,
            compact_bytes: COMPACT_BYTES,
            failed: None,
            _lock: lock,
            #[cfg(test)]
            fault: None,
        };
        journal.recover_files()?;
        Ok(journal)
    }

    /// Compacts a log once it is larger than `bytes`.
    pub fn with_compact_threshold(mut self, bytes: u64) -> Self {
        self.compact_bytes = bytes;
        self
    }

    /// Why appends are refused, after a write or sync error.
    pub fn failed(&self) -> Option<&str> {
        self.failed.as_deref()
    }

    #[cfg(test)]
    pub fn inject(&mut self, fault: Fault) {
        self.fault = Some(fault);
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

    fn read_log(&self, sid: &str) -> Result<Parsed, JournalError> {
        let path = self.log_path(sid);
        let mut file = open_private(&path, OpenOptions::new().read(true))
            .map_err(|e| io_err("cannot open", &path, e))?;
        let mut bytes = Vec::new();
        io::Read::read_to_end(&mut file, &mut bytes)
            .map_err(|e| io_err("cannot read", &path, e))?;
        Ok(parse_log(&bytes, sid))
    }

    /// Open-time recovery: drop compaction temps, truncate torn tails, learn
    /// the request owners and the next sequence number.
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
            for (seq, record) in parsed.records {
                self.next_seq = self.next_seq.max(seq + 1);
                match record {
                    Record::Accepted { request_id, .. } => {
                        self.owner.insert(request_id, sid.clone());
                    }
                    Record::Evicted { request_id } => {
                        self.owner.remove(&request_id);
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    fn fail(&mut self, why: String) -> JournalError {
        let message = format!("session journal failed: {why}; restart to reload it");
        self.failed = Some(message.clone());
        JournalError(message)
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
            } => {
                if self.owner.contains_key(request_id) {
                    return Err(JournalError(format!("request {request_id} admitted twice")));
                }
                target.session_id.clone()
            }
            Record::LeaseEpochs { session_id, .. } => session_id.clone(),
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
        let torn = self.take_fault(Fault::Write);
        #[cfg(not(test))]
        let torn = false;
        #[cfg(test)]
        let sync_fails = self.take_fault(Fault::Fsync);
        #[cfg(not(test))]
        let sync_fails = false;
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
                // Best effort: cut the log back so a restart doesn't find a
                // record the host was told is not written.
                let _ = log.file.set_len(before).and_then(|()| log.file.sync_all());
                self.open.remove(sid);
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

    /// Rewrites `sid`'s log with only its live state (see the module docs).
    fn compact(&mut self, sid: &str) -> Result<(), JournalError> {
        let parsed = self.read_log(sid)?;
        let seq_of: Vec<u64> = parsed.records.iter().map(|(s, _)| *s).collect();
        let last_seq = seq_of.last().copied().unwrap_or(0);
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
                },
            )?);
            let mut step = |state: ReceiptState, detail: Option<String>| {
                encode(
                    seq,
                    Record::Transition {
                        request_id: s.request_id.clone(),
                        state,
                        detail,
                        updated_at: s.updated_at,
                    },
                )
                .map(|line| out.extend(line))
            };
            match s.state {
                ReceiptState::Accepted => {}
                ReceiptState::Executing | ReceiptState::Rejected => step(s.state, s.detail)?,
                final_state => {
                    step(ReceiptState::Executing, None)?;
                    step(final_state, s.detail)?;
                }
            }
        }
        if let Some(&reserved) = replayed.lease_epochs.get(sid) {
            // `seq` only orders records across logs; a floor's place is free.
            out.extend(encode(
                last_seq,
                Record::LeaseEpochs {
                    session_id: sid.to_string(),
                    reserved,
                },
            )?);
        }
        if out.is_empty() {
            // Nothing live and no floor: the log goes (old or none is valid).
            self.open.remove(sid);
            let path = self.log_path(sid);
            remove_entry(&path).map_err(|e| io_err("cannot remove", &path, e))?;
            if let Err(e) = sync_dir(&self.logs) {
                return Err(self.fail(format!("cannot sync {}: {e}", self.logs.display())));
            }
            return Ok(());
        }
        self.replace_log(sid, &out)
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
}

impl Journal for FileJournal {
    fn append(&mut self, record: Record) -> Result<(), JournalError> {
        if let Some(f) = &self.failed {
            return Err(JournalError(f.clone()));
        }
        let sid = self.session_of(&record)?;
        let (owner_add, owner_remove) = match &record {
            Record::Accepted { request_id, .. } => (Some(request_id.clone()), None),
            Record::Evicted { request_id } => (None, Some(request_id.clone())),
            _ => (None, None),
        };
        let line = encode(self.next_seq, record)?;
        self.write_line(&sid, &line)?;
        self.next_seq += 1;
        if let Some(rid) = owner_add {
            self.owner.insert(rid, sid.clone());
        }
        if let Some(rid) = owner_remove {
            self.owner.remove(&rid);
        }
        let len = self.open.get(&sid).map_or(0, |l| l.len);
        if len > self.compact_bytes
            && let Err(e) = self.compact(&sid)
        {
            // The record itself is durable; a failed compaction only leaves
            // the log longer (or, after the rename, stops later appends).
            crate::diagnostics::warn(format!("atem: session journal compaction: {}", e.0));
        }
        Ok(())
    }

    fn load(&self) -> Result<Vec<Record>, JournalError> {
        let mut all: Vec<(u64, Record)> = Vec::new();
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

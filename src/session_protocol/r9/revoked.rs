//! The revoked grants journal on disk (§R9.6): `revoked_grants` in the
//! session journal's directory,
//! `{"v":1,"revoked":{grant_id: until},"quarantine"?:{"started_at":ms,"until":ms}}`.
//!
//! A file that can't be read can't tell a revocation it held from none, so
//! every browser grant is refused for a while (the quarantine, fail closed).
//! The quarantine is durable: the damaged file is kept aside
//! (`revoked_grants.damaged-<ms>`, never overwritten) and every later write
//! of the file carries the quarantine record until the quarantine ended, so
//! a revocation written during it, or a restart, can't drop it.
//!
//! Crash safety: the main path always holds either the damaged bytes or a
//! file with the record. The damaged file is hard-linked aside (and the
//! directory synced) before anything replaces it; the new file is written
//! to a temp (0600, `O_EXCL`), synced, then renamed over it (the directory
//! synced after). A crash at any step leaves the damaged file (quarantined
//! again at the next start, with another copy aside) or the new one (its
//! record restores the quarantine).
//!
//! The conservative bound lives in its own small file, independent of any
//! one damaged `revoked_grants`: `revoked_quarantine`,
//! `{"v":1,"until":ms,"high_water":ms}` ([`Bound`]): the latest quarantine
//! end (only ever rises) and the high-water mark (only ever rises): at
//! every write at least the host's wall time and every retained entry's
//! `until − 65 min` ([`Bound::cover`]), written first, durably. The host's
//! trusted time is `max(wall, high_water)`; revocations and quarantines are
//! bounded from it, never from a wall clock that went back. A new
//! quarantine ends no earlier than `max(until, high_water + 65 min, trusted
//! now + 65 min)`, so it outlives every entry a lost file could have held;
//! and while the wall clock is below `max(until, high_water)` browser
//! grants are refused (the clock went back).
//!
//! The files vouch for each other: a `revoked_grants` missing or unreadable
//! while the sidecar or a copy aside exists, or a sidecar missing or
//! unreadable while `revoked_grants` or a copy aside exists, is lost and
//! quarantined (a lost sidecar's bound is rebuilt from the entries and the
//! record left, with the newest modification time in the journal directory
//! as an extra floor, see [`newest_mtime`]). Only a journal with none of
//! them is fresh.

use atem_client::principal::{GRANT_ISSUED_AHEAD_MS, GRANT_MAX_LIFETIME_MS};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

/// The quarantine's length: how long after the file was found unreadable a
/// revocation it held could still matter. Every `until` the file can hold
/// ends at most 65 min after the wall time it was written:
/// - a live browser's revocation is kept until its grant's `expires_at`;
///   the grant was admitted at a wall time `w` only with `issued_at ≤ w +
///   300 000` (`GRANT_ISSUED_AHEAD_MS`), and `expires_at − issued_at ≤
///   3 600 000` (`GRANT_MAX_LIFETIME_MS`), so `expires_at ≤ w + 65 min`;
/// - any other revocation is kept until `wall + 65 min` (`revoke_grant`).
///
/// A wall clock that went back breaks "after the wall time it was
/// written" (a live browser admitted at a later wall time; a revocation
/// written while the clock was behind): revocations are bounded from the
/// trusted time `max(wall, high_water)` instead, and every write raises the
/// high-water mark to cover each retained entry ([`Bound::cover`]), so
/// `high_water + SAFE_WINDOW_MS` ([`Bound::floor`]) outlives them all.
pub const SAFE_WINDOW_MS: u64 = GRANT_MAX_LIFETIME_MS + GRANT_ISSUED_AHEAD_MS;

/// Browser grants refused because the revoked grants couldn't be read.
#[derive(Debug, Clone, Default)]
pub struct Quarantine {
    /// (started_at, until) in wall ms: `until = started_at + SAFE_WINDOW_MS`
    /// when the damage was found here (at the first wall time seen), as
    /// recorded when restored from the file.
    pub wall: Option<(u64, u64)>,
    /// This process's monotonic time when it took the quarantine (the first
    /// time seen after it found the damage or loaded the record).
    pub mono_from: Option<u64>,
    /// The earliest end of a quarantine found at this start (`wall` not
    /// set yet): the previous end and the high-water mark + the window.
    pub floor: u64,
}

impl Quarantine {
    pub fn restored(started_at: u64, until: u64) -> Quarantine {
        Quarantine {
            wall: Some((started_at, until)),
            mono_from: None,
            floor: 0,
        }
    }

    /// A quarantine found at this start that ends no earlier than `floor`
    /// (wall ms; see [`Bound::floor`]).
    pub fn starting(floor: u64) -> Quarantine {
        Quarantine {
            wall: None,
            mono_from: None,
            floor,
        }
    }

    pub fn anchor(&mut self, wall: u64, mono: u64) {
        let floor = self.floor;
        self.wall
            .get_or_insert((wall, floor.max(wall + SAFE_WINDOW_MS)));
        self.mono_from.get_or_insert(mono);
    }

    /// Ended only once the wall clock passed the recorded end **and** this
    /// process saw the whole window on its monotonic clock: a wall clock
    /// set back can't shorten it (the recorded end), nor one set forward
    /// (the monotonic window).
    pub fn ended(&self, wall: u64, mono: u64) -> bool {
        match (self.wall, self.mono_from) {
            (Some((_, until)), Some(from)) => {
                wall >= until && mono.saturating_sub(from) >= SAFE_WINDOW_MS
            }
            _ => false,
        }
    }
}

/// What `load` found.
#[derive(Debug)]
pub enum Loaded {
    Missing,
    Read {
        revoked: BTreeMap<String, u64>,
        /// (started_at, until)
        quarantine: Option<(u64, u64)>,
    },
    Unreadable,
}

/// Reads the file (never through a symlink, a regular file of this user,
/// bounded). Anything but the exact shape is `Unreadable`.
pub fn load(path: &Path) -> Loaded {
    let bytes = match super::membership::store::read_private(path) {
        Ok(None) => return Loaded::Missing,
        Ok(Some(bytes)) => bytes,
        Err(_) => return Loaded::Unreadable,
    };
    parse(&bytes).unwrap_or(Loaded::Unreadable)
}

fn parse(bytes: &[u8]) -> Option<Loaded> {
    let v: Value = serde_json::from_slice(bytes).ok()?;
    if v.get("v").and_then(Value::as_u64) != Some(1) {
        return None;
    }
    let revoked = v
        .get("revoked")?
        .as_object()?
        .iter()
        .map(|(id, until)| until.as_u64().map(|u| (id.clone(), u)))
        .collect::<Option<BTreeMap<_, _>>>()?;
    let quarantine = match v.get("quarantine") {
        None => None,
        Some(q) => {
            let started_at = q.get("started_at")?.as_u64()?;
            let until = q.get("until")?.as_u64()?;
            if until < started_at {
                return None;
            }
            Some((started_at, until))
        }
    };
    Some(Loaded::Read {
        revoked,
        quarantine,
    })
}

pub fn encode(revoked: &BTreeMap<String, u64>, quarantine: Option<(u64, u64)>) -> Vec<u8> {
    let mut body = serde_json::json!({"v": 1, "revoked": revoked});
    if let Some((started_at, until)) = quarantine {
        body["quarantine"] = serde_json::json!({"started_at": started_at, "until": until});
    }
    body.to_string().into_bytes()
}

/// The quarantine's sidecar, next to `revoked_grants`.
pub const SIDECAR_FILE: &str = "revoked_quarantine";

/// The conservative bound kept in [`SIDECAR_FILE`], independent of
/// `revoked_grants`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Bound {
    /// The latest quarantine end recorded (wall ms); only ever rises.
    pub until: u64,
    /// The highest host wall time seen at a write (wall ms); only rises.
    pub high_water: u64,
}

impl Bound {
    /// The earliest end of a quarantine that starts now, after any damage:
    /// the previous end, and the window after the high-water mark (a
    /// revocation written then may be kept that long).
    pub fn floor(&self) -> u64 {
        self.until
            .max(self.high_water.saturating_add(SAFE_WINDOW_MS))
    }

    /// Raises the high-water mark so that every entry kept `until` ends
    /// within the window after it (`high_water ≥ until − window`): a later
    /// quarantine, `high_water + window` or more, outlives every retained
    /// revocation, whatever wall time it was written at.
    pub fn cover(&mut self, untils: impl IntoIterator<Item = u64>) {
        for until in untils {
            self.high_water = self.high_water.max(until.saturating_sub(SAFE_WINDOW_MS));
        }
    }

    /// Wall times below this mean the clock went back.
    pub fn behind(&self) -> u64 {
        self.until.max(self.high_water)
    }
}

/// What [`load_sidecar`] found.
#[derive(Debug, PartialEq, Eq)]
pub enum SidecarLoaded {
    Missing,
    Read(Bound),
    Unreadable,
}

pub fn load_sidecar(path: &Path) -> SidecarLoaded {
    let bytes = match super::membership::store::read_private(path) {
        Ok(None) => return SidecarLoaded::Missing,
        Ok(Some(bytes)) => bytes,
        Err(_) => return SidecarLoaded::Unreadable,
    };
    let parse = || -> Option<Bound> {
        let v: Value = serde_json::from_slice(&bytes).ok()?;
        let o = v.as_object()?;
        if o.len() != 3 || o.get("v").and_then(Value::as_u64) != Some(1) {
            return None;
        }
        Some(Bound {
            until: o.get("until")?.as_u64()?,
            high_water: o.get("high_water")?.as_u64()?,
        })
    };
    parse().map_or(SidecarLoaded::Unreadable, SidecarLoaded::Read)
}

pub fn encode_sidecar(bound: Bound) -> Vec<u8> {
    serde_json::json!({"v": 1, "until": bound.until, "high_water": bound.high_water})
        .to_string()
        .into_bytes()
}

fn is_aside(name: &str) -> bool {
    name.starts_with(&format!("{}.damaged-", super::REVOKED_GRANTS_FILE))
        || name.starts_with(&format!("{SIDECAR_FILE}.damaged-"))
}

/// Whether a damaged `revoked_grants` or `revoked_quarantine` was kept
/// aside in `dir` (evidence of earlier damage).
pub fn damaged_asides(dir: &Path) -> bool {
    std::fs::read_dir(dir).is_ok_and(|entries| {
        entries
            .filter_map(Result::ok)
            .any(|e| is_aside(&e.file_name().to_string_lossy()))
    })
}

/// The newest modification time (wall ms) in the journal directory: its
/// own entries (the files kept aside, `revoked_grants`, the sidecar, the
/// session journal's files) and those one level down (`receipts/`), at
/// most 100 000 entries. The recovery's high-water mark when the sidecar
/// is lost: each write left its wall time there. Never followed through a
/// symlink.
pub fn newest_mtime(dir: &Path) -> u64 {
    fn ms(m: &std::fs::Metadata) -> u64 {
        m.modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_millis() as u64)
    }
    let mut newest = std::fs::symlink_metadata(dir).map_or(0, |m| ms(&m));
    let mut budget = 100_000u32;
    let mut scan = |d: &Path, newest: &mut u64, sub: &mut Vec<PathBuf>| {
        let Ok(entries) = std::fs::read_dir(d) else {
            return;
        };
        for e in entries.filter_map(Result::ok) {
            if budget == 0 {
                return;
            }
            budget -= 1;
            if let Ok(m) = std::fs::symlink_metadata(e.path()) {
                *newest = (*newest).max(ms(&m));
                if m.is_dir() {
                    sub.push(e.path());
                }
            }
        }
    };
    let mut subdirs = Vec::new();
    scan(dir, &mut newest, &mut subdirs);
    for d in subdirs {
        scan(&d, &mut newest, &mut Vec::new());
    }
    newest
}

/// A damaged file still at its path, to keep aside before anything
/// replaces it. The link is made once per damage: a later step that fails
/// (permissions, directory fsync) is retried on the same aside name.
#[derive(Debug, Default)]
pub struct Damaged {
    /// The damaged file is still at its path, not kept aside (and synced)
    /// yet.
    pub pending: bool,
    /// The aside link already made for it.
    pub aside: Option<PathBuf>,
}

impl Damaged {
    pub fn found() -> Damaged {
        Damaged {
            pending: true,
            aside: None,
        }
    }

    /// Keeps the file at `path` aside unless that is done: the aside path
    /// when it was kept now.
    pub fn keep(
        &mut self,
        path: &Path,
        wall: u64,
        crash: Option<Step>,
    ) -> io::Result<Option<PathBuf>> {
        if !self.pending {
            return Ok(None);
        }
        let aside = match &self.aside {
            Some(a) => a.clone(),
            None => match link_aside(path, wall, crash)? {
                Some(a) => {
                    self.aside = Some(a.clone());
                    a
                }
                None => {
                    // Gone already: nothing to keep.
                    self.pending = false;
                    return Ok(None);
                }
            },
        };
        seal_aside(path, &aside, crash)?;
        self.pending = false;
        Ok(Some(aside))
    }
}

/// A step of a write a test can crash after (the step done, nothing after
/// it), or (`Link`) fail at.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// The hard link that keeps a damaged file aside fails (an injected
    /// error, as EPERM on a filesystem without links); nothing done.
    Link,
    /// The damaged file is linked aside and the directory synced.
    Aside,
    /// The sidecar (`revoked_quarantine`) is written and synced.
    SidecarWritten,
    /// The temp is written and synced.
    TempWritten,
    /// The temp is renamed over the file (the directory not synced yet).
    Renamed,
}

pub fn checkpoint(step: Step, crash: Option<Step>) -> io::Result<()> {
    if crash == Some(step) {
        return Err(io::Error::other(format!("injected crash after {step:?}")));
    }
    Ok(())
}

fn sync_dir(path: &Path) -> io::Result<()> {
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::other("no directory"))?;
    std::fs::File::open(dir)?.sync_all()
}

/// Links the damaged file at `path` as `<name>.damaged-<wall>` (another
/// suffix when that exists; never overwritten): a hard link, so the main
/// path keeps it until it is replaced. `None` when it is gone already.
fn link_aside(path: &Path, wall: u64, crash: Option<Step>) -> io::Result<Option<PathBuf>> {
    if crash == Some(Step::Link) {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("no file name"))?
        .to_string_lossy()
        .into_owned();
    for n in 0..1000u32 {
        let aside = if n == 0 {
            path.with_file_name(format!("{name}.damaged-{wall}"))
        } else {
            path.with_file_name(format!("{name}.damaged-{wall}-{n}"))
        };
        match std::fs::hard_link(path, &aside) {
            Ok(()) => return Ok(Some(aside)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        }
    }
    Err(io::Error::other("no free name to keep the damaged file"))
}

/// The aside copy private (0600) and its link durable (directory synced).
fn seal_aside(path: &Path, aside: &Path, crash: Option<Step>) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    if std::fs::symlink_metadata(aside).is_ok_and(|m| m.is_file()) {
        std::fs::set_permissions(aside, std::fs::Permissions::from_mode(0o600))?;
    }
    sync_dir(path)?;
    checkpoint(Step::Aside, crash)
}

/// Replaces `path` whole: temp (0600, `O_EXCL`, `O_NOFOLLOW`), write,
/// fsync, rename, directory fsync.
pub fn write_atomic(path: &Path, bytes: &[u8], crash: Option<Step>) -> io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".tmp");
    let tmp = path.with_file_name(name);
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    drop(f);
    checkpoint(Step::TempWritten, crash)?;
    std::fs::rename(&tmp, path)?;
    checkpoint(Step::Renamed, crash)?;
    sync_dir(path)
}

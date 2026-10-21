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
/// Those entries were written before the damage was found, so 65 min after
/// that (on a wall clock that didn't go back before it was found) none of
/// them is in effect any more.
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
}

impl Quarantine {
    pub fn restored(started_at: u64, until: u64) -> Quarantine {
        Quarantine {
            wall: Some((started_at, until)),
            mono_from: None,
        }
    }

    pub fn anchor(&mut self, wall: u64, mono: u64) {
        self.wall.get_or_insert((wall, wall + SAFE_WINDOW_MS));
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

/// A step of a write a test can crash after (the step done, nothing after
/// it).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Step {
    /// The damaged file is linked aside and the directory synced.
    Aside,
    /// The temp is written and synced.
    TempWritten,
    /// The temp is renamed over the file (the directory not synced yet).
    Renamed,
}

fn checkpoint(step: Step, crash: Option<Step>) -> io::Result<()> {
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

/// Keeps the damaged file at `path` as `<name>.damaged-<wall>` (another
/// suffix when that exists; never overwritten): a hard link, so the main
/// path keeps it until it is replaced. `None` when it is gone already.
pub fn keep_aside(path: &Path, wall: u64, crash: Option<Step>) -> io::Result<Option<PathBuf>> {
    use std::os::unix::fs::PermissionsExt;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("no file name"))?
        .to_string_lossy()
        .into_owned();
    let mut kept = None;
    for n in 0..1000u32 {
        let aside = if n == 0 {
            path.with_file_name(format!("{name}.damaged-{wall}"))
        } else {
            path.with_file_name(format!("{name}.damaged-{wall}-{n}"))
        };
        match std::fs::hard_link(path, &aside) {
            Ok(()) => {
                kept = Some(aside);
                break;
            }
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        }
    }
    let aside = kept.ok_or_else(|| io::Error::other("no free name to keep the damaged file"))?;
    if std::fs::symlink_metadata(&aside).is_ok_and(|m| m.is_file()) {
        std::fs::set_permissions(&aside, std::fs::Permissions::from_mode(0o600))?;
    }
    sync_dir(path)?;
    checkpoint(Step::Aside, crash)?;
    Ok(Some(aside))
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

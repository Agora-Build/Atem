//! The hook script's event files (`chat/approval_hook.sh event`), shared by
//! the Codex and Claude adapters: `events/ev-<seq>-<Event>.json`, each the
//! hook's `$$ $PPID` line then its stdin JSON, published under the script's
//! lock with the session's counter as `<seq>` (publication order), read in
//! that order; and the start markers (`start-<Event>.<pid>`) a synchronous
//! hook leaves until its event is published, so a hook that died (killed,
//! timed out, failed: the agent went on as if it had run) is a lost event
//! (`EventReader::take_lost`).

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use serde_json::Value;

/// Event files read per poll; the rest wait for the next.
const EVENTS_PER_POLL: usize = 256;
/// Largest event file read; a bigger one is dropped.
pub const MAX_EVENT: u64 = 1024 * 1024;
/// A `tmp.*` left by a killed hook, or an unreadable event file, goes
/// after this long.
const LEFTOVER: Duration = Duration::from_secs(60);

/// One event file: the hook's `$$ $PPID` line, then its stdin JSON.
#[derive(Debug, Clone, PartialEq)]
pub struct RawEvent {
    /// The hook script's own pid.
    pub pid: u32,
    /// Its parent (Codex, or the shell Codex ran it in).
    pub parent: u32,
    /// The file's time (unix ms): when the hook wrote it.
    pub at_ms: i64,
    /// Its sequence (the name's `<seq>`): the script's counter, taken
    /// under its lock, so publication order.
    pub seq: u64,
    pub json: Value,
}

/// `"<pid> <ppid>\n<json>"` as written by the hook script.
fn parse_event(text: &str, at_ms: i64, seq: u64) -> Option<RawEvent> {
    let (head, body) = text.split_once('\n')?;
    let mut ids = head.split(' ');
    let pid = ids.next()?.parse().ok()?;
    let parent = ids.next()?.parse().ok()?;
    if ids.next().is_some() {
        return None;
    }
    let json = serde_json::from_str::<Value>(body).ok()?;
    Some(RawEvent {
        pid,
        parent,
        at_ms,
        seq,
        json,
    })
}

/// Reads the hook script's `events/ev-<seq>-<Event>.json` files in (seq,
/// name) order (a repeated seq is fine), deleting each once read. Nothing
/// else there is read: `tmp.*` (being written; removed once stale), `seq`,
/// `seq.<pid>`, `seq.lock` (the script's).
pub struct EventReader {
    dir: PathBuf,
    /// Events read but unusable since the last `take_lost` (their names'
    /// `<Event>`): unreadable, too big, or not a hook's.
    unusable: Vec<String>,
    /// Pids of the hooks whose events were read lately: a start marker of
    /// one of them was published, not lost.
    published: VecDeque<u32>,
    /// More events were waiting than one poll reads.
    backlog: bool,
}

/// The seq of an `ev-<digits>-<Letters>.json` name.
fn event_seq(name: &str) -> Option<u64> {
    let rest = name.strip_prefix("ev-")?.strip_suffix(".json")?;
    let (seq, event) = rest.split_once('-')?;
    let valid = !seq.is_empty()
        && seq.bytes().all(|b| b.is_ascii_digit())
        && !event.is_empty()
        && event.bytes().all(|b| b.is_ascii_alphabetic());
    valid.then(|| seq.parse().ok()).flatten()
}

fn stale(meta: &std::fs::Metadata, now: SystemTime) -> bool {
    meta.modified()
        .ok()
        .and_then(|t| now.duration_since(t).ok())
        .is_some_and(|age| age > LEFTOVER)
}

/// A regular file (never through a symlink) and its time (unix ms):
/// `Ok(None)` when larger than `MAX_EVENT`.
fn read_event(path: &Path) -> std::io::Result<Option<(String, i64)>> {
    use std::io::Read;
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let meta = file.metadata()?;
    if !meta.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let at_ms = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_millis() as i64);
    let mut text = String::new();
    file.take(MAX_EVENT + 1).read_to_string(&mut text)?;
    Ok((text.len() as u64 <= MAX_EVENT).then_some((text, at_ms)))
}

/// The `<Event>` of an `ev-<seq>-<Event>.json` name.
fn event_name(name: &str) -> Option<&str> {
    name.strip_prefix("ev-")?
        .strip_suffix(".json")?
        .split_once('-')
        .map(|(_, e)| e)
}

/// Pids remembered as published (`EventReader::published`).
const PUBLISHED_PIDS: usize = 4096;
/// A start marker this old is lost whatever its pid says (a reused pid):
/// beyond every synchronous hook's timeout.
const MARKER_LOST_AFTER: Duration = Duration::from_secs(30);

impl EventReader {
    pub fn new(dir: PathBuf) -> Self {
        Self {
            dir,
            unusable: Vec::new(),
            published: VecDeque::new(),
            backlog: false,
        }
    }

    /// The events lost since the last call (their `<Event>` names): read
    /// but unusable, and synchronous hooks that left their start marker
    /// (`start-<Event>.<pid>`) and died without publishing (killed, timed
    /// out, failed: Codex then went on as if they had run). Markers are
    /// judged only once every event published is read.
    pub fn take_lost(&mut self) -> Vec<String> {
        let mut lost = std::mem::take(&mut self.unusable);
        if self.backlog {
            return lost;
        }
        let Ok(rd) = std::fs::read_dir(self.dir.join("events")) else {
            return lost;
        };
        let now = SystemTime::now();
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            let Some((event, pid)) = name
                .strip_prefix("start-")
                .and_then(|r| r.split_once('.'))
                .and_then(|(ev, pid)| Some((ev.to_string(), pid.parse::<u32>().ok()?)))
            else {
                continue;
            };
            let old = std::fs::symlink_metadata(e.path())
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| now.duration_since(t).ok())
                .is_some_and(|age| age > MARKER_LOST_AFTER);
            // SAFETY: signal 0 only checks that the pid exists.
            let alive = unsafe { libc::kill(pid as libc::pid_t, 0) } == 0
                || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM);
            if alive && !old {
                continue;
            }
            let _ = std::fs::remove_file(e.path());
            if !self.published.contains(&pid) {
                lost.push(event);
            }
        }
        lost
    }

    /// The events in order; `None` for one that was too big, had no
    /// `$$ $PPID` line or wasn't JSON (deleted all the same).
    pub fn poll(&mut self) -> Vec<Option<RawEvent>> {
        let Ok(rd) = std::fs::read_dir(self.dir.join("events")) else {
            return Vec::new();
        };
        let now = SystemTime::now();
        let mut files = Vec::new();
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if let Some(seq) = event_seq(&name) {
                files.push((seq, name, e.path()));
            } else if name.starts_with("tmp.")
                && let Ok(meta) = std::fs::symlink_metadata(e.path())
                && meta.is_file()
                && stale(&meta, now)
            {
                let _ = std::fs::remove_file(e.path());
            }
        }
        files.sort();
        self.backlog = files.len() > EVENTS_PER_POLL;
        files.truncate(EVENTS_PER_POLL);
        let mut out = Vec::new();
        for (seq, name, path) in files {
            let event = event_name(&name).unwrap_or_default().to_string();
            match read_event(&path) {
                Ok(text) => {
                    let _ = std::fs::remove_file(&path);
                    let raw = text.and_then(|(t, at_ms)| parse_event(&t, at_ms, seq));
                    match &raw {
                        Some(raw) => {
                            if self.published.len() >= PUBLISHED_PIDS {
                                self.published.pop_front();
                            }
                            self.published.push_back(raw.pid);
                        }
                        None => self.unusable.push(event),
                    }
                    out.push(raw);
                }
                Err(_) => {
                    // Unreadable: kept for now, dropped once stale; lost
                    // either way (a later event may depend on it).
                    self.unusable.push(event);
                    if std::fs::symlink_metadata(&path).is_ok_and(|m| stale(&m, now)) {
                        let _ = std::fs::remove_file(&path);
                    }
                }
            }
        }
        out
    }
}

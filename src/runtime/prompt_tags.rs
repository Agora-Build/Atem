//! The live framing tag is for the agent and for whoever holds `control`
//! (owner decision 2026-11-10, delegated host-work design III.2): a
//! principal with only `view` could read it during the turn and plant it in
//! what the agent reads next.
//!
//! - **chat-v1:** every tag this runtime drew for a prompt it pasted is
//!   replaced, in all that chat-v1 serves to an attachment without
//!   `control` (live messages, history pages, lookups, snapshot replays),
//!   by [`PLACEHOLDER`], of the same length, so byte counts, offsets,
//!   sequences and `next` tokens (which bind positions, not text) hold.
//!   An agent's echo is replaced too, in any letter case, when the whole
//!   tag is in one string; an echo split across parts or cut short (a
//!   truncated tool summary or result) and a paraphrase aren't.
//! - **terminal-v1:** frames aren't text Atem controls (the agent's
//!   interface wraps, splits or truncates the prompt), so they are held
//!   from attachments without `control` while a framed prompt's turn runs
//!   ([`Pause`]; at most a day, the host's bound, never the sender's task
//!   deadline), and resume with a full frame once it ended.
//!
//! The tags are kept per session in `<state>/workers/<sid>.tags` (one per
//! line, 0600), written and synced before the prompt is pasted, so a
//! restarted broker still knows them; they go with the session's worker
//! files. Only a session the broker has, by a parsed id, is read: no text
//! of a request becomes a path. A tags file that can't be read hides every
//! tag-shaped string in that session's chat only. Control holders, the
//! local frontends, the session logs and the journal keep the real text.
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::Result;
use atem_client::membership::HostNow;
use atem_client::session::framing::{TAG_LEN, Tag};
use atem_client::session::wire::ReceiptState;

/// What an attachment without `control` sees in place of a tag.
pub const PLACEHOLDER: &str = "****-****-****";

/// The tags of the sessions this runtime has, each loaded once from its
/// tags file. Only sessions the broker knows by a parsed id are kept (a
/// request's text never becomes a path), and a session that is gone is
/// dropped (`retain`), so memory follows the live sessions.
#[derive(Default)]
pub struct PromptTags {
    sessions: HashMap<String, SessionTags>,
}

#[derive(Default)]
struct SessionTags {
    tags: HashSet<String>,
    /// Its tags file couldn't be read: every tag-shaped string in this
    /// session's chat is hidden (fail closed, for this session only).
    unreadable: bool,
}

impl PromptTags {
    /// Records `tag` for session `sid`, durably, before its prompt is
    /// pasted (the session's file read first, so its earlier tags stay).
    pub fn record(&mut self, state: &Path, sid: &str, tag: &Tag) -> Result<()> {
        if crate::session::SessionId::parse(sid).is_none() {
            anyhow::bail!("not a session id");
        }
        self.load(state, sid);
        let path = super::worker::tags_path(state, sid);
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path)?;
        if !file.metadata()?.is_file() {
            anyhow::bail!("the tags file is not a regular file");
        }
        file.write_all(format!("{}\n", tag.as_str()).as_bytes())?;
        file.sync_data()?;
        self.sessions
            .entry(sid.to_string())
            .or_default()
            .tags
            .insert(tag.as_str().to_string());
        Ok(())
    }

    /// Reads session `sid`'s tags once: a session the broker has (adopted,
    /// or registered after a restart). Nothing happens for a string that
    /// isn't a session id. A file that can't be read hides every
    /// tag-shaped string of that session.
    pub fn load(&mut self, state: &Path, sid: &str) {
        if crate::session::SessionId::parse(sid).is_none() || self.sessions.contains_key(sid) {
            return;
        }
        let entry = self.sessions.entry(sid.to_string()).or_default();
        let path = super::worker::tags_path(state, sid);
        let text = match read_private(&path) {
            Ok(Some(text)) => text,
            Ok(None) => return,
            Err(error) => {
                eprintln!(
                    "atem runtime: {sid}: prompt tags unreadable ({error}); every tag-shaped string of this session is hidden from attachments without control"
                );
                entry.unreadable = true;
                return;
            }
        };
        for line in text.lines() {
            match Tag::parse(line) {
                Some(tag) => {
                    entry.tags.insert(tag.as_str().to_string());
                }
                None => entry.unreadable = true,
            }
        }
    }

    /// Keeps only the sessions `live` names (the broker's).
    pub fn retain(&mut self, live: impl Fn(&str) -> bool) {
        self.sessions.retain(|sid, _| live(sid));
    }

    /// `text` (a chat-v1 envelope, serialized), served in session `sid`'s
    /// chat, with every tag any session of this runtime drew (an agent can
    /// echo another session's) replaced by [`PLACEHOLDER`], in any letter
    /// case; and, while `sid`'s tags file is unreadable, every tag-shaped
    /// string outside its ids ([`is_id_key`]: a UUID always holds one once
    /// uppercased; an id never holds prompt text). `None` when there is
    /// none. An echo split across parts, cut short or paraphrased isn't
    /// found.
    pub fn redact(&self, sid: &str, text: &str) -> Option<String> {
        let fail_closed = self.sessions.get(sid).is_some_and(|s| s.unreadable);
        if !fail_closed && self.sessions.values().all(|s| s.tags.is_empty()) {
            return None;
        }
        if fail_closed && let Ok(mut value) = serde_json::from_str::<serde_json::Value>(text) {
            return self
                .redact_value(&mut value, false)
                .then(|| value.to_string());
        }
        self.scan(text, fail_closed)
    }

    /// Redacts the strings of `value` in place; `id`: they are ids (only
    /// known tags go). Whether anything changed.
    fn redact_value(&self, value: &mut serde_json::Value, id: bool) -> bool {
        use serde_json::Value;
        match value {
            Value::String(s) => match self.scan(s, !id) {
                Some(redacted) => {
                    *s = redacted;
                    true
                }
                None => false,
            },
            Value::Array(items) => items
                .iter_mut()
                .fold(false, |changed, v| self.redact_value(v, id) | changed),
            Value::Object(map) => map.iter_mut().fold(false, |changed, (key, v)| {
                self.redact_value(v, is_id_key(key)) | changed
            }),
            _ => false,
        }
    }

    /// `text` with every known tag replaced, and with `any` every
    /// tag-shaped string; `None` when nothing was.
    fn scan(&self, text: &str, any: bool) -> Option<String> {
        let bytes = text.as_bytes();
        let mut out: Option<String> = None;
        let mut copied = 0;
        let mut at = 0;
        while at + TAG_LEN <= bytes.len() {
            let candidate = &bytes[at..at + TAG_LEN];
            let hit = candidate[4] == b'-'
                && candidate[9] == b'-'
                && std::str::from_utf8(candidate)
                    .ok()
                    .and_then(|c| Tag::parse(&c.to_ascii_uppercase()))
                    .is_some_and(|tag| {
                        any || self
                            .sessions
                            .values()
                            .any(|s| s.tags.contains(tag.as_str()))
                    });
            if hit {
                // A tag is ASCII: `at` and `at + TAG_LEN` are char boundaries.
                let o = out.get_or_insert_with(|| String::with_capacity(text.len()));
                o.push_str(&text[copied..at]);
                o.push_str(PLACEHOLDER);
                at += TAG_LEN;
                copied = at;
            } else {
                at += 1;
            }
        }
        out.map(|mut o| {
            o.push_str(&text[copied..]);
            o
        })
    }

    #[cfg(test)]
    pub fn knows(&self, tag: &str) -> bool {
        self.sessions.values().any(|s| s.tags.contains(tag))
    }

    #[cfg(test)]
    fn sessions(&self) -> usize {
        self.sessions.len()
    }
}

/// The chat-v1 keys whose strings are ids, generated by the host, the
/// agent's own logs or the client, never prompt text: `id`, `…Id`, `…_id`,
/// `…Ids`, `…_ids` (`messageId`, `turnId`, `requestId`, `conversationId`,
/// `approvalId`, `ruleId`, `page_id`, `after_message_id`,
/// `before_message_id`), the process `generation`, `oldest_retained` (a
/// message id), `controller_session` (`lease_held`'s holder), and the
/// history selectors `next` and `before`.
fn is_id_key(key: &str) -> bool {
    matches!(
        key,
        "id" | "next" | "before" | "generation" | "oldest_retained" | "controller_session"
    ) || key.ends_with("Id")
        || key.ends_with("_id")
        || key.ends_with("Ids")
        || key.ends_with("_ids")
}

/// A private file's text, `None` when it doesn't exist. Never follows a
/// symlink, never blocks on a FIFO, reads regular files only.
fn read_private(path: &Path) -> std::io::Result<Option<String>> {
    use std::io::Read;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path);
    let file = match file {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other("not a regular file"));
    }
    let mut text = String::new();
    file.take(1024 * 1024).read_to_string(&mut text)?;
    Ok(Some(text))
}

/// The longest a framed prompt's turn holds the session's terminal frames:
/// a day from the dispatch, on the host's wall clock and on its monotonic
/// clock both (the pause holds until both have passed, so a wall clock set
/// forward doesn't end it). The host's own bound: the sender's task
/// deadline never ends a pause, since a v1 turn isn't interrupted at it.
pub const PAUSE_BOUND_MS: u64 = 24 * 60 * 60 * 1000;

/// One framed prompt whose turn holds the session's terminal frames from
/// attachments without `control`. Kept in `<state>/workers/<sid>.pause`
/// (written before the paste, rewritten as pauses end), so a restarted
/// broker that adopts the worker goes on holding them.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Pause {
    /// The prompt's session-v1 request id.
    pub receipt_id: String,
    /// The prompt's tag: the user message that carries it shows the agent
    /// took the prompt (after a restart, when the receipt can't tell).
    pub tag: String,
    /// The bound ([`PAUSE_BOUND_MS`]) on the wall clock, ms since the epoch.
    pub until_wall_ms: u64,
    /// The bound on `CLOCK_MONOTONIC` (ms) of boot `boot_id`.
    pub until_mono_ms: u64,
    pub boot_id: String,
}

/// What a pause's end is decided from, each pass.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TurnSigns {
    /// The prompt's receipt, if the session host still has it.
    pub receipt: Option<ReceiptState>,
    /// The session runs with a worker.
    pub live: bool,
    /// What the session's chat shows of the prompt's turn.
    pub chat: ChatSigns,
}

/// The prompt's turn as the session's chat shows it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChatSigns {
    /// No turn state: no chat (Codex without hooks, a withdrawn chat), or
    /// an adopting broker that hasn't got the worker's chat yet.
    Unknown,
    /// The agent hasn't taken the prompt: no user message carries its tag.
    NotTaken,
    /// The agent took the prompt and its turn runs.
    Running,
    /// The agent took the prompt and its turn ended: the chat is `ready`
    /// with no current turn of it.
    Ended,
}

impl Pause {
    /// The pause of a prompt dispatched `now`: bounded a day from now.
    pub fn new(receipt_id: &str, tag: &Tag, now: &HostNow) -> Pause {
        Pause {
            receipt_id: receipt_id.to_string(),
            tag: tag.as_str().to_string(),
            until_wall_ms: now.wall_ms.saturating_add(PAUSE_BOUND_MS),
            until_mono_ms: now.mono_ms.saturating_add(PAUSE_BOUND_MS),
            boot_id: now.boot_id.clone(),
        }
    }

    /// Both clocks passed the bound. A reading of another boot can't tell
    /// the monotonic side: not passed (a broker that starts in what reads
    /// as another boot counts it again, [`load_pauses`]).
    pub fn bound_passed(&self, now: &HostNow) -> bool {
        now.wall_ms >= self.until_wall_ms
            && now.boot_id == self.boot_id
            && now.mono_ms >= self.until_mono_ms
    }

    /// Whether the prompt's turn may still run. The pause ends at the first
    /// of these:
    /// - the session is no longer live (the agent exited, its worker went
    ///   away, the session stopped);
    /// - the receipt completed (the turn ended, done or interrupted), or
    ///   was rejected (refused before the prompt reached the agent);
    /// - the chat shows the agent took the prompt and its turn ended;
    /// - the host's bound passed (a day on both clocks: a pause is never
    ///   stuck). The task's deadline isn't one of them: the turn goes on
    ///   past it.
    ///
    /// While the receipt is accepted or executing, the turn may run. When
    /// it can't tell (its outcome is unknown: a broker restart, a prompt the
    /// agent didn't take in time; or it is gone), the chat decides, and with
    /// no turn state the pause holds until the session ends or the bound.
    pub fn holds(&self, signs: TurnSigns, now: &HostNow) -> bool {
        if !signs.live || self.bound_passed(now) {
            return false;
        }
        match signs.receipt {
            Some(ReceiptState::Completed | ReceiptState::Rejected) => false,
            Some(ReceiptState::Accepted | ReceiptState::Executing) => true,
            Some(ReceiptState::OutcomeUnknown) | None => signs.chat != ChatSigns::Ended,
        }
    }
}

/// Sessions whose frames are held, and the prompts holding them.
pub type Pauses = HashMap<String, Vec<Pause>>;

/// Replaces session `sid`'s pause file with `pauses` (removes it when there
/// are none): before a paste, and when pauses end.
pub fn write_pauses(state: &Path, sid: &str, pauses: &[Pause]) -> std::io::Result<()> {
    if crate::session::SessionId::parse(sid).is_none() {
        return Err(std::io::Error::other("not a session id"));
    }
    let path = super::worker::pause_path(state, sid);
    if pauses.is_empty() {
        return match std::fs::remove_file(&path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => Err(error),
            _ => Ok(()),
        };
    }
    let mut bytes = serde_json::to_vec(pauses).map_err(std::io::Error::other)?;
    bytes.push(b'\n');
    let tmp = path.with_file_name(format!("{sid}.pause.tmp{}", std::process::id()));
    let result = (|| {
        let _ = std::fs::remove_file(&tmp);
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&tmp)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        std::fs::rename(&tmp, &path)?;
        if let Some(dir) = path.parent()
            && let Ok(dir) = std::fs::File::open(dir)
        {
            dir.sync_all()?;
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Session `sid`'s pauses as a broker reads them back (at its start, for a
/// session it adopted). A pause written in another boot counts its
/// monotonic side again from `now`, only longer: after a reboot (no session
/// survives one), on macOS after a clock step shifted `kern.boottime` (the
/// boot id there), or with no readable boot id (a fresh one per process). A file that can't be
/// read holds the frames anyway (fail closed), bounded a day from the
/// file's last write (its mtime, at most `now`) on the wall clock and a day
/// from `now` on the monotonic one; either change is written back, so the
/// next broker start keeps that start. If it can't be written, the
/// monotonic side keeps the file's start too (what is left of its day on
/// the wall clock), so no broker start lengthens the hold, and a wall clock
/// set forward before that start shortens it (a damaged file, an
/// unwritable path and a clock step, together).
pub fn load_pauses(state: &Path, sid: &str, now: &HostNow) -> Vec<Pause> {
    if crate::session::SessionId::parse(sid).is_none() {
        return Vec::new();
    }
    let path = super::worker::pause_path(state, sid);
    let read = read_private(&path).and_then(|text| match text {
        None => Ok(None),
        Some(text) => serde_json::from_str::<Vec<Pause>>(&text)
            .map(Some)
            .map_err(std::io::Error::other),
    });
    let (mut pauses, why) = match read {
        Ok(None) => return Vec::new(),
        Ok(Some(pauses)) => (pauses, None),
        Err(error) => {
            let written = std::fs::symlink_metadata(&path)
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                .map_or(now.wall_ms, |d| d.as_millis() as u64)
                .min(now.wall_ms);
            let pause = Pause {
                receipt_id: String::new(),
                tag: String::new(),
                until_wall_ms: written.saturating_add(PAUSE_BOUND_MS),
                until_mono_ms: now.mono_ms.saturating_add(PAUSE_BOUND_MS),
                boot_id: now.boot_id.clone(),
            };
            (vec![pause], Some(error.to_string()))
        }
    };
    let mut rewrite = why.is_some();
    for pause in &mut pauses {
        if pause.boot_id != now.boot_id {
            pause.boot_id = now.boot_id.clone();
            pause.until_mono_ms = now.mono_ms.saturating_add(PAUSE_BOUND_MS);
            rewrite = true;
        }
    }
    if let Some(why) = &why {
        eprintln!(
            "atem runtime: {sid}: terminal pause unreadable ({why}); frames stay held from attachments without control until the session ends or a day after the file's last write"
        );
    }
    if rewrite && let Err(error) = write_pauses(state, sid, &pauses) {
        eprintln!("atem runtime: {sid}: terminal pause not rewritten: {error}");
        if why.is_some() {
            for pause in &mut pauses {
                pause.until_mono_ms = now
                    .mono_ms
                    .saturating_add(pause.until_wall_ms.saturating_sub(now.wall_ms));
            }
        }
    }
    pauses
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "ses-aaaaaaaaaaaa";
    const B: &str = "ses-bbbbbbbbbbbb";

    fn tags(dir: &Path, sid: &str, list: &[&str]) -> PromptTags {
        let mut t = PromptTags::default();
        std::fs::create_dir_all(dir.join("workers")).unwrap();
        for tag in list {
            t.record(dir, sid, &Tag::parse(tag).unwrap()).unwrap();
        }
        t
    }

    fn at(wall_ms: u64, mono_ms: u64) -> HostNow {
        HostNow {
            wall_ms,
            mono_ms,
            boot_id: "boot-1".into(),
        }
    }

    #[test]
    fn known_tags_are_replaced_by_a_placeholder_of_the_same_length() {
        let dir = tempfile::tempdir().unwrap();
        let t = tags(dir.path(), A, &["7QK2-M9XD-4TPA", "3RRW-0B9C-KQ1T"]);
        assert_eq!(PLACEHOLDER.len(), TAG_LEN);
        let text = "[atem 7QK2-M9XD-4TPA] Atem task\n|[atem 3RRW-0B9C-KQ1T] end prompt \
                    echo 7QK2-M9XD-4TPA, other ZZZZ-ZZZZ-ZZZZ, é7QK2-M9XD-4TPA, \
                    lower 7qk2-m9xd-4tpa, mixed 3rRw-0b9C-kQ1t";
        let redacted = t.redact(A, text).unwrap();
        assert_eq!(redacted.len(), text.len());
        assert_eq!(
            redacted,
            "[atem ****-****-****] Atem task\n|[atem ****-****-****] end prompt \
             echo ****-****-****, other ZZZZ-ZZZZ-ZZZZ, é****-****-****, \
             lower ****-****-****, mixed ****-****-****"
        );
        // Another session's chat: an agent can echo any session's tag.
        assert_eq!(t.redact(B, text).unwrap(), redacted);
        // Nothing else changes; text without a known tag is left alone.
        assert_eq!(t.redact(A, "no tags here, ZZZZ-ZZZZ-ZZZZ"), None);
        assert_eq!(t.redact(A, ""), None);
        // Split or cut short, an echo isn't found (documented).
        assert_eq!(t.redact(A, "7QK2-M9XD-4TP… 7QK2-M9XD 4TPA"), None);
        // A file read back gives the same set (a restarted broker).
        let mut again = PromptTags::default();
        again.load(dir.path(), A);
        assert!(again.knows("7QK2-M9XD-4TPA") && again.knows("3RRW-0B9C-KQ1T"));
        assert_eq!(again.redact(A, text).unwrap(), redacted);
        // Recording reads the session's file first: a restarted broker
        // that records before it loaded keeps the earlier tags.
        let mut fresh = PromptTags::default();
        fresh
            .record(dir.path(), A, &Tag::parse("ZZZZ-ZZZZ-ZZZZ").unwrap())
            .unwrap();
        assert!(fresh.knows("7QK2-M9XD-4TPA") && fresh.knows("ZZZZ-ZZZZ-ZZZZ"));
    }

    /// A tags file that can't be read hides every tag-shaped string of that
    /// session's chat, outside its ids, and nothing in any other session's.
    #[test]
    fn an_unreadable_tags_file_hides_tag_shaped_strings_of_its_session_only() {
        let dir = tempfile::tempdir().unwrap();
        let workers = dir.path().join("workers");
        std::fs::create_dir_all(&workers).unwrap();
        std::fs::write(workers.join(format!("{A}.tags")), "not a tag\n").unwrap();
        let mut t = PromptTags::default();
        t.load(dir.path(), A);
        t.load(dir.path(), B);
        let envelope = serde_json::json!({
            "type": "agentChat",
            "data": {"v": 1, "op": "message", "agentId": A,
                "conversationId": "c-7qk2-m9xd-4tpa-x",
                "messageId": "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed",
                "message": {"id": "ZZZZ-ZZZZ-ZZZZ", "turn_id": "ZZZZ-ZZZZ-ZZZZ",
                    "reply_message_ids": ["ZZZZ-ZZZZ-ZZZZ"],
                    "parts": [{"type": "text", "markdown": "x ZZZZ-ZZZZ-ZZZZ y zzzz-zzzz-zzzz"}]},
                "next": "abcd-ABCD-abcd"}
        })
        .to_string();
        let redacted = t.redact(A, &envelope).unwrap();
        assert_eq!(redacted.len(), envelope.len());
        let value: serde_json::Value = serde_json::from_str(&redacted).unwrap();
        let data = &value["data"];
        assert_eq!(
            data["message"]["parts"][0]["markdown"],
            "x ****-****-**** y ****-****-****"
        );
        // Ids keep what they hold (a UUID's middle groups are tag-shaped).
        assert_eq!(data["messageId"], "1b9d6bcd-bbfd-4b2d-9b5d-ab8dfbbd4bed");
        assert_eq!(data["conversationId"], "c-7qk2-m9xd-4tpa-x");
        assert_eq!(data["message"]["id"], "ZZZZ-ZZZZ-ZZZZ");
        assert_eq!(data["message"]["turn_id"], "ZZZZ-ZZZZ-ZZZZ");
        assert_eq!(data["message"]["reply_message_ids"][0], "ZZZZ-ZZZZ-ZZZZ");
        assert_eq!(data["next"], "abcd-ABCD-abcd");
        // Another session is unaffected.
        assert_eq!(t.redact(B, &envelope), None);
        assert_eq!(t.redact(B, "x ZZZZ-ZZZZ-ZZZZ y"), None);
        // Text that isn't JSON: every tag-shaped string.
        assert_eq!(
            t.redact(A, "x ZZZZ-ZZZZ-ZZZZ y").as_deref(),
            Some("x ****-****-**** y")
        );
        // A symlink isn't followed.
        std::os::unix::fs::symlink(
            workers.join(format!("{A}.tags")),
            workers.join(format!("{B}.tags")),
        )
        .unwrap();
        let mut t = PromptTags::default();
        t.load(dir.path(), B);
        assert!(t.redact(B, "ZZZZ-ZZZZ-ZZZZ").is_some());
        assert!(t.redact(A, "ZZZZ-ZZZZ-ZZZZ").is_none());
    }

    /// In fail-closed mode every id of every chat-v1 envelope the host
    /// builds keeps what it holds (each a lowercase UUID here: tag-shaped
    /// once uppercased), and every text loses its tag-shaped strings.
    #[test]
    fn fail_closed_redaction_keeps_every_id_of_real_envelopes() {
        use crate::chat::adapter::Part;
        use crate::chat::session::{ChatMessage, CoverageState, Hole, Out, Role, State, Status};
        use crate::chat::wire;
        let dir = tempfile::tempdir().unwrap();
        let workers = dir.path().join("workers");
        std::fs::create_dir_all(&workers).unwrap();
        std::fs::write(workers.join(format!("{A}.tags")), "not a tag\n").unwrap();
        let mut t = PromptTags::default();
        t.load(dir.path(), A);
        let id = || uuid::Uuid::new_v4().to_string();
        let (conv, generation) = (id(), id());
        let text = "said ZZZZ-ZZZZ-ZZZZ and zzzz-zzzz-zzzz";
        let message = ChatMessage {
            message_id: id(),
            role: Role::Assistant,
            origin: None,
            turn_id: id(),
            request_id: Some(id()),
            created_at_ms: 1,
            parts: vec![
                Part::Text {
                    id: id(),
                    markdown: text.into(),
                },
                Part::Tool {
                    id: id(),
                    name: text.into(),
                    summary: text.into(),
                },
            ],
        };
        let holes = vec![Hole {
            after: id(),
            before: Some(id()),
            count: Some(2),
        }];
        let status = Status {
            state: State::Working,
            since_ms: 1,
            detail: Some(text.into()),
        };
        let rule = crate::session_protocol::wire::AlwaysRule {
            rule_id: id(),
            label: text.into(),
            scope: "session".into(),
        };
        let mut lease_held = wire::error(
            &conv,
            A,
            Some((&generation, 9)),
            "lease_held",
            text,
            Some(&id()),
        );
        lease_held.body.insert(
            "controller".into(),
            serde_json::json!({"controller_session": id(), "lease_epoch": 3}),
        );
        lease_held
            .body
            .insert("requestId".into(), serde_json::Value::String(id()));
        let envelopes = vec![
            wire::opened(
                &conv,
                A,
                &generation,
                &status,
                &[],
                std::slice::from_ref(&rule),
            ),
            wire::rules(&conv, A, &generation, 1, &[rule]),
            wire::event(&conv, A, &generation, 2, &Out::Message(message.clone())),
            wire::event(
                &conv,
                A,
                &generation,
                3,
                &Out::Recovered {
                    message: message.clone(),
                    after: Some(id()),
                },
            ),
            wire::event(
                &conv,
                A,
                &generation,
                4,
                &Out::Coverage(CoverageState {
                    oldest_retained: Some(id()),
                    truncated: false,
                    holes: holes.clone(),
                }),
            ),
            wire::event(&conv, A, &generation, 5, &Out::Status(status.clone())),
            wire::event(
                &conv,
                A,
                &generation,
                6,
                &Out::Accepted { request_id: id() },
            ),
            wire::event(
                &conv,
                A,
                &generation,
                7,
                &Out::Complete {
                    turn_id: id(),
                    request_id: Some(id()),
                    outcome: crate::chat::adapter::Outcome::Done,
                },
            ),
            wire::history_message(&conv, A, &generation, 8, &message, Some(&id())),
            wire::history_end(
                &conv,
                A,
                &generation,
                9,
                Some(&id()),
                &wire::PageInfo {
                    selector: "before",
                    count: 1,
                    content_bytes: 1,
                    wire_bytes: 1,
                    end: false,
                    next: Some(id()),
                    coverage: "partial",
                    oldest_retained: Some(id()),
                    truncated: false,
                    holes,
                },
            ),
            lease_held,
        ];
        // Every string leaf: a UUID kept, a text redacted.
        fn leaves(v: &serde_json::Value, path: String, out: &mut Vec<(String, String)>) {
            match v {
                serde_json::Value::String(s) => out.push((path, s.clone())),
                serde_json::Value::Array(items) => {
                    for (i, item) in items.iter().enumerate() {
                        leaves(item, format!("{path}[{i}]"), out);
                    }
                }
                serde_json::Value::Object(map) => {
                    for (k, item) in map {
                        leaves(item, format!("{path}.{k}"), out);
                    }
                }
                _ => {}
            }
        }
        let mut ids = 0;
        for env in envelopes {
            let op = env.op.clone();
            let text_in =
                serde_json::to_string(&crate::websocket_client::AstationMessage::AgentChat(env))
                    .unwrap();
            let text_out = t.redact(A, &text_in).unwrap_or_else(|| text_in.clone());
            assert_eq!(text_out.len(), text_in.len(), "{op}");
            let (mut before, mut after) = (Vec::new(), Vec::new());
            leaves(
                &serde_json::from_str(&text_in).unwrap(),
                String::new(),
                &mut before,
            );
            leaves(
                &serde_json::from_str(&text_out).unwrap(),
                String::new(),
                &mut after,
            );
            before.sort();
            after.sort();
            assert_eq!(before.len(), after.len(), "{op}");
            for ((path, was), (path_after, now)) in before.iter().zip(&after) {
                assert_eq!(path, path_after, "{op}");
                if uuid::Uuid::parse_str(was).is_ok() {
                    ids += 1;
                    assert_eq!(now, was, "{op} {path}: an id changed");
                } else if was == text {
                    assert_eq!(now, "said ****-****-**** and ****-****-****", "{op} {path}");
                } else {
                    assert_eq!(now, was, "{op} {path}");
                }
            }
        }
        assert!(ids > 40, "{ids}");
    }

    /// No text that isn't a session id becomes a path: nothing is opened,
    /// recorded or remembered, and redaction is unchanged.
    #[test]
    fn a_request_id_is_never_a_path() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        std::fs::create_dir_all(state.join("workers")).unwrap();
        // Files a traversal would reach: each one, read, would switch its
        // "session" to fail closed (not a tag).
        std::fs::write(state.join("x.tags"), "not a tag\n").unwrap();
        std::fs::write(dir.path().join("x.tags"), "not a tag\n").unwrap();
        let mut t = PromptTags::default();
        for id in [
            "../x",
            "../../x",
            "/etc/hostname/x",
            &format!("{}/x", dir.path().display()),
            "ses-aaaaaaaaaaaa/../../x",
            "ses-AAAAAAAAAAAA",
            "",
        ] {
            t.load(&state, id);
            assert!(t.record(&state, id, &Tag::random()).is_err(), "{id}");
            assert_eq!(t.redact(id, "x ZZZZ-ZZZZ-ZZZZ y"), None, "{id}");
            assert!(write_pauses(&state, id, &[]).is_err(), "{id}");
            assert_eq!(load_pauses(&state, id, &at(0, 0)), Vec::new(), "{id}");
        }
        assert_eq!(t.sessions(), 0);
        let mut left: Vec<_> = std::fs::read_dir(state.join("workers")).unwrap().collect();
        assert!(left.pop().is_none());
        // A session that is gone is forgotten.
        let mut t = tags(&state, A, &["7QK2-M9XD-4TPA"]);
        t.load(&state, B);
        assert_eq!(t.sessions(), 2);
        t.retain(|sid| sid == B);
        assert_eq!(t.sessions(), 1);
        assert!(!t.knows("7QK2-M9XD-4TPA"));
    }

    /// The pause ends on every way a framed prompt's turn can end; after a
    /// restart (the receipt's outcome unknown) the chat decides, and
    /// without turn state the pause holds until the session ends or the
    /// host's bound. The task's deadline isn't one of them.
    #[test]
    fn a_pause_ends_with_every_turn_outcome() {
        let now = at(1_000, 1_000);
        let pause = Pause::new("r", &Tag::parse("7QK2-M9XD-4TPA").unwrap(), &now);
        let running = TurnSigns {
            receipt: Some(ReceiptState::Executing),
            live: true,
            chat: ChatSigns::Running,
        };
        let restarted = TurnSigns {
            receipt: Some(ReceiptState::OutcomeUnknown),
            ..running
        };
        for holding in [
            running,
            TurnSigns {
                receipt: Some(ReceiptState::Accepted),
                chat: ChatSigns::NotTaken,
                ..running
            },
            // A running receipt holds whatever the chat says.
            TurnSigns {
                chat: ChatSigns::Ended,
                ..running
            },
            // After a restart: the turn runs, the prompt isn't taken yet, or
            // no turn state (the worker's chat not here yet, no chat).
            restarted,
            TurnSigns {
                chat: ChatSigns::NotTaken,
                ..restarted
            },
            TurnSigns {
                chat: ChatSigns::Unknown,
                ..restarted
            },
            TurnSigns {
                receipt: None,
                chat: ChatSigns::Unknown,
                ..running
            },
        ] {
            assert!(pause.holds(holding, &now), "{holding:?}");
            // A minute or an hour later (any task deadline long past).
            assert!(pause.holds(holding, &at(61_000, 61_000)), "{holding:?}");
            assert!(
                pause.holds(holding, &at(3_601_000, 3_601_000)),
                "{holding:?}"
            );
        }
        for ended in [
            // completed (done or interrupted)
            TurnSigns {
                receipt: Some(ReceiptState::Completed),
                ..running
            },
            // rejected: refused before the prompt reached the agent
            TurnSigns {
                receipt: Some(ReceiptState::Rejected),
                ..running
            },
            // after a restart, or a prompt not taken in time: the chat shows
            // the turn ended
            TurnSigns {
                chat: ChatSigns::Ended,
                ..restarted
            },
            TurnSigns {
                receipt: None,
                chat: ChatSigns::Ended,
                ..running
            },
            // the agent exited, its worker went away, the session stopped
            TurnSigns {
                live: false,
                ..running
            },
            TurnSigns {
                live: false,
                chat: ChatSigns::Unknown,
                ..restarted
            },
        ] {
            assert!(!pause.holds(ended, &now), "{ended:?}");
        }
    }

    /// The host's bound: a day from the dispatch on the wall clock and on
    /// the monotonic clock both; a reading of another boot can't end it.
    #[test]
    fn the_pause_bound_is_a_day_on_both_clocks() {
        let day = PAUSE_BOUND_MS;
        let pause = Pause::new("r", &Tag::random(), &at(1_000, 5_000));
        assert_eq!(
            (pause.until_wall_ms, pause.until_mono_ms),
            (1_000 + day, 5_000 + day)
        );
        let running = TurnSigns {
            receipt: Some(ReceiptState::Executing),
            live: true,
            chat: ChatSigns::Running,
        };
        // Within the day, on either clock: holds.
        assert!(pause.holds(running, &at(day, day)));
        // The wall clock set a day forward: the monotonic side holds.
        assert!(pause.holds(running, &at(1_000 + day, 5_000 + 60_000)));
        // The monotonic day passed, the wall clock set back: holds.
        assert!(pause.holds(running, &at(1_000, 5_000 + day)));
        // Both passed: the bound ends it, whatever the turn says.
        assert!(!pause.holds(running, &at(1_000 + day, 5_000 + day)));
        // Another boot: not passed.
        let other = HostNow {
            boot_id: "boot-2".into(),
            ..at(1_000 + 2 * day, 5_000 + 2 * day)
        };
        assert!(pause.holds(running, &other));
    }

    #[test]
    fn pauses_are_written_before_the_paste_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("workers")).unwrap();
        let path = super::super::worker::pause_path(dir.path(), A);
        let now = at(10_000, 20_000);
        let pauses = vec![
            Pause::new("r1", &Tag::parse("7QK2-M9XD-4TPA").unwrap(), &now),
            Pause::new("r2", &Tag::parse("3RRW-0B9C-KQ1T").unwrap(), &now),
        ];
        write_pauses(dir.path(), A, &pauses).unwrap();
        assert_eq!(load_pauses(dir.path(), A, &now), pauses);
        write_pauses(dir.path(), A, &pauses[1..]).unwrap();
        assert_eq!(load_pauses(dir.path(), A, &now), pauses[1..].to_vec());
        write_pauses(dir.path(), A, &[]).unwrap();
        assert!(!path.exists());
        assert_eq!(load_pauses(dir.path(), A, &now), Vec::new());
        // Read in another boot: the monotonic side counts again from now,
        // and that is written back.
        write_pauses(dir.path(), A, &pauses).unwrap();
        let rebooted = HostNow {
            boot_id: "boot-2".into(),
            ..at(11_000, 300)
        };
        let back = load_pauses(dir.path(), A, &rebooted);
        assert_eq!(back.len(), 2);
        for p in &back {
            assert_eq!(p.until_wall_ms, 10_000 + PAUSE_BOUND_MS);
            assert_eq!(
                (p.boot_id.as_str(), p.until_mono_ms),
                ("boot-2", 300 + PAUSE_BOUND_MS)
            );
        }
        assert_eq!(load_pauses(dir.path(), A, &rebooted), back);
    }

    /// A pause file that can't be read holds the frames anyway, a day from
    /// the file's last write, and keeps that start at every later broker
    /// start: written back when it can be, else from the file's time.
    #[test]
    fn an_unreadable_pause_keeps_its_start_across_broker_starts() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("workers")).unwrap();
        let path = super::super::worker::pause_path(dir.path(), A);
        std::fs::write(&path, "{").unwrap();
        let written = std::fs::metadata(&path)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let first = at(written + 5_000, 1_000);
        let held = load_pauses(dir.path(), A, &first);
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].until_wall_ms, written + PAUSE_BOUND_MS);
        assert_eq!(held[0].until_mono_ms, 1_000 + PAUSE_BOUND_MS);
        assert!(held[0].tag.is_empty() && held[0].receipt_id.is_empty());
        // Written back: the next broker start, hours later, keeps it.
        let later = at(written + 3_600_000, 1_000 + 3_595_000);
        assert_eq!(load_pauses(dir.path(), A, &later), held);
        // A path that can't be written either (a directory): the
        // monotonic side is what is left of the file's day.
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        let written = std::fs::symlink_metadata(&path)
            .unwrap()
            .modified()
            .unwrap()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64;
        let now = at(written + 3_600_000, 7_000);
        let held = load_pauses(dir.path(), A, &now);
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].until_wall_ms, written + PAUSE_BOUND_MS);
        assert_eq!(held[0].until_mono_ms, 7_000 + PAUSE_BOUND_MS - 3_600_000);
        // A file's time ahead of the wall clock counts as now.
        let early = at(written.saturating_sub(60_000), 7_000);
        let held = load_pauses(dir.path(), A, &early);
        assert_eq!(held[0].until_wall_ms, early.wall_ms + PAUSE_BOUND_MS);
    }
}

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
//!   Verbatim echoes by an agent are replaced too; a paraphrase isn't.
//! - **terminal-v1:** frames aren't text Atem controls (the agent's
//!   interface wraps, splits or truncates the prompt), so they are held
//!   from attachments without `control` while a framed prompt's turn runs
//!   ([`Pause`]), and resume with a full frame once it ended.
//!
//! The tags are kept per session in `<state>/workers/<sid>.tags` (one per
//! line, 0600), written and synced before the prompt is pasted, so a
//! restarted broker still knows them; they go with the session's worker
//! files. Control holders, the local frontends, the session logs and the
//! journal keep the real text.
use std::collections::{HashMap, HashSet};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::Result;
use atem_client::session::framing::{TAG_LEN, Tag};
use atem_client::session::wire::ReceiptState;

/// What an attachment without `control` sees in place of a tag.
pub const PLACEHOLDER: &str = "****-****-****";

#[derive(Default)]
pub struct PromptTags {
    known: HashSet<String>,
    loaded: HashSet<String>,
    /// Sessions whose tags file couldn't be read: every tag-shaped string
    /// is replaced for them (fail closed).
    unreadable: HashSet<String>,
}

impl PromptTags {
    /// Records `tag` for session `sid`, durably, before its prompt is
    /// pasted.
    pub fn record(&mut self, state: &Path, sid: &str, tag: &Tag) -> Result<()> {
        let path = super::worker::tags_path(state, sid);
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)?;
        file.write_all(format!("{}\n", tag.as_str()).as_bytes())?;
        file.sync_data()?;
        self.loaded.insert(sid.to_string());
        self.known.insert(tag.as_str().to_string());
        Ok(())
    }

    /// Reads session `sid`'s tags once (a session the broker adopted, or
    /// registered after a restart). A file that can't be read makes every
    /// tag-shaped string redacted.
    pub fn load(&mut self, state: &Path, sid: &str) {
        if !self.loaded.insert(sid.to_string()) {
            return;
        }
        let path = super::worker::tags_path(state, sid);
        let text = match read_private(&path) {
            Ok(Some(text)) => text,
            Ok(None) => return,
            Err(error) => {
                eprintln!(
                    "atem runtime: {sid}: prompt tags unreadable ({error}); every tag-shaped string is hidden from attachments without control"
                );
                self.unreadable.insert(sid.to_string());
                return;
            }
        };
        for line in text.lines() {
            match Tag::parse(line) {
                Some(tag) => {
                    self.known.insert(tag.as_str().to_string());
                }
                None => {
                    self.unreadable.insert(sid.to_string());
                }
            }
        }
    }

    /// `text` with every known tag (every tag-shaped string while a tags
    /// file is unreadable) replaced by [`PLACEHOLDER`]; `None` when there
    /// is none.
    pub fn redact(&self, text: &str) -> Option<String> {
        if self.known.is_empty() && self.unreadable.is_empty() {
            return None;
        }
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
                    .and_then(Tag::parse)
                    .is_some_and(|tag| {
                        !self.unreadable.is_empty() || self.known.contains(tag.as_str())
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
        self.known.contains(tag)
    }
}

fn read_private(path: &Path) -> std::io::Result<Option<String>> {
    use std::io::Read;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path);
    let mut file = match file {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    let mut text = String::new();
    file.read_to_string(&mut text)?;
    Ok(Some(text))
}

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
    /// The task's deadline (wall ms): the bounded fallback.
    pub until_wall_ms: u64,
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
    pub now_wall_ms: u64,
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
    /// Whether the prompt's turn may still run. The pause ends at the first
    /// of these:
    /// - the session is no longer live (the agent exited, its worker went
    ///   away, the session stopped);
    /// - the deadline passed (the bounded fallback: a pause is never
    ///   stuck);
    /// - the receipt completed (the turn ended, done or interrupted), or
    ///   was rejected (refused before the prompt reached the agent);
    /// - the chat shows the agent took the prompt and its turn ended.
    ///
    /// While the receipt is accepted or executing, the turn may run. When
    /// it can't tell (its outcome is unknown: a broker restart, a prompt the
    /// agent didn't take in time; or it is gone), the chat decides, and with
    /// no turn state the pause holds until the session ends or the
    /// deadline.
    pub fn holds(&self, signs: TurnSigns) -> bool {
        if !signs.live || signs.now_wall_ms >= self.until_wall_ms {
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

/// The longest a pause read back without its deadline holds (a task's
/// longest lifetime).
const UNREADABLE_PAUSE_MS: u64 = 24 * 60 * 60 * 1000;

/// Replaces session `sid`'s pause file with `pauses` (removes it when there
/// are none): before a paste, and when pauses end.
pub fn write_pauses(state: &Path, sid: &str, pauses: &[Pause]) -> std::io::Result<()> {
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

/// Session `sid`'s pauses as a restarted broker reads them back. A file
/// that can't be read holds the frames anyway (fail closed), for at most a
/// task's lifetime from `now_wall_ms`.
pub fn read_pauses(state: &Path, sid: &str, now_wall_ms: u64) -> Vec<Pause> {
    let path = super::worker::pause_path(state, sid);
    match read_private(&path) {
        Ok(None) => Vec::new(),
        Ok(Some(text)) => match serde_json::from_str::<Vec<Pause>>(&text) {
            Ok(pauses) => pauses,
            Err(error) => unreadable(sid, &error.to_string(), now_wall_ms),
        },
        Err(error) => unreadable(sid, &error.to_string(), now_wall_ms),
    }
}

fn unreadable(sid: &str, why: &str, now_wall_ms: u64) -> Vec<Pause> {
    eprintln!(
        "atem runtime: {sid}: terminal pause unreadable ({why}); frames stay held from attachments without control until the session ends or a day passed"
    );
    vec![Pause {
        receipt_id: String::new(),
        tag: String::new(),
        until_wall_ms: now_wall_ms.saturating_add(UNREADABLE_PAUSE_MS),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(dir: &Path, sid: &str, list: &[&str]) -> PromptTags {
        let mut t = PromptTags::default();
        std::fs::create_dir_all(dir.join("workers")).unwrap();
        for tag in list {
            t.record(dir, sid, &Tag::parse(tag).unwrap()).unwrap();
        }
        t
    }

    #[test]
    fn known_tags_are_replaced_by_a_placeholder_of_the_same_length() {
        let dir = tempfile::tempdir().unwrap();
        let t = tags(
            dir.path(),
            "ses-aaaaaaaaaaaa",
            &["7QK2-M9XD-4TPA", "3RRW-0B9C-KQ1T"],
        );
        assert_eq!(PLACEHOLDER.len(), TAG_LEN);
        let text = "[atem 7QK2-M9XD-4TPA] Atem task\n|[atem 3RRW-0B9C-KQ1T] end prompt \
                    echo 7QK2-M9XD-4TPA, other ZZZZ-ZZZZ-ZZZZ, é7QK2-M9XD-4TPA";
        let redacted = t.redact(text).unwrap();
        assert_eq!(redacted.len(), text.len());
        assert_eq!(
            redacted,
            "[atem ****-****-****] Atem task\n|[atem ****-****-****] end prompt \
             echo ****-****-****, other ZZZZ-ZZZZ-ZZZZ, é****-****-****"
        );
        // Nothing else changes; text without a known tag is left alone.
        assert_eq!(t.redact("no tags here, ZZZZ-ZZZZ-ZZZZ"), None);
        assert_eq!(t.redact(""), None);
        // A file read back gives the same set (a restarted broker).
        let mut again = PromptTags::default();
        again.load(dir.path(), "ses-aaaaaaaaaaaa");
        assert!(again.knows("7QK2-M9XD-4TPA") && again.knows("3RRW-0B9C-KQ1T"));
        assert_eq!(again.redact(text).unwrap(), redacted);
    }

    #[test]
    fn an_unreadable_tags_file_hides_every_tag_shaped_string() {
        let dir = tempfile::tempdir().unwrap();
        let workers = dir.path().join("workers");
        std::fs::create_dir_all(&workers).unwrap();
        std::fs::write(workers.join("ses-aaaaaaaaaaaa.tags"), "not a tag\n").unwrap();
        let mut t = PromptTags::default();
        t.load(dir.path(), "ses-aaaaaaaaaaaa");
        assert_eq!(
            t.redact("x ZZZZ-ZZZZ-ZZZZ y").as_deref(),
            Some("x ****-****-**** y")
        );
        // A symlink isn't followed.
        std::os::unix::fs::symlink(
            workers.join("ses-aaaaaaaaaaaa.tags"),
            workers.join("ses-bbbbbbbbbbbb.tags"),
        )
        .unwrap();
        let mut t = PromptTags::default();
        t.load(dir.path(), "ses-bbbbbbbbbbbb");
        assert!(t.redact("ZZZZ-ZZZZ-ZZZZ").is_some());
    }

    /// The pause ends on every way a framed prompt's turn can end, and on
    /// its bounded fallback (the task's deadline); after a restart (the
    /// receipt's outcome unknown) the chat decides, and without turn state
    /// the pause holds until the session ends or the deadline.
    #[test]
    fn a_pause_ends_with_every_turn_outcome() {
        let pause = Pause {
            receipt_id: "r".into(),
            tag: "7QK2-M9XD-4TPA".into(),
            until_wall_ms: 1_000,
        };
        let running = TurnSigns {
            receipt: Some(ReceiptState::Executing),
            live: true,
            chat: ChatSigns::Running,
            now_wall_ms: 10,
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
            assert!(pause.holds(holding), "{holding:?}");
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
            // the task's deadline passed (also without turn state)
            TurnSigns {
                now_wall_ms: 1_000,
                ..running
            },
            TurnSigns {
                now_wall_ms: 1_000,
                chat: ChatSigns::Unknown,
                ..restarted
            },
        ] {
            assert!(!pause.holds(ended), "{ended:?}");
        }
    }

    #[test]
    fn pauses_are_written_before_the_paste_and_read_back() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("workers")).unwrap();
        let sid = "ses-aaaaaaaaaaaa";
        let pauses = vec![
            Pause {
                receipt_id: "r1".into(),
                tag: "7QK2-M9XD-4TPA".into(),
                until_wall_ms: 5_000,
            },
            Pause {
                receipt_id: "r2".into(),
                tag: "3RRW-0B9C-KQ1T".into(),
                until_wall_ms: 6_000,
            },
        ];
        write_pauses(dir.path(), sid, &pauses).unwrap();
        assert_eq!(read_pauses(dir.path(), sid, 0), pauses);
        write_pauses(dir.path(), sid, &pauses[1..]).unwrap();
        assert_eq!(read_pauses(dir.path(), sid, 0), pauses[1..].to_vec());
        write_pauses(dir.path(), sid, &[]).unwrap();
        assert!(!super::super::worker::pause_path(dir.path(), sid).exists());
        assert_eq!(read_pauses(dir.path(), sid, 0), Vec::new());
        // A damaged file holds the frames anyway, for at most a day.
        std::fs::write(super::super::worker::pause_path(dir.path(), sid), "{").unwrap();
        let held = read_pauses(dir.path(), sid, 100);
        assert_eq!(held.len(), 1);
        assert_eq!(held[0].until_wall_ms, 100 + 24 * 60 * 60 * 1000);
    }
}

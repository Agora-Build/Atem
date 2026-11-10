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
/// attachments without `control`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pause {
    /// The prompt's session-v1 request id.
    pub receipt_id: String,
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
    /// The session's chat has turn state (chat-v1 available).
    pub chat: bool,
    pub now_wall_ms: u64,
}

impl Pause {
    /// Whether the prompt's turn may still run: its receipt is accepted or
    /// executing, its session is live with turn state, and its deadline
    /// hasn't passed. Every other case ends the pause: the turn completed
    /// (done or interrupted), the prompt was rejected (refused, timed out
    /// before the agent took it) or its outcome is unknown (a worker or
    /// broker restart), the receipt is gone, the agent exited or its worker
    /// went away, the session stopped, the chat was withdrawn (no turn end
    /// will come), or the deadline passed.
    pub fn holds(&self, signs: TurnSigns) -> bool {
        matches!(
            signs.receipt,
            Some(ReceiptState::Accepted | ReceiptState::Executing)
        ) && signs.live
            && signs.chat
            && signs.now_wall_ms < self.until_wall_ms
    }
}

/// Sessions whose frames are held, and the prompts holding them.
pub type Pauses = HashMap<String, Vec<Pause>>;

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
    /// its bounded fallback (the task's deadline).
    #[test]
    fn a_pause_ends_with_every_turn_outcome() {
        let pause = Pause {
            receipt_id: "r".into(),
            until_wall_ms: 1_000,
        };
        let running = TurnSigns {
            receipt: Some(ReceiptState::Executing),
            live: true,
            chat: true,
            now_wall_ms: 10,
        };
        assert!(pause.holds(running));
        assert!(pause.holds(TurnSigns {
            receipt: Some(ReceiptState::Accepted),
            ..running
        }));
        for ended in [
            // completed (done or interrupted)
            TurnSigns {
                receipt: Some(ReceiptState::Completed),
                ..running
            },
            // rejected: refused, or not taken by the agent in time
            TurnSigns {
                receipt: Some(ReceiptState::Rejected),
                ..running
            },
            // outcome unknown: a worker or broker restart mid-turn
            TurnSigns {
                receipt: Some(ReceiptState::OutcomeUnknown),
                ..running
            },
            // the receipt is gone
            TurnSigns {
                receipt: None,
                ..running
            },
            // the agent exited, its worker went away, the session stopped
            TurnSigns {
                live: false,
                ..running
            },
            // the chat was withdrawn: no turn end will come
            TurnSigns {
                chat: false,
                ..running
            },
            // the task's deadline passed
            TurnSigns {
                now_wall_ms: 1_000,
                ..running
            },
        ] {
            assert!(!pause.holds(ended), "{ended:?}");
        }
    }
}

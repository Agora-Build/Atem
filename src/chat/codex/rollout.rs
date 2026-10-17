//! Incremental reader for Codex's rollout transcript
//! (`$CODEX_HOME/sessions/YYYY/MM/DD/rollout-<time>-<session_id>.jsonl`,
//! `designs/fixtures/codex-hooks/README.md` §2).
//!
//! Lines are `{timestamp, ordinal, type, payload}`. Only the UI-level
//! records count:
//!
//! - `event_msg task_started{turn_id}` → `LogItem::TurnStarted` (the turn is
//!   working: also a compaction's, which has no prompt);
//! - `event_msg item_completed{turn_id, item}`: `UserMessage` →
//!   `LogItem::UserMessage`, `AgentMessage` (either phase, empty text
//!   skipped) → a text part, `CommandExecution` → a tool part; every other
//!   item (`Reasoning`, `ContextCompaction`, …) is skipped;
//! - `event_msg task_complete{turn_id}` → `TurnEnded` done, `turn_aborted`
//!   → `TurnEnded` interrupted.
//!
//! Everything else (`response_item`s, developer messages, `world_state`,
//! `turn_context`, `compacted`, token records, …) is skipped, as is any
//! record type this reader doesn't know. A known record without the ids the
//! reader relies on is a format change: a fatal `Problem` (chat is
//! withdrawn). A task that starts while a user turn runs (an automatic
//! compaction inside the turn) neither starts nor ends anything: the turn
//! goes on. Messages arrive whole (Codex writes no deltas, and an
//! interrupted turn's partial answer is never written).

use std::collections::{HashSet, VecDeque};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::chat::adapter::{LogItem, Outcome, Part};
use crate::chat::claude::transcript::{parse_rfc3339_ms, summarize_tool};

const SEEN_CAP: usize = 10_000;
/// The tool name a command execution is shown under (Codex's hooks call
/// its shell tool `Bash` too).
pub const COMMAND_TOOL: &str = "Bash";

pub struct RolloutReader {
    path: PathBuf,
    offset: u64,
    pending: Vec<u8>,
    seen: HashSet<String>,
    seen_order: VecDeque<String>,
    seen_cap: usize,
    /// The user turn running (its `task_started` read, no end yet).
    active: Option<String>,
    /// Tasks started inside `active` (compaction): their ends are not the
    /// turn's.
    nested: HashSet<String>,
}

impl RolloutReader {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            offset: 0,
            pending: Vec::new(),
            seen: HashSet::new(),
            seen_order: VecDeque::new(),
            seen_cap: SEEN_CAP,
            active: None,
            nested: HashSet::new(),
        }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(test)]
    fn reread_from_start(&mut self) {
        self.offset = 0;
        self.pending.clear();
    }

    /// Read new complete lines since the last call and map them to LogItems.
    pub fn poll(&mut self) -> Vec<LogItem> {
        let mut out = Vec::new();
        let Ok(mut file) = std::fs::File::open(&self.path) else {
            return out;
        };
        let len = file.metadata().map(|m| m.len()).unwrap_or(0);
        if len < self.offset {
            // truncated or replaced: start over (the seen set prevents duplicates)
            self.offset = 0;
            self.pending.clear();
        }
        if file.seek(SeekFrom::Start(self.offset)).is_err() {
            return out;
        }
        let mut buf = Vec::new();
        if file.read_to_end(&mut buf).is_err() {
            return out;
        }
        self.offset += buf.len() as u64;
        self.pending.extend_from_slice(&buf);

        let Some(last_nl) = self.pending.iter().rposition(|b| *b == b'\n') else {
            return out;
        };
        let rest = self.pending.split_off(last_nl + 1);
        let complete = std::mem::replace(&mut self.pending, rest);
        let mut garbage = false;
        for line in complete[..last_nl].split(|b| *b == b'\n') {
            if line.iter().all(|b| b.is_ascii_whitespace()) {
                continue;
            }
            match serde_json::from_slice::<Value>(line) {
                Ok(v) => self.map_record(&v, &mut out),
                Err(_) => {
                    if !garbage {
                        garbage = true;
                        out.push(LogItem::Problem {
                            detail: "rollout line is not valid JSON".into(),
                            fatal: false,
                        });
                    }
                }
            }
        }
        out
    }

    fn remember(&mut self, key: String) -> bool {
        if self.seen.contains(&key) {
            return false;
        }
        self.seen.insert(key.clone());
        self.seen_order.push_back(key);
        if self.seen_order.len() > self.seen_cap
            && let Some(old) = self.seen_order.pop_front()
        {
            self.seen.remove(&old);
        }
        true
    }

    fn map_record(&mut self, v: &Value, out: &mut Vec<LogItem>) {
        let fatal = |detail: String| LogItem::Problem {
            detail,
            fatal: true,
        };
        let Some(kind) = v.get("type").and_then(Value::as_str) else {
            out.push(fatal("rollout record has no type".into()));
            return;
        };
        if kind != "event_msg" {
            return;
        }
        let Some(payload) = v.get("payload").filter(|p| p.is_object()) else {
            out.push(fatal("rollout event has no payload".into()));
            return;
        };
        let Some(event) = payload.get("type").and_then(Value::as_str) else {
            out.push(fatal("rollout event has no type".into()));
            return;
        };
        if !matches!(
            event,
            "task_started" | "task_complete" | "turn_aborted" | "item_completed"
        ) {
            return;
        }
        let Some(turn_id) = payload.get("turn_id").and_then(Value::as_str) else {
            out.push(fatal(format!("rollout {event} has no turn_id")));
            return;
        };
        match event {
            "task_started" => {
                if !self.remember(format!("start:{turn_id}")) {
                    return;
                }
                let by_user =
                    payload.pointer("/turn_attribution/turn_trigger") == Some(&Value::from("user"));
                if self.active.is_some() && !by_user {
                    self.nested.insert(turn_id.to_string());
                    return;
                }
                self.active = Some(turn_id.to_string());
                out.push(LogItem::TurnStarted {
                    turn_id: turn_id.to_string(),
                });
            }
            "task_complete" | "turn_aborted" => {
                if !self.remember(format!("end:{turn_id}")) {
                    return;
                }
                if self.nested.remove(turn_id) {
                    return;
                }
                if self.active.as_deref() == Some(turn_id) {
                    self.active = None;
                }
                let outcome = if event == "task_complete" {
                    Outcome::Done
                } else {
                    Outcome::Interrupted
                };
                out.push(LogItem::TurnEnded {
                    turn_id: turn_id.to_string(),
                    outcome,
                });
            }
            _ => self.map_item(v, payload, turn_id, out),
        }
    }

    fn map_item(&mut self, v: &Value, payload: &Value, turn_id: &str, out: &mut Vec<LogItem>) {
        let item = payload.get("item");
        let Some(kind) = item.and_then(|i| i.get("type")).and_then(Value::as_str) else {
            out.push(LogItem::Problem {
                detail: "rollout item has no type".into(),
                fatal: true,
            });
            return;
        };
        let item = item.unwrap();
        if !matches!(kind, "UserMessage" | "AgentMessage" | "CommandExecution") {
            return;
        }
        let Some(id) = item.get("id").and_then(Value::as_str) else {
            out.push(LogItem::Problem {
                detail: format!("rollout {kind} has no id"),
                fatal: true,
            });
            return;
        };
        if !self.remember(format!("item:{id}")) {
            return;
        }
        let ts = created_at_ms(v, payload);
        let turn_id = turn_id.to_string();
        match kind {
            "UserMessage" => {
                let texts = texts(item);
                if texts.is_empty() {
                    return; // e.g. an image only: nothing to show as text
                }
                out.push(LogItem::UserMessage {
                    id: id.to_string(),
                    turn_id,
                    text: texts.join("\n"),
                    created_at_ms: ts,
                });
            }
            "AgentMessage" => {
                let texts: Vec<&str> = texts(item).into_iter().filter(|t| !t.is_empty()).collect();
                let multi = texts.len() > 1;
                for (i, text) in texts.into_iter().enumerate() {
                    let part_id = if multi {
                        format!("{id}:{i}")
                    } else {
                        id.to_string()
                    };
                    out.push(LogItem::AssistantPart {
                        message_id: id.to_string(),
                        part: Part::Text {
                            id: part_id,
                            markdown: text.to_string(),
                        },
                        turn_id: turn_id.clone(),
                        created_at_ms: ts,
                    });
                }
            }
            _ => {
                let command = command_text(item);
                out.push(LogItem::AssistantPart {
                    message_id: id.to_string(),
                    part: Part::Tool {
                        id: id.to_string(),
                        name: COMMAND_TOOL.to_string(),
                        summary: summarize_tool(
                            COMMAND_TOOL,
                            &serde_json::json!({ "command": command }),
                        ),
                    },
                    turn_id,
                    created_at_ms: ts,
                });
            }
        }
    }
}

/// The text entries of an item's `content` (`text` for user messages,
/// `Text` for agent messages).
fn texts(item: &Value) -> Vec<&str> {
    item.get("content")
        .and_then(Value::as_array)
        .map(|c| {
            c.iter()
                .filter(|b| {
                    b.get("type")
                        .and_then(Value::as_str)
                        .is_some_and(|t| t.eq_ignore_ascii_case("text"))
                })
                .filter_map(|b| b.get("text").and_then(Value::as_str))
                .collect()
        })
        .unwrap_or_default()
}

/// The command a `CommandExecution` ran: the script of `<shell> -lc
/// <script>`, else the argv joined.
fn command_text(item: &Value) -> String {
    let argv: Vec<&str> = item
        .get("command")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(Value::as_str).collect())
        .unwrap_or_default();
    match argv.as_slice() {
        [_, flag, script] if matches!(*flag, "-lc" | "-c") => script.to_string(),
        _ => argv.join(" "),
    }
}

/// The item's completion time, else the record's timestamp, else 0.
fn created_at_ms(v: &Value, payload: &Value) -> i64 {
    payload
        .get("completed_at_ms")
        .and_then(Value::as_i64)
        .or_else(|| {
            v.get("timestamp")
                .and_then(Value::as_str)
                .and_then(parse_rfc3339_ms)
        })
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::adapter::LogItem as L;

    pub(crate) const ROLLOUT_A: &str =
        include_str!("../../../designs/fixtures/codex-hooks/rollout-session-A.jsonl");
    pub(crate) const ROLLOUT_B: &str = include_str!(
        "../../../designs/fixtures/codex-hooks/rollout-session-B-new-and-compact.jsonl"
    );

    fn reader_with(content: &str) -> (tempfile::TempDir, RolloutReader) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("r.jsonl");
        std::fs::write(&p, content).unwrap();
        (dir, RolloutReader::new(p))
    }

    /// The fixture's line with `ordinal` `n`.
    fn line(src: &str, n: u64) -> String {
        src.lines()
            .find(|l| serde_json::from_str::<Value>(l).unwrap()["ordinal"] == n)
            .unwrap()
            .to_string()
            + "\n"
    }

    fn turns(items: &[LogItem]) -> Vec<(String, &'static str)> {
        items
            .iter()
            .filter_map(|i| match i {
                L::TurnStarted { turn_id } => Some((turn_id.clone(), "start")),
                L::TurnEnded {
                    turn_id,
                    outcome: Outcome::Done,
                } => Some((turn_id.clone(), "done")),
                L::TurnEnded {
                    turn_id,
                    outcome: Outcome::Interrupted,
                } => Some((turn_id.clone(), "interrupted")),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn session_a_maps_prompts_answers_tools_and_turns() {
        let (_d, mut r) = reader_with(ROLLOUT_A);
        let items = r.poll();
        assert!(
            !items.iter().any(|i| matches!(i, L::Problem { .. })),
            "{items:?}"
        );
        let expect: Vec<(String, &str)> = [
            ("<turn-1>", "start"),
            ("<turn-1>", "done"),
            ("<turn-2>", "start"),
            ("<turn-2>", "done"),
            ("<turn-3>", "start"),
            ("<turn-3>", "done"),
            ("<turn-4>", "start"),
            ("<turn-4>", "interrupted"),
            ("<turn-5>", "start"),
            ("<turn-5>", "interrupted"),
            ("<turn-6>", "start"),
            ("<turn-6>", "done"),
        ]
        .iter()
        .map(|(t, k)| (t.to_string(), *k))
        .collect();
        assert_eq!(turns(&items), expect);

        let users: Vec<(&str, &str, &str)> = items
            .iter()
            .filter_map(|i| match i {
                L::UserMessage {
                    id, turn_id, text, ..
                } => Some((id.as_str(), turn_id.as_str(), text.as_str())),
                _ => None,
            })
            .collect();
        assert_eq!(users.len(), 6, "{users:?}");
        assert_eq!(
            users[0],
            ("<id-2>", "<turn-1>", "Reply with exactly the word: pong")
        );
        // the bracketed two-line paste keeps its newline
        assert_eq!(
            users[4].2,
            "Two lines follow.\nRun the shell command: touch two.txt . Do nothing else."
        );
        // never the <environment_context> user message
        assert!(!users.iter().any(|u| u.2.contains("environment_context")));

        let parts: Vec<(&str, &Part, &str)> = items
            .iter()
            .filter_map(|i| match i {
                L::AssistantPart {
                    message_id,
                    part,
                    turn_id,
                    ..
                } => Some((message_id.as_str(), part, turn_id.as_str())),
                _ => None,
            })
            .collect();
        let ids: Vec<&str> = parts.iter().map(|p| p.0).collect();
        // <msg-8> is an empty final answer: skipped; no reasoning (<rs-1>)
        assert_eq!(
            ids,
            [
                "<msg-6>", "<exec-1>", "<msg-10>", "<exec-3>", "<msg-11>", "<msg-17>"
            ]
        );
        assert_eq!(
            parts[0].1,
            &Part::Text {
                id: "<msg-6>".into(),
                markdown: "pong".into()
            }
        );
        assert_eq!(parts[0].2, "<turn-1>");
        assert_eq!(
            parts[1].1,
            &Part::Tool {
                id: "<exec-1>".into(),
                name: "Bash".into(),
                summary: "touch made.txt".into()
            }
        );
        assert!(matches!(parts[3].1, Part::Tool { summary, .. } if summary == "cat notes.txt"));
        // the commentary (mid-turn update) is a message too
        assert!(
            matches!(parts[2].1, Part::Text { markdown, .. } if markdown.starts_with("I\u{2019}ll read notes.txt"))
        );
        // times from the item's completion
        assert!(matches!(&items[1], L::UserMessage { created_at_ms, .. }
            if *created_at_ms == 1_792_215_172_019));
    }

    #[test]
    fn manual_compaction_is_a_turn_without_messages() {
        let (_d, mut r) = reader_with(ROLLOUT_B);
        let items = r.poll();
        assert!(
            !items.iter().any(|i| matches!(i, L::Problem { .. })),
            "{items:?}"
        );
        let expect: Vec<(String, &str)> = vec![
            ("<turn-7>".into(), "start"),
            ("<turn-7>".into(), "done"),
            ("<turn-8>".into(), "start"),
            ("<turn-8>".into(), "done"),
        ];
        assert_eq!(turns(&items), expect);
        // the summary (a response_item assistant message) is never chat
        let after: Vec<&LogItem> = items
            .iter()
            .skip_while(|i| !matches!(i, L::TurnStarted { turn_id } if turn_id == "<turn-8>"))
            .collect();
        assert_eq!(after.len(), 2, "{after:?}");
        assert!(!format!("{items:?}").contains("Current Prog"));
    }

    #[test]
    fn compaction_inside_a_user_turn_keeps_the_turn() {
        // session B's compaction task, spliced into turn 7 before its answer
        let mut s = String::new();
        for n in [1, 9] {
            s += &line(ROLLOUT_B, n);
        }
        for n in [15, 17, 20, 25, 26] {
            s += &line(ROLLOUT_B, n);
        }
        for n in [10, 14] {
            s += &line(ROLLOUT_B, n);
        }
        let (_d, mut r) = reader_with(&s);
        let items = r.poll();
        let expect: Vec<(String, &str)> =
            vec![("<turn-7>".into(), "start"), ("<turn-7>".into(), "done")];
        assert_eq!(turns(&items), expect, "{items:?}");
        assert!(
            matches!(items.last(), Some(L::TurnEnded { turn_id, .. }) if turn_id == "<turn-7>")
        );
        assert!(items.iter().any(|i| matches!(i, L::AssistantPart { .. })));
    }

    #[test]
    fn a_user_turn_after_a_turn_that_never_ended_starts_anew() {
        // turn 1 started, its end lost (crash); turn 2 is still a turn
        let mut s = line(ROLLOUT_A, 1);
        s += &line(ROLLOUT_A, 16);
        s += &line(ROLLOUT_A, 29);
        let (_d, mut r) = reader_with(&s);
        let expect: Vec<(String, &str)> = vec![
            ("<turn-1>".into(), "start"),
            ("<turn-2>".into(), "start"),
            ("<turn-2>".into(), "done"),
        ];
        assert_eq!(turns(&r.poll()), expect);
    }

    #[test]
    fn unknown_records_and_items_are_skipped() {
        let renamed =
            line(ROLLOUT_A, 9).replace("\"type\": \"UserMessage\"", "\"type\": \"FutureItem\"");
        let new_kind = line(ROLLOUT_A, 14).replace("\"task_complete\"", "\"task_paused\"");
        let new_record = line(ROLLOUT_A, 6).replace("\"world_state\"", "\"new_state\"");
        let (_d, mut r) = reader_with(&(renamed + &new_kind + &new_record));
        assert!(r.poll().is_empty());
    }

    #[test]
    fn missing_ids_are_a_format_change() {
        for (n, from, to) in [
            (9, "\"id\": \"<id-2>\"", "\"uid\": \"<id-2>\""),
            (10, "\"turn_id\": \"<turn-1>\"", "\"turn\": \"<turn-1>\""),
            (14, "\"turn_id\": \"<turn-1>\"", "\"turn\": \"<turn-1>\""),
            (1, "\"type\": \"event_msg\"", "\"kind\": \"event_msg\""),
            (9, "\"type\": \"UserMessage\"", "\"kind\": \"UserMessage\""),
        ] {
            let bad = line(ROLLOUT_A, n).replacen(from, to, if n == 14 { 2 } else { 1 });
            assert_ne!(bad, line(ROLLOUT_A, n), "{n} {from}");
            let (_d, mut r) = reader_with(&bad);
            let items = r.poll();
            assert!(
                matches!(&items[..], [L::Problem { fatal: true, .. }]),
                "{n} {from}: {items:?}"
            );
        }
    }

    #[test]
    fn garbage_line_is_a_problem_not_a_stop() {
        let s = format!("not json\nalso bad\n{}", line(ROLLOUT_A, 9));
        let (_d, mut r) = reader_with(&s);
        let items = r.poll();
        assert_eq!(items.len(), 2);
        assert!(matches!(&items[0], L::Problem { fatal: false, .. }));
        assert!(matches!(&items[1], L::UserMessage { .. }));
    }

    #[test]
    fn partial_lines_wait_and_rereads_are_deduplicated() {
        let l = line(ROLLOUT_A, 10);
        let (half, rest) = l.split_at(l.len() / 2);
        let (_d, mut r) = reader_with(half);
        assert!(r.poll().is_empty());
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(r.path())
            .unwrap();
        std::io::Write::write_all(&mut f, rest.as_bytes()).unwrap();
        drop(f);
        assert_eq!(r.poll().len(), 1);
        assert!(r.poll().is_empty());
        r.reread_from_start();
        assert!(r.poll().is_empty());
        // a missing file is retried
        let mut later = RolloutReader::new(_d.path().join("later.jsonl"));
        assert!(later.poll().is_empty());
        std::fs::write(later.path(), line(ROLLOUT_A, 9)).unwrap();
        assert_eq!(later.poll().len(), 1);
    }

    #[test]
    fn seen_set_is_bounded() {
        let (_d, mut r) = reader_with(ROLLOUT_A);
        r.seen_cap = 3;
        assert!(!r.poll().is_empty());
        assert_eq!(r.seen.len(), 3);
    }
}

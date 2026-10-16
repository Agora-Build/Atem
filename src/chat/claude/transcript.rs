//! Incremental reader for Claude Code's session transcript (JSONL).

use std::collections::{HashSet, VecDeque};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::chat::adapter::{LogItem, Outcome, Part, ToolResultKind};

const SEEN_CAP: usize = 10_000;
/// Text of the user entry Claude writes when the user interrupts a turn.
const INTERRUPT_MARKER: &str = "[Request interrupted by user";
/// What Claude's tool result says when the user refused a tool call at its
/// permission dialog.
const REJECTED: [&str; 2] = [
    "doesn't want to proceed with this tool use",
    "tool use was rejected",
];
/// Tool calls remembered for their results (oldest dropped beyond this).
const TOOL_USES_CAP: usize = 512;
/// A tool input larger than this (as JSON) is not remembered.
const TOOL_INPUT_CAP: usize = 256 * 1024;
/// Text kept of an error result.
const RESULT_TEXT_CAP: usize = 2048;

pub struct TranscriptReader {
    path: PathBuf,
    offset: u64,
    pending: Vec<u8>,
    seen: HashSet<String>,
    seen_order: VecDeque<String>,
    turn_id: String,
    seen_cap: usize,
    /// tool_use id → (name, input as compact JSON), for error results.
    tool_uses: VecDeque<(String, String, String)>,
}

impl TranscriptReader {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            offset: 0,
            pending: Vec::new(),
            seen: HashSet::new(),
            seen_order: VecDeque::new(),
            turn_id: String::new(),
            seen_cap: SEEN_CAP,
            tool_uses: VecDeque::new(),
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

        let mut garbage = false;
        let Some(last_nl) = self.pending.iter().rposition(|b| *b == b'\n') else {
            return out;
        };
        let rest = self.pending.split_off(last_nl + 1);
        let complete = std::mem::replace(&mut self.pending, rest);
        for line in complete[..last_nl].split(|b| *b == b'\n') {
            if line.iter().all(|b| b.is_ascii_whitespace()) {
                continue;
            }
            match serde_json::from_slice::<Value>(line) {
                Ok(v) => self.map_entry(&v, &mut out),
                Err(_) => {
                    if !garbage {
                        garbage = true;
                        out.push(LogItem::Problem {
                            detail: "transcript line is not valid JSON".into(),
                            fatal: false,
                        });
                    }
                }
            }
        }
        out
    }

    fn remember(&mut self, uuid: &str) -> bool {
        if self.seen.contains(uuid) {
            return false;
        }
        self.seen.insert(uuid.to_string());
        self.seen_order.push_back(uuid.to_string());
        if self.seen_order.len() > self.seen_cap
            && let Some(old) = self.seen_order.pop_front()
        {
            self.seen.remove(&old);
        }
        true
    }

    fn map_entry(&mut self, v: &Value, out: &mut Vec<LogItem>) {
        let kind = v.get("type").and_then(Value::as_str).unwrap_or("");
        if kind != "user" && kind != "assistant" {
            return;
        }
        let Some(uuid) = v.get("uuid").and_then(Value::as_str) else {
            out.push(LogItem::Problem {
                detail: format!("{kind} transcript entry has no uuid"),
                fatal: true,
            });
            return;
        };
        if v.get("isSidechain").and_then(Value::as_bool) == Some(true)
            || v.get("isMeta").and_then(Value::as_bool) == Some(true)
        {
            return;
        }
        let ts = created_at_ms(v);
        let prompt_id = v.get("promptId").and_then(Value::as_str);

        if kind == "user" {
            let content = v.pointer("/message/content");
            let text = match content {
                Some(Value::String(s)) => Some(s.clone()),
                Some(Value::Array(blocks)) => {
                    let texts: Vec<&str> = blocks
                        .iter()
                        .filter(|b| b.get("type").and_then(Value::as_str) == Some("text"))
                        .filter_map(|b| b.get("text").and_then(Value::as_str))
                        .collect();
                    if texts.is_empty() {
                        None
                    } else {
                        Some(texts.join("\n"))
                    }
                }
                _ => None,
            };
            let Some(text) = text else {
                // tool_result only (or unknown): no message
                if !self.remember(uuid) {
                    return;
                }
                self.tool_results(content, ts, out);
                if let Some(p) = prompt_id {
                    self.turn_id = p.to_string();
                }
                return;
            };
            if text.starts_with("<command-") || text.starts_with("<local-command-") {
                return;
            }
            if !self.remember(uuid) {
                return;
            }
            self.tool_results(content, ts, out);
            // Esc during a reply, or deny/Esc at a permission prompt ("… for tool
            // use"); interruptedMessageId is present only in the first case.
            if text.starts_with(INTERRUPT_MARKER) {
                let turn_id = prompt_id
                    .map(str::to_string)
                    .unwrap_or_else(|| self.turn_id.clone());
                out.push(LogItem::TurnEnded {
                    turn_id,
                    outcome: Outcome::Interrupted,
                });
                return;
            }
            self.turn_id = prompt_id.unwrap_or(uuid).to_string();
            out.push(LogItem::UserMessage {
                id: uuid.to_string(),
                turn_id: self.turn_id.clone(),
                text,
                created_at_ms: ts,
            });
            return;
        }

        // assistant
        let Some(message_id) = v.pointer("/message/id").and_then(Value::as_str) else {
            out.push(LogItem::Problem {
                detail: "assistant transcript entry has no message.id".into(),
                fatal: true,
            });
            return;
        };
        if !self.remember(uuid) {
            return;
        }
        let blocks: &[Value] = v
            .pointer("/message/content")
            .and_then(Value::as_array)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        let multi = blocks.len() > 1;
        for (i, b) in blocks.iter().enumerate() {
            let id = if multi {
                format!("{uuid}:{i}")
            } else {
                uuid.to_string()
            };
            let part = match b.get("type").and_then(Value::as_str) {
                Some("text") => Part::Text {
                    id,
                    markdown: b
                        .get("text")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string(),
                },
                Some("tool_use") => {
                    let name = b
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_string();
                    self.remember_tool_use(b, &name);
                    let summary = summarize_tool(&name, b.get("input").unwrap_or(&Value::Null));
                    Part::Tool { id, name, summary }
                }
                _ => continue,
            };
            out.push(LogItem::AssistantPart {
                message_id: message_id.to_string(),
                part,
                turn_id: self.turn_id.clone(),
                created_at_ms: ts,
            });
        }
        if v.pointer("/message/stop_reason").and_then(Value::as_str) == Some("end_turn") {
            out.push(LogItem::TurnEnded {
                turn_id: self.turn_id.clone(),
                outcome: Outcome::Done,
            });
        }
    }
}

impl TranscriptReader {
    fn remember_tool_use(&mut self, block: &Value, name: &str) {
        let Some(id) = block.get("id").and_then(Value::as_str) else {
            return;
        };
        // serde_json's map keeps keys sorted: compact output is canonical.
        let input = block.get("input").map(Value::to_string).unwrap_or_default();
        if input.len() > TOOL_INPUT_CAP {
            return;
        }
        if self.tool_uses.len() >= TOOL_USES_CAP {
            self.tool_uses.pop_front();
        }
        self.tool_uses
            .push_back((id.to_string(), name.to_string(), input));
    }

    /// Error `tool_result`s of remembered tool calls → `ToolResult`.
    fn tool_results(&mut self, content: Option<&Value>, ts: i64, out: &mut Vec<LogItem>) {
        let Some(Value::Array(blocks)) = content else {
            return;
        };
        for b in blocks {
            if b.get("type").and_then(Value::as_str) != Some("tool_result")
                || b.get("is_error").and_then(Value::as_bool) != Some(true)
            {
                continue;
            }
            let Some(id) = b.get("tool_use_id").and_then(Value::as_str) else {
                continue;
            };
            let Some(pos) = self.tool_uses.iter().position(|(t, _, _)| t == id) else {
                continue;
            };
            let (_, tool_name, input) = self.tool_uses.remove(pos).unwrap();
            let text = match b.get("content") {
                Some(Value::String(s)) => s.clone(),
                Some(Value::Array(parts)) => parts
                    .iter()
                    .filter_map(|p| p.get("text").and_then(Value::as_str))
                    .collect::<Vec<_>>()
                    .join("\n"),
                _ => String::new(),
            };
            let kind = if REJECTED.iter().any(|r| text.contains(r)) {
                ToolResultKind::Rejected
            } else {
                ToolResultKind::Failed
            };
            out.push(LogItem::ToolResult {
                tool_name,
                input,
                kind,
                text: truncate(&text, RESULT_TEXT_CAP),
                at_ms: ts,
            });
        }
    }
}

fn created_at_ms(v: &Value) -> i64 {
    v.get("timestamp")
        .and_then(Value::as_str)
        .and_then(parse_rfc3339_ms)
        .unwrap_or(0)
}

/// Minimal RFC 3339 parser (`YYYY-MM-DDTHH:MM:SS[.fff](Z|±HH:MM)`) to unix ms.
fn parse_rfc3339_ms(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 20 || b[4] != b'-' || b[7] != b'-' || !(b[10] == b'T' || b[10] == b't') {
        return None;
    }
    if b[13] != b':' || b[16] != b':' {
        return None;
    }
    let num = |r: std::ops::Range<usize>| -> Option<i64> {
        let d = b.get(r)?;
        if d.is_empty() || !d.iter().all(u8::is_ascii_digit) {
            return None;
        }
        d.iter()
            .try_fold(0i64, |a, c| Some(a * 10 + i64::from(c - b'0')))
    };
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    let leap = (y % 4 == 0 && y % 100 != 0) || y % 400 == 0;
    let dim = match mo {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => 28 + i64::from(leap),
        _ => return None,
    };
    if !(1..=dim).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut i = 19;
    let mut ms = 0i64;
    if b[i] == b'.' {
        i += 1;
        let start = i;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        let frac = &b[start..i];
        if frac.is_empty() {
            return None;
        }
        for k in 0..3 {
            ms = ms * 10 + i64::from(frac.get(k).map_or(0, |c| c - b'0'));
        }
    }
    let offset_min = match b.get(i..)? {
        b"Z" | b"z" => 0,
        t if t.len() == 6 && (t[0] == b'+' || t[0] == b'-') && t[3] == b':' => {
            let hh = num(i + 1..i + 3)?;
            let mm = num(i + 4..i + 6)?;
            let v = hh * 60 + mm;
            if t[0] == b'-' { -v } else { v }
        }
        _ => return None,
    };
    // days from civil (Howard Hinnant)
    let yy = if mo <= 2 { y - 1 } else { y };
    let era = yy.div_euclid(400);
    let yoe = yy - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(((days * 86_400 + h * 3600 + mi * 60 + sec - offset_min * 60) * 1000) + ms)
}

/// One-line, bounded description of a tool call (≤120 chars).
pub fn summarize_tool(name: &str, input: &Value) -> String {
    let s = |k: &str| input.get(k).and_then(Value::as_str);
    let raw = match name {
        "Bash" => s("command").map(|c| c.lines().next().unwrap_or("")),
        "Read" | "Write" | "Edit" | "MultiEdit" | "NotebookEdit" => {
            s("file_path").or_else(|| s("notebook_path"))
        }
        "Glob" | "Grep" => s("pattern"),
        "WebFetch" => s("url"),
        "WebSearch" => s("query"),
        _ => None,
    }
    .unwrap_or("");
    truncate(raw, 120)
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut t: String = s.chars().take(max - 1).collect();
    t.push('…');
    t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::adapter::LogItem as L;
    use std::io::Write;

    const BASIC: &str = include_str!("../../../tests/fixtures/chat/claude/session-basic.jsonl");

    fn reader_with(content: &str) -> (tempfile::TempDir, TranscriptReader) {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.jsonl");
        std::fs::write(&p, content).unwrap();
        (dir, TranscriptReader::new(p))
    }

    fn user_line(uuid: &str, extra: &str, content: &str) -> String {
        format!(
            r#"{{"type":"user","uuid":"{uuid}","timestamp":"2026-10-15T01:02:03.456Z",{extra}"message":{{"role":"user","content":{content}}}}}"#
        ) + "\n"
    }

    #[test]
    fn basic_session_yields_user_messages_parts_and_turn_end() {
        let (_d, mut r) = reader_with(BASIC);
        let items = r.poll();
        assert!(
            !items.iter().any(|i| matches!(i, L::Problem { .. })),
            "{items:?}"
        );
        let L::UserMessage {
            text,
            turn_id,
            created_at_ms,
            ..
        } = &items[0]
        else {
            panic!("first item: {:?}", items[0]);
        };
        assert!(text.starts_with("run `echo hi`"));
        assert_eq!(turn_id, "fa1cc4a0-50ce-4785-aab5-0355d2a806db");
        assert!(*created_at_ms > 1_700_000_000_000);
        let first_end = items
            .iter()
            .position(|i| {
                matches!(
                    i,
                    L::TurnEnded {
                        outcome: Outcome::Done,
                        ..
                    }
                )
            })
            .unwrap();
        let first = &items[..first_end];
        assert!(first.iter().any(|i| matches!(i, L::AssistantPart {
            part: Part::Tool { name, summary, .. }, turn_id, ..
        } if name == "Bash" && summary == "echo hi" && turn_id == "fa1cc4a0-50ce-4785-aab5-0355d2a806db")));
        assert!(first.iter().any(|i| matches!(
            i,
            L::AssistantPart {
                part: Part::Text { .. },
                ..
            }
        )));
        let L::TurnEnded { turn_id, .. } = &items[first_end] else {
            unreachable!()
        };
        assert_eq!(turn_id, "fa1cc4a0-50ce-4785-aab5-0355d2a806db");
        // user messages: three prompts, none from tool results
        let users = items
            .iter()
            .filter(|i| matches!(i, L::UserMessage { .. }))
            .count();
        assert_eq!(users, 3);
        // no thinking
        assert!(!format!("{items:?}").contains("thinking"));
    }

    #[test]
    fn interrupt_entry_ends_the_turn_as_interrupted() {
        let (_d, mut r) = reader_with(BASIC);
        let items = r.poll();
        let last = items.last().unwrap();
        assert_eq!(
            last,
            &L::TurnEnded {
                turn_id: "64707c1e-bb7f-4bb8-9065-1514059dcb0d".into(),
                outcome: Outcome::Interrupted
            }
        );
        // the aborted partial text still produced a part
        assert!(matches!(
            &items[items.len() - 2],
            L::AssistantPart {
                part: Part::Text { .. },
                ..
            }
        ));
        assert!(!items.iter().any(|i| matches!(i,
            L::UserMessage { text, .. } if text.contains("Request interrupted"))));
    }

    #[test]
    fn interrupt_marker_without_message_id_ends_the_turn() {
        // "… for tool use" (deny/Esc at a permission prompt), as a string and as an
        // array, with no interruptedMessageId.
        let mut s = user_line("u1", r#""promptId":"p1","#, r#""run it""#);
        s += &user_line(
            "u2",
            r#""promptId":"p1","#,
            r#""[Request interrupted by user for tool use]""#,
        );
        s += &user_line("u3", r#""promptId":"p3","#, r#""again""#);
        s += &user_line(
            "u4",
            r#""promptId":"p3","#,
            r#"[{"type":"text","text":"[Request interrupted by user]"}]"#,
        );
        let (_d, mut r) = reader_with(&s);
        let items = r.poll();
        assert_eq!(items.len(), 4, "{items:?}");
        assert_eq!(
            items[1],
            L::TurnEnded {
                turn_id: "p1".into(),
                outcome: Outcome::Interrupted
            }
        );
        assert_eq!(
            items[3],
            L::TurnEnded {
                turn_id: "p3".into(),
                outcome: Outcome::Interrupted
            }
        );
    }

    #[test]
    fn meta_sidechain_and_command_entries_are_skipped() {
        let mut s = String::new();
        s += &user_line("u1", r#""isMeta":true,"#, r#""<local-command-caveat>x""#);
        s += &user_line("u2", r#""isSidechain":true,"#, r#""side""#);
        s += &user_line("u3", "", r#""<command-name>/clear</command-name>""#);
        s += &user_line("u4", "", r#""<local-command-stdout>ok""#);
        s += &user_line("u5", r#""promptId":"p5","#, r#""real""#);
        s += "{\"type\":\"attachment\",\"attachment\":{}}\n{\"type\":\"system\"}\n";
        let (_d, mut r) = reader_with(&s);
        let items = r.poll();
        assert_eq!(items.len(), 1, "{items:?}");
        assert!(matches!(&items[0], L::UserMessage { id, turn_id, text, .. }
            if id == "u5" && turn_id == "p5" && text == "real"));
    }

    #[test]
    fn array_content_prompt_is_a_user_message() {
        let l = user_line(
            "u1",
            "",
            r#"[{"type":"text","text":"hello"},{"type":"text","text":"world"}]"#,
        );
        let (_d, mut r) = reader_with(&l);
        let items = r.poll();
        assert!(matches!(&items[0], L::UserMessage { turn_id, text, .. }
            if turn_id == "u1" && text == "hello\nworld"));
    }

    #[test]
    fn partial_last_line_waits_for_the_rest() {
        let l = user_line("u1", r#""promptId":"p","#, r#""hi""#);
        let (half, rest) = l.split_at(l.len() / 2);
        let (_d, mut r) = reader_with(half);
        assert!(r.poll().is_empty());
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(r.path())
            .unwrap();
        f.write_all(rest.as_bytes()).unwrap();
        drop(f);
        let items = r.poll();
        assert_eq!(items.len(), 1);
        assert!(r.poll().is_empty());
    }

    #[test]
    fn lines_are_processed_once_even_if_reread() {
        let (_d, mut r) = reader_with(BASIC);
        assert!(!r.poll().is_empty());
        r.reread_from_start();
        assert!(r.poll().is_empty());
    }

    #[test]
    fn missing_file_is_retried() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("later.jsonl");
        let mut r = TranscriptReader::new(p.clone());
        assert!(r.poll().is_empty());
        std::fs::write(&p, user_line("u1", "", r#""hi""#)).unwrap();
        assert_eq!(r.poll().len(), 1);
    }

    #[test]
    fn garbage_line_is_a_problem_not_a_stop() {
        let s = format!("not json\nalso bad\n{}", user_line("u1", "", r#""hi""#));
        let (_d, mut r) = reader_with(&s);
        let items = r.poll();
        assert_eq!(items.len(), 2);
        assert!(matches!(&items[0], L::Problem { fatal: false, .. }));
        assert!(matches!(&items[1], L::UserMessage { .. }));
    }

    #[test]
    fn assistant_without_message_id_is_fatal() {
        let s =
            r#"{"type":"assistant","uuid":"a1","message":{"content":[{"type":"text","text":"x"}]}}"#
                .to_string()
                + "\n"
                + r#"{"type":"user","message":{"content":"x"}}"# + "\n";
        let (_d, mut r) = reader_with(&s);
        let items = r.poll();
        assert_eq!(items.len(), 2);
        assert!(
            items
                .iter()
                .all(|i| matches!(i, L::Problem { fatal: true, .. }))
        );
    }

    #[test]
    fn multi_block_lines_get_indexed_part_ids() {
        let s = r#"{"type":"assistant","uuid":"a1","message":{"id":"m1","stop_reason":"end_turn","content":[{"type":"thinking","thinking":"x"},{"type":"text","text":"a"},{"type":"tool_use","id":"t","name":"Glob","input":{"pattern":"*.rs"}}]}}"#
            .to_string()
            + "\n";
        let (_d, mut r) = reader_with(&s);
        let items = r.poll();
        assert_eq!(items.len(), 3);
        let ids: Vec<&str> = items
            .iter()
            .filter_map(|i| {
                if let L::AssistantPart { part, .. } = i {
                    Some(part.id())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(ids, ["a1:1", "a1:2"]);
        assert!(matches!(
            items[2],
            L::TurnEnded {
                outcome: Outcome::Done,
                ..
            }
        ));
    }

    #[test]
    fn refused_and_failed_tool_calls_are_tool_results() {
        let text = std::fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/chat/claude/session-rejected-tool.jsonl"),
        )
        .unwrap();
        let (_d, mut r) = reader_with(&text);
        let results: Vec<LogItem> = r
            .poll()
            .into_iter()
            .filter(|i| matches!(i, LogItem::ToolResult { .. }))
            .collect();
        let input = r#"{"command":"rm -rf build","description":"Remove the build directory"}"#;
        assert_eq!(results.len(), 2, "{results:?}");
        match &results[0] {
            LogItem::ToolResult {
                tool_name,
                input: i,
                kind,
                at_ms,
                ..
            } => {
                assert_eq!(tool_name, "Bash");
                assert_eq!(i, input, "compact, keys sorted");
                assert_eq!(*kind, ToolResultKind::Rejected);
                assert_eq!(
                    *at_ms,
                    parse_rfc3339_ms("2026-10-16T10:00:05.000Z").unwrap()
                );
            }
            other => panic!("{other:?}"),
        }
        match &results[1] {
            LogItem::ToolResult {
                input: i,
                kind,
                text,
                ..
            } => {
                assert_eq!(i, input, "the same input in another key order");
                assert_eq!(*kind, ToolResultKind::Failed);
                assert!(text.contains("Denied from Astation"));
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn timestamp_parsing() {
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:01.5Z"), Some(1500));
        assert_eq!(
            parse_rfc3339_ms("2026-10-15T01:00:00+01:00"),
            parse_rfc3339_ms("2026-10-15T00:00:00Z")
        );
        assert_eq!(parse_rfc3339_ms("garbage"), None);
    }

    #[test]
    fn tool_summaries_are_short_and_safe() {
        use serde_json::json;
        assert_eq!(
            summarize_tool("Bash", &json!({"command":"echo hi\nrm x"})),
            "echo hi"
        );
        let long = summarize_tool("Bash", &json!({"command":"é".repeat(200)}));
        assert_eq!(long.chars().count(), 120);
        assert!(long.ends_with('…'));
        assert_eq!(summarize_tool("Read", &json!({"file_path":"/a/b"})), "/a/b");
        assert_eq!(
            summarize_tool("NotebookEdit", &json!({"notebook_path":"/n"})),
            "/n"
        );
        assert_eq!(summarize_tool("Grep", &json!({"pattern":"foo"})), "foo");
        assert_eq!(
            summarize_tool("WebFetch", &json!({"url":"http://x"})),
            "http://x"
        );
        assert_eq!(summarize_tool("WebSearch", &json!({"query":"q"})), "q");
        assert_eq!(summarize_tool("Task", &json!({"prompt":"p"})), "");
        assert_eq!(summarize_tool("Bash", &json!({})), "");
    }

    #[test]
    fn multibyte_line_split_mid_codepoint() {
        let l = user_line("u1", r#""promptId":"p","#, r#""café 😀 ok""#);
        let pos = l.find('😀').unwrap() + 2; // inside the emoji
        let (a, b) = l.as_bytes().split_at(pos);
        let (_d, mut r) = reader_with("");
        std::fs::write(r.path(), a).unwrap();
        assert!(r.poll().is_empty());
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(r.path())
            .unwrap();
        f.write_all(b).unwrap();
        drop(f);
        let items = r.poll();
        assert!(
            matches!(&items[0], L::UserMessage { text, .. } if text == "café 😀 ok"),
            "{items:?}"
        );
    }

    #[test]
    fn seen_set_is_bounded() {
        let mut s = String::new();
        for i in 0..5 {
            s += &user_line(&format!("u{i}"), "", r#""x""#);
        }
        let (_d, mut r) = reader_with(&s);
        r.seen_cap = 2;
        assert_eq!(r.poll().len(), 5);
        assert_eq!(r.seen.len(), 2);
        assert!(r.seen.contains("u4") && r.seen.contains("u3"));
        r.reread_from_start();
        // evicted ids are accepted again (the set stays bounded)
        let again = r.poll();
        assert!(matches!(&again[0], L::UserMessage { id, .. } if id == "u0"));
        assert!(r.seen.len() <= 2);
    }

    #[test]
    fn tool_result_prompt_id_sets_turn_for_following_parts() {
        let mut s = user_line(
            "t1",
            r#""promptId":"pX","#,
            r#"[{"type":"tool_result","tool_use_id":"x","content":"ok"}]"#,
        );
        s += r#"{"type":"assistant","uuid":"a1","message":{"id":"m1","content":[{"type":"text","text":"hi"}]}}"#;
        s += "\n";
        let (_d, mut r) = reader_with(&s);
        let items = r.poll();
        assert_eq!(items.len(), 1);
        assert!(matches!(&items[0], L::AssistantPart { turn_id, .. } if turn_id == "pX"));
    }

    #[test]
    fn truncated_file_resets_offset() {
        let (_d, mut r) = reader_with(&user_line("u1", "", r#""hello there long""#));
        assert_eq!(r.poll().len(), 1);
        std::fs::write(r.path(), user_line("u2", "", r#""x""#)).unwrap();
        let items = r.poll();
        assert_eq!(items.len(), 1);
        assert!(matches!(&items[0], L::UserMessage { id, .. } if id == "u2"));
    }

    #[test]
    fn timestamp_edge_cases() {
        assert_eq!(
            parse_rfc3339_ms("2024-02-29T00:00:00Z"),
            Some(1_709_164_800_000)
        );
        assert_eq!(
            parse_rfc3339_ms("2000-03-01T00:00:00Z"),
            Some(951_868_800_000)
        );
        assert_eq!(
            parse_rfc3339_ms("2024-01-01T00:00:00-05:00"),
            parse_rfc3339_ms("2024-01-01T05:00:00Z")
        );
        assert_eq!(parse_rfc3339_ms("1970-01-01T00:00:02Z"), Some(2000));
        assert_eq!(parse_rfc3339_ms("2023-02-29T00:00:00Z"), None);
        assert_eq!(parse_rfc3339_ms("2024-+1-01T00:00:00Z"), None);
        assert_eq!(parse_rfc3339_ms("2024-01-01T00:00:00+é:00"), None);
        assert_eq!(parse_rfc3339_ms("2024-01-01T00:00:00éééé"), None);
    }
}

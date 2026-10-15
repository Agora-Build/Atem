//! Incremental reader for Claude Code's session transcript (JSONL).

use std::collections::{HashSet, VecDeque};
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::chat::adapter::{LogItem, Outcome, Part};

const SEEN_CAP: usize = 10_000;

pub struct TranscriptReader {
    path: PathBuf,
    offset: u64,
    pending: Vec<u8>,
    seen: HashSet<String>,
    seen_order: VecDeque<String>,
    turn_id: String,
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
        while let Some(pos) = self.pending.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=pos).collect();
            let line = &line[..line.len() - 1];
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
        if self.seen_order.len() > SEEN_CAP
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
            if v.get("interruptedMessageId").is_some() {
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
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
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
        let frac = &s[start..i];
        if frac.is_empty() {
            return None;
        }
        let three: String = frac.chars().chain("000".chars()).take(3).collect();
        ms = three.parse().ok()?;
    }
    let offset_min = match s.get(i..)? {
        "Z" | "z" => 0,
        t if t.len() == 6 && (t.starts_with('+') || t.starts_with('-')) && &t[3..4] == ":" => {
            let hh: i64 = t[1..3].parse().ok()?;
            let mm: i64 = t[4..6].parse().ok()?;
            let v = hh * 60 + mm;
            if t.starts_with('-') { -v } else { v }
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
}

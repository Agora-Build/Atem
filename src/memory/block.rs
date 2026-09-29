//! The atem-managed block inside CLAUDE.md / AGENTS.md / CLAUDE.local.md.
//! Text outside the markers is never touched; broken markers are refused.
use anyhow::{anyhow, Result};
use crate::memory::model::{confidence_rank, Memory};
use crate::memory::secrets::find_secrets;

pub const BEGIN_PREFIX: &str = "<!-- atem:memory:begin";
pub const BEGIN: &str = "<!-- atem:memory:begin (managed by atem — edits here are overwritten) -->";
pub const END: &str = "<!-- atem:memory:end -->";
/// Memory content containing this token is rejected (it could forge markers).
pub const RESERVED: &str = "atem:memory:";
pub const MAX_ENTRIES: usize = 50;
pub const MAX_BYTES: usize = 4096;

pub const CREDENTIAL_INSTRUCTION: &str = "Credentials are never stored in memory. When you need one, fetch it with `atem vault get <name>` at the moment you use it. Never paste a credential value into memory, skills, or instruction files.";
pub const CODEX_CAPTURE_INSTRUCTION: &str = "To save a durable fact for future sessions, run `atem memory add --agent codex \"<fact>\"`.";

pub fn contains_reserved(s: &str) -> bool {
    s.contains(RESERVED)
}

#[derive(Debug, PartialEq)]
enum Markers {
    Absent,
    Valid { start: usize, end: usize },
    Broken(&'static str),
}

fn find_markers(doc: &str) -> Markers {
    let begins: Vec<usize> = doc.match_indices(BEGIN_PREFIX).map(|(i, _)| i).collect();
    let ends: Vec<usize> = doc.match_indices(END).map(|(i, _)| i).collect();
    match (begins.len(), ends.len()) {
        (0, 0) => Markers::Absent,
        (1, 1) if begins[0] < ends[0] => Markers::Valid { start: begins[0], end: ends[0] + END.len() },
        (1, 1) => Markers::Broken("the end marker comes before the begin marker"),
        (b, e) if b > 1 || e > 1 => Markers::Broken("duplicate atem markers"),
        _ => Markers::Broken("a begin marker without an end marker (or the reverse)"),
    }
}

/// One memory as one bullet line.
pub fn one_line(content: &str) -> String {
    content.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Live memories, ordered by confidence then newest, capped at
/// MAX_ENTRIES and MAX_BYTES. An entry that doesn't fit is skipped, so one
/// huge memory can't crowd out the rest. Pulled content that could forge
/// markers or carries a credential is never written.
pub fn select_entries(mems: &[Memory]) -> Vec<String> {
    let mut sorted: Vec<&Memory> = mems.iter()
        .filter(|m| !m.deleted && !contains_reserved(&m.content) && find_secrets(&m.content).is_empty())
        .collect();
    sorted.sort_by(|a, b| {
        confidence_rank(&a.confidence).cmp(&confidence_rank(&b.confidence))
            .then(b.created_at.cmp(&a.created_at))
            .then(a.id.cmp(&b.id))
    });
    let mut out = Vec::new();
    let mut bytes = 0usize;
    for m in sorted {
        if out.len() >= MAX_ENTRIES {
            break;
        }
        let line = one_line(&m.content);
        let cost = line.len() + 3; // "- " + "\n"
        if bytes + cost > MAX_BYTES {
            continue;
        }
        bytes += cost;
        out.push(line);
    }
    out
}

pub fn render_block(entries: &[String], instructions: &[&str]) -> String {
    let mut s = String::new();
    s.push_str(BEGIN);
    s.push('\n');
    for e in entries {
        s.push_str("- ");
        s.push_str(e);
        s.push('\n');
    }
    if !instructions.is_empty() {
        if !entries.is_empty() {
            s.push('\n');
        }
        for i in instructions {
            s.push_str(i);
            s.push('\n');
        }
    }
    s.push_str(END);
    s
}

/// Replace the managed block in `doc`, or append it if absent.
pub fn splice(doc: &str, block: &str) -> Result<String> {
    match find_markers(doc) {
        Markers::Valid { start, end } => Ok(format!("{}{}{}", &doc[..start], block, &doc[end..])),
        Markers::Absent => {
            let base = doc.trim_end_matches('\n');
            Ok(if base.is_empty() { format!("{}\n", block) } else { format!("{}\n\n{}\n", base, block) })
        }
        Markers::Broken(why) => Err(anyhow!("refusing to edit: {}", why)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::model::{content_hash, Scope};

    fn mem(content: &str, conf: &str, created: i64) -> Memory {
        Memory {
            id: format!("mem_{}", created), scope: Scope::Global,
            project: String::new(), machine: String::new(),
            content: content.into(), content_hash: content_hash(content),
            confidence: conf.into(), source_agent: "cli".into(), source_machine: "m".into(),
            created_at: created, deleted: false, seq: 0,
        }
    }

    #[test]
    fn splice_into_empty_file() {
        let b = render_block(&["a".into()], &[]);
        assert_eq!(splice("", &b).unwrap(), format!("{}\n", b));
    }

    #[test]
    fn splice_appends_after_user_text() {
        let b = render_block(&[], &[CREDENTIAL_INSTRUCTION]);
        let out = splice("# Mine\n\nkeep me\n", &b).unwrap();
        assert!(out.starts_with("# Mine\n\nkeep me\n\n<!-- atem:memory:begin"));
        assert!(out.ends_with("<!-- atem:memory:end -->\n"));
    }

    #[test]
    fn splice_replaces_only_the_block() {
        let old = render_block(&["old".into()], &[]);
        let doc = format!("before\n{}\nafter\n", old);
        let new = render_block(&["new".into()], &[]);
        assert_eq!(splice(&doc, &new).unwrap(), format!("before\n{}\nafter\n", new));
    }

    #[test]
    fn splice_is_idempotent() {
        let b = render_block(&["x".into()], &[CREDENTIAL_INSTRUCTION]);
        let once = splice("user\n", &b).unwrap();
        assert_eq!(splice(&once, &b).unwrap(), once);
    }

    #[test]
    fn broken_markers_are_refused() {
        assert!(splice(&format!("{}\nno end\n", BEGIN), "b").is_err());
        assert!(splice(&format!("{}\n", END), "b").is_err());
        assert!(splice(&format!("{}\n{}\n{}\n{}\n", BEGIN, END, BEGIN, END), "b").is_err());
        assert!(splice(&format!("{}\n{}\n", END, BEGIN), "b").is_err());
    }

    #[test]
    fn render_block_shape() {
        let b = render_block(&["one".into(), "two".into()], &["instr"]);
        assert_eq!(b, format!("{}\n- one\n- two\n\ninstr\n{}", BEGIN, END));
        assert_eq!(render_block(&[], &["instr"]), format!("{}\ninstr\n{}", BEGIN, END));
    }

    #[test]
    fn select_orders_by_confidence_then_newest() {
        let ms = vec![mem("low old", "low", 1), mem("high old", "high", 2), mem("high new", "high", 3), mem("medium", "medium", 4)];
        assert_eq!(select_entries(&ms), vec!["high new", "high old", "medium", "low old"]);
    }

    #[test]
    fn select_caps_count_and_bytes_and_skips_deleted() {
        let many: Vec<Memory> = (0..60).map(|i| mem(&format!("fact {}", i), "medium", i)).collect();
        assert_eq!(select_entries(&many).len(), MAX_ENTRIES);
        let big = "x".repeat(MAX_BYTES);
        assert_eq!(select_entries(&[mem(&big, "high", 1), mem("small", "low", 2)]), vec!["small"]);
        let mut d = mem("gone", "high", 5);
        d.deleted = true;
        assert!(select_entries(&[d]).is_empty());
    }

    #[test]
    fn select_skips_reserved_and_secret_content() {
        let ms = vec![
            mem("ok fact", "high", 1),
            mem(&format!("sneaky {}", END), "high", 2),
            mem("key sk-proj-abcdef1234567890ABCDEF", "high", 3),
            // Built at runtime so the fixture isn't a literal webhook URL (GitHub push protection).
            mem(&format!("hook https://hooks.slack.com/services/{}/{}/{}", "T00000000", "B00000000", "X".repeat(24)), "high", 4),
        ];
        assert_eq!(select_entries(&ms), vec!["ok fact"]);
    }

    #[test]
    fn multi_line_content_is_flattened() {
        assert_eq!(select_entries(&[mem("a\n\nb  c", "high", 1)]), vec!["a b c"]);
    }

    #[test]
    fn reserved_token_detected() {
        assert!(contains_reserved("x <!-- atem:memory:end -->"));
        assert!(!contains_reserved("atem memory"));
    }
}

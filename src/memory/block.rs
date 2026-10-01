//! The atem-managed block inside CLAUDE.md / AGENTS.md / CLAUDE.local.md.
//! Text outside the markers is never touched; broken markers are refused.
use anyhow::{anyhow, Result};
use crate::memory::model::{confidence_rank, short_id, Memory};
use crate::memory::secrets::find_secrets;

pub const BEGIN_PREFIX: &str = "<!-- atem:memory:begin";
pub const BEGIN: &str = "<!-- atem:memory:begin (managed by atem — edits here are overwritten) -->";
pub const END: &str = "<!-- atem:memory:end -->";
/// Memory content containing this token is rejected (it could forge markers).
pub const RESERVED: &str = "atem:memory:";
pub const MAX_ENTRIES: usize = 50;
pub const MAX_BYTES: usize = 4096;

pub const CREDENTIAL_INSTRUCTION: &str = "Credentials are never stored in memory. Save a credential's name, never its value, and never paste a credential value into memory, skills, or instruction files.";
pub const CODEX_CAPTURE_INSTRUCTION: &str = "To save a durable fact for future sessions, run `atem memory add --agent codex \"<fact>\"`.";
pub const CODEX_REPLACE_INSTRUCTION: &str = "If a saved fact is outdated, run `atem memory replace <id> \"<new fact>\"`.";

/// What goes into one block: the entry lines, and how many valid facts
/// didn't fit (found with `atem memory search`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Selection {
    pub entries: Vec<String>,
    pub omitted: usize,
}

/// The block's last line when facts were left out.
pub fn omitted_line(n: usize) -> String {
    if n == 1 {
        "1 more fact is not shown here. To find it, run `atem memory search \"<query>\"`.".to_string()
    } else {
        format!("{} more facts are not shown here. To find them, run `atem memory search \"<query>\"`.", n)
    }
}

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

/// Valid facts, ordered by confidence then newest, capped at MAX_ENTRIES
/// and MAX_BYTES. An entry that doesn't fit is skipped (and counted in
/// `omitted`), so one huge memory can't crowd out the rest. Pulled content
/// that could forge markers or carries a credential is never written (and
/// not counted). `with_ids` prefixes each entry with `[<short id>] `.
pub fn select_entries(mems: &[Memory], with_ids: bool) -> Selection {
    let mut sorted: Vec<&Memory> = mems.iter()
        .filter(|m| m.is_valid() && !contains_reserved(&m.content) && find_secrets(&m.content).is_empty())
        .collect();
    sorted.sort_by(|a, b| {
        confidence_rank(&a.confidence).cmp(&confidence_rank(&b.confidence))
            .then(b.created_at.cmp(&a.created_at))
            .then(a.id.cmp(&b.id))
    });
    let eligible = sorted.len();
    let mut out = Vec::new();
    let mut bytes = 0usize;
    for m in sorted {
        if out.len() >= MAX_ENTRIES {
            break;
        }
        let text = one_line(&m.content);
        let line = if with_ids { format!("[{}] {}", short_id(&m.id), text) } else { text };
        let cost = line.len() + 3; // "- " + "\n"
        if bytes + cost > MAX_BYTES {
            continue;
        }
        bytes += cost;
        out.push(line);
    }
    Selection { omitted: eligible - out.len(), entries: out }
}

pub fn render_block(sel: &Selection, instructions: &[&str]) -> String {
    let mut s = String::new();
    s.push_str(BEGIN);
    s.push('\n');
    for e in &sel.entries {
        s.push_str("- ");
        s.push_str(e);
        s.push('\n');
    }
    if !instructions.is_empty() {
        if !sel.entries.is_empty() {
            s.push('\n');
        }
        for i in instructions {
            s.push_str(i);
            s.push('\n');
        }
    }
    if sel.omitted > 0 {
        if !sel.entries.is_empty() || !instructions.is_empty() {
            s.push('\n');
        }
        s.push_str(&omitted_line(sel.omitted));
        s.push('\n');
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
            created_at: created, seq: 0, ..Default::default()
        }
    }

    fn sel(entries: &[&str]) -> Selection {
        Selection { entries: entries.iter().map(|s| s.to_string()).collect(), omitted: 0 }
    }

    #[test]
    fn splice_into_empty_file() {
        let b = render_block(&sel(&["a"]), &[]);
        assert_eq!(splice("", &b).unwrap(), format!("{}\n", b));
    }

    #[test]
    fn splice_appends_after_user_text() {
        let b = render_block(&sel(&[]), &[CREDENTIAL_INSTRUCTION]);
        let out = splice("# Mine\n\nkeep me\n", &b).unwrap();
        assert!(out.starts_with("# Mine\n\nkeep me\n\n<!-- atem:memory:begin"));
        assert!(out.ends_with("<!-- atem:memory:end -->\n"));
    }

    #[test]
    fn splice_replaces_only_the_block() {
        let old = render_block(&sel(&["old"]), &[]);
        let doc = format!("before\n{}\nafter\n", old);
        let new = render_block(&sel(&["new"]), &[]);
        assert_eq!(splice(&doc, &new).unwrap(), format!("before\n{}\nafter\n", new));
    }

    #[test]
    fn splice_is_idempotent() {
        let b = render_block(&sel(&["x"]), &[CREDENTIAL_INSTRUCTION]);
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
        let b = render_block(&sel(&["one", "two"]), &["instr"]);
        assert_eq!(b, format!("{}\n- one\n- two\n\ninstr\n{}", BEGIN, END));
        assert_eq!(render_block(&sel(&[]), &["instr"]), format!("{}\ninstr\n{}", BEGIN, END));
    }

    #[test]
    fn select_orders_by_confidence_then_newest() {
        let ms = vec![mem("low old", "low", 1), mem("high old", "high", 2), mem("high new", "high", 3), mem("medium", "medium", 4)];
        assert_eq!(select_entries(&ms, false).entries, vec!["high new", "high old", "medium", "low old"]);
    }

    #[test]
    fn select_caps_count_and_bytes_and_skips_deleted() {
        let many: Vec<Memory> = (0..60).map(|i| mem(&format!("fact {}", i), "medium", i)).collect();
        assert_eq!(select_entries(&many, false).entries.len(), MAX_ENTRIES);
        let big = "x".repeat(MAX_BYTES);
        assert_eq!(select_entries(&[mem(&big, "high", 1), mem("small", "low", 2)], false).entries, vec!["small"]);
        let mut d = mem("gone", "high", 5);
        d.deleted_at = Some(5);
        assert!(select_entries(&[d], false).entries.is_empty());
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
        assert_eq!(select_entries(&ms, false).entries, vec!["ok fact"]);
    }

    #[test]
    fn multi_line_content_is_flattened() {
        assert_eq!(select_entries(&[mem("a\n\nb  c", "high", 1)], false).entries, vec!["a b c"]);
    }

    #[test]
    fn left_out_facts_are_counted_in_the_last_line() {
        let many: Vec<Memory> = (0..53).map(|i| mem(&format!("fact {}", i), "medium", i)).collect();
        let s = select_entries(&many, false);
        assert_eq!((s.entries.len(), s.omitted), (MAX_ENTRIES, 3));
        let b = render_block(&s, &[CREDENTIAL_INSTRUCTION]);
        let last = b.lines().rev().nth(1).unwrap(); // the line before END
        assert_eq!(last, "3 more facts are not shown here. To find them, run `atem memory search \"<query>\"`.");
        assert_eq!(omitted_line(1), "1 more fact is not shown here. To find it, run `atem memory search \"<query>\"`.");
        assert!(!render_block(&select_entries(&many[..2], false), &[]).contains("more fact"));
        // Skipped for the byte cap counts too.
        let big = "x".repeat(MAX_BYTES);
        assert_eq!(select_entries(&[mem(&big, "high", 1), mem("small", "low", 2)], false).omitted, 1);
    }

    #[test]
    fn invalid_facts_are_not_selected_or_counted() {
        let mut old = mem("old port", "high", 1);
        old.invalid_at = Some(2);
        let s = select_entries(&[old, mem("new port", "high", 3)], false);
        assert_eq!((s.entries, s.omitted), (vec!["new port".to_string()], 0));
    }

    #[test]
    fn ids_are_shown_when_asked() {
        let mut m = mem("DialF uses TCP 8765", "high", 1);
        m.id = "mem_1a2b3c4d5e6f".into();
        assert_eq!(select_entries(&[m.clone()], true).entries, vec!["[1a2b3c4d] DialF uses TCP 8765"]);
        assert_eq!(select_entries(&[m], false).entries, vec!["DialF uses TCP 8765"]);
    }

    #[test]
    fn replace_instruction_text() {
        assert_eq!(CODEX_REPLACE_INSTRUCTION, "If a saved fact is outdated, run `atem memory replace <id> \"<new fact>\"`.");
    }

    #[test]
    fn reserved_token_detected() {
        assert!(contains_reserved("x <!-- atem:memory:end -->"));
        assert!(!contains_reserved("atem memory"));
    }
}

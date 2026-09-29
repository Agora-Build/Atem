//! Harvest Claude Code's own saved memories
//! (~/.claude/projects/<encoded repo path>/memory/*.md) so other agents and
//! machines learn them. atem computes the encoded path; it never decodes.
use anyhow::Result;
use std::path::{Path, PathBuf};
use crate::memory::model::{content_hash, Scope};

#[derive(Debug, Clone, PartialEq)]
pub struct Harvested {
    /// "<atem_id>:<absolute file path>" — stable per file per machine.
    pub origin: String,
    pub scope: Scope,
    pub content: String,
    pub hash: String,
}

/// Claude's directory name for a project: every non-alphanumeric → '-'.
pub fn encode_project_dir(abs: &Path) -> String {
    abs.to_string_lossy()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

pub fn claude_memory_dir(home: &Path, repo_root: &Path) -> PathBuf {
    home.join(".claude").join("projects").join(encode_project_dir(repo_root)).join("memory")
}

/// Every origin harvested from `dir` starts with this (note the trailing '/').
pub fn origin_prefix(atem_id: &str, dir: &Path) -> String {
    format!("{}:{}/", atem_id, dir.display())
}

/// Returns (type, body). The type comes from `type:` at the top level or
/// under `metadata:`.
pub fn parse_memory_file(text: &str) -> Option<(String, String)> {
    let rest = text.strip_prefix("---\n").or_else(|| text.strip_prefix("---\r\n"))?;
    let close = rest.find("\n---")?;
    let front = &rest[..close];
    let body = rest[close + 4..].trim();
    let ty = front
        .lines()
        .map(str::trim)
        .find_map(|l| l.strip_prefix("type:"))
        .map(|v| v.trim().trim_matches('"').to_string())?;
    if ty.is_empty() || body.is_empty() {
        return None;
    }
    Some((ty, body.to_string()))
}

pub fn type_to_scope(t: &str) -> Option<Scope> {
    match t {
        "user" | "feedback" => Some(Scope::Global),
        "project" | "reference" => Some(Scope::Project),
        _ => None,
    }
}

pub fn harvest_dir(dir: &Path, atem_id: &str) -> Result<Vec<Harvested>> {
    let mut out = Vec::new();
    let rd = match std::fs::read_dir(dir) {
        Ok(rd) => rd,
        Err(_) => return Ok(out), // no memory dir yet → nothing to harvest
    };
    let mut paths: Vec<PathBuf> = rd.filter_map(|e| e.ok().map(|e| e.path())).collect();
    paths.sort();
    for p in paths {
        let name = p.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default();
        if !name.ends_with(".md") || name == "MEMORY.md" {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&p) else { continue };
        let Some((ty, body)) = parse_memory_file(&text) else { continue };
        let Some(scope) = type_to_scope(&ty) else { continue };
        out.push(Harvested {
            origin: format!("{}:{}", atem_id, p.display()),
            scope,
            hash: content_hash(&body),
            content: body,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_path_like_claude() {
        assert_eq!(
            encode_project_dir(Path::new("/home/u/Dev/Agora.Build/Atem")),
            "-home-u-Dev-Agora-Build-Atem"
        );
    }

    #[test]
    fn parses_metadata_type() {
        let t = "---\nname: x\ndescription: d\nmetadata:\n  type: feedback\n---\n\nDon't auto-commit.\n**Why:** asked\n";
        assert_eq!(
            parse_memory_file(t),
            Some(("feedback".into(), "Don't auto-commit.\n**Why:** asked".into()))
        );
    }

    #[test]
    fn parses_top_level_type() {
        let t = "---\nname: x\ntype: project\n---\nDialF uses TCP 8765\n";
        assert_eq!(parse_memory_file(t).unwrap().0, "project");
    }

    #[test]
    fn rejects_files_without_frontmatter_type_or_body() {
        assert!(parse_memory_file("just text").is_none());
        assert!(parse_memory_file("---\nname: x\n---\nbody").is_none());
        assert!(parse_memory_file("---\ntype: user\n---\n   \n").is_none());
    }

    #[test]
    fn maps_types_to_scopes() {
        assert_eq!(type_to_scope("user"), Some(Scope::Global));
        assert_eq!(type_to_scope("feedback"), Some(Scope::Global));
        assert_eq!(type_to_scope("project"), Some(Scope::Project));
        assert_eq!(type_to_scope("reference"), Some(Scope::Project));
        assert_eq!(type_to_scope("journal"), None);
    }

    #[test]
    fn harvests_dir_skipping_index_and_unknown() {
        let td = tempfile::tempdir().unwrap();
        let d = td.path();
        std::fs::write(d.join("MEMORY.md"), "- [a](a.md)").unwrap();
        std::fs::write(d.join("a.md"), "---\ntype: project\n---\nDialF uses TCP 8765\n").unwrap();
        std::fs::write(d.join("b.md"), "---\ntype: user\n---\nPrefers ripgrep\n").unwrap();
        std::fs::write(d.join("c.md"), "---\ntype: journal\n---\nskip me\n").unwrap();
        std::fs::write(d.join("notes.txt"), "---\ntype: user\n---\nnope\n").unwrap();
        let got = harvest_dir(d, "host-1234").unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].scope, Scope::Project);
        assert_eq!(got[0].content, "DialF uses TCP 8765");
        assert_eq!(got[0].origin, format!("host-1234:{}", d.join("a.md").display()));
        assert!(got[0].origin.starts_with(&origin_prefix("host-1234", d)));
        assert_eq!(got[1].scope, Scope::Global);
    }

    #[test]
    fn missing_dir_harvests_nothing() {
        assert!(harvest_dir(Path::new("/nonexistent/atem-test"), "m").unwrap().is_empty());
    }
}

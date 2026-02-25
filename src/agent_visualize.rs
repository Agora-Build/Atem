/// Agent-powered diagram generation.
///
/// Detects HTML files written by an active agent (Claude Code, Codex, etc.)
/// to `~/.agent/diagrams/` and opens them in the browser.
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::SystemTime;

use anyhow::{Result, anyhow};

// ── Diagrams directory ────────────────────────────────────────────────────

/// Returns `~/.agent/diagrams/`.
pub fn diagrams_dir() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".agent")
        .join("diagrams")
}

// ── Prompt builder ────────────────────────────────────────────────────────

/// Build a prompt that instructs the agent to generate a visual HTML diagram.
pub fn build_visualize_prompt(topic: &str) -> String {
    format!(
        "Generate a beautiful, self-contained HTML page that visually explains: {topic}\n\n\
         Requirements:\n\
         - Create a single HTML file with embedded CSS and JavaScript\n\
         - Use clear diagrams, flowcharts, or architecture visuals\n\
         - Make it visually appealing with a clean, modern design\n\
         - Save the file to ~/.agent/diagrams/ with a descriptive filename ending in .html\n\
         - The page should be fully self-contained (no external dependencies)"
    )
}

// ── Filesystem snapshot / diff ────────────────────────────────────────────

/// Snapshot all `.html` files in the diagrams directory with their modification times.
///
/// Creates the directory if it does not exist.
pub fn snapshot_diagrams_dir() -> HashMap<PathBuf, SystemTime> {
    let dir = diagrams_dir();
    let _ = std::fs::create_dir_all(&dir);

    let mut snapshot = HashMap::new();
    if let Ok(entries) = std::fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) == Some("html") {
                if let Ok(meta) = entry.metadata() {
                    if let Ok(modified) = meta.modified() {
                        snapshot.insert(path, modified);
                    }
                }
            }
        }
    }
    snapshot
}

/// Compare the current diagrams directory state against a pre-snapshot.
///
/// Returns paths to new or modified `.html` files, sorted newest-first.
pub fn detect_new_html_files(pre_snapshot: &HashMap<PathBuf, SystemTime>) -> Vec<String> {
    let current = snapshot_diagrams_dir();
    let mut new_files: Vec<(PathBuf, SystemTime)> = Vec::new();

    for (path, modified) in &current {
        match pre_snapshot.get(path) {
            None => {
                // Completely new file
                new_files.push((path.clone(), *modified));
            }
            Some(old_modified) if modified > old_modified => {
                // Modified since snapshot
                new_files.push((path.clone(), *modified));
            }
            _ => {}
        }
    }

    // Sort newest-first
    new_files.sort_by(|a, b| b.1.cmp(&a.1));
    new_files
        .into_iter()
        .map(|(p, _)| p.to_string_lossy().into_owned())
        .collect()
}

// ── Agent URL resolution ──────────────────────────────────────────────────

/// Resolve the ACP WebSocket URL for a running agent.
///
/// Priority: explicit URL > lockfile scan > port scan > error with help.
pub async fn resolve_agent_url(explicit: Option<String>) -> Result<String> {
    if let Some(url) = explicit {
        return Ok(url);
    }

    // Try lockfiles first
    let lockfile_agents = crate::agent_detector::scan_lockfiles();
    if let Some(agent) = lockfile_agents.first() {
        return Ok(agent.acp_url.clone());
    }

    // Fall back to port scanning
    let port_agents = crate::agent_detector::scan_default_ports().await;
    if let Some(agent) = port_agents.first() {
        return Ok(agent.acp_url.clone());
    }

    Err(anyhow!(
        "No running ACP agent detected.\n\
         Start an agent first, e.g.:\n  \
         npx -y @anthropic-ai/claude-code --acp\n\
         Or pass --url ws://localhost:8765 explicitly."
    ))
}

// ── Browser opener ────────────────────────────────────────────────────────

/// Open an HTML file in the default browser.
pub fn open_html_in_browser(path: &str) {
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(path).spawn();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open").arg(path).spawn();
    }
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", "", path])
            .spawn();
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_diagrams_dir_ends_with_expected_path() {
        let dir = diagrams_dir();
        assert!(dir.ends_with(".agent/diagrams"));
    }

    #[test]
    fn test_prompt_contains_topic() {
        let prompt = build_visualize_prompt("WebRTC data flow");
        assert!(prompt.contains("WebRTC data flow"));
        assert!(prompt.contains(".html"));
    }

    #[test]
    fn test_prompt_contains_save_instruction() {
        let prompt = build_visualize_prompt("auth system");
        assert!(prompt.contains("~/.agent/diagrams/"));
    }

    #[test]
    fn test_snapshot_is_idempotent() {
        let snap1 = snapshot_diagrams_dir();
        let snap2 = snapshot_diagrams_dir();
        assert_eq!(snap1.len(), snap2.len());
        for (path, time) in &snap1 {
            assert_eq!(snap2.get(path), Some(time));
        }
    }

    #[test]
    fn test_detect_new_files_empty_when_unchanged() {
        let snap = snapshot_diagrams_dir();
        let new_files = detect_new_html_files(&snap);
        assert!(new_files.is_empty());
    }

    #[test]
    fn test_detect_new_files_finds_new_file() {
        let dir = diagrams_dir();
        let _ = std::fs::create_dir_all(&dir);

        let snap = snapshot_diagrams_dir();

        // Write a temp file
        let test_file = dir.join("_test_visualize_detect.html");
        std::fs::write(&test_file, "<html>test</html>").unwrap();

        let new_files = detect_new_html_files(&snap);
        assert!(new_files.iter().any(|f| f.contains("_test_visualize_detect.html")));

        // Cleanup
        let _ = std::fs::remove_file(&test_file);
    }

    #[tokio::test]
    async fn test_resolve_agent_url_explicit() {
        let url = resolve_agent_url(Some("ws://localhost:9999".into()))
            .await
            .unwrap();
        assert_eq!(url, "ws://localhost:9999");
    }

    #[test]
    fn test_detect_new_files_sorted_newest_first() {
        let dir = diagrams_dir();
        let _ = std::fs::create_dir_all(&dir);

        let snap = snapshot_diagrams_dir();

        // Write two files with a small gap
        let f1 = dir.join("_test_sort_a.html");
        let f2 = dir.join("_test_sort_b.html");
        std::fs::write(&f1, "<html>a</html>").unwrap();
        // Touch f2 slightly later
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(&f2, "<html>b</html>").unwrap();

        let new_files = detect_new_html_files(&snap);
        assert!(new_files.len() >= 2);
        // Newest first — f2 should come before f1
        let pos_b = new_files.iter().position(|f| f.contains("_test_sort_b.html"));
        let pos_a = new_files.iter().position(|f| f.contains("_test_sort_a.html"));
        if let (Some(pb), Some(pa)) = (pos_b, pos_a) {
            assert!(pb < pa, "Expected newest file first");
        }

        // Cleanup
        let _ = std::fs::remove_file(&f1);
        let _ = std::fs::remove_file(&f2);
    }

    // ── Additional edge case tests ───────────────────────────────────────

    #[test]
    fn test_prompt_with_empty_topic() {
        let prompt = build_visualize_prompt("");
        // Should still contain structural instructions even with empty topic
        assert!(prompt.contains("~/.agent/diagrams/"));
        assert!(prompt.contains(".html"));
        assert!(prompt.contains("self-contained"));
    }

    #[test]
    fn test_prompt_with_special_characters() {
        let prompt = build_visualize_prompt("auth <system> & \"flow\" 100%");
        assert!(prompt.contains("auth <system> & \"flow\" 100%"));
    }

    #[test]
    fn test_prompt_with_multiline_topic() {
        let prompt = build_visualize_prompt("line1\nline2\nline3");
        assert!(prompt.contains("line1\nline2\nline3"));
    }

    #[test]
    fn test_diagrams_dir_is_absolute() {
        let dir = diagrams_dir();
        assert!(dir.is_absolute());
    }

    #[test]
    fn test_snapshot_creates_directory() {
        // snapshot_diagrams_dir should create the dir if it doesn't exist
        let dir = diagrams_dir();
        let _ = snapshot_diagrams_dir();
        assert!(dir.exists());
    }

    #[test]
    fn test_snapshot_ignores_non_html_files() {
        let dir = diagrams_dir();
        let _ = std::fs::create_dir_all(&dir);

        // Create a non-html file
        let txt_file = dir.join("_test_nonhtml.txt");
        std::fs::write(&txt_file, "not html").unwrap();

        let snap = snapshot_diagrams_dir();
        // The txt file should not be in the snapshot
        assert!(!snap.keys().any(|p| p.to_string_lossy().contains("_test_nonhtml.txt")));

        // Cleanup
        let _ = std::fs::remove_file(&txt_file);
    }

    #[test]
    fn test_detect_ignores_deleted_files() {
        let dir = diagrams_dir();
        let _ = std::fs::create_dir_all(&dir);

        // Create a file, take snapshot, then delete the file
        let test_file = dir.join("_test_deleted.html");
        std::fs::write(&test_file, "<html>temp</html>").unwrap();

        let snap = snapshot_diagrams_dir();

        // Delete the file
        let _ = std::fs::remove_file(&test_file);

        // detect_new_html_files should not report deleted files as new
        let new_files = detect_new_html_files(&snap);
        assert!(!new_files.iter().any(|f| f.contains("_test_deleted.html")));
    }

    #[test]
    fn test_detect_finds_modified_file() {
        let dir = diagrams_dir();
        let _ = std::fs::create_dir_all(&dir);

        let test_file = dir.join("_test_modified.html");
        std::fs::write(&test_file, "<html>v1</html>").unwrap();

        let snap = snapshot_diagrams_dir();

        // Modify the file (need a small delay so mtime changes)
        std::thread::sleep(std::time::Duration::from_millis(50));
        std::fs::write(&test_file, "<html>v2 - modified content</html>").unwrap();

        let new_files = detect_new_html_files(&snap);
        assert!(new_files.iter().any(|f| f.contains("_test_modified.html")));

        // Cleanup
        let _ = std::fs::remove_file(&test_file);
    }

    #[test]
    fn test_detect_with_empty_pre_snapshot() {
        let dir = diagrams_dir();
        let _ = std::fs::create_dir_all(&dir);

        let test_file = dir.join("_test_empty_pre.html");
        std::fs::write(&test_file, "<html>exists</html>").unwrap();

        // Empty pre-snapshot means all current files are "new"
        let empty_snap = HashMap::new();
        let new_files = detect_new_html_files(&empty_snap);
        assert!(new_files.iter().any(|f| f.contains("_test_empty_pre.html")));

        // Cleanup
        let _ = std::fs::remove_file(&test_file);
    }

    #[tokio::test]
    async fn test_resolve_agent_url_none_falls_through() {
        // With no explicit URL and likely no running agents, should error
        let result = resolve_agent_url(None).await;
        // This may succeed if there's actually a running agent, or fail with help message
        if let Err(e) = result {
            let msg = e.to_string();
            assert!(msg.contains("No running ACP agent") || msg.contains("agent"));
        }
        // If Ok, that's fine too — there was a real agent running
    }

    #[tokio::test]
    async fn test_resolve_agent_url_preserves_explicit_url_verbatim() {
        // Should return exactly what was passed, no normalization
        let url = "ws://192.168.1.100:9999/custom/path";
        let resolved = resolve_agent_url(Some(url.to_string())).await.unwrap();
        assert_eq!(resolved, url);
    }

    #[test]
    fn test_detect_returns_full_paths() {
        let dir = diagrams_dir();
        let _ = std::fs::create_dir_all(&dir);

        let snap = snapshot_diagrams_dir();

        let test_file = dir.join("_test_full_path.html");
        std::fs::write(&test_file, "<html>test</html>").unwrap();

        let new_files = detect_new_html_files(&snap);
        for f in &new_files {
            if f.contains("_test_full_path.html") {
                // Should contain the full absolute path
                assert!(PathBuf::from(f).is_absolute());
            }
        }

        // Cleanup
        let _ = std::fs::remove_file(&test_file);
    }
}

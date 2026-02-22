/// Agent detection — finds running Claude Code / Codex processes by
/// scanning their lockfiles, then probes whether each exposes an ACP
/// WebSocket endpoint.
///
/// ## Lockfile convention
///
/// Claude Code writes `~/.claude/claude_server_<pid>.lock` containing a
/// JSON object with at minimum `{"port": 8765}` when it starts an ACP
/// server.  Codex follows a similar convention in `~/.codex/`.
///
/// ## ACP probe
///
/// Connecting to `ws://127.0.0.1:<port>` and sending a JSON-RPC
/// `initialize` request within a short timeout is enough to confirm ACP
/// support and identify the agent kind.
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::agent_client::{AgentKind, AgentProtocol};

// ── Lockfile types ────────────────────────────────────────────────────────

/// Parsed contents of a Claude Code or Codex lockfile.
#[derive(Debug, Clone, Deserialize)]
pub struct LockfileData {
    /// TCP port on which the ACP WebSocket server is listening.
    pub port: u16,
    /// Process ID of the agent, if present in the lockfile.
    #[serde(default)]
    pub pid: Option<u32>,
}

/// Detected agent from a lockfile scan.
#[derive(Debug, Clone)]
pub struct DetectedAgent {
    pub kind: AgentKind,
    pub protocol: AgentProtocol,
    /// WebSocket URL built from the lockfile port.
    pub acp_url: String,
    /// PID from the lockfile (if any).
    pub pid: Option<u32>,
    /// Path to the lockfile.
    pub lockfile: PathBuf,
}

// ── Lockfile scanning ─────────────────────────────────────────────────────

/// Return glob patterns for Claude Code lockfiles.
pub fn claude_lockfile_patterns() -> Vec<String> {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    vec![
        home.join(".claude")
            .join("claude_server*.lock")
            .to_string_lossy()
            .into_owned(),
        home.join(".claude")
            .join("*.lock")
            .to_string_lossy()
            .into_owned(),
    ]
}

/// Return glob patterns for Codex lockfiles.
pub fn codex_lockfile_patterns() -> Vec<String> {
    let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
    vec![home
        .join(".codex")
        .join("codex_server*.lock")
        .to_string_lossy()
        .into_owned()]
}

/// Parse a single lockfile from disk.  Returns `None` if the file cannot
/// be read or does not contain a valid port.
pub fn parse_lockfile(path: &Path, kind: AgentKind) -> Option<DetectedAgent> {
    let content = std::fs::read_to_string(path).ok()?;
    let data: LockfileData = serde_json::from_str(content.trim()).ok()?;

    let acp_url = format!("ws://127.0.0.1:{}", data.port);

    Some(DetectedAgent {
        kind,
        protocol: AgentProtocol::Acp,
        acp_url,
        pid: data.pid,
        lockfile: path.to_path_buf(),
    })
}

/// Scan all known lockfile locations and return detected agents.
///
/// This is a synchronous, best-effort scan — it silently skips files that
/// cannot be read.
pub fn scan_lockfiles() -> Vec<DetectedAgent> {
    let mut agents = Vec::new();

    for pattern in claude_lockfile_patterns() {
        if let Ok(paths) = glob::glob(&pattern) {
            for entry in paths.flatten() {
                if let Some(agent) = parse_lockfile(&entry, AgentKind::ClaudeCode) {
                    agents.push(agent);
                }
            }
        }
    }

    for pattern in codex_lockfile_patterns() {
        if let Ok(paths) = glob::glob(&pattern) {
            for entry in paths.flatten() {
                if let Some(agent) = parse_lockfile(&entry, AgentKind::Codex) {
                    agents.push(agent);
                }
            }
        }
    }

    agents
}

/// Scan common ACP ports for running agents.
///
/// This probes localhost ports commonly used by ACP agents (8765-8770)
/// to detect agents that don't create lockfiles.
///
/// This is an async function that makes real network connections.
pub async fn scan_default_ports() -> Vec<DetectedAgent> {
    // Common ACP ports (8765 is the default from stdio-to-ws examples)
    let ports = vec![8765, 8766, 8767, 8768, 8769, 8770];
    let mut agents = Vec::new();

    for port in ports {
        let url = format!("ws://127.0.0.1:{}", port);
        // Use a short timeout (500ms) to avoid blocking startup
        match probe_acp(&url, 500).await {
            ProbeResult::AcpAvailable { kind, version: _ } => {
                agents.push(DetectedAgent {
                    kind,
                    protocol: AgentProtocol::Acp,
                    acp_url: url,
                    pid: None, // No PID available from port scan
                    lockfile: std::path::PathBuf::from(format!("<port-scan:{}>", port)),
                });
            }
            _ => {
                // Port not available or not ACP - continue
            }
        }
    }

    agents
}

// ── ACP probe ─────────────────────────────────────────────────────────────

/// Result of a WebSocket ACP probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbeResult {
    /// ACP server responded to `initialize`.
    AcpAvailable { kind: AgentKind, version: String },
    /// Port is open but did not respond with a valid ACP response in time.
    NotAcp,
    /// Could not connect at all (port closed / process not running).
    Unreachable,
}

impl ProbeResult {
    pub fn is_acp(&self) -> bool {
        matches!(self, ProbeResult::AcpAvailable { .. })
    }
}

/// Probe a WebSocket URL for ACP support.
///
/// Attempts a connection and sends `initialize`.  If a valid `serverInfo`
/// response arrives within `timeout_ms`, returns `AcpAvailable`.
///
/// NOTE: This makes a real network connection and therefore cannot be called
/// in unit tests that run without a local agent.  Integration tests and the
/// production code path use this.  Unit tests cover only the pure helpers.
pub async fn probe_acp(url: &str, timeout_ms: u64) -> ProbeResult {
    use std::time::Duration;
    use tokio::time::timeout;

    let connect_result = timeout(
        Duration::from_millis(timeout_ms),
        tokio_tungstenite::connect_async(url),
    )
    .await;

    let (mut ws, _) = match connect_result {
        Ok(Ok(pair)) => pair,
        Ok(Err(_)) => return ProbeResult::Unreachable,
        Err(_) => return ProbeResult::Unreachable, // timeout
    };

    // Send initialize
    use crate::acp_client::build_initialize_request;
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::tungstenite::Message;

    let req = build_initialize_request(1);
    let json = match serde_json::to_string(&req) {
        Ok(j) => j,
        Err(_) => return ProbeResult::NotAcp,
    };

    if ws.send(Message::Text(json.into())).await.is_err() {
        return ProbeResult::NotAcp;
    }

    // Wait for response
    let response = timeout(Duration::from_millis(timeout_ms), ws.next()).await;

    let raw = match response {
        Ok(Some(Ok(Message::Text(text)))) => text.to_string(),
        _ => return ProbeResult::NotAcp,
    };

    let resp: serde_json::Value = match serde_json::from_str(&raw) {
        Ok(v) => v,
        Err(_) => return ProbeResult::NotAcp,
    };

    let server_info = match resp.get("result").and_then(|r| r.get("serverInfo")) {
        Some(si) => si,
        None => return ProbeResult::NotAcp,
    };

    let name = server_info
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("unknown");
    let version = server_info
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("0.0.0")
        .to_string();

    ProbeResult::AcpAvailable {
        kind: AgentKind::from_server_name(name),
        version,
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    // ── parse_lockfile ────────────────────────────────────────────────────

    #[test]
    fn test_parse_lockfile_valid() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, r#"{{"port": 8765, "pid": 12345}}"#).unwrap();

        let agent = parse_lockfile(f.path(), AgentKind::ClaudeCode).unwrap();
        assert_eq!(agent.acp_url, "ws://127.0.0.1:8765");
        assert_eq!(agent.pid, Some(12345));
        assert_eq!(agent.kind, AgentKind::ClaudeCode);
        assert_eq!(agent.protocol, AgentProtocol::Acp);
    }

    #[test]
    fn test_parse_lockfile_port_only() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, r#"{{"port": 9000}}"#).unwrap();

        let agent = parse_lockfile(f.path(), AgentKind::Codex).unwrap();
        assert_eq!(agent.acp_url, "ws://127.0.0.1:9000");
        assert!(agent.pid.is_none());
        assert_eq!(agent.kind, AgentKind::Codex);
    }

    #[test]
    fn test_parse_lockfile_whitespace_trimmed() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "  {{ \"port\": 8080 }}\n").unwrap();

        let agent = parse_lockfile(f.path(), AgentKind::ClaudeCode).unwrap();
        assert_eq!(agent.acp_url, "ws://127.0.0.1:8080");
    }

    #[test]
    fn test_parse_lockfile_invalid_json_returns_none() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, "not valid json").unwrap();

        let result = parse_lockfile(f.path(), AgentKind::ClaudeCode);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_lockfile_missing_port_returns_none() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, r#"{{"pid": 1234}}"#).unwrap();

        let result = parse_lockfile(f.path(), AgentKind::ClaudeCode);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_lockfile_nonexistent_file_returns_none() {
        let result = parse_lockfile(Path::new("/nonexistent/path/to/file.lock"), AgentKind::ClaudeCode);
        assert!(result.is_none());
    }

    #[test]
    fn test_parse_lockfile_records_path() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, r#"{{"port": 7777}}"#).unwrap();

        let agent = parse_lockfile(f.path(), AgentKind::ClaudeCode).unwrap();
        assert_eq!(agent.lockfile, f.path());
    }

    // ── lockfile glob patterns ────────────────────────────────────────────

    #[test]
    fn test_claude_lockfile_patterns_non_empty() {
        let patterns = claude_lockfile_patterns();
        assert!(!patterns.is_empty());
        assert!(patterns.iter().any(|p| p.contains(".claude")));
    }

    #[test]
    fn test_codex_lockfile_patterns_non_empty() {
        let patterns = codex_lockfile_patterns();
        assert!(!patterns.is_empty());
        assert!(patterns.iter().any(|p| p.contains(".codex")));
    }

    #[test]
    fn test_claude_patterns_contain_lock_extension() {
        let patterns = claude_lockfile_patterns();
        assert!(patterns.iter().all(|p| p.contains(".lock")));
    }

    #[test]
    fn test_codex_patterns_contain_lock_extension() {
        let patterns = codex_lockfile_patterns();
        assert!(patterns.iter().all(|p| p.contains(".lock")));
    }

    // ── ProbeResult ───────────────────────────────────────────────────────

    #[test]
    fn test_probe_result_acp_available_is_acp() {
        let r = ProbeResult::AcpAvailable {
            kind: AgentKind::ClaudeCode,
            version: "1.0".into(),
        };
        assert!(r.is_acp());
    }

    #[test]
    fn test_probe_result_not_acp_is_not_acp() {
        assert!(!ProbeResult::NotAcp.is_acp());
    }

    #[test]
    fn test_probe_result_unreachable_is_not_acp() {
        assert!(!ProbeResult::Unreachable.is_acp());
    }

    // ── scan_lockfiles on clean machine ───────────────────────────────────

    #[test]
    fn test_scan_lockfiles_returns_vec() {
        // On machines without claude/codex installed this should return empty
        // without panicking.
        let agents = scan_lockfiles();
        // No assertion on count — may be 0 or more.
        let _ = agents;
    }

    // ── ACP URL construction ──────────────────────────────────────────────

    #[test]
    fn test_acp_url_format() {
        let mut f = NamedTempFile::new().unwrap();
        write!(f, r#"{{"port": 12345}}"#).unwrap();

        let agent = parse_lockfile(f.path(), AgentKind::ClaudeCode).unwrap();
        // Must be a valid WS URL
        assert!(agent.acp_url.starts_with("ws://127.0.0.1:"));
        assert!(agent.acp_url.ends_with("12345"));
    }

    #[test]
    fn test_probe_unreachable_on_closed_port() {
        // Port 1 is virtually never open; expect Unreachable quickly.
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(probe_acp("ws://127.0.0.1:1", 200));
        assert_eq!(result, ProbeResult::Unreachable);
    }
}

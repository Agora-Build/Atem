/// Core types for the unified agent abstraction.
///
/// Agents are the PTY sessions started by `atem agent launch` (Claude Code,
/// Codex); Astation lists and drives them through the agent registry.
use serde::{Deserialize, Serialize};

// ── Protocol / kind / origin ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentProtocol {
    /// The only protocol. Kept so the agent list Astation decodes still
    /// carries `"protocol": "Pty"`.
    Pty,
}

impl std::fmt::Display for AgentProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentProtocol::Pty => write!(f, "PTY"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentKind {
    ClaudeCode,
    Codex,
    Unknown(String),
}

impl std::fmt::Display for AgentKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentKind::ClaudeCode => write!(f, "claude-code"),
            AgentKind::Codex => write!(f, "codex"),
            AgentKind::Unknown(s) => write!(f, "{s}"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentOrigin {
    /// Atem spawned the process.
    Launched,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentStatus {
    Idle,
    Thinking,
    WaitingForInput,
    Disconnected,
}

// ── AgentInfo ─────────────────────────────────────────────────────────────

/// Snapshot of an agent entry — safe to clone/serialize and send to Astation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub id: String,
    pub name: String,
    pub kind: AgentKind,
    pub protocol: AgentProtocol,
    pub origin: AgentOrigin,
    pub status: AgentStatus,
    pub session_ids: Vec<String>,
    /// Always `None` (serialised as `"acp_url": null`): ACP agents were
    /// removed, and the field keeps the agent list Astation decodes unchanged.
    pub acp_url: Option<String>,
    /// Present for PTY agents.
    pub pty_pid: Option<u32>,
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── AgentProtocol Display ─────────────────────────────────────────────

    #[test]
    fn test_protocol_display() {
        assert_eq!(AgentProtocol::Pty.to_string(), "PTY");
    }

    // ── AgentInfo serialization ───────────────────────────────────────────

    #[test]
    fn test_agent_info_serialization_round_trip() {
        let info = AgentInfo {
            id: "abc123".to_string(),
            name: "claude-code".to_string(),
            kind: AgentKind::ClaudeCode,
            protocol: AgentProtocol::Pty,
            origin: AgentOrigin::Launched,
            status: AgentStatus::Idle,
            session_ids: vec!["sess-1".to_string()],
            acp_url: None,
            pty_pid: Some(4242),
        };

        let json = serde_json::to_string(&info).unwrap();
        let decoded: AgentInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, info.id);
        assert_eq!(decoded.protocol, AgentProtocol::Pty);
        assert_eq!(decoded.kind, AgentKind::ClaudeCode);
        assert_eq!(decoded.pty_pid, Some(4242));
    }

    /// The exact bytes Astation's `AtemAgentInfo` decoder receives for a
    /// launched PTY agent; the same as before ACP agents were removed.
    #[test]
    fn test_agent_info_wire_bytes_for_astation() {
        let info = AgentInfo {
            id: "claude-pty-1".to_string(),
            name: "claude-code".to_string(),
            kind: AgentKind::ClaudeCode,
            protocol: AgentProtocol::Pty,
            origin: AgentOrigin::Launched,
            status: AgentStatus::Idle,
            session_ids: vec![],
            acp_url: None,
            pty_pid: None,
        };
        assert_eq!(
            serde_json::to_string(&info).unwrap(),
            r#"{"id":"claude-pty-1","name":"claude-code","kind":"ClaudeCode","protocol":"Pty","origin":"Launched","status":"Idle","session_ids":[],"acp_url":null,"pty_pid":null}"#
        );
    }
}

/// Core types for the unified agent abstraction.
///
/// Both ACP (WebSocket/JSON-RPC) and PTY agents implement the same
/// [`AgentHandle`] enum so callers never need to care which protocol
/// is in use.
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

// ── Protocol / kind / origin ──────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentProtocol {
    Acp,
    Pty,
}

impl std::fmt::Display for AgentProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AgentProtocol::Acp => write!(f, "ACP"),
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

impl AgentKind {
    /// Parse from the `serverInfo.name` field returned by ACP `initialize`.
    pub fn from_server_name(name: &str) -> Self {
        let lower = name.to_lowercase();
        if lower.contains("claude") {
            AgentKind::ClaudeCode
        } else if lower.contains("codex") {
            AgentKind::Codex
        } else {
            AgentKind::Unknown(name.to_string())
        }
    }
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
    /// Found independently (lockfile / port probe).
    External,
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
    /// Present for ACP agents.
    pub acp_url: Option<String>,
    /// Present for PTY agents.
    pub pty_pid: Option<u32>,
}

// ── AgentEvent ────────────────────────────────────────────────────────────

/// Events emitted by an agent and forwarded to Astation / the TUI.
#[derive(Debug, Clone)]
pub enum AgentEvent {
    /// Streaming text token.
    TextDelta(String),
    /// Agent invoked a tool.
    ToolCall {
        id: String,
        name: String,
        input: serde_json::Value,
    },
    /// Tool execution result.
    ToolResult { id: String, output: String },
    /// Agent finished its turn.
    Done,
    /// Non-fatal error message from the agent.
    Error(String),
    /// Connection / process terminated.
    Disconnected,
}

// ── PtyAgentClient ────────────────────────────────────────────────────────

/// Wraps the existing PTY sender/receiver into the unified event model.
///
/// PTY sessions emit a continuous stream of terminal bytes.  We wrap each
/// chunk as a [`AgentEvent::TextDelta`] so downstream consumers are
/// protocol-agnostic.
pub struct PtyAgentClient {
    /// Forward input text to the PTY.
    pub sender: mpsc::UnboundedSender<String>,
    /// Raw PTY output chunks (ANSI-encoded terminal bytes).
    receiver: mpsc::UnboundedReceiver<String>,
    /// Stable agent ID for registry bookkeeping.
    pub agent_id: String,
}

impl PtyAgentClient {
    pub fn new(
        agent_id: impl Into<String>,
        sender: mpsc::UnboundedSender<String>,
        receiver: mpsc::UnboundedReceiver<String>,
    ) -> Self {
        Self {
            agent_id: agent_id.into(),
            sender,
            receiver,
        }
    }

    /// Send a prompt to the PTY (appends `\n`).
    pub fn send_prompt(&self, prompt: &str) -> anyhow::Result<()> {
        self.sender
            .send(format!("{prompt}\n"))
            .map_err(|_| anyhow::anyhow!("PTY sender closed"))
    }

    /// Drain all pending output chunks and return them as `AgentEvent`s.
    pub fn drain_events(&mut self) -> Vec<AgentEvent> {
        let mut events = Vec::new();
        loop {
            match self.receiver.try_recv() {
                Ok(chunk) => {
                    // Detect exit sentinel emitted by claude_client / codex_client.
                    if chunk.contains("CLI exited with status") {
                        events.push(AgentEvent::Disconnected);
                        break;
                    }
                    events.push(AgentEvent::TextDelta(chunk));
                }
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    events.push(AgentEvent::Disconnected);
                    break;
                }
            }
        }
        events
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── AgentKind::from_server_name ────────────────────────────────────────

    #[test]
    fn test_kind_from_server_name_claude() {
        assert_eq!(
            AgentKind::from_server_name("claude-code"),
            AgentKind::ClaudeCode
        );
        assert_eq!(
            AgentKind::from_server_name("Claude Code"),
            AgentKind::ClaudeCode
        );
        assert_eq!(
            AgentKind::from_server_name("anthropic-claude"),
            AgentKind::ClaudeCode
        );
    }

    #[test]
    fn test_kind_from_server_name_codex() {
        assert_eq!(AgentKind::from_server_name("codex"), AgentKind::Codex);
        assert_eq!(
            AgentKind::from_server_name("openai-codex"),
            AgentKind::Codex
        );
    }

    #[test]
    fn test_kind_from_server_name_unknown() {
        assert_eq!(
            AgentKind::from_server_name("gemini-cli"),
            AgentKind::Unknown("gemini-cli".to_string())
        );
    }

    // ── AgentProtocol Display ─────────────────────────────────────────────

    #[test]
    fn test_protocol_display() {
        assert_eq!(AgentProtocol::Acp.to_string(), "ACP");
        assert_eq!(AgentProtocol::Pty.to_string(), "PTY");
    }

    // ── PtyAgentClient ────────────────────────────────────────────────────

    #[test]
    fn test_pty_send_prompt_appends_newline() {
        let (tx, mut rx) = mpsc::unbounded_channel();
        let (_out_tx, out_rx) = mpsc::unbounded_channel::<String>();
        let client = PtyAgentClient::new("test-id", tx, out_rx);

        client.send_prompt("hello").unwrap();
        assert_eq!(rx.try_recv().unwrap(), "hello\n");
    }

    #[test]
    fn test_pty_drain_events_text_delta() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let mut client = PtyAgentClient::new("test-id", tx, out_rx);

        out_tx.send("chunk1".to_string()).unwrap();
        out_tx.send("chunk2".to_string()).unwrap();

        let events = client.drain_events();
        assert_eq!(events.len(), 2);
        assert!(matches!(&events[0], AgentEvent::TextDelta(t) if t == "chunk1"));
        assert!(matches!(&events[1], AgentEvent::TextDelta(t) if t == "chunk2"));
    }

    #[test]
    fn test_pty_drain_events_detects_exit_sentinel() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        let mut client = PtyAgentClient::new("test-id", tx, out_rx);

        out_tx
            .send("Claude CLI exited with status 0".to_string())
            .unwrap();

        let events = client.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], AgentEvent::Disconnected));
    }

    #[test]
    fn test_pty_drain_events_disconnected_on_closed_channel() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let (out_tx, out_rx) = mpsc::unbounded_channel::<String>();
        let mut client = PtyAgentClient::new("test-id", tx, out_rx);

        drop(out_tx); // close sender — simulates process exit

        let events = client.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], AgentEvent::Disconnected));
    }

    #[test]
    fn test_pty_drain_empty_returns_nothing() {
        let (tx, _rx) = mpsc::unbounded_channel();
        let (_out_tx, out_rx) = mpsc::unbounded_channel::<String>();
        let mut client = PtyAgentClient::new("test-id", tx, out_rx);

        let events = client.drain_events();
        assert!(events.is_empty());
    }

    #[test]
    fn test_pty_send_fails_when_receiver_dropped() {
        let (tx, rx) = mpsc::unbounded_channel();
        let (_out_tx, out_rx) = mpsc::unbounded_channel::<String>();
        let client = PtyAgentClient::new("test-id", tx, out_rx);

        drop(rx); // drop receiver — simulates PTY closed
        assert!(client.send_prompt("test").is_err());
    }

    // ── AgentInfo serialization ───────────────────────────────────────────

    #[test]
    fn test_agent_info_serialization_round_trip() {
        let info = AgentInfo {
            id: "abc123".to_string(),
            name: "claude-code".to_string(),
            kind: AgentKind::ClaudeCode,
            protocol: AgentProtocol::Acp,
            origin: AgentOrigin::Launched,
            status: AgentStatus::Idle,
            session_ids: vec!["sess-1".to_string()],
            acp_url: Some("ws://localhost:8765".to_string()),
            pty_pid: None,
        };

        let json = serde_json::to_string(&info).unwrap();
        let decoded: AgentInfo = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.id, info.id);
        assert_eq!(decoded.protocol, AgentProtocol::Acp);
        assert_eq!(decoded.kind, AgentKind::ClaudeCode);
    }
}

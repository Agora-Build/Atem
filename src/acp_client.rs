/// ACP (Agent Client Protocol) — JSON-RPC 2.0 over WebSocket.
///
/// This module handles the wire protocol for talking to Claude Code, Codex,
/// and any other agent that speaks the ACP spec.  It is intentionally
/// separated from transport so that the JSON-RPC message helpers can be
/// unit-tested without a real WebSocket server.
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::agent_client::{AgentEvent, AgentKind};

// ── JSON-RPC 2.0 wire types ───────────────────────────────────────────────

/// An outgoing JSON-RPC 2.0 request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: String,
    pub method: String,
    pub id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// An incoming JSON-RPC 2.0 response (success or error).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub id: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JsonRpcError>,
}

/// An incoming JSON-RPC 2.0 notification (no `id` field).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcNotification {
    pub jsonrpc: String,
    pub method: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
}

/// JSON-RPC 2.0 error object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// Result of the ACP `initialize` handshake.
#[derive(Debug, Clone)]
pub struct AcpServerInfo {
    pub kind: AgentKind,
    pub version: String,
}

// ── Message builders ──────────────────────────────────────────────────────

/// Build a JSON-RPC 2.0 `initialize` request.
pub fn build_initialize_request(id: u64) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".into(),
        method: "initialize".into(),
        id,
        params: Some(serde_json::json!({
            "protocolVersion": "0.1",
            "clientInfo": {
                "name": "atem",
                "version": env!("CARGO_PKG_VERSION"),
            }
        })),
    }
}

/// Build a JSON-RPC 2.0 `session/new` request.
pub fn build_new_session_request(id: u64) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".into(),
        method: "session/new".into(),
        id,
        params: Some(serde_json::json!({})),
    }
}

/// Build a JSON-RPC 2.0 `session/prompt` request.
pub fn build_prompt_request(id: u64, session_id: &str, text: &str) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".into(),
        method: "session/prompt".into(),
        id,
        params: Some(serde_json::json!({
            "sessionId": session_id,
            "text": text,
        })),
    }
}

/// Build a JSON-RPC 2.0 `session/cancel` request.
pub fn build_cancel_request(id: u64, session_id: &str) -> JsonRpcRequest {
    JsonRpcRequest {
        jsonrpc: "2.0".into(),
        method: "session/cancel".into(),
        id,
        params: Some(serde_json::json!({ "sessionId": session_id })),
    }
}

// ── Response parsers ──────────────────────────────────────────────────────

/// Parse a raw JSON string and determine whether it is a response or
/// notification, then convert to `AgentEvent`.
///
/// Returns `None` for messages that do not map to an event (e.g. the
/// `initialize` / `session/new` response — callers should handle those
/// directly via `parse_initialize_response` / `parse_new_session_response`).
pub fn parse_event_from_json(raw: &str) -> Result<Option<AgentEvent>> {
    let value: Value = serde_json::from_str(raw)
        .map_err(|e| anyhow!("invalid JSON from ACP server: {e}"))?;

    // Notification — no `id` field
    if value.get("id").is_none() {
        return Ok(parse_notification_event(&value));
    }

    // Response — check for `error` field
    if let Some(err_obj) = value.get("error") {
        let msg = err_obj
            .get("message")
            .and_then(|m| m.as_str())
            .unwrap_or("unknown ACP error")
            .to_string();
        return Ok(Some(AgentEvent::Error(msg)));
    }

    // Ordinary response (initialize / session/new) — caller handles separately
    Ok(None)
}

/// Extract `AgentEvent` from a JSON-RPC notification value.
fn parse_notification_event(value: &Value) -> Option<AgentEvent> {
    let method = value.get("method")?.as_str()?;
    let params = value.get("params");

    match method {
        "message" => {
            let msg_type = params?.get("type")?.as_str()?;
            match msg_type {
                "text" => {
                    let content = params?
                        .get("content")
                        .and_then(|c| c.as_str())
                        .unwrap_or("")
                        .to_string();
                    Some(AgentEvent::TextDelta(content))
                }
                "tool_use" => {
                    let p = params?;
                    let id = p.get("id")?.as_str()?.to_string();
                    let name = p.get("name")?.as_str()?.to_string();
                    let input = p.get("input").cloned().unwrap_or(Value::Null);
                    Some(AgentEvent::ToolCall { id, name, input })
                }
                "tool_result" => {
                    let p = params?;
                    let id = p.get("id")?.as_str()?.to_string();
                    let output = p
                        .get("output")
                        .and_then(|o| o.as_str())
                        .unwrap_or("")
                        .to_string();
                    Some(AgentEvent::ToolResult { id, output })
                }
                _ => None,
            }
        }
        "session/done" => Some(AgentEvent::Done),
        "session/error" => {
            let msg = params
                .and_then(|p| p.get("message"))
                .and_then(|m| m.as_str())
                .unwrap_or("session error")
                .to_string();
            Some(AgentEvent::Error(msg))
        }
        _ => None,
    }
}

/// Parse the `initialize` response and return `AcpServerInfo`.
pub fn parse_initialize_response(resp: &JsonRpcResponse) -> Result<AcpServerInfo> {
    let result = resp
        .result
        .as_ref()
        .ok_or_else(|| anyhow!("initialize response has no result"))?;

    let server_info = result
        .get("serverInfo")
        .ok_or_else(|| anyhow!("initialize result missing serverInfo"))?;

    let name = server_info
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("unknown");
    let version = server_info
        .get("version")
        .and_then(|v| v.as_str())
        .unwrap_or("0.0.0")
        .to_string();

    Ok(AcpServerInfo {
        kind: AgentKind::from_server_name(name),
        version,
    })
}

/// Parse the `session/new` response and return the session ID.
pub fn parse_new_session_response(resp: &JsonRpcResponse) -> Result<String> {
    let result = resp
        .result
        .as_ref()
        .ok_or_else(|| anyhow!("session/new response has no result"))?;

    let session_id = result
        .get("sessionId")
        .and_then(|s| s.as_str())
        .ok_or_else(|| anyhow!("session/new result missing sessionId"))?
        .to_string();

    Ok(session_id)
}

// ── AcpClient ─────────────────────────────────────────────────────────────

/// Stateful ACP client that owns a WebSocket connection to one agent.
///
/// Lifecycle:
/// 1. `AcpClient::connect(url).await` — establish WebSocket
/// 2. `client.initialize().await` — JSON-RPC handshake, returns server info
/// 3. `client.new_session().await` — creates a session, stores session_id
/// 4. `client.send_prompt(text)` — fire-and-forget prompt into the session
/// 5. Poll `client.try_recv_event()` in the TUI loop to get streaming events
///
/// Both sending and receiving use internal channels so the client can be used
/// with `&mut self` from a single-threaded context (e.g. inside `App`).
pub struct AcpClient {
    url: String,
    next_id: u64,
    session_id: Option<String>,
    /// Channel to send raw JSON frames to the WS writer task.
    sender: Option<tokio::sync::mpsc::UnboundedSender<String>>,
    /// Channel to receive raw JSON frames from the WS reader task.
    frame_rx: Option<tokio::sync::mpsc::UnboundedReceiver<String>>,
    /// Frames that arrived while waiting for a specific response (and were not
    /// the expected response) are buffered here so they are not lost.
    pending_events: std::collections::VecDeque<String>,
}

impl AcpClient {
    // ── Construction ──────────────────────────────────────────────────────

    /// Connect to an ACP WebSocket server at `url`.
    ///
    /// Spawns two background tasks (reader + writer).  Returns immediately
    /// once the WebSocket handshake completes.
    pub async fn connect(url: &str) -> Result<Self> {
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message;

        let (ws, _) = tokio_tungstenite::connect_async(url)
            .await
            .map_err(|e| anyhow!("ACP connect failed for {url}: {e}"))?;

        let (mut sink, mut stream) = ws.split();

        // Outgoing channel: caller → writer task → WS sink
        let (send_tx, mut send_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            while let Some(json) = send_rx.recv().await {
                if sink.send(Message::Text(json.into())).await.is_err() {
                    break;
                }
            }
        });

        // Incoming channel: WS stream → reader task → caller
        let (frame_tx, frame_rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        tokio::spawn(async move {
            while let Some(msg) = stream.next().await {
                match msg {
                    Ok(Message::Text(text)) => {
                        if frame_tx.send(text.to_string()).is_err() {
                            break;
                        }
                    }
                    Ok(Message::Close(_)) | Err(_) => break,
                    _ => {}
                }
            }
        });

        Ok(Self {
            url: url.to_string(),
            next_id: 1,
            session_id: None,
            sender: Some(send_tx),
            frame_rx: Some(frame_rx),
            pending_events: std::collections::VecDeque::new(),
        })
    }

    // ── Accessors ─────────────────────────────────────────────────────────

    pub fn url(&self) -> &str {
        &self.url
    }

    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    pub fn is_connected(&self) -> bool {
        self.sender.is_some()
    }

    // ── Internal helpers ──────────────────────────────────────────────────

    /// Increment and return the next JSON-RPC request ID.
    pub fn next_request_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Send a raw JSON string to the agent.
    pub fn send_raw(&self, json: &str) -> Result<()> {
        self.sender
            .as_ref()
            .ok_or_else(|| anyhow!("ACP client not connected"))?
            .send(json.to_string())
            .map_err(|_| anyhow!("ACP sender closed"))
    }

    /// Read frames from the WebSocket channel until a JSON-RPC response with
    /// the matching `id` arrives.  Frames that are not this response are stored
    /// in `pending_events` so `try_recv_event` can return them later.
    async fn wait_response(
        &mut self,
        id: u64,
        timeout_ms: u64,
    ) -> Result<JsonRpcResponse> {
        use tokio::time::{Duration, Instant, timeout};

        let deadline = Instant::now() + Duration::from_millis(timeout_ms);

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(anyhow!("ACP timeout waiting for response id={id}"));
            }

            let rx = self
                .frame_rx
                .as_mut()
                .ok_or_else(|| anyhow!("ACP client not connected"))?;

            let raw = timeout(remaining, rx.recv())
                .await
                .map_err(|_| anyhow!("ACP timeout waiting for response id={id}"))?
                .ok_or_else(|| anyhow!("ACP channel closed"))?;

            let val: Value = match serde_json::from_str(&raw) {
                Ok(v) => v,
                Err(_) => continue, // skip malformed frames
            };

            // Match by id field
            if val.get("id").and_then(|v| v.as_u64()) == Some(id) {
                return serde_json::from_str(&raw)
                    .map_err(|e| anyhow!("Failed to parse ACP response: {e}"));
            }

            // Not our response — buffer as pending event
            self.pending_events.push_back(raw);
        }
    }

    // ── ACP handshake ─────────────────────────────────────────────────────

    /// Send `initialize` and return the agent's server info.
    pub async fn initialize(&mut self) -> Result<AcpServerInfo> {
        let id = self.next_request_id();
        let req = build_initialize_request(id);
        self.send_raw(&serde_json::to_string(&req)?)?;
        let resp = self.wait_response(id, 5000).await?;
        parse_initialize_response(&resp)
    }

    /// Create a new session and store the returned session ID.
    pub async fn new_session(&mut self) -> Result<String> {
        let id = self.next_request_id();
        let req = build_new_session_request(id);
        self.send_raw(&serde_json::to_string(&req)?)?;
        let resp = self.wait_response(id, 5000).await?;
        let session_id = parse_new_session_response(&resp)?;
        self.session_id = Some(session_id.clone());
        Ok(session_id)
    }

    /// Send a text prompt into the current session.
    ///
    /// This is fire-and-forget — responses arrive as notifications and are
    /// surfaced via `try_recv_event`.
    pub fn send_prompt(&mut self, text: &str) -> Result<()> {
        let session_id = self
            .session_id
            .as_deref()
            .ok_or_else(|| anyhow!("No active ACP session — call new_session() first"))?
            .to_string();
        let id = self.next_request_id();
        let req = build_prompt_request(id, &session_id, text);
        self.send_raw(&serde_json::to_string(&req)?)
    }

    /// Send a cancel request for the current session.
    pub fn cancel(&mut self) -> Result<()> {
        let session_id = self
            .session_id
            .as_deref()
            .ok_or_else(|| anyhow!("No active ACP session"))?
            .to_string();
        let id = self.next_request_id();
        let req = build_cancel_request(id, &session_id);
        self.send_raw(&serde_json::to_string(&req)?)
    }

    // ── Event polling ─────────────────────────────────────────────────────

    /// Non-blocking poll for the next agent event.
    ///
    /// Drains `pending_events` first, then reads from the WebSocket channel.
    /// Returns `None` if no events are currently available.
    pub fn try_recv_event(&mut self) -> Option<AgentEvent> {
        // Drain buffered events from wait_response first
        while let Some(raw) = self.pending_events.pop_front() {
            if let Ok(Some(event)) = parse_event_from_json(&raw) {
                return Some(event);
            }
        }

        // Then drain the live channel
        loop {
            let rx = self.frame_rx.as_mut()?;
            match rx.try_recv() {
                Ok(raw) => {
                    if let Ok(Some(event)) = parse_event_from_json(&raw) {
                        return Some(event);
                    }
                    // Ordinary ACK responses (id present, no error) → skip
                }
                Err(_) => return None,
            }
        }
    }

    /// Drain ALL currently available events into a Vec.  Useful in the TUI
    /// poll loop where we want to forward everything in one shot.
    pub fn drain_events(&mut self) -> Vec<AgentEvent> {
        let mut events = Vec::new();
        while let Some(e) = self.try_recv_event() {
            events.push(e);
        }
        events
    }
}

impl Default for AcpClient {
    fn default() -> Self {
        Self {
            url: String::new(),
            next_id: 1,
            session_id: None,
            sender: None,
            frame_rx: None,
            pending_events: std::collections::VecDeque::new(),
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_client::AgentKind;

    // ── build_* helpers ───────────────────────────────────────────────────

    #[test]
    fn test_build_initialize_has_correct_method() {
        let req = build_initialize_request(1);
        assert_eq!(req.method, "initialize");
        assert_eq!(req.id, 1);
        assert_eq!(req.jsonrpc, "2.0");
    }

    #[test]
    fn test_build_initialize_includes_protocol_version() {
        let req = build_initialize_request(1);
        let params = req.params.unwrap();
        assert_eq!(params["protocolVersion"], "0.1");
        assert_eq!(params["clientInfo"]["name"], "atem");
    }

    #[test]
    fn test_build_new_session() {
        let req = build_new_session_request(2);
        assert_eq!(req.method, "session/new");
        assert_eq!(req.id, 2);
    }

    #[test]
    fn test_build_prompt() {
        let req = build_prompt_request(3, "sess-abc", "hello world");
        assert_eq!(req.method, "session/prompt");
        assert_eq!(req.id, 3);
        let p = req.params.unwrap();
        assert_eq!(p["sessionId"], "sess-abc");
        assert_eq!(p["text"], "hello world");
    }

    #[test]
    fn test_build_cancel() {
        let req = build_cancel_request(4, "sess-abc");
        assert_eq!(req.method, "session/cancel");
        let p = req.params.unwrap();
        assert_eq!(p["sessionId"], "sess-abc");
    }

    #[test]
    fn test_request_serializes_to_valid_json() {
        let req = build_prompt_request(5, "sess-1", "write a test");
        let json = serde_json::to_string(&req).unwrap();
        let value: Value = serde_json::from_str(&json).unwrap();
        assert_eq!(value["jsonrpc"], "2.0");
        assert_eq!(value["method"], "session/prompt");
        assert_eq!(value["id"], 5);
        assert_eq!(value["params"]["text"], "write a test");
    }

    // ── parse_initialize_response ─────────────────────────────────────────

    #[test]
    fn test_parse_initialize_claude_code() {
        let resp = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: 1,
            result: Some(serde_json::json!({
                "serverInfo": { "name": "claude-code", "version": "1.2.3" },
                "capabilities": {}
            })),
            error: None,
        };
        let info = parse_initialize_response(&resp).unwrap();
        assert_eq!(info.kind, AgentKind::ClaudeCode);
        assert_eq!(info.version, "1.2.3");
    }

    #[test]
    fn test_parse_initialize_codex() {
        let resp = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: 1,
            result: Some(serde_json::json!({
                "serverInfo": { "name": "openai-codex", "version": "0.9" }
            })),
            error: None,
        };
        let info = parse_initialize_response(&resp).unwrap();
        assert_eq!(info.kind, AgentKind::Codex);
    }

    #[test]
    fn test_parse_initialize_unknown_agent() {
        let resp = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: 1,
            result: Some(serde_json::json!({
                "serverInfo": { "name": "gemini-cli", "version": "1.0" }
            })),
            error: None,
        };
        let info = parse_initialize_response(&resp).unwrap();
        assert_eq!(info.kind, AgentKind::Unknown("gemini-cli".into()));
    }

    #[test]
    fn test_parse_initialize_missing_server_info() {
        let resp = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: 1,
            result: Some(serde_json::json!({ "capabilities": {} })),
            error: None,
        };
        assert!(parse_initialize_response(&resp).is_err());
    }

    #[test]
    fn test_parse_initialize_no_result() {
        let resp = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: 1,
            result: None,
            error: Some(JsonRpcError {
                code: -32600,
                message: "Internal error".into(),
                data: None,
            }),
        };
        assert!(parse_initialize_response(&resp).is_err());
    }

    // ── parse_new_session_response ────────────────────────────────────────

    #[test]
    fn test_parse_new_session_returns_id() {
        let resp = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: 2,
            result: Some(serde_json::json!({ "sessionId": "sess-xyz789" })),
            error: None,
        };
        let id = parse_new_session_response(&resp).unwrap();
        assert_eq!(id, "sess-xyz789");
    }

    #[test]
    fn test_parse_new_session_missing_field() {
        let resp = JsonRpcResponse {
            jsonrpc: "2.0".into(),
            id: 2,
            result: Some(serde_json::json!({ "other": "field" })),
            error: None,
        };
        assert!(parse_new_session_response(&resp).is_err());
    }

    // ── parse_event_from_json ─────────────────────────────────────────────

    #[test]
    fn test_parse_text_notification() {
        let raw = r#"{"jsonrpc":"2.0","method":"message","params":{"type":"text","content":"hello"}}"#;
        let event = parse_event_from_json(raw).unwrap().unwrap();
        assert!(matches!(event, AgentEvent::TextDelta(t) if t == "hello"));
    }

    #[test]
    fn test_parse_tool_use_notification() {
        let raw = r#"{
            "jsonrpc":"2.0","method":"message",
            "params":{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"ls"}}
        }"#;
        let event = parse_event_from_json(raw).unwrap().unwrap();
        match event {
            AgentEvent::ToolCall { id, name, input } => {
                assert_eq!(id, "toolu_1");
                assert_eq!(name, "Bash");
                assert_eq!(input["command"], "ls");
            }
            _ => panic!("expected ToolCall"),
        }
    }

    #[test]
    fn test_parse_tool_result_notification() {
        let raw = r#"{
            "jsonrpc":"2.0","method":"message",
            "params":{"type":"tool_result","id":"toolu_1","output":"file1.txt\nfile2.txt"}
        }"#;
        let event = parse_event_from_json(raw).unwrap().unwrap();
        assert!(
            matches!(event, AgentEvent::ToolResult { id, output } if id == "toolu_1" && output.contains("file1"))
        );
    }

    #[test]
    fn test_parse_session_done() {
        let raw =
            r#"{"jsonrpc":"2.0","method":"session/done","params":{"sessionId":"sess-abc"}}"#;
        let event = parse_event_from_json(raw).unwrap().unwrap();
        assert!(matches!(event, AgentEvent::Done));
    }

    #[test]
    fn test_parse_session_error() {
        let raw = r#"{"jsonrpc":"2.0","method":"session/error","params":{"message":"oops"}}"#;
        let event = parse_event_from_json(raw).unwrap().unwrap();
        assert!(matches!(event, AgentEvent::Error(m) if m == "oops"));
    }

    #[test]
    fn test_parse_rpc_error_response() {
        let raw = r#"{"jsonrpc":"2.0","id":3,"error":{"code":-32600,"message":"bad request"}}"#;
        let event = parse_event_from_json(raw).unwrap().unwrap();
        assert!(matches!(event, AgentEvent::Error(m) if m == "bad request"));
    }

    #[test]
    fn test_parse_ordinary_response_returns_none() {
        // A success response (e.g. from session/new) should return None — callers
        // use the dedicated parse_* helpers for those.
        let raw = r#"{"jsonrpc":"2.0","id":2,"result":{"sessionId":"sess-abc"}}"#;
        let event = parse_event_from_json(raw).unwrap();
        assert!(event.is_none());
    }

    #[test]
    fn test_parse_invalid_json_errors() {
        let result = parse_event_from_json("not json");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_unknown_notification_returns_none() {
        let raw = r#"{"jsonrpc":"2.0","method":"unknown/event","params":{}}"#;
        let event = parse_event_from_json(raw).unwrap();
        assert!(event.is_none());
    }

    // ── AcpClient helpers ─────────────────────────────────────────────────

    #[test]
    fn test_client_next_request_id_increments() {
        let mut client = AcpClient::default();
        assert_eq!(client.next_request_id(), 1);
        assert_eq!(client.next_request_id(), 2);
        assert_eq!(client.next_request_id(), 3);
    }

    #[test]
    fn test_client_url() {
        let mut client = AcpClient::default();
        client.url = "ws://localhost:8765".into();
        assert_eq!(client.url(), "ws://localhost:8765");
    }

    #[test]
    fn test_client_session_id_none_initially() {
        let client = AcpClient::default();
        assert!(client.session_id().is_none());
    }

    #[test]
    fn test_client_is_connected_false_by_default() {
        let client = AcpClient::default();
        assert!(!client.is_connected());
    }

    #[test]
    fn test_client_try_recv_with_channel_events() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let mut client = AcpClient {
            frame_rx: Some(rx),
            ..AcpClient::default()
        };

        tx.send(
            r#"{"jsonrpc":"2.0","method":"session/done","params":{"sessionId":"s1"}}"#.into(),
        )
        .unwrap();

        let event = client.try_recv_event().unwrap();
        assert!(matches!(event, AgentEvent::Done));
    }

    #[test]
    fn test_client_try_recv_empty_channel() {
        let (_tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let mut client = AcpClient {
            frame_rx: Some(rx),
            ..AcpClient::default()
        };
        assert!(client.try_recv_event().is_none());
    }

    // ── send_raw ──────────────────────────────────────────────────────────

    #[test]
    fn test_send_raw_not_connected_errors() {
        let client = AcpClient::default();
        assert!(client.send_raw("{}").is_err());
    }

    #[test]
    fn test_send_raw_sends_to_channel() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let client = AcpClient {
            sender: Some(tx),
            ..AcpClient::default()
        };

        client.send_raw(r#"{"hello":"world"}"#).unwrap();
        assert_eq!(rx.try_recv().unwrap(), r#"{"hello":"world"}"#);
    }

    #[test]
    fn test_send_raw_closed_sender_errors() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        drop(rx); // close receiver
        let client = AcpClient {
            sender: Some(tx),
            ..AcpClient::default()
        };
        assert!(client.send_raw("{}").is_err());
    }

    // ── send_prompt ───────────────────────────────────────────────────────

    #[test]
    fn test_send_prompt_without_session_errors() {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let mut client = AcpClient {
            sender: Some(tx),
            ..AcpClient::default()
        };
        assert!(client.send_prompt("hello").is_err());
    }

    #[test]
    fn test_send_prompt_sends_correct_method() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let mut client = AcpClient {
            sender: Some(tx),
            session_id: Some("sess-123".into()),
            ..AcpClient::default()
        };

        client.send_prompt("write a hello world").unwrap();

        let raw = rx.try_recv().unwrap();
        let val: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(val["method"], "session/prompt");
        assert_eq!(val["params"]["sessionId"], "sess-123");
        assert_eq!(val["params"]["text"], "write a hello world");
    }

    #[test]
    fn test_send_prompt_increments_id() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let mut client = AcpClient {
            sender: Some(tx),
            session_id: Some("sess-1".into()),
            ..AcpClient::default()
        };

        client.send_prompt("first").unwrap();
        client.send_prompt("second").unwrap();

        let v1: serde_json::Value = serde_json::from_str(&rx.try_recv().unwrap()).unwrap();
        let v2: serde_json::Value = serde_json::from_str(&rx.try_recv().unwrap()).unwrap();
        let id1 = v1["id"].as_u64().unwrap();
        let id2 = v2["id"].as_u64().unwrap();
        assert!(id2 > id1, "second prompt should have higher id");
    }

    // ── cancel ────────────────────────────────────────────────────────────

    #[test]
    fn test_cancel_without_session_errors() {
        let (tx, _rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let mut client = AcpClient {
            sender: Some(tx),
            ..AcpClient::default()
        };
        assert!(client.cancel().is_err());
    }

    #[test]
    fn test_cancel_sends_cancel_method() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let mut client = AcpClient {
            sender: Some(tx),
            session_id: Some("sess-99".into()),
            ..AcpClient::default()
        };

        client.cancel().unwrap();
        let raw = rx.try_recv().unwrap();
        let val: serde_json::Value = serde_json::from_str(&raw).unwrap();
        assert_eq!(val["method"], "session/cancel");
        assert_eq!(val["params"]["sessionId"], "sess-99");
    }

    // ── drain_events ──────────────────────────────────────────────────────

    #[test]
    fn test_drain_events_returns_all() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let mut client = AcpClient {
            frame_rx: Some(rx),
            ..AcpClient::default()
        };

        tx.send(r#"{"jsonrpc":"2.0","method":"message","params":{"type":"text","content":"A"}}"#.into()).unwrap();
        tx.send(r#"{"jsonrpc":"2.0","method":"message","params":{"type":"text","content":"B"}}"#.into()).unwrap();
        tx.send(r#"{"jsonrpc":"2.0","method":"session/done","params":{}}"#.into()).unwrap();

        let events = client.drain_events();
        assert_eq!(events.len(), 3);
        assert!(matches!(&events[0], AgentEvent::TextDelta(t) if t == "A"));
        assert!(matches!(&events[1], AgentEvent::TextDelta(t) if t == "B"));
        assert!(matches!(&events[2], AgentEvent::Done));
    }

    #[test]
    fn test_drain_events_drains_pending_first() {
        let (_tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let mut client = AcpClient {
            frame_rx: Some(rx),
            pending_events: std::collections::VecDeque::from([
                r#"{"jsonrpc":"2.0","method":"session/done","params":{}}"#.to_string(),
            ]),
            ..AcpClient::default()
        };

        let events = client.drain_events();
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], AgentEvent::Done));
    }

    #[test]
    fn test_drain_events_skips_ack_responses() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let mut client = AcpClient {
            frame_rx: Some(rx),
            ..AcpClient::default()
        };

        // This is an ordinary success ACK — should be silently dropped
        tx.send(r#"{"jsonrpc":"2.0","id":3,"result":{}}"#.into()).unwrap();
        tx.send(r#"{"jsonrpc":"2.0","method":"session/done","params":{}}"#.into()).unwrap();

        let events = client.drain_events();
        // Only the Done event; the ACK is skipped
        assert_eq!(events.len(), 1);
        assert!(matches!(events[0], AgentEvent::Done));
    }

    // ── Mock WS integration test ──────────────────────────────────────────

    /// Spin up a minimal WS echo server, connect an AcpClient, push a
    /// notification frame through it, and verify it surfaces as an event.
    #[tokio::test]
    async fn test_connect_and_recv_event_via_mock_server() {
        use futures_util::{SinkExt, StreamExt};
        use tokio::net::TcpListener;
        use tokio_tungstenite::tungstenite::Message;

        // Bind on an OS-assigned port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        // Server task: accept one connection, send a session/done notification
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            let notification = r#"{"jsonrpc":"2.0","method":"session/done","params":{"sessionId":"s1"}}"#;
            ws.send(Message::Text(notification.into())).await.unwrap();
            // Keep connection open long enough for the client to read
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        // Give the server a moment to start
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let url = format!("ws://127.0.0.1:{port}");
        let mut client = AcpClient::connect(&url).await.unwrap();
        assert!(client.is_connected());

        // Wait a bit for the notification to arrive
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let event = client.try_recv_event().unwrap();
        assert!(matches!(event, AgentEvent::Done));
    }

    #[tokio::test]
    async fn test_send_raw_reaches_server() {
        use futures_util::{SinkExt, StreamExt};
        use tokio::net::TcpListener;
        use tokio::sync::oneshot;
        use tokio_tungstenite::tungstenite::Message;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = oneshot::channel::<String>();

        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            if let Some(Ok(Message::Text(text))) = ws.next().await {
                let _ = tx.send(text.to_string());
            }
        });

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        let url = format!("ws://127.0.0.1:{port}");
        let client = AcpClient::connect(&url).await.unwrap();

        client.send_raw(r#"{"test":"payload"}"#).unwrap();

        let received = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            rx,
        ).await.unwrap().unwrap();

        assert_eq!(received, r#"{"test":"payload"}"#);
    }
}

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
/// After construction (via [`AcpClient::connect`]) call [`initialize`] then
/// [`new_session`] before sending any prompts.  Events are read with
/// [`next_event`].
pub struct AcpClient {
    url: String,
    next_id: u64,
    session_id: Option<String>,
    // The WebSocket sink/stream are boxed to decouple from tungstenite types.
    // They are set by `connect()`.
    sink: Option<Box<dyn tokio::io::AsyncWrite + Send + Unpin>>,
    // We store raw JSON frames in a channel so `next_event` is non-blocking.
    event_rx: Option<tokio::sync::mpsc::UnboundedReceiver<String>>,
}

impl AcpClient {
    /// Return the URL this client is connected to (for display / logging).
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Return the current session ID (set after `new_session`).
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }

    /// Increment and return the next JSON-RPC request ID.
    pub fn next_request_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    /// Try to drain one pending event from the internal channel without
    /// blocking.  Returns `None` if no events are queued.
    ///
    /// This is used in tests and polling loops where async is unavailable.
    pub fn try_recv_event(&mut self) -> Option<AgentEvent> {
        let rx = self.event_rx.as_mut()?;
        let raw = rx.try_recv().ok()?;
        parse_event_from_json(&raw).ok().flatten()
    }
}

impl Default for AcpClient {
    fn default() -> Self {
        Self {
            url: String::new(),
            next_id: 1,
            session_id: None,
            sink: None,
            event_rx: None,
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
    fn test_client_try_recv_with_channel_events() {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<String>();
        let mut client = AcpClient {
            event_rx: Some(rx),
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
            event_rx: Some(rx),
            ..AcpClient::default()
        };
        assert!(client.try_recv_event().is_none());
    }
}

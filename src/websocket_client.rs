use anyhow::{Result, anyhow};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::config::AtemConfig;

/// Authentication response from Astation
enum AuthResponse {
    Authenticated,
    SessionExpired,
    Denied(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum AstationMessage {
    #[serde(rename = "projectListRequest")]
    ProjectListRequest,

    #[serde(rename = "projectListResponse")]
    ProjectListResponse {
        projects: Vec<AgoraProject>,
        timestamp: String,
    },

    #[serde(rename = "tokenRequest")]
    TokenRequest {
        channel: String,
        uid: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        project_id: Option<String>,
    },

    #[serde(rename = "tokenResponse")]
    TokenResponse {
        token: String,
        channel: String,
        uid: String,
        expires_in: String,
        timestamp: String,
    },

    #[serde(rename = "userCommand")]
    UserCommand {
        command: String,
        context: std::collections::HashMap<String, String>,
    },

    #[serde(rename = "commandResponse")]
    CommandResponse {
        output: String,
        success: bool,
        timestamp: String,
    },

    #[serde(rename = "codexTaskRequest")]
    CodexTaskRequest {
        prompt: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        context: Option<std::collections::HashMap<String, String>>,
    },

    #[serde(rename = "codexTaskResponse")]
    CodexTaskResponse {
        output: String,
        success: bool,
        timestamp: String,
    },

    #[serde(rename = "statusUpdate")]
    StatusUpdate {
        status: String,
        data: std::collections::HashMap<String, String>,
    },

    #[serde(rename = "systemStatusRequest")]
    SystemStatusRequest,

    #[serde(rename = "systemStatusResponse")]
    SystemStatusResponse {
        status: SystemStatus,
        timestamp: String,
    },

    #[serde(rename = "claudeLaunchRequest")]
    ClaudeLaunchRequest {
        #[serde(skip_serializing_if = "Option::is_none")]
        context: Option<String>,
    },

    #[serde(rename = "claudeLaunchResponse")]
    ClaudeLaunchResponse {
        success: bool,
        message: String,
        timestamp: String,
    },

    #[serde(rename = "volume_update")]
    VolumeUpdate { level: f32 },

    #[serde(rename = "heartbeat")]
    Heartbeat { timestamp: String },

    #[serde(rename = "pong")]
    Pong { timestamp: String },

    #[serde(rename = "voice_toggle")]
    VoiceToggle { active: bool },

    #[serde(rename = "video_toggle")]
    VideoToggle { active: bool },

    #[serde(rename = "atem_instance_list")]
    AtemInstanceList { instances: Vec<AtemInstance> },

    #[serde(rename = "voiceCommand")]
    VoiceCommand {
        text: String,
        /// true = final chunk (trigger word detected by sender), false = partial
        #[serde(default)]
        is_final: bool,
    },

    #[serde(rename = "markTaskAssignment")]
    MarkTaskAssignment {
        #[serde(rename = "taskId")]
        task_id: String,
        #[serde(default, rename = "receivedAtMs")]
        received_at_ms: u64,
    },

    #[serde(rename = "markTaskResult")]
    MarkTaskResult {
        #[serde(rename = "taskId")]
        task_id: String,
        success: bool,
        message: String,
    },

    // ── Agent hub messages ────────────────────────────────────────────────

    /// Astation → Atem: request the list of connected agents.
    #[serde(rename = "agentListRequest")]
    AgentListRequest,

    /// Atem → Astation: snapshot of all registered agents.
    #[serde(rename = "agentListResponse")]
    AgentListResponse {
        agents: Vec<crate::agent_client::AgentInfo>,
    },

    /// Astation → Atem: send a text prompt to a specific agent.
    #[serde(rename = "agentPrompt")]
    AgentPrompt {
        agent_id: String,
        session_id: String,
        text: String,
    },

    /// Atem → Astation: a streaming event from an agent.
    ///
    /// `event_type` is one of: `"text_delta"`, `"tool_call"`,
    /// `"tool_result"`, `"done"`, `"error"`, `"disconnected"`.
    #[serde(rename = "agentEvent")]
    AgentEventMsg {
        agent_id: String,
        session_id: String,
        event_type: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        text: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        data: Option<serde_json::Value>,
    },

    /// Atem → Astation: an agent's status changed.
    #[serde(rename = "agentStatusUpdate")]
    AgentStatusUpdate {
        agent_id: String,
        status: crate::agent_client::AgentStatus,
    },

    // ── Visual Explainer messages ─────────────────────────────────────────

    /// Astation → Atem: generate a visual HTML explanation.
    #[serde(rename = "generateExplainer")]
    GenerateExplainer {
        /// The topic or concept to explain.
        topic: String,
        /// Optional context (agent output, code snippet, etc.).
        #[serde(skip_serializing_if = "Option::is_none")]
        context: Option<String>,
        /// Optional request ID so the response can be correlated.
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
    },

    /// Astation → Atem: Agora REST API credentials for use without env vars.
    /// Priority: synced (this) > env vars > config file.
    #[serde(rename = "credentialSync")]
    CredentialSync {
        #[serde(rename = "customer_id")]
        customer_id: String,
        #[serde(rename = "customer_secret")]
        customer_secret: String,
    },

    /// Atem → Astation: the generated HTML page.
    #[serde(rename = "explainerResult")]
    ExplainerResult {
        /// Matches the request_id from GenerateExplainer (if provided).
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
        /// The complete self-contained HTML string.
        html: String,
        /// The topic that was explained.
        topic: String,
        success: bool,
        #[serde(skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgoraProject {
    pub id: String,
    pub name: String,
    pub description: String,
    pub created_at: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    pub connected_clients: i32,
    pub claude_running: bool,
    pub uptime_seconds: u64,
    pub projects: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtemInstance {
    pub id: String,
    pub hostname: String,
    pub tag: String,
    pub is_focused: bool,
}

pub struct AstationClient {
    sender: Option<mpsc::UnboundedSender<AstationMessage>>,
    receiver: Option<mpsc::UnboundedReceiver<AstationMessage>>,
}

impl AstationClient {
    pub fn new() -> Self {
        Self {
            sender: None,
            receiver: None,
        }
    }

    /// Connect to Astation using a saved auth session.
    /// Connect with session (now handled via message-based auth)
    /// This is now just an alias for connect() since auth happens after connection.
    pub async fn connect_with_session(&mut self, base_url: &str, _session_id: &str) -> Result<()> {
        // Session auth now happens inside connect() via authenticate()
        // The session_id parameter is ignored - session is loaded from disk
        self.connect(base_url).await
    }

    pub async fn connect(&mut self, url: &str) -> Result<()> {
        let (ws_stream, _) = tokio::time::timeout(Duration::from_secs(5), connect_async(url))
            .await
            .map_err(|_| anyhow!("WebSocket connection timed out after 5s"))?
            .map_err(|e| anyhow!("Failed to connect to WebSocket: {}", e))?;

        let (mut write, mut read) = ws_stream.split();
        let (tx, rx) = mpsc::unbounded_channel::<AstationMessage>();
        let (msg_tx, mut msg_rx) = mpsc::unbounded_channel::<AstationMessage>();

        // Spawn task to handle outgoing messages
        tokio::spawn(async move {
            while let Some(message) = msg_rx.recv().await {
                if let Ok(json) = serde_json::to_string(&message) {
                    if let Err(_) = write.send(Message::Text(json)).await {
                        break;
                    }
                }
            }
        });

        // Spawn task to handle incoming messages
        tokio::spawn(async move {
            while let Some(message) = read.next().await {
                match message {
                    Ok(Message::Text(text)) => {
                        if let Ok(astation_msg) = serde_json::from_str::<AstationMessage>(&text) {
                            if let Err(_) = tx.send(astation_msg) {
                                break; // Receiver has been dropped
                            }
                        }
                    }
                    Ok(Message::Close(_)) => {
                        break;
                    }
                    Err(_) => {
                        break;
                    }
                    _ => {}
                }
            }
        });

        self.sender = Some(msg_tx);
        self.receiver = Some(rx);

        // Perform authentication handshake
        self.authenticate().await?;

        Ok(())
    }

    /// Authenticate with Astation after WebSocket connection.
    /// Waits for auth_required, then sends session ID or pairing code.
    async fn authenticate(&mut self) -> Result<()> {
        // Wait for auth_required message (with timeout)
        let auth_required = tokio::time::timeout(
            Duration::from_secs(5),
            self.wait_for_message(|msg| {
                matches!(msg, AstationMessage::StatusUpdate { status, .. } if status == "auth_required")
            })
        )
        .await
        .map_err(|_| anyhow!("Timeout waiting for auth_required"))?
        .ok_or_else(|| anyhow!("Connection closed before auth_required"))?;

        // Extract astation_id from auth_required message
        let astation_id = if let AstationMessage::StatusUpdate { data, .. } = &auth_required {
            data.get("astation_id")
                .ok_or_else(|| anyhow!("auth_required missing astation_id"))?
                .clone()
        } else {
            return Err(anyhow!("Invalid auth_required message"));
        };

        // Load session manager
        let mut session_mgr = crate::auth::SessionManager::load()
            .unwrap_or_default();

        // Try session-based auth first if we have a saved session for this Astation
        if let Some(session) = session_mgr.get(&astation_id) {
            // Send session auth
            let mut auth_data = std::collections::HashMap::new();
            auth_data.insert("session_id".to_string(), session.session_id.clone());

            let auth_msg = AstationMessage::StatusUpdate {
                status: "auth".to_string(),
                data: auth_data,
            };
            self.send_message(auth_msg).await?;

            // Wait for response
            if let Some(response) = self.wait_for_auth_response(&astation_id).await? {
                match response {
                    AuthResponse::Authenticated => {
                        // Session auth successful - refresh and save
                        if let Some(session) = session_mgr.get_mut(&astation_id) {
                            session.refresh();
                            let _ = session_mgr.save();
                        }
                        return Ok(());
                    }
                    AuthResponse::SessionExpired => {
                        // Fall through to pairing
                    }
                    AuthResponse::Denied(msg) => {
                        return Err(anyhow!("Authentication denied: {}", msg));
                    }
                }
            }
        }

        // Session auth failed or no session - use pairing
        self.authenticate_with_pairing(&astation_id).await
    }

    /// Authenticate using pairing code (fallback when session invalid/missing)
    async fn authenticate_with_pairing(&mut self, astation_id: &str) -> Result<()> {
        // Generate pairing code
        let pairing_code = crate::auth::generate_otp();
        let hostname = crate::auth::get_hostname();

        println!("🔐 Pairing with Astation...");
        println!("   Code: {}", pairing_code);
        println!("   Waiting for approval...");

        // Send pairing auth
        let mut auth_data = std::collections::HashMap::new();
        auth_data.insert("pairing_code".to_string(), pairing_code.clone());
        auth_data.insert("hostname".to_string(), hostname.clone());

        let auth_msg = AstationMessage::StatusUpdate {
            status: "auth".to_string(),
            data: auth_data,
        };
        self.send_message(auth_msg).await?;

        // Wait for pairing response (longer timeout for user to approve)
        let response = tokio::time::timeout(
            Duration::from_secs(300), // 5 minutes for user to approve
            self.wait_for_auth_response(astation_id)
        )
        .await
        .map_err(|_| anyhow!("Pairing timed out after 5 minutes"))??;

        match response {
            Some(AuthResponse::Authenticated) => {
                println!("✅ Pairing approved!");
                Ok(())
            }
            Some(AuthResponse::Denied(msg)) => {
                println!("❌ Pairing denied: {}", msg);
                Err(anyhow!("Pairing denied: {}", msg))
            }
            Some(AuthResponse::SessionExpired) => {
                Err(anyhow!("Unexpected session_expired during pairing"))
            }
            None => {
                Err(anyhow!("Connection closed during pairing"))
            }
        }
    }

    /// Wait for auth response message and extract session if granted
    async fn wait_for_auth_response(&mut self, astation_id: &str) -> Result<Option<AuthResponse>> {
        while let Some(msg) = self.recv_message_async().await {
            match msg {
                AstationMessage::StatusUpdate { status, data } if status == "auth" => {
                    // Check auth response
                    if let Some(auth_status) = data.get("status") {
                        match auth_status.as_str() {
                            "granted" => {
                                // Save new session if provided
                                if let (Some(session_id), Some(token)) =
                                    (data.get("session_id"), data.get("token"))
                                {
                                    let hostname = crate::auth::get_hostname();
                                    let session = crate::auth::AuthSession::new(
                                        session_id.clone(),
                                        token.clone(),
                                        astation_id.to_string(),
                                        hostname,
                                    );

                                    // Save to session manager
                                    let mut session_mgr = crate::auth::SessionManager::load()
                                        .unwrap_or_default();
                                    let _ = session_mgr.save_session(session);
                                }
                                return Ok(Some(AuthResponse::Authenticated));
                            }
                            "denied" => {
                                let msg = data.get("message")
                                    .map(|s| s.as_str())
                                    .unwrap_or("Unknown reason");
                                return Ok(Some(AuthResponse::Denied(msg.to_string())));
                            }
                            _ => {}
                        }
                    }
                }
                AstationMessage::StatusUpdate { status, data: _ } if status == "authenticated" => {
                    // Alternative authenticated message format
                    return Ok(Some(AuthResponse::Authenticated));
                }
                AstationMessage::StatusUpdate { status, data } if status == "error" => {
                    if let Some(msg) = data.get("message") {
                        if msg.contains("expired") || msg.contains("Session expired") {
                            return Ok(Some(AuthResponse::SessionExpired));
                        }
                        return Ok(Some(AuthResponse::Denied(msg.clone())));
                    }
                }
                _ => {
                    // Ignore other messages during auth
                }
            }
        }
        Ok(None) // Connection closed
    }

    /// Wait for a message matching the predicate
    async fn wait_for_message<F>(&mut self, predicate: F) -> Option<AstationMessage>
    where
        F: Fn(&AstationMessage) -> bool,
    {
        while let Some(msg) = self.recv_message_async().await {
            if predicate(&msg) {
                return Some(msg);
            }
        }
        None
    }

    pub async fn send_message(&self, message: AstationMessage) -> Result<()> {
        if let Some(sender) = &self.sender {
            sender
                .send(message)
                .map_err(|e| anyhow!("Failed to send message: {}", e))?;
        } else {
            return Err(anyhow!("Not connected to Astation"));
        }
        Ok(())
    }

    /// Non-blocking: returns a message if one is already queued, None otherwise.
    pub fn recv_message(&mut self) -> Option<AstationMessage> {
        if let Some(receiver) = &mut self.receiver {
            receiver.try_recv().ok()
        } else {
            None
        }
    }

    /// Blocking: waits until a message arrives (for CLI use only, not the TUI loop).
    pub async fn recv_message_async(&mut self) -> Option<AstationMessage> {
        if let Some(receiver) = &mut self.receiver {
            receiver.recv().await
        } else {
            None
        }
    }

    pub async fn request_projects(&self) -> Result<()> {
        self.send_message(AstationMessage::ProjectListRequest).await
    }

    pub async fn request_token(
        &self,
        channel: &str,
        uid: &str,
        project_id: Option<String>,
    ) -> Result<()> {
        let message = AstationMessage::TokenRequest {
            channel: channel.to_string(),
            uid: uid.to_string(),
            project_id,
        };
        self.send_message(message).await
    }

    pub async fn launch_claude(&self, context: Option<String>) -> Result<()> {
        let message = AstationMessage::ClaudeLaunchRequest { context };
        self.send_message(message).await
    }

    pub async fn send_user_command(
        &self,
        command: &str,
        context: std::collections::HashMap<String, String>,
    ) -> Result<()> {
        let message = AstationMessage::UserCommand {
            command: command.to_string(),
            context,
        };
        self.send_message(message).await
    }

    pub async fn send_status_update(&self, status: &str) -> Result<()> {
        let mut data = std::collections::HashMap::new();
        data.insert("client_type".to_string(), "Atem".to_string());
        data.insert("version".to_string(), "0.1.0".to_string());

        let message = AstationMessage::StatusUpdate {
            status: status.to_string(),
            data,
        };
        self.send_message(message).await
    }

    pub async fn send_heartbeat(&self) -> Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();

        let message = AstationMessage::Heartbeat { timestamp };
        self.send_message(message).await
    }

    pub fn is_connected(&self) -> bool {
        self.sender.is_some() && self.receiver.is_some()
    }

    pub async fn send_mark_result(
        &self,
        task_id: &str,
        success: bool,
        message: &str,
    ) -> Result<()> {
        let msg = AstationMessage::MarkTaskResult {
            task_id: task_id.to_string(),
            success,
            message: message.to_string(),
        };
        self.send_message(msg).await
    }

    pub async fn send_codex_task(
        &self,
        prompt: &str,
        context: Option<std::collections::HashMap<String, String>>,
    ) -> Result<()> {
        let message = AstationMessage::CodexTaskRequest {
            prompt: prompt.to_string(),
            context,
        };
        self.send_message(message).await
    }

    /// Reply to an `agentListRequest` with all currently registered agents.
    pub async fn send_agent_list(
        &self,
        agents: Vec<crate::agent_client::AgentInfo>,
    ) -> Result<()> {
        self.send_message(AstationMessage::AgentListResponse { agents }).await
    }

    /// Stream an agent event to Astation.
    pub async fn send_agent_event(
        &self,
        agent_id: &str,
        session_id: &str,
        event: &crate::agent_client::AgentEvent,
    ) -> Result<()> {
        use crate::agent_client::AgentEvent;
        let (event_type, text, data) = match event {
            AgentEvent::TextDelta(t) => {
                ("text_delta".to_string(), Some(t.clone()), None)
            }
            AgentEvent::ToolCall { id, name, input } => (
                "tool_call".to_string(),
                None,
                Some(serde_json::json!({ "id": id, "name": name, "input": input })),
            ),
            AgentEvent::ToolResult { id, output } => (
                "tool_result".to_string(),
                None,
                Some(serde_json::json!({ "id": id, "output": output })),
            ),
            AgentEvent::Done => ("done".to_string(), None, None),
            AgentEvent::Error(msg) => ("error".to_string(), Some(msg.clone()), None),
            AgentEvent::Disconnected => ("disconnected".to_string(), None, None),
        };

        self.send_message(AstationMessage::AgentEventMsg {
            agent_id: agent_id.to_string(),
            session_id: session_id.to_string(),
            event_type,
            text,
            data,
        })
        .await
    }

    /// Notify Astation that an agent's status has changed.
    pub async fn send_agent_status(
        &self,
        agent_id: &str,
        status: crate::agent_client::AgentStatus,
    ) -> Result<()> {
        self.send_message(AstationMessage::AgentStatusUpdate {
            agent_id: agent_id.to_string(),
            status,
        })
        .await
    }

    /// Send a generated explainer page back to Astation.
    pub async fn send_explainer_result(
        &self,
        request_id: Option<String>,
        topic: &str,
        html: &str,
    ) -> Result<()> {
        self.send_message(AstationMessage::ExplainerResult {
            request_id,
            html: html.to_string(),
            topic: topic.to_string(),
            success: true,
            error: None,
        })
        .await
    }

    /// Send an explainer error back to Astation.
    pub async fn send_explainer_error(
        &self,
        request_id: Option<String>,
        topic: &str,
        error: &str,
    ) -> Result<()> {
        self.send_message(AstationMessage::ExplainerResult {
            request_id,
            html: String::new(),
            topic: topic.to_string(),
            success: false,
            error: Some(error.to_string()),
        })
        .await
    }

    /// Register with the relay service to get a pairing code, then connect.
    ///
    /// Flow:
    /// 1. POST to relay /api/pair → get pairing code
    /// 2. Try local Astation (ws://127.0.0.1:8080/ws)
    /// 3. If local fails → fall back to relay WebSocket
    ///
    /// Returns the pairing code on success.
    pub async fn connect_with_pairing(&mut self, config: &AtemConfig) -> Result<String> {
        let station_url = config.astation_relay_url().to_string();

        // 1. Register with relay → get pairing code (5s timeout)
        let code = tokio::time::timeout(
            Duration::from_secs(5),
            self.register_pair(&station_url),
        )
        .await
        .map_err(|_| anyhow!("Relay registration timed out"))??;

        // 2. Try local Astation first
        if self.try_connect_local().await.is_ok() {
            return Ok(code);
        }

        // 3. Fall back to relay
        let ws_scheme = if station_url.starts_with("https://") {
            station_url.replace("https://", "wss://")
        } else {
            station_url.replace("http://", "ws://")
        };
        let ws_url = format!("{}/ws?role=atem&code={}", ws_scheme, code);
        self.connect(&ws_url).await?;
        Ok(code)
    }

    /// Register with the relay service and get a pairing code.
    async fn register_pair(&self, station_url: &str) -> Result<String> {
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap_or_else(|_| reqwest::Client::new());
        let resp = client
            .post(format!("{}/api/pair", station_url))
            .json(&serde_json::json!({"hostname": hostname}))
            .send()
            .await
            .map_err(|e| anyhow!("Failed to register with relay: {}", e))?;

        if !resp.status().is_success() {
            return Err(anyhow!(
                "Relay returned status {}",
                resp.status()
            ));
        }

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| anyhow!("Failed to parse relay response: {}", e))?;

        body.get("code")
            .and_then(|c| c.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| anyhow!("Relay response missing 'code' field"))
    }

    /// Try connecting to a local Astation instance on 127.0.0.1:8080.
    async fn try_connect_local(&mut self) -> Result<()> {
        self.connect("ws://127.0.0.1:8080/ws").await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Serialization round-trip tests ---

    #[test]
    fn project_list_request_serializes() {
        let msg = AstationMessage::ProjectListRequest;
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"projectListRequest\""));
    }

    #[test]
    fn project_list_request_roundtrip() {
        let msg = AstationMessage::ProjectListRequest;
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, AstationMessage::ProjectListRequest));
    }

    #[test]
    fn project_list_response_roundtrip() {
        let msg = AstationMessage::ProjectListResponse {
            projects: vec![AgoraProject {
                id: "p1".into(),
                name: "Test".into(),
                description: "A test project".into(),
                created_at: "2025-01-01".into(),
                status: "active".into(),
            }],
            timestamp: "12345".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::ProjectListResponse {
            projects,
            timestamp,
        } = parsed
        {
            assert_eq!(projects.len(), 1);
            assert_eq!(projects[0].id, "p1");
            assert_eq!(projects[0].name, "Test");
            assert_eq!(timestamp, "12345");
        } else {
            panic!("expected ProjectListResponse");
        }
    }

    #[test]
    fn token_request_serializes_without_project_id() {
        let msg = AstationMessage::TokenRequest {
            channel: "ch1".into(),
            uid: "u1".into(),
            project_id: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(!json.contains("project_id"));
    }

    #[test]
    fn token_request_serializes_with_project_id() {
        let msg = AstationMessage::TokenRequest {
            channel: "ch1".into(),
            uid: "u1".into(),
            project_id: Some("proj_1".into()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("proj_1"));
    }

    #[test]
    fn token_response_roundtrip() {
        let msg = AstationMessage::TokenResponse {
            token: "abc123".into(),
            channel: "ch1".into(),
            uid: "u1".into(),
            expires_in: "3600".into(),
            timestamp: "99999".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::TokenResponse { token, channel, .. } = parsed {
            assert_eq!(token, "abc123");
            assert_eq!(channel, "ch1");
        } else {
            panic!("expected TokenResponse");
        }
    }

    #[test]
    fn claude_launch_request_roundtrip() {
        let msg = AstationMessage::ClaudeLaunchRequest {
            context: Some("fix the bug".into()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::ClaudeLaunchRequest { context } = parsed {
            assert_eq!(context, Some("fix the bug".into()));
        } else {
            panic!("expected ClaudeLaunchRequest");
        }
    }

    #[test]
    fn claude_launch_request_none_context() {
        let msg = AstationMessage::ClaudeLaunchRequest { context: None };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::ClaudeLaunchRequest { context } = parsed {
            assert!(context.is_none());
        } else {
            panic!("expected ClaudeLaunchRequest");
        }
    }

    #[test]
    fn command_response_roundtrip() {
        let msg = AstationMessage::CommandResponse {
            output: "hello world".into(),
            success: true,
            timestamp: "1000".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::CommandResponse {
            output, success, ..
        } = parsed
        {
            assert_eq!(output, "hello world");
            assert!(success);
        } else {
            panic!("expected CommandResponse");
        }
    }

    #[test]
    fn heartbeat_roundtrip() {
        let msg = AstationMessage::Heartbeat {
            timestamp: "555".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::Heartbeat { timestamp } = parsed {
            assert_eq!(timestamp, "555");
        } else {
            panic!("expected Heartbeat");
        }
    }

    #[test]
    fn pong_roundtrip() {
        let msg = AstationMessage::Pong {
            timestamp: "666".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, AstationMessage::Pong { .. }));
    }

    #[test]
    fn system_status_response_roundtrip() {
        let msg = AstationMessage::SystemStatusResponse {
            status: SystemStatus {
                connected_clients: 2,
                claude_running: true,
                uptime_seconds: 3600,
                projects: 5,
            },
            timestamp: "7777".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::SystemStatusResponse { status, .. } = parsed {
            assert_eq!(status.connected_clients, 2);
            assert!(status.claude_running);
            assert_eq!(status.uptime_seconds, 3600);
            assert_eq!(status.projects, 5);
        } else {
            panic!("expected SystemStatusResponse");
        }
    }

    #[test]
    fn codex_task_request_without_context() {
        let msg = AstationMessage::CodexTaskRequest {
            prompt: "write a test".into(),
            context: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(!json.contains("context"));
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::CodexTaskRequest { prompt, context } = parsed {
            assert_eq!(prompt, "write a test");
            assert!(context.is_none());
        } else {
            panic!("expected CodexTaskRequest");
        }
    }

    #[test]
    fn status_update_roundtrip() {
        let mut data = std::collections::HashMap::new();
        data.insert("client_type".to_string(), "Atem".to_string());
        let msg = AstationMessage::StatusUpdate {
            status: "connected".into(),
            data,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::StatusUpdate { status, data } = parsed {
            assert_eq!(status, "connected");
            assert_eq!(data.get("client_type").unwrap(), "Atem");
        } else {
            panic!("expected StatusUpdate");
        }
    }

    // --- AstationClient unit tests ---

    #[test]
    fn new_client_is_not_connected() {
        let client = AstationClient::new();
        assert!(client.sender.is_none());
        assert!(client.receiver.is_none());
    }

    // --- Deserialization from raw JSON ---

    #[test]
    fn deserialize_project_list_request_from_json() {
        let json = r#"{"type":"projectListRequest"}"#;
        let msg: AstationMessage = serde_json::from_str(json).unwrap();
        assert!(matches!(msg, AstationMessage::ProjectListRequest));
    }

    #[test]
    fn deserialize_token_response_from_json() {
        let json = r#"{
            "type": "tokenResponse",
            "data": {
                "token": "tok_abc",
                "channel": "ch",
                "uid": "42",
                "expires_in": "7200",
                "timestamp": "100"
            }
        }"#;
        let msg: AstationMessage = serde_json::from_str(json).unwrap();
        if let AstationMessage::TokenResponse { token, uid, .. } = msg {
            assert_eq!(token, "tok_abc");
            assert_eq!(uid, "42");
        } else {
            panic!("expected TokenResponse");
        }
    }

    #[test]
    fn invalid_type_fails_deserialization() {
        let json = r#"{"type":"unknownMessageType","data":{}}"#;
        let result = serde_json::from_str::<AstationMessage>(json);
        assert!(result.is_err());
    }

    // --- VoiceToggle tests ---

    #[test]
    fn voice_toggle_roundtrip() {
        let msg = AstationMessage::VoiceToggle { active: true };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"voice_toggle""#));
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::VoiceToggle { active } = parsed {
            assert!(active);
        } else {
            panic!("expected VoiceToggle");
        }
    }

    #[test]
    fn voice_toggle_false_roundtrip() {
        let msg = AstationMessage::VoiceToggle { active: false };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::VoiceToggle { active } = parsed {
            assert!(!active);
        } else {
            panic!("expected VoiceToggle");
        }
    }

    #[test]
    fn deserialize_voice_toggle_from_json() {
        let json = r#"{"type":"voice_toggle","data":{"active":true}}"#;
        let msg: AstationMessage = serde_json::from_str(json).unwrap();
        if let AstationMessage::VoiceToggle { active } = msg {
            assert!(active);
        } else {
            panic!("expected VoiceToggle");
        }
    }

    // --- VideoToggle tests ---

    #[test]
    fn video_toggle_roundtrip() {
        let msg = AstationMessage::VideoToggle { active: true };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"video_toggle""#));
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::VideoToggle { active } = parsed {
            assert!(active);
        } else {
            panic!("expected VideoToggle");
        }
    }

    #[test]
    fn video_toggle_false_roundtrip() {
        let msg = AstationMessage::VideoToggle { active: false };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::VideoToggle { active } = parsed {
            assert!(!active);
        } else {
            panic!("expected VideoToggle");
        }
    }

    #[test]
    fn deserialize_video_toggle_from_json() {
        let json = r#"{"type":"video_toggle","data":{"active":false}}"#;
        let msg: AstationMessage = serde_json::from_str(json).unwrap();
        if let AstationMessage::VideoToggle { active } = msg {
            assert!(!active);
        } else {
            panic!("expected VideoToggle");
        }
    }

    // --- AtemInstanceList tests ---

    #[test]
    fn atem_instance_list_roundtrip() {
        let msg = AstationMessage::AtemInstanceList {
            instances: vec![
                AtemInstance {
                    id: "inst-1".into(),
                    hostname: "dev-laptop".into(),
                    tag: "primary".into(),
                    is_focused: true,
                },
                AtemInstance {
                    id: "inst-2".into(),
                    hostname: "build-server".into(),
                    tag: "ci".into(),
                    is_focused: false,
                },
            ],
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::AtemInstanceList { instances } = parsed {
            assert_eq!(instances.len(), 2);
            assert_eq!(instances[0].id, "inst-1");
            assert_eq!(instances[0].hostname, "dev-laptop");
            assert_eq!(instances[0].tag, "primary");
            assert!(instances[0].is_focused);
            assert_eq!(instances[1].id, "inst-2");
            assert!(!instances[1].is_focused);
        } else {
            panic!("expected AtemInstanceList");
        }
    }

    #[test]
    fn atem_instance_list_empty_roundtrip() {
        let msg = AstationMessage::AtemInstanceList {
            instances: vec![],
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::AtemInstanceList { instances } = parsed {
            assert!(instances.is_empty());
        } else {
            panic!("expected AtemInstanceList");
        }
    }

    #[test]
    fn deserialize_atem_instance_list_from_json() {
        let json = "{\"type\": \"atem_instance_list\", \"data\": {\"instances\": [{\"id\": \"a1\", \"hostname\": \"host1\", \"tag\": \"dev\", \"is_focused\": true}]}}";
        let msg: AstationMessage = serde_json::from_str(json).unwrap();
        if let AstationMessage::AtemInstanceList { instances } = msg {
            assert_eq!(instances.len(), 1);
            assert_eq!(instances[0].id, "a1");
        } else {
            panic!("expected AtemInstanceList");
        }
    }

    #[test]
    fn atem_instance_struct_serializes() {
        let inst = AtemInstance {
            id: "test-id".into(),
            hostname: "my-host".into(),
            tag: "main".into(),
            is_focused: false,
        };
        let json = serde_json::to_string(&inst).unwrap();
        assert!(json.contains("test-id"));
        assert!(json.contains("my-host"));
        assert!(json.contains("false"));
    }

    // --- VoiceCommand tests ---

    #[test]
    fn voice_command_roundtrip() {
        let msg = AstationMessage::VoiceCommand {
            text: "fix the login page".into(),
            is_final: false,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"voiceCommand""#));
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::VoiceCommand { text, is_final } = parsed {
            assert_eq!(text, "fix the login page");
            assert!(!is_final);
        } else {
            panic!("expected VoiceCommand");
        }
    }

    #[test]
    fn voice_command_final_roundtrip() {
        let msg = AstationMessage::VoiceCommand {
            text: "execute".into(),
            is_final: true,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::VoiceCommand { text, is_final } = parsed {
            assert_eq!(text, "execute");
            assert!(is_final);
        } else {
            panic!("expected VoiceCommand");
        }
    }

    #[test]
    fn deserialize_voice_command_from_json() {
        let json = r#"{"type":"voiceCommand","data":{"text":"add a button","is_final":false}}"#;
        let msg: AstationMessage = serde_json::from_str(json).unwrap();
        if let AstationMessage::VoiceCommand { text, is_final } = msg {
            assert_eq!(text, "add a button");
            assert!(!is_final);
        } else {
            panic!("expected VoiceCommand");
        }
    }

    #[test]
    fn deserialize_voice_command_without_is_final() {
        // is_final should default to false when missing
        let json = r#"{"type":"voiceCommand","data":{"text":"hello world"}}"#;
        let msg: AstationMessage = serde_json::from_str(json).unwrap();
        if let AstationMessage::VoiceCommand { text, is_final } = msg {
            assert_eq!(text, "hello world");
            assert!(!is_final);
        } else {
            panic!("expected VoiceCommand");
        }
    }

    // --- MarkTaskAssignment / MarkTaskResult tests ---

    #[test]
    fn test_mark_task_assignment_deserialize() {
        let json = r#"{"type":"markTaskAssignment","data":{"taskId":"mark_123_abc","receivedAtMs":1700000000000}}"#;
        let msg: AstationMessage = serde_json::from_str(json).unwrap();
        if let AstationMessage::MarkTaskAssignment { task_id, received_at_ms } = msg {
            assert_eq!(task_id, "mark_123_abc");
            assert_eq!(received_at_ms, 1700000000000);
        } else {
            panic!("expected MarkTaskAssignment");
        }
    }

    #[test]
    fn test_mark_task_assignment_backward_compat() {
        // Old Astation without receivedAtMs — should default to 0
        let json = r#"{"type":"markTaskAssignment","data":{"taskId":"mark_old"}}"#;
        let msg: AstationMessage = serde_json::from_str(json).unwrap();
        if let AstationMessage::MarkTaskAssignment { task_id, received_at_ms } = msg {
            assert_eq!(task_id, "mark_old");
            assert_eq!(received_at_ms, 0);
        } else {
            panic!("expected MarkTaskAssignment");
        }
    }

    #[test]
    fn test_mark_task_result_serialize() {
        let msg = AstationMessage::MarkTaskResult {
            task_id: "mark_456_def".into(),
            success: true,
            message: "All annotations addressed".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"markTaskResult""#));
        assert!(json.contains(r#""taskId":"mark_456_def""#));
        assert!(json.contains(r#""success":true"#));
        assert!(json.contains("All annotations addressed"));
    }

    #[test]
    fn test_mark_task_round_trip() {
        let msg = AstationMessage::MarkTaskResult {
            task_id: "mark_789_ghi".into(),
            success: false,
            message: "Failed to parse task".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::MarkTaskResult {
            task_id,
            success,
            message,
        } = parsed
        {
            assert_eq!(task_id, "mark_789_ghi");
            assert!(!success);
            assert_eq!(message, "Failed to parse task");
        } else {
            panic!("expected MarkTaskResult");
        }
    }

    // --- UserCommand tests ---

    #[test]
    fn test_user_command_roundtrip() {
        let mut context = std::collections::HashMap::new();
        context.insert("action".to_string(), "cli_input".to_string());
        context.insert("source".to_string(), "voice".to_string());
        let msg = AstationMessage::UserCommand {
            command: "fix the bug".into(),
            context,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::UserCommand { command, context } = parsed {
            assert_eq!(command, "fix the bug");
            assert_eq!(context.get("action").unwrap(), "cli_input");
            assert_eq!(context.get("source").unwrap(), "voice");
        } else {
            panic!("expected UserCommand");
        }
    }

    #[test]
    fn test_user_command_with_cli_input_action() {
        let mut context = std::collections::HashMap::new();
        context.insert("action".to_string(), "cli_input".to_string());
        let msg = AstationMessage::UserCommand {
            command: "refactor the module".into(),
            context,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::UserCommand { command, context } = parsed {
            assert_eq!(command, "refactor the module");
            assert_eq!(context.get("action").unwrap(), "cli_input");
        } else {
            panic!("expected UserCommand");
        }
    }

    #[test]
    fn test_user_command_with_shell_action() {
        let mut context = std::collections::HashMap::new();
        context.insert("action".to_string(), "shell".to_string());
        let msg = AstationMessage::UserCommand {
            command: "ls -la".into(),
            context,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::UserCommand { command, context } = parsed {
            assert_eq!(command, "ls -la");
            assert_eq!(context.get("action").unwrap(), "shell");
        } else {
            panic!("expected UserCommand");
        }
    }

    #[test]
    fn test_user_command_with_claude_input_action() {
        let mut context = std::collections::HashMap::new();
        context.insert("action".to_string(), "claude_input".to_string());
        let msg = AstationMessage::UserCommand {
            command: "explain this code".into(),
            context,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::UserCommand { command, context } = parsed {
            assert_eq!(command, "explain this code");
            assert_eq!(context.get("action").unwrap(), "claude_input");
        } else {
            panic!("expected UserCommand");
        }
    }

    #[test]
    fn test_user_command_with_codex_input_action() {
        let mut context = std::collections::HashMap::new();
        context.insert("action".to_string(), "codex_input".to_string());
        let msg = AstationMessage::UserCommand {
            command: "write a test".into(),
            context,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::UserCommand { command, context } = parsed {
            assert_eq!(command, "write a test");
            assert_eq!(context.get("action").unwrap(), "codex_input");
        } else {
            panic!("expected UserCommand");
        }
    }

    #[test]
    fn test_user_command_empty_context() {
        let context = std::collections::HashMap::new();
        let msg = AstationMessage::UserCommand {
            command: "hello".into(),
            context,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::UserCommand { command, context } = parsed {
            assert_eq!(command, "hello");
            assert!(context.is_empty());
        } else {
            panic!("expected UserCommand");
        }
    }

    // ── Agent hub message tests ───────────────────────────────────────────

    fn make_agent_info(id: &str) -> crate::agent_client::AgentInfo {
        use crate::agent_client::{AgentKind, AgentOrigin, AgentProtocol, AgentStatus};
        crate::agent_client::AgentInfo {
            id: id.to_string(),
            name: format!("agent-{id}"),
            kind: AgentKind::ClaudeCode,
            protocol: AgentProtocol::Acp,
            origin: AgentOrigin::Launched,
            status: AgentStatus::Idle,
            session_ids: vec![],
            acp_url: Some("ws://localhost:8765".to_string()),
            pty_pid: None,
        }
    }

    #[test]
    fn agent_list_request_roundtrip() {
        let msg = AstationMessage::AgentListRequest;
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"agentListRequest\""));
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, AstationMessage::AgentListRequest));
    }

    #[test]
    fn agent_list_response_roundtrip() {
        let msg = AstationMessage::AgentListResponse {
            agents: vec![make_agent_info("abc"), make_agent_info("def")],
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::AgentListResponse { agents } = parsed {
            assert_eq!(agents.len(), 2);
            assert_eq!(agents[0].id, "abc");
            assert_eq!(agents[1].id, "def");
        } else {
            panic!("expected AgentListResponse");
        }
    }

    #[test]
    fn agent_list_response_empty() {
        let msg = AstationMessage::AgentListResponse { agents: vec![] };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::AgentListResponse { agents } = parsed {
            assert!(agents.is_empty());
        } else {
            panic!("expected AgentListResponse");
        }
    }

    #[test]
    fn agent_prompt_roundtrip() {
        let msg = AstationMessage::AgentPrompt {
            agent_id: "agent-1".into(),
            session_id: "sess-1".into(),
            text: "write a unit test".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::AgentPrompt {
            agent_id,
            session_id,
            text,
        } = parsed
        {
            assert_eq!(agent_id, "agent-1");
            assert_eq!(session_id, "sess-1");
            assert_eq!(text, "write a unit test");
        } else {
            panic!("expected AgentPrompt");
        }
    }

    #[test]
    fn agent_event_text_delta_roundtrip() {
        let msg = AstationMessage::AgentEventMsg {
            agent_id: "agent-1".into(),
            session_id: "sess-1".into(),
            event_type: "text_delta".into(),
            text: Some("hello world".into()),
            data: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        // The outer "data" content key is always present (serde tagged enum).
        // The inner optional "text" field should be present; inner "data" skipped.
        assert!(json.contains("\"text\""));
        assert!(json.contains("hello world"));
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::AgentEventMsg {
            event_type, text, data, ..
        } = parsed
        {
            assert_eq!(event_type, "text_delta");
            assert_eq!(text.as_deref(), Some("hello world"));
            assert!(data.is_none());
        } else {
            panic!("expected AgentEventMsg");
        }
    }

    #[test]
    fn agent_event_done_roundtrip() {
        let msg = AstationMessage::AgentEventMsg {
            agent_id: "agent-1".into(),
            session_id: "sess-1".into(),
            event_type: "done".into(),
            text: None,
            data: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        // Inner optional "text" and "data" fields should both be omitted.
        assert!(!json.contains("\"text\""));
        // Outer "data" content key is present but inner field should not add another "data"
        let parsed_val: serde_json::Value = serde_json::from_str(&json).unwrap();
        let inner = &parsed_val["data"];
        assert!(inner["text"].is_null());
        assert!(inner["data"].is_null());
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, AstationMessage::AgentEventMsg { .. }));
    }

    #[test]
    fn agent_status_update_roundtrip() {
        use crate::agent_client::AgentStatus;
        let msg = AstationMessage::AgentStatusUpdate {
            agent_id: "agent-1".into(),
            status: AgentStatus::Thinking,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::AgentStatusUpdate { agent_id, status } = parsed {
            assert_eq!(agent_id, "agent-1");
            assert_eq!(status, AgentStatus::Thinking);
        } else {
            panic!("expected AgentStatusUpdate");
        }
    }

    #[test]
    fn agent_list_response_preserves_all_info_fields() {
        let info = make_agent_info("test-id");
        let msg = AstationMessage::AgentListResponse {
            agents: vec![info],
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::AgentListResponse { agents } = parsed {
            let a = &agents[0];
            assert_eq!(a.id, "test-id");
            assert_eq!(a.acp_url.as_deref(), Some("ws://localhost:8765"));
        } else {
            panic!("expected AgentListResponse");
        }
    }

    // ── Visual Explainer message tests ────────────────────────────────────

    #[test]
    fn generate_explainer_roundtrip() {
        let msg = AstationMessage::GenerateExplainer {
            topic: "ACP Protocol".into(),
            context: Some("some context".into()),
            request_id: Some("req-1".into()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains("\"type\":\"generateExplainer\""));
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::GenerateExplainer {
            topic,
            context,
            request_id,
        } = parsed
        {
            assert_eq!(topic, "ACP Protocol");
            assert_eq!(context.as_deref(), Some("some context"));
            assert_eq!(request_id.as_deref(), Some("req-1"));
        } else {
            panic!("expected GenerateExplainer");
        }
    }

    #[test]
    fn generate_explainer_optional_fields_omitted() {
        let msg = AstationMessage::GenerateExplainer {
            topic: "hello".into(),
            context: None,
            request_id: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(!json.contains("\"context\""));
        assert!(!json.contains("\"request_id\""));
    }

    #[test]
    fn explainer_result_success_roundtrip() {
        let msg = AstationMessage::ExplainerResult {
            request_id: Some("req-1".into()),
            html: "<html><body>hi</body></html>".into(),
            topic: "Test".into(),
            success: true,
            error: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::ExplainerResult {
            success,
            html,
            topic,
            error,
            ..
        } = parsed
        {
            assert!(success);
            assert_eq!(html, "<html><body>hi</body></html>");
            assert_eq!(topic, "Test");
            assert!(error.is_none());
        } else {
            panic!("expected ExplainerResult");
        }
    }

    #[test]
    fn credential_sync_roundtrip() {
        let msg = AstationMessage::CredentialSync {
            customer_id: "cid_abc123".into(),
            customer_secret: "csec_xyz789".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"credentialSync""#));
        assert!(json.contains("customer_id"));
        assert!(json.contains("customer_secret"));
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::CredentialSync {
            customer_id,
            customer_secret,
        } = parsed
        {
            assert_eq!(customer_id, "cid_abc123");
            assert_eq!(customer_secret, "csec_xyz789");
        } else {
            panic!("expected CredentialSync");
        }
    }

    #[test]
    fn credential_sync_deserialize_from_json() {
        let json = r#"{"type":"credentialSync","data":{"customer_id":"my_id","customer_secret":"my_secret"}}"#;
        let msg: AstationMessage = serde_json::from_str(json).unwrap();
        if let AstationMessage::CredentialSync {
            customer_id,
            customer_secret,
        } = msg
        {
            assert_eq!(customer_id, "my_id");
            assert_eq!(customer_secret, "my_secret");
        } else {
            panic!("expected CredentialSync");
        }
    }

    #[test]
    fn explainer_result_error_roundtrip() {
        let msg = AstationMessage::ExplainerResult {
            request_id: None,
            html: String::new(),
            topic: "Test".into(),
            success: false,
            error: Some("API key missing".into()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::ExplainerResult { success, error, .. } = parsed {
            assert!(!success);
            assert_eq!(error.as_deref(), Some("API key missing"));
        } else {
            panic!("expected ExplainerResult");
        }
    }
}

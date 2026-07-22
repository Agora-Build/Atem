use anyhow::{Result, anyhow};
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::fs;
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

    /// Astation → Atem: voice coding request with accumulated transcription.
    #[serde(rename = "voiceRequest")]
    VoiceRequest {
        session_id: String,
        accumulated_text: String,
        relay_url: String,
    },

    /// Astation → Atem (remote agent control v1): text or a control key to write
    /// to the focused agent's PTY. `agent_id` is optional (v1 = focused/only
    /// agent). Wire shape: `{type:"agentInput", data:{agentId?, kind, text?, key?}}`.
    #[serde(rename = "agentInput")]
    AgentInput {
        #[serde(rename = "agentId", default, skip_serializing_if = "Option::is_none")]
        agent_id: Option<String>,
        kind: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        text: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        key: Option<String>,
    },

    /// Atem → Astation: voice coding response confirmation.
    #[serde(rename = "voiceResponse")]
    VoiceResponse {
        session_id: String,
        success: bool,
        message: String,
    },

    /// Astation → Atem: request to generate a visual diagram via an agent.
    #[serde(rename = "visualizeRequest")]
    VisualizeRequest {
        session_id: String,
        topic: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        relay_url: Option<String>,
    },

    /// Atem → Astation: result of a visualize request.
    #[serde(rename = "visualizeResult")]
    VisualizeResult {
        session_id: String,
        success: bool,
        message: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        file_path: Option<String>,
    },

    /// Astation → Atem: SSO tokens to use for BFF calls + paired session
    /// resolution. Repurposed in 2026-05; previously carried customer_id/
    /// customer_secret. Identical payload to the now-removed SsoTokenSync.
    #[serde(rename = "credentialSync")]
    CredentialSync {
        access_token: String,
        refresh_token: String,
        expires_at: u64,
        #[serde(default)]
        login_id: Option<String>,
        astation_id: String,
        save_credentials: bool,
    },

    /// Atem → Astation: user's preference for whether paired credentials should persist
    /// after Astation disconnect. Sent during `atem pair`.
    #[serde(rename = "pairSavePreference")]
    PairSavePreference {
        save_credentials: bool,
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
    transport_tasks: Vec<tokio::task::JoinHandle<()>>,
    atem_id_override: Option<String>,
    session_path_override: Option<std::path::PathBuf>,
    #[cfg(test)]
    relay_code_path_override: Option<std::path::PathBuf>,
    /// Set to true when the WebSocket reader task exits (connection dropped).
    ws_closed: bool,
}

impl AstationClient {
    pub fn new() -> Self {
        Self {
            sender: None,
            receiver: None,
            transport_tasks: Vec::new(),
            atem_id_override: None,
            session_path_override: None,
            #[cfg(test)]
            relay_code_path_override: None,
            ws_closed: false,
        }
    }

    #[cfg(test)]
    fn new_with_test_state(atem_id: &str, session_path: std::path::PathBuf) -> Self {
        let mut client = Self::new();
        client.atem_id_override = Some(atem_id.to_string());
        client.relay_code_path_override = Some(session_path.with_file_name("relay-code"));
        client.session_path_override = Some(session_path);
        client
    }

    fn resolved_atem_id(&self, hostname: &str) -> String {
        self.atem_id_override
            .clone()
            .unwrap_or_else(|| resolved_atem_id(hostname))
    }

    fn load_session_manager(&self) -> Result<crate::auth::SessionManager> {
        match self.session_path_override.as_deref() {
            Some(path) => crate::auth::SessionManager::load_from(path),
            None => crate::auth::SessionManager::load(),
        }
    }

    fn save_session_manager(&self, manager: &crate::auth::SessionManager) -> Result<()> {
        match self.session_path_override.as_deref() {
            Some(path) => manager.save_to(path),
            None => manager.save(),
        }
    }

    fn persist_session(&self, session: crate::auth::AuthSession) -> Result<()> {
        let mut manager = self.load_session_manager()?;
        manager.insert_session(session);
        self.save_session_manager(&manager)
    }

    fn remember_astation_relay_code(&self, astation_id: &str) {
        #[cfg(test)]
        if let Some(path) = self.relay_code_path_override.as_deref() {
            let _ = fs::write(path, astation_id);
            return;
        }

        AtemConfig::store_astation_relay_code(astation_id);
    }

    fn abort_transport(&mut self) {
        self.sender = None;
        self.receiver = None;
        for task in self.transport_tasks.drain(..) {
            task.abort();
        }
        self.ws_closed = true;
    }

    /// Connect to Astation using a saved auth session.
    /// Connect with session (now handled via message-based auth)
    /// This is now just an alias for connect() since auth happens after connection.
    pub async fn connect_with_session(&mut self, base_url: &str, _session_id: &str) -> Result<()> {
        // Session auth now happens inside connect() via authenticate()
        // The session_id parameter is ignored - session is loaded from disk
        self.connect_without_pairing(base_url).await
    }

    /// Connect WebSocket and authenticate (local Astation connections).
    pub async fn connect(&mut self, url: &str) -> Result<()> {
        self.connect_with_auth_mode(url, true).await
    }

    /// Connect using an existing proof or same-user bootstrap without prompting.
    pub async fn connect_without_pairing(&mut self, url: &str) -> Result<()> {
        self.connect_with_auth_mode(url, false).await
    }

    async fn connect_with_auth_mode(&mut self, url: &str, allow_pairing: bool) -> Result<()> {
        self.connect_raw(url).await?;
        let result = self
            .authenticate(
                Duration::from_secs(5),
                Duration::from_secs(300),
                allow_pairing,
            )
            .await;
        if result.is_err() {
            self.abort_transport();
        }
        result
    }

    /// Connect WebSocket transport only, without authentication.
    /// Used by relay flow where auth happens separately after code exchange.
    pub async fn connect_raw(&mut self, url: &str) -> Result<()> {
        self.abort_transport();
        let (ws_stream, _) = tokio::time::timeout(Duration::from_secs(5), connect_async(url))
            .await
            .map_err(|_| anyhow!("WebSocket connection timed out after 5s"))?
            .map_err(|e| anyhow!("Failed to connect to WebSocket: {}", e))?;

        let (mut write, mut read) = ws_stream.split();
        let (tx, rx) = mpsc::unbounded_channel::<AstationMessage>();
        let (msg_tx, mut msg_rx) = mpsc::unbounded_channel::<AstationMessage>();

        // Spawn task to handle outgoing messages
        let writer_task = tokio::spawn(async move {
            while let Some(message) = msg_rx.recv().await {
                if let Ok(json) = serde_json::to_string(&message) {
                    if let Err(_) = write.send(Message::Text(json)).await {
                        break;
                    }
                }
            }
        });

        // Spawn task to handle incoming messages
        let reader_task = tokio::spawn(async move {
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
        self.transport_tasks = vec![writer_task, reader_task];
        self.ws_closed = false;

        Ok(())
    }

    /// Authenticate with Astation after WebSocket connection.
    /// Waits for auth_required, then sends session ID or pairing code.
    /// `challenge_timeout` controls how long to wait for `auth_required`.
    /// `completion_timeout` bounds everything after the challenge, including
    /// session proof and interactive pairing.
    async fn authenticate(
        &mut self,
        challenge_timeout: Duration,
        completion_timeout: Duration,
        allow_pairing: bool,
    ) -> Result<()> {
        // Wait for auth_required message (with timeout)
        let auth_required = tokio::time::timeout(
            challenge_timeout,
            self.wait_for_message(|msg| {
                matches!(msg, AstationMessage::StatusUpdate { status, .. } if status == "auth_required")
            })
        )
        .await
        .map_err(|_| anyhow!("Timeout waiting for auth_required"))?
        .ok_or_else(|| anyhow!("Connection closed before auth_required"))?;

        tokio::time::timeout(
            completion_timeout,
            self.authenticate_after_challenge(auth_required, allow_pairing),
        )
        .await
        .map_err(|_| anyhow!("Authentication timed out"))?
    }

    async fn authenticate_after_challenge(
        &mut self,
        auth_required: AstationMessage,
        allow_pairing: bool,
    ) -> Result<()> {
        // Extract the server identity and challenge from auth_required.
        let (astation_id, challenge, transport, protocol) =
            if let AstationMessage::StatusUpdate { data, .. } = &auth_required {
                let astation_id = data
                    .get("astation_id")
                    .ok_or_else(|| anyhow!("auth_required missing astation_id"))?
                    .clone();
                (
                    astation_id,
                    data.get("challenge").cloned(),
                    data.get("transport").cloned(),
                    data.get("protocol").cloned(),
                )
            } else {
                return Err(anyhow!("Invalid auth_required message"));
            };

        if protocol.as_deref() != Some("2") {
            return Err(anyhow!("Astation authentication protocol v2 is required"));
        }
        let challenge = challenge
            .as_deref()
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or_else(|| anyhow!("Invalid Astation authentication challenge"))?;
        let transport = transport
            .as_deref()
            .filter(|value| matches!(*value, "loopback" | "lan" | "relay"))
            .ok_or_else(|| anyhow!("Invalid Astation authentication transport"))?;

        let hostname = crate::auth::get_hostname();
        let atem_id = self.resolved_atem_id(&hostname);

        if transport == "loopback" {
            let token = read_local_bootstrap_token()
                .ok_or_else(|| anyhow!("Astation local bootstrap token is unavailable"))?;
            let mut auth_data = std::collections::HashMap::new();
            auth_data.insert("method".to_string(), "local_proof".to_string());
            auth_data.insert("atem_id".to_string(), atem_id.clone());
            auth_data.insert("hostname".to_string(), hostname.clone());
            auth_data.insert(
                "proof".to_string(),
                device_auth_proof(&token, challenge, &astation_id, &atem_id, "local")?,
            );
            self.send_message(AstationMessage::StatusUpdate {
                status: "auth".to_string(),
                data: auth_data,
            })
            .await?;

            return match self.wait_for_auth_response(&astation_id).await? {
                Some(AuthResponse::Authenticated) => Ok(()),
                Some(AuthResponse::Denied(message)) => {
                    Err(anyhow!("Local authentication denied: {}", message))
                }
                Some(AuthResponse::SessionExpired) => {
                    Err(anyhow!("Unexpected local session expiry"))
                }
                None => Err(anyhow!("Connection closed during local authentication")),
            };
        }

        // Load session manager
        let mut session_mgr = self.load_session_manager()?;

        // Try session-based auth first if we have a saved session for this Astation
        if let Some(session) = session_mgr.get(&astation_id) {
            let mut auth_data = std::collections::HashMap::new();
            auth_data.insert("session_id".to_string(), session.session_id.clone());
            auth_data.insert("atem_id".to_string(), atem_id.clone());
            auth_data.insert(
                "proof".to_string(),
                device_auth_proof(
                    &session.token,
                    challenge,
                    &astation_id,
                    &atem_id,
                    &session.session_id,
                )?,
            );

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
                            if let Err(error) = self.save_session_manager(&session_mgr) {
                                eprintln!(
                                    "Warning: could not refresh saved Astation session: {error}"
                                );
                            }
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

        if !allow_pairing {
            return Err(anyhow!("Pairing required; run 'atem pair'"));
        }

        // Session auth failed or no session - use explicit pairing.
        self.authenticate_with_pairing(&astation_id, &atem_id).await
    }

    /// Authenticate using pairing code (fallback when session invalid/missing)
    async fn authenticate_with_pairing(&mut self, astation_id: &str, atem_id: &str) -> Result<()> {
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
        auth_data.insert("atem_id".to_string(), atem_id.to_string());

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
                                let session_id = data.get("session_id").ok_or_else(|| {
                                    anyhow!("Pairing response missing session ID")
                                })?;
                                let token = data.get("token").ok_or_else(|| {
                                    anyhow!("Pairing response missing session token")
                                })?;
                                let hostname = crate::auth::get_hostname();
                                let session = crate::auth::AuthSession::new(
                                    session_id.clone(),
                                    token.clone(),
                                    astation_id.to_string(),
                                    hostname,
                                );

                                self.persist_session(session)?;
                                self.remember_astation_relay_code(astation_id);
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
                    self.remember_astation_relay_code(astation_id);
                    return Ok(Some(AuthResponse::Authenticated));
                }
                AstationMessage::StatusUpdate { status, data } if status == "error" => {
                    if let Some(msg) = data.get("message") {
                        let lower = msg.to_ascii_lowercase();
                        if lower.contains("expired") || lower.contains("pairing required") {
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
    /// Sets `is_ws_closed()` to true when the WebSocket channel is dropped.
    pub fn recv_message(&mut self) -> Option<AstationMessage> {
        if let Some(receiver) = &mut self.receiver {
            match receiver.try_recv() {
                Ok(msg) => Some(msg),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => None,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    self.ws_closed = true;
                    None
                }
            }
        } else {
            None
        }
    }

    /// Returns true if the WebSocket connection has been closed.
    /// Detected lazily when `recv_message()` encounters a closed channel.
    pub fn is_ws_closed(&self) -> bool {
        self.ws_closed
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

    pub async fn send_voice_response(
        &self,
        session_id: &str,
        success: bool,
        message: &str,
    ) -> Result<()> {
        let msg = AstationMessage::VoiceResponse {
            session_id: session_id.to_string(),
            success,
            message: message.to_string(),
        };
        self.send_message(msg).await
    }

    pub async fn send_visualize_result(
        &self,
        session_id: &str,
        success: bool,
        message: &str,
        file_path: Option<String>,
    ) -> Result<()> {
        let msg = AstationMessage::VisualizeResult {
            session_id: session_id.to_string(),
            success,
            message: message.to_string(),
            file_path,
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

    pub async fn send_command_response(
        &self,
        output: &str,
        success: bool,
    ) -> Result<()> {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
            .to_string();
        let message = AstationMessage::CommandResponse {
            output: output.to_string(),
            success,
            timestamp,
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

    /// Register with the relay service to get a pairing code, then connect.
    ///
    /// Flow:
    /// 1. POST to relay /api/pair → get pairing code
    /// 2. Try local Astation (ws://127.0.0.1:8080/ws)
    /// 3. If local fails → fall back to relay WebSocket
    ///
    /// Returns the pairing code on success.
    pub async fn connect_with_pairing(&mut self, config: &AtemConfig) -> Result<String> {
        // 1. Try local Astation first (fast, no relay needed)
        let local_url = config.astation_ws().to_string();
        if self.connect(&local_url).await.is_ok() {
            return Ok("local".to_string());
        }

        // 2. Local failed - fall back to relay
        let station_url = config.astation_relay_url().to_string();

        // Register with relay → get pairing code (5s timeout)
        let code = tokio::time::timeout(
            Duration::from_secs(5),
            self.register_pair(&station_url),
        )
        .await
        .map_err(|_| anyhow!("Relay registration timed out"))??;

        // Connect WebSocket to relay (raw, no auth yet)
        let ws_scheme = if station_url.starts_with("https://") {
            station_url.replace("https://", "wss://")
        } else {
            station_url.replace("http://", "ws://")
        };
        let ws_url = format!("{}/ws?role=atem&code={}", ws_scheme, code);
        self.connect_raw(&ws_url).await?;

        // Return the code — caller is responsible for any UI (println!, open_browser, etc.)
        // so this function stays silent and TUI-safe.
        Ok(code)
    }

    /// Connect to Astation's persistent identity relay room for TUI auto-reconnect.
    ///
    /// Astation registers its identity UUID as a permanent relay room on startup.
    /// After `atem pair`, Atem stores the identity as `astation_relay_code` in config.
    /// The TUI calls this to auto-connect without a new `atem pair`.
    ///
    /// Flow: connect_raw → hello → challenge/response authentication.
    pub async fn connect_relay_identity(
        &mut self,
        relay_url: &str,
        identity_code: &str,
    ) -> Result<()> {
        self.connect_relay_identity_with_mode(relay_url, identity_code, true)
            .await
    }

    /// Reconnect to an identity room using existing credentials only.
    pub async fn connect_relay_identity_without_pairing(
        &mut self,
        relay_url: &str,
        identity_code: &str,
    ) -> Result<()> {
        self.connect_relay_identity_with_mode(relay_url, identity_code, false)
            .await
    }

    async fn connect_relay_identity_with_mode(
        &mut self,
        relay_url: &str,
        identity_code: &str,
        allow_pairing: bool,
    ) -> Result<()> {
        let ws_scheme = if relay_url.starts_with("https://") {
            relay_url.replace("https://", "wss://")
        } else {
            relay_url.replace("http://", "ws://")
        };

        // atem_id lets the relay distinguish multiple Atems in the same room.
        // Generated once from hostname + instance id and frozen in config.toml,
        // so it's stable across restarts (and hostname changes) and unique so two
        // machines that share a hostname don't collide. See build_atem_id.
        let hostname = hostname::get()
            .map(|h| h.to_string_lossy().to_string())
            .unwrap_or_else(|_| "unknown".to_string());
        let atem_id = self.resolved_atem_id(&hostname);

        let ws_url = relay_ws_url(&ws_scheme, identity_code, &atem_id);
        self.connect_raw(&ws_url).await?;

        // Send hello to announce ourselves and trigger Astation to send credentials
        let mut hello_data = std::collections::HashMap::new();
        hello_data.insert("hostname".to_string(), hostname.clone());

        let result = async {
            self.send_message(AstationMessage::StatusUpdate {
                status: "hello".to_string(),
                data: hello_data,
            })
            .await?;

            self.authenticate(
                Duration::from_secs(10),
                Duration::from_secs(300),
                allow_pairing,
            )
            .await
        }
        .await;
        if result.is_err() {
            self.abort_transport();
        }
        result
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
}

impl Drop for AstationClient {
    fn drop(&mut self) {
        self.abort_transport();
    }
}

type HmacSha256 = Hmac<Sha256>;

fn resolved_atem_id(hostname: &str) -> String {
    if let Some(existing) = AtemConfig::stored_atem_id() {
        return existing;
    }
    let atem_id = build_atem_id(hostname, &AtemConfig::ensure_instance_id());
    AtemConfig::store_atem_id(&atem_id);
    atem_id
}

fn device_auth_proof(
    token: &str,
    challenge: &str,
    astation_id: &str,
    atem_id: &str,
    session_id: &str,
) -> Result<String> {
    let canonical = format!(
        "astation-auth-v2\n{}\n{}\n{}\n{}",
        challenge, astation_id, atem_id, session_id
    );
    let mut mac = <HmacSha256 as Mac>::new_from_slice(token.as_bytes())
        .map_err(|_| anyhow!("Invalid device authentication key"))?;
    mac.update(canonical.as_bytes());
    Ok(mac
        .finalize()
        .into_bytes()
        .iter()
        .map(|byte| format!("{:02x}", byte))
        .collect())
}

fn read_local_bootstrap_token() -> Option<String> {
    #[cfg(target_os = "macos")]
    let path = dirs::data_dir()?
        .join("Astation")
        .join("local-bootstrap-token");

    #[cfg(not(target_os = "macos"))]
    return None;

    #[cfg(target_os = "macos")]
    read_local_bootstrap_token_from(&path)
}

#[cfg(unix)]
fn read_local_bootstrap_token_from(path: &std::path::Path) -> Option<String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let mut file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o077 != 0
    {
        return None;
    }
    let mut token = String::new();
    file.read_to_string(&mut token).ok()?;
    let token = token.trim().to_string();
    (!token.is_empty()).then_some(token)
}

/// Length of the host segment of an `atem_id` (truncated or padded to this).
const ATEM_ID_HOST_LEN: usize = 12;
/// Length of the instance-id suffix of an `atem_id`.
const ATEM_ID_SUFFIX_LEN: usize = 8;

/// Build the relay `atem_id`: `<host:12>-<instance suffix:8>` (21 chars).
///
/// Lengths are counted in **characters**, not bytes (CJK chars are multibyte).
/// Host charset: non-ASCII chars (CJK etc.) are kept as-is; ASCII is restricted
/// to `[A-Za-z0-9-]` (dots, underscores, and other punctuation are dropped). The
/// host is normalized to [`ATEM_ID_HOST_LEN`] chars — truncated if longer, padded
/// if shorter. Padding and suffix are drawn from the instance-id hex (the suffix
/// is the first UUID block), so the id is unique per install and *stable* across
/// restarts, never fresh-random.
///
/// Because non-ASCII is allowed, the value must be percent-encoded before it
/// goes into the relay URL (see `connect_relay_identity`).
fn build_atem_id(hostname: &str, instance_id: &str) -> String {
    // Pool of stable chars from the instance id (UUID → 32 hex chars).
    let pool: Vec<char> = instance_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();

    // Host segment: keep non-ASCII as-is; for ASCII keep only [A-Za-z0-9-].
    let mut host: Vec<char> = hostname
        .chars()
        .filter(|c| !c.is_ascii() || c.is_ascii_alphanumeric() || *c == '-')
        .take(ATEM_ID_HOST_LEN)
        .collect();

    // Without an instance id there's nothing unique to add; fall back to the
    // bare (truncated) hostname.
    if pool.is_empty() {
        return if host.is_empty() {
            "atem".to_string()
        } else {
            host.into_iter().collect()
        };
    }

    let suffix: String = pool.iter().take(ATEM_ID_SUFFIX_LEN).collect();

    // Pad the host segment to a uniform width using letters from the instance-id
    // pool, drawn after the suffix chars so padding and suffix differ.
    let pad: Vec<char> = pool.iter().skip(ATEM_ID_SUFFIX_LEN).copied().collect();
    let mut i = 0;
    while host.len() < ATEM_ID_HOST_LEN {
        let c = if pad.is_empty() {
            pool[i % pool.len()]
        } else {
            pad[i % pad.len()]
        };
        host.push(c);
        i += 1;
    }

    let host: String = host.into_iter().collect();
    format!("{host}-{suffix}")
}

/// Build the relay WebSocket URL. `atem_id` may contain non-ASCII (CJK etc.), so
/// it is percent-encoded into the query value — the resulting URL is pure ASCII
/// and valid URI syntax. The relay percent-decodes the query param back to the
/// canonical `atem_id`. `relay_base` is the ws/wss scheme + host (e.g.
/// `wss://relay.example`); `identity_code` is already ASCII.
fn relay_ws_url(relay_base: &str, identity_code: &str, atem_id: &str) -> String {
    format!(
        "{}/ws?role=atem&code={}&atem_id={}",
        relay_base,
        identity_code,
        urlencoding::encode(atem_id)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn isolated_client(atem_id: &str) -> (tempfile::TempDir, AstationClient) {
        let directory = tempfile::tempdir().unwrap();
        let session_path = directory.path().join("sessions.json");
        let client = AstationClient::new_with_test_state(atem_id, session_path);
        (directory, client)
    }

    #[test]
    fn device_auth_proof_matches_protocol_vector() {
        let proof = device_auth_proof(
            "token-abc",
            "challenge-123",
            "astation-home",
            "atem-office",
            "session-456",
        )
        .unwrap();

        assert_eq!(
            proof,
            "9fde5ba861c1a159d377b89e6fb3f92d245795998af958f5db3ad343d589d0ba"
        );
    }

    #[cfg(unix)]
    #[test]
    fn local_bootstrap_token_requires_private_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("local-bootstrap-token");
        fs::write(&path, "bootstrap-secret\n").unwrap();

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(
            read_local_bootstrap_token_from(&path).as_deref(),
            Some("bootstrap-secret")
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(read_local_bootstrap_token_from(&path), None);
    }

    #[cfg(unix)]
    #[test]
    fn local_bootstrap_token_refuses_symlink() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("bootstrap-target");
        let link = directory.path().join("local-bootstrap-token");
        fs::write(&target, "bootstrap-secret\n").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &link).unwrap();

        assert_eq!(read_local_bootstrap_token_from(&link), None);
        assert_eq!(fs::read_to_string(&target).unwrap(), "bootstrap-secret\n");
    }

    #[tokio::test]
    async fn practical_websocket_v2_pairing_sends_identity_and_handles_denial() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind test Astation");
        let address = listener.local_addr().unwrap();
        let astation_id = format!("astation-integration-{}", uuid::Uuid::new_v4());
        let expected_astation_id = astation_id.clone();

        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("test Astation did not accept");
            let mut socket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("WebSocket handshake failed");
            let auth_required = AstationMessage::StatusUpdate {
                status: "auth_required".to_string(),
                data: std::collections::HashMap::from([
                    ("astation_id".to_string(), expected_astation_id),
                    ("challenge".to_string(), "a".repeat(64)),
                    ("transport".to_string(), "lan".to_string()),
                    ("protocol".to_string(), "2".to_string()),
                ]),
            };
            socket
                .send(Message::Text(
                    serde_json::to_string(&auth_required).unwrap(),
                ))
                .await
                .unwrap();

            let frame = tokio::time::timeout(Duration::from_secs(2), socket.next())
                .await
                .expect("timed out waiting for pairing request")
                .expect("Atem closed before pairing request")
                .expect("failed to read pairing request");
            let Message::Text(text) = frame else {
                panic!("expected text pairing request");
            };
            let request: AstationMessage = serde_json::from_str(&text).unwrap();
            let AstationMessage::StatusUpdate { status, data } = request else {
                panic!("expected authentication status update");
            };
            assert_eq!(status, "auth");
            assert!(!data["atem_id"].is_empty());
            assert!(!data["hostname"].is_empty());
            assert_eq!(data["pairing_code"].len(), 8);
            assert!(
                data["pairing_code"]
                    .chars()
                    .all(|value| value.is_ascii_digit())
            );
            assert!(!data.contains_key("session_id"));
            assert!(!data.contains_key("proof"));

            let denied = AstationMessage::StatusUpdate {
                status: "auth".to_string(),
                data: std::collections::HashMap::from([
                    ("status".to_string(), "denied".to_string()),
                    ("message".to_string(), "integration denial".to_string()),
                ]),
            };
            socket
                .send(Message::Text(serde_json::to_string(&denied).unwrap()))
                .await
                .unwrap();
        });

        let (_state, mut client) = isolated_client("atem-test-denial");
        let error = client
            .connect(&format!("ws://{address}"))
            .await
            .expect_err("denied pairing unexpectedly authenticated");
        assert!(
            error
                .to_string()
                .contains("Pairing denied: integration denial")
        );
        server.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn practical_websocket_pairing_fails_when_session_cannot_be_persisted() {
        use std::os::unix::fs::symlink;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind test Astation");
        let address = listener.local_addr().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let session_path = directory.path().join("sessions.json");
        let target_path = directory.path().join("protected-target");
        let server_session_path = session_path.clone();
        let server_target_path = target_path.clone();

        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("test Astation did not accept");
            let mut socket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("WebSocket handshake failed");
            let auth_required = AstationMessage::StatusUpdate {
                status: "auth_required".to_string(),
                data: std::collections::HashMap::from([
                    (
                        "astation_id".to_string(),
                        "astation-persist-failure".to_string(),
                    ),
                    ("challenge".to_string(), "e".repeat(64)),
                    ("transport".to_string(), "lan".to_string()),
                    ("protocol".to_string(), "2".to_string()),
                ]),
            };
            socket
                .send(Message::Text(
                    serde_json::to_string(&auth_required).unwrap(),
                ))
                .await
                .unwrap();

            tokio::time::timeout(Duration::from_secs(1), socket.next())
                .await
                .expect("timed out waiting for pairing request")
                .expect("Atem closed before pairing request")
                .expect("failed to read pairing request");

            fs::write(&server_target_path, "must remain unchanged").unwrap();
            symlink(&server_target_path, &server_session_path).unwrap();
            let granted = AstationMessage::StatusUpdate {
                status: "auth".to_string(),
                data: std::collections::HashMap::from([
                    ("status".to_string(), "granted".to_string()),
                    ("session_id".to_string(), "session-new".to_string()),
                    ("token".to_string(), "token-new".to_string()),
                ]),
            };
            socket
                .send(Message::Text(serde_json::to_string(&granted).unwrap()))
                .await
                .unwrap();
        });

        let mut client =
            AstationClient::new_with_test_state("atem-test-persist-failure", session_path);
        let error = client
            .connect(&format!("ws://{address}"))
            .await
            .expect_err("pairing unexpectedly ignored session persistence failure");
        assert!(error.to_string().contains("Failed to open private file"));
        assert_eq!(
            fs::read_to_string(target_path).unwrap(),
            "must remain unchanged"
        );
        assert!(!directory.path().join("relay-code").exists());
        server.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn practical_websocket_reconnect_survives_session_refresh_failure() {
        use std::os::unix::fs::symlink;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind test Astation");
        let address = listener.local_addr().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let session_path = directory.path().join("sessions.json");
        let target_path = directory.path().join("protected-target");
        let astation_id = "astation-refresh-failure".to_string();

        let mut sessions = crate::auth::SessionManager::default();
        sessions.insert_session(crate::auth::AuthSession::new(
            "session-existing".to_string(),
            "token-existing".to_string(),
            astation_id.clone(),
            "test-machine".to_string(),
        ));
        sessions.save_to(&session_path).unwrap();

        let server_session_path = session_path.clone();
        let server_target_path = target_path.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("test Astation did not accept");
            let mut socket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("WebSocket handshake failed");
            let auth_required = AstationMessage::StatusUpdate {
                status: "auth_required".to_string(),
                data: std::collections::HashMap::from([
                    ("astation_id".to_string(), astation_id),
                    ("challenge".to_string(), "f".repeat(64)),
                    ("transport".to_string(), "lan".to_string()),
                    ("protocol".to_string(), "2".to_string()),
                ]),
            };
            socket
                .send(Message::Text(
                    serde_json::to_string(&auth_required).unwrap(),
                ))
                .await
                .unwrap();

            let request = tokio::time::timeout(Duration::from_secs(1), socket.next())
                .await
                .expect("timed out waiting for session proof")
                .expect("Atem closed before session proof")
                .expect("failed to read session proof");
            assert!(matches!(request, Message::Text(_)));

            fs::remove_file(&server_session_path).unwrap();
            fs::write(&server_target_path, "must remain unchanged").unwrap();
            symlink(&server_target_path, &server_session_path).unwrap();
            let authenticated = AstationMessage::StatusUpdate {
                status: "authenticated".to_string(),
                data: std::collections::HashMap::from([(
                    "method".to_string(),
                    "session_proof".to_string(),
                )]),
            };
            socket
                .send(Message::Text(
                    serde_json::to_string(&authenticated).unwrap(),
                ))
                .await
                .unwrap();
        });

        let mut client =
            AstationClient::new_with_test_state("atem-test-refresh-failure", session_path);
        client
            .connect_without_pairing(&format!("ws://{address}"))
            .await
            .expect("session metadata failure aborted an authenticated reconnect");
        assert!(client.sender.is_some());
        assert_eq!(
            fs::read_to_string(target_path).unwrap(),
            "must remain unchanged"
        );
        assert_eq!(
            fs::read_to_string(directory.path().join("relay-code")).unwrap(),
            "astation-refresh-failure"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn practical_websocket_rejects_protocol_downgrade_without_credentials() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind test Astation");
        let address = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("test Astation did not accept");
            let mut socket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("WebSocket handshake failed");
            let auth_required = AstationMessage::StatusUpdate {
                status: "auth_required".to_string(),
                data: std::collections::HashMap::from([
                    ("astation_id".to_string(), "astation-downgrade".to_string()),
                    ("challenge".to_string(), "b".repeat(64)),
                    ("transport".to_string(), "lan".to_string()),
                ]),
            };
            socket
                .send(Message::Text(
                    serde_json::to_string(&auth_required).unwrap(),
                ))
                .await
                .unwrap();

            match tokio::time::timeout(Duration::from_millis(250), socket.next()).await {
                Err(_) | Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(Message::Close(_)))) => {}
                Ok(Some(Ok(Message::Text(text)))) => {
                    panic!("Atem leaked an authentication message after downgrade: {text}")
                }
                Ok(Some(other)) => panic!("unexpected WebSocket frame: {other:?}"),
            }
        });

        let (_state, mut client) = isolated_client("atem-test-downgrade");
        client
            .connect_raw(&format!("ws://{address}"))
            .await
            .unwrap();
        let error = client
            .authenticate(Duration::from_secs(1), Duration::from_secs(1), true)
            .await
            .expect_err("protocol downgrade unexpectedly authenticated");
        assert!(error.to_string().contains("protocol v2 is required"));
        drop(client);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn practical_websocket_background_connect_never_starts_pairing() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind test Astation");
        let address = listener.local_addr().unwrap();
        let astation_id = format!("astation-proof-only-{}", uuid::Uuid::new_v4());

        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("test Astation did not accept");
            let mut socket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("WebSocket handshake failed");
            let auth_required = AstationMessage::StatusUpdate {
                status: "auth_required".to_string(),
                data: std::collections::HashMap::from([
                    ("astation_id".to_string(), astation_id),
                    ("challenge".to_string(), "d".repeat(64)),
                    ("transport".to_string(), "lan".to_string()),
                    ("protocol".to_string(), "2".to_string()),
                ]),
            };
            socket
                .send(Message::Text(
                    serde_json::to_string(&auth_required).unwrap(),
                ))
                .await
                .unwrap();

            match tokio::time::timeout(Duration::from_millis(250), socket.next()).await {
                Err(_) | Ok(None) | Ok(Some(Err(_))) | Ok(Some(Ok(Message::Close(_)))) => {}
                Ok(Some(Ok(Message::Text(text)))) => {
                    panic!("background reconnect unexpectedly sent pairing data: {text}")
                }
                Ok(Some(other)) => panic!("unexpected WebSocket frame: {other:?}"),
            }
        });

        let (_state, mut client) = isolated_client("atem-test-proof-only");
        let error = client
            .connect_without_pairing(&format!("ws://{address}"))
            .await
            .expect_err("proof-only connection unexpectedly started pairing");
        assert_eq!(error.to_string(), "Pairing required; run 'atem pair'");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn practical_websocket_bounds_authentication_after_challenge() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind test Astation");
        let address = listener.local_addr().unwrap();
        let astation_id = format!("astation-timeout-{}", uuid::Uuid::new_v4());

        let server = tokio::spawn(async move {
            let (stream, _) = listener
                .accept()
                .await
                .expect("test Astation did not accept");
            let mut socket = tokio_tungstenite::accept_async(stream)
                .await
                .expect("WebSocket handshake failed");
            let auth_required = AstationMessage::StatusUpdate {
                status: "auth_required".to_string(),
                data: std::collections::HashMap::from([
                    ("astation_id".to_string(), astation_id),
                    ("challenge".to_string(), "c".repeat(64)),
                    ("transport".to_string(), "lan".to_string()),
                    ("protocol".to_string(), "2".to_string()),
                ]),
            };
            socket
                .send(Message::Text(
                    serde_json::to_string(&auth_required).unwrap(),
                ))
                .await
                .unwrap();

            let request = tokio::time::timeout(Duration::from_secs(1), socket.next())
                .await
                .expect("timed out waiting for authentication request")
                .expect("Atem closed before authentication request")
                .expect("failed to read authentication request");
            assert!(matches!(request, Message::Text(_)));
            tokio::time::sleep(Duration::from_millis(200)).await;
        });

        let (_state, mut client) = isolated_client("atem-test-timeout");
        client
            .connect_raw(&format!("ws://{address}"))
            .await
            .unwrap();
        let error = client
            .authenticate(Duration::from_secs(1), Duration::from_millis(50), true)
            .await
            .expect_err("silent Astation unexpectedly authenticated");
        assert_eq!(error.to_string(), "Authentication timed out");
        drop(client);
        server.await.unwrap();
    }

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

    #[test]
    fn credential_sync_roundtrip() {
        let msg = AstationMessage::CredentialSync {
            access_token: "AT".to_string(),
            refresh_token: "RT".to_string(),
            expires_at: 1_700_000_000,
            login_id: Some("u@a.io".to_string()),
            astation_id: "ast-1".to_string(),
            save_credentials: true,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"credentialSync""#));
        assert!(json.contains(r#""access_token":"AT""#));
        assert!(json.contains(r#""refresh_token":"RT""#));
        assert!(json.contains(r#""expires_at":1700000000"#));
        assert!(json.contains(r#""login_id":"u@a.io""#));
        assert!(json.contains(r#""astation_id":"ast-1""#));
        assert!(json.contains(r#""save_credentials":true"#));
    }

    #[test]
    fn credential_sync_deserialize_from_json() {
        let json = r#"{"type":"credentialSync","data":{
            "access_token":"AT","refresh_token":"RT","expires_at":1700000000,
            "login_id":"u","astation_id":"ast-1","save_credentials":false
        }}"#;
        let msg: AstationMessage = serde_json::from_str(json).unwrap();
        match msg {
            AstationMessage::CredentialSync {
                access_token, refresh_token, expires_at, login_id,
                astation_id, save_credentials,
            } => {
                assert_eq!(access_token, "AT");
                assert_eq!(refresh_token, "RT");
                assert_eq!(expires_at, 1_700_000_000);
                assert_eq!(login_id.as_deref(), Some("u"));
                assert_eq!(astation_id, "ast-1");
                assert!(!save_credentials);
            }
            _ => panic!("expected CredentialSync"),
        }
    }

    #[test]
    fn credential_sync_without_login_id() {
        let json = r#"{"type":"credentialSync","data":{
            "access_token":"AT","refresh_token":"RT","expires_at":1,
            "astation_id":"ast-1","save_credentials":true
        }}"#;
        let msg: AstationMessage = serde_json::from_str(json).unwrap();
        match msg {
            AstationMessage::CredentialSync { login_id, .. } => assert!(login_id.is_none()),
            _ => panic!("expected CredentialSync"),
        }
    }

    // ── VoiceRequest / VoiceResponse tests ─────────────────────────────

    #[test]
    fn voice_request_deserialize() {
        let json = r#"{"type":"voiceRequest","data":{"session_id":"sess-abc","accumulated_text":"fix the login bug","relay_url":"https://station.agora.build"}}"#;
        let msg: AstationMessage = serde_json::from_str(json).unwrap();
        if let AstationMessage::VoiceRequest {
            session_id,
            accumulated_text,
            relay_url,
        } = msg
        {
            assert_eq!(session_id, "sess-abc");
            assert_eq!(accumulated_text, "fix the login bug");
            assert_eq!(relay_url, "https://station.agora.build");
        } else {
            panic!("expected VoiceRequest");
        }
    }

    #[test]
    fn voice_request_roundtrip() {
        let msg = AstationMessage::VoiceRequest {
            session_id: "sess-1".into(),
            accumulated_text: "add a button".into(),
            relay_url: "https://relay.example.com".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"voiceRequest""#));
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::VoiceRequest {
            session_id,
            accumulated_text,
            relay_url,
        } = parsed
        {
            assert_eq!(session_id, "sess-1");
            assert_eq!(accumulated_text, "add a button");
            assert_eq!(relay_url, "https://relay.example.com");
        } else {
            panic!("expected VoiceRequest");
        }
    }

    #[test]
    fn voice_response_serialize() {
        let msg = AstationMessage::VoiceResponse {
            session_id: "sess-1".into(),
            success: true,
            message: "Response delivered".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"voiceResponse""#));
        assert!(json.contains(r#""session_id":"sess-1""#));
        assert!(json.contains(r#""success":true"#));
        assert!(json.contains("Response delivered"));
    }

    #[test]
    fn voice_response_roundtrip() {
        let msg = AstationMessage::VoiceResponse {
            session_id: "sess-2".into(),
            success: false,
            message: "Claude timeout".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::VoiceResponse {
            session_id,
            success,
            message,
        } = parsed
        {
            assert_eq!(session_id, "sess-2");
            assert!(!success);
            assert_eq!(message, "Claude timeout");
        } else {
            panic!("expected VoiceResponse");
        }
    }

    #[test]
    fn voice_request_empty_text() {
        let msg = AstationMessage::VoiceRequest {
            session_id: "sess-empty".into(),
            accumulated_text: "".into(),
            relay_url: "https://relay.example.com".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::VoiceRequest { accumulated_text, .. } = parsed {
            assert_eq!(accumulated_text, "");
        } else {
            panic!("expected VoiceRequest");
        }
    }

    #[test]
    fn voice_request_special_characters() {
        let msg = AstationMessage::VoiceRequest {
            session_id: "sess-special".into(),
            accumulated_text: "create a fn that returns \"hello\" with 100% accuracy & <b>tags</b>".into(),
            relay_url: "https://relay.example.com/path?key=val&other=1".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::VoiceRequest { accumulated_text, relay_url, .. } = parsed {
            assert!(accumulated_text.contains("\"hello\""));
            assert!(accumulated_text.contains("100%"));
            assert!(accumulated_text.contains("<b>tags</b>"));
            assert!(relay_url.contains("key=val&other=1"));
        } else {
            panic!("expected VoiceRequest");
        }
    }

    #[test]
    fn voice_response_success_true() {
        let msg = AstationMessage::VoiceResponse {
            session_id: "sess-ok".into(),
            success: true,
            message: "Response delivered to relay".into(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::VoiceResponse { success, message, .. } = parsed {
            assert!(success);
            assert_eq!(message, "Response delivered to relay");
        } else {
            panic!("expected VoiceResponse");
        }
    }

    #[test]
    fn voice_request_wire_format_field_names() {
        // Verify the exact wire format field names match what Astation Swift sends
        let json = r#"{"type":"voiceRequest","data":{"session_id":"s1","accumulated_text":"hello","relay_url":"https://r.test"}}"#;
        let msg: AstationMessage = serde_json::from_str(json).unwrap();
        if let AstationMessage::VoiceRequest { session_id, accumulated_text, relay_url } = msg {
            assert_eq!(session_id, "s1");
            assert_eq!(accumulated_text, "hello");
            assert_eq!(relay_url, "https://r.test");
        } else {
            panic!("expected VoiceRequest");
        }
    }

    #[test]
    fn voice_response_wire_format_field_names() {
        // Verify the exact wire format field names match what Atem Rust sends
        let json = r#"{"type":"voiceResponse","data":{"session_id":"s1","success":true,"message":"ok"}}"#;
        let msg: AstationMessage = serde_json::from_str(json).unwrap();
        if let AstationMessage::VoiceResponse { session_id, success, message } = msg {
            assert_eq!(session_id, "s1");
            assert!(success);
            assert_eq!(message, "ok");
        } else {
            panic!("expected VoiceResponse");
        }
    }

    // ── VisualizeRequest / VisualizeResult tests ──────────────────────────

    #[test]
    fn visualize_request_deserialize() {
        let json = r#"{"type":"visualizeRequest","data":{"session_id":"vis-1","topic":"WebRTC flow","relay_url":"https://relay.test"}}"#;
        let msg: AstationMessage = serde_json::from_str(json).unwrap();
        if let AstationMessage::VisualizeRequest { session_id, topic, relay_url } = msg {
            assert_eq!(session_id, "vis-1");
            assert_eq!(topic, "WebRTC flow");
            assert_eq!(relay_url.as_deref(), Some("https://relay.test"));
        } else {
            panic!("expected VisualizeRequest");
        }
    }

    #[test]
    fn visualize_request_without_relay_url() {
        let json = r#"{"type":"visualizeRequest","data":{"session_id":"vis-2","topic":"auth system"}}"#;
        let msg: AstationMessage = serde_json::from_str(json).unwrap();
        if let AstationMessage::VisualizeRequest { session_id, topic, relay_url } = msg {
            assert_eq!(session_id, "vis-2");
            assert_eq!(topic, "auth system");
            assert!(relay_url.is_none());
        } else {
            panic!("expected VisualizeRequest");
        }
    }

    #[test]
    fn visualize_request_roundtrip() {
        let msg = AstationMessage::VisualizeRequest {
            session_id: "vis-rt".into(),
            topic: "data pipeline".into(),
            relay_url: Some("https://relay.example.com".into()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"visualizeRequest""#));
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::VisualizeRequest { session_id, topic, relay_url } = parsed {
            assert_eq!(session_id, "vis-rt");
            assert_eq!(topic, "data pipeline");
            assert_eq!(relay_url.as_deref(), Some("https://relay.example.com"));
        } else {
            panic!("expected VisualizeRequest");
        }
    }

    #[test]
    fn visualize_result_serialize() {
        let msg = AstationMessage::VisualizeResult {
            session_id: "vis-1".into(),
            success: true,
            message: "Diagram generated".into(),
            file_path: Some("/home/user/.agent/diagrams/webrtc.html".into()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"visualizeResult""#));
        assert!(json.contains(r#""success":true"#));
        assert!(json.contains("webrtc.html"));
    }

    #[test]
    fn visualize_result_without_file_path() {
        let msg = AstationMessage::VisualizeResult {
            session_id: "vis-2".into(),
            success: false,
            message: "No HTML detected".into(),
            file_path: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(!json.contains("file_path"));
    }

    #[test]
    fn visualize_result_roundtrip() {
        let msg = AstationMessage::VisualizeResult {
            session_id: "vis-rt".into(),
            success: true,
            message: "OK".into(),
            file_path: Some("/tmp/diagram.html".into()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::VisualizeResult { session_id, success, message, file_path } = parsed {
            assert_eq!(session_id, "vis-rt");
            assert!(success);
            assert_eq!(message, "OK");
            assert_eq!(file_path.as_deref(), Some("/tmp/diagram.html"));
        } else {
            panic!("expected VisualizeResult");
        }
    }

    #[test]
    fn visualize_request_wire_format() {
        // Verify exact wire format matches what Astation Swift would send
        let json = r#"{"type":"visualizeRequest","data":{"session_id":"v1","topic":"WebRTC","relay_url":"https://relay.test"}}"#;
        let msg: AstationMessage = serde_json::from_str(json).unwrap();
        if let AstationMessage::VisualizeRequest { session_id, topic, relay_url } = msg {
            assert_eq!(session_id, "v1");
            assert_eq!(topic, "WebRTC");
            assert_eq!(relay_url.as_deref(), Some("https://relay.test"));
        } else {
            panic!("expected VisualizeRequest");
        }
    }

    #[test]
    fn visualize_result_wire_format() {
        // Verify exact wire format matches what Atem Rust sends
        let json = r#"{"type":"visualizeResult","data":{"session_id":"v1","success":true,"message":"ok","file_path":"/tmp/x.html"}}"#;
        let msg: AstationMessage = serde_json::from_str(json).unwrap();
        if let AstationMessage::VisualizeResult { session_id, success, message, file_path } = msg {
            assert_eq!(session_id, "v1");
            assert!(success);
            assert_eq!(message, "ok");
            assert_eq!(file_path.as_deref(), Some("/tmp/x.html"));
        } else {
            panic!("expected VisualizeResult");
        }
    }

    #[test]
    fn visualize_request_special_characters() {
        let msg = AstationMessage::VisualizeRequest {
            session_id: "vis-special".into(),
            topic: "design with \"quotes\" & <tags> 100%".into(),
            relay_url: Some("https://relay.test/path?a=1&b=2".into()),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::VisualizeRequest { topic, relay_url, .. } = parsed {
            assert!(topic.contains("\"quotes\""));
            assert!(topic.contains("<tags>"));
            assert!(topic.contains("100%"));
            assert!(relay_url.unwrap().contains("a=1&b=2"));
        } else {
            panic!("expected VisualizeRequest");
        }
    }

    #[test]
    fn visualize_result_failure_case() {
        let msg = AstationMessage::VisualizeResult {
            session_id: "vis-fail".into(),
            success: false,
            message: "No HTML diagram file was detected".into(),
            file_path: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        if let AstationMessage::VisualizeResult { success, message, file_path, .. } = parsed {
            assert!(!success);
            assert!(message.contains("No HTML"));
            assert!(file_path.is_none());
        } else {
            panic!("expected VisualizeResult");
        }
    }

    // ── PairSavePreference ────────────────────────────────

    #[test]
    fn pair_save_preference_roundtrip_true() {
        let msg = AstationMessage::PairSavePreference { save_credentials: true };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"pairSavePreference""#));
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        matches!(parsed, AstationMessage::PairSavePreference { save_credentials: true });
    }

    // --- AgentInput (remote agent control) ---

    #[test]
    fn agent_input_text_deserializes_from_astation_wire() {
        // Exact shape sent by Astation's sendAgentText (key omitted).
        let json = r#"{"type":"agentInput","data":{"agentId":"a1","kind":"text","text":"refactor auth"}}"#;
        let msg: AstationMessage = serde_json::from_str(json).unwrap();
        match msg {
            AstationMessage::AgentInput { agent_id, kind, text, key } => {
                assert_eq!(agent_id.as_deref(), Some("a1"));
                assert_eq!(kind, "text");
                assert_eq!(text.as_deref(), Some("refactor auth"));
                assert_eq!(key, None);
            }
            _ => panic!("expected AgentInput"),
        }
    }

    #[test]
    fn agent_input_key_deserializes_without_agent_id() {
        // sendAgentKey with agentId omitted (v1 focused-agent default).
        let json = r#"{"type":"agentInput","data":{"kind":"key","key":"ctrl-c"}}"#;
        let msg: AstationMessage = serde_json::from_str(json).unwrap();
        match msg {
            AstationMessage::AgentInput { agent_id, kind, text, key } => {
                assert_eq!(agent_id, None);
                assert_eq!(kind, "key");
                assert_eq!(text, None);
                assert_eq!(key.as_deref(), Some("ctrl-c"));
            }
            _ => panic!("expected AgentInput"),
        }
    }

    #[test]
    fn agent_input_roundtrips() {
        let msg = AstationMessage::AgentInput {
            agent_id: None,
            kind: "text".into(),
            text: Some("hi".into()),
            key: None,
        };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"agentInput""#));
        // nil fields are omitted on the wire
        assert!(!json.contains("agentId"));
        assert!(!json.contains("\"key\""));
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        matches!(parsed, AstationMessage::AgentInput { .. });
    }

    #[test]
    fn pair_save_preference_roundtrip_false() {
        let msg = AstationMessage::PairSavePreference { save_credentials: false };
        let json = serde_json::to_string(&msg).unwrap();
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        match parsed {
            AstationMessage::PairSavePreference { save_credentials } => {
                assert!(!save_credentials);
            }
            _ => panic!("wrong variant"),
        }
    }

    // --- atem_id shape + charset + uniqueness ---

    /// Every ASCII char of an atem_id must be in `[A-Za-z0-9-]`; non-ASCII (CJK
    /// etc.) is allowed through.
    fn assert_atem_id_charset(id: &str) {
        assert!(
            id.chars().all(|c| !c.is_ascii() || c.is_ascii_alphanumeric() || c == '-'),
            "atem_id has disallowed ASCII chars: {id}"
        );
    }

    #[test]
    fn atem_id_drops_dots_keeps_digits_and_truncates_to_12() {
        // Dot dropped; "host01" digits kept: "host-01.lan" → "host-01lan" → padded.
        let id = build_atem_id("host-01.lan", "550e8400-e29b-41d4-a716-446655440000");
        let (host, suffix) = id.rsplit_once('-').unwrap();
        assert!(host.starts_with("host-01lan"));
        assert_eq!(host.chars().count(), ATEM_ID_HOST_LEN);
        assert_eq!(suffix, "550e8400"); // first UUID block
        assert_atem_id_charset(&id);
    }

    #[test]
    fn atem_id_truncates_long_ascii_to_12() {
        let id = build_atem_id("MacBookPro2024Dev", "550e8400-e29b-41d4-a716-446655440000");
        let (host, _suffix) = id.rsplit_once('-').unwrap();
        assert_eq!(host, "MacBookPro20");
        assert_eq!(host.chars().count(), ATEM_ID_HOST_LEN);
    }

    #[test]
    fn atem_id_pads_short_hostname_to_12() {
        let id = build_atem_id("mbp", "550e8400-e29b-41d4-a716-446655440000");
        let (host, _suffix) = id.rsplit_once('-').unwrap();
        assert_eq!(host.chars().count(), ATEM_ID_HOST_LEN);
        assert!(host.starts_with("mbp"));
        assert_atem_id_charset(&id);
    }

    #[test]
    fn atem_id_keeps_chinese_hostname() {
        let id = build_atem_id("我的电脑", "abcdef12-3456-7890-abcd-ef1234567890");
        let (host, suffix) = id.rsplit_once('-').unwrap();
        assert!(host.starts_with("我的电脑"));
        assert_eq!(host.chars().count(), ATEM_ID_HOST_LEN);
        assert_eq!(suffix, "abcdef12");
        assert_atem_id_charset(&id);
    }

    #[test]
    fn atem_id_keeps_japanese_hostname() {
        // Mixed kanji + hiragana + katakana.
        let id = build_atem_id("私のパソコン端末", "550e8400-e29b-41d4-a716-446655440000");
        let (host, suffix) = id.rsplit_once('-').unwrap();
        assert!(host.starts_with("私のパソコン端末"));
        assert_eq!(host.chars().count(), ATEM_ID_HOST_LEN);
        assert_eq!(suffix, "550e8400");
        assert_atem_id_charset(&id);
    }

    #[test]
    fn atem_id_keeps_korean_hostname() {
        let id = build_atem_id("내컴퓨터", "550e8400-e29b-41d4-a716-446655440000");
        let (host, suffix) = id.rsplit_once('-').unwrap();
        assert!(host.starts_with("내컴퓨터"));
        assert_eq!(host.chars().count(), ATEM_ID_HOST_LEN);
        assert_eq!(suffix, "550e8400");
        assert_atem_id_charset(&id);
    }

    #[test]
    fn atem_id_truncates_long_non_ascii_hostname_by_chars() {
        // 14 CJK chars → truncated to 12 chars (not bytes).
        let id = build_atem_id("一二三四五六七八九十甲乙丙丁", "550e8400-e29b-41d4-a716-446655440000");
        let (host, _suffix) = id.rsplit_once('-').unwrap();
        assert_eq!(host.chars().count(), ATEM_ID_HOST_LEN);
        assert_eq!(host, "一二三四五六七八九十甲乙");
    }

    #[test]
    fn atem_id_keeps_mixed_korean_and_ascii_hostname() {
        // Korean + ASCII letters/digits kept; dot dropped.
        let id = build_atem_id("서버01.dev", "550e8400-e29b-41d4-a716-446655440000");
        let (host, _suffix) = id.rsplit_once('-').unwrap();
        assert!(host.starts_with("서버01dev"));
        assert_eq!(host.chars().count(), ATEM_ID_HOST_LEN);
        assert_atem_id_charset(&id);
    }

    #[test]
    fn atem_id_is_stable_for_same_inputs() {
        let a = build_atem_id("mbp", "11111111-aaaa-bbbb-cccc-dddddddddddd");
        let b = build_atem_id("mbp", "11111111-aaaa-bbbb-cccc-dddddddddddd");
        assert_eq!(a, b);
    }

    #[test]
    fn atem_id_unique_for_same_hostname_different_instance() {
        let a = build_atem_id("mbp", "11111111-aaaa-bbbb-cccc-dddddddddddd");
        let b = build_atem_id("mbp", "22222222-aaaa-bbbb-cccc-dddddddddddd");
        assert_ne!(a, b);
        assert!(a.starts_with("mbp"));
        assert!(b.starts_with("mbp"));
    }

    #[test]
    fn atem_id_is_hostname_only_when_instance_id_empty() {
        let id = build_atem_id("host", "");
        assert_eq!(id, "host");
    }

    // --- relay URL encoding ---

    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    #[test]
    fn relay_url_is_ascii_and_parses_for_non_ascii_atem_id() {
        let atem_id = build_atem_id("私のパソコン", "550e8400-e29b-41d4-a716-446655440000");
        let url = relay_ws_url("wss://relay.example", "astation-abc", &atem_id);

        // The built URL must be pure ASCII (percent-encoded UTF-8).
        assert!(url.is_ascii(), "relay URL not ASCII: {url}");

        // It must parse with the exact path the WS client uses (connect_async).
        assert!(
            url.as_str().into_client_request().is_ok(),
            "encoded relay URL rejected by WS client: {url}"
        );
    }

    #[test]
    fn relay_url_query_round_trips_to_canonical_atem_id() {
        let atem_id = build_atem_id("我的电脑", "550e8400-e29b-41d4-a716-446655440000");
        let url = relay_ws_url("wss://relay.example", "code", &atem_id);

        // Pull the atem_id query value back out and percent-decode it.
        let encoded = url.split("atem_id=").nth(1).unwrap();
        let decoded = urlencoding::decode(encoded).unwrap();
        assert_eq!(decoded, atem_id);
    }

    #[test]
    fn raw_non_ascii_atem_id_would_break_the_url() {
        // Demonstrates why encoding is required: a raw CJK value yields a URL the
        // WS client refuses to parse.
        let raw = "wss://relay.example/ws?role=atem&code=c&atem_id=我的电脑";
        assert!(
            raw.into_client_request().is_err(),
            "expected raw non-ASCII URL to be rejected"
        );
    }
}

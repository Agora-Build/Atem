use anyhow::{Result, anyhow};
use futures_util::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio_tungstenite::{connect_async, tungstenite::Message};

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

    #[serde(rename = "heartbeat")]
    Heartbeat { timestamp: String },

    #[serde(rename = "pong")]
    Pong { timestamp: String },
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

    pub async fn connect(&mut self, url: &str) -> Result<()> {
        let (ws_stream, _) = connect_async(url)
            .await
            .map_err(|e| anyhow!("Failed to connect to WebSocket: {}", e))?;

        let (mut write, mut read) = ws_stream.split();
        let (tx, rx) = mpsc::unbounded_channel::<AstationMessage>();
        let (msg_tx, mut msg_rx) = mpsc::unbounded_channel::<AstationMessage>();

        // Spawn task to handle outgoing messages
        tokio::spawn(async move {
            while let Some(message) = msg_rx.recv().await {
                if let Ok(json) = serde_json::to_string(&message) {
                    if let Err(e) = write.send(Message::Text(json)).await {
                        eprintln!("❌ Failed to send WebSocket message: {}", e);
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
                        println!("🔌 WebSocket connection closed by server");
                        break;
                    }
                    Err(e) => {
                        eprintln!("❌ WebSocket error: {}", e);
                        break;
                    }
                    _ => {}
                }
            }
        });

        self.sender = Some(msg_tx);
        self.receiver = Some(rx);

        // Send initial status update to let Astation know we're connected
        self.send_status_update("connected").await?;

        println!("🔌 Connected to Astation at {}", url);
        Ok(())
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

    pub async fn recv_message(&mut self) -> Option<AstationMessage> {
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
}

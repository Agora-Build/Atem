use anyhow::{Result, anyhow};
use futures_util::{SinkExt, StreamExt};
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::sync::mpsc;
use tokio::time::Duration;
use tokio_tungstenite::{connect_async, tungstenite::Message};

use crate::config::AtemConfig;

/// Authentication response from Astation
#[derive(Debug, PartialEq)]
pub(crate) enum AuthResponse {
    Authenticated,
    SessionExpired,
    Denied(String),
}

/// What a session Astation grants may do with the pairing record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GrantSave {
    /// Nothing is saved (re-authentication over an open socket).
    Never,
    /// Only `atem pair`'s connections: may start the record.
    Pairing,
    /// Background connections: only the existing record of the pairing
    /// this connection captured, bound to that Astation, gets the session;
    /// without one it stays in memory (never creates a record).
    UpdateBound,
}

/// A validated `auth_required` challenge (protocol v2).
struct AuthChallenge {
    astation_id: String,
    challenge: String,
    transport: String,
}

impl AuthChallenge {
    fn parse(auth_required: &AstationMessage) -> Result<Self> {
        let AstationMessage::StatusUpdate { data, .. } = auth_required else {
            return Err(anyhow!("Invalid auth_required message"));
        };
        let astation_id = data
            .get("astation_id")
            .ok_or_else(|| anyhow!("auth_required missing astation_id"))?
            .clone();
        if data.get("protocol").map(String::as_str) != Some("2") {
            return Err(anyhow!("Astation authentication protocol v2 is required"));
        }
        let challenge = data
            .get("challenge")
            .filter(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
            .ok_or_else(|| anyhow!("Invalid Astation authentication challenge"))?
            .clone();
        let transport = data
            .get("transport")
            .filter(|value| matches!(value.as_str(), "loopback" | "lan" | "relay"))
            .ok_or_else(|| anyhow!("Invalid Astation authentication transport"))?
            .clone();
        Ok(Self { astation_id, challenge, transport })
    }
}

/// True for Astation's `auth_required` challenge.
pub(crate) fn is_auth_required(message: &AstationMessage) -> bool {
    matches!(message, AstationMessage::StatusUpdate { status, .. } if status == "auth_required")
}

/// The family of a message the session host decodes itself (`session`,
/// `terminal`, `agentChat`), from its `type`.
pub(crate) fn session_family(text: &str) -> Option<&'static str> {
    #[derive(Deserialize)]
    struct Peek {
        #[serde(rename = "type")]
        kind: Option<String>,
    }
    let peek: Peek = serde_json::from_str(text).ok()?;
    match peek.kind.as_deref()? {
        "session" => Some("session"),
        "terminal" => Some("terminal"),
        "agentChat" => Some("agentChat"),
        _ => None,
    }
}

/// Message types removed in atem-session r6 (§0): no compatibility, but
/// still answered, so a sender learns they are gone.
pub(crate) const REMOVED_OPS: &[&str] = &[
    "agentInput",
    "agentPrompt",
    "voiceCommand",
    "voiceToggle",
    "voice_toggle",
    "voiceRequest",
    "userCommand",
    "codexTaskRequest",
    "agentListRequest",
];

/// `text` is one of the `REMOVED_OPS`.
pub(crate) fn is_removed_op(text: &str) -> bool {
    #[derive(Deserialize)]
    struct Peek {
        #[serde(rename = "type")]
        kind: Option<String>,
    }
    serde_json::from_str::<Peek>(text)
        .ok()
        .and_then(|p| p.kind)
        .is_some_and(|kind| REMOVED_OPS.contains(&kind.as_str()))
}

/// The `data.id` of a `session` message, when it has one (no other check).
fn session_message_id(text: &str) -> Option<String> {
    #[derive(Deserialize)]
    struct Data {
        id: Option<String>,
    }
    #[derive(Deserialize)]
    struct Outer {
        #[serde(rename = "type")]
        kind: String,
        data: Option<Data>,
    }
    let outer: Outer = serde_json::from_str(text).ok()?;
    (outer.kind == "session")
        .then_some(outer.data?.id?)
        .filter(|id| crate::session_protocol::wire::is_uuid_v4(id))
}

struct OutboundMessage {
    message: AstationMessage,
    delivered: Option<tokio::sync::oneshot::Sender<Result<(), String>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", content = "data")]
pub enum AstationMessage {
    /// A `session`, `terminal` or `agentChat` message as its raw JSON text:
    /// the session host decodes those strictly itself. Inbound messages of
    /// those families always arrive as this; outbound, the text is written
    /// as is.
    #[serde(skip)]
    SessionWire(String),

    /// A `session`, `terminal` or `agentChat` message over its size bound
    /// (not kept): answered with an `error` (`re` = its session `id`, when
    /// it had a readable one).
    #[serde(skip)]
    SessionOversize { id: Option<String>, family: String },

    /// An op removed in atem-session r6 (`REMOVED_OPS`): answered with an
    /// `error` `unsupported_version` and no effect.
    #[serde(skip)]
    RemovedOp,

    /// An r9 channel envelope (`{"type":"channel",…}`, atem-session-v1.md
    /// §R9.7a) as its raw JSON text: demultiplexed before every other
    /// message on the link, parsed strictly by the runtime's r9 host.
    /// Outbound, the text is written as is.
    #[serde(skip)]
    Channel(String),

    /// An r9 channel envelope over its 2 MiB bound (not kept, not
    /// parsed): its handle, closed `too_large`.
    #[serde(skip)]
    ChannelTooLarge(String),

    #[serde(rename = "terminal")]
    Terminal(crate::terminal_share::Envelope),

    #[serde(rename = "agentChat")]
    AgentChat(crate::chat::wire::ChatEnvelope),

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

    #[serde(rename = "credentialProjectListRequest")]
    CredentialProjectListRequest,

    #[serde(rename = "credentialProjectListResponse")]
    CredentialProjectListResponse { report: crate::memory::credential_projects::ProjectReportWire },

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

    /// Astation → Atem: the account's encryption mode, as a signed
    /// `atem-account-state-v1` statement. Messages without one are ignored.
    #[serde(rename = "encryptionMode")]
    EncryptionMode {
        #[serde(default)]
        account_state: Option<crate::memory::statements::SignedWire>,
    },

    /// Atem → Astation: a verified device asks for `K`; `public_key` is its
    /// base64 X25519 device key, which Astation checks against its pin.
    #[serde(rename = "keyRequest")]
    KeyRequest { public_key: String },

    /// Astation → Atem: `K` sealed to this device with a signed grant.
    #[serde(rename = "keyGrant")]
    KeyGrant {
        #[serde(default)]
        grant: Option<crate::memory::grant::GrantWire>,
    },

    /// Atem → Astation: start device verification with a commitment to keys
    /// atem hasn't revealed yet. All values base64.
    #[serde(rename = "verifyCommit")]
    VerifyCommit { device_id: String, commitment: String },

    /// Astation → Atem: Astation's public keys and nonce, sent only after it
    /// stored the commitment. `sign_pub` is a 65-byte SEC1 P-256 point.
    /// r9 (§R9.2 "Pairing"): `genesis_hash` (hex) names the account's
    /// device list; a verifyKeys without it can't pin one and is refused.
    #[serde(rename = "verifyKeys")]
    VerifyKeys {
        sign_pub: String,
        enc_pub: String,
        recovery_sign_pub: String,
        nonce: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        genesis_hash: Option<String>,
    },

    /// Atem → Astation: the keys and nonce behind the commitment.
    /// r9: `host_channel_pub` (base64url, §R9.1) is this host's new
    /// `host_channel_key`, inside the commitment.
    #[serde(rename = "verifyReveal")]
    VerifyReveal {
        device_pub: String,
        device_sign_pub: String,
        unlock_auth_pub: String,
        host_channel_pub: String,
        nonce: String,
    },

    /// Astation → Atem: after Touch ID, the signed device certificate, the
    /// signed account state, and signed grants (`K` when it exists).
    #[serde(rename = "deviceVerified")]
    DeviceVerified {
        device_verified: crate::memory::statements::SignedWire,
        account_state: crate::memory::statements::SignedWire,
        #[serde(default)]
        grants: Vec<crate::memory::grant::GrantWire>,
        /// r9: `{"entries": [...]}`, the device list from its genesis to
        /// the `add_host` naming this host (§R9.2 "Pairing").
        #[serde(default, skip_serializing_if = "Option::is_none")]
        membership: Option<serde_json::Value>,
    },

    /// Either side: verification was cancelled; discard everything from it.
    #[serde(rename = "verifyAbort")]
    VerifyAbort { reason: String },

    /// Atem → Astation: an `atem-unlock-request-v1` statement (base64) and
    /// its Ed25519 signature by this device's unlock-auth key.
    #[serde(rename = "unlockRequest")]
    UnlockRequest { request: String, signature: String },

    /// Astation → Atem: after Touch ID, the storage key sealed to the
    /// request's `e_pub`, with a signed `atem-unlock-grant-v1`.
    #[serde(rename = "unlockGrant")]
    UnlockGrant { grant: crate::memory::statements::SignedWire, encapped_key: String, ciphertext: String },

    /// Astation → Atem: the unlock was denied. `revoked` is set when the
    /// user chose Deny and revoke (older Astations only say so in `reason`).
    #[serde(rename = "unlockDenied")]
    UnlockDenied {
        reason: String,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        revoked: bool,
    },

    /// Atem → Astation: a storage key sealed to Astation's encryption key,
    /// with a device-signed `atem-storage-rotate-v1`.
    #[serde(rename = "storageKeyRotate")]
    StorageKeyRotate { rotate: crate::memory::statements::SignedWire, encapped_key: String, ciphertext: String },

    /// Astation → Atem: the storage key is stored as pending (`atem-storage-ack-v1`).
    #[serde(rename = "storageKeyAck")]
    StorageKeyAck { ack: crate::memory::statements::SignedWire },

    /// Astation → Atem: the rotate was refused. `pending_kid` names the
    /// pending key Astation is committed to when that is the reason; the
    /// device may give it up with `storageKeyAbandon` and send the rotate again.
    #[serde(rename = "storageKeyRejected")]
    StorageKeyRejected {
        reason: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pending_kid: Option<String>,
    },

    /// Atem → Astation: this device switched to the new storage key
    /// (device-signed `atem-storage-confirm-v1`); Astation drops the old one.
    #[serde(rename = "storageKeyConfirm")]
    StorageKeyConfirm { confirm: crate::memory::statements::SignedWire },

    /// Atem → Astation: a device-signed `atem-storage-abandon-v1`; Astation
    /// drops its pending key only if it is exactly the one named (the kid
    /// stays acked, so it is never reused). A replay is a no-op.
    #[serde(rename = "storageKeyAbandon")]
    StorageKeyAbandon { abandon: crate::memory::statements::SignedWire },

    #[serde(rename = "encryptionMigrationComplete")]
    EncryptionMigrationComplete { mode: String, kid: String, completion: crate::memory::statements::SignedWire },

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

/// Channel envelopes handed to the link and not yet written, at most (bytes):
/// beyond it `try_send_channel` refuses and the r9 host's per-channel
/// queues hold the rest (§R9.7a "Bounds").
const CHANNEL_INFLIGHT_BYTES: usize = 8 << 20;

pub struct AstationClient {
    sender: Option<mpsc::UnboundedSender<OutboundMessage>>,
    /// Bytes of channel envelopes queued on `sender` and not yet written.
    channel_inflight: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    terminal_sender: Option<mpsc::Sender<OutboundMessage>>,
    receiver: Option<mpsc::Receiver<AstationMessage>>,
    transport_tasks: Vec<tokio::task::JoinHandle<()>>,
    atem_id_override: Option<String>,
    #[cfg(test)]
    #[cfg(test)]
    local_token_path_override: Option<std::path::PathBuf>,
    /// Set to true when the WebSocket reader task exits (connection dropped).
    ws_closed: bool,
    connected_astation_id: Option<String>,
    /// The newest challenge answered on this socket, as (astation_id,
    /// challenge): a repeat of it is spent and is not answered again.
    answered_challenge: Option<(String, String)>,
    /// Encryption messages held until they can be applied: ones that arrived
    /// before Astation said who it is (a pairing-code relay connection never
    /// authenticates), or during device verification.
    held_encryption: Vec<AstationMessage>,
    /// The profile whose pairing errors advise on (`with_profile`); `None`
    /// is this user's profile.
    profile: Option<crate::profile::Sources>,
    /// The pairing state and session this connection's authentication
    /// started under, captured before the proof went out. Every reply with
    /// effects (auth success, credentials, encryption, keys) is applied only
    /// while it is still current (`pairing::Captured::apply`).
    capture: Option<crate::pairing::Captured>,
    /// Shows the pairing code and its outcome (`authenticate_with_pairing`);
    /// `None` prints them. The runtime sends them to the CLI that pairs.
    pairing_notice: Option<std::sync::Arc<dyn Fn(&str) + Send + Sync>>,
    /// The cred agent encryption messages and reports use (`with_agent`);
    /// `None` is this user's agent.
    agent: Option<std::sync::Arc<dyn crate::memory::cred_agent::CredAgentApi>>,
    /// A handle for one runtime operation (`op_view`): it waits for a
    /// migration the link is finishing instead of skipping its own.
    is_op_view: bool,
    /// How this client reached Astation, once connected (`atem status`).
    via: Option<LinkVia>,
}

/// How a link reached Astation, for `atem status`: never a secret (no
/// session, token or relay room code).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkVia {
    Local,
    /// The relay's host and this Atem's id in the room.
    Relay { label: String },
}

/// `<relay host> as <atem_id>`: what `atem status` shows for a relay link.
pub(crate) fn relay_label(relay_url: &str, atem_id: &str) -> String {
    let host = relay_url
        .split_once("://")
        .map_or(relay_url, |(_, rest)| rest)
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .rsplit('@')
        .next()
        .unwrap_or_default();
    if atem_id.is_empty() {
        host.to_string()
    } else {
        format!("{host} as {atem_id}")
    }
}

/// One encryption migration at a time per process: the runtime's link and
/// an operation on it may both be asked to finish one.
pub(crate) static MIGRATION: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Why a connection couldn't authenticate with the saved session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionProblem {
    /// Astation denied the saved session.
    Refused,
    /// No saved session for this Astation.
    Missing,
    /// The session didn't authenticate and pairing isn't allowed here.
    PairingRequired,
}

/// A `SessionProblem` with its message; `advised` when the message already
/// says to run `atem unpair`, then `atem pair` (a paired profile).
#[derive(Debug)]
pub struct SessionError {
    pub problem: SessionProblem,
    pub advised: bool,
    message: String,
}

impl SessionError {
    pub fn new(problem: SessionProblem, advised: bool, message: String) -> Self {
        Self { problem, advised, message }
    }
}

impl std::fmt::Display for SessionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for SessionError {}

/// Status of an encryption message held for later; internal, not shown.
pub const HOLDING_ENCRYPTION: &str = "Holding an encryption message until Astation's identity is known";

/// At most this many held encryption messages are kept (the newest).
const MAX_HELD_ENCRYPTION: usize = 16;

impl AstationClient {
    pub fn new() -> Self {
        Self {
            sender: None,
            channel_inflight: Default::default(),
            receiver: None,
            terminal_sender: None,
            transport_tasks: Vec::new(),
            atem_id_override: None,
            #[cfg(test)]
            #[cfg(test)]
            local_token_path_override: None,
            ws_closed: false,
            connected_astation_id: None,
            answered_challenge: None,
            held_encryption: Vec::new(),
            profile: None,
            capture: None,
            pairing_notice: None,
            agent: None,
            is_op_view: false,
            via: None,
        }
    }

    /// Encryption messages and reports use `agent` (not this user's).
    pub(crate) fn with_agent(
        mut self,
        agent: std::sync::Arc<dyn crate::memory::cred_agent::CredAgentApi>,
    ) -> Self {
        self.agent = Some(agent);
        self
    }

    /// The cred agent of this client (started on demand when it's the user's).
    fn cred_agent(&self) -> std::sync::Arc<dyn crate::memory::cred_agent::CredAgentApi> {
        match &self.agent {
            Some(agent) => agent.clone(),
            None => std::sync::Arc::from(crate::memory::cred_agent::default_agent()),
        }
    }

    /// The running cred agent of this client, never started.
    fn running_cred_agent(&self) -> Option<std::sync::Arc<dyn crate::memory::cred_agent::CredAgentApi>> {
        match &self.agent {
            Some(agent) => Some(agent.clone()),
            None => crate::memory::cred_agent::running_agent().map(std::sync::Arc::from),
        }
    }

    /// This client's profile (`with_profile`, else this user's).
    pub(crate) fn profile(&self) -> Result<crate::profile::Sources> {
        self.profile_sources()
    }

    /// Pairing lines go to `notice` instead of stdout.
    pub(crate) fn with_pairing_notice(
        mut self,
        notice: std::sync::Arc<dyn Fn(&str) + Send + Sync>,
    ) -> Self {
        self.pairing_notice = Some(notice);
        self
    }

    fn pairing_line(&self, text: &str) {
        match &self.pairing_notice {
            Some(notice) => notice(text),
            None => println!("{text}"),
        }
    }

    /// A handle for one operation on this link (`atem runtime`'s Astation
    /// operations): it sends through this link's writer and receives only
    /// what the link's owner routes to it through the returned sender. It
    /// shares the link's identity and captured pairing; dropping it leaves
    /// the link alone.
    pub(crate) fn op_view(&self) -> (Self, mpsc::Sender<AstationMessage>) {
        let (tx, rx) = mpsc::channel(64);
        let mut view = Self::new();
        view.sender = self.sender.clone();
        view.channel_inflight = self.channel_inflight.clone();
        view.terminal_sender = self.terminal_sender.clone();
        view.receiver = Some(rx);
        view.atem_id_override = self.atem_id_override.clone();
        #[cfg(test)]
        {
            view.local_token_path_override = self.local_token_path_override.clone();
        }
        view.connected_astation_id = self.connected_astation_id.clone();
        view.profile = self.profile.clone();
        view.capture = self.capture.clone();
        view.agent = self.agent.clone();
        view.is_op_view = true;
        (view, tx)
    }

    /// This atem's relay identity (`atem_id`), the device id verification uses.
    pub(crate) fn device_atem_id(&self) -> String {
        self.resolved_atem_id(&crate::auth::get_hostname())
    }

    /// The profile this client reads and writes (`with_profile`, else this
    /// user's). Test clients must name one.
    fn profile_sources(&self) -> Result<crate::profile::Sources> {
        match &self.profile {
            Some(profile) => Ok(profile.clone()),
            None if cfg!(test) => Err(anyhow!("test client without a profile")),
            None => crate::profile::Sources::current(),
        }
    }

    /// The pairing this connection authenticated under.
    pub(crate) fn capture(&self) -> Option<&crate::pairing::Captured> {
        self.capture.as_ref()
    }

    /// This run's `atem pair` created a binding (`bind_new`) from `before`:
    /// the connection goes on under it.
    pub(crate) fn adopt_binding(
        &mut self,
        before: &crate::pairing::TrustState,
        after: &crate::pairing::TrustState,
    ) -> Result<()> {
        self.capture
            .as_mut()
            .ok_or_else(|| anyhow!(crate::pairing::NO_BINDING))?
            .adopt(before, after)
    }

    /// Runs `apply` (blocking file work) only while this connection's
    /// pairing and session are the ones its authentication captured, under
    /// the pairing lock.
    fn guarded<T>(&self, apply: impl FnOnce() -> Result<T>) -> Result<T> {
        let capture = self
            .capture
            .as_ref()
            .ok_or_else(|| anyhow!("this connection has no captured pairing; nothing was applied"))?;
        capture.apply(|| {
            self.check_session(capture)?;
            apply()
        })
    }

    /// The saved session is still the one the proof used (when one was).
    fn check_session(&self, capture: &crate::pairing::Captured) -> Result<()> {
        let (Some((session_id, token)), Some(astation_id)) =
            (&capture.session, self.connected_astation_id.as_deref())
        else {
            return Ok(());
        };
        let current = self.saved_session(astation_id)?;
        if current.is_some_and(|s| &s.session_id == session_id && &s.token == token) {
            Ok(())
        } else {
            Err(anyhow!(
                "The saved Astation session changed while this connection authenticated; nothing from it was applied"
            ))
        }
    }

    /// Runs `apply` only while this connection is bound to `astation_id`'s
    /// current pairing (credentials Astation sends, for example).
    pub(crate) fn apply_bound<T>(&self, astation_id: &str, apply: impl FnOnce() -> Result<T>) -> Result<T> {
        let capture = self
            .capture
            .as_ref()
            .ok_or_else(|| anyhow!(crate::pairing::NO_BINDING))?;
        capture.bound_to(astation_id)?;
        if self.connected_astation_id.as_deref() != Some(astation_id) {
            return Err(anyhow!("this connection authenticated another Astation than {astation_id}"));
        }
        self.guarded(apply)
    }

    /// A saved session may answer `astation_id` only when the captured
    /// pairing binding is with it: after an `atem unpair` that stopped before
    /// removing the sessions (or one for another Astation), it is never used.
    fn session_usable(&self, astation_id: &str) -> bool {
        self.capture
            .as_ref()
            .and_then(|capture| capture.state.binding.as_ref())
            .is_some_and(|binding| binding.astation_id == astation_id)
    }

    /// No saved session may answer: what to do (`advised` when the message
    /// says to unpair). `unpaired` is the message for a profile not paired.
    fn no_session(&self, problem: SessionProblem, lead: &str, unpaired: &str) -> anyhow::Error {
        let paired = self.profile_paired();
        let unbound = self
            .capture
            .as_ref()
            .is_some_and(|capture| capture.state.binding.is_none());
        let message = if paired && unbound {
            format!("{lead}. {}", crate::pairing::NO_BINDING)
        } else if paired {
            format!("{lead}. {}", crate::status::SESSION_GONE)
        } else {
            unpaired.to_string()
        };
        SessionError::new(problem, paired, message).into()
    }

    #[cfg(test)]
    pub(crate) fn set_capture_for_test(&mut self, capture: crate::pairing::Captured) {
        self.capture = Some(capture);
    }

    /// Advise on pairing errors from `profile` instead of this user's profile.
    pub(crate) fn with_profile(mut self, profile: crate::profile::Sources) -> Self {
        self.profile = Some(profile);
        self
    }

    /// Whether the client's profile is paired (`status::profile_paired`).
    pub(crate) fn profile_paired(&self) -> bool {
        match &self.profile {
            Some(profile) => crate::status::profile_paired(profile),
            None => crate::status::current_profile_paired(),
        }
    }

    /// The Astation this client authenticated with, once it said who it is.
    pub fn connected_astation_id(&self) -> Option<&str> {
        self.connected_astation_id.as_deref()
    }

    /// How this client reached Astation (`None`: not connected yet).
    pub fn via(&self) -> Option<&LinkVia> {
        self.via.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn new_with_test_state(atem_id: &str, profile: &std::path::Path) -> Self {
        let mut client = Self::new();
        client.atem_id_override = Some(atem_id.to_string());
        client.profile = Some(crate::profile::Sources::in_dir(profile));
        client
    }

    /// The connect-time challenge/response alone (no credential report).
    #[cfg(test)]
    pub(crate) async fn authenticate_for_test(&mut self) -> Result<()> {
        let auth_required = self
            .wait_for_message(is_auth_required)
            .await
            .ok_or_else(|| anyhow!("Connection closed before auth_required"))?;
        self.authenticate_after_challenge(auth_required, false).await
    }

    /// Pretend the connect-time authentication pinned `astation_id`.
    #[cfg(test)]
    /// Also captures the profile's pairing and saved session, as the
    /// connect-time authentication does.
    pub(crate) fn pin_astation_for_test(&mut self, astation_id: &str) {
        self.connected_astation_id = Some(astation_id.to_string());
        let profile = self.profile_sources().expect("a test profile");
        let mut capture = crate::pairing::Captured::now(&profile).unwrap();
        capture.session = self
            .saved_session(astation_id)
            .unwrap()
            .map(|s| (s.session_id, s.token));
        self.capture = Some(capture);
    }

    fn resolved_atem_id(&self, hostname: &str) -> String {
        self.atem_id_override
            .clone()
            .unwrap_or_else(|| resolved_atem_id(hostname))
    }

    /// The pairing's valid saved session for `astation_id`.
    fn saved_session(&self, astation_id: &str) -> Result<Option<crate::records::SavedSession>> {
        let paths = self.profile_sources()?.paths.pairing;
        Ok(crate::records::PairingRecord::load(&paths)?
            .and_then(|record| record.session_for(astation_id).cloned()))
    }

    /// Saves the session Astation granted `astation_id` as `mode` allows
    /// (under the pairing lock, `guarded`): whether it was saved. Only a
    /// pairing in progress (`atem pair`) starts a record.
    fn persist_session(
        &self,
        astation_id: &str,
        session: crate::records::SavedSession,
        mode: GrantSave,
    ) -> Result<bool> {
        let paths = self.profile_sources()?.paths.pairing;
        match mode {
            GrantSave::Never => Ok(false),
            GrantSave::Pairing => {
                let mut record = crate::records::PairingRecord::load(&paths)?
                    .filter(|record| record.astation_id == astation_id)
                    .unwrap_or_else(|| crate::records::PairingRecord::new(astation_id));
                record.session = Some(session);
                record.save(&paths)?;
                Ok(true)
            }
            GrantSave::UpdateBound => {
                let bound = self
                    .capture
                    .as_ref()
                    .is_some_and(|capture| capture.bound_to(astation_id).is_ok());
                if !bound {
                    return Ok(false);
                }
                crate::records::PairingRecord::update_locked(&paths, astation_id, |record| {
                    record.session = Some(session);
                })
            }
        }
    }

    fn abort_transport(&mut self) {
        self.sender = None;
        self.terminal_sender = None;
        self.receiver = None;
        for task in self.transport_tasks.drain(..) {
            task.abort();
        }
        self.ws_closed = true;
        self.answered_challenge = None;
        self.capture = None;
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
        } else {
            self.via = Some(LinkVia::Local);
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
        let (tx, rx) = mpsc::channel::<AstationMessage>(64);
        let (msg_tx, mut msg_rx) = mpsc::unbounded_channel::<OutboundMessage>();

        let (terminal_tx, mut terminal_rx) = mpsc::channel::<OutboundMessage>(32);
        // A new socket: nothing of the old one is in flight.
        self.channel_inflight = Default::default();
        let inflight = self.channel_inflight.clone();

        // Spawn task to handle outgoing messages
        let writer_task = tokio::spawn(async move {
            loop {
                let outbound = tokio::select! {
                    outbound = msg_rx.recv() => outbound,
                    outbound = terminal_rx.recv() => outbound,
                };
                let Some(outbound) = outbound else { break; };
                if let AstationMessage::Channel(text) = &outbound.message {
                    inflight.fetch_sub(text.len(), std::sync::atomic::Ordering::Relaxed);
                }
                let encoded = match &outbound.message {
                    AstationMessage::SessionWire(text) | AstationMessage::Channel(text) => Ok(text.clone()),
                    message => serde_json::to_string(message),
                };
                let result = match encoded {
                    Ok(json) => write.send(Message::Text(json)).await.map_err(|_| "WebSocket write failed".to_string()),
                    Err(_) => Err("WebSocket message encoding failed".to_string()),
                };
                let failed = result.is_err();
                if let Some(delivered) = outbound.delivered { let _ = delivered.send(result); }
                if failed { break; }
            }
        });

        // Spawn task to handle incoming messages
        let reader_task = tokio::spawn(async move {
            while let Some(message) = read.next().await {
                match message {
                    Ok(Message::Text(text)) => {
                        // §R9.7a 7: channel traffic is demultiplexed first;
                        // one over its bound is never parsed (its handle only,
                        // from its first bytes, for the `too_large` close).
                        if text.len() > crate::session_protocol::r9::envelope::MAX_ENVELOPE_BYTES {
                            if let Some(handle) = crate::session_protocol::r9::envelope::oversize_envelope(&text) {
                                if let Some(handle) = handle
                                    && tx.send(AstationMessage::ChannelTooLarge(handle)).await.is_err()
                                {
                                    break;
                                }
                                continue;
                            }
                        } else if crate::session_protocol::r9::envelope::is_envelope(&text) {
                            if tx.send(AstationMessage::Channel(text)).await.is_err() {
                                break;
                            }
                            continue;
                        }
                        let astation_msg = match session_family(&text) {
                            Some(family) if text.len() > if family == "terminal" { 32 * 1024 } else { crate::session_protocol::wire::MAX_MESSAGE_BYTES } => {
                                Some(AstationMessage::SessionOversize { id: session_message_id(&text), family: family.to_string() })
                            }
                            Some(_) => Some(AstationMessage::SessionWire(text)),
                            None if is_removed_op(&text) => Some(AstationMessage::RemovedOp),
                            None => serde_json::from_str::<AstationMessage>(&text).ok(),
                        };
                        if let Some(astation_msg) = astation_msg
                            && tx.send(astation_msg).await.is_err()
                        {
                            break; // Receiver has been dropped
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
        self.terminal_sender = Some(terminal_tx);
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
            self.wait_for_message(is_auth_required)
        )
        .await
        .map_err(|_| anyhow!("Timeout waiting for auth_required"))?
        .ok_or_else(|| anyhow!("Connection closed before auth_required"))?;

        let result = tokio::time::timeout(
            completion_timeout,
            self.authenticate_after_challenge(auth_required, allow_pairing),
        )
        .await
        .map_err(|_| anyhow!("Authentication timed out"))?;
        if result.is_ok() { let _ = self.report_credential_projects().await; }
        result
    }

    async fn authenticate_after_challenge(
        &mut self,
        auth_required: AstationMessage,
        allow_pairing: bool,
    ) -> Result<()> {
        // Remember who answered, even when the rest of the challenge is invalid.
        if let AstationMessage::StatusUpdate { data, .. } = &auth_required
            && let Some(astation_id) = data.get("astation_id")
        {
            self.connected_astation_id = Some(astation_id.clone());
        }
        let challenge = AuthChallenge::parse(&auth_required)?;
        let astation_id = challenge.astation_id.clone();
        // What this authentication runs under, captured before any proof
        // goes out: a reply that arrives after `atem unpair`/`atem pair`
        // can't adopt the later binding or refresh its session.
        self.capture = Some(crate::pairing::Captured::now(&self.profile_sources()?)?);

        if let Some((proof, session)) = self.auth_proof(&challenge)? {
            if let Some(capture) = self.capture.as_mut() {
                capture.session = session;
            }
            self.send_message(proof).await?;
            self.answered_challenge = Some((astation_id.clone(), challenge.challenge.clone()));
            let save = if allow_pairing { GrantSave::Pairing } else { GrantSave::UpdateBound };
            let response = self.wait_for_auth_response(&astation_id, save).await?;
            if challenge.transport == "loopback" {
                return match response {
                    Some(AuthResponse::Authenticated) => self.guarded(|| Ok(())),
                    Some(AuthResponse::Denied(message)) => {
                        Err(anyhow!("Local authentication denied: {}", message))
                    }
                    Some(AuthResponse::SessionExpired) => {
                        Err(anyhow!("Unexpected local session expiry"))
                    }
                    None => Err(anyhow!("Connection closed during local authentication")),
                };
            }
            match response {
                Some(AuthResponse::Authenticated) => {
                    return self.guarded(|| {
                        self.refresh_saved_session(&astation_id);
                        Ok(())
                    });
                }
                // Fall through to pairing.
                Some(AuthResponse::SessionExpired) | None => {}
                Some(AuthResponse::Denied(msg)) => {
                    let message = format!("Authentication denied: {}", msg);
                    return Err(SessionError::new(SessionProblem::Refused, false, message).into());
                }
            }
        }

        let hostname = crate::auth::get_hostname();
        let atem_id = self.resolved_atem_id(&hostname);
        if !allow_pairing {
            return Err(self.no_session(
                SessionProblem::PairingRequired,
                "Pairing required",
                "Pairing required; run 'atem pair'",
            ));
        }

        // Session auth failed or no session - use explicit pairing.
        if let Some(capture) = self.capture.as_mut() {
            capture.session = None;
        }
        self.authenticate_with_pairing(&astation_id, &atem_id).await?;
        // Later checks compare against the session the grant saved.
        let granted = self
            .saved_session(&astation_id)?
            .map(|s| (s.session_id, s.token));
        if let Some(capture) = self.capture.as_mut() {
            capture.session = granted;
        }
        Ok(())
    }

    /// Authenticate using pairing code (fallback when session invalid/missing)
    async fn authenticate_with_pairing(&mut self, astation_id: &str, atem_id: &str) -> Result<()> {
        // Generate pairing code
        let pairing_code = crate::auth::generate_otp();
        let hostname = crate::auth::get_hostname();

        self.pairing_line("🔐 Pairing with Astation...");
        self.pairing_line(&format!("   Code: {}", pairing_code));
        self.pairing_line("   Waiting for approval...");

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
            self.wait_for_auth_response(astation_id, GrantSave::Pairing)
        )
        .await
        .map_err(|_| anyhow!("Pairing timed out after 5 minutes"))??;

        match response {
            Some(AuthResponse::Authenticated) => {
                self.pairing_line("✅ Pairing approved!");
                Ok(())
            }
            Some(AuthResponse::Denied(msg)) => {
                self.pairing_line(&format!("❌ Pairing denied: {}", msg));
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

    /// Build the non-interactive proof answering `challenge`: the local
    /// bootstrap proof on loopback, else the saved session's proof. `None` when
    /// there is no saved session for that Astation. Shared by the connect path
    /// and re-authentication over an open socket so the two can't drift.
    /// Also returns the saved session the proof used (`None` on loopback).
    #[allow(clippy::type_complexity)]
    fn auth_proof(
        &self,
        challenge: &AuthChallenge,
    ) -> Result<Option<(AstationMessage, Option<(String, String)>)>> {
        let hostname = crate::auth::get_hostname();
        let atem_id = self.resolved_atem_id(&hostname);
        let astation_id = &challenge.astation_id;
        let mut auth_data = std::collections::HashMap::new();
        let mut used = None;
        if challenge.transport == "loopback" {
            let token = self
                .local_bootstrap_token()
                .ok_or_else(|| anyhow!("Astation local bootstrap token is unavailable"))?;
            auth_data.insert("method".to_string(), "local_proof".to_string());
            auth_data.insert("atem_id".to_string(), atem_id.clone());
            auth_data.insert("hostname".to_string(), hostname);
            auth_data.insert(
                "proof".to_string(),
                device_auth_proof(&token, &challenge.challenge, astation_id, &atem_id, "local")?,
            );
        } else {
            if !self.session_usable(astation_id) {
                return Ok(None);
            }
            let Some(session) = self.saved_session(astation_id)? else {
                return Ok(None);
            };
            used = Some((session.session_id.clone(), session.token.clone()));
            auth_data.insert("session_id".to_string(), session.session_id.clone());
            auth_data.insert("atem_id".to_string(), atem_id.clone());
            auth_data.insert(
                "proof".to_string(),
                device_auth_proof(
                    &session.token,
                    &challenge.challenge,
                    astation_id,
                    &atem_id,
                    &session.session_id,
                )?,
            );
        }
        let proof = AstationMessage::StatusUpdate {
            status: "auth".to_string(),
            data: auth_data,
        };
        Ok(Some((proof, used)))
    }

    fn local_bootstrap_token(&self) -> Option<String> {
        #[cfg(all(test, unix))]
        if let Some(path) = self.local_token_path_override.as_deref() {
            return read_local_bootstrap_token_from(path);
        }
        read_local_bootstrap_token()
    }

    /// Refresh the saved session's activity after a successful session proof.
    fn refresh_saved_session(&self, astation_id: &str) {
        let result = self.profile_sources().and_then(|src| {
            crate::records::PairingRecord::update_locked(&src.paths.pairing, astation_id, |record| {
                if let Some(session) = record.session.as_mut().filter(|s| s.is_valid()) {
                    session.last_activity = crate::credentials::now_secs();
                }
            })
        });
        if let Err(error) = result {
            crate::diagnostics::warn(format!(
                "Warning: could not refresh saved Astation session: {error}"
            ));
        }
    }

    /// Answer an `auth_required` that arrives on an already-authenticated
    /// socket (Astation reconnected to the relay, which kept this socket).
    /// Only the pinned Astation is answered, and only non-interactively; the
    /// proof is queued without waiting.
    pub(crate) async fn answer_auth_required(&mut self, auth_required: &AstationMessage) -> Result<()> {
        let challenge = AuthChallenge::parse(auth_required)?;
        let pinned = self
            .connected_astation_id
            .as_deref()
            .ok_or_else(|| anyhow!("this connection never authenticated an Astation"))?;
        if challenge.astation_id != pinned {
            return Err(anyhow!(
                "Astation {} challenged a connection authenticated with {pinned}",
                challenge.astation_id
            ));
        }
        // Only for the pairing and session this connection authenticated
        // with: never answer with a replacement's session.
        self.guarded(|| Ok(()))?;
        let (proof, _) = self
            .auth_proof(&challenge)?
            .ok_or_else(|| {
                self.no_session(
                    SessionProblem::Missing,
                    "no saved session for this Astation",
                    "no saved session for this Astation; run `atem pair`",
                )
            })?;
        self.send_message(proof).await?;
        self.answered_challenge = Some((challenge.astation_id, challenge.challenge));
        Ok(())
    }

    /// True when `auth_required` repeats the challenge this socket already
    /// answered, from the same Astation (Astation re-sends a pending challenge
    /// when a hello races it). Answering a spent challenge would be denied.
    pub(crate) fn is_answered_challenge(&self, auth_required: &AstationMessage) -> bool {
        let AstationMessage::StatusUpdate { data, .. } = auth_required else { return false; };
        self.answered_challenge.as_ref().is_some_and(|(astation_id, challenge)| {
            data.get("astation_id") == Some(astation_id) && data.get("challenge") == Some(challenge)
        })
    }

    /// Keeps the saved session fresh (after a re-authentication, and while
    /// the link is in use; it expires after 7 days without activity), only
    /// while the pairing and session are still the ones this connection
    /// authenticated with (else nothing is touched).
    pub(crate) fn refresh_session(&self) -> Result<()> {
        self.guarded(|| {
            if let Some(astation_id) = self.connected_astation_id.as_deref() {
                self.refresh_saved_session(astation_id);
            }
            Ok(())
        })
    }

    /// Classify one message as an authentication response for `astation_id`.
    /// `None` when it is not one. A grant's new session is saved as `save`
    /// allows (only pairing starts a record; re-authentication saves none).
    pub(crate) fn auth_response(&self, msg: &AstationMessage, astation_id: &str, save: GrantSave) -> Result<Option<AuthResponse>> {
        Ok(self.auth_response_saving(msg, astation_id, save)?.map(|(response, _)| response))
    }

    /// `auth_response`, plus the granted session (`(session_id, token)`)
    /// when it was saved.
    #[allow(clippy::type_complexity)]
    fn auth_response_saving(&self, msg: &AstationMessage, astation_id: &str, save: GrantSave) -> Result<Option<(AuthResponse, Option<(String, String)>)>> {
        let AstationMessage::StatusUpdate { status, data } = msg else { return Ok(None); };
        let response = |response| Ok(Some((response, None)));
        match status.as_str() {
            "auth" => match data.get("status").map(String::as_str) {
                Some("granted") if save == GrantSave::Never => response(AuthResponse::Authenticated),
                Some("granted") => {
                    let session_id = data.get("session_id").ok_or_else(|| {
                        anyhow!("Pairing response missing session ID")
                    })?;
                    let token = data.get("token").ok_or_else(|| {
                        anyhow!("Pairing response missing session token")
                    })?;
                    let session = crate::records::SavedSession::new(
                        session_id.clone(),
                        token.clone(),
                        crate::auth::get_hostname(),
                    );

                    let saved = self.guarded(|| self.persist_session(astation_id, session, save))?;
                    let saved = saved.then(|| (session_id.clone(), token.clone()));
                    Ok(Some((AuthResponse::Authenticated, saved)))
                }
                Some("denied") => {
                    let msg = data.get("message")
                        .map(|s| s.as_str())
                        .unwrap_or("Unknown reason");
                    response(AuthResponse::Denied(msg.to_string()))
                }
                _ => Ok(None),
            },
            "authenticated" => {
                // Alternative authenticated message format
                self.guarded(|| Ok(()))?;
                response(AuthResponse::Authenticated)
            }
            "error" => Ok(data.get("message").map(|msg| {
                let lower = msg.to_ascii_lowercase();
                if lower.contains("expired") || lower.contains("pairing required") {
                    AuthResponse::SessionExpired
                } else {
                    AuthResponse::Denied(msg.clone())
                }
            }).map(|response| (response, None))),
            _ => Ok(None),
        }
    }

    /// Wait for auth response message and save the session if granted (as
    /// `save` allows).
    async fn wait_for_auth_response(&mut self, astation_id: &str, save: GrantSave) -> Result<Option<AuthResponse>> {
        while let Some(msg) = self.recv_message_async().await {
            if let Some((response, saved)) = self.auth_response_saving(&msg, astation_id, save)? {
                // A grant saved a new session (under the captured pairing):
                // later checks compare against that one. One kept in memory
                // only leaves the capture as it was.
                if let (Some(saved), Some(capture)) = (saved, self.capture.as_mut()) {
                    capture.session = Some(saved);
                }
                return Ok(Some(response));
            }
            // Ignore other messages during auth
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

    /// A separate bounded queue prevents a slow terminal viewer from growing
    /// the ordinary control-message queue or blocking the TUI loop.
    pub fn try_send_terminal(&self, envelope: crate::terminal_share::Envelope) -> Result<()> {
        self.terminal_sender.as_ref().ok_or_else(|| anyhow!("Not connected"))?
            .try_send(OutboundMessage { message: AstationMessage::Terminal(envelope), delivered: None })
            .map_err(|_| anyhow!("Terminal transport queue full or closed"))
    }

    /// A session-family message as raw JSON: terminal-v1 ones on the bounded
    /// terminal queue (in order with the frames), the rest on the control queue.
    pub fn try_send_wire(&self, text: String, terminal: bool) -> Result<()> {
        let outbound = OutboundMessage { message: AstationMessage::SessionWire(text), delivered: None };
        if terminal {
            return self.terminal_sender.as_ref().ok_or_else(|| anyhow!("Not connected"))?
                .try_send(outbound)
                .map_err(|_| anyhow!("Terminal transport queue full or closed"));
        }
        self.sender.as_ref().ok_or_else(|| anyhow!("Not connected to Astation"))?
            .send(outbound)
            .map_err(|e| anyhow!("Failed to send message: {}", e))
    }

    /// An r9 channel envelope for the link (§R9.7a). `false` when the link
    /// is gone or already holds `CHANNEL_INFLIGHT_BYTES` of unwritten
    /// envelopes: the caller keeps it queued and tries again.
    pub fn try_send_channel(&self, text: String) -> bool {
        use std::sync::atomic::Ordering;
        let Some(sender) = self.sender.as_ref() else { return false };
        let len = text.len();
        if self.channel_inflight.load(Ordering::Relaxed) + len > CHANNEL_INFLIGHT_BYTES
            && self.channel_inflight.load(Ordering::Relaxed) > 0
        {
            return false;
        }
        self.channel_inflight.fetch_add(len, Ordering::Relaxed);
        let outbound = OutboundMessage { message: AstationMessage::Channel(text), delivered: None };
        if sender.send(outbound).is_err() {
            self.channel_inflight.fetch_sub(len, Ordering::Relaxed);
            return false;
        }
        true
    }

    pub async fn send_message(&self, message: AstationMessage) -> Result<()> {
        if let AstationMessage::Terminal(envelope) = message {
            return self.try_send_terminal(envelope);
        }
        if let Some(sender) = &self.sender {
            sender
                .send(OutboundMessage { message, delivered: None })
                .map_err(|e| anyhow!("Failed to send message: {}", e))?;
        } else {
            return Err(anyhow!("Not connected to Astation"));
        }
        Ok(())
    }

    /// Sends and waits (at most 5 s) until the writer has written the frame,
    /// so a client dropped right after doesn't lose it.
    pub(crate) async fn send_message_flushed(&self, message: AstationMessage) -> Result<()> {
        let sender = self.sender.as_ref().ok_or_else(|| anyhow!("Not connected to Astation"))?;
        let (delivered, receipt) = tokio::sync::oneshot::channel();
        sender.send(OutboundMessage { message, delivered: Some(delivered) })
            .map_err(|_| anyhow!("WebSocket writer closed before delivery"))?;
        tokio::time::timeout(Duration::from_secs(5), receipt).await
            .map_err(|_| anyhow!("WebSocket delivery timed out; retry this command"))?
            .map_err(|_| anyhow!("WebSocket writer closed before delivery"))?
            .map_err(|error| anyhow!(error))
    }

    /// Best effort metadata; failure never prevents the user's command.
    pub async fn report_credential_projects(&self) -> Result<()> {
        self.report_credential_projects_in(std::env::current_dir().ok()).await
    }

    /// `report_credential_projects` naming the Git project of `cwd`.
    pub(crate) async fn report_credential_projects_in(&self, cwd: Option<std::path::PathBuf>) -> Result<()> {
        // The binding first: nothing else is asked for a connection that has none.
        self.capture.as_ref().ok_or_else(|| anyhow!(crate::pairing::NO_BINDING))?.bound()?;
        crate::auth::pairing_session_in(&self.profile_sources()?)
            .map_err(|_| anyhow!("this machine isn't paired with an Astation"))?;
        let agent = match &self.agent {
            Some(agent) => agent.clone(),
            None => crate::memory::cred_agent::blocking(|| {
                crate::memory::cred_agent::running_agent().ok_or_else(|| anyhow!("cred agent is not running"))
            })
            .await
            .map(std::sync::Arc::from)?,
        };
        self.report_credential_projects_with(cwd, agent).await
    }

    /// The credential-project report signed by `agent` (`atem cred
    /// projects` runs in the runtime, for the CLI's directory).
    pub(crate) async fn report_credential_projects_with(
        &self,
        cwd: Option<std::path::PathBuf>,
        agent: std::sync::Arc<dyn crate::memory::cred_agent::CredAgentApi>,
    ) -> Result<()> {
        use crate::memory::cred_agent::{blocking, CredAgentApi};
        let astation_id = self.connected_astation_id.clone().ok_or_else(|| anyhow!("Astation identity is not known"))?;
        // Signed only under the pairing this connection authenticated with.
        let capture = self.capture.clone().ok_or_else(|| anyhow!(crate::pairing::NO_BINDING))?;
        capture.bound()?;
        let report = blocking(move || {
            let agent = crate::pairing::BoundAgent::new(capture, agent)?;
            if !agent.status()?.unlocked { return Err(anyhow!("cred agent is locked")); }
            let project = cwd.and_then(|cwd| crate::memory::project::detect_repo(&cwd)).map(|repo| repo.label);
            agent.credential_projects(&astation_id, project)
        }).await?;
        self.send_message_flushed(AstationMessage::CredentialProjectListResponse { report }).await
    }

    /// Persist encryption mode/key messages before application code handles
    /// ordinary Astation traffic. Returns a user-facing status when handled.
    pub async fn handle_encryption_message(
        &mut self,
        message: &AstationMessage,
    ) -> Result<Option<String>> {
        use crate::memory::cred_agent::{blocking, LOCKED};
        use crate::memory::verification::{apply_account_state, apply_grant, key_needed, Applied};

        if matches!(message, AstationMessage::CredentialProjectListRequest) {
            let _ = self.report_credential_projects().await;
            return Ok(Some(String::new()));
        }

        if !matches!(message, AstationMessage::EncryptionMode { .. } | AstationMessage::KeyGrant { .. }) {
            return Ok(None);
        }
        let Some(astation_id) = self.connected_astation_id.clone() else {
            // Applied once a connection knows the Astation (`apply_held_encryption`);
            // signatures are still checked against the pinned keys then.
            self.hold_encryption(message.clone());
            return Ok(Some(HOLDING_ENCRYPTION.into()));
        };
        // Applied only under the pairing this connection authenticated with
        // (never one removed or replaced since), under its lock. Before the
        // pairing has a binding (`atem pair` waiting for credentials), held
        // until it has one.
        let Some(capture) = self.capture.clone().filter(|c| c.state.binding.is_some()) else {
            self.hold_encryption(message.clone());
            return Ok(Some(HOLDING_ENCRYPTION.into()));
        };
        let paths = self.profile_sources()?.paths.cred;
        let agent = self.cred_agent();
        let applied = match message {
            AstationMessage::EncryptionMode { account_state } => {
                capture.apply(|| apply_account_state(&paths, &astation_id, account_state.as_ref()))?
            }
            AstationMessage::KeyGrant { grant } => {
                // Grants are opened only inside the cred agent (blocking socket I/O).
                let (paths, astation_id, grant) = (paths.clone(), astation_id.clone(), grant.clone());
                let (capture, agent) = (capture.clone(), agent.clone());
                blocking(move || capture.apply(|| apply_grant(&paths, agent.as_ref(), &astation_id, grant.as_ref()))).await?
            }
            _ => unreachable!("filtered above"),
        };
        let request_key = || async {
            // A grant can't be opened while the keys are locked: ask after `atem cred unlock`.
            let status = agent.clone();
            if !blocking(move || status.status().map(|status| status.unlocked)).await? {
                return Ok(Some(format!("Encryption key needed, but {LOCKED}")));
            }
            // Astation answers only for the device key it pinned, so ask with exactly that one.
            let trust = crate::memory::trust::TrustStore::load_from(&paths.trust)?;
            let public_key = trust
                .verified(&astation_id)
                .ok_or_else(|| anyhow!("this device isn't verified with this Astation"))?
                .device_pub
                .clone();
            self.send_message(AstationMessage::KeyRequest { public_key }).await?;
            Ok::<_, anyhow::Error>(Some("Encryption key requested from Astation".to_string()))
        };
        // Asks the agent whether K for the signed kid is held (blocking socket I/O).
        let needs_key = || {
            let (paths, astation_id, agent) = (paths.clone(), astation_id.clone(), agent.clone());
            blocking(move || key_needed(&paths, agent.as_ref(), &astation_id))
        };
        match applied {
            Applied::Ignored(reason) => Ok(Some(format!("Ignored {reason}"))),
            Applied::Locked => Ok(Some(format!("Ignored a key grant: {LOCKED}"))),
            Applied::Unchanged => {
                // A repeat of the stored state still asks for K if it is missing
                // (e.g. a keyRequest or grant was lost earlier).
                if needs_key().await? {
                    return request_key().await;
                }
                Ok(Some("Account encryption state unchanged".into()))
            }
            Applied::ModeChanged(state) | Applied::MigrationPending(state) => {
                if !state.mode.requires_key() {
                    // A running, unlocked agent drops the account's keys now; a
                    // locked one does at its next unlock.
                    let astation = astation_id.clone();
                    let running = self.running_cred_agent();
                    blocking(move || {
                        if let Some(agent) = running {
                            let _ = agent.held_kid(&astation);
                        }
                        Ok(())
                    })
                    .await?;
                }
                if needs_key().await? {
                    return request_key().await;
                }
                self.finish_encryption_migration(&astation_id, state.kid).await
            }
            Applied::KeyInstalled(kid) => self.finish_encryption_migration(&astation_id, Some(kid)).await,
        }
    }

    /// The migration's signed completion goes out only under the captured
    /// pairing.
    fn check_capture(&self) -> Result<()> {
        self.capture.as_ref().ok_or_else(|| anyhow!(crate::pairing::NO_BINDING))?.check()
    }

    /// Keeps an encryption message to apply later (`apply_held_encryption`).
    /// Anything else is not held.
    pub fn hold_encryption(&mut self, message: AstationMessage) {
        if !matches!(message, AstationMessage::EncryptionMode { .. } | AstationMessage::KeyGrant { .. }) {
            return;
        }
        if self.held_encryption.len() >= MAX_HELD_ENCRYPTION {
            self.held_encryption.remove(0);
        }
        self.held_encryption.push(message);
    }

    /// Takes the held encryption messages (`atem pair` replaces its
    /// pairing-code connection with an authenticated one, which holds them
    /// again with `hold_encryption`).
    pub fn take_held_encryption(&mut self) -> Vec<AstationMessage> {
        std::mem::take(&mut self.held_encryption)
    }

    /// Applies the held encryption messages, in arrival order, once this
    /// client knows its Astation; returns their status lines. Without an
    /// Astation id they stay held.
    pub async fn apply_held_encryption(&mut self) -> Vec<String> {
        let bound = self.capture.as_ref().is_some_and(|c| c.state.binding.is_some());
        if self.connected_astation_id.is_none() || !bound {
            return Vec::new();
        }
        let mut statuses = Vec::new();
        for message in std::mem::take(&mut self.held_encryption) {
            match self.handle_encryption_message(&message).await {
                Ok(Some(status)) => statuses.push(status),
                Ok(None) => {}
                // Older than the state the verification just delivered: stale, not news.
                Err(error) if format!("{error:#}").contains(crate::memory::trust::STATE_OLDER_THAN_VERIFICATION) => {}
                Err(error) => statuses.push(format!("Ignored an encryption message: {error:#}")),
            }
        }
        statuses
    }

    /// Finishes this device's part of a pending migration of
    /// `astation_id`'s account under the newest signed state (`atem cred
    /// unlock` on an already unlocked device).
    pub(crate) async fn finish_pending_migration(&self, astation_id: &str) -> Result<Option<String>> {
        let trust = crate::memory::trust::TrustStore::load_from(&self.profile_sources()?.paths.cred.trust)?;
        let kid = crate::memory::verification::effective_state(&trust, astation_id)?
            .and_then(|(_, state)| state).and_then(|state| state.kid);
        self.finish_encryption_migration(astation_id, kid).await
    }

    /// Runs this device's part of a migration and reports it, one at a
    /// time: the runtime's link skips one an operation is running (that
    /// operation reports it); an operation waits for the link's.
    async fn finish_encryption_migration(&self, astation_id: &str, kid: Option<String>) -> Result<Option<String>> {
        self.check_capture()?;
        let _one = if self.is_op_view {
            MIGRATION.lock().await
        } else {
            match MIGRATION.try_lock() {
                Ok(guard) => guard,
                Err(_) => return Ok(Some("An encryption migration is already running".into())),
            }
        };
        let src = self.profile_sources()?;
        let agent = self.cred_agent();
        let trust = crate::memory::trust::TrustStore::load_from(&src.paths.cred.trust)?;
        let epoch = crate::memory::verification::effective_state(&trust, astation_id)?
            .and_then(|(_, state)| state).map(|state| state.epoch);
        if let Some(target) = crate::memory::crypto::migrate_account_in(astation_id, &src, agent.clone()).await? {
            let kid = kid.ok_or_else(|| anyhow!("encryption migration has no key id"))?;
            let (account, proof_kid) = (astation_id.to_string(), kid.clone());
            let epoch = epoch.ok_or_else(|| anyhow!("the signed migration state is missing"))?;
            let completion = crate::memory::cred_agent::blocking(move ||
                agent.migration_completion(&account, epoch, target, &proof_kid)).await?;
            self.send_message_flushed(AstationMessage::EncryptionMigrationComplete { mode: target.to_string(), kid, completion }).await?;
            return Ok(Some(format!("Encryption migration complete; requesting {target}")));
        }
        Ok(Some("Account encryption state updated".into()))
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

    /// Returns true if the WebSocket connection has been closed: `recv_message()`
    /// found the channel closed, or a transport task (reader or writer) ended.
    pub fn is_ws_closed(&self) -> bool {
        self.ws_closed || self.transport_tasks.iter().any(|task| task.is_finished())
    }

    /// Blocking: waits until a message arrives (for CLI use only, not the TUI loop).
    pub async fn recv_message_async(&mut self) -> Option<AstationMessage> {
        if let Some(receiver) = &mut self.receiver {
            receiver.recv().await
        } else {
            None
        }
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



    /// Connect to Astation for pairing.
    ///
    /// Flow:
    /// 1. Try local Astation (`astation_ws`, default ws://127.0.0.1:8080/ws)
    /// 2. If local fails → POST to relay /api/pair → get pairing code
    /// 3. Connect the relay WebSocket with that code (no auth yet)
    ///
    /// Returns the pairing code on success ("local" for a local connection).
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
        // A pairing room: its code is a secret until the pairing ends.
        self.via = Some(LinkVia::Relay {
            label: relay_label(&station_url, ""),
        });

        // Return the code — caller is responsible for any UI (println!, open_browser, etc.)
        // so this function stays silent and TUI-safe.
        Ok(code)
    }

    /// Connect to Astation's persistent identity relay room for TUI auto-reconnect.
    ///
    /// Astation registers its identity UUID as a permanent relay room on startup.
    /// After `atem pair`, the pairing names the identity (`PairingRecord::astation_id`).
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
        } else {
            self.via = Some(LinkVia::Relay {
                label: relay_label(relay_url, &atem_id),
            });
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

pub(crate) fn resolved_atem_id(hostname: &str) -> String {
    if let Some(existing) = AtemConfig::stored_atem_id() {
        return existing;
    }
    let atem_id = build_atem_id(hostname, &AtemConfig::ensure_instance_id());
    AtemConfig::store_atem_id(&atem_id);
    atem_id
}

pub(crate) fn device_auth_proof(
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

/// Used on macOS (the only Astation platform) and by tests.
#[cfg(all(unix, any(target_os = "macos", test)))]
fn read_local_bootstrap_token_from(path: &std::path::Path) -> Option<String> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    let mut file = std::fs::OpenOptions::new()
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

/// Build the relay `atem_id`: `<host>[-<filler>]-<instance suffix:8>`.
///
/// Lengths are counted in **characters**, not bytes (CJK chars are multibyte).
/// Host charset: non-ASCII chars (CJK etc.) are kept as-is; ASCII is restricted
/// to `[A-Za-z0-9-]` (dots, underscores, and other punctuation are dropped). A
/// host longer than [`ATEM_ID_HOST_LEN`] chars is truncated; a shorter one is
/// followed by a `-` and filler chars so host + filler is
/// [`ATEM_ID_HOST_LEN`] chars (`Genie` → `Genie-dc1649f-956631ec`). Filler and
/// suffix are drawn from the instance-id hex (the suffix is the first UUID
/// block), so the id is unique per install and *stable* across restarts, never
/// fresh-random.
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

    // Fill a short host up to a uniform width using chars from the instance-id
    // pool, drawn after the suffix chars so filler and suffix differ. A `-`
    // separates the real hostname from the filler (not when the host is empty
    // or already ends in `-`).
    let pad: Vec<char> = pool.iter().skip(ATEM_ID_SUFFIX_LEN).copied().collect();
    let fill = ATEM_ID_HOST_LEN.saturating_sub(host.len());
    if fill > 0 && host.last().is_some_and(|&c| c != '-') {
        host.push('-');
    }
    for i in 0..fill {
        let c = if pad.is_empty() {
            pool[i % pool.len()]
        } else {
            pad[i % pad.len()]
        };
        host.push(c);
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
    use std::fs;

    /// A delayed success for a connection whose pairing was replaced (atem
    /// unpair, then atem pair) while the proof was out is not adopted: no
    /// session refresh, no relay code, no connection.
    #[cfg(unix)]
    #[tokio::test]
    async fn delayed_authentication_cannot_adopt_a_later_binding() {
        use std::os::unix::fs::PermissionsExt;
        for transport in ["relay", "loopback"] {
            let state = tempfile::tempdir().unwrap();
            crate::pairing::tests::bound_profile(state.path(), "mac-a");
            crate::pairing::tests::set_session(state.path(), "mac-a", "old-session", "old-token");
            let token_path = state.path().join("local-bootstrap-token");
            fs::write(&token_path, "bootstrap-secret\n").unwrap();
            fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let address = listener.local_addr().unwrap();
            let dir = state.path().to_path_buf();
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.unwrap();
                let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
                let challenge = reauth_challenge("mac-a", transport);
                socket
                    .send(Message::Text(serde_json::to_string(&challenge).unwrap()))
                    .await
                    .unwrap();
                // The proof is out; meanwhile the profile is unpaired and
                // paired again, with a new session.
                socket.next().await.unwrap().unwrap();
                let src = crate::profile::Sources::in_dir(&dir);
                crate::pairing::unpair(&src).unwrap();
                let before = crate::pairing::capture(&src).unwrap();
                crate::pairing::bind_new(&src, &before, "mac-a").unwrap();
                crate::pairing::tests::set_session(&dir, "mac-a", "new-session", "new-token");
                let reply = AstationMessage::StatusUpdate {
                    status: "authenticated".into(),
                    data: std::collections::HashMap::new(),
                };
                socket
                    .send(Message::Text(serde_json::to_string(&reply).unwrap()))
                    .await
                    .unwrap();
                let _ = socket.next().await;
            });
            let mut client = AstationClient::new_with_test_state("atem-test", state.path());
            client.local_token_path_override = Some(token_path);
            let error = client
                .connect_without_pairing(&format!("ws://{address}"))
                .await
                .unwrap_err();
            assert!(
                format!("{error:#}").contains(crate::pairing::CHANGED),
                "{transport}: {error:#}"
            );
            assert!(client.capture().is_none());
            assert_eq!(
                crate::pairing::tests::session_id(state.path()).as_deref(),
                Some("new-session")
            );
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn closed_transport_is_detected_before_buffered_input_is_drained() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
            socket.send(Message::Text(r#"{"type":"terminal","data":{"v":1,"op":"subscribe","terminal_id":"ses-aaaaaaaaaaaa","generation":"g"}}"#.into())).await.unwrap();
            socket.close(None).await.unwrap();
        });
        let mut client = AstationClient::new();
        client.connect_raw(&format!("ws://{address}")).await.unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            while !client.is_ws_closed() {
                tokio::task::yield_now().await;
            }
        }).await.unwrap();
        assert!(matches!(client.recv_message(), Some(AstationMessage::SessionWire(text)) if text.contains("subscribe")));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn migration_flush_delivers_before_an_ephemeral_client_disconnects() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let received = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let message = socket.next().await.unwrap().unwrap();
            match message { Message::Text(text) => serde_json::from_str::<serde_json::Value>(&text).unwrap(),
                _ => panic!("expected the completion frame") }
        });
        let mut client = AstationClient::new();
        client.connect_raw(&format!("ws://{address}")).await.unwrap();
        client.send_message_flushed(AstationMessage::EncryptionMigrationComplete {
            mode: "on".into(), kid: "0123abcd".into(),
            completion: crate::memory::statements::SignedWire { statement: "c3RhdGVtZW50".into(), signature: "c2lnbmF0dXJl".into() },
        }).await.unwrap();
        drop(client);
        let frame = tokio::time::timeout(Duration::from_secs(2), received).await.unwrap().unwrap();
        assert_eq!(frame["type"], "encryptionMigrationComplete");
        assert_eq!(frame["data"]["completion"]["statement"], "c3RhdGVtZW50");
    }

    #[tokio::test]
    async fn migration_flush_fails_when_the_writer_has_already_closed() {
        let mut client = AstationClient::new();
        let (sender, receiver) = mpsc::unbounded_channel();
        client.sender = Some(sender);
        drop(receiver);
        assert!(client.send_message_flushed(AstationMessage::ProjectListRequest).await.is_err());
    }

    #[tokio::test]
    async fn encryption_messages_before_the_astation_identity_are_held_then_applied() {
        let _profile = crate::test_profile::temp();
        // A pairing-code relay connection: no Astation identity yet.
        let mut pairing = AstationClient::new();
        let unsigned = AstationMessage::EncryptionMode { account_state: None };
        let status = pairing.handle_encryption_message(&unsigned).await.unwrap().unwrap();
        assert!(status.contains("Holding"), "{status}");
        assert!(pairing.apply_held_encryption().await.is_empty(), "still no identity");
        // Other traffic is never held.
        pairing.hold_encryption(AstationMessage::Heartbeat { timestamp: "1".into() });

        // The authenticated connection takes them over and applies them,
        // through the same signature checks (unsigned here: ignored).
        let profile = tempfile::tempdir().unwrap();
        let capture = crate::pairing::tests::bound_profile(profile.path(), "astation-1");
        let paths = capture.sources().paths.cred.clone();
        let mut authenticated = AstationClient::new()
            .with_profile(capture.sources().clone())
            .with_agent(std::sync::Arc::new(crate::memory::cred_agent::test_agent(&paths)));
        authenticated.connected_astation_id = Some("astation-1".into());
        authenticated.set_capture_for_test(capture.clone());
        let held = pairing.take_held_encryption();
        for message in held.clone() {
            authenticated.hold_encryption(message);
        }
        assert_eq!(
            authenticated.apply_held_encryption().await,
            vec!["Ignored an unsigned encryption mode from the relay".to_string()]
        );
        assert!(authenticated.apply_held_encryption().await.is_empty());

        // After `atem unpair`, nothing reaches the keys or the trust state.
        crate::pairing::unpair(capture.sources()).unwrap();
        for message in held {
            authenticated.hold_encryption(message);
        }
        assert_eq!(
            authenticated.apply_held_encryption().await,
            vec![format!("Ignored an encryption message: {}", crate::pairing::CHANGED)]
        );
        // Without a pairing binding yet (`atem pair` waiting for its
        // credentials), they are held, not applied.
        let mut unbound = AstationClient::new();
        unbound.connected_astation_id = Some("astation-1".into());
        let status = unbound
            .handle_encryption_message(&AstationMessage::KeyGrant { grant: None })
            .await
            .unwrap()
            .unwrap();
        assert_eq!(status, HOLDING_ENCRYPTION);
        assert!(unbound.apply_held_encryption().await.is_empty());
        assert_eq!(unbound.take_held_encryption().len(), 1);
    }

    #[test]
    fn only_the_newest_held_encryption_messages_are_kept() {
        let mut client = AstationClient::new();
        for _ in 0..MAX_HELD_ENCRYPTION + 3 {
            client.hold_encryption(AstationMessage::KeyGrant { grant: None });
        }
        assert_eq!(client.take_held_encryption().len(), MAX_HELD_ENCRYPTION);
    }

    fn isolated_client(atem_id: &str) -> (tempfile::TempDir, AstationClient) {
        let directory = tempfile::tempdir().unwrap();
        let client = AstationClient::new_with_test_state(atem_id, directory.path());
        (directory, client)
    }

    /// A test Astation that records the first frame Atem sends it.
    async fn recording_peer() -> (String, tokio::task::JoinHandle<Option<AstationMessage>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let frame = tokio::time::timeout(Duration::from_secs(2), socket.next()).await.ok()??;
            match frame.ok()? {
                Message::Text(text) => serde_json::from_str(&text).ok(),
                _ => None,
            }
        });
        (format!("ws://{address}"), server)
    }

    fn reauth_challenge(astation_id: &str, transport: &str) -> AstationMessage {
        AstationMessage::StatusUpdate {
            status: "auth_required".to_string(),
            data: std::collections::HashMap::from([
                ("astation_id".to_string(), astation_id.to_string()),
                ("challenge".to_string(), "d".repeat(64)),
                ("transport".to_string(), transport.to_string()),
                ("protocol".to_string(), "2".to_string()),
            ]),
        }
    }

    /// A test Astation that challenges over `transport`, grants the session
    /// `granted-session` to the first `auth` it gets, then keeps the socket
    /// open until Atem closes it.
    async fn granting_peer(astation_id: &str, transport: &str) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let challenge = reauth_challenge(astation_id, transport);
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            socket
                .send(Message::Text(serde_json::to_string(&challenge).unwrap()))
                .await
                .unwrap();
            while let Some(Ok(frame)) = socket.next().await {
                let Message::Text(text) = frame else { continue };
                let Ok(AstationMessage::StatusUpdate { status, .. }) = serde_json::from_str(&text) else {
                    continue;
                };
                if status != "auth" {
                    continue;
                }
                let granted = AstationMessage::StatusUpdate {
                    status: "auth".into(),
                    data: std::collections::HashMap::from([
                        ("status".to_string(), "granted".to_string()),
                        ("session_id".to_string(), "granted-session".to_string()),
                        ("token".to_string(), "granted-token".to_string()),
                    ]),
                };
                socket
                    .send(Message::Text(serde_json::to_string(&granted).unwrap()))
                    .await
                    .unwrap();
                break;
            }
            while let Some(Ok(_)) = socket.next().await {}
        });
        (format!("ws://{address}"), server)
    }

    #[cfg(unix)]
    fn with_bootstrap_token(state: &std::path::Path, client: &mut AstationClient) {
        use std::os::unix::fs::PermissionsExt;
        let token_path = state.join("local-bootstrap-token");
        fs::write(&token_path, "bootstrap-secret\n").unwrap();
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();
        client.local_token_path_override = Some(token_path);
    }

    /// After `atem unpair` (or on a profile never paired), the runtime's
    /// background reconnect to the local Astation authenticates with the
    /// loopback proof; the session Astation grants stays in memory: no
    /// pairing record appears, and the profile stays not paired.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_background_local_grant_never_creates_a_pairing() {
        for unpaired in [true, false] {
            let (state, mut client) = isolated_client("atem-test-local-grant");
            let _profile = crate::test_profile::use_dir(state.path());
            with_bootstrap_token(state.path(), &mut client);
            let src = crate::profile::Sources::in_dir(state.path());
            if unpaired {
                crate::pairing::tests::bound_profile(state.path(), "mac-local");
                crate::pairing::unpair(&src).unwrap();
            }
            let (url, server) = granting_peer("mac-local", "loopback").await;
            client.connect_without_pairing(&url).await.unwrap();
            assert_eq!(client.connected_astation_id(), Some("mac-local"));
            assert!(!src.paths.pairing.record.exists(), "unpaired {unpaired}: a record appeared");
            assert!(!crate::status::profile_paired(&src));
            assert_eq!(crate::status::already_paired(&src), None);
            let report = crate::status::gather_with(&src, None);
            assert_eq!(report.pairing.value, "not paired");
            // Still usable: the guard compares against no saved session.
            client.refresh_session().unwrap();
            assert!(!src.paths.pairing.record.exists());
            drop(client);
            server.await.unwrap();
        }
    }

    /// The background reconnect of a pairing (bound) still keeps the session
    /// Astation grants on the loopback, in the existing record.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_background_local_grant_updates_the_bound_pairings_session() {
        let (state, mut client) = isolated_client("atem-test-local-bound");
        let _profile = crate::test_profile::use_dir(state.path());
        with_bootstrap_token(state.path(), &mut client);
        crate::pairing::tests::bound_profile(state.path(), "mac-local");
        let src = crate::profile::Sources::in_dir(state.path());
        let before = crate::pairing::load(&src).unwrap();
        let (url, server) = granting_peer("mac-local", "loopback").await;
        client.connect_without_pairing(&url).await.unwrap();
        assert_eq!(
            crate::pairing::tests::session_id(state.path()).as_deref(),
            Some("granted-session")
        );
        assert_eq!(crate::pairing::load(&src).unwrap(), before, "binding kept");
        // Later checks compare against the granted session.
        client.refresh_session().unwrap();
        drop(client);
        server.await.unwrap();
    }

    /// A leftover record without a binding (from v0.7.2) is not updated by
    /// a background grant, and is not a pairing.
    #[cfg(unix)]
    #[tokio::test]
    async fn a_background_local_grant_leaves_a_record_without_a_binding_alone() {
        let (state, mut client) = isolated_client("atem-test-local-unbound");
        let _profile = crate::test_profile::use_dir(state.path());
        with_bootstrap_token(state.path(), &mut client);
        crate::pairing::tests::set_session(state.path(), "mac-local", "stale", "stale-token");
        let src = crate::profile::Sources::in_dir(state.path());
        let (url, server) = granting_peer("mac-local", "loopback").await;
        client.connect_without_pairing(&url).await.unwrap();
        assert_eq!(crate::pairing::tests::session_id(state.path()).as_deref(), Some("stale"));
        assert_eq!(crate::status::already_paired(&src), None);
        drop(client);
        server.await.unwrap();
    }

    /// `atem pair`'s connections (local and relay) still start the record
    /// with the granted session; `bind_new` then binds it.
    #[cfg(unix)]
    #[tokio::test]
    async fn pairing_connections_save_the_granted_session_and_bind() {
        for transport in ["loopback", "relay"] {
            let (state, mut client) = isolated_client("atem-test-pair-grant");
            let _profile = crate::test_profile::use_dir(state.path());
            with_bootstrap_token(state.path(), &mut client);
            let src = crate::profile::Sources::in_dir(state.path());
            let before = crate::pairing::capture(&src).unwrap();
            let (url, server) = granting_peer("mac-pair", transport).await;
            if transport == "relay" {
                let base = url.replace("ws://", "http://");
                client.connect_relay_identity(&base, "mac-pair").await.unwrap();
            } else {
                client.connect(&url).await.unwrap();
            }
            assert_eq!(
                crate::pairing::tests::session_id(state.path()).as_deref(),
                Some("granted-session"),
                "{transport}"
            );
            let after = crate::pairing::bind_new(&src, &before, "mac-pair").unwrap();
            client.adopt_binding(&before, &after).unwrap();
            client.refresh_session().unwrap();
            assert_eq!(crate::status::pairing(&src).unwrap().astation_id, "mac-pair");
            assert!(crate::status::already_paired(&src).is_some(), "{transport}");
            assert_eq!(
                crate::pairing::tests::session_id(state.path()).as_deref(),
                Some("granted-session")
            );
            drop(client);
            server.await.unwrap();
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn reauth_over_loopback_answers_with_the_local_proof() {
        use std::os::unix::fs::PermissionsExt;
        let (state, mut client) = isolated_client("atem-test-loopback");
        let token_path = state.path().join("local-bootstrap-token");
        fs::write(&token_path, "bootstrap-secret\n").unwrap();
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).unwrap();
        client.local_token_path_override = Some(token_path);
        let (url, server) = recording_peer().await;
        client.connect_raw(&url).await.unwrap();
        client.pin_astation_for_test("astation-local");

        let challenge = reauth_challenge("astation-local", "loopback");
        client.answer_auth_required(&challenge).await.unwrap();
        assert!(client.is_answered_challenge(&challenge));
        let Some(AstationMessage::StatusUpdate { status, data }) = server.await.unwrap() else {
            panic!("no proof reached Astation");
        };
        assert_eq!(status, "auth");
        assert_eq!(data["method"], "local_proof");
        assert_eq!(data["atem_id"], "atem-test-loopback");
        assert_eq!(
            data["proof"],
            device_auth_proof("bootstrap-secret", &"d".repeat(64), "astation-local", "atem-test-loopback", "local").unwrap()
        );
        assert!(!data.contains_key("session_id"));
    }

    #[tokio::test]
    async fn reauth_without_a_saved_session_never_starts_pairing() {
        let (_state, mut client) = isolated_client("atem-test-no-session");
        let (url, server) = recording_peer().await;
        client.connect_raw(&url).await.unwrap();
        client.pin_astation_for_test("astation-unknown");

        let error = client
            .answer_auth_required(&reauth_challenge("astation-unknown", "relay"))
            .await
            .expect_err("answered without a saved session");
        assert!(error.to_string().contains("atem pair"), "{error}");
        drop(client);
        assert!(server.await.unwrap().is_none(), "sent something without a session");
    }

    /// `dir`'s profile after an `atem unpair` that crashed after its commit:
    /// the pairing record with its saved session for `astation_id` is still
    /// on disk, but its binding is of an older generation.
    fn interrupted_unpair(dir: &std::path::Path, astation_id: &str) {
        crate::pairing::tests::bound_profile(dir, astation_id);
        crate::pairing::tests::set_session(dir, astation_id, "leftover-session", "leftover-token");
        crate::pairing::tests::interrupted_unpair(dir);
    }

    #[tokio::test]
    async fn an_interrupted_unpair_never_authenticates_with_the_leftover_session() {
        let (state, mut client) = isolated_client("atem-test-leftover");
        interrupted_unpair(state.path(), "astation-a");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            let challenge = reauth_challenge("astation-a", "relay");
            socket
                .send(Message::Text(serde_json::to_string(&challenge).unwrap()))
                .await
                .unwrap();
            // Whatever Atem sends before it gives up (nothing, it should be).
            let mut frames = Vec::new();
            while let Ok(Some(Ok(Message::Text(text)))) =
                tokio::time::timeout(Duration::from_secs(2), socket.next()).await
            {
                frames.push(text);
            }
            frames
        });
        let error = client
            .connect_without_pairing(&format!("ws://{address}"))
            .await
            .expect_err("authenticated with a leftover session");
        assert!(format!("{error:#}").contains(crate::pairing::NO_BINDING), "{error:#}");
        let frames = server.await.unwrap();
        assert!(
            !frames.iter().any(|frame| frame.contains("leftover-session")),
            "{frames:?}"
        );
    }

    #[tokio::test]
    async fn reauth_after_an_interrupted_unpair_never_uses_the_leftover_session() {
        let (state, mut client) = isolated_client("atem-test-leftover-reauth");
        interrupted_unpair(state.path(), "astation-a");
        let (url, server) = recording_peer().await;
        client.connect_raw(&url).await.unwrap();
        client.pin_astation_for_test("astation-a");
        let error = client
            .answer_auth_required(&reauth_challenge("astation-a", "relay"))
            .await
            .expect_err("answered with a leftover session");
        assert!(error.to_string().contains(crate::pairing::NO_BINDING), "{error}");
        drop(client);
        assert!(server.await.unwrap().is_none(), "sent the leftover session");
    }

    #[tokio::test]
    async fn reauth_refuses_a_different_astation() {
        let (_state, mut client) = isolated_client("atem-test-pinned");
        let (url, server) = recording_peer().await;
        client.connect_raw(&url).await.unwrap();
        client.pin_astation_for_test("astation-pinned");

        let error = client
            .answer_auth_required(&reauth_challenge("astation-other", "relay"))
            .await
            .expect_err("answered a different Astation");
        assert!(error.to_string().contains("astation-other"), "{error}");
        drop(client);
        assert!(server.await.unwrap().is_none());
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
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind test Astation");
        let address = listener.local_addr().unwrap();
        let directory = tempfile::tempdir().unwrap();
        // The record can't be written: a directory (not empty) is in its place.
        let record = crate::paths::ProfilePaths::in_dir(directory.path()).pairing.record;
        let server_record = record.clone();

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

            fs::create_dir_all(server_record.join("occupied")).unwrap();
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
            AstationClient::new_with_test_state("atem-test-persist-failure", directory.path());
        client
            .connect(&format!("ws://{address}"))
            .await
            .expect_err("pairing unexpectedly ignored session persistence failure");
        assert!(record.join("occupied").is_dir(), "left alone");
        server.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn practical_websocket_reconnect_fails_closed_when_the_session_cant_be_rechecked() {
        use std::os::unix::fs::symlink;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("failed to bind test Astation");
        let address = listener.local_addr().unwrap();
        let directory = tempfile::tempdir().unwrap();
        let target_path = directory.path().join("protected-target");
        let astation_id = "astation-refresh-failure".to_string();

        crate::pairing::tests::bound_profile(directory.path(), &astation_id);
        crate::pairing::tests::set_session(directory.path(), &astation_id, "session-existing", "token-existing");
        let session_path = crate::paths::ProfilePaths::in_dir(directory.path()).pairing.record;

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
            AstationClient::new_with_test_state("atem-test-refresh-failure", directory.path());
        // The saved session the proof used can't be read back (a symlink is
        // refused), so the success can't be tied to it: nothing is adopted.
        let error = client
            .connect_without_pairing(&format!("ws://{address}"))
            .await
            .expect_err("an unverifiable session authorized the connection");
        assert!(format!("{error:#}").contains("could not read"), "{error:#}");
        assert!(client.sender.is_none());
        assert!(client.capture().is_none());
        assert_eq!(
            fs::read_to_string(target_path).unwrap(),
            "must remain unchanged"
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
    async fn a_paired_profile_without_a_usable_session_is_told_to_unpair_then_pair() {
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

        let (state, mut client) = isolated_client("atem-test-proof-only");
        // A pairing without a saved session in the client's profile (a temp dir).
        crate::pairing::tests::bound_profile(state.path(), "astation-x");
        crate::pairing::tests::edit(state.path(), |record| record.session = None);
        let error = client
            .connect_without_pairing(&format!("ws://{address}"))
            .await
            .expect_err("proof-only connection unexpectedly started pairing");
        assert_eq!(
            error.to_string(),
            format!("Pairing required. {}", crate::status::SESSION_GONE)
        );
        let session = error.downcast_ref::<SessionError>().expect("typed session error");
        assert_eq!(session.problem, SessionProblem::PairingRequired);
        assert!(session.advised);
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

    #[test]
    fn removed_volume_video_and_instance_messages_do_not_parse() {
        for json in [
            r#"{"type":"volume_update","data":{"level":0.5}}"#,
            r#"{"type":"video_toggle","data":{"active":true}}"#,
            r#"{"type":"atem_instance_list","data":{"instances":[]}}"#,
        ] {
            assert!(serde_json::from_str::<AstationMessage>(json).is_err(), "{json}");
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

    // ── Agent hub message tests ───────────────────────────────────────────

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
    fn agent_chat_round_trips_through_astation_message() {
        let json = r#"{"type":"agentChat","data":{"v":1,"op":"open","conversationId":"c1","agentId":"claude","before":"m9"}}"#;
        let msg: AstationMessage = serde_json::from_str(json).unwrap();
        match &msg {
            AstationMessage::AgentChat(env) => {
                assert_eq!(env.op, "open");
                assert_eq!(env.conversation_id, "c1");
                assert_eq!(env.body["before"], "m9");
            }
            other => panic!("unexpected {other:?}"),
        }
        let back: serde_json::Value = serde_json::to_value(&msg).unwrap();
        assert_eq!(back, serde_json::from_str::<serde_json::Value>(json).unwrap());
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

    // ── PairSavePreference ────────────────────────────────

    #[test]
    fn pair_save_preference_roundtrip_true() {
        let msg = AstationMessage::PairSavePreference { save_credentials: true };
        let json = serde_json::to_string(&msg).unwrap();
        assert!(json.contains(r#""type":"pairSavePreference""#));
        let parsed: AstationMessage = serde_json::from_str(&json).unwrap();
        matches!(parsed, AstationMessage::PairSavePreference { save_credentials: true });
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

    #[test]
    fn unsigned_encryption_mode_from_old_astation_still_parses() {
        let json = r#"{"type":"encryptionMode","data":{"mode":"off","data_account":"a","astation_id":"b"}}"#;
        let parsed: AstationMessage = serde_json::from_str(json).unwrap();
        assert!(matches!(parsed, AstationMessage::EncryptionMode { account_state: None }));
    }

    #[test]
    fn verify_messages_round_trip() {
        let message = AstationMessage::VerifyCommit { device_id: "d".into(), commitment: "c".into() };
        let json = serde_json::to_string(&message).unwrap();
        assert_eq!(json, r#"{"type":"verifyCommit","data":{"device_id":"d","commitment":"c"}}"#);
    }

    #[test]
    fn unlock_denied_parses_with_and_without_revoked() {
        let old: AstationMessage =
            serde_json::from_str(r#"{"type":"unlockDenied","data":{"reason":"no"}}"#).unwrap();
        assert!(matches!(old, AstationMessage::UnlockDenied { ref reason, revoked: false } if reason == "no"));
        let new: AstationMessage = serde_json::from_str(
            r#"{"type":"unlockDenied","data":{"reason":"no","revoked":true}}"#,
        )
        .unwrap();
        assert!(matches!(new, AstationMessage::UnlockDenied { revoked: true, .. }));
        assert_eq!(
            serde_json::to_string(&AstationMessage::UnlockDenied { reason: "no".into(), revoked: true }).unwrap(),
            r#"{"type":"unlockDenied","data":{"reason":"no","revoked":true}}"#
        );
    }

    #[test]
    fn unlock_and_storage_messages_round_trip() {
        use crate::memory::statements::SignedWire;
        let signed = SignedWire { statement: "s".into(), signature: "g".into() };
        let messages = vec![
            (
                AstationMessage::UnlockRequest { request: "r".into(), signature: "g".into() },
                r#"{"type":"unlockRequest","data":{"request":"r","signature":"g"}}"#,
            ),
            (
                AstationMessage::UnlockGrant { grant: signed.clone(), encapped_key: "e".into(), ciphertext: "c".into() },
                r#"{"type":"unlockGrant","data":{"grant":{"statement":"s","signature":"g"},"encapped_key":"e","ciphertext":"c"}}"#,
            ),
            (
                AstationMessage::UnlockDenied { reason: "no".into(), revoked: false },
                r#"{"type":"unlockDenied","data":{"reason":"no"}}"#,
            ),
            (
                AstationMessage::StorageKeyRotate { rotate: signed.clone(), encapped_key: "e".into(), ciphertext: "c".into() },
                r#"{"type":"storageKeyRotate","data":{"rotate":{"statement":"s","signature":"g"},"encapped_key":"e","ciphertext":"c"}}"#,
            ),
            (
                AstationMessage::StorageKeyAck { ack: signed.clone() },
                r#"{"type":"storageKeyAck","data":{"ack":{"statement":"s","signature":"g"}}}"#,
            ),
            (
                AstationMessage::StorageKeyRejected { reason: "pending".into(), pending_kid: Some("4e5f6a7b".into()) },
                r#"{"type":"storageKeyRejected","data":{"reason":"pending","pending_kid":"4e5f6a7b"}}"#,
            ),
            (
                AstationMessage::StorageKeyRejected { reason: "bad".into(), pending_kid: None },
                r#"{"type":"storageKeyRejected","data":{"reason":"bad"}}"#,
            ),
            (
                AstationMessage::StorageKeyConfirm { confirm: signed.clone() },
                r#"{"type":"storageKeyConfirm","data":{"confirm":{"statement":"s","signature":"g"}}}"#,
            ),
            (
                AstationMessage::StorageKeyAbandon { abandon: signed },
                r#"{"type":"storageKeyAbandon","data":{"abandon":{"statement":"s","signature":"g"}}}"#,
            ),
        ];
        for (message, json) in messages {
            assert_eq!(serde_json::to_string(&message).unwrap(), json);
            let parsed: AstationMessage = serde_json::from_str(json).unwrap();
            assert_eq!(serde_json::to_string(&parsed).unwrap(), json);
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

    // Instance id 550e8400-e29b-41d4-a716-446655440000 → suffix "550e8400",
    // filler drawn from "e29b41d4a716446655440000".
    const UUID_A: &str = "550e8400-e29b-41d4-a716-446655440000";

    #[test]
    fn atem_id_drops_dots_keeps_digits_and_fills_to_12() {
        // Dot dropped: "host-01.lan" → "host-01lan" (10) → "-" + 2 filler chars.
        let id = build_atem_id("host-01.lan", UUID_A);
        assert_eq!(id, "host-01lan-e2-550e8400");
        assert_atem_id_charset(&id);
    }

    #[test]
    fn atem_id_separates_hostname_from_filler() {
        // The example that motivated the dash.
        let id = build_atem_id("Genie", "956631ec-dc16-49f2-b546-86ca45ce7926");
        assert_eq!(id, "Genie-dc1649f-956631ec");
    }

    #[test]
    fn atem_id_has_no_filler_or_extra_dash_at_exactly_12() {
        assert_eq!(build_atem_id("MacBookPro20", UUID_A), "MacBookPro20-550e8400");
    }

    #[test]
    fn atem_id_does_not_double_a_trailing_dash() {
        assert_eq!(build_atem_id("web-", UUID_A), "web-e29b41d4-550e8400");
    }

    #[test]
    fn atem_id_is_filler_only_for_an_empty_hostname() {
        // "..." sanitizes to nothing: no leading dash.
        assert_eq!(build_atem_id("...", UUID_A), "e29b41d4a716-550e8400");
    }

    #[test]
    fn atem_id_truncates_long_ascii_to_12() {
        let id = build_atem_id("MacBookPro2024Dev", "550e8400-e29b-41d4-a716-446655440000");
        let (host, _suffix) = id.rsplit_once('-').unwrap();
        assert_eq!(host, "MacBookPro20");
        assert_eq!(host.chars().count(), ATEM_ID_HOST_LEN);
    }

    #[test]
    fn atem_id_fills_short_hostname_to_12() {
        let id = build_atem_id("mbp", UUID_A);
        assert_eq!(id, "mbp-e29b41d4a-550e8400");
        assert_atem_id_charset(&id);
    }

    #[test]
    fn atem_id_keeps_chinese_hostname() {
        let id = build_atem_id("我的电脑", "abcdef12-3456-7890-abcd-ef1234567890");
        assert_eq!(id, "我的电脑-34567890-abcdef12");
        assert_atem_id_charset(&id);
    }

    #[test]
    fn atem_id_keeps_japanese_hostname() {
        // Mixed kanji + hiragana + katakana; filler counted in chars.
        let id = build_atem_id("私のパソコン端末", UUID_A);
        assert_eq!(id, "私のパソコン端末-e29b-550e8400");
        assert_atem_id_charset(&id);
    }

    #[test]
    fn atem_id_keeps_korean_hostname() {
        let id = build_atem_id("내컴퓨터", UUID_A);
        assert_eq!(id, "내컴퓨터-e29b41d4-550e8400");
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
        let id = build_atem_id("서버01.dev", UUID_A);
        assert_eq!(id, "서버01dev-e29b4-550e8400");
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

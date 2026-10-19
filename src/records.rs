//! The data the profile stores, as plain serde types: the logins
//! (`login.enc`, and inside the pairing) and the pairing record
//! (`pairing/pairing.enc`). Their behaviour is in `credentials.rs` and
//! `pairing.rs`. Dependency-free besides serde, so binary tests include this
//! file (`#[path]`) to write fixtures of the very same shape.
use serde::{Deserialize, Serialize};

/// An access token, its refresh token and when it expires (Unix seconds).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: u64,
}

/// An Agora account linked to a login of another issuer (none yet).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgoraConnection {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_id: Option<String>,
    pub tokens: Tokens,
}

/// Service connections of a login.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connections {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agora: Option<AgoraConnection>,
}

/// One login: who issued it, for whom, its identity tokens and its
/// connections.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Login {
    pub issuer: String,
    /// The login id.
    pub subject: Option<String>,
    pub tokens: Tokens,
    #[serde(default)]
    pub connections: Connections,
}

/// The session Astation granted this device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SavedSession {
    pub session_id: String,
    pub token: String,
    pub hostname: String,
    /// Unix seconds of the last connection that used it.
    pub last_activity: u64,
}

/// A binding as the record keeps it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BindingRecord {
    pub binding_id: String,
    pub host_trust_gen: u64,
    pub created_at: u64,
}

/// `pairing.enc`: the pairing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingRecord {
    pub astation_id: String,
    /// Set by `atem pair` once Astation approved it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding: Option<BindingRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<SavedSession>,
    /// The login Astation shares (`credentialSync`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared: Option<Login>,
    #[serde(default)]
    pub save_credentials: bool,
    /// When the link to this Astation last dropped (Unix seconds).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disconnected_at: Option<u64>,
}


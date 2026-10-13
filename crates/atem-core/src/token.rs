//! Agora AccessToken2 (version "007") for RTC and RTM. See designs/atem-core.md.

use std::collections::BTreeMap;

pub use crate::error::TokenError;

/// Service types inside a token.
pub const SERVICE_RTC: u16 = 1;
pub const SERVICE_RTM: u16 = 2;
pub const SERVICE_FPA: u16 = 4;
pub const SERVICE_CHAT: u16 = 5;
pub const SERVICE_APAAS: u16 = 7;

/// RTC privileges.
pub const PRIVILEGE_JOIN_CHANNEL: u16 = 1;
pub const PRIVILEGE_PUBLISH_AUDIO_STREAM: u16 = 2;
pub const PRIVILEGE_PUBLISH_VIDEO_STREAM: u16 = 3;
pub const PRIVILEGE_PUBLISH_DATA_STREAM: u16 = 4;
/// RTM privilege.
pub const PRIVILEGE_RTM_LOGIN: u16 = 1;

/// The service-specific fields of one service in a token.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "snake_case"))]
pub enum ServiceDetails {
    /// `account` is the user account, or the decimal uid; empty means uid 0 (any user).
    Rtc {
        channel: String,
        account: String,
    },
    Rtm {
        user_id: String,
    },
    Fpa,
    Chat {
        user_id: String,
    },
    Apaas {
        room_uuid: String,
        user_uuid: String,
        role: i16,
    },
}

impl ServiceDetails {
    pub fn service_type(&self) -> u16 {
        match self {
            ServiceDetails::Rtc { .. } => SERVICE_RTC,
            ServiceDetails::Rtm { .. } => SERVICE_RTM,
            ServiceDetails::Fpa => SERVICE_FPA,
            ServiceDetails::Chat { .. } => SERVICE_CHAT,
            ServiceDetails::Apaas { .. } => SERVICE_APAAS,
        }
    }
}

/// One service as read from a token: its privileges (privilege → expiry in
/// seconds after the issue time) and fields.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct DecodedService {
    pub service_type: u16,
    pub privileges: BTreeMap<u16, u32>,
    pub details: ServiceDetails,
}

/// What a token says about itself. Reading these fields does **not**
/// establish that the token is authentic: use `verify_token_signature`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct DecodedToken {
    pub version: String,
    pub app_id: String,
    /// Unix seconds.
    pub issued_at: u32,
    /// Seconds after `issued_at`.
    pub expire: u32,
    pub salt: u32,
    pub services: Vec<DecodedService>,
}

impl DecodedToken {
    /// Unix seconds at which the token itself expires.
    pub fn expires_at(&self) -> u64 {
        self.issued_at as u64 + self.expire as u64
    }
}

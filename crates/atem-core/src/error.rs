//! Why a token could not be built, decoded or verified.

use std::fmt;

/// Every failure in atem-core. Messages name the field and the rule, never
/// the App Certificate or the token text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TokenError {
    /// The App ID isn't 32 hexadecimal characters.
    InvalidAppId,
    /// The App Certificate isn't 32 hexadecimal characters.
    InvalidAppCertificate,
    InvalidChannel(String),
    InvalidUserAccount(String),
    InvalidRtmUserId(String),
    InvalidExpiry(String),
    /// The token doesn't start with the AccessToken2 version "007".
    UnsupportedVersion,
    Malformed(String),
}

impl fmt::Display for TokenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TokenError::InvalidAppId => write!(f, "App ID must be 32 hexadecimal characters"),
            TokenError::InvalidAppCertificate => {
                write!(f, "App Certificate must be 32 hexadecimal characters")
            }
            TokenError::InvalidChannel(why) => write!(f, "invalid channel name: {why}"),
            TokenError::InvalidUserAccount(why) => write!(f, "invalid RTC user account: {why}"),
            TokenError::InvalidRtmUserId(why) => write!(f, "invalid RTM user id: {why}"),
            TokenError::InvalidExpiry(why) => write!(f, "invalid expiry: {why}"),
            TokenError::UnsupportedVersion => {
                write!(
                    f,
                    "unsupported token version (expected an AccessToken2 starting with \"007\")"
                )
            }
            TokenError::Malformed(why) => write!(f, "malformed token: {why}"),
        }
    }
}

impl std::error::Error for TokenError {}

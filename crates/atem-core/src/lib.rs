//! Shared library for atem and Astation, starting with Agora RTC/RTM tokens.
//! The Rust API is `token`; C callers use the `atem-core-ffi` crate.
//! See designs/atem-core.md.

mod error;
pub mod token;
mod wire;

pub use error::TokenError;
pub use token::{
    DecodedService, DecodedToken, Issue, RtcIdentity, RtcPrivileges, RtcTokenRequest, RtmLogin,
    RtmTokenRequest, ServiceDetails, build_rtc_token, build_rtm_token, decode_token,
    verify_token_signature,
};

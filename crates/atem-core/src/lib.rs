//! Shared library for atem and Astation, starting with Agora RTC/RTM tokens.
//! The Rust API is `token`; C callers use the `atem-core-ffi` crate.
//! See designs/atem-core.md.

mod error;
pub mod token;
mod wire;

pub use error::TokenError;

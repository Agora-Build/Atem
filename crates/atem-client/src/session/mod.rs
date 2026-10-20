//! Session-family messages inside the channel.
//!
//! - [`wire`]: atem-session v1's wire types and strict decoder (r8, §1–§7);
//! - [`client`]: the r8 client machines ([`client::LeaseClient`],
//!   [`client::RegistryClient`], [`client::ChatClient`],
//!   [`client::AdmissionClient`]); they moved here from the atem binary
//!   (`src/session_protocol/`, which re-exports them) so apps and their
//!   bindings run the same code inside the channel;
//! - [`terminal`], [`chat`]: terminal-v1's wire types and chat-v1's inbound
//!   envelope, which the decoder checks;
//! - [`revision`]: r8's revision and feature names (and the r8 fixture
//!   gating both runners share);
//! - [`r9`]: the r9 `hello` (built by the crate around `sig_c`, parsed by the
//!   host), `welcome`, the r9 session errors and the new session ops of
//!   §R9.8 (`membership`, `membership_head`, `revoke_grant`,
//!   `grant_revoked`, `approval_seen`, `seen`).
use rand_core::{OsRng, RngCore};

pub mod chat;
pub mod client;
pub mod r9;
pub mod revision;
pub mod terminal;
pub mod wire;

/// A fresh UUID v4 (lowercase, hyphenated): request and message ids.
pub fn new_id() -> String {
    let mut b = [0u8; 16];
    OsRng.fill_bytes(&mut b);
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = crate::encoding::hex(&b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

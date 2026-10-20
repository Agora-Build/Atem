//! Session-family messages inside the channel.
//!
//! - [`r9`]: the r9 `hello` (built by the crate around `sig_c`, parsed by the
//!   host), `welcome`, the r9 session errors and the new session ops of
//!   §R9.8 (`membership`, `membership_head`, `revoke_grant`,
//!   `grant_revoked`, `approval_seen`, `seen`).
use rand_core::{OsRng, RngCore};

pub mod r9;

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

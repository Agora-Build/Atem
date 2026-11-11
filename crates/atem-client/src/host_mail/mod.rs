//! The mailbox's two signed, sealed objects between hosts (delegated
//! host-work design II.4.2, II.4.4, III.1): **`atem-envelope`**, which a host
//! sender signs and seals to the receiving host (a request, a cancel or a
//! complete), and **`atem-result`**, which the host that ran the work sends
//! back (a status, a refusal or a result). They follow R9.9's push hint: a
//! signed body that names both hosts and the hash of the sealed part, with
//! the sealed part (`enc`, `ct`) beside it.
//!
//! ```text
//! {"body":{"type":"atem-envelope","v":1,"account_id":…,"genesis_hash":…,
//!          "sender":{"host_id","host_trust_gen"},
//!          "recipient":{"host_id","host_trust_gen","enc_kid"},
//!          "id":…,"created_at":…,"expires_at":…,
//!          "signed_at_head":{"seq","hash"},"sealed_hash":…},
//!  "sig":…,"enc":…,"ct":…}
//! ```
//!
//! - [`body`]: [`MailBody`] (the signed body and its strict reader),
//!   [`MailFields`] (the body before the seal names its `sealed_hash`),
//!   [`HostRef`], and the plaintexts that are sealed: [`EnvelopePlain`] and
//!   [`ResultPlain`] (canonical JSON, read back exactly);
//! - [`seal`]: [`seal_envelope`] and [`seal_result`] (HPKE base mode with
//!   R9.9's suite and empty AAD, `info` binding both hosts and the ids, then
//!   Ed25519 by the sender's `host_key`), their inverse [`unseal_envelope`]
//!   and [`unseal_result`], and [`seal_info`].
//!
//! Signature: Ed25519 by the sender's `host_key` over `enc([label,
//! jcs(body)])` with `atem-envelope-v1` or `atem-result-v1` (a different
//! label, so an object of one direction can't pass for the other), checked
//! by the receiver with the key of the sender's newest `add_host`, never one
//! the object names. Seal: `atem-envelope-seal-v1` or `atem-result-seal-v1`.
//!
//! This module builds, seals, opens and reads. It judges nothing a receiver
//! decides from its own state and clock (the sender's authorization, its
//! generation and `signed_at_head`, the times, that the plaintext's ids equal
//! the body's, the route and project checks): those are the receiver's
//! checks (II.4.2 steps 2 to 7).
//!
//! **Bounds.** A signed body's `jcs` is at most 4,096 bytes (R9.1); the
//! Message in a request at most [`MAX_MESSAGE_BYTES`](crate::session::messages::MAX_MESSAGE_BYTES)
//! (240 KiB, host-work-v1 §5); the whole object, as it arrives, at most
//! [`MAX_MAIL_OBJECT_BYTES`] (512 KiB; owner decision 2026-11-07, choice 13:
//! a sealed 240 KiB Message is about 330 KB after base64url).
use crate::canonical::{self, Numbers};
use crate::error::Result;
use crate::signed::SignedObject;

pub mod body;
pub mod seal;
#[cfg(test)]
mod test_support;

pub use body::{
    EnvelopePlain, HostRef, MailBody, MailFields, MailKind, REFUSAL_CODES, ResultPlain,
};
pub use seal::{seal_envelope, seal_info, seal_result, unseal_envelope, unseal_result};

/// One mailbox object's wire bytes are at most this long (II.4.2, "Size";
/// owner decision 2026-11-07, choice 13). Checked before anything is parsed
/// or allocated.
pub const MAX_MAIL_OBJECT_BYTES: usize = 512 * 1024;

/// Strict parse of the wire bytes of an envelope or a result: at most
/// [`MAX_MAIL_OBJECT_BYTES`], strict I-JSON, a known `type` with `v: 1`, the
/// signed-object rules of R9.1, the body's exact fields ([`MailBody`]) and a
/// sealed part of the right shape (II.4.2, step 1). Nothing is verified or
/// opened.
pub fn parse_object(bytes: &[u8]) -> Result<SignedObject> {
    let value = canonical::parse_strict(bytes, MAX_MAIL_OBJECT_BYTES, Numbers::IntegersOnly)?;
    let object = SignedObject::from_value(&value)?;
    MailBody::from_object(&object)?;
    Ok(object)
}

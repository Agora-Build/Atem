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
//!   and [`unseal_result`], and [`seal_info`];
//! - [`verified`]: [`VerifiedMail`], an object whose signature verified with
//!   the sender's key. The only way to open one: `unseal_*` take it, so an
//!   unverified object can't be opened (it doesn't compile).
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
//! **Bounds.** A signed body's `jcs` is at most 4,096 bytes (R9.1). What is
//! sealed is bounded by [`MAX_PLAINTEXT_BYTES`] (240 KiB): a request's
//! *Message* (a host sender's Message keeps host-work-v1 §5's bound, II.4.2)
//! and the *whole plaintext* of every other envelope kind and of a result. A
//! request's plaintext adds its 29-byte wrapper to the Message. The whole
//! object, as it arrives, is at most [`MAX_MAIL_OBJECT_BYTES`] (512 KiB; owner
//! decision 2026-11-07, choice 13): a sealed 240 KiB plaintext is about 330 KB
//! after base64url, so every sealed object fits a mailbox call.
//!
//! **Plaintexts are strict** (II.4.2 step 6, R9.1): no `null`. Sealing drops
//! every member whose value is `null` (a missing `Option` member reads as
//! `None`) and refuses an array holding one; reading refuses any `null`.
use crate::canonical::{self, Numbers};
use crate::error::Result;
use crate::session::messages::MAX_MESSAGE_BYTES;
use crate::signed::SignedObject;

pub mod body;
pub mod seal;
#[cfg(test)]
mod test_support;
pub mod verified;

pub use body::{
    EnvelopePlain, HostRef, MailBody, MailFields, MailKind, REFUSAL_CODES, ResultPlain,
};
pub use seal::{seal_envelope, seal_info, seal_result, unseal_envelope, unseal_result};
#[cfg(feature = "test-vectors")]
pub use seal::{seal_envelope_with_ikm, seal_result_with_ikm};
pub use verified::VerifiedMail;

/// The bound on what is sealed: 240 KiB, host-work-v1 §5's Message bound,
/// which the shared core keeps as its one. It applies to a request's
/// *Message* (a host sender's Message keeps it, II.4.2, so a valid 240 KiB
/// Message stays sendable; the request's plaintext adds its 29-byte wrapper)
/// and to the *whole plaintext* of every other envelope kind and of a result.
/// Every sealed object then fits [`MAX_MAIL_OBJECT_BYTES`].
pub const MAX_PLAINTEXT_BYTES: usize = MAX_MESSAGE_BYTES;

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

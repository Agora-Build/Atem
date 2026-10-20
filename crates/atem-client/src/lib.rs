//! `atem-client`: the shared client core of atem-session r9
//! (`designs/protocol/atem-session-v1.md`, appendix r9). Sans-I/O: no
//! networking, no filesystem, no clocks; secret keys stay behind
//! [`KeyProvider`].
//!
//! This first part covers §R9.1–§R9.2's encodings and signatures and the
//! Recovery Kit / K-backup formats of §R9.5:
//!
//! - [`encoding`]: `enc`, `u64`, `b64u`, hex, [`Hash32`] (constant-time `==`);
//! - [`canonical`]: strict I-JSON parsing and RFC 8785 `jcs`;
//! - [`domain`]: every label; [`SigningInput`] can only be built with a
//!   [`SignLabel`];
//! - [`keys`]: [`PublicKey`] with its pinned [`Alg`], verification (P-256
//!   low S, Ed25519 `verify_strict`), Ed25519 → X25519;
//! - [`signed`]: [`SignedObject`] (body/sig/kit_sig, set and sequence rules,
//!   `entry_hash`, `grant_hash`);
//! - [`hpke`]: the one HPKE suite (base mode, X25519, HKDF-SHA256,
//!   ChaCha20-Poly1305);
//! - [`kit`]: Recovery Kit v2 derivations and `kit_tag`;
//! - [`backup`]: the `atem-k-backup-v2` envelope;
//! - [`provider`]: [`KeyProvider`], and `SoftwareKeys` with the
//!   `software-keys` feature.
//!
//! The membership log (§R9.2–§R9.5), pure functions and state machines the
//! host and the clients call:
//!
//! - [`membership`]: typed entries and their schemas, [`membership::Membership`]
//!   (chain verification, signer authority, carriage evaluation, the
//!   conflict rule and freeze, the recovery state machine on the verifier's
//!   clock, the membership side of admission); `publish`, the manager's
//!   CAS append rules;
//! - [`backup_writer`]: K-backup version allocation, upload and `k_backup`
//!   publication with their `409` paths;
//! - [`restore`]: the Recovery Kit restore over the fetched log, envelope
//!   and host-signed heads.
//!
//! The channel (§R9.7):
//!
//! - [`channel`]: `atem-ch1` in both roles (initiator and responder state
//!   machines, transcript and key schedule, records, limits and errors).
//!
//! The client machines and formats of §R9.6, §R9.8 and §R9.9 (Task 4):
//!
//! - [`session`]: r8's session-v1 wire and client machines (moved here from
//!   the atem binary, which re-exports them) and r9's `hello` (built by the
//!   crate around `sig_c`), `welcome`, errors and new ops;
//! - [`connect`]: a client's connection: handshake, carriage, the checked
//!   welcome, then r8's lease/registry/chat machines inside the channel;
//! - [`principal`]: native, service and browser principals, scope, ops,
//!   expiry, browser grants (the checks a host runs at admission);
//! - [`push`]: sealed push hints, seen, acks, the relay's schedule from the
//!   signed `created_at` (a pure function), a reference relay ledger, and
//!   the host's per-approval seen state and resend outbox;
//! - [`restore::RestoreFlow`]: the Recovery Kit restore as a client
//!   machine (withheld until a host-signed head confirms the log).

pub mod backup;
pub mod backup_writer;
pub mod canonical;
pub mod ceremony;
pub mod channel;
pub mod connect;
pub mod domain;
pub mod encoding;
pub mod error;
pub mod hpke;
pub mod keys;
pub mod kit;
pub mod membership;
pub mod principal;
pub mod provider;
pub mod push;
pub mod restore;
pub mod session;
pub mod signed;
#[cfg(feature = "software-keys")]
pub mod software;

pub use domain::{SignLabel, SigningInput};
pub use encoding::Hash32;
pub use error::{Error, Result};
pub use keys::{Alg, PublicKey};
pub use provider::{KeyId, KeyProvider};
pub use signed::SignedObject;
#[cfg(feature = "software-keys")]
pub use software::SoftwareKeys;

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

pub mod backup;
pub mod canonical;
pub mod domain;
pub mod encoding;
pub mod error;
pub mod hpke;
pub mod keys;
pub mod kit;
pub mod provider;
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

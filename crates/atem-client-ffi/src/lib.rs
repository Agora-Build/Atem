//! Bindings over `atem-client` (atem-session r9's client core) for
//! Astation's native apps (Swift and Kotlin through UniFFI) and for
//! browsers and Node bots (WASM through wasm-bindgen, feature `wasm`).
//!
//! A deliberately small surface; every check stays in `atem-client`:
//!
//! - [`provider`]: the app's key store as a foreign trait
//!   ([`provider::AppKeyProvider`]); each signing request names its
//!   [`types::SigningPurpose`] so the app applies the 5-minute reuse
//!   (channel) or a fresh owner confirmation (entries, recovery, kit);
//! - [`log`]: the membership log ([`log::MembershipLog`]): verify, extend
//!   with fetched or carried entries, members, hosts, pending recovery,
//!   drafts, and its durable snapshot (`stored_json` / `from_stored`);
//! - [`publish`]: the entry publisher (§R9.4 CAS rules) and the K-backup
//!   writer;
//! - [`kit`]: the Recovery Kit, K-backup envelopes and the restore flow;
//! - [`push`]: push hints (verify, dedup, open), the escalation schedule,
//!   seen, acks and browser grants;
//! - [`connection`]: `atem-ch1` plus the r9 hello/welcome and r8's
//!   session-v1 machines as one byte-in/byte-out object
//!   ([`connection::ClientConnection`]); the app owns the socket and the
//!   clock;
//! - [`service`]: service member builders (`add`/`set_roles` action JSON,
//!   renewal, narrowing) and the `projects` scope hash (§R9.6);
//! - [`encoding`]: canonical JSON, `enc`, signing inputs and hashes.
//!
//! Contract for Astation: `designs/protocol/atem-client-bindings.md`.
// The provider-taking `*_with` helpers are called by the UniFFI and WASM
// layers; a build with neither only type-checks them.
#![cfg_attr(
    not(any(feature = "uniffi", all(feature = "wasm", feature = "software-keys"))),
    allow(dead_code)
)]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

#[macro_use]
mod macros;

pub mod connection;
pub mod encoding;
pub mod error;
pub mod kit;
pub mod log;
pub mod provider;
pub mod publish;
pub mod push;
pub mod service;
pub mod types;
#[cfg(feature = "wasm")]
pub mod wasm;

pub use error::AtemError;

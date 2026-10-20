//! atem-session v1 (designs/protocol/atem-session-v1.md, r8, compatibility mode):
//! wire types, strict decoding and the canonical payload digest (`wire`,
//! `canonical`), r8 revision admission and features (`revision`), the client
//! lease/registry/admission state machines (`client`), the host
//! authority (`host`) and its durable receipt journal (`journal`, on disk
//! `file_journal`), all checked against the shared fixtures (`fixtures`, run
//! on the host through `fake_runtime`).
//!
//! Pure logic apart from `file_journal` (the journal on disk): nothing here
//! touches sockets or PTYs; `atem runtime` performs the host's effects
//! (src/runtime/host_bridge.rs), and tests/runtime_fixtures_binary.rs runs
//! the host fixtures against it.
//!
//! Unknown fields are ignored (§1), but they still go through the strict
//! parser: an unsafe integer (beyond ±(2^53−1)) or a float that overflows f64
//! inside an unknown field rejects the whole message, as do duplicate keys or
//! lone surrogates anywhere in it.

// Parts are used only by tests (the client machines, journal helpers).
#[allow(dead_code)]
pub mod canonical;
#[allow(dead_code)]
pub mod client;
#[allow(dead_code)]
pub mod file_journal;
#[allow(dead_code)]
pub mod host;
#[allow(dead_code)]
pub mod journal;
#[allow(dead_code)]
pub mod membership;
#[allow(dead_code)]
pub mod r9;
#[allow(dead_code)]
pub mod revision;
#[allow(dead_code)]
pub mod wire;

#[cfg(test)]
mod approval_tests;
#[cfg(test)]
mod fake_runtime;
#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod host_tests;
#[cfg(test)]
mod persistence_tests;
#[cfg(test)]
mod tests;

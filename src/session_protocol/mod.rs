//! atem-session v1 (designs/protocol/atem-session-v1.md, r5, compatibility mode):
//! wire types, strict decoding and the canonical payload digest (`wire`,
//! `canonical`), and the client lease/registry state machines (`client`),
//! checked against the shared fixtures (`fixtures`).
//!
//! Pure logic: nothing here touches sockets, PTYs or files. Later tasks add the
//! host authority on top of these types.
//!
//! Unknown fields are ignored (§1), but they still go through the strict
//! parser: an unsafe integer (beyond ±(2^53−1)) or a float that overflows f64
//! inside an unknown field rejects the whole message, as do duplicate keys or
//! lone surrogates anywhere in it.

// Not wired into the runtime yet (plan Task 3 does that); until then only the
// tests use most of this module.
#[allow(dead_code)]
pub mod canonical;
#[allow(dead_code)]
pub mod client;
#[allow(dead_code)]
pub mod wire;

// The setup fields are read by the host under test (plan Task 3).
#[cfg(test)]
#[allow(dead_code)]
mod fixtures;
#[cfg(test)]
mod tests;

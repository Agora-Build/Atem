//! atem-session v1 (designs/protocol/atem-session-v1.md, r6, compatibility mode):
//! wire types, strict decoding and the canonical payload digest (`wire`,
//! `canonical`), the client lease/registry state machines (`client`), the host
//! authority (`host`) and its durable receipt journal (`journal`), all checked
//! against the shared fixtures (`fixtures`, run on the host through
//! `fake_runtime`).
//!
//! Pure logic: nothing here touches sockets, PTYs or files; the runtime
//! performs the host's effects (a later plan wires it in).
//!
//! Unknown fields are ignored (§1), but they still go through the strict
//! parser: an unsafe integer (beyond ±(2^53−1)) or a float that overflows f64
//! inside an unknown field rejects the whole message, as do duplicate keys or
//! lone surrogates anywhere in it.

// Not wired into the runtime yet (a later plan does that); until then only the
// tests use most of this module.
#[allow(dead_code)]
pub mod canonical;
#[allow(dead_code)]
pub mod client;
#[allow(dead_code)]
pub mod host;
#[allow(dead_code)]
pub mod journal;
#[allow(dead_code)]
pub mod wire;

#[cfg(test)]
mod fake_runtime;
#[cfg(test)]
mod fixtures;
#[cfg(test)]
mod host_tests;
#[cfg(test)]
mod tests;

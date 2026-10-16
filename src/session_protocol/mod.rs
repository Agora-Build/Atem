//! atem-session v1 (designs/protocol/atem-session-v1.md, r5, compatibility mode):
//! wire types, strict decoding and the canonical payload digest.
//!
//! Pure logic: nothing here touches sockets, PTYs or files. Later tasks add the
//! client state machines and the host authority on top of these types.

// Not wired into the runtime yet (plan Task 3 does that); until then only the
// tests use most of this module.
#[allow(dead_code)]
pub mod canonical;
#[allow(dead_code)]
pub mod wire;

#[cfg(test)]
mod tests;

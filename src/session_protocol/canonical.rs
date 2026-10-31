//! Strict JSON parsing and RFC 8785 (JCS) canonicalisation: the shared
//! implementation lives in `atem-client` (r9 signs over the same `jcs`).
pub use atem_client::canonical::*;

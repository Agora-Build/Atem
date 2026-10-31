//! The pairing ceremony's r9 field that both sides check the same way
//! (atem-session-v1.md §R9.2 "Pairing"): `verifyCommit.host_trust_gen`,
//! the binding's host trust generation that Astation copies into the
//! signed `add_host`. A JSON integer, 1 ≤ n ≤ 2^53−1, required.
use serde_json::Value;

use crate::canonical::{MAX_SAFE_INTEGER, Numbers, parse_strict};

/// Largest ceremony message read.
const MAX_MESSAGE: usize = 64 * 1024;

/// Why a `verifyCommit` is refused (Astation answers `verifyAbort`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommitRefusal {
    /// Not strict JSON (duplicate keys, an unsafe integer, …).
    Malformed,
    /// Not a `verifyCommit` message.
    NotVerifyCommit,
    /// `host_trust_gen` missing.
    Absent,
    /// Not an integer in 1 ≤ n ≤ 2^53−1.
    OutOfRange,
}

/// `host_trust_gen` of a `verifyCommit` message
/// (`{"type":"verifyCommit","data":{…,"host_trust_gen":n}}`), as Astation
/// must read it.
pub fn verify_commit_host_trust_gen(raw: &[u8]) -> Result<u64, CommitRefusal> {
    let value = parse_strict(raw, MAX_MESSAGE, Numbers::AllowFractions)
        .map_err(|_| CommitRefusal::Malformed)?;
    if value.get("type").and_then(Value::as_str) != Some("verifyCommit") {
        return Err(CommitRefusal::NotVerifyCommit);
    }
    let field = value
        .get("data")
        .and_then(|d| d.get("host_trust_gen"))
        .ok_or(CommitRefusal::Absent)?;
    if field.is_null() {
        return Err(CommitRefusal::Absent);
    }
    match field.as_u64() {
        Some(n) if (1..=MAX_SAFE_INTEGER).contains(&n) && field.is_u64() => Ok(n),
        _ => Err(CommitRefusal::OutOfRange),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_generation_is_read_strictly() {
        let msg = |g: &str| {
            format!(
                r#"{{"type":"verifyCommit","data":{{"device_id":"d","commitment":"c","host_trust_gen":{g}}}}}"#
            )
        };
        assert_eq!(verify_commit_host_trust_gen(msg("3").as_bytes()), Ok(3));
        for bad in ["0", "-1", "1.5", "3.0", "\"3\"", "null"] {
            assert!(
                verify_commit_host_trust_gen(msg(bad).as_bytes()).is_err(),
                "{bad}"
            );
        }
        assert_eq!(
            verify_commit_host_trust_gen(msg("9007199254740992").as_bytes()),
            Err(CommitRefusal::Malformed)
        );
    }
}

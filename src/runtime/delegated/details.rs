//! The `detail` texts of the delegated lifecycle, exactly as host-work-v1
//! §11.6 "Details" gives them: display text clients don't parse, whose
//! texts are exact. A test compares them with the table, byte for byte.

/// `blocked`: the sender is held (a `hold` record).
pub const PAUSED: &str = "paused";
/// `blocked`: the revocation gate (or, for a host sender, the mailbox gate)
/// is closed.
pub const REVOCATIONS_NOT_YET_CHECKED: &str = "revocations not yet checked";
/// `blocked`: the last carriage or fetch stopped at a deferred entry.
pub const DEVICE_LIST_UPDATE_PENDING: &str = "device list update pending";
/// `blocked`: a locked cred agent leaves the project scope pending.
pub const WAITING_FOR_UNLOCK: &str = "waiting for unlock";
/// `cancelled`: a `revoke` record, an R9 removal, or a host sender's
/// `host_sender_revoke`, `remove_host` or new membership epoch.
pub const SENDER_REVOKED: &str = "sender revoked";
/// `failed`: the current grant (or a host sender's projects) no longer
/// covers the task.
pub const AUTHORIZATION_NARROWED: &str = "sender's authorization narrowed";
/// `failed`: the route's revision, principals or profile changed.
pub const ROUTE_CHANGED: &str = "route changed";
/// `failed`: a frozen, faulted or held device list.
pub const AUTHORITY_CHANGED: &str = "sender's authority changed";
/// `failed`: 8 attempts.
pub const TOO_MANY_ATTEMPTS: &str = "too many attempts";
/// `failed`: a launch still waiting at the spawn boundary at its expiry.
pub const EXPIRED_BEFORE_THE_SPAWN: &str = "expired before the spawn";
/// `awaiting_result`: a running turn interrupted at the task's deadline
/// (then `expired`, as in v1).
pub const INTERRUPTED_AT_DEADLINE: &str = "interrupted at deadline";
/// `outcome_unknown`: its deadline passed unresolved.
pub const DEADLINE_PASSED_OUTCOME_UNKNOWN: &str = "deadline passed; outcome unknown";
/// A `work_interrupt` result: the task's turn isn't the session's current
/// turn (§11.2); that result only, never stored.
pub const NOT_RUNNING: &str = "not running";
/// An error, `busy`: the 64 (per sender) or 256 (per host) limit.
pub const TOO_MANY_UNRESOLVED_OUTCOMES: &str = "too many unresolved outcomes";
/// A receipt (session-v1 R9.14 item 6): an `accepted` attempt found at
/// recovery; the session host's own text.
pub use crate::session_protocol::host::DETAIL_WITHDRAWN_AT_RECOVERY as WITHDRAWN_AT_RECOVERY;
/// A receipt (session-v1 R9.14 items 3 and 4): host-work withdrew the
/// attempt; the session host's own text.
pub use crate::session_protocol::host::DETAIL_WITHDRAWN_BY_HOST as WITHDRAWN_BY_THE_HOST;

/// Every text, in the table's order.
pub const ALL: [&str; 16] = [
    PAUSED,
    REVOCATIONS_NOT_YET_CHECKED,
    DEVICE_LIST_UPDATE_PENDING,
    WAITING_FOR_UNLOCK,
    SENDER_REVOKED,
    AUTHORIZATION_NARROWED,
    ROUTE_CHANGED,
    AUTHORITY_CHANGED,
    TOO_MANY_ATTEMPTS,
    EXPIRED_BEFORE_THE_SPAWN,
    INTERRUPTED_AT_DEADLINE,
    DEADLINE_PASSED_OUTCOME_UNKNOWN,
    NOT_RUNNING,
    TOO_MANY_UNRESOLVED_OUTCOMES,
    WITHDRAWN_BY_THE_HOST,
    WITHDRAWN_AT_RECOVERY,
];

#[cfg(test)]
mod tests {
    use super::*;

    /// host-work-v1, whose §11.6 "Details" table these texts are.
    const CONTRACT: &str = include_str!("../../../designs/protocol/atem-host-work-v1.md");

    /// The table's rows: the state cell as written, and every backticked
    /// text of the `detail` cell, in order.
    fn table() -> Vec<(String, Vec<String>)> {
        let (_, section) = CONTRACT
            .split_once("\n#### Details\n")
            .expect("§11.6 has a Details table");
        let section = section.split("\n#### ").next().unwrap();
        let rows: Vec<_> = section
            .lines()
            .filter(|l| l.starts_with('|'))
            .skip(2) // the header and its rule
            .map(|line| {
                let cells: Vec<&str> = line.split('|').map(str::trim).collect();
                assert_eq!(cells.len(), 5, "three cells: {line}");
                let texts = cells[2]
                    .split('`')
                    .skip(1)
                    .step_by(2)
                    .map(str::to_owned)
                    .collect();
                (cells[1].to_owned(), texts)
            })
            .collect();
        assert!(!rows.is_empty());
        rows
    }

    /// Every text here is the table's, byte for byte, in the table's
    /// order and under its state; and the table has no other.
    #[test]
    fn details_match_the_contract_table() {
        let blocked = "`blocked`";
        let failed = "`failed`";
        let ours: Vec<(&str, Vec<&str>)> = vec![
            (blocked, vec![PAUSED]),
            (blocked, vec![REVOCATIONS_NOT_YET_CHECKED]),
            (blocked, vec![DEVICE_LIST_UPDATE_PENDING]),
            (blocked, vec![WAITING_FOR_UNLOCK]),
            ("`cancelled`", vec![SENDER_REVOKED]),
            (failed, vec![AUTHORIZATION_NARROWED]),
            (failed, vec![ROUTE_CHANGED]),
            (failed, vec![AUTHORITY_CHANGED]),
            (failed, vec![TOO_MANY_ATTEMPTS]),
            (failed, vec![EXPIRED_BEFORE_THE_SPAWN]),
            ("`awaiting_result`", vec![INTERRUPTED_AT_DEADLINE]),
            ("`outcome_unknown`", vec![DEADLINE_PASSED_OUTCOME_UNKNOWN]),
            ("(a `work_interrupt` result)", vec![NOT_RUNNING]),
            ("(an error)", vec![TOO_MANY_UNRESOLVED_OUTCOMES]),
            (
                "(a receipt)",
                vec![WITHDRAWN_BY_THE_HOST, WITHDRAWN_AT_RECOVERY],
            ),
        ];
        let theirs = table();
        let theirs: Vec<(&str, Vec<&str>)> = theirs
            .iter()
            .map(|(state, texts)| (state.as_str(), texts.iter().map(String::as_str).collect()))
            .collect();
        assert_eq!(ours, theirs);
        let mut all: Vec<&str> = ours.iter().flat_map(|(_, t)| t.iter().copied()).collect();
        assert_eq!(all, ALL, "ALL lists every text, in the table's order");
        all.sort_unstable();
        all.dedup();
        assert_eq!(all.len(), ALL.len(), "no text twice");
    }
}

//! atem-session r8 revision admission and features (contract appendix "r8",
//! §A): the revision a `hello`/`welcome` must name, the feature names a host
//! may advertise, which of them this host implements, and which host work
//! each `r8-*` shared fixture needs before the runners run it.
//!
//! Dependency-free (std only), so tests/runtime_fixtures_binary.rs includes
//! this file too (`#[path]`) and both fixture runners gate on the same list.

/// The contract revision `hello` must carry and `welcome` echoes.
pub const REVISION: u64 = 8;

pub const CHAT_HISTORY_END: &str = "chat.history_end";
pub const CHAT_HISTORY: &str = "chat.history";
pub const CHAT_LOOKUP: &str = "chat.lookup";
pub const CHAT_COVERAGE: &str = "chat.coverage";
pub const RECEIPT_RESULT: &str = "receipt.result";
pub const APPROVAL_SESSION_RULES: &str = "approval.session_rules";
pub const APPROVAL_CARD_REASON: &str = "approval.card_reason";
pub const CHAT_SEND_ACQUIRE: &str = "chat.send_acquire";
pub const APPROVAL_LEASE_FREE: &str = "approval.lease_free";

/// Every feature the r8 contract names (§A). A client enables only these,
/// and only when the host advertised them; other names are ignored.
pub const KNOWN_FEATURES: &[&str] = &[
    CHAT_HISTORY_END,
    CHAT_HISTORY,
    CHAT_LOOKUP,
    CHAT_COVERAGE,
    RECEIPT_RESULT,
    APPROVAL_SESSION_RULES,
    APPROVAL_CARD_REASON,
    CHAT_SEND_ACQUIRE,
    APPROVAL_LEASE_FREE,
];

/// What this host implements and advertises in `welcome.features`, in
/// order. A feature is added here only once its fixtures pass (§A): the
/// r8 tasks extend this one list. `receipt.result` is implemented
/// (`HostConfig::receipt_result`) but joins only with the history
/// features its fixture needs (`r8-receipt-result-bounds-reply-message-ids`).
pub const FEATURES: &[&str] = &[
    APPROVAL_SESSION_RULES,
    APPROVAL_CARD_REASON,
    CHAT_SEND_ACQUIRE,
    APPROVAL_LEASE_FREE,
];

/// Host work an r8 fixture may need that is not a wire feature.
/// `admission`: `hello.revision`, `welcome.revision`/`features`, the removed
/// r7 forms refused (task 1). `principals`: submitter principals, control
/// generations, the durable fence, the refusal list, clean close, journal
/// halts and the restart's resolution (§H, §I; task 2).
pub const ADMISSION: &str = "admission";
pub const PRINCIPALS: &str = "principals";

/// The non-feature host work implemented and on in the runtime.
pub const IMPLEMENTED_WORK: &[&str] = &[ADMISSION, PRINCIPALS];

/// §F/§G scenarios: their setup `welcome` must advertise both
/// (fixtures/schema.md).
const SEND: &[&str] = &[CHAT_SEND_ACQUIRE, APPROVAL_LEASE_FREE];
/// §H/§I fixtures (they send with the acquiring Send).
const SEND_DURABLE: &[&str] = &[CHAT_SEND_ACQUIRE, APPROVAL_LEASE_FREE, PRINCIPALS];
const PAGES: &[&str] = &[CHAT_HISTORY_END, CHAT_HISTORY];
const PAGES_COVERAGE: &[&str] = &[CHAT_HISTORY_END, CHAT_HISTORY, CHAT_COVERAGE];
const LOOKUP: &[&str] = &[CHAT_HISTORY_END, CHAT_HISTORY, CHAT_LOOKUP];

/// What each `r8-*` fixture needs, by name. Send and approval scenarios
/// need both §F/§G features: their setup `welcome` must advertise them
/// (fixtures/schema.md). The admission scenario's welcome names seven
/// features, so it runs once all of them ship.
pub const R8_FIXTURE_NEEDS: &[(&str, &[&str])] = &[
    ("r8-approval-answer-by-a-non-holder-leaves-the-lease", SEND),
    ("r8-approval-answer-keeps-the-holders-deadline", SEND),
    (
        "r8-approval-answer-to-a-closed-request-is-stale-target",
        SEND,
    ),
    ("r8-approval-answer-with-acquire-is-refused", SEND),
    ("r8-approval-answers-crossing-first-wins", SEND),
    (
        "r8-approval-late-answer-after-push-resolved-is-stale-target",
        SEND,
    ),
    ("r8-approval-opens-without-a-lease-holder", SEND),
    ("r8-approval-stays-pending-when-the-lease-ends", SEND),
    ("r8-approval-survives-takeover", SEND),
    ("r8-backlog-hole-is-reported-not-reopened", PAGES_COVERAGE),
    (
        "r8-clean-close-runs-queued-work-once-its-principal-is-confirmed",
        SEND_DURABLE,
    ),
    ("r8-client-delayed-send-reply-never-restores-control", SEND),
    ("r8-client-enables-only-advertised-features", &[ADMISSION]),
    ("r8-client-refuses-a-host-without-revision-8", &[ADMISSION]),
    (
        "r8-client-shows-truncation-and-resyncs-only-on-a-sequence-gap",
        PAGES_COVERAGE,
    ),
    (
        "r8-control-fence-holds-when-a-rejection-write-fails",
        SEND_DURABLE,
    ),
    (
        "r8-crash-after-durable-acceptance-grants-no-lease",
        SEND_DURABLE,
    ),
    (
        "r8-crash-rejects-queued-work-whose-history-is-unknown",
        SEND_DURABLE,
    ),
    ("r8-delayed-send-reply-does-not-regrant-lost-control", SEND),
    ("r8-disconnect-right-after-acceptance", SEND),
    ("r8-double-write-failure-takeover-never-runs", SEND_DURABLE),
    ("r8-duplicate-send-never-reacquires-or-replays", SEND),
    ("r8-expired-lease-is-checked-at-admission", SEND),
    (
        "r8-failed-fence-write-rejects-queued-work-at-once",
        SEND_DURABLE,
    ),
    (
        "r8-failed-fence-write-then-control-restored-never-runs",
        SEND_DURABLE,
    ),
    ("r8-failed-persistence-changes-no-lease", SEND_DURABLE),
    (
        "r8-hello-without-revision-8-is-refused-before-any-attachment",
        &[
            ADMISSION,
            CHAT_HISTORY_END,
            CHAT_HISTORY,
            CHAT_LOOKUP,
            CHAT_COVERAGE,
            RECEIPT_RESULT,
            APPROVAL_SESSION_RULES,
            APPROVAL_CARD_REASON,
        ],
    ),
    (
        "r8-history-page-and-live-events-share-one-ordered-stream",
        LOOKUP,
    ),
    ("r8-history-selectors-are-exclusive-and-validated", LOOKUP),
    ("r8-local-input-wins-over-a-send", SEND),
    ("r8-long-turn-is-recovered-in-bounded-pages", LOOKUP),
    (
        "r8-open-with-before-is-refused",
        &[ADMISSION, CHAT_HISTORY_END],
    ),
    (
        "r8-ownership-is-checked-at-admission-not-as-displayed",
        SEND,
    ),
    ("r8-process-replaced-before-dispatch", SEND),
    (
        "r8-receipt-result-bounds-reply-message-ids",
        &[CHAT_HISTORY_END, CHAT_HISTORY, CHAT_LOOKUP, RECEIPT_RESULT],
    ),
    (
        "r8-recovered-work-needs-its-principal-confirmed",
        SEND_DURABLE,
    ),
    (
        "r8-revoked-control-fences-work-across-reconnect-and-restart",
        SEND_DURABLE,
    ),
    (
        "r8-revoked-control-refuses-the-send-and-its-queued-prompt",
        SEND_DURABLE,
    ),
    ("r8-send-acquire-wire-rules", SEND),
    ("r8-send-acquires-an-unowned-session", SEND),
    ("r8-send-refused-while-another-holds-then-takeover", SEND),
    ("r8-send-under-the-own-lease-checks-the-epoch", SEND),
    (
        "r8-stale-or-foreign-next-token-is-stale-target",
        &[CHAT_HISTORY_END, CHAT_HISTORY, CHAT_LOOKUP, CHAT_COVERAGE],
    ),
    ("r8-stale-takeover-confirmation-is-refused", SEND),
    (
        "r8-truncated-history-reopens-once-then-stays-live",
        PAGES_COVERAGE,
    ),
    ("r8-two-simultaneous-sends-acquire-once", SEND),
];

/// Whether an `r8-*` fixture can run against the runtime now: `Ok(())`, or
/// `Err` with the reason (the work it still needs, or that it is not
/// listed).
pub fn r8_fixture_runnable(name: &str) -> Result<(), String> {
    let Some((_, needs)) = R8_FIXTURE_NEEDS.iter().find(|(n, _)| *n == name) else {
        return Err(format!("{name} is not listed in R8_FIXTURE_NEEDS"));
    };
    let missing: Vec<&str> = needs
        .iter()
        .copied()
        .filter(|n| !FEATURES.contains(n) && !IMPLEMENTED_WORK.contains(n))
        .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!("needs {}", missing.join(", ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn features_are_known_and_needs_are_named() {
        assert!(FEATURES.iter().all(|f| KNOWN_FEATURES.contains(f)));
        for (name, needs) in R8_FIXTURE_NEEDS {
            assert!(name.starts_with("r8-"), "{name}");
            for n in *needs {
                assert!(
                    KNOWN_FEATURES.contains(n) || [ADMISSION, PRINCIPALS].contains(n),
                    "{name}: {n}"
                );
            }
        }
        assert!(r8_fixture_runnable("r8-client-refuses-a-host-without-revision-8").is_ok());
        assert_eq!(
            r8_fixture_runnable("r8-open-with-before-is-refused"),
            Err("needs chat.history_end".into())
        );
        assert!(r8_fixture_runnable("r8-unknown").is_err());
        assert!(r8_fixture_runnable("r8-failed-fence-write-rejects-queued-work-at-once").is_ok());
        assert!(r8_fixture_runnable("r8-approval-answer-with-acquire-is-refused").is_ok());
    }
}

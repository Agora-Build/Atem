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
/// r8 tasks extend this one list.
pub const FEATURES: &[&str] = &[APPROVAL_SESSION_RULES];

/// Host work an r8 fixture may need that is not a wire feature.
/// `admission`: `hello.revision`, `welcome.revision`/`features`, the removed
/// r7 forms refused (task 1). `principals`: submitter principals, control
/// generations, the durable fence, the refusal list, clean close, journal
/// halts and the restart's resolution (§H, §I; task 2).
/// `session.send_acquire`: §F's acquiring `prompt` submit in its session-v1
/// form (`acquire`/`takeover`/`expected_controller`, `lease_held` naming the
/// holder, the lease on the admitting reply). Built with §I in task 2, but
/// off in the runtime (`HostConfig::send_acquire`) and not advertised
/// until `chat.send_acquire` ships with the chat-v1 form in task 3.
pub const ADMISSION: &str = "admission";
pub const PRINCIPALS: &str = "principals";
pub const SESSION_SEND_ACQUIRE: &str = "session.send_acquire";

/// The non-feature host work implemented and on in the runtime.
pub const IMPLEMENTED_WORK: &[&str] = &[ADMISSION, PRINCIPALS];

/// Work implemented but on only in the core fixture harness
/// (`fake_runtime::harness_config`): the core runner treats a fixture's need
/// for it as met, the real-runtime runner doesn't.
pub const HARNESS_WORK: &[&str] = &[SESSION_SEND_ACQUIRE];

const SEND: &[&str] = &[CHAT_SEND_ACQUIRE, APPROVAL_LEASE_FREE];
// TODO(r8 task 3): once `chat.send_acquire` and `approval.lease_free` are
// advertised, these fixtures need `SEND` (their setup welcome must
// advertise both, fixtures/schema.md) instead of `session.send_acquire`.
/// §F fixtures that only use the session-v1 Send.
const SESSION_SEND: &[&str] = &[SESSION_SEND_ACQUIRE];
/// §H/§I fixtures (they send with the session-v1 Send).
const SESSION_SEND_DURABLE: &[&str] = &[SESSION_SEND_ACQUIRE, PRINCIPALS];
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
    ("r8-backlog-hole-is-reported-not-reopened", PAGES_COVERAGE),
    (
        "r8-clean-close-runs-queued-work-once-its-principal-is-confirmed",
        SESSION_SEND_DURABLE,
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
        SESSION_SEND_DURABLE,
    ),
    (
        "r8-crash-after-durable-acceptance-grants-no-lease",
        SESSION_SEND_DURABLE,
    ),
    (
        "r8-crash-rejects-queued-work-whose-history-is-unknown",
        SESSION_SEND_DURABLE,
    ),
    (
        "r8-delayed-send-reply-does-not-regrant-lost-control",
        SESSION_SEND,
    ),
    ("r8-disconnect-right-after-acceptance", SESSION_SEND),
    (
        "r8-double-write-failure-takeover-never-runs",
        SESSION_SEND_DURABLE,
    ),
    (
        "r8-duplicate-send-never-reacquires-or-replays",
        SESSION_SEND,
    ),
    ("r8-expired-lease-is-checked-at-admission", SESSION_SEND),
    (
        "r8-failed-fence-write-rejects-queued-work-at-once",
        SESSION_SEND_DURABLE,
    ),
    (
        "r8-failed-fence-write-then-control-restored-never-runs",
        SESSION_SEND_DURABLE,
    ),
    (
        "r8-failed-persistence-changes-no-lease",
        SESSION_SEND_DURABLE,
    ),
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
    ("r8-local-input-wins-over-a-send", SESSION_SEND),
    ("r8-long-turn-is-recovered-in-bounded-pages", LOOKUP),
    (
        "r8-open-with-before-is-refused",
        &[ADMISSION, CHAT_HISTORY_END],
    ),
    (
        "r8-ownership-is-checked-at-admission-not-as-displayed",
        SESSION_SEND,
    ),
    ("r8-process-replaced-before-dispatch", SESSION_SEND),
    (
        "r8-receipt-result-bounds-reply-message-ids",
        &[CHAT_HISTORY_END, CHAT_HISTORY, CHAT_LOOKUP, RECEIPT_RESULT],
    ),
    (
        "r8-recovered-work-needs-its-principal-confirmed",
        SESSION_SEND_DURABLE,
    ),
    (
        "r8-revoked-control-fences-work-across-reconnect-and-restart",
        SESSION_SEND_DURABLE,
    ),
    (
        "r8-revoked-control-refuses-the-send-and-its-queued-prompt",
        SESSION_SEND_DURABLE,
    ),
    ("r8-send-acquire-wire-rules", SEND),
    ("r8-send-acquires-an-unowned-session", SEND),
    (
        "r8-send-refused-while-another-holds-then-takeover",
        SESSION_SEND,
    ),
    ("r8-send-under-the-own-lease-checks-the-epoch", SESSION_SEND),
    (
        "r8-stale-or-foreign-next-token-is-stale-target",
        &[CHAT_HISTORY_END, CHAT_HISTORY, CHAT_LOOKUP, CHAT_COVERAGE],
    ),
    ("r8-stale-takeover-confirmation-is-refused", SESSION_SEND),
    (
        "r8-truncated-history-reopens-once-then-stays-live",
        PAGES_COVERAGE,
    ),
    ("r8-two-simultaneous-sends-acquire-once", SESSION_SEND),
];

/// r7.x fixtures whose text contradicts the r8 appendix: they are not
/// edited (the fixtures are shared with Astation) but reported as not run,
/// with the appendix rule that removes what they exercise. Each one's r8
/// counterpart is named.
pub const SUPERSEDED_BY_R8: &[(&str, &str)] = &[
    (
        "approval-answer-with-acquire-takes-control-from-the-holder",
        "superseded by r8: acquire on an approval answer is removed (§A, §G); see r8-approval-answer-with-acquire-is-refused",
    ),
    (
        "approval-late-answer-after-push-resolved-is-stale-target",
        "superseded by r8: it answers with acquire, removed (§A, §G); see r8-approval-answer-to-a-closed-request-is-stale-target",
    ),
    (
        "approval-opens-without-a-lease-holder",
        "superseded by r8: it answers with acquire, removed (§A, §G); see r8-approval-answer-keeps-the-holders-deadline",
    ),
    (
        "approval-stays-pending-when-the-lease-ends",
        "superseded by r8: it answers with acquire, removed (§A, §G); see r8-approval-answer-by-a-non-holder-leaves-the-lease",
    ),
];

/// Why an r7.x fixture is not run (`SUPERSEDED_BY_R8`), if it isn't.
pub fn superseded(name: &str) -> Option<&'static str> {
    SUPERSEDED_BY_R8
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, why)| *why)
}

/// Whether an `r8-*` fixture can run against the runtime now: `Ok(())`, or
/// `Err` with the reason (the work it still needs, or that it is not
/// listed).
pub fn r8_fixture_runnable(name: &str) -> Result<(), String> {
    runnable_with(name, &[])
}

/// As `r8_fixture_runnable`, in the core harness, which also has
/// `HARNESS_WORK` on.
pub fn r8_fixture_runnable_in_harness(name: &str) -> Result<(), String> {
    runnable_with(name, HARNESS_WORK)
}

fn runnable_with(name: &str, extra: &[&str]) -> Result<(), String> {
    let Some((_, needs)) = R8_FIXTURE_NEEDS.iter().find(|(n, _)| *n == name) else {
        return Err(format!("{name} is not listed in R8_FIXTURE_NEEDS"));
    };
    let missing: Vec<&str> = needs
        .iter()
        .copied()
        .filter(|n| !FEATURES.contains(n) && !IMPLEMENTED_WORK.contains(n) && !extra.contains(n))
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
                    KNOWN_FEATURES.contains(n)
                        || [ADMISSION, PRINCIPALS, SESSION_SEND_ACQUIRE].contains(n),
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
        let fence = "r8-failed-fence-write-rejects-queued-work-at-once";
        assert_eq!(
            r8_fixture_runnable(fence),
            Err("needs session.send_acquire".into())
        );
        assert!(r8_fixture_runnable_in_harness(fence).is_ok());
        assert!(HARNESS_WORK.iter().all(|w| !IMPLEMENTED_WORK.contains(w)));
    }
}

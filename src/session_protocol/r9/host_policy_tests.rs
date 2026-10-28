use super::*;
use crate::paths::ProfilePaths;
use crate::session_protocol::membership::store::Injected;

const ACCT: &str = "acct-1";
const GEN: &str = "aaaa";
const R1: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const R2: &str = "aaaaaaaa-0000-4000-8000-000000000002";
const R3: &str = "aaaaaaaa-0000-4000-8000-000000000003";

struct Rig {
    _dir: tempfile::TempDir,
    paths: PairingPaths,
    store: Store,
}

impl Rig {
    fn new() -> Rig {
        let dir = tempfile::tempdir().unwrap();
        let paths = ProfilePaths::in_dir(dir.path()).pairing;
        let journal = dir.path().join("runtime").join("journal");
        store::private_dir(&journal).unwrap();
        store::private_dir(paths.dir()).unwrap();
        // The pinned list, as `peek_pin_genesis` reads it.
        std::fs::write(
            &paths.membership,
            serde_json::json!({"account_id": ACCT, "genesis_hash": GEN,
                "host": {"host_id": "host-a", "host_trust_gen": 1}})
            .to_string(),
        )
        .unwrap();
        let store = Store::new(&paths, &journal);
        Rig {
            _dir: dir,
            paths,
            store,
        }
    }

    fn set(
        &mut self,
        request_id: &str,
        relay_only: bool,
        expected: u64,
    ) -> Result<SetResult, Refused> {
        set(
            &mut self.store,
            &self.paths,
            ACCT,
            GEN,
            &Change {
                principal: "member:dev-mac",
                request_id,
                relay_only,
                expected_revision: expected,
            },
        )
    }

    fn current(&self) -> Current {
        current(&self.paths, ACCT, GEN).unwrap()
    }
}

fn outcome(r: Result<SetResult, Refused>) -> (Outcome, u64, bool, PolicyState) {
    let r = r.unwrap();
    (
        r.outcome,
        r.policy.revision,
        r.policy.relay_only,
        r.policy.state,
    )
}

use PolicyState::{Durable, Uncertain};

#[test]
fn a_fresh_host_allows_local_and_a_commit_moves_the_revision_once() {
    let mut rig = Rig::new();
    assert!(local_allowed(&rig.paths));
    assert_eq!(rig.current().policy().revision, 0);
    assert_eq!(
        outcome(rig.set(R1, true, 0)),
        (Outcome::Committed, 1, true, Durable)
    );
    assert!(!local_allowed(&rig.paths));
    assert!(!rig.paths.host_policy_pending.exists());
    // The retry: the same result, no second change.
    assert_eq!(
        outcome(rig.set(R1, true, 0)),
        (Outcome::Committed, 1, true, Durable)
    );
    // Same id, another body; or another principal.
    assert_eq!(rig.set(R1, false, 0), Err(Refused::Reused));
    assert_eq!(
        set(
            &mut rig.store,
            &rig.paths,
            ACCT,
            GEN,
            &Change {
                principal: "member:dev-phone",
                request_id: R1,
                relay_only: true,
                expected_revision: 0,
            },
        ),
        Err(Refused::Reused)
    );
    assert_eq!(rig.set(R1, true, 1), Err(Refused::Reused));
    // A new request for the value already set: unchanged, nothing written.
    assert_eq!(
        outcome(rig.set(R2, true, 1)),
        (Outcome::Unchanged, 1, true, Durable)
    );
    // A stale expected revision: conflict, the current policy reported.
    assert_eq!(
        outcome(rig.set(R3, false, 0)),
        (Outcome::Conflict, 1, true, Durable)
    );
}

/// Astation's counterexample: A=true, B=false, then A retried. A never
/// re-applies; its result is `superseded` with the current state.
#[test]
fn a_retry_after_a_later_change_is_superseded_and_never_reapplies() {
    let mut rig = Rig::new();
    assert_eq!(
        outcome(rig.set(R1, true, 0)),
        (Outcome::Committed, 1, true, Durable)
    );
    assert_eq!(
        outcome(rig.set(R2, false, 1)),
        (Outcome::Committed, 2, false, Durable)
    );
    assert_eq!(
        outcome(rig.set(R1, true, 0)),
        (Outcome::Superseded, 2, false, Durable)
    );
    assert!(local_allowed(&rig.paths));
    assert!(!rig.current().doc.relay_only);
}

#[test]
fn a_failure_before_the_pending_rename_changes_nothing() {
    for step in [Step::TempWrite, Step::TempFsync, Step::Rename] {
        let mut rig = Rig::new();
        rig.store.inject(Injected {
            file: DlFile::HostPolicyPending,
            step,
        });
        assert_eq!(
            outcome(rig.set(R1, true, 0)),
            (Outcome::SaveFailed, 0, false, Durable),
            "{step:?}"
        );
        assert!(local_allowed(&rig.paths), "{step:?}");
        // Not recorded: the retry is a new request and commits.
        assert_eq!(
            outcome(rig.set(R1, true, 0)),
            (Outcome::Committed, 1, true, Durable)
        );
    }
}

#[test]
fn an_unknown_durability_is_uncertain_blocks_local_and_rolls_forward() {
    let cases = [
        (DlFile::HostPolicyPending, Step::DirectoryFsync),
        (DlFile::HostPolicy, Step::TempWrite),
        (DlFile::HostPolicy, Step::Rename),
        (DlFile::HostPolicy, Step::DirectoryFsync),
    ];
    for (file, step) in cases {
        let mut rig = Rig::new();
        rig.store.inject(Injected { file, step });
        assert_eq!(
            outcome(rig.set(R1, true, 0)),
            (Outcome::Uncertain, 1, true, Uncertain),
            "{file:?} {step:?}"
        );
        assert!(!local_allowed(&rig.paths), "{file:?} {step:?}");
        // The retry says so too, until the change is durable.
        assert_eq!(
            outcome(rig.set(R1, true, 0)),
            (Outcome::Uncertain, 1, true, Uncertain)
        );
        assert_eq!(roll_forward(&mut rig.store, &rig.paths), Ok(true));
        assert_eq!(
            outcome(rig.set(R1, true, 0)),
            (Outcome::Committed, 1, true, Durable)
        );
        assert!(!local_allowed(&rig.paths));
        // A later false is allowed again once durable.
        assert_eq!(
            outcome(rig.set(R2, false, 1)),
            (Outcome::Committed, 2, false, Durable)
        );
        assert!(local_allowed(&rig.paths), "{file:?} {step:?}");
    }
}

/// A crash that lost `host_policy.json`'s rename but kept the pending
/// file: the change is rolled forward, never the older `false`.
#[test]
fn a_lost_rename_with_a_pending_file_rolls_forward_at_start() {
    let mut rig = Rig::new();
    rig.store.inject(Injected {
        file: DlFile::HostPolicy,
        step: Step::Rename,
    });
    rig.set(R1, true, 0).unwrap();
    assert!(!rig.paths.host_policy.exists());
    assert!(!local_allowed(&rig.paths));
    roll_forward(&mut rig.store, &rig.paths).unwrap();
    let c = rig.current();
    assert!(c.doc.relay_only && !c.uncertain);
    assert!(!local_allowed(&rig.paths));
}

#[test]
fn unreadable_or_foreign_policy_fails_closed() {
    let mut rig = Rig::new();
    rig.set(R1, false, 0).unwrap();
    std::fs::write(&rig.paths.host_policy, b"{not json").unwrap();
    assert!(!local_allowed(&rig.paths));
    assert!(matches!(rig.set(R2, true, 0), Err(Refused::Unreadable(_))));
    // Another list's policy.
    let other = Doc::fresh("acct-2", GEN);
    std::fs::write(&rig.paths.host_policy, serde_json::to_vec(&other).unwrap()).unwrap();
    assert!(!local_allowed(&rig.paths));
    assert!(matches!(rig.set(R2, true, 0), Err(Refused::Unreadable(_))));
    // A policy without a readable pinned list.
    std::fs::write(
        &rig.paths.host_policy,
        serde_json::to_vec(&Doc::fresh(ACCT, GEN)).unwrap(),
    )
    .unwrap();
    std::fs::write(&rig.paths.membership, b"x").unwrap();
    assert!(!local_allowed(&rig.paths));
    // A damaged pending file stays and blocks local.
    std::fs::write(&rig.paths.host_policy_pending, b"x").unwrap();
    assert!(roll_forward(&mut rig.store, &rig.paths).is_err());
    assert!(!local_allowed(&rig.paths));
}

#[test]
fn the_newest_requests_are_kept() {
    let mut rig = Rig::new();
    let mut ids = Vec::new();
    for i in 0..(MAX_REQUESTS as u64 + 2) {
        let id = format!("aaaaaaaa-0000-4000-8000-{:012}", i + 10);
        let value = i % 2 == 0;
        assert_eq!(rig.set(&id, value, i).unwrap().outcome, Outcome::Committed);
        ids.push((id, value, i));
    }
    let doc = rig.current().doc;
    assert_eq!(doc.requests.len(), MAX_REQUESTS);
    // The evicted first request: its retry meets the revision check.
    let (id, value, expected) = &ids[0];
    assert_eq!(
        rig.set(id, *value, *expected).unwrap().outcome,
        Outcome::Conflict
    );
    let (id, value, expected) = &ids[5];
    assert_eq!(
        rig.set(id, *value, *expected).unwrap().outcome,
        Outcome::Superseded
    );
}

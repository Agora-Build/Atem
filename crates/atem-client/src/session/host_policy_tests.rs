use super::*;
use crate::encoding::Hash32;
use crate::principal::{ClientKind, Permission};

const RID: &str = "aaaaaaaa-0000-4000-8000-000000000001";
const ID: &str = "aaaaaaaa-0000-4000-8000-000000000002";

fn welcome(features: &[&str]) -> Welcome {
    Welcome {
        id: "w".into(),
        re: None,
        account_id: "acct".into(),
        atem_device_id: "host-a".into(),
        host_trust_gen: 3,
        runtime_gen: "rg".into(),
        controller_session: "cs".into(),
        attachment_gen: "ag-1".into(),
        client_kind: ClientKind::Native,
        permissions: vec![Permission::View, Permission::Control],
        authorization_ms_left: 1,
        server_time: 1,
        revision: 9,
        features: features.iter().map(|f| f.to_string()).collect(),
        principal: "member:phone".into(),
        scope: None,
        head: head(),
        pending_recovery: vec![],
        channel_id: "ch-1".into(),
    }
}

fn head() -> Head {
    Head {
        seq: 7,
        hash: Hash32([7; 32]),
    }
}

fn result(re: &str, outcome: Outcome, relay_only: bool, state: PolicyState) -> HostPolicyResult {
    HostPolicyResult {
        id: crate::session::new_id(),
        re: re.into(),
        request_id: (outcome != Outcome::Current).then(|| RID.to_owned()),
        outcome,
        policy: Policy {
            relay_only,
            revision: 4,
            state,
        },
        account_id: "acct".into(),
        atem_device_id: "host-a".into(),
        host_trust_gen: 3,
        head: head(),
        channel_id: "ch-1".into(),
        attachment_gen: "ag-1".into(),
    }
}

fn sent_id(message: &Value) -> String {
    message["data"]["id"].as_str().unwrap().to_owned()
}

#[test]
fn requests_round_trip_and_reject_extra_or_missing_fields() {
    let s = set(ID, RID, true, 3);
    assert_eq!(
        Request::from_data(&s["data"]).unwrap(),
        Request::Set {
            id: ID.into(),
            request_id: RID.into(),
            relay_only: true,
            expected_revision: 3
        }
    );
    let g = get(ID);
    assert_eq!(
        Request::from_data(&g["data"]).unwrap(),
        Request::Get { id: ID.into() }
    );
    let mut extra = s["data"].clone();
    extra["acquire"] = json!(true);
    assert_eq!(Request::from_data(&extra), Err("fields"));
    let mut missing = s["data"].clone();
    missing.as_object_mut().unwrap().remove("expected_revision");
    missing["x"] = json!(1);
    assert_eq!(Request::from_data(&missing), Err("expected_revision"));
    let mut bad = s["data"].clone();
    bad["request_id"] = json!("not-a-uuid");
    assert_eq!(Request::from_data(&bad), Err("request_id"));
    let mut bad = s["data"].clone();
    bad["relay_only"] = json!("true");
    assert_eq!(Request::from_data(&bad), Err("relay_only"));
    let mut bad = g["data"].clone();
    bad["request_id"] = json!(RID);
    assert_eq!(Request::from_data(&bad), Err("fields"));
}

#[test]
fn a_result_round_trips_and_request_id_follows_the_outcome() {
    for outcome in [Outcome::Committed, Outcome::Current, Outcome::SaveFailed] {
        let r = result(ID, outcome, true, PolicyState::Durable);
        let bytes = r.to_bytes();
        match crate::session::r9::Incoming::parse(&bytes).unwrap() {
            crate::session::r9::Incoming::HostPolicyResult(got) => assert_eq!(*got, r),
            other => panic!("{other:?}"),
        }
    }
    let mut current = result(ID, Outcome::Current, true, PolicyState::Durable).to_json();
    current["data"]["request_id"] = json!(RID);
    assert_eq!(
        HostPolicyResult::from_data(&current["data"]),
        Err("request_id")
    );
    let mut set_result = result(ID, Outcome::Committed, true, PolicyState::Durable).to_json();
    set_result["data"]
        .as_object_mut()
        .unwrap()
        .remove("request_id");
    assert_eq!(
        HostPolicyResult::from_data(&set_result["data"]),
        Err("request_id")
    );
    let mut extra = result(ID, Outcome::Committed, true, PolicyState::Durable).to_json();
    extra["data"]["stored"] = json!(true);
    assert_eq!(HostPolicyResult::from_data(&extra["data"]), Err("fields"));
}

#[test]
fn only_a_durable_confirming_result_for_an_outstanding_id_is_ready() {
    let mut t = HostPolicyTracker::new(&welcome(&[FEATURE]), true);
    assert!(!t.ready());
    // Nothing outstanding: a result is foreign.
    let r = result(ID, Outcome::Committed, true, PolicyState::Durable);
    assert_eq!(t.observe(&r), Observed::Foreign);
    for (outcome, state, relay_only, expect) in [
        (
            Outcome::Uncertain,
            PolicyState::Uncertain,
            true,
            Observed::NotReady,
        ),
        (
            Outcome::SaveFailed,
            PolicyState::Durable,
            false,
            Observed::NotReady,
        ),
        (
            Outcome::Conflict,
            PolicyState::Durable,
            true,
            Observed::NotReady,
        ),
        (
            Outcome::Superseded,
            PolicyState::Durable,
            true,
            Observed::NotReady,
        ),
        (
            Outcome::Committed,
            PolicyState::Uncertain,
            true,
            Observed::NotReady,
        ),
        (
            Outcome::Unchanged,
            PolicyState::Durable,
            false,
            Observed::NotReady,
        ),
        (
            Outcome::Committed,
            PolicyState::Durable,
            true,
            Observed::Ready,
        ),
    ] {
        let id = sent_id(&t.set(RID));
        assert_eq!(
            t.observe(&result(&id, outcome, relay_only, state)),
            expect,
            "{outcome:?} {state:?} {relay_only}"
        );
        // An id answers once.
        assert_eq!(
            t.observe(&result(&id, outcome, relay_only, state)),
            Observed::Foreign
        );
    }
    assert!(t.ready());
    // A later result reporting another value ends readiness.
    let id = sent_id(&t.get());
    assert_eq!(
        t.observe(&result(&id, Outcome::Current, false, PolicyState::Durable)),
        Observed::NotReady
    );
    assert!(!t.ready());
}

#[test]
fn a_result_bound_to_another_channel_or_host_never_confirms() {
    let mut t = HostPolicyTracker::new(&welcome(&[FEATURE]), true);
    type Edit = fn(&mut HostPolicyResult);
    let edits: [Edit; 5] = [
        |r| r.channel_id = "ch-2".into(),
        |r| r.attachment_gen = "ag-2".into(),
        |r| r.account_id = "other".into(),
        |r| r.atem_device_id = "host-b".into(),
        |r| r.host_trust_gen = 4,
    ];
    for edit in edits {
        let id = sent_id(&t.get());
        let mut r = result(&id, Outcome::Current, true, PolicyState::Durable);
        edit(&mut r);
        assert_eq!(t.observe(&r), Observed::Foreign);
        assert!(!t.ready());
    }
}

#[test]
fn a_host_without_the_feature_is_never_ready_and_retries_reuse_the_request() {
    let mut t = HostPolicyTracker::new(&welcome(&[]), true);
    assert!(!t.supported());
    let id = sent_id(&t.get());
    assert_eq!(
        t.observe(&result(&id, Outcome::Current, true, PolicyState::Durable)),
        Observed::NotReady
    );
    // Expected revision follows the newest bound result; a retry keeps the
    // request id and body under a fresh id.
    let mut t = HostPolicyTracker::new(&welcome(&[FEATURE]), true);
    let first = t.set(RID);
    assert_eq!(first["data"]["expected_revision"], json!(0));
    let again = t.retry(RID, 0);
    assert_eq!(again["data"]["request_id"], json!(RID));
    assert_ne!(again["data"]["id"], first["data"]["id"]);
    let id = sent_id(&first);
    t.observe(&result(&id, Outcome::Conflict, false, PolicyState::Durable));
    assert_eq!(t.known().unwrap().revision, 4);
    assert_eq!(t.set(RID)["data"]["expected_revision"], json!(4));
    // Changing the wanted value drops readiness.
    let id = sent_id(&t.get());
    t.set_desired(false);
    assert_eq!(
        t.observe(&result(&id, Outcome::Current, false, PolicyState::Durable)),
        Observed::Ready
    );
    t.set_desired(true);
    assert!(!t.ready());
}

fn change(relay_only: bool, state: PolicyState) -> HostPolicyChanged {
    HostPolicyChanged {
        id: crate::session::new_id(),
        policy: Policy {
            relay_only,
            revision: 5,
            state,
        },
        account_id: "acct".into(),
        atem_device_id: "host-a".into(),
        host_trust_gen: 3,
        head: head(),
        channel_id: "ch-1".into(),
        attachment_gen: "ag-1".into(),
    }
}

#[test]
fn another_managers_change_never_confirms_and_ends_a_contradicted_readiness() {
    let mut t = HostPolicyTracker::new(&welcome(&[FEATURE]), true);
    // Never confirms, even with the wanted value.
    assert_eq!(
        t.observe_change(&change(true, PolicyState::Durable)),
        Observed::NotReady
    );
    assert!(!t.ready());
    assert_eq!(t.known().unwrap().revision, 5);
    let id = sent_id(&t.get());
    t.observe(&result(&id, Outcome::Current, true, PolicyState::Durable));
    assert!(t.ready());
    // The same value keeps it; another value or an uncertain state ends it.
    assert_eq!(
        t.observe_change(&change(true, PolicyState::Durable)),
        Observed::Ready
    );
    assert_eq!(
        t.observe_change(&change(false, PolicyState::Durable)),
        Observed::NotReady
    );
    assert!(!t.ready());
    // Bound elsewhere: ignored.
    let mut other = change(false, PolicyState::Durable);
    other.channel_id = "ch-2".into();
    assert_eq!(t.observe_change(&other), Observed::Foreign);
    // The wire form round-trips; an extra field is refused.
    let c = change(true, PolicyState::Uncertain);
    match crate::session::r9::Incoming::parse(&c.to_bytes()).unwrap() {
        crate::session::r9::Incoming::HostPolicyChanged(got) => assert_eq!(*got, c),
        other => panic!("{other:?}"),
    }
    let mut extra = c.to_json();
    extra["data"]["re"] = json!("x");
    assert_eq!(HostPolicyChanged::from_data(&extra["data"]), Err("fields"));
}

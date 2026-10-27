//! §R9.8a on the host: `host_policy_set`/`host_policy_get` over real
//! channels (the shared client core on the other end).
use super::host_policy;
use super::tests::{HOST, Rig, bot, phone};
use crate::session_protocol::membership::r9log;
use atem_client::connect::{Event as CEvent, Identity};
use atem_client::session::host_policy::{HostPolicyResult, Observed, Outcome, PolicyState};
use serde_json::json;

const R1: &str = "aaaaaaaa-0000-4000-8000-0000000000a1";
const R2: &str = "aaaaaaaa-0000-4000-8000-0000000000a2";

fn mac() -> Identity {
    Identity::native(r9log::MAC, r9log::auth(r9log::MAC))
}

/// A rig whose engine stores the policy, with the Mac (a manager) and the
/// phone (control, no manage) attached.
fn rig() -> Rig {
    let mut rig = Rig::new();
    rig.engine
        .set_policy_paths(rig.pairing.clone(), rig.journal.clone());
    rig.link_up();
    rig.connect("ch-mac", mac());
    rig.advance(1000);
    rig.connect("ch-phone", phone());
    rig
}

/// The host policy results `handle` received since the last call.
fn results(rig: &mut Rig, handle: &str) -> Vec<(HostPolicyResult, Observed)> {
    rig.events(handle)
        .into_iter()
        .filter_map(|e| match e {
            CEvent::HostPolicy { result, observed } => Some((*result, observed)),
            _ => None,
        })
        .collect()
}

fn errors(rig: &mut Rig, handle: &str) -> Vec<(String, Option<String>)> {
    rig.events(handle)
        .into_iter()
        .filter_map(|e| match e {
            CEvent::Error(e) => Some((e.code, e.detail)),
            _ => None,
        })
        .collect()
}

fn set(rig: &mut Rig, handle: &str, relay_only: bool, request_id: &str) -> String {
    let mono = rig.now.host.mono_ms;
    let (id, frame) = rig
        .attached(handle)
        .host_policy_set(relay_only, request_id, mono)
        .unwrap();
    rig.send_frame(handle, &frame);
    id
}

fn retry(rig: &mut Rig, handle: &str, relay_only: bool, request_id: &str, expected: u64) {
    let mono = rig.now.host.mono_ms;
    let (_, frame) = rig
        .attached(handle)
        .host_policy_retry(relay_only, request_id, expected, mono)
        .unwrap();
    rig.send_frame(handle, &frame);
}

fn get(rig: &mut Rig, handle: &str, desired: bool) {
    let mono = rig.now.host.mono_ms;
    let (_, frame) = rig.attached(handle).host_policy_get(desired, mono).unwrap();
    rig.send_frame(handle, &frame);
}

#[test]
fn a_manager_sets_and_reads_the_policy_bound_to_its_channel() {
    let mut rig = rig();
    let welcome = rig.attached("ch-mac").welcome().clone();
    assert!(welcome.features.iter().any(|f| f == "host.policy"));
    let id = set(&mut rig, "ch-mac", true, R1);
    let got = results(&mut rig, "ch-mac");
    assert_eq!(got.len(), 1, "{got:?}");
    let (r, observed) = &got[0];
    assert_eq!(*observed, Observed::Ready);
    assert_eq!(r.re, id);
    assert_ne!(r.id, id, "a fresh id");
    assert_eq!(r.request_id.as_deref(), Some(R1));
    assert_eq!(r.outcome, Outcome::Committed);
    assert_eq!(
        (r.policy.relay_only, r.policy.revision, r.policy.state),
        (true, 1, PolicyState::Durable)
    );
    assert_eq!(r.channel_id, welcome.channel_id);
    assert_eq!(r.attachment_gen, welcome.attachment_gen);
    assert_eq!(r.account_id, welcome.account_id);
    assert_eq!(r.atem_device_id, welcome.atem_device_id);
    assert_eq!(r.host_trust_gen, welcome.host_trust_gen);
    assert_eq!(r.head, welcome.head);
    assert!(rig.attached("ch-mac").host_policy().ready());
    // Stored for the pinned list: no local link from now on.
    assert!(!host_policy::local_allowed(&rig.pairing));
    assert_eq!(rig.engine.take_policy_changes(), vec![true]);
    assert_eq!(rig.receipts, 1, "the result's write is reported");
    // Another manager channel reads it; a retry is the same commit, re-wrapped
    // for the channel it arrives on.
    rig.advance(1000);
    rig.connect("ch-mac-2", mac());
    get(&mut rig, "ch-mac-2", true);
    let got = results(&mut rig, "ch-mac-2");
    assert_eq!(got[0].0.outcome, Outcome::Current);
    assert_eq!(got[0].0.request_id, None);
    assert_eq!(got[0].1, Observed::Ready);
    retry(&mut rig, "ch-mac-2", true, R1, 0);
    let got = results(&mut rig, "ch-mac-2");
    assert_eq!(got[0].0.outcome, Outcome::Committed);
    assert_eq!(got[0].0.policy.revision, 1);
    assert_eq!(
        got[0].0.channel_id,
        rig.attached("ch-mac-2").welcome().channel_id
    );
    // Nothing reached the first channel.
    assert!(results(&mut rig, "ch-mac").is_empty());
}

/// A commit tells every other manager attachment the current policy
/// (`host_policy_changed`), never a non-manager; it confirms nothing.
#[test]
fn other_managers_hear_a_committed_change() {
    let mut rig = rig();
    rig.advance(1000);
    rig.connect("ch-mac-2", mac());
    rig.advance(1000);
    rig.connect("ch-bot", bot());
    set(&mut rig, "ch-mac", true, R1);
    let heard: Vec<_> = rig
        .events("ch-mac-2")
        .into_iter()
        .filter_map(|e| match e {
            CEvent::HostPolicyChanged { change, observed } => Some((*change, observed)),
            _ => None,
        })
        .collect();
    assert_eq!(heard.len(), 1, "{heard:?}");
    let (change, observed) = &heard[0];
    assert_eq!(*observed, Observed::NotReady, "never a confirmation");
    assert!(change.policy.relay_only && change.policy.revision == 1);
    let welcome = rig.attached("ch-mac-2").welcome().clone();
    assert_eq!(change.channel_id, welcome.channel_id);
    assert_eq!(change.attachment_gen, welcome.attachment_gen);
    // The phone has no manage in this rig; the bot is a service.
    for handle in ["ch-phone", "ch-bot"] {
        assert!(
            !rig.events(handle)
                .iter()
                .any(|e| matches!(e, CEvent::HostPolicyChanged { .. })),
            "{handle}"
        );
    }
    // A get confirms it on the other channel; a later change ends it there.
    get(&mut rig, "ch-mac-2", true);
    assert_eq!(results(&mut rig, "ch-mac-2")[0].1, Observed::Ready);
    set(&mut rig, "ch-mac", false, R2);
    assert!(rig.events("ch-mac-2").iter().any(|e| matches!(
        e,
        CEvent::HostPolicyChanged {
            observed: Observed::NotReady,
            ..
        }
    )));
    assert!(!rig.attached("ch-mac-2").host_policy().ready());
}

#[test]
fn only_a_native_manager_may_set_or_read_it() {
    let mut rig = rig();
    rig.advance(1000);
    rig.connect("ch-bot", bot());
    for handle in ["ch-phone", "ch-bot"] {
        set(&mut rig, handle, true, R1);
        get(&mut rig, handle, true);
        assert_eq!(
            errors(&mut rig, handle),
            vec![("forbidden".into(), None), ("forbidden".into(), None)],
            "{handle}"
        );
    }
    assert!(host_policy::local_allowed(&rig.pairing), "nothing stored");
    // A browser holds a grant, not membership.
    let wall = rig.now.host.wall_ms;
    let (g, k) = rig.log.grant(
        "dev-phone",
        "aaaaaaaa-1111-4111-8111-000000000001",
        HOST,
        1,
        None,
        &["view"],
        wall,
        wall + 50 * 60_000,
    );
    rig.advance(1000);
    rig.connect("ch-browser", Identity::browser(g, k).unwrap());
    get(&mut rig, "ch-browser", true);
    assert_eq!(
        errors(&mut rig, "ch-browser"),
        vec![("forbidden".into(), None)]
    );
}

/// `manage` is checked at handling time, on retries too: a member demoted
/// by a carried `set_roles` can't replay its earlier request.
#[test]
fn a_demoted_managers_retry_is_forbidden() {
    let mut rig = rig();
    let roles = rig
        .log
        .set_native_roles("dev-phone", &["control", "manage", "view"]);
    let entry = atem_client::SignedObject::parse(roles.to_string().as_bytes()).unwrap();
    let mono = rig.now.host.mono_ms;
    let (_, frame) = rig
        .attached("ch-mac")
        .send_membership(&[entry], mono)
        .unwrap();
    rig.send_frame("ch-mac", &frame);
    // The phone's roles changed: fenced, re-admitted under the new ones.
    rig.advance(1000);
    rig.connect("ch-phone-2", phone());
    set(&mut rig, "ch-phone-2", true, R1);
    assert_eq!(
        results(&mut rig, "ch-phone-2")[0].0.outcome,
        Outcome::Committed
    );
    let demote = rig.log.set_native_roles("dev-phone", &["control", "view"]);
    let entry = atem_client::SignedObject::parse(demote.to_string().as_bytes()).unwrap();
    let mono = rig.now.host.mono_ms;
    let (_, frame) = rig
        .attached("ch-mac")
        .send_membership(&[entry], mono)
        .unwrap();
    rig.send_frame("ch-mac", &frame);
    rig.advance(1000);
    rig.connect("ch-phone-3", phone());
    retry(&mut rig, "ch-phone-3", true, R1, 0);
    assert_eq!(
        errors(&mut rig, "ch-phone-3"),
        vec![("forbidden".into(), None)]
    );
}

/// Astation's counterexample over the wire: A=true, B=false, retry A →
/// `superseded` with the current (false) state; never re-applied.
#[test]
fn a_superseded_retry_reports_the_current_policy() {
    let mut rig = rig();
    set(&mut rig, "ch-mac", true, R1);
    results(&mut rig, "ch-mac");
    set(&mut rig, "ch-mac", false, R2);
    let got = results(&mut rig, "ch-mac");
    assert_eq!(got[0].0.outcome, Outcome::Committed);
    assert_eq!(got[0].1, Observed::Ready);
    retry(&mut rig, "ch-mac", true, R1, 0);
    let got = results(&mut rig, "ch-mac");
    assert_eq!(got[0].0.outcome, Outcome::Superseded);
    assert!(!got[0].0.policy.relay_only);
    assert_eq!(got[0].0.policy.revision, 2);
    assert_eq!(got[0].1, Observed::NotReady, "wanted true, it is false");
    assert!(host_policy::local_allowed(&rig.pairing));
    assert_eq!(rig.engine.take_policy_changes(), vec![true, false]);
}

#[test]
fn malformed_and_reused_requests_are_refused() {
    let mut rig = rig();
    rig.send(
        "ch-mac",
        &json!({"type": "session", "data": {"v": 1, "op": "host_policy_set",
            "id": "aaaaaaaa-0000-4000-8000-0000000000f1", "request_id": R1,
            "relay_only": "yes", "expected_revision": 0}}),
    );
    assert_eq!(
        errors(&mut rig, "ch-mac"),
        vec![("invalid_request".into(), None)]
    );
    set(&mut rig, "ch-mac", true, R1);
    results(&mut rig, "ch-mac");
    retry(&mut rig, "ch-mac", false, R1, 0);
    assert_eq!(
        errors(&mut rig, "ch-mac"),
        vec![("request_id_reused".into(), None)]
    );
}

/// While the local link waits to close for relay only, new channels are
/// refused with `close{closed}`.
#[test]
fn new_channels_are_refused_while_the_local_link_closes() {
    let mut rig = rig();
    rig.local_closing = true;
    rig.advance(1000);
    rig.connect("ch-new", mac());
    assert!(
        rig.closes
            .iter()
            .any(|(h, r)| h == "ch-new" && r.as_deref() == Some("closed")),
        "{:?}",
        rig.closes
    );
    rig.local_closing = false;
    rig.advance(1000);
    rig.connect("ch-new-2", mac());
    rig.attached("ch-new-2");
}

/// An unreadable stored policy answers `busy` and allows no local link.
#[test]
fn an_unreadable_policy_is_busy_and_fails_closed() {
    let mut rig = rig();
    std::fs::write(&rig.pairing.host_policy, b"{").unwrap();
    get(&mut rig, "ch-mac", true);
    assert_eq!(
        errors(&mut rig, "ch-mac"),
        vec![("busy".into(), Some(host_policy::DETAIL_UNREADABLE.into()))]
    );
    assert!(!host_policy::local_allowed(&rig.pairing));
}

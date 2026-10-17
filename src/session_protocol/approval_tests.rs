//! Approvals (contract r7): the wire shapes and bounds of `approval_request`,
//! `approval_closed` and the `approval` submission, the host's pending
//! approvals (open/close, hand-off, the agent's report, lease loss, process
//! end, restart) and the registry client's catch-up. The shared fixtures
//! cover the main scenarios; these cover the edges.

use super::client::{RegistryClient, RegistryOutcome};
use super::fake_runtime::FakeRuntime;
use super::host::*;
use super::journal::{MemJournal, Record};
use super::wire::{
    self, AlwaysRule, ApprovalCloseReason, ApprovalDecision, ErrorCode, Op, ReceiptKind,
    ReceiptState, Target,
};
use serde_json::{Value, json};

const S1: &str = "ses-aaaaaaaaaaaa";
const P1: &str = "22222222-2222-4222-8222-222222222222";
const P1B: &str = "22222222-2222-4222-8222-cccccccccccc";
const C1: &str = "33333333-3333-4333-8333-333333333333";
const C1B: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const V: &str = "77777777-7777-4777-8777-777777777777";
const R: &str = "99999999-9999-4999-8999-999999999999";
const AID: &str = "88888888-8888-4888-8888-888888888888";

fn setup() -> FakeRuntime {
    let client = |name: &str, g: &str, perms: Value| json!({"name": name, "attachment_gen": g, "permissions": perms, "client_kind": "native"});
    FakeRuntime::from_json(
        json!({
            "host": {"account_id": "account-a", "atem_device_id": "host-a", "host_trust_gen": 1,
                     "runtime_gen": "55555555-5555-4555-8555-555555555555", "runtime_epoch": 7},
            "sessions": [{"session_id": S1, "process_gen": P1, "chat": true}],
            "clients": [client("c1", C1, json!(["view", "control"])),
                        client("v", V, json!(["view", "control"])),
                        client("r", R, json!(["view"]))]
        }),
        HostConfig::default(),
    )
}

fn msg(op: &str, fields: Value) -> Value {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut data = json!({"v": 1, "op": op, "id": format!("11111111-1111-4111-8111-{n:012}")});
    data.as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    json!({"type": "session", "data": data})
}

fn target(pg: &str) -> Value {
    json!({"account_id": "account-a", "atem_device_id": "host-a", "host_trust_gen": 1,
           "session_id": S1, "process_gen": pg})
}

fn binding(rt: &FakeRuntime, client: &str, epoch: Option<u64>) -> Value {
    let mut b = json!({"target": target(P1), "attachment_gen": rt.attachment(client)});
    if let Some(e) = epoch {
        b["lease_epoch"] = json!(e);
    }
    b
}

fn rid(n: u64) -> String {
    format!("44444444-4444-4444-8444-{n:012}")
}

/// An answer that takes the lease with it (`acquire: true`, no lease epoch).
fn answer_acquiring(rt: &FakeRuntime, client: &str, n: u64, mut payload: Value) -> Value {
    payload["acquire"] = json!(true);
    msg(
        "submit",
        json!({"binding": binding(rt, client, None), "request_id": rid(n),
               "kind": "approval", "payload": payload}),
    )
}

fn pushes(rt: &FakeRuntime) -> Vec<Effect> {
    rt.effects
        .iter()
        .filter(|e| matches!(e, Effect::PushApproval { .. } | Effect::PushResolved { .. }))
        .cloned()
        .collect()
}

fn answer(rt: &FakeRuntime, client: &str, epoch: u64, n: u64, payload: Value) -> Value {
    msg(
        "submit",
        json!({"binding": binding(rt, client, Some(epoch)), "request_id": rid(n),
               "kind": "approval", "payload": payload}),
    )
}

fn got(rt: &mut FakeRuntime, client: &str) -> Vec<Value> {
    rt.take(client)
        .into_iter()
        .map(|m| m["data"].clone())
        .collect()
}

fn ops(msgs: &[Value]) -> Vec<String> {
    msgs.iter()
        .map(|m| m["op"].as_str().unwrap_or("?").to_string())
        .collect()
}

/// `client` lists (subscribes) and holds `S1`'s lease; returns the epoch.
fn list_and_hold(rt: &mut FakeRuntime, client: &str) -> u64 {
    rt.send(client, &msg("list", json!({})));
    let m = msg(
        "acquire",
        json!({"binding": binding(rt, client, None), "takeover": false}),
    );
    rt.send(client, &m);
    let lease = got(rt, client)
        .into_iter()
        .find(|m| m["op"] == "lease")
        .expect("lease");
    lease["binding"]["lease_epoch"].as_u64().unwrap()
}

fn rule(id: &str) -> AlwaysRule {
    AlwaysRule {
        rule_id: id.into(),
        label: format!("Allow {id}"),
        scope: "this project".into(),
    }
}

fn info(rules: Vec<AlwaysRule>) -> ApprovalInfo {
    ApprovalInfo {
        tool: "Bash".into(),
        summary: "npm test".into(),
        always_rules: rules,
    }
}

fn open(rt: &mut FakeRuntime, rules: Vec<AlwaysRule>) -> String {
    let now = rt.now();
    let (id, fx) = rt.host.open_approval(S1, P1, info(rules), now);
    rt.apply(fx);
    id.expect("open")
}

/// `open_approval` at the runtime's clock is refused.
fn refused(rt: &mut FakeRuntime, sid: &str, pg: &str, info: ApprovalInfo) -> bool {
    let now = rt.now();
    let (r, fx) = rt.host.open_approval(sid, pg, info, now);
    rt.apply(fx);
    r.is_err()
}

fn approval_effects(rt: &FakeRuntime) -> Vec<Effect> {
    rt.effects
        .iter()
        .filter(|e| matches!(e, Effect::Approval { .. }))
        .cloned()
        .collect()
}

fn released(rt: &FakeRuntime) -> Vec<String> {
    rt.effects
        .iter()
        .filter_map(|e| match e {
            Effect::ApprovalReleased { approval_id, .. } => Some(approval_id.clone()),
            _ => None,
        })
        .collect()
}

// ── wire ──

fn decodes(v: &Value) -> bool {
    wire::decode(&serde_json::to_vec(v).unwrap()).is_ok()
}

fn submit_payload(payload: Value) -> Value {
    msg(
        "submit",
        json!({"binding": {"target": target(P1), "attachment_gen": C1, "lease_epoch": 1},
               "request_id": rid(1), "kind": "approval", "payload": payload}),
    )
}

#[test]
fn approval_payloads_decode_strictly() {
    for ok in [
        json!({"approval_id": AID, "decision": "allow_once"}),
        json!({"approval_id": AID, "decision": "allow_always", "rule_id": "r-1"}),
        json!({"approval_id": AID, "decision": "deny"}),
        json!({"approval_id": AID, "decision": "deny", "message": "not now\nuse the staging db"}),
        json!({"approval_id": AID, "decision": "deny", "message": "é".repeat(256)}),
        json!({"approval_id": AID, "decision": "allow_once", "acquire": false}),
    ] {
        assert!(decodes(&submit_payload(ok.clone())), "{ok}");
    }
    // `acquire: true` takes the lease: its binding carries no lease epoch
    // (and one without acquire must).
    let acquiring = json!({"approval_id": AID, "decision": "allow_once", "acquire": true});
    assert!(!decodes(&submit_payload(acquiring.clone())));
    let mut m = submit_payload(acquiring.clone());
    m["data"]["binding"]
        .as_object_mut()
        .unwrap()
        .remove("lease_epoch");
    assert!(decodes(&m));
    let mut m = submit_payload(json!({"approval_id": AID, "decision": "allow_once"}));
    m["data"]["binding"]
        .as_object_mut()
        .unwrap()
        .remove("lease_epoch");
    assert!(!decodes(&m));
    assert!(!decodes(&submit_payload(
        json!({"approval_id": AID, "decision": "deny", "acquire": "yes"})
    )));
    // chat-v1: `approval` instead of `text`, under the same rule.
    let chat = |approval: Value, lease: Option<u64>| {
        let mut b = json!({"target": target(P1), "attachment_gen": C1});
        if let Some(e) = lease {
            b["lease_epoch"] = json!(e);
        }
        json!({"type": "agentChat", "data": {"v": 1, "op": "submit", "conversationId": "c1",
               "agentId": S1, "generation": P1, "requestId": rid(2), "approval": approval,
               "binding": b}})
    };
    assert!(decodes(&chat(acquiring.clone(), None)));
    assert!(!decodes(&chat(acquiring, Some(1))));
    let plain = json!({"approval_id": AID, "decision": "deny"});
    assert!(decodes(&chat(plain.clone(), Some(1))));
    assert!(!decodes(&chat(plain, None)));
    assert!(!decodes(&chat(json!({"approval_id": AID}), Some(1))));
    for bad in [
        json!({}),
        json!({"approval_id": AID}),
        json!({"approval_id": "not-a-uuid", "decision": "deny"}),
        json!({"approval_id": AID, "decision": "allow"}),
        // rule_id only (and always) with allow_always
        json!({"approval_id": AID, "decision": "allow_always"}),
        json!({"approval_id": AID, "decision": "allow_once", "rule_id": "r-1"}),
        json!({"approval_id": AID, "decision": "deny", "rule_id": "r-1"}),
        json!({"approval_id": AID, "decision": "allow_always", "rule_id": "bad rule"}),
        json!({"approval_id": AID, "decision": "allow_always", "rule_id": null}),
        // message only with deny, bounded, no control characters but newline
        json!({"approval_id": AID, "decision": "allow_once", "message": "x"}),
        json!({"approval_id": AID, "decision": "deny", "message": "a".repeat(513)}),
        json!({"approval_id": AID, "decision": "deny", "message": "a\u{1b}[2J"}),
        json!({"approval_id": AID, "decision": "deny", "message": null}),
        // unknown fields are refused inside a payload
        json!({"approval_id": AID, "decision": "deny", "extra": 1}),
        json!("deny"),
    ] {
        let err = wire::decode(&serde_json::to_vec(&submit_payload(bad.clone())).unwrap());
        assert_eq!(
            err.map(|_| ()).unwrap_err().code,
            ErrorCode::UnsupportedVersion,
            "{bad}"
        );
    }
}

fn request(fields: Value) -> Value {
    let mut base = json!({"approval_id": AID, "session_id": S1, "process_gen": P1,
        "tool": "Bash", "summary": "npm test", "created_at": 1_760_000_000_000u64,
        "always_rules": [{"rule_id": "r-1", "label": "Bash(npm test:*)", "scope": "this project"}]});
    base.as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    msg("approval_request", base)
}

#[test]
fn approval_request_and_closed_are_bounded() {
    assert!(decodes(&request(json!({}))));
    assert!(decodes(&request(json!({"always_rules": []}))));
    assert!(decodes(&request(json!({"summary": ""}))));
    assert!(decodes(&request(json!({"summary": "a".repeat(512)}))));
    let rules = |n: usize| {
        (0..n)
            .map(|i| json!({"rule_id": format!("r-{i}"), "label": "l", "scope": "s"}))
            .collect::<Vec<_>>()
    };
    assert!(decodes(&request(json!({"always_rules": rules(8)}))));
    for bad in [
        json!({"approval_id": "x"}),
        json!({"session_id": "ses-x"}),
        json!({"process_gen": "x"}),
        json!({"tool": ""}),
        json!({"tool": "a".repeat(129)}),
        json!({"summary": "a".repeat(513)}),
        json!({"summary": "line one\nline two"}),
        json!({"summary": "\u{9b}31m"}),
        json!({"created_at": 9_007_199_254_740_992u64}),
        json!({"always_rules": rules(9)}),
        json!({"always_rules": [{"rule_id": "r", "label": "", "scope": "s"}]}),
        json!({"always_rules": [{"rule_id": "r", "label": "l", "scope": ""}]}),
        json!({"always_rules": [{"rule_id": "r", "label": "a".repeat(257), "scope": "s"}]}),
        json!({"always_rules": [{"rule_id": "r", "label": "l", "scope": "a".repeat(257)}]}),
        json!({"always_rules": [{"rule_id": "r", "label": "l"}]}),
        json!({"always_rules": [{"rule_id": "r", "label": "l", "scope": "s"},
                                {"rule_id": "r", "label": "m", "scope": "t"}]}),
    ] {
        assert!(!decodes(&request(bad.clone())), "{bad}");
    }
    for reason in [
        "answered_remote",
        "answered_terminal",
        "interrupted",
        "timed_out",
        "released",
        "process_ended",
    ] {
        let m = msg(
            "approval_closed",
            json!({"approval_id": AID, "reason": reason}),
        );
        assert!(decodes(&m), "{reason}");
    }
    assert!(!decodes(&msg(
        "approval_closed",
        json!({"approval_id": AID, "reason": "answered"})
    )));
    assert!(!decodes(&msg(
        "approval_closed",
        json!({"approval_id": "x", "reason": "timed_out"})
    )));
}

#[test]
fn approval_ops_are_not_requests() {
    let mut rt = setup();
    rt.send("c1", &request(json!({})));
    let err = got(&mut rt, "c1");
    assert_eq!(err[0]["code"], "unsupported_version");
}

// ── host: opening ──

#[test]
fn an_approval_opens_whoever_holds_the_lease() {
    let mut rt = setup();
    // No lease holder, nobody subscribed: it opens, and the relay is asked
    // to push it.
    let id = open(&mut rt, vec![]);
    assert_eq!(rt.host.pending_approvals(S1), std::slice::from_ref(&id));
    match &pushes(&rt)[..] {
        [Effect::PushApproval { request }] => {
            assert_eq!(request.approval_id, id);
            assert_eq!(request.session_id, S1);
            assert_eq!(request.summary, "npm test");
        }
        other => panic!("{other:?}"),
    }
    let e = list_and_hold(&mut rt, "c1");
    assert_eq!(e, 1);
    assert!(refused(&mut rt, S1, P1B, info(vec![])));
    assert!(refused(&mut rt, "ses-bbbbbbbbbbbb", P1, info(vec![])));
    let mut long = info(vec![]);
    long.summary = "a".repeat(513);
    assert!(refused(&mut rt, S1, P1, long));
    let mut dup = info(vec![rule("r"), rule("r")]);
    assert!(refused(&mut rt, S1, P1, dup.clone()));
    dup.always_rules = (0..9).map(|i| rule(&format!("r{i}"))).collect();
    assert!(refused(&mut rt, S1, P1, dup));
    // The lease expiring changes nothing about it.
    rt.set_now(LEASE_MS);
    assert!(got(&mut rt, "c1").iter().any(|m| m["reason"] == "expired"));
    assert_eq!(rt.host.pending_approvals(S1), std::slice::from_ref(&id));
    assert!(released(&rt).is_empty());
    // Pending approvals per session are bounded.
    let mut rt = setup();
    for _ in 0..MAX_PENDING_APPROVALS {
        open(&mut rt, vec![]);
    }
    assert!(refused(&mut rt, S1, P1, info(vec![])));
}

#[test]
fn a_view_only_attachment_never_sees_approvals() {
    let mut rt = setup();
    rt.send("r", &msg("list", json!({})));
    got(&mut rt, "r");
    let id = open(&mut rt, vec![]);
    assert!(got(&mut rt, "r").is_empty());
    rt.send("r", &msg("list", json!({})));
    assert_eq!(ops(&got(&mut rt, "r")), ["sessions"]);
    let fx = rt.host.close_approval(&id, ApprovalCloseReason::TimedOut);
    rt.apply(fx);
    assert!(got(&mut rt, "r").is_empty());
    // Nor can it answer one, with or without acquire.
    let id = open(&mut rt, vec![]);
    let m = answer_acquiring(
        &rt,
        "r",
        1,
        json!({"approval_id": id, "decision": "allow_once"}),
    );
    rt.send("r", &m);
    assert_eq!(got(&mut rt, "r")[0]["code"], "forbidden");
    assert!(rt.host.lease_holder(S1).is_none());
    assert!(approval_effects(&rt).is_empty());
}

#[test]
fn an_answer_with_acquire_takes_the_lease_and_applies_atomically() {
    // From a controller while another attachment holds the lease: takeover.
    let mut rt = setup();
    let e = list_and_hold(&mut rt, "c1");
    rt.send("v", &msg("list", json!({})));
    let id = open(&mut rt, vec![]);
    got(&mut rt, "c1");
    got(&mut rt, "v");
    // Without acquire and without the lease: stale_lease, nothing taken.
    let plain = answer(
        &rt,
        "v",
        e,
        1,
        json!({"approval_id": id, "decision": "allow_once"}),
    );
    rt.send("v", &plain);
    assert_eq!(got(&mut rt, "v")[0]["code"], "stale_lease");
    assert_eq!(rt.host.lease_holder(S1), Some(rt.attachment("c1").as_str()));
    // A stale answer with acquire takes nothing either.
    let stale = answer_acquiring(
        &rt,
        "v",
        2,
        json!({"approval_id": AID, "decision": "allow_once"}),
    );
    rt.send("v", &stale);
    assert_eq!(got(&mut rt, "v")[0]["code"], "stale_target");
    assert_eq!(rt.host.lease_holder(S1), Some(rt.attachment("c1").as_str()));
    let m = answer_acquiring(
        &rt,
        "v",
        3,
        json!({"approval_id": id, "decision": "allow_once"}),
    );
    rt.send("v", &m);
    let v = got(&mut rt, "v");
    assert_eq!(
        ops(&v),
        [
            "lease_changed",
            "session_changed",
            "receipt",
            "receipt",
            "approval_closed"
        ]
    );
    assert_eq!(v[0]["reason"], "takeover");
    assert_eq!(v[0]["lease_epoch"], e + 1);
    assert_eq!(v[2]["state"], "accepted");
    assert_eq!(v[3]["state"], "executing");
    assert_eq!(rt.host.lease_holder(S1), Some(rt.attachment("v").as_str()));
    let c1 = got(&mut rt, "c1");
    assert_eq!(
        ops(&c1),
        ["lease_changed", "session_changed", "approval_closed"]
    );
    assert_eq!(approval_effects(&rt).len(), 1);
    // The duplicate returns the receipt and takes nothing again.
    rt.send("v", &m);
    assert_eq!(ops(&got(&mut rt, "v")), ["receipt"]);
    // With no holder at all: granted.
    let mut rt = setup();
    rt.send("v", &msg("list", json!({})));
    let id = open(&mut rt, vec![]);
    got(&mut rt, "v");
    let m = answer_acquiring(
        &rt,
        "v",
        4,
        json!({"approval_id": id, "decision": "deny", "message": "no"}),
    );
    rt.send("v", &m);
    let v = got(&mut rt, "v");
    assert_eq!(v[0]["op"], "lease_changed");
    assert_eq!(v[0]["reason"], "granted");
    assert_eq!(rt.host.lease_holder(S1), Some(rt.attachment("v").as_str()));
    // The holder answering with acquire keeps its lease (no new epoch).
    let mut rt = setup();
    let e = list_and_hold(&mut rt, "c1");
    let id = open(&mut rt, vec![]);
    got(&mut rt, "c1");
    let m = answer_acquiring(
        &rt,
        "c1",
        5,
        json!({"approval_id": id, "decision": "allow_once"}),
    );
    rt.send("c1", &m);
    assert_eq!(
        ops(&got(&mut rt, "c1")),
        ["receipt", "receipt", "approval_closed"]
    );
    assert_eq!(rt.host.lease_epoch(S1), Some(e));
}

#[test]
fn every_close_resolves_the_push() {
    let mut rt = setup();
    let e = list_and_hold(&mut rt, "c1");
    let a = open(&mut rt, vec![]);
    let b = open(&mut rt, vec![]);
    let c = open(&mut rt, vec![]);
    let fx = rt
        .host
        .close_approval(&a, ApprovalCloseReason::AnsweredTerminal);
    rt.apply(fx);
    rt.send(
        "c1",
        &answer(
            &rt,
            "c1",
            e,
            1,
            json!({"approval_id": b, "decision": "allow_once"}),
        ),
    );
    let fx = rt.host.process_exited(S1, None);
    rt.apply(fx);
    let resolved: Vec<(String, ApprovalCloseReason)> = pushes(&rt)
        .into_iter()
        .filter_map(|e| match e {
            Effect::PushResolved {
                approval_id,
                reason,
            } => Some((approval_id, reason)),
            _ => None,
        })
        .collect();
    assert_eq!(
        resolved,
        [
            (a, ApprovalCloseReason::AnsweredTerminal),
            (b, ApprovalCloseReason::AnsweredRemote),
            (c, ApprovalCloseReason::ProcessEnded),
        ]
    );
}

#[test]
fn approval_requests_go_to_subscribed_viewers_and_again_after_list() {
    let mut rt = setup();
    list_and_hold(&mut rt, "c1");
    got(&mut rt, "c1");
    got(&mut rt, "v");
    rt.set_now(2500);
    let id = open(&mut rt, vec![rule("r-1")]);
    assert!(wire::is_uuid_v4(&id));
    let req = got(&mut rt, "c1");
    assert_eq!(ops(&req), ["approval_request"]);
    assert_eq!(req[0]["approval_id"], id.as_str());
    assert_eq!(req[0]["session_id"], S1);
    assert_eq!(req[0]["process_gen"], P1);
    assert_eq!(req[0]["tool"], "Bash");
    assert_eq!(req[0]["summary"], "npm test");
    assert_eq!(req[0]["created_at"], 2500);
    assert_eq!(
        req[0]["always_rules"],
        json!([{"rule_id": "r-1", "label": "Allow r-1", "scope": "this project"}])
    );
    // The viewer hasn't listed: nothing yet; its list catches up.
    assert!(got(&mut rt, "v").is_empty());
    rt.send("v", &msg("list", json!({})));
    let caught = got(&mut rt, "v");
    assert_eq!(ops(&caught), ["sessions", "approval_request"]);
    assert_eq!(caught[1]["approval_id"], id.as_str());
    // Now subscribed, it hears the close.
    let fx = rt.host.close_approval(&id, ApprovalCloseReason::TimedOut);
    rt.apply(fx);
    for c in ["c1", "v"] {
        let closed = got(&mut rt, c);
        assert_eq!(ops(&closed), ["approval_closed"], "{c}");
        assert_eq!(closed[0]["reason"], "timed_out");
    }
    // The runtime closed it itself: no release effect.
    assert!(released(&rt).is_empty());
    assert!(rt.host.pending_approvals(S1).is_empty());
}

// ── host: answers ──

#[test]
fn a_remote_answer_is_handed_to_the_agent_and_completes_on_its_report() {
    let mut rt = setup();
    let e = list_and_hold(&mut rt, "c1");
    rt.send("v", &msg("list", json!({})));
    let id = open(&mut rt, vec![rule("r-1"), rule("r-2")]);
    got(&mut rt, "c1");
    got(&mut rt, "v");
    let m = answer(
        &rt,
        "c1",
        e,
        1,
        json!({"approval_id": id, "decision": "allow_always", "rule_id": "r-2"}),
    );
    rt.send("c1", &m);
    let c1 = got(&mut rt, "c1");
    assert_eq!(ops(&c1), ["receipt", "receipt", "approval_closed"]);
    assert_eq!(c1[0]["state"], "accepted");
    assert_eq!(c1[0]["kind"], "approval");
    assert_eq!(c1[1]["state"], "executing");
    assert_eq!(c1[2]["reason"], "answered_remote");
    assert_eq!(got(&mut rt, "v")[0]["reason"], "answered_remote");
    assert_eq!(
        approval_effects(&rt),
        [Effect::Approval {
            request_id: rid(1),
            session_id: S1.into(),
            approval_id: id.clone(),
            decision: ApprovalDecision::AllowAlways,
            rule_id: Some("r-2".into()),
            message: None,
        }]
    );
    // A second answer (another request id) is stale: the approval closed.
    let again = answer(
        &rt,
        "c1",
        e,
        2,
        json!({"approval_id": id, "decision": "deny"}),
    );
    rt.send("c1", &again);
    assert_eq!(got(&mut rt, "c1")[0]["code"], "stale_target");
    assert!(rt.host.receipt(&rid(2)).is_none());
    // Lease loss after the hand-off doesn't change the handed-off answer.
    rt.set_now(LEASE_MS);
    let after = got(&mut rt, "c1");
    assert!(!ops(&after).contains(&"approval_closed".to_string()));
    let fx = rt.host.approval_applied(&id, true);
    rt.apply(fx);
    let done = got(&mut rt, "c1");
    assert_eq!(ops(&done), ["receipt"]);
    assert_eq!(done[0]["state"], "completed");
    // A late report changes nothing.
    let fx = rt.host.approval_applied(&id, false);
    rt.apply(fx);
    let fx = rt
        .host
        .close_approval(&id, ApprovalCloseReason::AnsweredTerminal);
    rt.apply(fx);
    assert!(got(&mut rt, "c1").is_empty());
    assert_eq!(
        rt.host.receipt(&rid(1)).unwrap().state,
        ReceiptState::Completed
    );
}

#[test]
fn crossed_or_unconfirmed_answers_are_outcome_unknown() {
    for how in [
        "not_applied",
        "terminal",
        "interrupted",
        "exit",
        "dispatch_failed",
    ] {
        let mut rt = setup();
        let e = list_and_hold(&mut rt, "c1");
        let id = open(&mut rt, vec![]);
        let m = answer(
            &rt,
            "c1",
            e,
            1,
            json!({"approval_id": id, "decision": "deny", "message": "no"}),
        );
        rt.send("c1", &m);
        got(&mut rt, "c1");
        let fx = match how {
            "not_applied" => rt.host.approval_applied(&id, false),
            "terminal" => rt
                .host
                .close_approval(&id, ApprovalCloseReason::AnsweredTerminal),
            "interrupted" => rt
                .host
                .close_approval(&id, ApprovalCloseReason::Interrupted),
            "exit" => rt.host.process_exited(S1, Some("0".into())),
            _ => rt
                .host
                .dispatch_report(&rid(1), DispatchReport::FailedNoEffect),
        };
        rt.apply(fx);
        let r = rt.host.receipt(&rid(1)).unwrap();
        let (state, detail) = match how {
            "not_applied" | "terminal" => (ReceiptState::OutcomeUnknown, DETAIL_APPROVAL_CROSSED),
            "interrupted" => (ReceiptState::OutcomeUnknown, DETAIL_APPROVAL_UNCONFIRMED),
            "exit" => (ReceiptState::OutcomeUnknown, DETAIL_AGENT_EXITED),
            _ => (ReceiptState::Rejected, DETAIL_DECISION_NOT_DELIVERED),
        };
        assert_eq!(
            (r.state, r.detail.as_deref()),
            (state, Some(detail)),
            "{how}"
        );
        // The answer was already closed for viewers: no second close.
        let rest = got(&mut rt, "c1");
        assert!(
            !ops(&rest).contains(&"approval_closed".to_string()),
            "{how}: {rest:?}"
        );
        assert!(rt.host.pending_approvals(S1).is_empty(), "{how}");
    }
}

#[test]
fn an_answer_must_name_this_sessions_pending_approval_and_an_offered_rule() {
    let mut rt = setup();
    let e = list_and_hold(&mut rt, "c1");
    let id = open(&mut rt, vec![rule("r-1")]);
    got(&mut rt, "c1");
    let cases = [
        json!({"approval_id": AID, "decision": "allow_once"}),
        json!({"approval_id": id, "decision": "allow_always", "rule_id": "r-9"}),
    ];
    for (n, payload) in cases.into_iter().enumerate() {
        let m = answer(&rt, "c1", e, 10 + n as u64, payload.clone());
        rt.send("c1", &m);
        let err = got(&mut rt, "c1");
        assert_eq!(err[0]["code"], "stale_target", "{payload}");
        assert!(err[0].get("detail").is_none(), "{payload}");
    }
    // Another process of the session: stale too (the binding check).
    let mut m = answer(
        &rt,
        "c1",
        e,
        12,
        json!({"approval_id": id, "decision": "allow_once"}),
    );
    m["data"]["binding"]["target"]["process_gen"] = json!(P1B);
    rt.send("c1", &m);
    assert_eq!(got(&mut rt, "c1")[0]["code"], "stale_target");
    // Nothing was recorded or handed off; it is still pending.
    assert!(approval_effects(&rt).is_empty());
    assert_eq!(rt.host.pending_approvals(S1), [id]);
    for n in 10..=12 {
        assert!(rt.host.receipt(&rid(n)).is_none());
    }
}

// ── host: closing ──

#[test]
fn losing_the_lease_keeps_pending_approvals() {
    for how in ["expired", "local_input", "released", "trust"] {
        let mut rt = setup();
        let e = list_and_hold(&mut rt, "c1");
        rt.send("v", &msg("list", json!({})));
        let id = open(&mut rt, vec![]);
        got(&mut rt, "c1");
        got(&mut rt, "v");
        let fx = match how {
            "expired" => rt.host.advance(LEASE_MS),
            "local_input" => rt.host.local_input(S1, b"y".to_vec()),
            "released" => {
                let m = msg("release", json!({"binding": binding(&rt, "c1", Some(e))}));
                rt.send("c1", &m);
                Vec::new()
            }
            _ => rt.host.change_trust_gen(2).unwrap(),
        };
        rt.apply(fx);
        let closed = got(&mut rt, "v")
            .into_iter()
            .filter(|m| m["op"] == "approval_closed")
            .count();
        assert_eq!(closed, 0, "{how}");
        assert!(released(&rt).is_empty(), "{how}");
        assert_eq!(rt.host.pending_approvals(S1), [id], "{how}");
    }
}

#[test]
fn the_process_ending_closes_pending_approvals() {
    for how in ["exit", "replace", "close", "remove", "lost"] {
        let mut rt = setup();
        list_and_hold(&mut rt, "c1");
        rt.send("v", &msg("list", json!({})));
        let id = open(&mut rt, vec![]);
        got(&mut rt, "v");
        let fx = match how {
            "exit" => rt.host.process_exited(S1, None),
            "replace" => rt.host.replace_process(S1, P1B).unwrap(),
            "close" => rt.host.close_session(S1, false),
            "remove" => rt.host.remove_session(S1),
            _ => rt
                .host
                .process_lost(S1, wire::SessionState::Interrupted, None),
        };
        rt.apply(fx);
        let closed: Vec<Value> = got(&mut rt, "v")
            .into_iter()
            .filter(|m| m["op"] == "approval_closed")
            .collect();
        assert_eq!(closed.len(), 1, "{how}");
        assert_eq!(closed[0]["reason"], "process_ended", "{how}");
        assert_eq!(released(&rt), std::slice::from_ref(&id), "{how}");
        assert!(rt.host.pending_approvals(S1).is_empty(), "{how}");
    }
}

#[test]
fn the_runtime_can_not_close_an_approval_as_answered_remotely() {
    let mut rt = setup();
    list_and_hold(&mut rt, "c1");
    let id = open(&mut rt, vec![]);
    got(&mut rt, "c1");
    let fx = rt
        .host
        .close_approval(&id, ApprovalCloseReason::AnsweredRemote);
    rt.apply(fx);
    assert!(got(&mut rt, "c1").is_empty());
    assert_eq!(rt.host.pending_approvals(S1), std::slice::from_ref(&id));
    // Unknown ids are ignored.
    let fx = rt.host.close_approval(AID, ApprovalCloseReason::TimedOut);
    rt.apply(fx);
    let fx = rt.host.approval_applied(AID, true);
    rt.apply(fx);
    assert!(got(&mut rt, "c1").is_empty());
}

#[test]
fn a_restart_releases_pending_approvals_and_rejects_unstarted_answers() {
    let mut rt = setup();
    list_and_hold(&mut rt, "c1");
    let id = open(&mut rt, vec![]);
    let fx = rt
        .host
        .restart("99999999-9999-4999-8999-999999999999", 8)
        .unwrap();
    rt.apply(fx);
    assert_eq!(released(&rt), [id]);
    assert!(rt.host.pending_approvals(S1).is_empty());

    // An approval answer recorded as accepted but never started (a crash
    // between the two writes): after a restart its approval is gone, so it
    // is rejected, never handed to the agent.
    let mut journal = MemJournal::default();
    let t = Target {
        account_id: "account-a".into(),
        atem_device_id: "host-a".into(),
        host_trust_gen: 1,
        session_id: S1.into(),
        process_gen: P1.into(),
    };
    let payload = json!({"approval_id": AID, "decision": "allow_once"});
    use super::journal::Journal;
    journal
        .append(Record::Accepted {
            request_id: rid(1),
            target: t,
            kind: ReceiptKind::Approval,
            payload_digest: super::canonical::payload_digest(&payload).unwrap(),
            payload,
            updated_at: 1,
        })
        .unwrap();
    let ctx = HostContext {
        account_id: "account-a".into(),
        atem_device_id: "host-a".into(),
        host_trust_gen: 1,
        runtime_gen: "55555555-5555-4555-8555-555555555555".into(),
        runtime_epoch: 7,
    };
    let mut host = SessionHost::new(ctx, HostConfig::default(), journal, random_ids()).unwrap();
    host.restore_session(SessionSpec {
        session_id: S1.into(),
        process_gen: P1.into(),
        provider: "claude".into(),
        cwd_label: "Atem".into(),
        chat: true,
        rows: 24,
        cols: 80,
    })
    .unwrap();
    let fx = host.recover();
    assert!(!fx.iter().any(|e| matches!(e, Effect::Approval { .. })));
    let r = host.receipt(&rid(1)).unwrap();
    assert_eq!(r.state, ReceiptState::Rejected);
    assert_eq!(r.detail.as_deref(), Some(DETAIL_APPROVAL_CLOSED));
}

#[test]
fn approval_receipts_survive_in_the_file_journal() {
    use super::file_journal::FileJournal;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state");
    let journal = FileJournal::open(&path).unwrap();
    let setup = json!({
        "host": {"account_id": "account-a", "atem_device_id": "host-a", "host_trust_gen": 1,
                 "runtime_gen": "55555555-5555-4555-8555-555555555555", "runtime_epoch": 7},
        "sessions": [{"session_id": S1, "process_gen": P1}],
        "clients": [{"name": "c1", "attachment_gen": C1, "permissions": ["view", "control"],
                     "client_kind": "native"}]
    });
    let mut rt = FakeRuntime::from_json_with(setup, HostConfig::default(), journal);
    rt.send("c1", &msg("list", json!({})));
    let m = msg(
        "acquire",
        json!({"binding": {"target": target(P1), "attachment_gen": C1}, "takeover": false}),
    );
    rt.send("c1", &m);
    let (id, fx) = rt.host.open_approval(S1, P1, info(vec![]), 0);
    rt.apply(fx);
    let id = id.unwrap();
    let m = msg(
        "submit",
        json!({"binding": {"target": target(P1), "attachment_gen": C1, "lease_epoch": 1},
               "request_id": rid(1), "kind": "approval",
               "payload": {"approval_id": id, "decision": "allow_once"}}),
    );
    rt.send("c1", &m);
    let fx = rt.host.approval_applied(&id, true);
    rt.apply(fx);
    drop(rt);
    let reopened = FileJournal::open(&path).unwrap();
    let replayed =
        super::journal::replay(super::journal::Journal::load(&reopened).unwrap()).unwrap();
    let stored = &replayed.receipts[&rid(1)];
    assert_eq!(stored.kind, ReceiptKind::Approval);
    assert_eq!(stored.state, ReceiptState::Completed);
}

// ── client ──

#[test]
fn the_registry_client_keeps_pending_approvals_for_known_processes() {
    let mut rt = setup();
    list_and_hold(&mut rt, "c1");
    rt.send("v", &msg("list", json!({})));
    let id = open(&mut rt, vec![rule("r-1")]);
    let mut reg = RegistryClient::default();
    let feed = |reg: &mut RegistryClient, msgs: Vec<Value>| {
        for m in msgs {
            let env =
                wire::decode(&serde_json::to_vec(&json!({"type": "session", "data": m})).unwrap())
                    .unwrap();
            let wire::Envelope::Session(s) = env else {
                unreachable!()
            };
            reg.on_message(&s.op);
        }
    };
    feed(&mut reg, got(&mut rt, "v"));
    let pending: Vec<_> = reg
        .pending_approvals()
        .map(|a| a.approval_id.clone())
        .collect();
    assert_eq!(pending, std::slice::from_ref(&id));
    assert_eq!(
        reg.pending_approvals().next().unwrap().always_rules,
        [rule("r-1")]
    );

    // A request for an unknown session is ignored.
    let other = wire::ApprovalRequest {
        approval_id: AID.into(),
        session_id: "ses-bbbbbbbbbbbb".into(),
        process_gen: P1.into(),
        tool: "Bash".into(),
        summary: String::new(),
        created_at: 0,
        always_rules: vec![],
    };
    assert_eq!(
        reg.on_message(&Op::ApprovalRequest(other.clone())),
        RegistryOutcome::Ignored
    );
    // Closing removes it.
    let fx = rt
        .host
        .close_approval(&id, ApprovalCloseReason::Interrupted);
    rt.apply(fx);
    feed(&mut reg, got(&mut rt, "v"));
    assert_eq!(reg.pending_approvals().count(), 0);

    // A new process of the session drops its approvals; so does a new attachment.
    let id2 = open(&mut rt, vec![]);
    feed(&mut reg, got(&mut rt, "v"));
    assert_eq!(reg.pending_approvals().count(), 1);
    let fx = rt.host.replace_process(S1, P1B).unwrap();
    rt.apply(fx);
    let msgs: Vec<Value> = got(&mut rt, "v")
        .into_iter()
        .filter(|m| m["op"] != "approval_closed")
        .collect();
    feed(&mut reg, msgs);
    assert_eq!(reg.pending_approvals().count(), 0, "{id2}");
    let mut own = other;
    own.session_id = S1.into();
    own.process_gen = P1B.into();
    assert_eq!(
        reg.on_message(&Op::ApprovalRequest(own)),
        RegistryOutcome::Applied
    );
    reg.new_attachment();
    assert_eq!(reg.pending_approvals().count(), 0);
}

#[test]
fn a_reconnected_attachment_sees_pending_approvals_after_list() {
    let mut rt = setup();
    list_and_hold(&mut rt, "c1");
    let id = open(&mut rt, vec![]);
    got(&mut rt, "c1");
    rt.attach("c1", C1B).unwrap();
    assert!(got(&mut rt, "c1").is_empty());
    rt.send("c1", &msg("list", json!({})));
    let caught = got(&mut rt, "c1");
    assert_eq!(ops(&caught), ["sessions", "approval_request"]);
    assert_eq!(caught[1]["approval_id"], id.as_str());
}

#[test]
fn a_handed_off_answer_still_completes_after_the_session_closes() {
    let mut rt = setup();
    let e = list_and_hold(&mut rt, "c1");
    let id = open(&mut rt, vec![]);
    let m = answer(
        &rt,
        "c1",
        e,
        1,
        json!({"approval_id": id, "decision": "allow_once"}),
    );
    rt.send("c1", &m);
    // Closed, but the process still runs and may apply the decision.
    let fx = rt.host.close_session(S1, false);
    rt.apply(fx);
    let fx = rt.host.approval_applied(&id, true);
    rt.apply(fx);
    assert_eq!(
        rt.host.receipt(&rid(1)).unwrap().state,
        ReceiptState::Completed
    );
    // With the process gone the receipt finishes and the approval is forgotten.
    let mut rt = setup();
    let e = list_and_hold(&mut rt, "c1");
    let id = open(&mut rt, vec![]);
    let m = answer(
        &rt,
        "c1",
        e,
        1,
        json!({"approval_id": id, "decision": "allow_once"}),
    );
    rt.send("c1", &m);
    let fx = rt.host.close_session(S1, true);
    rt.apply(fx);
    assert_eq!(
        rt.host.receipt(&rid(1)).unwrap().state,
        ReceiptState::OutcomeUnknown
    );
    let fx = rt.host.approval_applied(&id, true);
    assert!(fx.is_empty());
}

#[test]
fn a_takeover_keeps_the_pending_approval_for_the_new_holder() {
    let mut rt = setup();
    let e1 = list_and_hold(&mut rt, "c1");
    let id = open(&mut rt, vec![]);
    let c2 = "66666666-6666-4666-8666-666666666666";
    rt.connect_only(
        "c2",
        c2,
        vec![wire::Permission::View, wire::Permission::Control],
        1_000_000,
    );
    rt.send("c2", &msg("hello", json!({})));
    rt.send("c2", &msg("list", json!({})));
    let caught = got(&mut rt, "c2");
    assert_eq!(ops(&caught), ["welcome", "sessions", "approval_request"]);
    let m = msg(
        "acquire",
        json!({"binding": binding(&rt, "c2", None), "takeover": true}),
    );
    rt.send("c2", &m);
    let e2 = got(&mut rt, "c2")
        .into_iter()
        .find(|m| m["op"] == "lease")
        .unwrap()["binding"]["lease_epoch"]
        .as_u64()
        .unwrap();
    assert!(e2 > e1);
    // Still pending, nothing released, no close.
    assert_eq!(rt.host.pending_approvals(S1), std::slice::from_ref(&id));
    assert!(released(&rt).is_empty());
    assert!(!ops(&got(&mut rt, "c1")).contains(&"approval_closed".to_string()));
    // The old holder's epoch is stale; the new holder answers with its own.
    let old = answer(
        &rt,
        "c1",
        e1,
        1,
        json!({"approval_id": id, "decision": "deny"}),
    );
    rt.send("c1", &old);
    assert_eq!(got(&mut rt, "c1")[0]["code"], "stale_lease");
    let new = answer(
        &rt,
        "c2",
        e2,
        2,
        json!({"approval_id": id, "decision": "allow_once"}),
    );
    rt.send("c2", &new);
    assert_eq!(
        ops(&got(&mut rt, "c2")),
        ["receipt", "receipt", "approval_closed"]
    );
    assert_eq!(approval_effects(&rt).len(), 1);
}

#[test]
fn the_runtime_closes_an_approval_it_released() {
    let mut rt = setup();
    list_and_hold(&mut rt, "c1");
    let id = open(&mut rt, vec![]);
    got(&mut rt, "c1");
    let fx = rt.host.close_approval(&id, ApprovalCloseReason::Released);
    rt.apply(fx);
    let closed = got(&mut rt, "c1");
    assert_eq!(ops(&closed), ["approval_closed"]);
    assert_eq!(closed[0]["reason"], "released");
    assert!(rt.host.pending_approvals(S1).is_empty());
    // The runtime released it itself: no release effect back.
    assert!(released(&rt).is_empty());
}

#[test]
fn a_failed_hand_off_releases_the_waiting_prompt() {
    let mut rt = setup();
    let e = list_and_hold(&mut rt, "c1");
    let id = open(&mut rt, vec![]);
    let m = answer(
        &rt,
        "c1",
        e,
        1,
        json!({"approval_id": id, "decision": "allow_once"}),
    );
    rt.send("c1", &m);
    assert!(released(&rt).is_empty());
    let fx = rt
        .host
        .dispatch_report(&rid(1), DispatchReport::FailedNoEffect);
    assert!(fx.iter().any(|e| matches!(e,
        Effect::ApprovalReleased { approval_id, session_id } if *approval_id == id && session_id == S1)));
    rt.apply(fx);
    assert_eq!(
        rt.host.receipt(&rid(1)).unwrap().state,
        ReceiptState::Rejected
    );
}

#[test]
fn a_handed_off_answer_the_agent_never_confirms_ends_at_the_deadline() {
    let mut rt = setup();
    let e = list_and_hold(&mut rt, "c1");
    // Renewals keep the lease; the deadline doesn't depend on it.
    let id = open(&mut rt, vec![]);
    rt.set_now(1000);
    let m = answer(
        &rt,
        "c1",
        e,
        1,
        json!({"approval_id": id, "decision": "allow_once"}),
    );
    rt.send("c1", &m);
    const { assert!(APPROVAL_HANDOFF_MS > 600_000) };
    rt.set_now(1000 + APPROVAL_HANDOFF_MS - 1);
    assert_eq!(
        rt.host.receipt(&rid(1)).unwrap().state,
        ReceiptState::Executing
    );
    rt.set_now(1000 + APPROVAL_HANDOFF_MS);
    let r = rt.host.receipt(&rid(1)).unwrap();
    assert_eq!(
        (r.state, r.detail.as_deref()),
        (
            ReceiptState::OutcomeUnknown,
            Some(DETAIL_APPROVAL_UNCONFIRMED)
        )
    );
    // Forgotten: a late report changes nothing.
    assert!(rt.host.approval_applied(&id, true).is_empty());
}

#[test]
fn welcome_permissions_have_no_approve() {
    let m = msg(
        "welcome",
        json!({"account_id":"account-a","atem_device_id":"host-a","host_trust_gen":1,
            "runtime_gen":P1,"controller_session":C1,"attachment_gen":C1,"client_kind":"native",
            "permissions":["view","control","approve"],"authorization_ms_left":1,"server_time":1}),
    );
    assert!(!decodes(&m));
}

// ── Atem session rules (r7.2) ──

fn session_rule(id: &str) -> AlwaysRule {
    AlwaysRule {
        rule_id: id.into(),
        label: format!("Always allow `{id}` in /p for this session"),
        scope: "session".into(),
    }
}

fn revoke(rt: &FakeRuntime, client: &str, epoch: Option<u64>, n: u64, rule_id: &str) -> Value {
    msg(
        "submit",
        json!({"binding": binding(rt, client, epoch), "request_id": rid(n),
               "kind": "approval_rule_revoke", "payload": {"rule_id": rule_id}}),
    )
}

#[test]
fn rule_revoke_payloads_decode_strictly() {
    let with = |payload: Value| {
        msg(
            "submit",
            json!({"binding": {"target": target(P1), "attachment_gen": C1, "lease_epoch": 1},
                   "request_id": rid(1), "kind": "approval_rule_revoke", "payload": payload}),
        )
    };
    assert!(decodes(&with(json!({"rule_id": "s-0123456789abcdef"}))));
    for bad in [
        json!({}),
        json!({"rule_id": "bad rule"}),
        json!({"rule_id": "s-1", "extra": 1}),
        json!({"rule_id": null}),
        json!("s-1"),
    ] {
        assert!(!decodes(&with(bad.clone())), "{bad}");
    }
    // r7.3: the lease doesn't govern a revoke, so `lease_epoch` is optional;
    // `acquire` is refused (the payload is exactly `{rule_id}`).
    let mut m = with(json!({"rule_id": "s-1"}));
    m["data"]["binding"]
        .as_object_mut()
        .unwrap()
        .remove("lease_epoch");
    assert!(decodes(&m));
    assert!(!decodes(&with(json!({"rule_id": "s-1", "acquire": true}))));
    let mut m = with(json!({"rule_id": "s-1", "acquire": true}));
    m["data"]["binding"]
        .as_object_mut()
        .unwrap()
        .remove("lease_epoch");
    assert!(!decodes(&m));
    // chat-v1: `approval_rule_revoke` instead of `text`, lease or not.
    let chat = |revoke: Value, lease: Option<u64>| {
        let mut b = json!({"target": target(P1), "attachment_gen": C1});
        if let Some(e) = lease {
            b["lease_epoch"] = json!(e);
        }
        json!({"type": "agentChat", "data": {"v": 1, "op": "submit", "conversationId": "c1",
               "agentId": S1, "generation": P1, "requestId": rid(2),
               "approval_rule_revoke": revoke, "binding": b}})
    };
    assert!(decodes(&chat(json!({"rule_id": "s-1"}), Some(1))));
    assert!(decodes(&chat(json!({"rule_id": "s-1"}), None)));
    assert!(!decodes(&chat(json!({"rule_id": "s 1"}), Some(1))));
    assert!(!decodes(&chat(
        json!({"rule_id": "s-1", "acquire": true}),
        None
    )));
    // `approval_rules` from the host: ≤ 32 rules, unique ids.
    let rules =
        |n: usize| -> Vec<AlwaysRule> { (0..n).map(|i| session_rule(&format!("s-{i}"))).collect() };
    let op = |rules: Vec<AlwaysRule>| {
        msg(
            "approval_rules",
            json!({"session_id": S1, "process_gen": P1, "rules": rules}),
        )
    };
    assert!(decodes(&op(rules(32))));
    assert!(!decodes(&op(rules(33))));
    assert!(!decodes(&op(vec![
        session_rule("s-1"),
        session_rule("s-1")
    ])));
}

#[test]
fn session_rules_reach_control_viewers_and_end_with_the_process() {
    let mut rt = setup();
    let epoch = list_and_hold(&mut rt, "c1");
    rt.send("r", &msg("list", json!({})));
    got(&mut rt, "r");
    let fx = rt
        .host
        .set_approval_rules(S1, P1, vec![session_rule("s-1")])
        .unwrap();
    rt.apply(fx);
    let c1 = got(&mut rt, "c1");
    assert_eq!(ops(&c1), ["approval_rules"]);
    assert_eq!(c1[0]["rules"][0]["rule_id"], "s-1");
    assert_eq!(c1[0]["process_gen"], P1);
    assert!(got(&mut rt, "r").is_empty(), "view-only gets no rules");
    // The same list again changes nothing; another process is refused.
    let fx = rt
        .host
        .set_approval_rules(S1, P1, vec![session_rule("s-1")])
        .unwrap();
    rt.apply(fx);
    assert!(got(&mut rt, "c1").is_empty());
    assert!(rt.host.set_approval_rules(S1, P1B, vec![]).is_err());
    // A late subscriber with control gets them after its snapshot.
    got(&mut rt, "v");
    rt.send("v", &msg("list", json!({})));
    assert_eq!(ops(&got(&mut rt, "v")), ["sessions", "approval_rules"]);
    // A view-only one doesn't, and can't revoke either.
    rt.send("r", &msg("list", json!({})));
    assert_eq!(ops(&got(&mut rt, "r")), ["sessions"]);
    rt.send("r", &revoke(&rt, "r", Some(epoch), 1, "s-1"));
    assert_eq!(got(&mut rt, "r")[0]["code"], "forbidden");
    // An inactive rule is stale, whatever the lease epoch says.
    rt.send("c1", &revoke(&rt, "c1", Some(epoch + 1), 2, "s-9"));
    assert_eq!(got(&mut rt, "c1")[0]["code"], "stale_target");
    // The process ends: the list empties for viewers, and a revoke of the
    // old process's rule is stale.
    let fx = rt.host.process_exited(S1, None);
    rt.apply(fx);
    let c1 = got(&mut rt, "c1");
    let empty = c1.iter().find(|m| m["op"] == "approval_rules").unwrap();
    assert_eq!(empty["rules"], json!([]));
    assert!(rt.host.approval_rules(S1).is_empty());
}

/// r7.3: any attachment with `control` revokes, lease or not; the lease
/// holder keeps its lease, epoch and deadline.
#[test]
fn a_control_attachment_revokes_without_the_lease_and_leaves_it_alone() {
    let mut rt = setup();
    let epoch = list_and_hold(&mut rt, "c1");
    rt.send("v", &msg("list", json!({})));
    let fx = rt
        .host
        .set_approval_rules(S1, P1, vec![session_rule("s-1"), session_rule("s-2")])
        .unwrap();
    rt.apply(fx);
    got(&mut rt, "c1");
    got(&mut rt, "v");
    // Another process's rule: stale_target, nothing dispatched.
    let mut other = revoke(&rt, "v", None, 1, "s-1");
    other["data"]["binding"]["target"]["process_gen"] = json!(P1B);
    rt.send("v", &other);
    assert_eq!(got(&mut rt, "v")[0]["code"], "stale_target");
    // An unknown rule: stale_target.
    rt.send("v", &revoke(&rt, "v", None, 2, "s-9"));
    assert_eq!(got(&mut rt, "v")[0]["code"], "stale_target");
    assert!(rt.host.receipt(&rid(1)).is_none() && rt.host.receipt(&rid(2)).is_none());
    // No lease, no lease_epoch: revoked.
    rt.send("v", &revoke(&rt, "v", None, 3, "s-1"));
    let v = got(&mut rt, "v");
    let states: Vec<_> = v
        .iter()
        .filter(|m| m["op"] == "receipt")
        .map(|m| m["state"].as_str().unwrap().to_string())
        .collect();
    assert_eq!(states, ["accepted", "executing", "completed"]);
    // A lease epoch it doesn't hold (the holder's, or a stale one) is ignored.
    rt.send("v", &revoke(&rt, "v", Some(epoch + 5), 4, "s-2"));
    let v = got(&mut rt, "v");
    assert!(
        v.iter()
            .any(|m| m["op"] == "receipt" && m["state"] == "completed")
    );
    assert!(rt.host.approval_rules(S1).is_empty());
    // The holder saw only the shorter lists: no lease or session change.
    let c1 = got(&mut rt, "c1");
    assert_eq!(ops(&c1), ["approval_rules", "approval_rules"]);
    assert_eq!(rt.host.lease_holder(S1), Some(rt.attachment("c1").as_str()));
    assert_eq!(rt.host.lease_epoch(S1), Some(epoch));
    // It still renews at the same epoch.
    rt.send(
        "c1",
        &msg("renew", json!({"binding": binding(&rt, "c1", Some(epoch))})),
    );
    assert_eq!(ops(&got(&mut rt, "c1")), ["lease"]);
    // Both receipts are durable approval_rule_revoke receipts.
    for n in [3, 4] {
        assert_eq!(
            rt.host.receipt(&rid(n)).unwrap().kind,
            ReceiptKind::ApprovalRuleRevoke
        );
    }
}

#[test]
fn a_rule_revoked_from_chat_completes_in_chat() {
    let mut rt = setup();
    let epoch = list_and_hold(&mut rt, "c1");
    let fx = rt
        .host
        .set_approval_rules(S1, P1, vec![session_rule("s-1")])
        .unwrap();
    rt.apply(fx);
    got(&mut rt, "c1");
    let m = json!({"type": "agentChat", "data": {"v": 1, "op": "submit", "conversationId": "conv",
        "agentId": S1, "generation": P1, "requestId": rid(7),
        "approval_rule_revoke": {"rule_id": "s-1"},
        "binding": binding(&rt, "v", None)}});
    // r7.3: from another control attachment, without the lease c1 holds.
    rt.send("v", &m);
    let chats: Vec<ChatReply> = rt
        .effects
        .iter()
        .filter_map(|e| match e {
            Effect::Chat { reply, .. } => Some(reply.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        chats,
        [
            ChatReply::Accepted { request_id: rid(7) },
            ChatReply::Complete {
                request_id: rid(7),
                turn_id: None,
                interrupted: false
            }
        ]
    );
    assert!(rt.host.approval_rules(S1).is_empty());
    assert_eq!(
        rt.host.receipt(&rid(7)).unwrap().kind,
        ReceiptKind::ApprovalRuleRevoke
    );
    assert_eq!(rt.host.lease_holder(S1), Some(rt.attachment("c1").as_str()));
    assert_eq!(rt.host.lease_epoch(S1), Some(epoch));
}

#[test]
fn a_trust_change_or_restart_clears_the_session_rules() {
    let mut rt = setup();
    list_and_hold(&mut rt, "c1");
    let fx = rt
        .host
        .set_approval_rules(S1, P1, vec![session_rule("s-1")])
        .unwrap();
    rt.apply(fx);
    got(&mut rt, "c1");
    // A new trust generation: the copy goes and viewers see it empty (the
    // runtime has its workers drop theirs).
    let fx = rt.host.change_trust_gen(2).unwrap();
    rt.apply(fx);
    let c1 = got(&mut rt, "c1");
    let empty = c1.iter().find(|m| m["op"] == "approval_rules").unwrap();
    assert_eq!(empty["rules"], json!([]));
    assert!(rt.host.approval_rules(S1).is_empty());
    // A restart (or rebind) loses the copy too; the workers report again.
    let fx = rt
        .host
        .set_approval_rules(S1, P1, vec![session_rule("s-2")])
        .unwrap();
    rt.apply(fx);
    let fx = rt
        .host
        .restart("66666666-6666-4666-8666-666666666666", 8)
        .unwrap();
    rt.apply(fx);
    assert!(rt.host.approval_rules(S1).is_empty());
}

/// The outcome of a chat prompt's turn lives in its receipt's detail, so a
/// duplicate submit after a runtime restart still says it was interrupted.
#[test]
fn a_duplicate_chat_prompt_after_a_restart_keeps_its_interrupted_outcome() {
    let mut rt = setup();
    let epoch = list_and_hold(&mut rt, "c1");
    let submit = |rt: &FakeRuntime, epoch: u64| {
        json!({"type": "agentChat", "data": {"v": 1, "op": "submit", "conversationId": "conv",
            "agentId": S1, "generation": P1, "requestId": rid(5), "text": "run it",
            "binding": binding(rt, "c1", Some(epoch))}})
    };
    rt.send("c1", &submit(&rt, epoch));
    let fx = rt.host.dispatch_report(
        &rid(5),
        DispatchReport::Completed {
            detail: Some(DETAIL_TURN_INTERRUPTED.into()),
            turn_id: Some("t1".into()),
        },
    );
    rt.apply(fx);
    assert_eq!(
        rt.host.receipt(&rid(5)).unwrap().detail.as_deref(),
        Some("interrupted")
    );
    let fx = rt
        .host
        .restart("99999999-9999-4999-8999-999999999999", 8)
        .unwrap();
    rt.apply(fx);
    rt.attach("c1", C1B).unwrap();
    let epoch = list_and_hold(&mut rt, "c1");
    rt.effects.clear();
    rt.send("c1", &submit(&rt, epoch));
    let chats: Vec<ChatReply> = rt
        .effects
        .iter()
        .filter_map(|e| match e {
            Effect::Chat { reply, .. } => Some(reply.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(
        chats,
        [ChatReply::Complete {
            request_id: rid(5),
            turn_id: None,
            interrupted: true
        }]
    );
}

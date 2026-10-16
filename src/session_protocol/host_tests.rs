//! Host authority rules beyond the shared fixtures (contract §8 first set):
//! hello/welcome, takeover, repeat acquire, stale epochs and the write
//! boundary, trust change before dispatch, closed sessions, receipt-query
//! scoping and limits, fenced attachments, runtime restarts, the registry's
//! per-attachment `seq`, durable-write failures and the crash rules.

use super::client::{RegistryClient, RegistryOutcome};
use super::fake_runtime::{AUTHORIZATION_MS, FakeRuntime};
use super::host::*;
use super::journal::{MemJournal, Record};
use super::wire::{self, Envelope, Op, Permission, ReceiptKind, ReceiptState, Target};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicU64, Ordering};

const S1: &str = "ses-aaaaaaaaaaaa";
const S2: &str = "ses-bbbbbbbbbbbb";
const P1: &str = "22222222-2222-4222-8222-222222222222";
const P2: &str = "22222222-2222-4222-8222-bbbbbbbbbbbb";
const C1: &str = "33333333-3333-4333-8333-333333333333";
const C2: &str = "66666666-6666-4666-8666-666666666666";
const V: &str = "77777777-7777-4777-8777-777777777777";
const C1B: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const GEN2: &str = "99999999-9999-4999-8999-999999999999";

fn id() -> String {
    static N: AtomicU64 = AtomicU64::new(1);
    format!(
        "11111111-1111-4111-8111-{:012}",
        N.fetch_add(1, Ordering::Relaxed)
    )
}

fn rid(n: u64) -> String {
    format!("44444444-4444-4444-8444-{n:012}")
}

fn setup_with(config: HostConfig) -> FakeRuntime {
    let client = |name: &str, att_gen: &str, perms: Value| json!({"name": name, "attachment_gen": att_gen, "permissions": perms, "client_kind": "native"});
    FakeRuntime::from_json(
        json!({
            "host": {"account_id": "account-a", "atem_device_id": "host-a", "host_trust_gen": 1,
                     "runtime_gen": "55555555-5555-4555-8555-555555555555", "runtime_epoch": 7},
            "sessions": [{"session_id": S1, "process_gen": P1, "chat": true},
                         {"session_id": S2, "process_gen": P2}],
            "clients": [client("c1", C1, json!(["view", "control"])),
                        client("c2", C2, json!(["view", "control"])),
                        client("v", V, json!(["view"]))]
        }),
        config,
    )
}

fn setup() -> FakeRuntime {
    setup_with(HostConfig::default())
}

fn pg(session: &str) -> &'static str {
    if session == S1 { P1 } else { P2 }
}

fn target_with(session: &str, trust: u64) -> Value {
    json!({"account_id": "account-a", "atem_device_id": "host-a", "host_trust_gen": trust,
           "session_id": session, "process_gen": pg(session)})
}

fn binding(rt: &FakeRuntime, client: &str, session: &str, epoch: Option<u64>) -> Value {
    let mut b = json!({"target": target_with(session, 1), "attachment_gen": rt.attachment(client)});
    if let Some(e) = epoch {
        b["lease_epoch"] = json!(e);
    }
    b
}

fn session(op: &str, fields: Value) -> Value {
    let mut data = json!({"v": 1, "op": op, "id": id()});
    data.as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    json!({"type": "session", "data": data})
}

fn acquire(rt: &FakeRuntime, client: &str, s: &str, takeover: bool) -> Value {
    session(
        "acquire",
        json!({"binding": binding(rt, client, s, None), "takeover": takeover}),
    )
}

fn renew(rt: &FakeRuntime, client: &str, s: &str, epoch: u64) -> Value {
    session(
        "renew",
        json!({"binding": binding(rt, client, s, Some(epoch))}),
    )
}

fn submit(rt: &FakeRuntime, client: &str, s: &str, epoch: u64, n: u64, kind: &str) -> Value {
    let payload = if kind == "prompt" {
        json!({"text": "run the tests"})
    } else {
        json!({})
    };
    session(
        "submit",
        json!({"binding": binding(rt, client, s, Some(epoch)), "request_id": rid(n),
               "kind": kind, "payload": payload}),
    )
}

fn query(rt: &FakeRuntime, client: &str, target: Value, ids: Vec<String>) -> Value {
    session(
        "receipt_query",
        json!({"binding": {"target": target, "attachment_gen": rt.attachment(client)},
               "request_ids": ids}),
    )
}

fn terminal(rt: &FakeRuntime, client: &str, op: &str, epoch: Option<u64>, extra: Value) -> Value {
    let mut data = json!({"v": 1, "op": op, "terminal_id": S1, "generation": P1,
                          "binding": binding(rt, client, S1, epoch)});
    data.as_object_mut()
        .unwrap()
        .extend(extra.as_object().unwrap().clone());
    json!({"type": "terminal", "data": data})
}

/// Takes `client`'s queued messages and returns the `data` of each.
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

fn only(rt: &mut FakeRuntime, client: &str) -> Value {
    let msgs = got(rt, client);
    assert_eq!(msgs.len(), 1, "{client} got {msgs:#?}");
    msgs[0].clone()
}

fn assert_error(msg: &Value, code: &str) {
    assert_eq!(msg["op"], "error", "{msg}");
    assert_eq!(msg["code"], code, "{msg}");
}

/// Acquires `s` for `client` and returns the lease epoch.
fn hold(rt: &mut FakeRuntime, client: &str, s: &str) -> u64 {
    let m = acquire(rt, client, s, false);
    rt.send(client, &m);
    let reply = got(rt, client)
        .into_iter()
        .find(|m| m["op"] == "lease")
        .expect("lease");
    reply["binding"]["lease_epoch"].as_u64().unwrap()
}

fn subscribe(rt: &mut FakeRuntime, client: &str) -> String {
    let m = terminal(rt, client, "subscribe", None, json!({}));
    rt.send(client, &m);
    let attached = got(rt, client)
        .into_iter()
        .find(|m| m["op"] == "attached")
        .expect("attached");
    attached["stream_id"].as_str().unwrap().to_string()
}

fn input(rt: &FakeRuntime, client: &str, stream: &str, epoch: u64) -> Value {
    terminal(
        rt,
        client,
        "input",
        Some(epoch),
        json!({"stream_id": stream, "sequence": 0, "bytes": "aGkN"}),
    )
}

fn receipts_of(rt: &mut FakeRuntime, client: &str) -> Vec<(String, String)> {
    got(rt, client)
        .into_iter()
        .filter(|m| m["op"] == "receipt")
        .map(|m| {
            (
                m["state"].as_str().unwrap().to_string(),
                m["detail"].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect()
}

fn st(state: &str, detail: &str) -> (String, String) {
    (state.to_string(), detail.to_string())
}

// ── hello / welcome (§3) ──

#[test]
fn hello_gets_a_welcome_and_nothing_works_before_it() {
    let mut rt = setup();
    let fresh = "88888888-8888-4888-8888-888888888888";
    rt.connect_only("n", fresh, vec![Permission::View], AUTHORIZATION_MS);
    rt.send("n", &session("list", json!({})));
    assert_error(&only(&mut rt, "n"), "unsupported_version");
    let m = terminal(&rt, "n", "subscribe", None, json!({}));
    rt.send("n", &m);
    assert_error(&only(&mut rt, "n"), "unsupported_version");

    // Compatibility mode: resume and resume_proof are refused, never trusted.
    let resume = session(
        "hello",
        json!({"resume": {"controller_session": "12345678-1234-4234-8234-123456789012"}}),
    );
    rt.send("n", &resume);
    assert_error(&only(&mut rt, "n"), "unauthorized");
    rt.send("n", &session("resume_proof", json!({"proof": "x"})));
    assert_error(&only(&mut rt, "n"), "unauthorized");

    rt.set_now(1000);
    let hello = session("hello", json!({}));
    rt.send("n", &hello);
    let w = only(&mut rt, "n");
    assert_eq!(w["op"], "welcome");
    assert_eq!(w["re"], hello["data"]["id"]);
    assert_eq!(w["attachment_gen"], fresh);
    assert_eq!(w["account_id"], "account-a");
    assert_eq!(w["host_trust_gen"], 1);
    assert_eq!(w["runtime_gen"], "55555555-5555-4555-8555-555555555555");
    assert_eq!(w["permissions"], json!(["view"]));
    assert_eq!(w["client_kind"], "native");
    assert_eq!(w["authorization_ms_left"], AUTHORIZATION_MS - 1000);
    assert!(wire::is_uuid_v4(w["controller_session"].as_str().unwrap()));
    // One welcome per attachment.
    rt.send("n", &session("hello", json!({})));
    assert_error(&only(&mut rt, "n"), "unauthorized");
    // Host-only ops are not requests.
    rt.send("n", &session("lease_released", json!({})));
    assert_error(&only(&mut rt, "n"), "unsupported_version");
}

#[test]
fn every_hello_gets_its_own_controller_and_no_lease() {
    let mut rt = setup();
    hold(&mut rt, "c1", S1);
    rt.event_reconnect("c1", C1B);
    assert_eq!(rt.host.lease_holder(S1), Some(C1));
    // The new attachment is another controller: the old lease is held.
    let m = acquire(&rt, "c1", S1, false);
    rt.send("c1", &m);
    assert_error(&only(&mut rt, "c1"), "lease_held");
}

#[test]
fn authorization_bounds_leases_and_then_pauses() {
    let mut rt = setup();
    let short = "88888888-8888-4888-8888-888888888888";
    rt.connect_only(
        "s",
        short,
        vec![Permission::View, Permission::Control],
        5000,
    );
    rt.send("s", &session("hello", json!({})));
    got(&mut rt, "s");
    rt.set_now(1000);
    let m = acquire(&rt, "s", S1, false);
    rt.send("s", &m);
    let lease = only(&mut rt, "s");
    assert_eq!(lease["ms_left"], 4000);
    rt.set_now(5000);
    let changed = only(&mut rt, "s");
    assert_eq!(changed["reason"], "expired");
    rt.send("s", &session("list", json!({})));
    assert_error(&only(&mut rt, "s"), "paused");
}

// ── leases (§5) ──

#[test]
fn takeover_moves_the_lease_and_the_old_holder_becomes_a_viewer() {
    let mut rt = setup();
    assert_eq!(hold(&mut rt, "c1", S1), 1);
    got(&mut rt, "v");
    got(&mut rt, "c2");
    let m = acquire(&rt, "c2", S1, false);
    rt.send("c2", &m);
    assert_error(&only(&mut rt, "c2"), "lease_held");

    let m = acquire(&rt, "c2", S1, true);
    rt.send("c2", &m);
    let lease = only(&mut rt, "c2");
    assert_eq!(lease["op"], "lease");
    assert_eq!(lease["binding"]["lease_epoch"], 2);
    assert_eq!(lease["ms_left"], LEASE_MS);
    for viewer in ["c1", "v"] {
        let c = only(&mut rt, viewer);
        assert_eq!(c["op"], "lease_changed");
        assert_eq!(c["reason"], "takeover");
        assert_eq!(c["lease_epoch"], 2);
        assert_eq!(c["controller"]["lease_epoch"], 2);
    }
    assert_eq!(rt.host.lease_holder(S1), Some(C2));
    let m = renew(&rt, "c1", S1, 1);
    rt.send("c1", &m);
    assert_error(&only(&mut rt, "c1"), "stale_lease");
    // Takeover needs control.
    let m = acquire(&rt, "v", S1, true);
    rt.send("v", &m);
    assert_error(&only(&mut rt, "v"), "forbidden");
    assert_eq!(rt.host.lease_holder(S1), Some(C2));
}

#[test]
fn repeat_acquire_returns_the_current_lease_unchanged() {
    let mut rt = setup();
    assert_eq!(hold(&mut rt, "c1", S1), 1);
    rt.set_now(4000);
    let m = acquire(&rt, "c1", S1, false);
    rt.send("c1", &m);
    let lease = only(&mut rt, "c1");
    assert_eq!(lease["binding"]["lease_epoch"], 1);
    assert_eq!(lease["ms_left"], 11_000);
    // Renew extends from now; expiry is now >= deadline.
    rt.set_now(5000);
    let m = renew(&rt, "c1", S1, 1);
    rt.send("c1", &m);
    assert_eq!(only(&mut rt, "c1")["ms_left"], LEASE_MS);
    rt.set_now(19_999);
    assert!(got(&mut rt, "c1").is_empty());
    assert_eq!(rt.host.lease_holder(S1), Some(C1));
    rt.set_now(20_000);
    let expired = only(&mut rt, "c1");
    assert_eq!(expired["reason"], "expired");
    assert_eq!(expired["lease_epoch"], 2);
    assert_eq!(expired["controller"], Value::Null);
    let m = renew(&rt, "c1", S1, 1);
    rt.send("c1", &m);
    assert_error(&only(&mut rt, "c1"), "stale_lease");
}

#[test]
fn stale_epochs_are_refused_without_effect() {
    let mut rt = setup();
    let stream = subscribe(&mut rt, "c1");
    let epoch = hold(&mut rt, "c1", S1);
    for wrong in [0, epoch + 1] {
        let m = input(&rt, "c1", &stream, wrong);
        rt.send("c1", &m);
        assert_error(&only(&mut rt, "c1"), "stale_lease");
        let m = submit(&rt, "c1", S1, wrong, 1, "prompt");
        rt.send("c1", &m);
        assert_error(&only(&mut rt, "c1"), "stale_lease");
    }
    // Another attachment's binding on this one is a stale target.
    let mut m = input(&rt, "c1", &stream, epoch);
    m["data"]["binding"]["attachment_gen"] = json!(C2);
    rt.send("c1", &m);
    assert_error(&only(&mut rt, "c1"), "stale_target");
    // A stream from another subscription is stale too.
    let m = input(&rt, "c1", "not-the-stream", epoch);
    rt.send("c1", &m);
    assert_error(&only(&mut rt, "c1"), "stale_target");
    assert!(
        !rt.effects
            .iter()
            .any(|e| matches!(e, Effect::PtyWrite { .. } | Effect::Dispatch { .. }))
    );
    // The right epoch writes.
    let m = input(&rt, "c1", &stream, epoch);
    rt.send("c1", &m);
    assert_eq!(rt.pty.writes_remote, 1);
}

#[test]
fn queued_remote_bytes_are_dropped_at_the_write_boundary() {
    type Revoke = fn(&mut FakeRuntime);
    let revokes: &[(&str, Revoke)] = &[
        ("takeover", |rt| {
            let m = acquire(rt, "c2", S1, true);
            rt.send("c2", &m);
        }),
        ("local input", |rt| rt.local_input(S1, b"x")),
        ("release", |rt| {
            let m = session(
                "release",
                json!({"binding": binding(rt, "c1", S1, Some(1))}),
            );
            rt.send("c1", &m);
        }),
        ("expiry", |rt| rt.set_now(LEASE_MS)),
    ];
    for (name, revoke) in revokes {
        let mut rt = setup();
        let stream = subscribe(&mut rt, "c1");
        assert_eq!(hold(&mut rt, "c1", S1), 1);
        rt.hold_writes = true;
        let m = input(&rt, "c1", &stream, 1);
        rt.send("c1", &m);
        revoke(&mut rt);
        rt.flush_writes();
        assert_eq!(rt.pty.writes_remote, 0, "{name}");
        assert_eq!(rt.pty.dropped_remote, 1, "{name}");
    }
}

#[test]
fn local_input_revokes_the_lease_before_it_is_written() {
    let mut rt = setup();
    hold(&mut rt, "c1", S1);
    rt.effects.clear();
    rt.local_input(S1, b"x");
    let changed = rt
        .effects
        .iter()
        .position(|e| matches!(e, Effect::Send { message: Envelope::Session(m), .. } if matches!(m.op, Op::LeaseChanged { .. })))
        .expect("lease_changed");
    let write = rt
        .effects
        .iter()
        .position(|e| matches!(e, Effect::PtyWrite { .. }))
        .expect("write");
    assert!(changed < write);
    let c = only(&mut rt, "c1");
    assert_eq!(c["reason"], "local_input");
    assert_eq!(c["lease_epoch"], 2);
    assert_eq!(rt.pty.writes_local, 1);
    assert_eq!(rt.host.lease_holder(S1), None);
}

#[test]
fn terminal_mutations_need_the_lease() {
    let mut rt = setup();
    let stream = subscribe(&mut rt, "c1");
    let resize = |rt: &FakeRuntime, e| {
        terminal(
            rt,
            "c1",
            "resize",
            Some(e),
            json!({"stream_id": stream, "rows": 40, "cols": 120}),
        )
    };
    let stop =
        |rt: &FakeRuntime, e| terminal(rt, "c1", "stop", Some(e), json!({"stream_id": stream}));
    let m = resize(&rt, 1);
    rt.send("c1", &m);
    assert_error(&only(&mut rt, "c1"), "stale_lease");
    let m = stop(&rt, 1);
    rt.send("c1", &m);
    assert_error(&only(&mut rt, "c1"), "stale_lease");
    assert_eq!((rt.pty.resizes, rt.pty.stops), (0, 0));
    let e = hold(&mut rt, "c1", S1);
    let m = resize(&rt, e);
    rt.send("c1", &m);
    let m = stop(&rt, e);
    rt.send("c1", &m);
    assert_eq!((rt.pty.resizes, rt.pty.stops), (1, 1));
    assert!(got(&mut rt, "c1").is_empty());
    // A viewer can subscribe but never mutate.
    let vs = subscribe(&mut rt, "v");
    let m = terminal(
        &rt,
        "v",
        "input",
        Some(e),
        json!({"stream_id": vs, "sequence": 0, "bytes": "eA=="}),
    );
    rt.send("v", &m);
    assert_error(&only(&mut rt, "v"), "forbidden");
}

// ── registry (§4) ──

fn registry_feed(client: &mut RegistryClient, msgs: Vec<Value>) -> Vec<RegistryOutcome> {
    msgs.into_iter()
        .filter(|m| matches!(m["op"].as_str(), Some("sessions" | "session_changed")))
        .map(|m| {
            let env =
                wire::decode(&serde_json::to_vec(&json!({"type": "session", "data": m})).unwrap())
                    .unwrap();
            let Envelope::Session(s) = env else { panic!() };
            client.on_message(&s.op)
        })
        .collect()
}

#[test]
fn registry_seq_is_per_attachment_and_a_gap_recovers_with_a_new_snapshot() {
    let mut rt = setup();
    rt.send("c1", &session("list", json!({})));
    let snap = only(&mut rt, "c1");
    assert_eq!(snap["op"], "sessions");
    assert_eq!(snap["seq"], 1);
    assert_eq!(snap["runtime_epoch"], 7);
    assert_eq!(snap["sessions"].as_array().unwrap().len(), 2);
    assert_eq!(
        snap["sessions"][0]["capabilities"],
        json!(["terminal-v1", "chat-v1"])
    );
    assert_eq!(snap["sessions"][0]["activity"], "unknown");
    let mut client = RegistryClient::default();
    registry_feed(&mut client, vec![snap]);

    // c2 never listed: it gets lease_changed but no registry changes.
    hold(&mut rt, "c2", S1);
    let c2_msgs = got(&mut rt, "c2");
    assert!(c2_msgs.iter().all(|m| m["op"] != "session_changed"));

    // c1 got lease_changed and a session_changed with seq 2; the change is
    // lost to simulate a gap.
    let c1_msgs = got(&mut rt, "c1");
    assert_eq!(ops(&c1_msgs), vec!["lease_changed", "session_changed"]);
    let lost: Vec<&Value> = c1_msgs
        .iter()
        .filter(|m| m["op"] == "session_changed")
        .collect();
    assert_eq!(lost[0]["seq"], 2);
    assert_eq!(lost[0]["descriptor"]["controller"]["lease_epoch"], 1);

    rt.local_input(S1, b"x");
    let next: Vec<Value> = got(&mut rt, "c1");
    let change = next.iter().find(|m| m["op"] == "session_changed").unwrap();
    assert_eq!(change["seq"], 3);
    assert_eq!(change["descriptor"]["controller"], Value::Null);
    let outcomes = registry_feed(&mut client, vec![change.clone()]);
    assert_eq!(outcomes, vec![RegistryOutcome::Buffered]);
    assert!(client.take_list_request(), "gap → list");
    rt.send("c1", &session("list", json!({})));
    let resync = only(&mut rt, "c1");
    assert_eq!(resync["seq"], 4);
    registry_feed(&mut client, vec![resync]);
    assert_eq!(client.seq(), Some(4));
    assert_eq!(client.session(S1).unwrap().controller, None);

    // Removal: the last descriptor with state removed, then unknown_session.
    rt.remove_session(S2);
    let removed = only(&mut rt, "c1");
    assert_eq!(removed["seq"], 5);
    assert_eq!(removed["descriptor"]["state"], "removed");
    assert_eq!(removed["descriptor"]["session_id"], S2);
    registry_feed(&mut client, vec![removed]);
    assert_eq!(client.session_ids(), vec![S1.to_string()]);
    got(&mut rt, "c2");
    let m = acquire(&rt, "c2", S2, false);
    rt.send("c2", &m);
    assert_error(&only(&mut rt, "c2"), "unknown_session");
    assert!(rt.host.add_session(spec(S2, P2)).is_err(), "tombstoned id");
    // A viewer without `view` gets no registry.
    let blind = "88888888-8888-4888-8888-888888888888";
    rt.connect_only("b", blind, vec![Permission::Control], AUTHORIZATION_MS);
    rt.send("b", &session("hello", json!({})));
    got(&mut rt, "b");
    rt.send("b", &session("list", json!({})));
    assert_error(&only(&mut rt, "b"), "forbidden");
    let m = acquire(&rt, "b", S1, false);
    rt.send("b", &m);
    assert_error(&only(&mut rt, "b"), "unknown_session");
}

fn spec(session_id: &str, process_gen: &str) -> SessionSpec {
    SessionSpec {
        session_id: session_id.into(),
        process_gen: process_gen.into(),
        provider: "codex".into(),
        cwd_label: "Atem".into(),
        chat: false,
        rows: 24,
        cols: 80,
    }
}

// ── attachments and restarts ──

#[test]
fn old_attachment_input_after_reconnect_is_refused() {
    let mut rt = setup();
    let stream = subscribe(&mut rt, "c1");
    hold(&mut rt, "c1", S1);
    rt.event_reconnect("c1", C1B);
    rt.effects.clear();
    let mut m = input(&rt, "c1", &stream, 1);
    m["data"]["binding"]["attachment_gen"] = json!(C1);
    rt.send_on(C1, &m);
    let refused = rt.effects.iter().any(|e| matches!(e,
        Effect::Send { attachment, message: Envelope::Session(s) }
            if attachment == C1 && matches!(s.op, Op::Error { code: wire::ErrorCode::Unauthorized, .. })));
    assert!(refused);
    assert!(
        !rt.effects
            .iter()
            .any(|e| matches!(e, Effect::PtyWrite { .. }))
    );
    assert_eq!(rt.pty.writes_remote, 0);
    // The new attachment can't use the old epoch either.
    let m = renew(&rt, "c1", S1, 1);
    rt.send("c1", &m);
    assert_error(&only(&mut rt, "c1"), "stale_lease");
    // Disconnect stops renewal; the lease then expires and can be acquired.
    rt.set_now(LEASE_MS);
    got(&mut rt, "c1");
    assert_eq!(hold(&mut rt, "c1", S1), 3);
}

#[test]
fn runtime_restart_invalidates_attachments_and_leases() {
    let mut rt = setup();
    assert_eq!(hold(&mut rt, "c1", S1), 1);
    rt.restart(GEN2, 8);
    assert_eq!(rt.host.lease_holder(S1), None);
    let m = renew(&rt, "c1", S1, 1);
    rt.effects.clear();
    rt.send_on(C1, &m);
    assert!(rt.effects.iter().any(|e| matches!(e,
        Effect::Send { message: Envelope::Session(s), .. }
            if matches!(s.op, Op::Error { code: wire::ErrorCode::Unauthorized, .. }))));
    rt.event_reconnect("c1", C1B);
    rt.send("c1", &session("list", json!({})));
    let snap = only(&mut rt, "c1");
    assert_eq!(
        (snap["runtime_epoch"].clone(), snap["seq"].clone()),
        (json!(8), json!(1))
    );
    assert_eq!(snap["runtime_gen"], GEN2);
    // Lease epochs never repeat across the restart.
    let e = hold(&mut rt, "c1", S1);
    assert!(e > 2, "epoch {e} after restart");
    // A restart needs a higher runtime epoch.
    assert!(rt.host.restart(GEN2, 8).is_err());
}

// ── submissions and receipts (§6) ──

#[test]
fn prompt_runs_to_completion_and_duplicates_return_the_receipt() {
    let mut rt = setup();
    let e = hold(&mut rt, "c1", S1);
    let m = submit(&rt, "c1", S1, e, 1, "prompt");
    rt.send("c1", &m);
    let msgs = got(&mut rt, "c1");
    assert_eq!(msgs[0]["re"], m["data"]["id"]);
    assert_eq!(msgs[0]["state"], "accepted");
    assert_eq!(msgs[1]["state"], "executing");
    assert_eq!(msgs[0]["target"], target_with(S1, 1));
    rt.dispatch_report(&rid(1), DispatchReport::Completed { detail: None });
    assert_eq!(receipts_of(&mut rt, "c1"), vec![st("completed", "")]);
    // A duplicate needs no lease, only view of the target.
    rt.set_now(LEASE_MS);
    got(&mut rt, "c1");
    rt.send("c1", &m);
    let dup = only(&mut rt, "c1");
    assert_eq!(dup["state"], "completed");
    assert_eq!(rt.pty.dispatch_attempts, 1);
    // Same id on another target is reuse.
    let e2 = hold(&mut rt, "c1", S2);
    let mut other = submit(&rt, "c1", S2, e2, 1, "prompt");
    rt.send("c1", &other);
    assert_error(&only(&mut rt, "c1"), "request_id_reused");
    other["data"]["kind"] = json!("interrupt");
    other["data"]["payload"] = json!({});
    other["data"]["binding"]["target"] = target_with(S1, 1);
    rt.send("c1", &other);
    assert_error(&only(&mut rt, "c1"), "request_id_reused");
}

#[test]
fn approval_answers_are_forbidden_in_v1() {
    let mut rt = setup();
    let e = hold(&mut rt, "c1", S1);
    let mut m = submit(&rt, "c1", S1, e, 1, "interrupt");
    m["data"]["kind"] = json!("approval");
    rt.send("c1", &m);
    let err = only(&mut rt, "c1");
    assert_error(&err, "forbidden");
    assert_eq!(err["detail"], DETAIL_APPROVAL);
    assert!(rt.host.receipt(&rid(1)).is_none());
}

#[test]
fn trust_change_before_dispatch_rejects_and_revokes() {
    let mut rt = setup();
    let e = hold(&mut rt, "c1", S1);
    let a = submit(&rt, "c1", S1, e, 1, "prompt");
    rt.send("c1", &a);
    let b = submit(&rt, "c1", S1, e, 2, "prompt");
    rt.send("c1", &b);
    // B waits behind the executing A.
    let states: Vec<_> = receipts_of(&mut rt, "c1");
    assert_eq!(
        states,
        vec![st("accepted", ""), st("executing", ""), st("accepted", "")]
    );
    rt.change_trust_gen(2);
    let msgs = got(&mut rt, "c1");
    assert!(
        msgs.iter()
            .any(|m| m["op"] == "lease_changed" && m["reason"] == "revoked")
    );
    let rejected = msgs.iter().find(|m| m["op"] == "receipt").unwrap();
    assert_eq!(rejected["request_id"], rid(2));
    assert_eq!(rejected["state"], "rejected");
    assert_eq!(rejected["detail"], DETAIL_TRUST_CHANGED);
    assert_eq!(rt.pty.dispatch_attempts, 1);
    // Bindings at the old generation are stale; A still finishes.
    let m = acquire(&rt, "c1", S1, false);
    rt.send("c1", &m);
    assert_error(&only(&mut rt, "c1"), "stale_target");
    rt.dispatch_report(&rid(1), DispatchReport::Completed { detail: None });
    assert_eq!(receipts_of(&mut rt, "c1"), vec![st("completed", "")]);
    assert_eq!(rt.pty.dispatch_attempts, 1);
    assert!(rt.host.change_trust_gen(2).is_err(), "never goes back");
}

fn ctx(trust: u64) -> HostContext {
    HostContext {
        account_id: "account-a".into(),
        atem_device_id: "host-a".into(),
        host_trust_gen: trust,
        runtime_gen: GEN2.into(),
        runtime_epoch: 9,
    }
}

fn target_struct(trust: u64) -> Target {
    serde_json::from_value(target_with(S1, trust)).unwrap()
}

fn accepted_record(n: u64, trust: u64) -> Record {
    Record::Accepted {
        request_id: rid(n),
        target: target_struct(trust),
        kind: ReceiptKind::Prompt,
        payload_digest: "0".repeat(64),
        payload: json!({"text": "hi"}),
        updated_at: 1,
    }
}

#[test]
fn crash_rules_dispatch_accepted_once_and_reconcile_executing() {
    // Accepted under an older trust generation: rejected, never dispatched.
    let mut j = MemJournal::default();
    j.append_ok(accepted_record(1, 1));
    let mut host = SessionHost::new(ctx(2), HostConfig::default(), j, random_ids()).unwrap();
    host.add_session(spec(S1, P1)).unwrap();
    let fx = host.recover();
    assert!(!fx.iter().any(|e| matches!(e, Effect::Dispatch { .. })));
    let r = host.receipt(&rid(1)).unwrap();
    assert_eq!(r.state, ReceiptState::Rejected);
    assert_eq!(r.detail.as_deref(), Some(DETAIL_TRUST_CHANGED));

    // Same trust generation: dispatched once, and a second crash only
    // reconciles it.
    let mut j = MemJournal::default();
    j.append_ok(accepted_record(1, 1));
    let mut host = SessionHost::new(ctx(1), HostConfig::default(), j, random_ids()).unwrap();
    host.add_session(spec(S1, P1)).unwrap();
    let fx = host.recover();
    let dispatches = fx
        .iter()
        .filter(|e| matches!(e, Effect::Dispatch { .. }))
        .count();
    assert_eq!(dispatches, 1);
    assert_eq!(
        host.receipt(&rid(1)).unwrap().state,
        ReceiptState::Executing
    );
    let fx = host
        .restart("12121212-1212-4212-8212-121212121212", 10)
        .unwrap();
    assert!(!fx.iter().any(|e| matches!(e, Effect::Dispatch { .. })));
    assert!(fx.iter().any(|e| matches!(e, Effect::Reconcile { .. })));
    host.dispatch_report(&rid(1), DispatchReport::Unknown);
    let r = host.receipt(&rid(1)).unwrap();
    assert_eq!(r.state, ReceiptState::OutcomeUnknown);
    assert_eq!(r.detail.as_deref(), Some(DETAIL_UNRECONCILED));

    // Accepted for a process that is gone: rejected, session closed.
    let mut j = MemJournal::default();
    j.append_ok(accepted_record(1, 1));
    let mut host = SessionHost::new(ctx(1), HostConfig::default(), j, random_ids()).unwrap();
    host.add_session(spec(S1, "33333333-3333-4333-8333-000000000001"))
        .unwrap();
    host.recover();
    assert_eq!(
        host.receipt(&rid(1)).unwrap().detail.as_deref(),
        Some(DETAIL_SESSION_CLOSED)
    );
}

#[test]
fn crash_after_executing_is_outcome_unknown_and_queued_work_runs_once() {
    let mut rt = setup();
    let e = hold(&mut rt, "c1", S1);
    for n in [1, 2] {
        let m = submit(&rt, "c1", S1, e, n, "prompt");
        rt.send("c1", &m);
    }
    assert_eq!(rt.pty.dispatch_attempts, 1);
    rt.restart(GEN2, 8);
    // A is reconciled (unknown), then B — accepted, trust unchanged — runs once.
    let a = rt.host.receipt(&rid(1)).unwrap();
    assert_eq!(a.state, ReceiptState::OutcomeUnknown);
    assert_eq!(
        rt.host.receipt(&rid(2)).unwrap().state,
        ReceiptState::Executing
    );
    assert_eq!(rt.pty.dispatch_attempts, 2);
    rt.restart("12121212-1212-4212-8212-121212121212", 9);
    assert_eq!(
        rt.pty.dispatch_attempts, 2,
        "executing is never dispatched again"
    );
    assert_eq!(
        rt.host.receipt(&rid(2)).unwrap().state,
        ReceiptState::OutcomeUnknown
    );
    // A reconciliation that establishes the outcome reports it.
    let mut rt = setup();
    let e = hold(&mut rt, "c1", S1);
    let m = submit(&rt, "c1", S1, e, 1, "prompt");
    rt.send("c1", &m);
    rt.reconcile_answer = DispatchReport::Completed { detail: None };
    rt.restart(GEN2, 8);
    assert_eq!(
        rt.host.receipt(&rid(1)).unwrap().state,
        ReceiptState::Completed
    );
}

#[test]
fn failed_durable_writes() {
    // `accepted` can't be recorded: busy, nothing recorded, retry works.
    let mut rt = setup();
    let e = hold(&mut rt, "c1", S1);
    rt.host.journal_mut().fail_next_fsync();
    let m = submit(&rt, "c1", S1, e, 1, "prompt");
    rt.send("c1", &m);
    assert_error(&only(&mut rt, "c1"), "busy");
    assert!(rt.host.receipt(&rid(1)).is_none());
    assert_eq!(rt.pty.dispatch_attempts, 0);
    rt.send("c1", &m);
    assert_eq!(
        rt.host.receipt(&rid(1)).unwrap().state,
        ReceiptState::Executing
    );

    // `executing` can't be recorded: rejected before any side effect.
    let mut rt = setup();
    let e = hold(&mut rt, "c1", S1);
    rt.host.journal_mut().fail_fsync_of(2);
    let m = submit(&rt, "c1", S1, e, 1, "prompt");
    rt.send("c1", &m);
    assert_eq!(
        receipts_of(&mut rt, "c1"),
        vec![st("accepted", ""), st("rejected", DETAIL_NOT_RECORDED)]
    );
    assert_eq!(rt.pty.dispatch_attempts, 0);

    // A final state that can't be recorded isn't reported until it is.
    let mut rt = setup();
    let e = hold(&mut rt, "c1", S1);
    let m = submit(&rt, "c1", S1, e, 1, "prompt");
    rt.send("c1", &m);
    got(&mut rt, "c1");
    rt.host.journal_mut().fail_next_fsync();
    rt.dispatch_report(&rid(1), DispatchReport::FailedAfterPossibleEffect);
    assert!(got(&mut rt, "c1").is_empty());
    assert_eq!(
        rt.host.receipt(&rid(1)).unwrap().state,
        ReceiptState::Executing
    );
    rt.set_now(1);
    assert_eq!(
        receipts_of(&mut rt, "c1"),
        vec![st("outcome_unknown", DETAIL_WRITE_INTERRUPTED)]
    );
    // The lease grant's epoch reservation is durable too.
    let mut rt = setup();
    rt.host.journal_mut().fail_next_fsync();
    let m = acquire(&rt, "c1", S1, false);
    rt.send("c1", &m);
    assert_error(&only(&mut rt, "c1"), "busy");
    assert_eq!(rt.host.lease_holder(S1), None);
}

#[test]
fn process_end_and_observation_windows() {
    let mut rt = setup();
    let e = hold(&mut rt, "c1", S1);
    let m = submit(&rt, "c1", S1, e, 1, "prompt");
    rt.send("c1", &m);
    got(&mut rt, "c1");
    rt.process_exited(S1);
    let msgs = got(&mut rt, "c1");
    let ended = msgs.iter().find(|m| m["op"] == "lease_changed").unwrap();
    assert_eq!(ended["reason"], "process_ended");
    let r = msgs.iter().find(|m| m["op"] == "receipt").unwrap();
    assert_eq!(
        (r["state"].clone(), r["detail"].clone()),
        (json!("outcome_unknown"), json!(DETAIL_AGENT_EXITED))
    );
    let m = submit(&rt, "c1", S1, e + 1, 2, "prompt");
    rt.send("c1", &m);
    assert_error(&only(&mut rt, "c1"), "stale_lease");

    // interrupt: nothing observed within 10 s; stop: completes on exit.
    let mut rt = setup();
    let e = hold(&mut rt, "c1", S2);
    let m = submit(&rt, "c1", S2, e, 1, "interrupt");
    rt.send("c1", &m);
    let m = submit(&rt, "c1", S2, e, 2, "stop");
    rt.send("c1", &m);
    got(&mut rt, "c1");
    rt.set_now(OBSERVE_MS - 1);
    assert!(receipts_of(&mut rt, "c1").is_empty());
    rt.set_now(OBSERVE_MS);
    let r = rt.host.receipt(&rid(1)).unwrap();
    assert_eq!(r.detail.as_deref(), Some(DETAIL_NO_INTERRUPT));
    let r = rt.host.receipt(&rid(2)).unwrap();
    assert_eq!(r.detail.as_deref(), Some(DETAIL_STILL_RUNNING));

    let mut rt = setup();
    let e = hold(&mut rt, "c1", S2);
    let m = submit(&rt, "c1", S2, e, 1, "stop");
    rt.send("c1", &m);
    rt.process_exited(S2);
    assert_eq!(
        rt.host.receipt(&rid(1)).unwrap().state,
        ReceiptState::Completed
    );
    // A stop that could not be delivered is rejected.
    let mut rt = setup();
    let e = hold(&mut rt, "c1", S2);
    rt.pty.fail_next_enqueue = true;
    let m = submit(&rt, "c1", S2, e, 1, "stop");
    rt.send("c1", &m);
    let r = rt.host.receipt(&rid(1)).unwrap();
    assert_eq!(
        (r.state, r.detail.as_deref()),
        (ReceiptState::Rejected, Some(DETAIL_STOP_FAILED))
    );
}

#[test]
fn closed_session_refuses_submissions_and_rejects_queued_work() {
    let mut rt = setup();
    let e = hold(&mut rt, "c1", S1);
    for n in [1, 2] {
        let m = submit(&rt, "c1", S1, e, n, "prompt");
        rt.send("c1", &m);
    }
    got(&mut rt, "c1");
    rt.close_session(S1);
    let msgs = got(&mut rt, "c1");
    let r = msgs.iter().find(|m| m["op"] == "receipt").unwrap();
    assert_eq!(r["request_id"], rid(2));
    assert_eq!(r["detail"], DETAIL_SESSION_CLOSED);
    let m = acquire(&rt, "c1", S1, false);
    rt.send("c1", &m);
    assert_error(&only(&mut rt, "c1"), "session_closed");
    // Receipts stay readable while the session is retained.
    let q = query(&rt, "c1", target_with(S1, 1), vec![rid(1), rid(2)]);
    rt.send("c1", &q);
    assert_eq!(only(&mut rt, "c1")["receipts"].as_array().unwrap().len(), 2);
    // ... for 7 days after it closed.
    rt.set_now(RECEIPT_RETENTION_MS);
    assert!(rt.host.receipt(&rid(1)).is_none());
}

#[test]
fn receipt_query_is_scoped_to_the_exact_target() {
    let mut rt = setup();
    let e1 = hold(&mut rt, "c1", S1);
    let e2 = hold(&mut rt, "c1", S2);
    let m = submit(&rt, "c1", S1, e1, 1, "prompt");
    rt.send("c1", &m);
    let m = submit(&rt, "c1", S2, e2, 2, "prompt");
    rt.send("c1", &m);
    got(&mut rt, "c1");
    let unknown = rid(99);
    let q = query(
        &rt,
        "c1",
        target_with(S1, 1),
        vec![rid(1), rid(2), unknown, rid(1)],
    );
    rt.send("c1", &q);
    let r = only(&mut rt, "c1");
    let ids: Vec<&str> = r["receipts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|x| x["request_id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec![rid(1).as_str()]);
    // Another client with view sees the target's receipts; no view, none.
    got(&mut rt, "v");
    let q = query(&rt, "v", target_with(S2, 1), vec![rid(1), rid(2)]);
    rt.send("v", &q);
    assert_eq!(only(&mut rt, "v")["receipts"][0]["request_id"], rid(2));
    let blind = "88888888-8888-4888-8888-888888888888";
    rt.connect_only("b", blind, vec![Permission::Control], AUTHORIZATION_MS);
    rt.send("b", &session("hello", json!({})));
    got(&mut rt, "b");
    let q = query(&rt, "b", target_with(S1, 1), vec![rid(1)]);
    rt.send("b", &q);
    let err = only(&mut rt, "b");
    assert_error(&err, "unknown_session");
    // Errors never carry current values or details.
    assert_eq!(
        err.as_object().unwrap().keys().collect::<Vec<_>>(),
        vec!["code", "id", "op", "re", "v"]
    );
    let q = query(&rt, "c1", target_with(S1, 5), vec![rid(1)]);
    rt.send("c1", &q);
    assert_error(&only(&mut rt, "c1"), "stale_target");
    assert_eq!(rt.counter_receipts_visible(), (2, 2, 0));
    rt.remove_session(S2);
    got(&mut rt, "c1");
    let q = query(&rt, "c1", target_with(S2, 1), vec![rid(2)]);
    rt.send("c1", &q);
    assert_error(&only(&mut rt, "c1"), "unknown_session");
}

#[test]
fn receipt_and_in_flight_limits() {
    let mut rt = setup_with(HostConfig {
        max_receipts_per_session: 2,
        ..HostConfig::default()
    });
    let e = hold(&mut rt, "c1", S1);
    for n in [1, 2, 3] {
        let m = submit(&rt, "c1", S1, e, n, "prompt");
        rt.send("c1", &m);
    }
    let msgs = got(&mut rt, "c1");
    assert_error(msgs.last().unwrap(), "receipt_limit");
    // Recorded receipts are still answered at the limit.
    let m = submit(&rt, "c1", S1, e, 2, "prompt");
    rt.send("c1", &m);
    assert_eq!(only(&mut rt, "c1")["op"], "receipt");

    let mut rt = setup();
    let e = hold(&mut rt, "c1", S1);
    for n in 0..wire::MAX_IN_FLIGHT as u64 {
        let m = submit(&rt, "c1", S1, e, n, "prompt");
        rt.send("c1", &m);
    }
    got(&mut rt, "c1");
    let m = submit(&rt, "c1", S1, e, 1000, "prompt");
    rt.send("c1", &m);
    assert_error(&only(&mut rt, "c1"), "busy");
}

#[test]
fn chat_submit_is_a_bound_prompt_submit() {
    let mut rt = setup();
    let e = hold(&mut rt, "c1", S1);
    let chat = |rt: &FakeRuntime, agent: &str, n: u64| {
        json!({"type": "agentChat", "data": {"v": 1, "op": "submit", "conversationId": "c",
            "agentId": agent, "generation": P1, "requestId": rid(n), "text": "run the tests",
            "binding": binding(rt, "c1", S1, Some(e))}})
    };
    let m = chat(&rt, S1, 1);
    rt.send("c1", &m);
    assert_eq!(
        receipts_of(&mut rt, "c1"),
        vec![st("accepted", ""), st("executing", "")]
    );
    // The same request through session-v1 is a duplicate (same digest).
    let m = submit(&rt, "c1", S1, e, 1, "prompt");
    rt.send("c1", &m);
    assert_eq!(only(&mut rt, "c1")["state"], "executing");
    assert_eq!(rt.pty.dispatch_attempts, 1);
    // agentId must equal the binding's session.
    let m = chat(&rt, S2, 2);
    rt.send("c1", &m);
    assert_error(&only(&mut rt, "c1"), "stale_target");
}

impl FakeRuntime {
    fn event_reconnect(&mut self, client: &str, att_gen: &str) {
        self.attach(client, att_gen).unwrap();
    }

    fn restart(&mut self, att_gen: &str, epoch: u64) {
        use super::fixtures::{HostEvent, HostUnderTest};
        let now = self.now();
        let event = HostEvent::RestartRuntime {
            runtime_gen: att_gen.into(),
            runtime_epoch: epoch,
        };
        self.event(&event, now).unwrap();
    }

    fn local_input(&mut self, s: &str, bytes: &[u8]) {
        let fx = self.host.local_input(s, bytes.to_vec());
        self.apply(fx);
    }

    fn dispatch_report(&mut self, request_id: &str, report: DispatchReport) {
        let fx = self.host.dispatch_report(request_id, report);
        self.apply(fx);
    }

    fn process_exited(&mut self, s: &str) {
        let fx = self.host.process_exited(s, Some("0".into()));
        self.apply(fx);
    }

    fn close_session(&mut self, s: &str) {
        let fx = self.host.close_session(s);
        self.apply(fx);
    }

    fn remove_session(&mut self, s: &str) {
        let fx = self.host.remove_session(s);
        self.apply(fx);
    }

    fn change_trust_gen(&mut self, n: u64) {
        let fx = self.host.change_trust_gen(n).unwrap();
        self.apply(fx);
    }

    fn counter_receipts_visible(&self) -> (usize, usize, usize) {
        let h = &self.host;
        (
            h.receipts_visible(C1),
            h.receipts_visible(V),
            h.receipts_visible("88888888-8888-4888-8888-888888888888"),
        )
    }
}

trait AppendOk {
    fn append_ok(&mut self, r: Record);
}

impl AppendOk for MemJournal {
    fn append_ok(&mut self, r: Record) {
        use super::journal::Journal;
        self.append(r).unwrap();
    }
}

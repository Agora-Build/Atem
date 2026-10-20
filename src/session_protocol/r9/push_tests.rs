//! Sealed push hints and seen on the host (§R9.9) in process: the r9
//! engine with the real device list and session host (`tests::Rig`), the
//! relay played by the test (what Atem sends it, its `push_ack`s), and
//! clients that are the shared core: the phone opens its own sealed part
//! with its `enc_key`, the Mac its own.
use super::push::{HostPush, MAX_APPROVALS, Signer};
use super::tests::{PGEN, PGEN_B, Rig, SID, SID_B, WAIT_MS, phone};
use super::*;
use crate::session_protocol::host::ApprovalInfo;
use crate::session_protocol::membership::r9log::{self, MAC, enc};
use atem_client::SignedObject;
use atem_client::connect::Event as CEvent;
use atem_client::push::{
    self as cpush, ApprovalKey, Hint, HintPlain, HintState, Identity, Seen, Verifier,
};
use serde_json::json;

fn info() -> ApprovalInfo {
    ApprovalInfo {
        tool: "Bash".into(),
        summary: "npm test --secret-flag".into(),
        always_rules: Vec::new(),
    }
}

/// The session host opens an approval on `sid`/`pg` (as the runtime's
/// worker report does); its push effects reach the engine.
fn open(rig: &mut Rig, sid: &str, pg: &str) -> String {
    let (opened, fx) = rig.rt.host.open_approval(sid, pg, info(), rig.now.mono);
    rig.rt.apply(fx);
    rig.route();
    opened.unwrap()
}

fn close(rig: &mut Rig, approval: &str, reason: r8::ApprovalCloseReason) {
    let fx = rig.rt.host.close_approval(approval, reason);
    rig.rt.apply(fx);
    rig.route();
}

fn object(v: &Value) -> SignedObject {
    SignedObject::parse(v.to_string().as_bytes()).unwrap()
}

/// The hints of a `push_hint`, verified as a client does.
fn hints(rig: &Rig, message: &Value) -> Vec<Hint> {
    assert_eq!(message["type"], "relay", "{message}");
    assert_eq!(message["op"], "push_hint", "{message}");
    message["hints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            Hint::verify(
                &object(h),
                &rig.log.log,
                rig.now.host.wall_ms,
                Verifier::Client,
            )
            .unwrap()
        })
        .collect()
}

fn recipient(h: &Hint) -> &str {
    match h.state() {
        HintState::Open { device_id, .. } => device_id,
        HintState::Resolved { .. } => panic!("a resolved hint"),
    }
}

/// `approval_seen` from `handle` (its binding on `sid`).
fn seen(rig: &mut Rig, handle: &str, binding: &Value, approval: &str) -> Vec<CEvent> {
    rig.send(
        handle,
        &json!({"type": "session", "data": {"v": 1, "op": "approval_seen",
            "id": uuid::Uuid::new_v4().to_string(), "binding": binding, "approval_id": approval}}),
    );
    rig.events(handle)
}

fn ack(identities: &[Identity]) -> Value {
    cpush::push_ack(identities)
}

/// An approval opens: one `push_hint` with an open hint per native member
/// with `control` (the Mac and the phone; never the bot), signed with the
/// host channel key, `created_at` now on the host clock and `expires_at`
/// the hook's wait later; each device opens only its own sealed part,
/// and neither tool nor summary is on the wire in clear.
#[test]
fn an_approval_sends_one_sealed_hint_per_control_device() {
    let mut rig = Rig::new();
    rig.link_up();
    let wall = rig.now.host.wall_ms;
    let ap = open(&mut rig, SID, PGEN);
    let out = rig.relay_out();
    assert_eq!(out.len(), 1, "{out:?}");
    let text = out[0].to_string();
    assert!(!text.contains("npm test"), "clear text on the wire: {text}");
    assert!(!text.contains("push_approval"), "{text}");
    let hs = hints(&rig, &out[0]);
    let devices: Vec<&str> = hs.iter().map(recipient).collect();
    assert_eq!(devices, [MAC, "dev-phone"]);
    for h in &hs {
        assert_eq!(h.key().approval_id, ap);
        assert_eq!(h.key().session_id, SID);
        assert_eq!(h.key().process_gen, PGEN);
        assert_eq!(h.key().host_id, super::tests::HOST);
        assert_eq!(h.key().host_trust_gen, 1);
        assert_eq!(h.created_at(), wall);
        assert_eq!(h.expires_at(), wall + WAIT_MS);
        h.check_sealed().unwrap();
    }
    let keys = &rig.log.keys;
    let plain = hs[1].open(keys, &enc("dev-phone"), "dev-phone").unwrap();
    assert_eq!(
        plain,
        HintPlain {
            tool: "Bash".into(),
            summary: "npm test --secret-flag".into()
        }
    );
    let mac = hs[0].open(keys, &enc(MAC), MAC).unwrap();
    assert_eq!(mac, plain);
    // Each sealed part is its device's only.
    assert!(hs[0].open(keys, &enc("dev-phone"), "dev-phone").is_err());
    assert!(hs[1].open(keys, &enc(MAC), "dev-phone").is_err());
    // Nothing more without time passing.
    assert!(rig.relay_out().is_empty());
}

/// Lost acks: the same bytes again every 10 s until the relay
/// acknowledges each hint; a reconnect sends everything unacknowledged at
/// once (an approval opened while the link was down included).
#[test]
fn hints_are_resent_until_acknowledged_and_at_a_reconnect() {
    let mut rig = Rig::new();
    rig.link_up();
    open(&mut rig, SID, PGEN);
    let first = rig.relay_out();
    assert_eq!(first.len(), 1);
    rig.advance(9_000);
    assert!(rig.relay_out().is_empty(), "not before 10 s");
    rig.advance(1_000);
    assert_eq!(rig.relay_out(), first, "the same bytes");
    // The relay acknowledges the phone's only: the Mac's goes on alone.
    let hs = hints(&rig, &first[0]);
    rig.relay_in(&ack(&[hs[1].identity()]));
    rig.advance(10_000);
    let again = rig.relay_out();
    assert_eq!(again.len(), 1);
    assert_eq!(again[0]["hints"], json!([first[0]["hints"][0]]));
    rig.relay_in(&ack(&[hs[0].identity()]));
    rig.advance(10_000);
    assert!(rig.relay_out().is_empty(), "both acknowledged");
    assert_eq!(rig.engine.push_status(rig.now.host.wall_ms).pending, 0);

    // The link drops: an approval opened meanwhile goes at the reconnect,
    // with no 10 s wait, and unacknowledged ones go with it.
    rig.link_down();
    let ap2 = open(&mut rig, SID_B, PGEN_B);
    rig.advance(10_000);
    assert!(rig.relay_out().is_empty(), "no link");
    let status = rig.engine.push_status(rig.now.host.wall_ms);
    assert_eq!(status.pending, 2);
    assert_eq!(status.oldest_ms, Some(10_000));
    rig.link_up();
    let out = rig.relay_out();
    assert_eq!(out.len(), 1, "{out:?}");
    let hs = hints(&rig, &out[0]);
    assert!(hs.iter().all(|h| h.key().approval_id == ap2));
    // The resend schedule restarts from the reconnect.
    rig.advance(10_000);
    assert_eq!(rig.relay_out(), out);
}

/// The phone's first `approval_seen` is signed (host channel key, the
/// approval's identity and `created_at`, `seen_at` now) and sent as
/// `push_seen`; a repeat is answered `seen` and never re-signed; a lost
/// delivery is resent with the same bytes until acknowledged.
#[test]
fn a_seen_is_signed_once_resent_until_acked_and_deduplicated() {
    let mut rig = Rig::new();
    rig.link_up();
    rig.connect("phone", phone());
    let ap = open(&mut rig, SID, PGEN);
    let opens = rig.relay_out();
    let hs = hints(&rig, &opens[0]);
    rig.relay_in(&ack(&hs.iter().map(Hint::identity).collect::<Vec<_>>()));
    let b = rig.binding("phone", SID);
    rig.advance(2_000);
    let events = seen(&mut rig, "phone", &b, &ap);
    assert!(events.iter().any(|e| matches!(e, CEvent::Seen { .. })));
    let out = rig.relay_out();
    assert_eq!(out.len(), 1, "{out:?}");
    assert_eq!(out[0]["op"], "push_seen");
    let s = Seen::verify(&object(&out[0]["seen"]), &rig.log.log).unwrap();
    assert_eq!(s.device_id(), "dev-phone");
    assert_eq!(s.key(), hs[0].key());
    assert_eq!(s.created_at(), hs[0].created_at());
    assert_eq!(s.seen_at(), rig.now.host.wall_ms);
    assert!(s.in_window(hs[0].created_at()));
    // A repeat: `seen`, nothing signed.
    let events = seen(&mut rig, "phone", &b, &ap);
    assert!(events.iter().any(|e| matches!(e, CEvent::Seen { .. })));
    assert!(rig.relay_out().is_empty());
    // Lost on the way: resent as is.
    rig.relay_down = true;
    rig.advance(10_000);
    assert_eq!(rig.relay_out(), Vec::<Value>::new());
    rig.relay_down = false;
    rig.advance(10_000);
    assert_eq!(rig.relay_out(), out, "the first seen's bytes");
    rig.relay_in(&ack(&[s.identity()]));
    rig.advance(30_000);
    assert!(rig.relay_out().is_empty());
}

/// A seen after the approval resolved, or naming another process
/// generation, is `stale_target` and signs nothing; a service with the
/// `approval` op (never a hint recipient) is answered `seen` and signs
/// nothing.
#[test]
fn a_seen_after_resolution_from_another_process_or_a_service_signs_nothing() {
    let wall = r9log::host_now().wall_ms;
    let mut rig = Rig::with(|log| {
        log.add_service(
            "svc-appr",
            &[super::tests::HOST],
            None,
            &["approval", "view"],
            wall + 3_600_000,
        );
    });
    rig.link_up();
    rig.connect("phone", phone());
    let ap = open(&mut rig, SID, PGEN);
    rig.relay_out();
    let b = rig.binding("phone", SID);
    let mut other = b.clone();
    other["target"]["process_gen"] = json!(PGEN_B);
    let events = seen(&mut rig, "phone", &other, &ap);
    assert_eq!(
        Rig::last_error(&events).map(|e| e.0),
        Some("stale_target".into())
    );
    assert!(rig.relay_out().is_empty());
    rig.advance(1_000);
    rig.connect(
        "svc",
        atem_client::connect::Identity::service("svc-appr", r9log::auth("svc-appr")),
    );
    let sb = rig.binding("svc", SID);
    let events = seen(&mut rig, "svc", &sb, &ap);
    assert!(
        events.iter().any(|e| matches!(e, CEvent::Seen { .. })),
        "{events:?}"
    );
    assert!(rig.relay_out().is_empty(), "a service gets no hint");
    // Resolved: the resolved hint, then a seen reopens nothing.
    close(&mut rig, &ap, r8::ApprovalCloseReason::AnsweredTerminal);
    let out = rig.relay_out();
    assert_eq!(out.len(), 1);
    let resolved = hints(&rig, &out[0]);
    assert!(matches!(
        resolved[0].state(),
        HintState::Resolved { reason, .. } if reason == "answered_terminal"
    ));
    rig.events("phone");
    let events = seen(&mut rig, "phone", &b, &ap);
    assert_eq!(
        Rig::last_error(&events).map(|e| e.0),
        Some("stale_target".into())
    );
    assert!(rig.relay_out().is_empty());
}

/// The resolved hint replaces the opens and seens still waiting (it
/// dominates them at the relay), is resent until acknowledged, and its ack
/// ends the approval.
#[test]
fn a_resolved_hint_replaces_the_opens_and_its_ack_ends_the_approval() {
    let mut rig = Rig::new();
    rig.link_up();
    rig.connect("phone", phone());
    let ap = open(&mut rig, SID, PGEN);
    rig.relay_out();
    let b = rig.binding("phone", SID);
    seen(&mut rig, "phone", &b, &ap);
    assert_eq!(rig.relay_out().len(), 1);
    assert_eq!(rig.engine.push_status(rig.now.host.wall_ms).pending, 3);
    close(&mut rig, &ap, r8::ApprovalCloseReason::Interrupted);
    let out = rig.relay_out();
    assert_eq!(out.len(), 1);
    let r = hints(&rig, &out[0]);
    assert_eq!(r.len(), 1);
    assert_eq!(rig.engine.push_status(rig.now.host.wall_ms).pending, 1);
    rig.advance(10_000);
    assert_eq!(rig.relay_out(), out, "only the resolved, the same bytes");
    rig.relay_in(&ack(&[r[0].identity()]));
    rig.advance(10_000);
    assert!(rig.relay_out().is_empty());
    assert_eq!(rig.engine.push_status(rig.now.host.wall_ms).pending, 0);
    assert!(!rig.engine.push.tracks(&ap));
    // An ack naming another approval, process or trust generation ends
    // nothing (the whole identity is compared).
    let ap2 = open(&mut rig, SID, PGEN);
    let out = rig.relay_out();
    let hs = hints(&rig, &out[0]);
    let mut wrong = hs[0].key().clone();
    wrong.process_gen = PGEN_B.into();
    rig.relay_in(&ack(&[Identity::Resolved { key: wrong.clone() }]));
    wrong.process_gen = PGEN.into();
    wrong.host_trust_gen = 2;
    rig.relay_in(&ack(&[Identity::Open {
        key: wrong,
        device_id: "dev-phone".into(),
    }]));
    assert!(rig.engine.push.tracks(&ap2));
    assert_eq!(rig.engine.push_status(rig.now.host.wall_ms).pending, 2);
}

/// Nothing is signed or sent while the device list is held or frozen, or
/// the journal halted; what was queued is dropped when it starts.
#[test]
fn nothing_is_pushed_while_held_frozen_or_the_journal_halted() {
    // Held at start (a recorded fault).
    let mut rig = Rig::new();
    std::fs::write(
        &rig.pairing.fault,
        br#"{"v":1,"runtime_epoch":1,"file":"membership.json","at":1}"#,
    )
    .unwrap();
    let mut fences = crate::session_protocol::membership::HostFences::new(&mut rig.rt.host);
    let (m, _) = MembershipHost::open(&rig.pairing, &rig.journal, 2, &rig.now.host, &mut fences)
        .unwrap()
        .unwrap();
    assert!(m.held().is_some());
    rig.m = Some(m);
    rig.link_up();
    open(&mut rig, SID, PGEN);
    rig.advance(10_000);
    assert!(rig.relay_out().is_empty(), "held");
    assert_eq!(
        rig.engine.push_status(rig.now.host.wall_ms).suppressed,
        Some("device list held")
    );

    // Frozen while an approval's hints wait: dropped, nothing after.
    let mut rig = Rig::new();
    rig.link_up();
    rig.connect(
        "mac",
        atem_client::connect::Identity::native(MAC, r9log::auth(MAC)),
    );
    let ap = open(&mut rig, SID, PGEN);
    assert_eq!(rig.relay_out().len(), 1);
    let conflict = rig.log.conflicting_add("dev-x");
    let mono = rig.now.host.mono_ms;
    let entry = SignedObject::parse(conflict.to_string().as_bytes()).unwrap();
    let (_, frame) = rig.attached("mac").send_membership(&[entry], mono).unwrap();
    rig.send_frame_raw("mac", &frame);
    assert!(rig.m.as_ref().unwrap().is_frozen());
    rig.advance(10_000);
    assert!(rig.relay_out().is_empty(), "frozen: no resend");
    close(&mut rig, &ap, r8::ApprovalCloseReason::AnsweredTerminal);
    open(&mut rig, SID_B, PGEN_B);
    rig.advance(10_000);
    assert!(rig.relay_out().is_empty(), "frozen: nothing new");
    let status = rig.engine.push_status(rig.now.host.wall_ms);
    assert_eq!(status.pending, 0);
    assert_eq!(status.suppressed, Some("device list frozen"));

    // The journal halts (a failed write) with an approval pending.
    let mut rig = Rig::new();
    rig.link_up();
    rig.connect("phone", phone());
    let ap = open(&mut rig, SID, PGEN);
    assert_eq!(rig.relay_out().len(), 1);
    let b = rig.binding("phone", SID);
    use crate::session_protocol::fake_runtime::FailFsync;
    rig.rt.host.journal_mut().fail_next_fsync();
    rig.send(
        "phone",
        &json!({"type": "session", "data": {"v": 1, "op": "submit", "id": uuid::Uuid::new_v4().to_string(),
            "binding": b, "kind": "approval", "request_id": uuid::Uuid::new_v4().to_string(),
            "payload": {"approval_id": ap, "decision": "allow_once"}}}),
    );
    assert!(rig.rt.host.journal_halted());
    rig.advance(10_000);
    assert!(rig.relay_out().is_empty(), "halted: no resend");
    assert_eq!(
        rig.engine.push_status(rig.now.host.wall_ms).suppressed,
        Some("journal halted")
    );
}

/// The guard on Atem's side: an approval whose hints couldn't go before
/// `expires_at − 15 s` (the link was down) sends no open and no seen at
/// the reconnect; its resolved still goes (it only cancels).
#[test]
fn no_open_or_seen_is_sent_at_or_after_the_guard() {
    let mut rig = Rig::new();
    rig.link_up();
    rig.connect("phone", phone());
    let b = rig.binding("phone", SID);
    rig.link_down();
    let ap = open(&mut rig, SID, PGEN);
    // 1 ms before the guard: it would still go.
    rig.advance(WAIT_MS - 15_000 - 1);
    rig.link_up();
    let out = rig.relay_out();
    assert_eq!(out.len(), 1);
    rig.link_down();
    rig.advance(1);
    rig.link_up();
    assert!(rig.relay_out().is_empty(), "at the guard: no open");
    // A seen at the guard (on a new channel) is answered, never signed.
    rig.connect("phone2", phone());
    let b2 = rig.binding("phone2", SID);
    let events = seen(&mut rig, "phone2", &b2, &ap);
    assert!(events.iter().any(|e| matches!(e, CEvent::Seen { .. })));
    assert!(rig.relay_out().is_empty(), "no seen past the guard");
    drop(b);
    close(&mut rig, &ap, r8::ApprovalCloseReason::TimedOut);
    let out = rig.relay_out();
    assert_eq!(out.len(), 1);
    assert!(matches!(
        hints(&rig, &out[0])[0].state(),
        HintState::Resolved { reason, .. } if reason == "timed_out"
    ));
}

/// Bounded: at most `MAX_APPROVALS` approvals tracked (the oldest
/// forgotten with what it still had to send); a re-pin drops everything.
#[test]
fn the_push_state_is_bounded_and_a_repin_drops_it() {
    let rig = Rig::new();
    let wall = rig.now.host.wall_ms;
    let m = rig.m.as_ref().unwrap();
    let signer = || Signer {
        log: m.membership(),
        key: &rig.key,
    };
    let mut push = HostPush::default();
    push.link_up(None, wall);
    let plain = HintPlain {
        tool: "Bash".into(),
        summary: "ls".into(),
    };
    let key = |n: usize| {
        ApprovalKey::new(
            m.membership(),
            super::tests::HOST,
            1,
            SID,
            PGEN,
            &format!("8c3e9d6b-1f40-4b52-8dae-{n:012x}"),
        )
    };
    for n in 0..MAX_APPROVALS + 6 {
        push.opened(key(n), wall, wall + WAIT_MS, &plain, Some(signer()), wall);
    }
    assert_eq!(push.status(wall).pending, MAX_APPROVALS * 2);
    assert!(!push.tracks(&key(0).approval_id));
    assert!(push.tracks(&key(MAX_APPROVALS + 5).approval_id));
    // A reconnect resends every tracked approval's hints, once each,
    // each message under the cap.
    push.link_down();
    push.link_up(None, wall + 1);
    let mut sent = Vec::new();
    push.flush(&mut |text| {
        sent.push(text);
        true
    });
    let mut hints = 0;
    for text in &sent {
        assert!(
            text.len() <= super::push::MAX_MESSAGE_BYTES,
            "{}",
            text.len()
        );
        let v: Value = serde_json::from_str(text).unwrap();
        hints += v["hints"].as_array().unwrap().len();
    }
    assert_eq!(hints, MAX_APPROVALS * 2);
    push.reset();
    assert_eq!(push.status(wall).pending, 0);
    // Opened within 15 s of its expiry: no hint at all.
    push.opened(key(1), wall, wall + 15_000, &plain, Some(signer()), wall);
    assert_eq!(push.status(wall).pending, 0);
    // An approval forgotten 300 s after its expiry.
    push.opened(key(2), wall, wall + WAIT_MS, &plain, Some(signer()), wall);
    push.tick(None, wall + WAIT_MS + 300_000);
    assert!(!push.tracks(&key(2).approval_id));
    assert_eq!(push.status(wall).pending, 0);
}

/// §R9.6/§R9.9 recipients: a view-only native device, a service (even one
/// with the `approval` op) and a removed device get no hint; only native
/// members with `control` at the host's head do.
#[test]
fn only_native_members_with_control_at_the_head_get_hints() {
    let wall = r9log::host_now().wall_ms;
    let mut rig = Rig::with(|log| {
        log.add_native("dev-tablet", &["view"]);
        log.add_native("dev-old", &["control", "view"]);
        log.remove("dev-old");
        log.add_service(
            "svc-appr",
            &[super::tests::HOST],
            None,
            &["approval", "view"],
            wall + 3_600_000,
        );
    });
    rig.link_up();
    open(&mut rig, SID, PGEN);
    let out = rig.relay_out();
    let devices: Vec<String> = hints(&rig, &out[0])
        .iter()
        .map(|h| recipient(h).to_string())
        .collect();
    assert_eq!(devices, [MAC, "dev-phone"]);
}

/// A batch of hints over `MAX_MESSAGE_BYTES` goes as several `push_hint`
/// messages, each under it, every hint once and in order; a small one as
/// is.
#[test]
fn an_oversize_push_hint_is_split_by_bytes() {
    use super::push::{MAX_MESSAGE_BYTES, split};
    let hints: Vec<Value> = (0..700)
        .map(|i| json!({"body": {"n": i}, "sig": "x".repeat(1_000)}))
        .collect();
    let message = json!({"type": "relay", "op": "push_hint", "hints": hints});
    assert!(message.to_string().len() > 2 * MAX_MESSAGE_BYTES);
    let parts = split(message);
    assert!(parts.len() >= 3, "{}", parts.len());
    let mut n = 0;
    for p in &parts {
        assert!(p.len() <= MAX_MESSAGE_BYTES, "{}", p.len());
        let v: Value = serde_json::from_str(p).unwrap();
        assert_eq!(
            (v["type"].as_str(), v["op"].as_str()),
            (Some("relay"), Some("push_hint"))
        );
        for h in v["hints"].as_array().unwrap() {
            assert_eq!(h["body"]["n"], n);
            n += 1;
        }
    }
    assert_eq!(n, 700);
    let small = json!({"type": "relay", "op": "push_hint", "hints": [{"a": 1}]});
    assert_eq!(split(small.clone()), vec![small.to_string()]);
}

/// §R9.9/§R9.6: a device removed while its open hint isn't acknowledged
/// never gets it again: the next resend and a reconnect carry the Mac's
/// only; the resolved hint still goes.
#[test]
fn a_device_removed_mid_approval_gets_no_more_hints() {
    let mut rig = Rig::new();
    rig.link_up();
    rig.connect(
        "mac",
        atem_client::connect::Identity::native(MAC, r9log::auth(MAC)),
    );
    let ap = open(&mut rig, SID, PGEN);
    let first = rig.relay_out();
    assert_eq!(hints(&rig, &first[0]).len(), 2);
    let removal = rig.log.remove("dev-phone");
    let mono = rig.now.host.mono_ms;
    let entry = SignedObject::parse(removal.to_string().as_bytes()).unwrap();
    let (_, frame) = rig.attached("mac").send_membership(&[entry], mono).unwrap();
    rig.send_frame_raw("mac", &frame);
    assert_eq!(rig.engine.push_status(rig.now.host.wall_ms).pending, 1);
    rig.advance(10_000);
    let out = rig.relay_out();
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0]["hints"],
        json!([first[0]["hints"][0]]),
        "the Mac's only"
    );
    rig.link_down();
    rig.link_up();
    let out = rig.relay_out();
    let devices: Vec<String> = hints(&rig, &out[0])
        .iter()
        .map(|h| recipient(h).to_string())
        .collect();
    assert_eq!(devices, [MAC]);
    close(&mut rig, &ap, r8::ApprovalCloseReason::AnsweredTerminal);
    let out = rig.relay_out();
    assert!(matches!(
        hints(&rig, &out[0])[0].state(),
        HintState::Resolved { .. }
    ));
}

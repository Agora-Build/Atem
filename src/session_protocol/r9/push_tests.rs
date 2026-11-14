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
    // Stamped with the host clock, as the runtime's bridge does.
    let (opened, fx) =
        rig.rt
            .host
            .open_approval_at(sid, pg, info(), rig.now.mono, rig.now.host.wall_ms);
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

/// Bounded: at most `MAX_APPROVALS` approvals tracked (every
/// published lifecycle kept, newer approvals unhinted); a re-pin drops
/// everything.
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
    // Every one published (the link is up): the first 64 are kept, the
    // newer 6 go unhinted.
    assert_eq!(push.status(wall).pending, MAX_APPROVALS * 2);
    assert!(push.tracks(&key(0).approval_id));
    assert!(!push.tracks(&key(MAX_APPROVALS).approval_id));
    assert_eq!(push.unhinted(), 6);
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

/// Carries `entry` (a signed membership entry, as JSON) on `handle`'s
/// channel.
fn carry(rig: &mut Rig, handle: &str, entry: &Value) {
    let mono = rig.now.host.mono_ms;
    let entry = SignedObject::parse(entry.to_string().as_bytes()).unwrap();
    let (_, frame) = rig
        .attached(handle)
        .send_membership(&[entry], mono)
        .unwrap();
    rig.send_frame_raw(handle, &frame);
}

/// §R9.9/§R9.6: a device demoted (`set_roles` without `control`) while its
/// open hint waits never gets it again; the Mac's goes on.
#[test]
fn a_device_demoted_mid_approval_gets_no_more_hints() {
    let mut rig = Rig::new();
    rig.link_up();
    rig.connect(
        "mac",
        atem_client::connect::Identity::native(MAC, r9log::auth(MAC)),
    );
    open(&mut rig, SID, PGEN);
    let first = rig.relay_out();
    assert_eq!(hints(&rig, &first[0]).len(), 2);
    let demotion = rig.log.set_native_roles("dev-phone", &["view"]);
    carry(&mut rig, "mac", &demotion);
    assert_eq!(rig.engine.push_status(rig.now.host.wall_ms).pending, 1);
    rig.advance(10_000);
    let out = rig.relay_out();
    assert_eq!(out.len(), 1);
    assert_eq!(
        out[0]["hints"],
        json!([first[0]["hints"][0]]),
        "the Mac's only"
    );
}

/// §R9.9: a device added with `control` after the open got no hint, so its
/// `approval_seen` is answered `seen` and nothing is signed; a recipient's
/// still is.
#[test]
fn a_device_added_after_the_open_is_answered_but_its_seen_not_signed() {
    let mut rig = Rig::new();
    rig.link_up();
    rig.connect(
        "mac",
        atem_client::connect::Identity::native(MAC, r9log::auth(MAC)),
    );
    let ap = open(&mut rig, SID, PGEN);
    rig.relay_out();
    let added = rig.log.add_native("dev-tab", &["control", "view"]);
    carry(&mut rig, "mac", &added);
    rig.advance(1_000);
    rig.connect(
        "tab",
        atem_client::connect::Identity::native("dev-tab", r9log::auth("dev-tab")),
    );
    let b = rig.binding("tab", SID);
    let events = seen(&mut rig, "tab", &b, &ap);
    assert!(
        events.iter().any(|e| matches!(e, CEvent::Seen { .. })),
        "{events:?}"
    );
    assert!(
        rig.relay_out().is_empty(),
        "not a recipient: nothing signed"
    );
    let b = rig.binding("mac", SID);
    seen(&mut rig, "mac", &b, &ap);
    let out = rig.relay_out();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0]["seen"]["body"]["device_id"], MAC);
}

/// The session host's own wall clock stands still while the machine
/// sleeps (an offset plus a monotonic clock); the host clock moves. An
/// approval opened after a "suspend" (the host wall 700 s ahead, the
/// monotonic clock not) is stamped with the host clock: hints go, with
/// `created_at` the card's and now.
#[test]
fn after_a_suspend_hints_carry_the_host_clock() {
    let mut rig = Rig::new();
    rig.link_up();
    rig.connect("phone", phone());
    rig.binding("phone", SID);
    rig.now.host.wall_ms += 700_000;
    let wall = rig.now.host.wall_ms;
    assert!(
        rig.rt.host.wall_ms() + 600_000 < wall,
        "the session host lags"
    );
    let ap = open(&mut rig, SID, PGEN);
    let out = rig.relay_out();
    assert_eq!(out.len(), 1, "hints still go");
    for h in hints(&rig, &out[0]) {
        assert_eq!(h.created_at(), wall);
        assert_eq!(h.expires_at(), wall + WAIT_MS);
    }
    let card = rig
        .events("phone")
        .into_iter()
        .find_map(|e| match e {
            CEvent::Session(m) => match m.op {
                r8::Op::ApprovalRequest(r) if r.approval_id == ap => Some(r),
                _ => None,
            },
            _ => None,
        })
        .expect("the card");
    assert_eq!(card.created_at, wall, "one created_at for card and hint");
}

// ── Capacity: published lifecycles are kept (Astation's Task 8 review) ──

/// Five sessions (the session host allows 16 pending approvals each).
fn five_sessions() -> (Rig, Vec<(String, String)>) {
    let sessions: Vec<(String, String)> = ["c", "d", "e", "f", "g"]
        .iter()
        .enumerate()
        .map(|(i, c)| {
            (
                format!("ses-{}", c.repeat(12)),
                format!("4444444{i}-4444-4444-8444-444444444444"),
            )
        })
        .collect();
    let json = Value::Array(
        sessions
            .iter()
            .map(|(s, p)| json!({"session_id": s, "process_gen": p, "chat": true}))
            .collect(),
    );
    (Rig::with_sessions(|_| {}, json), sessions)
}

/// The resolved hint of `ap` among what Atem sent the relay now, if any.
fn resolved_of(rig: &mut Rig, ap: &str) -> Option<Value> {
    let messages = rig.relay_out();
    let rig = &*rig;
    messages.iter().find_map(|m| {
        if m["op"] != "push_hint" {
            return None;
        }
        hints(rig, m).iter().find_map(|h| {
            (h.key().approval_id == ap && matches!(h.state(), HintState::Resolved { .. }))
                .then(|| h.object().to_json())
        })
    })
}

/// Approval A's open is delivered and acknowledged, then 63 more fill the
/// 64 tracked; the 65th gets no hint (counted), never at A's expense. A
/// is answered: its resolved hint goes, is resent byte-identical while
/// unacknowledged, and stops once acknowledged.
#[test]
fn a_published_approval_keeps_its_cancellation_past_capacity() {
    let (mut rig, s) = five_sessions();
    rig.link_up();
    let a = open(&mut rig, &s[0].0, &s[0].1);
    let out = rig.relay_out();
    let hs = hints(&rig, &out[0]);
    rig.relay_in(&ack(&hs.iter().map(Hint::identity).collect::<Vec<_>>()));
    for i in 0..63 {
        let (sid, pg) = &s[(i + 1) / 16];
        open(&mut rig, sid, pg);
    }
    assert_eq!(rig.relay_out().len(), 63);
    assert_eq!(rig.engine.push.unhinted(), 0);
    // The 65th: no room (every tracked approval was published).
    let late = open(&mut rig, &s[4].0, &s[4].1);
    assert!(rig.relay_out().is_empty(), "no hint for the 65th");
    assert_eq!(rig.engine.push.unhinted(), 1);
    assert!(!rig.engine.push.tracks(&late));
    assert!(rig.engine.push.tracks(&a), "A's lifecycle is kept");
    // A is answered: its resolved hint, retried unchanged until acked.
    close(&mut rig, &a, r8::ApprovalCloseReason::AnsweredTerminal);
    let first = resolved_of(&mut rig, &a).expect("A's resolved hint");
    rig.advance(10_000);
    let again = resolved_of(&mut rig, &a).expect("resent");
    assert_eq!(again, first, "byte-identical");
    let r = Hint::verify(
        &object(&first),
        &rig.log.log,
        rig.now.host.wall_ms,
        Verifier::Client,
    )
    .unwrap();
    rig.relay_in(&ack(&[r.identity()]));
    rig.advance(10_000);
    assert_eq!(resolved_of(&mut rig, &a), None);
    assert!(!rig.engine.push.tracks(&a));
}

/// Capacity pressure while A's resolved acknowledgment is lost: A's
/// resolved hint is kept (never evicted) and resent unchanged; the new
/// approval that finds no room goes unhinted; once A's resolution is
/// acknowledged, the next one gets its hints.
#[test]
fn an_unacknowledged_resolution_survives_capacity_pressure() {
    let (mut rig, s) = five_sessions();
    rig.link_up();
    let a = open(&mut rig, &s[4].0, &s[4].1);
    rig.relay_out();
    close(&mut rig, &a, r8::ApprovalCloseReason::Interrupted);
    let first = resolved_of(&mut rig, &a).expect("A's resolved hint");
    // Its ack is lost; 63 published approvals fill the rest.
    for i in 0..63 {
        let (sid, pg) = &s[i / 16];
        open(&mut rig, sid, pg);
    }
    rig.relay_out();
    let late = open(&mut rig, &s[3].0, &s[3].1);
    assert!(rig.relay_out().is_empty(), "no room: no hint");
    assert!(!rig.engine.push.tracks(&late));
    assert_eq!(rig.engine.push.unhinted(), 1);
    rig.advance(10_000);
    let again = resolved_of(&mut rig, &a).expect("A's resolution is resent");
    assert_eq!(again, first, "byte-identical");
    let r = Hint::verify(
        &object(&first),
        &rig.log.log,
        rig.now.host.wall_ms,
        Verifier::Client,
    )
    .unwrap();
    rig.relay_in(&ack(&[r.identity()]));
    // Room again: the next approval gets its hints.
    let next = open(&mut rig, &s[4].0, &s[4].1);
    let out = rig.relay_out();
    assert_eq!(out.len(), 1);
    assert!(
        hints(&rig, &out[0])
            .iter()
            .all(|h| h.key().approval_id == next)
    );
}

/// Opens never published (the link was down) make room first: the oldest
/// of them is forgotten for a 65th, and the reconnect sends the other 64.
#[test]
fn unpublished_opens_make_room_first() {
    let (mut rig, s) = five_sessions();
    rig.link_up();
    rig.link_down();
    let mut ids = Vec::new();
    for i in 0..65 {
        let (sid, pg) = &s[i / 16];
        ids.push(open(&mut rig, sid, pg));
    }
    assert!(!rig.engine.push.tracks(&ids[0]), "the oldest unpublished");
    assert_eq!(rig.engine.push.unhinted(), 0);
    rig.link_up();
    let sent: std::collections::BTreeSet<String> = rig
        .relay_out()
        .iter()
        .flat_map(|m| hints(&rig, m))
        .map(|h| h.key().approval_id.clone())
        .collect();
    assert_eq!(sent.len(), 64);
    assert!(!sent.contains(&ids[0]));
    assert!(sent.contains(&ids[64]));
}

/// The make-room order on a bare `HostPush` with the rig's signer.
fn approval_key(rig: &Rig, n: usize) -> ApprovalKey {
    ApprovalKey::new(
        rig.m.as_ref().unwrap().membership(),
        super::tests::HOST,
        1,
        SID,
        PGEN,
        &format!("8c3e9d6b-1f40-4b52-8dae-{n:012x}"),
    )
}

fn signer_of(rig: &Rig) -> Signer<'_> {
    Signer {
        log: rig.m.as_ref().unwrap().membership(),
        key: &rig.key,
    }
}

fn plain() -> HintPlain {
    HintPlain {
        tool: "Bash".into(),
        summary: "ls".into(),
    }
}

/// Task 8 re-review 3 F1: an approval closed before its opens were ever
/// published holds no lifecycle the relay may have; it makes room like an
/// unpublished pending one, whether its resolution was acknowledged or
/// not.
#[test]
fn a_closed_never_published_approval_makes_room() {
    let rig = Rig::new();
    let (key, signer) = (|n| approval_key(&rig, n), || signer_of(&rig));
    let wall = rig.now.host.wall_ms;
    let push = &mut HostPush::default();
    {
        push.link_up(None, wall);
        for n in 0..MAX_APPROVALS - 1 {
            push.opened(key(n), wall, wall + WAIT_MS, &plain(), Some(signer()), wall);
        }
        push.link_down();
        let closed = key(100);
        push.opened(
            closed.clone(),
            wall,
            wall + WAIT_MS,
            &plain(),
            Some(signer()),
            wall,
        );
        push.resolved(&closed.approval_id, "interrupted", Some(signer()), wall);
        let next = key(101);
        push.opened(
            next.clone(),
            wall,
            wall + WAIT_MS,
            &plain(),
            Some(signer()),
            wall,
        );
        assert!(!push.tracks(&closed.approval_id), "made room");
        assert!(push.tracks(&next.approval_id));
        assert_eq!(push.unhinted(), 0);
        for n in 0..MAX_APPROVALS - 1 {
            assert!(push.tracks(&key(n).approval_id), "published {n} kept");
        }
    }
}

/// Task 8 re-review 3 F3: a mixed population (published old, unpublished
/// newer). Room is made from one with nothing left to send first, even a
/// newer one, then from the oldest unpublished; never from a published
/// lifecycle, however old; once all are published, a new one is unhinted.
#[test]
fn make_room_takes_finished_then_unpublished_never_published() {
    let rig = Rig::new();
    let (key, signer) = (|n| approval_key(&rig, n), || signer_of(&rig));
    let wall = rig.now.host.wall_ms;
    let push = &mut HostPush::default();
    {
        push.link_up(None, wall);
        for n in 0..MAX_APPROVALS - 2 {
            push.opened(key(n), wall, wall + WAIT_MS, &plain(), Some(signer()), wall);
        }
        push.link_down();
        // Unpublished, pending (tier 2), older than…
        let pending = key(200);
        push.opened(
            pending.clone(),
            wall,
            wall + WAIT_MS,
            &plain(),
            Some(signer()),
            wall,
        );
        // …one unpublished whose opens the guard ended: nothing left to
        // send (tier 1).
        let finished = key(201);
        push.opened(
            finished.clone(),
            wall,
            wall + 20_000,
            &plain(),
            Some(signer()),
            wall,
        );
        push.tick(None, wall + 6_000);
        let at = wall + 6_000;
        let a = key(202);
        push.opened(a.clone(), at, at + WAIT_MS, &plain(), Some(signer()), at);
        assert!(!push.tracks(&finished.approval_id), "tier 1 first");
        assert!(push.tracks(&pending.approval_id));
        let b = key(203);
        push.opened(b.clone(), at, at + WAIT_MS, &plain(), Some(signer()), at);
        assert!(
            !push.tracks(&pending.approval_id),
            "then the oldest unpublished"
        );
        assert!(push.tracks(&a.approval_id) && push.tracks(&b.approval_id));
        for n in 0..MAX_APPROVALS - 2 {
            assert!(push.tracks(&key(n).approval_id), "published {n} kept");
        }
        // The reconnect publishes the rest: no room for another.
        push.link_up(None, at);
        let c = key(204);
        push.opened(c.clone(), at, at + WAIT_MS, &plain(), Some(signer()), at);
        assert!(!push.tracks(&c.approval_id));
        assert_eq!(push.unhinted(), 1);
    }
}

// ── `outcome_unknown` hints (`host.alerts`; delegated host-work I.4.6) ──

use atem_client::push::{AlertHint, AlertKey, AlertPlain, MAX_HINT_LIFETIME_MS};
use atem_client::session::alerts::{Alert, AlertKind};

/// The rig with `host.delegated` and `host.alerts` on, as the runtime's
/// debug-only hook turns them on, and hosting on: its welcome lists
/// `host.alerts`.
fn alert_rig() -> Rig {
    let mut rig = Rig::new();
    rig.engine.set_delegated_features(true, true);
    rig.engine.enable_host_work(true);
    rig
}

/// The `n`th alert, raised now on the host clock: the phone's task on
/// `SID` became `outcome_unknown` (`agent exited`).
fn alert_now(rig: &Rig, n: u64) -> Alert {
    Alert {
        alert_id: uuid::Uuid::new_v4().to_string(),
        seq: n,
        kind: AlertKind::OutcomeUnknown,
        host_id: super::tests::HOST.into(),
        session_id: SID.into(),
        task_id: uuid::Uuid::new_v4().to_string(),
        sender: "member:dev-phone".into(),
        reason: "agent exited".into(),
        created_at: rig.now.host.wall_ms,
    }
}

/// The alert's row is committed: the bridge hands it to the engine.
fn raise(rig: &mut Rig, alert: &Alert) {
    rig.with_parts(|e, p| e.alert_opened(alert, p));
}

/// A new alert, raised now and handed over.
fn raise_new(rig: &mut Rig, n: u64) -> Alert {
    let alert = alert_now(rig, n);
    raise(rig, &alert);
    alert
}

/// The `outcome_unknown` hints of a `push_hint`, verified as a client does.
fn alert_hints(rig: &Rig, message: &Value) -> Vec<AlertHint> {
    assert_eq!(message["type"], "relay", "{message}");
    assert_eq!(message["op"], "push_hint", "{message}");
    message["hints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| {
            AlertHint::verify(
                &object(h),
                &rig.log.log,
                rig.now.host.wall_ms,
                Verifier::Client,
            )
            .unwrap()
        })
        .collect()
}

fn alert_key(rig: &Rig, alert: &Alert) -> AlertKey {
    AlertKey::new(&rig.log.log, super::tests::HOST, 1, &alert.alert_id)
}

/// What a recipient opens: the alert's facts.
fn facts(alert: &Alert) -> AlertPlain {
    AlertPlain {
        task_id: alert.task_id.clone(),
        session_id: alert.session_id.clone(),
        sender: alert.sender.clone(),
        reason: alert.reason.clone(),
    }
}

/// Session-v1 R9.9 ("`outcome_unknown` hint", delivery as an open hint's):
/// an alert's hints, one per native member with `control` (the Mac and the
/// phone), its `created_at` the alert's and its window the longest a hint
/// has, are resent with the same bytes every 10 s and at a reconnect until
/// the relay acknowledges each, the alert ends, or `expires_at + 300 s`
/// passes (past the guard: nothing cancels an alert's hint, and its ack is
/// still wanted). Handed over again, an alert signs nothing new; an ack
/// naming another alert or trust generation ends nothing.
#[test]
fn a_hint_is_resent_until_push_ack_or_its_expiry() {
    let mut rig = alert_rig();
    rig.link_up();
    let a = alert_now(&rig, 1);
    raise(&mut rig, &a);
    let first = rig.relay_out();
    assert_eq!(first.len(), 1, "{first:?}");
    let hs = alert_hints(&rig, &first[0]);
    let devices: Vec<&str> = hs.iter().map(AlertHint::device_id).collect();
    assert_eq!(devices, [MAC, "dev-phone"]);
    for h in &hs {
        assert_eq!(h.key(), &alert_key(&rig, &a));
        assert_eq!(h.created_at(), a.created_at);
        assert_eq!(h.expires_at(), a.created_at + MAX_HINT_LIFETIME_MS);
    }
    rig.advance(9_000);
    assert!(rig.relay_out().is_empty(), "not before 10 s");
    rig.advance(1_000);
    assert_eq!(rig.relay_out(), first, "the same bytes");
    // Handed over again (another pass): nothing new is signed.
    raise(&mut rig, &a);
    assert!(rig.relay_out().is_empty());
    // Acks naming another alert, or another trust generation, end nothing.
    let mut other = hs[1].key().clone();
    other.alert_id = uuid::Uuid::new_v4().to_string();
    let mut gen2 = hs[1].key().clone();
    gen2.host_trust_gen = 2;
    rig.relay_in(&ack(&[
        Identity::Alert {
            key: other,
            device_id: "dev-phone".into(),
        },
        Identity::Alert {
            key: gen2,
            device_id: "dev-phone".into(),
        },
    ]));
    assert_eq!(rig.engine.push_status(rig.now.host.wall_ms).pending, 2);
    // The phone's is acknowledged: the Mac's goes on alone.
    rig.relay_in(&ack(&[hs[1].identity()]));
    rig.advance(10_000);
    let again = rig.relay_out();
    assert_eq!(again.len(), 1);
    assert_eq!(again[0]["hints"], json!([first[0]["hints"][0]]));
    rig.relay_in(&ack(&[hs[0].identity()]));
    rig.advance(10_000);
    assert!(rig.relay_out().is_empty(), "both acknowledged");
    assert_eq!(rig.engine.push_status(rig.now.host.wall_ms).pending, 0);
    assert!(!rig.engine.push.tracks_alert(&a.alert_id));

    // Never acknowledged: raised while the link is down, it goes at the
    // reconnect, then every 10 s, past the guard, until `expires_at + 300 s`.
    rig.link_down();
    let b = alert_now(&rig, 2);
    raise(&mut rig, &b);
    rig.advance(5_000);
    assert!(rig.relay_out().is_empty(), "no link");
    rig.link_up();
    let out = rig.relay_out();
    assert_eq!(out.len(), 1);
    assert!(
        alert_hints(&rig, &out[0])
            .iter()
            .all(|h| h.key().alert_id == b.alert_id)
    );
    let live_until = b.created_at + MAX_HINT_LIFETIME_MS + 300_000;
    rig.advance(live_until - 1 - rig.now.host.wall_ms);
    assert_eq!(rig.relay_out(), out, "resent at its expiry + 299.999 s");
    rig.advance(1);
    assert!(rig.relay_out().is_empty(), "not at expires_at + 300 s");
    assert_eq!(rig.engine.push_status(rig.now.host.wall_ms).pending, 0);
    assert!(!rig.engine.push.tracks_alert(&b.alert_id));

    // The alert ends (its task resolved, or a reply moved it): its hints
    // are not sent again.
    let c = alert_now(&rig, 3);
    raise(&mut rig, &c);
    assert_eq!(rig.relay_out().len(), 1);
    assert_eq!(rig.engine.hinted_alerts(), [c.alert_id.as_str()]);
    rig.engine.alert_ended(&c.alert_id);
    rig.advance(10_000);
    assert!(rig.relay_out().is_empty(), "ended");
    assert_eq!(rig.engine.push_status(rig.now.host.wall_ms).pending, 0);
    assert!(rig.engine.hinted_alerts().is_empty());
}

/// Session-v1 R9.9 with R9.3, R9.4 and r8 §I: no alert hint is signed or
/// sent while the device list is held, frozen or faulted, or the session
/// journal halted; what was queued is dropped when it starts.
#[test]
fn no_hint_while_the_list_is_held_frozen_or_faulted_or_the_journal_halted() {
    // Held at start (a recorded fault).
    let mut rig = alert_rig();
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
    let a = alert_now(&rig, 1);
    raise(&mut rig, &a);
    rig.advance(10_000);
    assert!(rig.relay_out().is_empty(), "held");
    let status = rig.engine.push_status(rig.now.host.wall_ms);
    assert_eq!(
        (status.pending, status.suppressed),
        (0, Some("device list held"))
    );

    // Frozen while an alert's hints wait: dropped, nothing after.
    let mut rig = alert_rig();
    rig.link_up();
    rig.connect(
        "mac",
        atem_client::connect::Identity::native(MAC, r9log::auth(MAC)),
    );
    raise_new(&mut rig, 1);
    assert_eq!(rig.relay_out().len(), 1);
    let conflict = rig.log.conflicting_add("dev-x");
    carry(&mut rig, "mac", &conflict);
    assert!(rig.m.as_ref().unwrap().is_frozen());
    rig.advance(10_000);
    assert!(rig.relay_out().is_empty(), "frozen: no resend");
    raise_new(&mut rig, 2);
    rig.advance(10_000);
    assert!(rig.relay_out().is_empty(), "frozen: nothing new");
    let status = rig.engine.push_status(rig.now.host.wall_ms);
    assert_eq!(
        (status.pending, status.suppressed),
        (0, Some("device list frozen"))
    );

    // Faulted: a device-list write fails while an alert's hints wait (the
    // journal halts with it).
    let mut rig = alert_rig();
    rig.link_up();
    rig.connect(
        "mac",
        atem_client::connect::Identity::native(MAC, r9log::auth(MAC)),
    );
    raise_new(&mut rig, 1);
    assert_eq!(rig.relay_out().len(), 1);
    rig.m.as_mut().unwrap().store_mut().inject(
        crate::session_protocol::membership::store::Injected {
            file: crate::session_protocol::membership::store::DlFile::Applied,
            step: crate::session_protocol::membership::store::Step::TempWrite,
        },
    );
    let added = rig.log.add_native("dev-tab", &["control", "view"]);
    carry(&mut rig, "mac", &added);
    assert!(rig.m.as_ref().unwrap().faulted().is_some());
    rig.advance(10_000);
    assert!(rig.relay_out().is_empty(), "faulted: no resend");
    raise_new(&mut rig, 2);
    rig.advance(10_000);
    assert!(rig.relay_out().is_empty(), "faulted: nothing new");
    // The write fault halts the journal too, and `push_suppressed` names
    // the halt first: for this host the faulted list and the halted
    // journal are one path.
    let status = rig.engine.push_status(rig.now.host.wall_ms);
    assert_eq!(
        (status.pending, status.suppressed),
        (0, Some("journal halted"))
    );

    // The journal halts (a failed write) while an alert's hints wait.
    let mut rig = alert_rig();
    rig.link_up();
    rig.connect("phone", phone());
    let ap = open(&mut rig, SID, PGEN);
    raise_new(&mut rig, 1);
    assert_eq!(rig.relay_out().len(), 2, "the approval's and the alert's");
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
    raise_new(&mut rig, 2);
    rig.advance(10_000);
    assert!(rig.relay_out().is_empty(), "halted: nothing new");
    let status = rig.engine.push_status(rig.now.host.wall_ms);
    assert_eq!(
        (status.pending, status.suppressed),
        (0, Some("journal halted"))
    );
}

/// The relay's side (the shared core's reference `RelayLedger`, which
/// verifies as the relay does): every alert hint the host sends is
/// accepted under its identity (`kind` `outcome_unknown`, the alert id and
/// the device), a resend is idempotent, the relay's `push_ack` of those
/// identities ends the resends, and the schedule runs from the signed
/// `created_at` with the alert id as its collapse id. Each recipient opens
/// only its own sealed part: the task, session, sender and reason. A hint
/// the relay first gets more than 120 s after its `created_at` is refused
/// `skew`, and its acknowledgment (it names the identity) ends its resends
/// too.
#[test]
fn hints_verify_with_the_relay_ledger() {
    use atem_client::push::{DeviceClass, Push, RecipientInfo, Refusal, RelayLedger, Verdict};
    let mut rig = alert_rig();
    rig.link_up();
    let a = alert_now(&rig, 1);
    raise(&mut rig, &a);
    let out = rig.relay_out();
    assert_eq!(out.len(), 1);
    let mut ledger = RelayLedger::new();
    let now = rig.now.host.wall_ms;
    let mut acks = Vec::new();
    for h in out[0]["hints"].as_array().unwrap() {
        let (verdict, identity) = ledger.receive_hint(&object(h), &rig.log.log, now);
        assert_eq!(verdict, Verdict::Accepted, "{h}");
        acks.push(identity.expect("named"));
    }
    for (identity, device) in acks.iter().zip([MAC, "dev-phone"]) {
        assert_eq!(
            identity,
            &Identity::Alert {
                key: alert_key(&rig, &a),
                device_id: device.into(),
            }
        );
        let entry = identity.to_ack();
        assert_eq!(entry["kind"], "outcome_unknown");
        assert_eq!(entry.as_object().unwrap().len(), 7, "{entry}");
    }
    // The schedule, from the signed `created_at`: the Mac (a desktop with
    // no Astation connected) at once, the phone at + 60 s; collapsed on the
    // alert id.
    let device = |d: &str| RecipientInfo {
        class: if d == MAC {
            DeviceClass::Desktop
        } else {
            DeviceClass::Mobile
        },
        connected: false,
        immediate_mobile: false,
    };
    assert_eq!(
        ledger.due(now, &device),
        [Push {
            device_id: MAC.into(),
            kind: "desktop_os",
            due_at: a.created_at,
            collapse_id: a.alert_id.clone(),
        }]
    );
    assert_eq!(
        ledger.due(a.created_at + 60_000, &device),
        [Push {
            device_id: "dev-phone".into(),
            kind: "mobile",
            due_at: a.created_at + 60_000,
            collapse_id: a.alert_id.clone(),
        }]
    );
    // Each device opens its own part only: the alert's facts.
    let hs = alert_hints(&rig, &out[0]);
    let keys = &rig.log.keys;
    assert_eq!(hs[0].open(keys, &enc(MAC), MAC).unwrap(), facts(&a));
    assert_eq!(
        hs[1].open(keys, &enc("dev-phone"), "dev-phone").unwrap(),
        facts(&a)
    );
    assert!(hs[0].open(keys, &enc("dev-phone"), "dev-phone").is_err());
    let text = out[0].to_string();
    for clear in [&a.task_id, &a.sender, &a.reason, &a.session_id] {
        assert!(!text.contains(clear.as_str()), "{clear} in clear: {text}");
    }
    // A lost ack: the resend is idempotent; the relay's `push_ack` ends it.
    rig.advance(10_000);
    let again = rig.relay_out();
    assert_eq!(again, out);
    for h in again[0]["hints"].as_array().unwrap() {
        let (verdict, _) = ledger.receive_hint(&object(h), &rig.log.log, rig.now.host.wall_ms);
        assert_eq!(verdict, Verdict::Idempotent);
    }
    rig.relay_in(&ack(&acks));
    rig.advance(10_000);
    assert!(rig.relay_out().is_empty());
    assert_eq!(rig.engine.push_status(rig.now.host.wall_ms).pending, 0);

    // First received 121 s after its `created_at` (the link was down):
    // refused `skew`, named, and that ack ends the resends.
    rig.link_down();
    let b = alert_now(&rig, 2);
    raise(&mut rig, &b);
    rig.advance(121_000);
    rig.link_up();
    let late = rig.relay_out();
    assert_eq!(late.len(), 1);
    let mut acks = Vec::new();
    for h in late[0]["hints"].as_array().unwrap() {
        let (verdict, identity) =
            ledger.receive_hint(&object(h), &rig.log.log, rig.now.host.wall_ms);
        assert_eq!(verdict, Verdict::Refused(Refusal::Skew));
        acks.push(identity.expect("named"));
    }
    rig.relay_in(&ack(&acks));
    rig.advance(10_000);
    assert!(rig.relay_out().is_empty());
    assert_eq!(rig.engine.push_status(rig.now.host.wall_ms).pending, 0);
}

/// Session-v1 R9.9 / R9.6: an alert hint not yet acknowledged whose device
/// is removed, or demoted below `control`, is never sent again (the Mac's
/// goes on); an alert left with none ends its tracking; a device added with
/// `control` afterwards gets none of an alert raised before.
#[test]
fn an_alert_hint_follows_the_recipients_at_the_head() {
    let mut rig = Rig::with(|log| {
        log.add_native("dev-tab", &["control", "view"]);
    });
    rig.engine.set_delegated_features(true, true);
    rig.engine.enable_host_work(true);
    rig.link_up();
    rig.connect(
        "mac",
        atem_client::connect::Identity::native(MAC, r9log::auth(MAC)),
    );
    let a = raise_new(&mut rig, 1);
    let first = rig.relay_out();
    let devices: Vec<String> = alert_hints(&rig, &first[0])
        .iter()
        .map(|h| h.device_id().to_string())
        .collect();
    assert_eq!(devices, [MAC, "dev-phone", "dev-tab"]);
    let removal = rig.log.remove("dev-phone");
    carry(&mut rig, "mac", &removal);
    let demotion = rig.log.set_native_roles("dev-tab", &["view"]);
    carry(&mut rig, "mac", &demotion);
    assert_eq!(rig.engine.push_status(rig.now.host.wall_ms).pending, 1);
    let added = rig.log.add_native("dev-new", &["control", "view"]);
    carry(&mut rig, "mac", &added);
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
    assert_eq!(out[0]["hints"], json!([first[0]["hints"][0]]));
    // The Mac's acknowledged: nothing left of the alert.
    let mac = alert_hints(&rig, &first[0]).remove(0);
    rig.relay_in(&ack(&[mac.identity()]));
    assert!(!rig.engine.push.tracks_alert(&a.alert_id));
}

/// Bounded apart from the approvals: at most `MAX_ALERTS` alerts tracked; a
/// published one is never forgotten for room (a newer alert goes unhinted,
/// counted), an acknowledged one frees its place at once, an unpublished one
/// (the link was down) makes room for a newer; a full set of alerts takes
/// nothing from the approvals; a reconnect resends every tracked alert's
/// hints, each message under the 256 KiB bound; a re-pin drops them.
#[test]
fn alert_hints_are_bounded_and_a_published_alert_is_never_forgotten() {
    use super::push::{MAX_ALERTS, MAX_MESSAGE_BYTES};
    let rig = alert_rig();
    let wall = rig.now.host.wall_ms;
    let m = rig.m.as_ref().unwrap();
    let signer = || Signer {
        log: m.membership(),
        key: &rig.key,
    };
    let key = |n: usize| {
        AlertKey::new(
            m.membership(),
            super::tests::HOST,
            1,
            &format!("8c3e9d6b-1f40-4b52-8dae-{n:012x}"),
        )
    };
    let facts = facts(&alert_now(&rig, 1));
    let mut push = HostPush::default();
    push.link_up(None, wall);
    for n in 0..MAX_ALERTS + 3 {
        push.alert_opened(key(n), wall, &facts, Some(signer()), wall);
    }
    assert_eq!(push.status(wall).pending, MAX_ALERTS * 2);
    assert!(push.tracks_alert(&key(0).alert_id));
    assert!(!push.tracks_alert(&key(MAX_ALERTS).alert_id));
    assert_eq!(push.unhinted_alerts(), 3);
    // An approval still gets its hints.
    let approval = ApprovalKey::new(
        m.membership(),
        super::tests::HOST,
        1,
        SID,
        PGEN,
        "8c3e9d6b-1f40-4b52-8dae-ffffffffffff",
    );
    push.opened(
        approval.clone(),
        wall,
        wall + WAIT_MS,
        &plain(),
        Some(signer()),
        wall,
    );
    assert!(push.tracks(&approval.approval_id));
    // Alert 0 acknowledged: its place goes to the next.
    let acks: Vec<Identity> = [MAC, "dev-phone"]
        .iter()
        .map(|d| Identity::Alert {
            key: key(0),
            device_id: d.to_string(),
        })
        .collect();
    assert_eq!(push.ack(&ack(&acks)), 2);
    assert!(!push.tracks_alert(&key(0).alert_id));
    push.alert_opened(key(100), wall, &facts, Some(signer()), wall);
    assert!(push.tracks_alert(&key(100).alert_id));
    // A reconnect resends every tracked alert's hints, in bounded messages.
    push.link_down();
    push.link_up(None, wall + 1);
    let mut sent = Vec::new();
    push.flush(&mut |text| {
        sent.push(text);
        true
    });
    let mut hints = 0;
    for text in &sent {
        assert!(text.len() <= MAX_MESSAGE_BYTES, "{}", text.len());
        let v: Value = serde_json::from_str(text).unwrap();
        hints += v["hints"].as_array().unwrap().len();
    }
    assert_eq!(hints, MAX_ALERTS * 2 + 2, "the alerts' and the approval's");
    push.reset();
    assert_eq!(push.status(wall).pending, 0);
    assert!(!push.tracks_alert(&key(1).alert_id));

    // Unpublished (the link down): the oldest makes room for a newer one.
    let mut push = HostPush::default();
    push.link_up(None, wall);
    push.link_down();
    for n in 0..MAX_ALERTS + 1 {
        push.alert_opened(key(n), wall, &facts, Some(signer()), wall);
    }
    assert!(
        !push.tracks_alert(&key(0).alert_id),
        "the oldest unpublished"
    );
    assert!(push.tracks_alert(&key(MAX_ALERTS).alert_id));
    assert_eq!(push.unhinted_alerts(), 0);
    // Raised within 15 s of its window's end: no hint.
    push.reset();
    push.alert_opened(
        key(1),
        wall,
        &facts,
        Some(signer()),
        wall + MAX_HINT_LIFETIME_MS - 15_000,
    );
    assert_eq!(push.status(wall).pending, 0);
}

/// Host-work-v1 §11.3 ("Compatibility", "Not advertised yet"): a hint is
/// sent only behind `host.alerts` as the welcome lists it. With the hook's
/// features on and hosting off the welcome lists no `host.alerts`, and an
/// alert raised then signs and sends nothing; with hosting on again the
/// welcome lists it and a new alert is hinted (the bridge never hands the
/// earlier one over again: `an_alert_raised_while_hosting_is_off_is_never_hinted`).
#[test]
fn no_hint_while_hosting_is_off() {
    let alerts = atem_client::session::host_work::ALERTS_FEATURE;
    let mut rig = alert_rig();
    rig.engine.enable_host_work(false);
    rig.link_up();
    assert!(!rig.engine.advertised_features().iter().any(|f| f == alerts));
    let a = raise_new(&mut rig, 1);
    rig.advance(10_000);
    assert!(rig.relay_out().is_empty(), "hosting off: no hint");
    assert_eq!(rig.engine.push_status(rig.now.host.wall_ms).pending, 0);
    assert!(!rig.engine.push.tracks_alert(&a.alert_id));
    rig.engine.enable_host_work(true);
    assert!(rig.engine.advertised_features().iter().any(|f| f == alerts));
    let b = raise_new(&mut rig, 2);
    let out = rig.relay_out();
    assert_eq!(out.len(), 1, "{out:?}");
    let hs = alert_hints(&rig, &out[0]);
    assert_eq!(hs.len(), 2);
    assert!(hs.iter().all(|h| h.key().alert_id == b.alert_id));
}

/// An alert that ends in the pass its resend fell due: the resend already
/// queued for the link is taken back (it is not sent again), and another
/// alert's queued resend goes as it was.
#[test]
fn an_ended_alerts_queued_resend_is_not_sent() {
    let rig = alert_rig();
    let wall = rig.now.host.wall_ms;
    let m = rig.m.as_ref().unwrap();
    let signer = || Signer {
        log: m.membership(),
        key: &rig.key,
    };
    let key = |n: usize| {
        AlertKey::new(
            m.membership(),
            super::tests::HOST,
            1,
            &format!("8c3e9d6b-1f40-4b52-8dae-{n:012x}"),
        )
    };
    let facts = facts(&alert_now(&rig, 1));
    let mut push = HostPush::default();
    push.link_up(None, wall);
    push.alert_opened(key(1), wall, &facts, Some(signer()), wall);
    push.alert_opened(key(2), wall, &facts, Some(signer()), wall);
    let flushed = |push: &mut HostPush| {
        let mut ids = Vec::new();
        push.flush(&mut |text| {
            let v: Value = serde_json::from_str(&text).unwrap();
            for h in v["hints"].as_array().unwrap() {
                ids.push(h["body"]["alert_id"].as_str().unwrap().to_string());
            }
            true
        });
        ids
    };
    assert_eq!(flushed(&mut push).len(), 4);
    // The resend falls due (queued), then alert 1 ends in the same pass.
    push.tick(None, wall + 10_000);
    push.alert_ended(&key(1).alert_id);
    let sent = flushed(&mut push);
    assert_eq!(sent, [key(2).alert_id.clone(), key(2).alert_id.clone()]);
    assert_eq!(push.status(wall).pending, 2);
}

/// PR 7 review m7 (the Task 24 re-review's N2): an alert that ends with
/// its only resend queued leaves no message at all (one whose hints all
/// went is dropped, never sent empty), and nothing is pending.
#[test]
fn an_ended_alerts_only_queued_resend_leaves_nothing_to_send() {
    let rig = alert_rig();
    let wall = rig.now.host.wall_ms;
    let m = rig.m.as_ref().unwrap();
    let key = AlertKey::new(
        m.membership(),
        super::tests::HOST,
        1,
        "8c3e9d6b-1f40-4b52-8dae-000000000001",
    );
    let facts = facts(&alert_now(&rig, 1));
    let mut push = HostPush::default();
    push.link_up(None, wall);
    push.alert_opened(
        key.clone(),
        wall,
        &facts,
        Some(Signer {
            log: m.membership(),
            key: &rig.key,
        }),
        wall,
    );
    let mut sent = 0;
    push.flush(&mut |_| {
        sent += 1;
        true
    });
    assert_eq!(sent, 1, "the first send");
    push.tick(None, wall + 10_000);
    push.alert_ended(&key.alert_id);
    let mut texts = Vec::new();
    push.flush(&mut |text| {
        texts.push(text);
        true
    });
    assert!(texts.is_empty(), "{texts:?}");
    assert_eq!(push.status(wall).pending, 0);
}

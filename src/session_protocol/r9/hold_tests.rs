//! A service a control record holds (host-work-v1 §11.1, the hold's
//! session-v1 fence; session-v1 R9.11), in process: the r9 engine with the
//! real device list and session host (`tests::Rig`), and clients that are
//! the shared core. The runtime gives the engine the held services from
//! its committed control state (`HostBridge::sync_services`); here the
//! test does.
use super::envelope::{self, Event};
use super::tests::{Client, PGEN, Rig, SID, bot, phone};
use super::*;
use crate::session_protocol::fixtures::{HostEvent, HostUnderTest};
use crate::session_protocol::host::ApprovalInfo;
use crate::session_protocol::membership::r9log;
use crate::session_protocol::wire::ReceiptState;
use atem_client::connect::{Event as CEvent, Identity};
use serde_json::json;

const CTL: &str = "service:svc-ctl";
const BOT: &str = "service:svc-bot";

/// The service with every session op on `SID` (`approval`, `prompt`,
/// `terminal`, `view`), an hour left.
fn ctl() -> Identity {
    Identity::service("svc-ctl", r9log::auth("svc-ctl"))
}

/// [`Rig::new`] with [`ctl`] on the list too.
fn ctl_rig() -> Rig {
    ctl_rig_with(&["approval", "prompt", "terminal", "view"])
}

/// [`ctl_rig`], [`ctl`]'s grant holding `ops`.
fn ctl_rig_with(ops: &[&str]) -> Rig {
    let wall = r9log::host_now().wall_ms;
    Rig::with(|log| {
        log.add_service(
            "svc-ctl",
            &[super::tests::HOST],
            Some(&[SID]),
            ops,
            wall + 3_600_000,
        );
    })
}

fn set(principals: &[&str]) -> HashSet<String> {
    principals.iter().map(|p| p.to_string()).collect()
}

fn hold(rig: &mut Rig, principals: &[&str]) {
    let held = set(principals);
    rig.run(|e, p| ((), e.set_held_services(held, p)));
}

fn paused() -> (String, Option<String>) {
    ("busy".into(), Some(DETAIL_PAUSED.into()))
}

/// What the engine sent `handle`'s client since the last flush: the
/// errors it read (code, detail), and the close's reason if the channel
/// closed (the client is then closed in the rig too). Other channels'
/// output is dropped.
fn errors_then_close(
    rig: &mut Rig,
    handle: &str,
) -> (Vec<(String, Option<String>)>, Option<String>) {
    let mono = rig.now.host.mono_ms;
    let mut out = Vec::new();
    rig.engine.flush(&mut |text, _| {
        out.push(text);
        true
    });
    let mut errors = Vec::new();
    let mut close = None;
    for text in out {
        match envelope::parse(&text).unwrap() {
            Event::Frame { channel, frame } if channel == handle => {
                if let Some(Client::Attached(a, _)) = rig.clients.get_mut(handle) {
                    for e in a.on_frame(&frame, mono).unwrap() {
                        if let CEvent::Error(e) | CEvent::Fenced(e) = e {
                            errors.push((e.code, e.detail));
                        }
                    }
                }
            }
            Event::Close { channel, reason } if channel == handle => {
                rig.clients
                    .insert(channel, Client::Refused("closed".into(), reason.clone()));
                close = Some(reason.unwrap_or_default());
            }
            _ => {}
        }
    }
    (errors, close)
}

/// `handle` acquires `SID`'s lease: its lease binding (epoch 1).
fn acquire(rig: &mut Rig, handle: &str) -> Value {
    let read = rig.binding(handle, SID);
    rig.send(
        handle,
        &json!({"type": "session", "data": {"v": 1, "op": "acquire",
            "id": uuid::Uuid::new_v4().to_string(), "binding": read, "takeover": false}}),
    );
    assert!(rig.rt.host.lease_holder(SID).is_some(), "the lease");
    let mut lease = read;
    lease["lease_epoch"] = json!(rig.rt.host.lease_epoch(SID).unwrap());
    lease
}

/// `handle` subscribes to `SID`'s terminal: the stream id.
fn subscribe(rig: &mut Rig, handle: &str, read: &Value) -> Value {
    let mut read = read.clone();
    if let Some(binding) = read.as_object_mut() {
        binding.remove("lease_epoch");
    }
    rig.send(
        handle,
        &json!({"type": "terminal", "data": {"v": 1, "op": "subscribe", "terminal_id": SID,
            "generation": PGEN, "binding": read}}),
    );
    rig.events(handle)
        .into_iter()
        .find_map(|e| match e {
            CEvent::Family(f) => f
                .data
                .filter(|d| d["op"] == "attached")
                .map(|d| d["stream_id"].clone()),
            _ => None,
        })
        .expect("subscribed")
}

/// `handle`'s raw terminal input of `x` on `stream`, with `lease`.
fn input(rig: &mut Rig, handle: &str, stream: &Value, sequence: u64, lease: &Value) {
    rig.send(
        handle,
        &json!({"type": "terminal", "data": {"v": 1, "op": "input", "terminal_id": SID,
            "generation": PGEN, "stream_id": stream, "sequence": sequence, "bytes": "eA==",
            "binding": lease}}),
    );
}

/// Item 7 of Astation's review of the delegated build (#120): a hold
/// fences the service's session-v1, reversibly. Its live attachment is
/// closed after `busy`, `paused` through §H (its `control_gen` raised once,
/// its lease revoked); a native stays; its new `hello`s are refused `busy`,
/// `paused` while it stays held, and staying held fences nothing more. Its
/// release admits a fresh `hello` and restores nothing: the old lease stays
/// gone.
#[test]
fn a_held_service_is_fenced_and_refused_paused_until_its_release() {
    let mut rig = ctl_rig();
    rig.link_up();
    rig.connect("ctl-1", ctl());
    rig.advance(1000);
    rig.connect("phone", phone());
    rig.attached("phone");
    acquire(&mut rig, "ctl-1");
    let before = rig.rt.host.control_gen(CTL);
    hold(&mut rig, &[CTL]);
    let (errors, close) = errors_then_close(&mut rig, "ctl-1");
    assert_eq!(errors, [paused()]);
    assert!(close.is_some(), "closed");
    assert_eq!(rig.rt.host.control_gen(CTL), before + 1);
    assert!(!rig.rt.host.grants_control(CTL));
    assert_eq!(rig.rt.host.lease_holder(SID), None, "its lease revoked");
    assert_eq!(rig.engine.status().attachments, 1, "the phone stays");
    // Staying held fences nothing more.
    hold(&mut rig, &[CTL]);
    assert_eq!(rig.rt.host.control_gen(CTL), before + 1);
    rig.advance(1000);
    rig.connect("ctl-2", ctl());
    assert_eq!(rig.refused("ctl-2"), paused());
    rig.advance(1000);
    rig.connect("phone-2", phone());
    rig.attached("phone-2");
    // Released: a fresh hello, nothing restored.
    hold(&mut rig, &[]);
    rig.advance(1000);
    rig.connect("ctl-3", ctl());
    rig.attached("ctl-3");
    assert_eq!(
        rig.rt.host.lease_holder(SID),
        None,
        "the old lease stays gone"
    );
    assert_eq!(rig.rt.host.control_gen(CTL), before + 1);
    // Held again: fenced again, once.
    hold(&mut rig, &[CTL]);
    rig.pump();
    assert_eq!(rig.refused("ctl-3").0, "closed");
    assert_eq!(rig.rt.host.control_gen(CTL), before + 2);
}

/// Item 7: a command the held service queued before the hold never runs
/// after it. Its raw input queued at the PTY writer is dropped at the
/// write boundary (the fence revoked its lease: the input epoch moved),
/// and its prompt accepted but not dispatched yet is rejected (`control
/// revoked`): nothing of either reaches the PTY, the dispatch let go or
/// not.
#[test]
fn a_held_services_queued_input_and_prompt_never_reach_the_pty() {
    let mut rig = ctl_rig();
    rig.link_up();
    rig.connect("ctl-1", ctl());
    let lease = acquire(&mut rig, "ctl-1");
    let stream = subscribe(&mut rig, "ctl-1", &lease);
    let now = rig.rt.now();
    rig.rt.event(&HostEvent::HoldPtyWrites, now).unwrap();
    input(&mut rig, "ctl-1", &stream, 0, &lease);
    rig.rt.host.hold_dispatch(true);
    let rid = uuid::Uuid::new_v4().to_string();
    rig.send(
        "ctl-1",
        &json!({"type": "session", "data": {"v": 1, "op": "submit",
            "id": uuid::Uuid::new_v4().to_string(), "binding": lease, "kind": "prompt",
            "request_id": rid, "payload": {"text": "QUEUED_BEFORE_THE_HOLD"}}}),
    );
    assert_eq!(
        rig.rt.host.receipt(&rid).map(|r| r.state),
        Some(ReceiptState::Accepted)
    );
    hold(&mut rig, &[CTL]);
    rig.pump();
    assert_eq!(rig.refused("ctl-1").0, "closed");
    let receipt = rig.rt.host.receipt(&rid).unwrap();
    assert_eq!(
        (receipt.state, receipt.detail.as_deref()),
        (ReceiptState::Rejected, Some("control revoked"))
    );
    let now = rig.rt.now();
    rig.rt.event(&HostEvent::FlushPtyWrites, now).unwrap();
    rig.rt.host.hold_dispatch(false);
    rig.advance(1000);
    assert_eq!(rig.rt.counter("pty_writes_dropped").unwrap(), json!(1));
    assert_eq!(rig.rt.counter("pty_writes_remote").unwrap(), json!(0));
    assert_eq!(rig.rt.counter("dispatches").unwrap(), json!(0));
}

/// Items 7 and 16: the hold is enforced where the held service's requests
/// are admitted, not only by its channel's close. Between the fence and
/// the close the runtime carries out, the service's raw input and its
/// lease-free approval answer are refused `busy` (`paused`, the session
/// family naming it): nothing is written, the approval stays pending.
/// Once closed, a native's answer is taken.
#[test]
fn a_held_services_input_and_approval_answer_are_refused_before_its_close() {
    let mut rig = ctl_rig();
    rig.link_up();
    rig.connect("ctl-1", ctl());
    rig.advance(1000);
    rig.connect("phone", phone());
    let lease = acquire(&mut rig, "ctl-1");
    let stream = subscribe(&mut rig, "ctl-1", &lease);
    let info = ApprovalInfo {
        tool: "Bash".into(),
        summary: "ls".into(),
        always_rules: Vec::new(),
    };
    let (opened, fx) =
        rig.rt
            .host
            .open_approval_at(SID, PGEN, info, rig.now.mono, rig.now.host.wall_ms);
    rig.rt.apply(fx);
    rig.route();
    let approval = opened.unwrap();
    // The fence, its close not carried out yet.
    let held = set(&[CTL]);
    let fenced = rig.with_parts(|e, p| e.set_held_services(held, p));
    assert!(!fenced.is_empty(), "the §H fence's effects");
    input(&mut rig, "ctl-1", &stream, 0, &lease);
    let events = rig.events("ctl-1");
    assert_eq!(
        Rig::last_error(&events).map(|e| e.0),
        Some("busy".into()),
        "{events:?}"
    );
    rig.send(
        "ctl-1",
        &json!({"type": "session", "data": {"v": 1, "op": "submit",
            "id": uuid::Uuid::new_v4().to_string(), "binding": lease, "kind": "approval",
            "request_id": uuid::Uuid::new_v4().to_string(),
            "payload": {"approval_id": approval, "decision": "allow_once"}}}),
    );
    let events = rig.events("ctl-1");
    assert_eq!(Rig::last_error(&events), Some(paused()), "{events:?}");
    assert_eq!(
        rig.rt.host.pending_approvals(SID),
        std::slice::from_ref(&approval)
    );
    assert_eq!(rig.rt.counter("pty_writes_remote").unwrap(), json!(0));
    assert!(rig.rt.pty.approval_decisions.is_empty());
    // The close; then the phone's answer is taken.
    rig.rt.apply(fenced);
    rig.route();
    rig.pump();
    assert_eq!(rig.refused("ctl-1").0, "closed");
    let b = rig.binding("phone", SID);
    rig.send(
        "phone",
        &json!({"type": "session", "data": {"v": 1, "op": "submit",
            "id": uuid::Uuid::new_v4().to_string(), "binding": b, "kind": "approval",
            "request_id": uuid::Uuid::new_v4().to_string(),
            "payload": {"approval_id": approval, "decision": "allow_once"}}}),
    );
    assert_eq!(rig.rt.pty.approval_decisions.len(), 1, "the phone's answer");
}

/// Item 7: every session-v1 mutation of a held service is refused at its
/// admission, whatever the family (its grant holds every op, so each would
/// be admitted unheld): prompt, interrupt, stop, a rule revoke, terminal
/// resize and stop, a chat-v1 submit. Each is answered `busy` before it is
/// read; nothing reaches the session host (no receipt) or the PTY.
#[test]
fn every_session_v1_mutation_of_a_held_service_is_refused_at_admission() {
    let mut rig = ctl_rig_with(&[
        "approval",
        "interrupt",
        "prompt",
        "rule_revoke",
        "stop",
        "terminal",
        "view",
    ]);
    rig.link_up();
    rig.connect("ctl-1", ctl());
    let lease = acquire(&mut rig, "ctl-1");
    let stream = subscribe(&mut rig, "ctl-1", &lease);
    let held = set(&[CTL]);
    let fenced = rig.with_parts(|e, p| e.set_held_services(held, p));
    let id = || uuid::Uuid::new_v4().to_string();
    let mut rids = Vec::new();
    let mut submit = |kind: &str, payload: Value| {
        let rid = id();
        rids.push(rid.clone());
        json!({"type": "session", "data": {"v": 1, "op": "submit", "id": id(),
            "binding": lease, "kind": kind, "request_id": rid, "payload": payload}})
    };
    let mut requests = vec![
        submit("prompt", json!({"text": "WHILE_HELD"})),
        submit("interrupt", json!({})),
        submit("stop", json!({})),
        submit(
            "approval_rule_revoke",
            json!({"rule_id": "s-0123456789abcdef"}),
        ),
    ];
    for (op, extra) in [
        ("resize", json!({"rows": 40, "cols": 100})),
        ("stop", json!({})),
    ] {
        let mut data = json!({"v": 1, "op": op, "terminal_id": SID, "generation": PGEN,
            "stream_id": stream, "binding": lease});
        data.as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        requests.push(json!({"type": "terminal", "data": data}));
    }
    let chat = id();
    rids.push(chat.clone());
    requests.push(json!({"type": "agentChat", "data": {"v": 1, "op": "submit",
        "conversationId": id(), "agentId": SID, "generation": PGEN, "requestId": chat,
        "text": "WHILE_HELD", "binding": lease}}));
    for request in &requests {
        rig.send("ctl-1", request);
        let events = rig.events("ctl-1");
        assert_eq!(
            Rig::last_error(&events).map(|e| e.0),
            Some("busy".into()),
            "{request}: {events:?}"
        );
    }
    for rid in &rids {
        assert!(rig.rt.host.receipt(rid).is_none(), "{rid} admitted");
    }
    for counter in ["dispatches", "pty_writes_remote", "resizes", "stops"] {
        assert_eq!(rig.rt.counter(counter).unwrap(), json!(0), "{counter}");
    }
    rig.rt.apply(fenced);
    rig.route();
    rig.pump();
    assert_eq!(rig.refused("ctl-1").0, "closed");
}

/// The order of a service's `hello` refusals (session-v1 R9.11): the
/// device list's own first (an expired grant's final `unauthorized`), then
/// a revoke (`unauthorized`, `revoked`: final, it wins over a hold), then
/// the unchecked control state (`busy`, `revocations not yet checked`: it
/// keeps its own detail), then the hold (`busy`, `paused`).
#[test]
fn a_held_services_hello_refusals_come_in_their_order() {
    let mut rig = Rig::new();
    rig.link_up();
    hold(&mut rig, &[BOT]);
    rig.engine.start_services_unchecked(true);
    rig.connect("bot-1", bot());
    assert_eq!(
        rig.refused("bot-1"),
        ("busy".into(), Some(DETAIL_UNCHECKED.into()))
    );
    rig.engine.set_revoked_services(set(&[BOT]));
    rig.advance(1000);
    rig.connect("bot-2", bot());
    assert_eq!(
        rig.refused("bot-2"),
        ("unauthorized".into(), Some(DETAIL_REVOKED.into()))
    );
    rig.engine.set_revoked_services(HashSet::new());
    rig.run(|e, p| ((), e.set_services_unchecked(false, p)));
    rig.advance(1000);
    rig.connect("bot-3", bot());
    assert_eq!(rig.refused("bot-3"), paused());
    // The bot's grant expires: its own final refusal first.
    rig.advance(3_600_000);
    rig.connect("bot-4", bot());
    assert_eq!(
        rig.refused("bot-4"),
        ("unauthorized".into(), Some("expired".into()))
    );
}

/// Item 7: natives and browser grants are never held, whatever the set
/// names: a native's and a browser's attachments stay, their `control_gen`
/// unmoved, and their new `hello`s are admitted; the service named beside
/// them is fenced.
#[test]
fn natives_and_browser_grants_are_never_held() {
    let mut rig = Rig::new();
    rig.link_up();
    rig.connect("phone", phone());
    rig.advance(1000);
    let wall = rig.now.host.wall_ms;
    let grant_id = "aaaaaaaa-1111-4111-8111-0000000000d1";
    let (grant, key) = rig.log.grant(
        "dev-phone",
        grant_id,
        super::tests::HOST,
        1,
        None,
        &["view"],
        wall,
        wall + 600_000,
    );
    rig.connect(
        "browser",
        Identity::browser(grant.clone(), key.clone()).unwrap(),
    );
    rig.advance(1000);
    rig.connect("bot-1", bot());
    rig.attached("phone");
    rig.attached("browser");
    rig.attached("bot-1");
    let phone_gen = rig.rt.host.control_gen("member:dev-phone");
    let browser = format!("browser:{grant_id}");
    let browser_gen = rig.rt.host.control_gen(&browser);
    hold(&mut rig, &["member:dev-phone", &browser, BOT]);
    rig.pump();
    assert_eq!(rig.refused("bot-1").0, "closed");
    rig.attached("phone");
    rig.attached("browser");
    assert_eq!(rig.rt.host.control_gen("member:dev-phone"), phone_gen);
    assert_eq!(rig.rt.host.control_gen(&browser), browser_gen);
    rig.advance(1000);
    rig.connect("phone-2", phone());
    rig.attached("phone-2");
    rig.advance(1000);
    rig.connect("browser-2", Identity::browser(grant, key).unwrap());
    rig.attached("browser-2");
}

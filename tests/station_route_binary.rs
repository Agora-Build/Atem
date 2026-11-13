//! Real runtime and worker; synthetic paired peers on isolated loopback
//! endpoints. No live profile, relay, native app or provider is contacted.
#![cfg(target_os = "linux")]
mod support;

use atem_client::connect::{Attached, Event as ClientEvent, Identity};
use atem_client::session::wire;
use atem_client::station_route::{Message, Offer, Request};
use serde_json::{Value, json};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use support::astation::{ASTATION, Event, FakeAstation};
use support::r9::{Router, client_ms, write_pin};
use support::r9log::{MAC, TestLog, auth, secret};
use support::{Sandbox, within};

/// The longest a "wait until" helper waits. A passing run never gets near it;
/// a slow runner (the Intel macOS CI one takes ~340 s for ~45 s of tests) needs
/// the slack, and a hung test still ends.
const WAIT: Duration = Duration::from_secs(60);
const ACCOUNT: &str = "acct-station-selection";
const HOST: &str = "host-station-selection";

struct Runtime(Child);
impl Drop for Runtime {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start(sandbox: &Sandbox, source: &FakeAstation, fallback: &FakeAstation) -> Runtime {
    let log = std::fs::File::create(sandbox.dir.path().join("runtime.log")).unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_atem"))
        .arg("runtime")
        .env_clear()
        .envs(sandbox.env())
        .env("ASTATION_WS", &source.url)
        .env("ASTATION_RELAY_URL", &fallback.url)
        .stdin(Stdio::null())
        .stdout(log.try_clone().unwrap())
        .stderr(log)
        .spawn()
        .unwrap();
    within("runtime socket", || {
        sandbox.config().join("runtime.socket").exists()
    });
    sandbox.track();
    Runtime(child)
}

fn origin(peer: &FakeAstation) -> String {
    peer.url
        .replace("ws://", "http://")
        .trim_end_matches("/ws")
        .to_string()
}

fn request(router: &mut Router<'_>) -> Request {
    loop {
        let value = router.next_other();
        if let Ok(Message::Request { request, .. }) = Message::parse(value.to_string().as_bytes()) {
            return request;
        }
    }
}

fn accepted(router: &mut Router<'_>, offer: &Offer, blocked: bool) {
    let deadline = Instant::now() + WAIT;
    loop {
        assert!(
            Instant::now() < deadline,
            "routing acceptance was not delivered"
        );
        let value = router.next_other();
        if let Ok(Message::Accepted { accepted, .. }) = Message::parse(value.to_string().as_bytes())
        {
            assert_eq!(
                accepted.verify(offer, b"token-1").unwrap(),
                offer.request.route_revision + 1
            );
            assert_eq!(accepted.direct_blocked, blocked);
            break;
        }
    }
}

#[track_caller]
fn wait_data(
    router: &mut Router<'_>,
    attached: &mut Attached,
    handle: &str,
    accept: impl Fn(&Value) -> bool,
) -> Value {
    let deadline = Instant::now() + WAIT;
    let mut seen = Vec::new();
    loop {
        assert!(
            Instant::now() < deadline,
            "missing expected session response: {seen:?}"
        );
        for event in router.events(handle, attached).expect("open channel") {
            if seen.len() < 12 {
                seen.push(format!("{event:?}"));
            }
            let data = match event {
                ClientEvent::Session(message) => {
                    wire::to_value(&wire::Envelope::Session(message))["data"].clone()
                }
                ClientEvent::Family(family) => family.data.unwrap_or(Value::Null),
                _ => continue,
            };
            if accept(&data) {
                return data;
            }
        }
    }
}

fn workers(sandbox: &Sandbox) -> Vec<Value> {
    std::fs::read_dir(sandbox.workers())
        .unwrap()
        .filter_map(|e| {
            let path = e.unwrap().path();
            if path.extension().is_some_and(|e| e == "json") {
                let v: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
                Some(
                    json!({"session_id": v["session_id"], "process_gen": v["process_gen"],
                "worker_pid": v["worker_pid"], "agent_pid": v["agent_pid"]}),
                )
            } else {
                None
            }
        })
        .collect()
}

#[test]
fn selected_relay_switch_preserves_worker_input_receipts_and_pairing() {
    let sandbox = Sandbox::new();
    support::astation::write_verified_pairing(&sandbox.config(), ACCOUNT, HOST, 1);
    let seed = secret("selected relay host");
    let mut log = TestLog::genesis(ACCOUNT, &secret("selected relay native"));
    log.add_host(HOST, 1, &seed);
    write_pin(&sandbox.config(), &log, HOST, 1, &seed);
    let (source, selected, fallback) = (
        FakeAstation::start(),
        FakeAstation::start(),
        FakeAstation::start(),
    );
    let mut runtime = start(&sandbox, &source, &fallback);
    let runtime_pid = runtime.0.id();
    let mut router = Router::new(&source);
    let route_request = request(&mut router);

    let fake = sandbox.dir.path().join("fake");
    std::fs::create_dir(&fake).unwrap();
    let script = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/approvals/fake-agent.py");
    let mut frontend = sandbox.spawn(
        &["agent", "launch", "claude"],
        &sandbox.home,
        &[
            ("CLAUDE_CLI_BIN", script.to_str().unwrap()),
            ("FAKE_DIR", fake.to_str().unwrap()),
        ],
    );
    within("fixture agent startup", || {
        std::fs::read_to_string(fake.join("events"))
            .unwrap_or_default()
            .contains("started")
    });
    let sid = frontend.detach();
    sandbox.track();
    let before = workers(&sandbox);
    assert_eq!(before.len(), 1);
    assert!(
        before[0]["worker_pid"].as_u64().is_some(),
        "worker identity is measured"
    );
    let membership_before =
        std::fs::read(sandbox.config().join("pairing/membership.json")).unwrap();
    let trust_before = std::fs::read(sandbox.config().join("pairing/trust_gen")).unwrap();
    let identity = Identity::native(MAC, auth(MAC));
    let mut attached = router.connect("before", &log, HOST, &identity).unwrap();
    assert_eq!(router.list("before", &mut attached), [sid.clone()]);
    let process_gen = attached.target(&sid).unwrap().process_gen.clone();
    let ready_deadline = Instant::now() + WAIT;
    loop {
        let conversation = uuid::Uuid::new_v4().to_string();
        let frame = attached.send(&json!({"type":"agentChat", "data": {"v":1,"op":"open",
            "conversationId":conversation,"agentId":sid,"binding":{
                "target":attached.target(&sid).unwrap(),"attachment_gen":attached.welcome().attachment_gen}}}), client_ms()).unwrap();
        router.frame("before", &frame);
        let opened = wait_data(&mut router, &mut attached, "before", |v| {
            v["conversationId"] == conversation && (v["op"] == "opened" || v["op"] == "error")
        });
        if opened["status"]["state"] == "ready" {
            break;
        }
        assert!(Instant::now() < ready_deadline, "{opened}");
        std::thread::sleep(Duration::from_millis(100));
    }
    let rid = uuid::Uuid::new_v4().to_string();
    let (_, prompt) = attached
        .submit_prompt(
            &sid,
            &rid,
            "one prompt across a Station switch",
            client_ms(),
        )
        .unwrap();
    router.frame("before", &prompt);
    wait_data(&mut router, &mut attached, "before", |v| {
        v["op"] == "receipt" && v["state"] == "executing"
    });
    std::fs::write(fake.join("complete"), "").unwrap();
    wait_data(&mut router, &mut attached, "before", |v| {
        v["op"] == "receipt" && v["state"] == "completed"
    });
    let input_before = std::fs::read(fake.join("input")).unwrap();
    assert!(String::from_utf8_lossy(&input_before).contains("one prompt across a Station switch"));

    let forged = Offer::sign(route_request.clone(), &origin(&fallback), true, b"forged").unwrap();
    router.send_raw(
        Message::Offer {
            v: 1,
            offer: forged,
        }
        .to_json(),
    );
    std::thread::sleep(Duration::from_millis(100));
    assert!(!sandbox.config().join("pairing/station_route.json").exists());
    // Stage the selected endpoint before R9 relay-only closes the direct
    // socket. Native can commit policy only after verifying the durable ACK.
    let offer = Offer::sign(route_request, &origin(&selected), false, b"token-1").unwrap();
    let stale_offer = Message::Offer {
        v: 1,
        offer: offer.clone(),
    }
    .to_json();
    router.send_raw(stale_offer.clone());
    accepted(&mut router, &offer, false);
    assert!(
        selected.events.try_recv().is_err(),
        "staging keeps the direct socket"
    );
    let (_, frame) = attached
        .host_policy_set(true, &uuid::Uuid::new_v4().to_string(), client_ms())
        .unwrap();
    router.frame("before", &frame);
    let deadline = Instant::now() + WAIT;
    loop {
        assert!(
            Instant::now() < deadline,
            "relay-only policy result was not delivered"
        );
        if router.events("before", &mut attached).unwrap().iter().any(|e|
            matches!(e, ClientEvent::HostPolicy { result, .. } if result.policy.relay_only && result.outcome.confirms()))
        { break; }
    }

    let mut migrated = Router::new(&selected);
    let next_request = request(&mut migrated);
    assert_eq!(next_request.route_revision, 1);
    let mut attached = migrated.connect("after", &log, HOST, &identity).unwrap();
    assert_eq!(migrated.list("after", &mut attached), [sid.clone()]);
    assert_eq!(attached.target(&sid).unwrap().process_gen, process_gen);
    let (_, query) = attached
        .receipt_query(&sid, &[rid.clone()], client_ms())
        .unwrap();
    migrated.frame("after", &query);
    let receipts = wait_data(&mut migrated, &mut attached, "after", |v| {
        v["op"] == "receipts"
    });
    assert_eq!(receipts["receipts"][0]["request_id"], rid);
    assert_eq!(receipts["receipts"][0]["state"], "completed");
    migrated.send_raw(stale_offer);
    std::thread::sleep(Duration::from_millis(100));
    assert_eq!(workers(&sandbox), before);
    assert_eq!(
        std::fs::read(fake.join("input")).unwrap(),
        input_before,
        "no input replay"
    );
    assert_eq!(runtime.0.id(), runtime_pid);
    assert!(runtime.0.try_wait().unwrap().is_none());
    assert_eq!(
        std::fs::read(sandbox.config().join("pairing/trust_gen")).unwrap(),
        trust_before
    );
    assert_eq!(
        std::fs::read(sandbox.config().join("pairing/membership.json")).unwrap(),
        membership_before
    );
    assert_eq!(
        support::profile::saved_session_id(&sandbox.config()).as_deref(),
        Some("session-1")
    );
    assert!(
        fallback.events.try_recv().is_err(),
        "configured default never contacted"
    );
    assert!(
        source
            .events
            .try_iter()
            .all(|e| !matches!(e, Event::Authenticated(_))),
        "blocked direct link never reconnected"
    );

    // A second selection replaces the first relay while the agent runs.
    let custom = FakeAstation::start();
    let offer = Offer::sign(next_request, &origin(&custom), true, b"token-1").unwrap();
    migrated.send_raw(
        Message::Offer {
            v: 1,
            offer: offer.clone(),
        }
        .to_json(),
    );
    accepted(&mut migrated, &offer, true);
    let mut migrated = Router::new(&custom);
    assert_eq!(request(&mut migrated).route_revision, 2);
    let mut attached = migrated.connect("custom", &log, HOST, &identity).unwrap();
    assert_eq!(migrated.list("custom", &mut attached), [sid.clone()]);
    let (_, query) = attached
        .receipt_query(&sid, &[rid.clone()], client_ms())
        .unwrap();
    migrated.frame("custom", &query);
    let receipts = wait_data(&mut migrated, &mut attached, "custom", |v| {
        v["op"] == "receipts"
    });
    assert_eq!(receipts["receipts"][0]["request_id"], rid);
    assert_eq!(receipts["receipts"][0]["state"], "completed");
    assert_eq!(std::fs::read(fake.join("input")).unwrap(), input_before);

    // Only a durable R9 manager decision can reopen the direct route.
    // An unchanged true keeps the policy aligned before a newer false.
    let (_, frame) = attached.host_policy_get(false, client_ms()).unwrap();
    migrated.frame("custom", &frame);
    let deadline = Instant::now() + WAIT;
    loop {
        assert!(
            Instant::now() < deadline,
            "current policy was not delivered"
        );
        if migrated.events("custom", &mut attached).unwrap().iter().any(|e|
            matches!(e, ClientEvent::HostPolicy { result, .. } if result.policy.revision == 1 && result.policy.relay_only))
        { break; }
    }
    for relay_only in [true, false] {
        let (_, frame) = attached
            .host_policy_set(relay_only, &uuid::Uuid::new_v4().to_string(), client_ms())
            .unwrap();
        migrated.frame("custom", &frame);
        let deadline = Instant::now() + WAIT;
        loop {
            assert!(Instant::now() < deadline, "policy result was not delivered");
            if migrated.events("custom", &mut attached).unwrap().iter().any(|e|
                matches!(e, ClientEvent::HostPolicy { result, .. } if result.policy.relay_only == relay_only && result.outcome.confirms()))
            { break; }
        }
    }
    let mut direct = Router::new(&source);
    assert_eq!(request(&mut direct).route_revision, 2);
    assert_eq!(workers(&sandbox), before);
}

#[test]
fn unavailable_selected_relay_has_no_direct_or_default_fallback() {
    let sandbox = Sandbox::new();
    support::profile::write_pairing(&sandbox.config(), ASTATION, 1);
    let (source, fallback) = (FakeAstation::start(), FakeAstation::start());
    let mut runtime = start(&sandbox, &source, &fallback);
    let mut router = Router::new(&source);
    let request = request(&mut router);
    assert!(
        request.context.account_id.is_none(),
        "routing does not require membership"
    );
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let unavailable = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let offer = Offer::sign(request, &unavailable, true, b"token-1").unwrap();
    router.send_raw(
        Message::Offer {
            v: 1,
            offer: offer.clone(),
        }
        .to_json(),
    );
    accepted(&mut router, &offer, true);
    within("selected endpoint saved", || {
        sandbox.config().join("pairing/station_route.json").exists()
    });
    std::thread::sleep(Duration::from_millis(1500));
    assert!(runtime.0.try_wait().unwrap().is_none());
    assert!(
        source
            .events
            .try_iter()
            .all(|e| !matches!(e, Event::Authenticated(_))),
        "direct stays blocked"
    );
    assert!(
        fallback.events.try_recv().is_err(),
        "no configured/default relay fallback"
    );
    let log = std::fs::read_to_string(sandbox.dir.path().join("runtime.log")).unwrap();
    assert!(!log.contains("token-1"));
}

// ----------------------------------------------------- the fake Station
//
// The fake Station's own tests (tests/support/station.rs; later binary
// tests stand it in for Astation's Station on the host's link). Atem makes
// no Station call yet, so these play the host's side of the link by hand:
// a WebSocket client of the fake Astation that sends calls built with the
// shared builders (`atem_client::control::relay`) and reads what the fake
// sends as bytes.

use atem_client::canonical::jcs;
use atem_client::control::relay::MAX_RELAY_MESSAGE_BYTES;
use atem_client::control::{
    AckResult, ApplicationResult, CallRefused, ControlAck, ControlAction, ControlCheck,
    ControlRecord, ControlSigner, ControlState, ControlSync, ControlSyncResult, EffectKind,
    EffectResult, FeedEntry, FeedHead, FeedPos, Heads, MembershipFetch, MembershipFetchResult,
    RefusalCode, RefusalReason, RefusedCall, ToHost, ToStation, verify_control,
};
use atem_client::membership::{
    Entry, Head, Membership, ServiceScope, draft_on, service_add, sign_entry,
};
use atem_client::{Alg, PublicKey};
use support::station::{FakeStation, OTHER_ACCOUNT, StaleFeed};
use tokio_tungstenite::tungstenite::{self, Message as WsMessage, stream::MaybeTlsStream};

const FS_ACCOUNT: &str = "acct-fake-station";
const FS_HOST: &str = "host-fake-station";
const FS_SVC: &str = "svc-fake-station";
const FS_ORIGIN: &str = "https://station.test";
/// The Station's clock in these tests (ms).
const T0: u64 = 1_793_620_800_000;

/// The fake's device list: the Mac, this host and [`FS_SVC`].
fn station_log() -> TestLog {
    let mut log = TestLog::genesis(FS_ACCOUNT, &secret("fake station astation"));
    log.add_host(FS_HOST, 1, &secret("fake station host"));
    log.enroll_service(
        FS_SVC,
        &ServiceScope::new([FS_HOST]).ops(["prompt", "view"]),
        support::r9log::host_now().wall_ms + 3_600_000,
    );
    log
}

/// The shared builder's bytes for a message the shared reader read.
fn rebuilt(message: &ToHost) -> String {
    let refused = |call| CallRefused {
        call,
        code: RefusalCode::Forbidden,
    };
    match message {
        ToHost::ControlSyncResult(m) => m.to_json(),
        ToHost::Heads(m) => m.to_json(),
        ToHost::MembershipFetchResult(m) => m.to_json(),
        ToHost::ControlSyncRefused(_) => refused(RefusedCall::ControlSync).to_json(),
        ToHost::MembershipFetchRefused(_) => refused(RefusedCall::MembershipFetch).to_json(),
        ToHost::ControlAckRefused(_) => refused(RefusedCall::ControlAck).to_json(),
    }
    .unwrap()
    .to_string()
}

/// The host's side of its link: an authenticated client of the fake
/// Astation.
struct HostSide {
    ws: tungstenite::WebSocket<MaybeTlsStream<std::net::TcpStream>>,
    link: u64,
    /// Every call sent, as its bytes.
    calls: Vec<String>,
}

impl HostSide {
    fn connect(astation: &FakeAstation) -> HostSide {
        let (ws, _) = tungstenite::connect(astation.url.as_str()).unwrap();
        let MaybeTlsStream::Plain(stream) = ws.get_ref() else {
            unreachable!("ws://")
        };
        stream.set_read_timeout(Some(WAIT)).unwrap();
        let mut host = HostSide {
            ws,
            link: 0,
            calls: Vec::new(),
        };
        assert!(host.text().contains("auth_required"));
        let auth = json!({"type": "statusUpdate", "data": {"status": "auth", "data": {}}});
        host.ws.send(WsMessage::Text(auth.to_string())).unwrap();
        assert!(host.text().contains("authenticated"));
        host.link = Router::new(astation).link;
        host
    }

    fn text(&mut self) -> String {
        loop {
            match self.ws.read().unwrap() {
                WsMessage::Text(text) => return text,
                WsMessage::Close(_) => panic!("the link closed"),
                _ => {}
            }
        }
    }

    /// Sends a call the shared builder made.
    fn call(&mut self, message: Value) {
        let bytes = message.to_string();
        self.calls.push(bytes.clone());
        self.ws.send(WsMessage::Text(bytes)).unwrap();
    }

    /// The Station's next message: its bytes, which the shared reader
    /// reads and which are exactly the shared builder's for what it read.
    fn next(&mut self) -> (String, ToHost) {
        let bytes = self.text();
        let read = ToHost::decode(bytes.as_bytes())
            .unwrap_or_else(|e| panic!("the shared reader refuses {bytes}: {e}"));
        assert_eq!(rebuilt(&read), bytes, "not the shared builder's bytes");
        (bytes, read)
    }
}

fn sync(feed_id: Option<&str>, after: u64) -> Value {
    ControlSync {
        origin: FS_ORIGIN.into(),
        feed_id: feed_id.map(str::to_owned),
        after,
    }
    .to_json()
    .unwrap()
}

fn fetch(after: u64) -> Value {
    MembershipFetch { after }.to_json().unwrap()
}

fn page(host: &mut HostSide) -> ControlSyncResult {
    match host.next().1 {
        ToHost::ControlSyncResult(page) => page,
        other => panic!("not a page: {other:?}"),
    }
}

fn fetched(host: &mut HostSide) -> (String, MembershipFetchResult) {
    match host.next() {
        (bytes, ToHost::MembershipFetchResult(result)) => (bytes, result),
        (_, other) => panic!("not a fetch result: {other:?}"),
    }
}

fn record(object: &atem_client::SignedObject) -> ControlRecord {
    ControlRecord::from_signed(object.clone()).unwrap()
}

fn effect(effect: EffectKind, result: ApplicationResult) -> EffectResult {
    EffectResult { effect, result }
}

#[test]
fn fake_station_speaks_only_the_shared_builders() {
    let astation = FakeAstation::start();
    let log = station_log();
    let mut station = FakeStation::new(&astation, FS_ORIGIN, &log, FS_HOST, 1);
    station.station_time(T0);
    let mut host = HostSide::connect(&astation);

    // On the connection: heads, of an empty feed.
    assert!(station.serve(host.link).is_empty());
    let feed_id = station.feed_id().to_owned();
    let heads = |head| {
        ToHost::Heads(Heads {
            feeds: vec![FeedHead {
                origin: FS_ORIGIN.into(),
                feed_id: feed_id.clone(),
                head,
                station_time: T0,
            }],
            membership: log.log.head(),
        })
    };
    assert_eq!(host.next().1, heads(0));

    // Each record stored: heads at once.
    let cover = station.record_for(FS_SVC, ControlAction::Cover);
    let revoke = station.record_for(
        FS_SVC,
        ControlAction::Revoke {
            interrupt_running: true,
        },
    );
    assert_eq!(station.append(cover.clone()), 1);
    assert_eq!(host.next().1, heads(1));
    assert_eq!(station.append(revoke.clone()), 2);
    assert_eq!(host.next().1, heads(2));

    // control_sync from the start: the feed's page, as the builder writes it.
    host.call(sync(None, 0));
    assert!(matches!(
        station.next_call(host.link),
        Ok(ToStation::ControlSync(_))
    ));
    let expected = ControlSyncResult {
        origin: FS_ORIGIN.into(),
        feed_id: feed_id.clone(),
        head: 2,
        station_time: T0,
        records: vec![
            FeedEntry::new(1, &record(&cover)),
            FeedEntry::new(2, &record(&revoke)),
        ],
    };
    assert_eq!(host.next().0, expected.to_json().unwrap().to_string());
    // After the cursor: nothing more.
    host.call(sync(Some(&feed_id), 2));
    station.next_call(host.link).unwrap();
    let empty = ControlSyncResult {
        records: Vec::new(),
        ..expected
    };
    assert_eq!(host.next().0, empty.to_json().unwrap().to_string());

    // membership_fetch: the entries after `after`, the list's head.
    host.call(fetch(1));
    assert!(matches!(
        station.next_call(host.link),
        Ok(ToStation::MembershipFetch(MembershipFetch { after: 1 }))
    ));
    let expected = MembershipFetchResult {
        head: log.log.head(),
        entries: log.entries[1..]
            .iter()
            .map(|e| e.object().clone())
            .collect(),
    };
    assert_eq!(host.next().0, expected.to_json().unwrap().to_string());

    // control_ack: no answer; the reference ledger counts it for the link's
    // host (the revocation applied there: its first report).
    let revoke_id = record(&revoke).record_id().to_owned();
    let ack = ControlAck {
        account_id: FS_ACCOUNT.into(),
        genesis_hash: log.genesis_hash(),
        host_id: FS_HOST.into(),
        host_trust_gen: 1,
        origin: FS_ORIGIN.into(),
        feed_id: feed_id.clone(),
        cursor: 2,
        results: vec![AckResult::Record {
            record_id: revoke_id,
            effects: vec![
                effect(EffectKind::Revocation, ApplicationResult::Applied),
                effect(EffectKind::Interrupt, ApplicationResult::Applied),
            ],
        }],
    };
    assert!(station.acks().pending_reports().is_empty());
    host.call(ack.to_json().unwrap());
    assert!(matches!(
        station.next_call(host.link),
        Ok(ToStation::ControlAck(_))
    ));
    let reports = station.acks().pending_reports();
    assert_eq!(reports.len(), 1, "{reports:?}");
    assert_eq!(reports[0].report.kind(), "revocation_applied");

    // An ack whose claim isn't the link's: refused, counted nothing (the
    // refusal is the next thing the host reads: the ack above got none).
    let ledger = station.acks().clone();
    let claim = ControlAck {
        host_trust_gen: 2,
        ..ack.clone()
    };
    host.call(claim.to_json().unwrap());
    station.next_call(host.link).unwrap();
    assert_eq!(
        host.next().1,
        ToHost::ControlAckRefused(RefusalCode::Forbidden)
    );
    assert_eq!(station.acks(), &ledger);
    // An ack about another Station's feed (its claim the link's): refused
    // too. (`other_account` can't arise here: the link is the host's, in
    // the ledger's account.)
    let elsewhere = ControlAck {
        origin: "https://other.test".into(),
        ..ack.clone()
    };
    host.call(elsewhere.to_json().unwrap());
    station.next_call(host.link).unwrap();
    assert_eq!(
        host.next().1,
        ToHost::ControlAckRefused(RefusalCode::Forbidden)
    );
    assert_eq!(station.acks(), &ledger);
    let codes: Vec<_> = station.ack_refusals().iter().map(|r| r.code()).collect();
    assert_eq!(codes, ["not_the_link", "other_station"]);

    // Each call refused when the test says so: its typed refusal, nothing
    // served or counted.
    station.refuse(RefusedCall::ControlSync, true);
    host.call(sync(Some(&feed_id), 0));
    station.next_call(host.link).unwrap();
    assert_eq!(
        host.next().1,
        ToHost::ControlSyncRefused(RefusalCode::Forbidden)
    );
    station.refuse(RefusedCall::MembershipFetch, true);
    host.call(fetch(0));
    station.next_call(host.link).unwrap();
    assert_eq!(
        host.next().1,
        ToHost::MembershipFetchRefused(RefusalCode::Forbidden)
    );
    station.refuse(RefusedCall::ControlAck, true);
    host.call(ack.to_json().unwrap());
    station.next_call(host.link).unwrap();
    assert_eq!(
        host.next().1,
        ToHost::ControlAckRefused(RefusalCode::Forbidden)
    );
    assert_eq!(station.acks(), &ledger);
    // And served again once it says no more.
    station.refuse(RefusedCall::ControlSync, false);
    host.call(sync(Some(&feed_id), 2));
    station.next_call(host.link).unwrap();
    assert_eq!(host.next().0, empty.to_json().unwrap().to_string());

    // The host's calls, as the bytes it sent, in order.
    assert_eq!(station.sent(), host.calls);
}

/// Ed25519 public key of `label`'s test secret.
fn ed25519(label: &str) -> PublicKey {
    let seed = secret(label);
    let public = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    PublicKey::new(Alg::Ed25519, &public).unwrap()
}

/// `log` grown by the Mac's entries of `bodies` (each made from the head
/// before it), chained by hand and the chain verified once at the end
/// (`TestLog::append` verifies all of it at every entry: slow in debug for a
/// long list).
fn grow(log: &mut TestLog, mut body: impl FnMut(&TestLog, Head) -> Option<Value>) {
    let mut head = log.log.head();
    while let Some(draft) = body(log, head) {
        let entry: Entry = sign_entry(&log.keys, &auth(MAC), draft).unwrap();
        head = Head {
            seq: entry.seq,
            hash: entry.hash(),
        };
        log.entries.push(entry);
    }
    log.log = Membership::verify_chain(&log.account, &log.genesis_hash(), &log.entries, &log.now)
        .unwrap()
        .membership;
}

/// The Mac's `add` of service `id` with `scope`, on `head` (`None`: the
/// builder refuses it, e.g. too large).
fn service_body(log: &TestLog, head: Head, id: &str, scope: &ServiceScope) -> Option<Value> {
    let now = support::r9log::host_now().wall_ms;
    let action = service_add(id, ed25519(id), scope, now + 3_600_000, now).ok()?;
    let body = draft_on(
        &log.account,
        &log.genesis_hash(),
        head.seq + 1,
        &head.hash,
        MAC,
        now,
        &action,
    );
    (jcs(&body).unwrap().len() <= atem_client::signed::MAX_BODY_BYTES).then_some(body)
}

/// A service whose entry's body is as near the 4,096-byte bound as its
/// scope gets: sixteen 128-character hosts, then project hashes, then
/// session ids, each added while the body's `jcs` stays within it.
fn near_max_service(log: &TestLog, head: Head, n: usize) -> Value {
    let id = format!("svc-big-{n}");
    let hosts: Vec<String> = (0..16)
        .map(|j| format!("{:x<128}", format!("h{n}-{j}-")))
        .collect();
    let fits = |scope: &ServiceScope| service_body(log, head, &id, scope);
    let project = |k: usize| format!("h1.0a0b0c0d.{:064x}", n * 100 + k);
    let session = |k: usize| {
        let digits = format!("{:012}", n * 100 + k);
        let base32: String = digits
            .bytes()
            .map(|d| (b'a' + (d - b'0')) as char)
            .collect();
        format!("ses-{base32}")
    };
    let mut projects = 0;
    let scope_of = |projects: usize, sessions: usize| {
        let scope = ServiceScope::new(hosts.clone()).ops(["view"]);
        let scope = scope.projects(Some((0..projects).map(project)));
        if sessions == 0 {
            scope
        } else {
            scope.sessions(Some((0..sessions).map(session)))
        }
    };
    while projects < 64 && fits(&scope_of(projects + 1, 0)).is_some() {
        projects += 1;
    }
    let mut sessions = 0;
    while sessions < 64 && fits(&scope_of(projects, sessions + 1)).is_some() {
        sessions += 1;
    }
    let body = fits(&scope_of(projects, sessions)).unwrap();
    assert!(jcs(&body).unwrap().len() > 4000, "a near-max entry");
    body
}

#[test]
fn fake_station_pages_within_256_kib_and_64_items() {
    let astation = FakeAstation::start();
    let mut log = station_log();
    // 70 small entries in all.
    let mut n = 0;
    grow(&mut log, |log, head| {
        n += 1;
        (n <= 67).then(|| {
            let scope = ServiceScope::new([FS_HOST]).ops(["view"]);
            service_body(log, head, &format!("svc-small-{n}"), &scope).unwrap()
        })
    });
    assert_eq!(log.log.head().seq, 70);
    let mut station = FakeStation::new(&astation, FS_ORIGIN, &log, FS_HOST, 1);
    station.station_time(T0);
    station.silence_heads(true);
    let mut host = HostSide::connect(&astation);
    assert!(station.serve(host.link).is_empty());

    // A feed of 70 records: 64 in a page, then the other 6.
    for _ in 0..70 {
        let hold = station.record_for(FS_SVC, ControlAction::Hold);
        station.append(hold);
    }
    let feed_id = station.feed_id().to_owned();
    host.call(sync(Some(&feed_id), 0));
    station.next_call(host.link).unwrap();
    let first = page(&mut host);
    assert_eq!((first.head, first.records.len()), (70, 64));
    let seqs: Vec<u64> = first.records.iter().map(|e| e.feed_seq).collect();
    assert_eq!(seqs, (1..=64).collect::<Vec<_>>());
    host.call(sync(Some(&feed_id), 64));
    station.next_call(host.link).unwrap();
    let rest = page(&mut host);
    let seqs: Vec<u64> = rest.records.iter().map(|e| e.feed_seq).collect();
    assert_eq!(seqs, (65..=70).collect::<Vec<_>>());
    assert_eq!(
        rest.records[5].raw(),
        &station.records()[69].1.object().to_json()
    );

    // A device list of 70 small entries: 64 entries in a fetch.
    host.call(fetch(0));
    station.next_call(host.link).unwrap();
    let (_, result) = fetched(&mut host);
    assert_eq!(result.head, log.log.head());
    let wire =
        |entries: &[Entry]| -> Vec<_> { entries.iter().map(|e| e.object().clone()).collect() };
    assert_eq!(result.entries, wire(&log.entries[..64]));
    host.call(fetch(64));
    station.next_call(host.link).unwrap();
    assert_eq!(fetched(&mut host).1.entries, wire(&log.entries[64..]));

    // 70 near-max entries more: a fetch holds as many as fit in 256 KiB,
    // fewer than 64, and one more wouldn't fit; fetching from each new
    // head brings all of them, in order.
    let mut big = 0;
    grow(&mut log, |log, head| {
        big += 1;
        (big <= 70).then(|| near_max_service(log, head, big))
    });
    station.set_log(&log);
    let mut after = 70;
    let mut pages = Vec::new();
    loop {
        host.call(fetch(after));
        station.next_call(host.link).unwrap();
        let (bytes, result) = fetched(&mut host);
        assert!(bytes.len() <= MAX_RELAY_MESSAGE_BYTES, "{}", bytes.len());
        assert_eq!(result.head, log.log.head());
        let n = result.entries.len();
        if n == 0 {
            break;
        }
        let from = after as usize;
        assert_eq!(result.entries, wire(&log.entries[from..from + n]));
        if from + n < log.entries.len() {
            let one_more = MembershipFetchResult {
                head: result.head,
                entries: wire(&log.entries[from..from + n + 1]),
            };
            assert_eq!(
                one_more.to_json(),
                Err(atem_client::control::RelayError::TooLarge),
                "a page as full as fits"
            );
        }
        pages.push(n);
        after += n as u64;
    }
    assert_eq!(after, 140);
    assert!(pages[0] < 64, "the byte bound, not the count: {pages:?}");
}

#[test]
fn fake_station_refuses_other_feeds_and_serves_another_account_when_told() {
    let astation = FakeAstation::start();
    let log = station_log();
    let mut station = FakeStation::new(&astation, FS_ORIGIN, &log, FS_HOST, 1);
    station.station_time(T0);
    station.silence_heads(true);
    let mut host = HostSide::connect(&astation);
    station.serve(host.link);
    let revoke = ControlAction::Revoke {
        interrupt_running: false,
    };
    let own = station.record_for(FS_SVC, revoke);
    station.append(own.clone());
    let own_feed = station.feed_id().to_owned();

    // One feed per account: a feed that isn't this account's at this
    // Station is refused, and nothing of it served.
    let elsewhere = ControlSync {
        origin: "https://other.test".into(),
        feed_id: None,
        after: 0,
    };
    for call in [
        sync(Some("6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b"), 0),
        elsewhere.to_json().unwrap(),
    ] {
        host.call(call);
        station.next_call(host.link).unwrap();
        assert_eq!(
            host.next().1,
            ToHost::ControlSyncRefused(RefusalCode::Forbidden)
        );
    }

    // Told to, it serves another account's data: heads naming its feed and
    // device list, its feed's records and its device list's entries.
    station.serve_other_account(true);
    let other_feed = station.feed_id().to_owned();
    assert_ne!(other_feed, own_feed);
    let other = station.record_for(FS_SVC, revoke);
    assert_eq!(station.append(other.clone()), 1);
    station.heads_now();
    let ToHost::Heads(heads) = host.next().1 else {
        panic!("heads")
    };
    assert_eq!(heads.feeds[0].feed_id, other_feed);
    assert_eq!(heads.feeds[0].head, 1);
    assert_ne!(heads.membership, log.log.head());
    host.call(sync(Some(&other_feed), 0));
    station.next_call(host.link).unwrap();
    let served = page(&mut host);
    assert_eq!(served.feed_id, other_feed);
    let read = served.records[0].parse_record().unwrap();
    assert_eq!(read.account_id(), OTHER_ACCOUNT);
    assert_eq!(read.object(), &other);
    assert!(matches!(
        verify_control(&read, &log.log),
        ControlCheck::Refused(RefusalReason::WrongAccount)
    ));
    host.call(fetch(0));
    station.next_call(host.link).unwrap();
    let (_, result) = fetched(&mut host);
    assert_eq!(result.head, heads.membership);
    let genesis = Entry::parse(result.entries[0].clone()).unwrap();
    assert_eq!(genesis.account_id, OTHER_ACCOUNT);
    // While it does, this account's own feed is the one it doesn't serve.
    host.call(sync(Some(&own_feed), 0));
    station.next_call(host.link).unwrap();
    assert_eq!(
        host.next().1,
        ToHost::ControlSyncRefused(RefusalCode::Forbidden)
    );

    // Back to this account's.
    station.serve_other_account(false);
    assert_eq!(station.feed_id(), own_feed);
    host.call(sync(Some(&own_feed), 0));
    station.next_call(host.link).unwrap();
    let served = page(&mut host);
    assert_eq!(served.records[0].parse_record().unwrap().object(), &own);
}

#[test]
fn fake_station_reset_mints_a_feed_and_snapshots_each_principals_state() {
    let astation = FakeAstation::start();
    let log = station_log();
    let mut station = FakeStation::new(&astation, FS_ORIGIN, &log, FS_HOST, 1);
    station.station_time(T0);
    let mut host = HostSide::connect(&astation);
    station.serve(host.link);
    let _ = host.next();
    let cover = record(&station.record_for(FS_SVC, ControlAction::Cover));
    let hold = record(&station.record_for(FS_SVC, ControlAction::Hold));
    let revoke = record(&station.record_for(
        FS_SVC,
        ControlAction::Revoke {
            interrupt_running: true,
        },
    ));
    for rec in [&cover, &hold, &revoke] {
        station.append(rec.object().clone());
        let _ = host.next();
    }
    let old_feed = station.feed_id().to_owned();

    // A reset: a new feed, announced at once, starting with the snapshot.
    station.station_time(T0 + 1_000);
    station.reset();
    let new_feed = station.feed_id().to_owned();
    assert_ne!(new_feed, old_feed);
    let ToHost::Heads(heads) = host.next().1 else {
        panic!("heads")
    };
    assert_eq!(
        (heads.feeds[0].feed_id.as_str(), heads.feeds[0].head),
        (new_feed.as_str(), 3)
    );
    host.call(sync(None, 0));
    station.next_call(host.link).unwrap();
    let snapshot: Vec<ControlRecord> = page(&mut host)
        .records
        .iter()
        .map(|e| e.parse_record().unwrap())
        .collect();
    assert_eq!(snapshot.len(), 3);
    // Its cover and hold signed anew for the new feed, newer than the old
    // ones; its revoke as it is.
    for (anew, old) in [(&snapshot[0], &cover), (&snapshot[1], &hold)] {
        assert_eq!(anew.action(), old.action());
        assert_eq!(anew.feed(), Some((FS_ORIGIN, new_feed.as_str())));
        assert_ne!(anew.record_id(), old.record_id());
        assert!(anew.issued_at() > old.issued_at());
        assert_eq!(anew.signer(), &ControlSigner::Principal);
    }
    assert_eq!(snapshot[2].object(), revoke.object());
    for rec in &snapshot {
        assert!(matches!(
            verify_control(rec, &log.log),
            ControlCheck::Valid(_)
        ));
    }

    // The snapshot loses no stop: on a host that never saw the old feed it
    // applies, on one that applied the old feed it is a duplicate.
    let at = |feed: &str, feed_seq| {
        Some(FeedPos {
            origin: FS_ORIGIN.into(),
            feed_id: feed.into(),
            feed_seq,
        })
    };
    let seq = log.log.head().seq;
    let (mut fresh, mut seen) = (ControlState::new(&log.log), ControlState::new(&log.log));
    for (n, rec) in [&cover, &hold, &revoke].into_iter().enumerate() {
        seen = seen
            .apply(rec, &log.log, at(&old_feed, n as u64 + 1), seq)
            .next;
    }
    for (n, rec) in snapshot.iter().enumerate() {
        let pos = at(&new_feed, n as u64 + 1);
        let applied = fresh.apply(rec, &log.log, pos.clone(), seq);
        assert_eq!(
            applied.applied.record_result,
            ApplicationResult::Applied,
            "{n}"
        );
        fresh = applied.next;
        let again = seen.apply(rec, &log.log, pos, seq);
        assert_eq!(
            again.applied.record_result,
            ApplicationResult::Duplicate,
            "{n}"
        );
        seen = again.next;
    }

    // A call naming the old feed: §11.4 doesn't say. Refused by default
    // (Atem's literal reading) ...
    host.call(sync(Some(&old_feed), 3));
    station.next_call(host.link).unwrap();
    assert_eq!(
        host.next().1,
        ToHost::ControlSyncRefused(RefusalCode::Forbidden)
    );
    // ... or, in the other reading, the current feed from position 0 (the
    // old cursor is no position in it): the new `feed_id` tells the host.
    station.stale_feed(StaleFeed::ServeCurrent);
    host.call(sync(Some(&old_feed), 3));
    station.next_call(host.link).unwrap();
    let served = page(&mut host);
    assert_eq!(
        (served.feed_id.as_str(), served.head),
        (new_feed.as_str(), 3)
    );
    let objects: Vec<_> = served
        .records
        .iter()
        .map(|e| e.parse_record().unwrap().object().clone())
        .collect();
    let snapshot: Vec<_> = snapshot.iter().map(|r| r.object().clone()).collect();
    assert_eq!(objects, snapshot);
    // A `feed_id` the account never had is refused in either reading.
    for mode in [StaleFeed::ServeCurrent, StaleFeed::Refuse] {
        station.stale_feed(mode);
        host.call(sync(Some("6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b"), 0));
        station.next_call(host.link).unwrap();
        assert_eq!(
            host.next().1,
            ToHost::ControlSyncRefused(RefusalCode::Forbidden)
        );
    }
}

#[test]
fn fake_station_announces_any_heads_leaves_gaps_and_rolls_back() {
    let astation = FakeAstation::start();
    let log = station_log();
    let mut station = FakeStation::new(&astation, FS_ORIGIN, &log, FS_HOST, 1);
    station.station_time(T0);
    station.silence_heads(true);
    let mut host = HostSide::connect(&astation);
    station.serve(host.link);
    let feed_id = station.feed_id().to_owned();

    // Heads naming any feeds: another origin's beside this one.
    let feeds = vec![
        FeedHead {
            origin: "https://other.test".into(),
            feed_id: "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b".into(),
            head: 7,
            station_time: T0,
        },
        FeedHead {
            origin: FS_ORIGIN.into(),
            feed_id: feed_id.clone(),
            head: 0,
            station_time: T0,
        },
    ];
    station.heads_with(feeds.clone());
    assert_eq!(
        host.next().1,
        ToHost::Heads(Heads {
            feeds,
            membership: log.log.head()
        })
    );

    // Positions left out: records at 1 and 4.
    let hold = station.record_for(FS_SVC, ControlAction::Hold);
    assert_eq!(station.append(hold), 1);
    station.append_gap(2);
    let release = station.record_for(FS_SVC, ControlAction::Release);
    assert_eq!(station.append(release), 4);
    host.call(sync(Some(&feed_id), 0));
    station.next_call(host.link).unwrap();
    let served = page(&mut host);
    let seqs: Vec<u64> = served.records.iter().map(|e| e.feed_seq).collect();
    assert_eq!((served.head, seqs), (4, vec![1, 4]));

    // Rolled back under the same feed: the head below a cursor at 4.
    station.truncate(1);
    station.heads_now();
    let ToHost::Heads(heads) = host.next().1 else {
        panic!("heads")
    };
    assert_eq!(
        (heads.feeds[0].feed_id.as_str(), heads.feeds[0].head),
        (feed_id.as_str(), 1)
    );
    host.call(sync(Some(&feed_id), 4));
    station.next_call(host.link).unwrap();
    let served = page(&mut host);
    assert_eq!((served.head, served.records.len()), (1, 0));
    let cover = station.record_for(FS_SVC, ControlAction::Cover);
    assert_eq!(station.append(cover), 2);
}

#[test]
fn fake_station_keeps_the_hosts_exact_bytes() {
    let astation = FakeAstation::start();
    let log = station_log();
    let mut station = FakeStation::new(&astation, FS_ORIGIN, &log, FS_HOST, 1);
    station.station_time(T0);
    station.silence_heads(true);
    let mut host = HostSide::connect(&astation);
    station.serve(host.link);

    // Whitespace and escapes the strict reader accepts: read, answered,
    // and kept byte for byte.
    let spaced = r#"{ "type": "relay", "op": "control_syn\u0063",
        "origin": "https://station.tes\u0074", "after": 0 }"#;
    host.ws.send(WsMessage::Text(spaced.into())).unwrap();
    assert_eq!(
        station.next_call(host.link),
        Ok(ToStation::ControlSync(ControlSync {
            origin: FS_ORIGIN.into(),
            feed_id: None,
            after: 0,
        }))
    );
    assert!(matches!(page(&mut host).records[..], []));

    // Text that isn't JSON but names a call: kept, refused by the reader,
    // not answered (the next thing the host reads answers the next call).
    let broken = r#"{"type":"relay","op":"membership_fetch","after":"#;
    host.ws.send(WsMessage::Text(broken.into())).unwrap();
    assert_eq!(
        station.next_call(host.link),
        Err(atem_client::control::RelayError::NotStrict)
    );
    host.call(fetch(2));
    station.next_call(host.link).unwrap();
    assert_eq!(
        fetched(&mut host).1.entries,
        log.entries[2..]
            .iter()
            .map(|e| e.object().clone())
            .collect::<Vec<_>>()
    );

    let mut expected = vec![spaced.to_owned(), broken.to_owned()];
    expected.extend(host.calls.iter().cloned());
    assert_eq!(station.sent(), expected);
}

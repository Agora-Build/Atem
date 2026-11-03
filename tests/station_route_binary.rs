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
    let deadline = Instant::now() + Duration::from_secs(10);
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
    let deadline = Instant::now() + Duration::from_secs(10);
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
    let ready_deadline = Instant::now() + Duration::from_secs(10);
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
    let deadline = Instant::now() + Duration::from_secs(10);
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
    let deadline = Instant::now() + Duration::from_secs(10);
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
        let deadline = Instant::now() + Duration::from_secs(10);
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

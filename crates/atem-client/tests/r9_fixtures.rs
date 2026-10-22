//! Runs the r9 push, seen, principal and multi-device scenarios
//! (`designs/protocol/fixtures/r9-push-*`, `r9-seen-*`, `r9-approval-seen`,
//! `r9-service-scope-and-expiry`, `r9-browser-grant`, `r9-multi-device-*`).
//!
//! - `side: "relay"` scenarios run in full against the crate's reference
//!   relay (`push::RelayLedger`: verification, the full-identity book, the
//!   schedule from the signed `created_at`, seen, acks), the fixture
//!   playing hosts and devices; a device opens its sealed part with its own
//!   key.
//! - `side: "host"` scenarios run the client machines (`connect`) against
//!   the test host of `support/host.rs`, built from the crate's responder
//!   role and host-side decisions: admission and the welcome, §R9.6
//!   authority (scope, ops, expiry, grants, revocation), the push hints,
//!   seen outcomes and the outbox. What only the real runtime host can
//!   show (r8 events to other attachments, approval cards, receipts beyond
//!   acceptance, control generations, attachment counts) is listed pending
//!   with its owner. An unknown step or key fails the run.
mod support;

use std::collections::{BTreeMap, VecDeque};

use atem_client::connect::{Attached, ConnectError, Connector, Event, Identity};
use atem_client::membership::Membership;
use atem_client::principal::{Need, Op as AuthOp};
use atem_client::push::{
    self, DeviceClass, Hint, HintPlain, Push, RecipientInfo, RelayLedger, Verifier,
};
use atem_client::session::wire::{self, Envelope};
use atem_client::{KeyId, SignedObject};
use serde_json::{Value, json};
use support::host::{HostConn, HostCore, HostSession};
use support::*;

const T7: &str = "host runner (src/session_protocol/membership/fixtures_tests.rs: the real r9 admission engine, device-list store and session host)";

fn resolve(value: &Value, v: &Vectors, captured: &BTreeMap<String, Value>) -> Value {
    match value {
        Value::String(text) => {
            if let Some(label) = text
                .strip_prefix("${hash:")
                .and_then(|t| t.strip_suffix('}'))
            {
                return Value::String(v.hash(label).to_hex());
            }
            if let Some(rest) = text
                .strip_prefix("${vector:")
                .and_then(|t| t.strip_suffix('}'))
            {
                let (file, path) = rest.split_once(':').unwrap();
                let mut node = load(file);
                for part in path.split('.') {
                    node = match part.parse::<usize>() {
                        Ok(i) => node[i].clone(),
                        Err(_) => node[part].clone(),
                    };
                }
                return node;
            }
            if let Some(name) = text.strip_prefix("${").and_then(|t| t.strip_suffix('}'))
                && let Some(value) = captured.get(name)
            {
                return value.clone();
            }
            value.clone()
        }
        Value::Array(items) => {
            Value::Array(items.iter().map(|i| resolve(i, v, captured)).collect())
        }
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(k, x)| (k.clone(), resolve(x, v, captured)))
                .collect(),
        ),
        other => other.clone(),
    }
}

/// `a.b.0.c` (and `x.#` for an array's length) in `value`.
fn at(value: &Value, path: &str) -> Value {
    let mut node = value.clone();
    for part in path.split('.') {
        node = match (part, part.parse::<usize>()) {
            ("#", _) => json!(node.as_array().map_or(0, |a| a.len())),
            (_, Ok(i)) => node[i].clone(),
            (_, Err(_)) => node[part].clone(),
        };
    }
    node
}

fn matches(value: &Value, want: &Value) -> bool {
    want.as_object()
        .unwrap()
        .iter()
        .all(|(path, w)| at(value, path) == *w)
}

#[derive(Default)]
struct Report {
    name: String,
    passed: usize,
    pending: Vec<(String, &'static str)>,
}

impl Report {
    fn pass(&mut self) {
        self.passed += 1;
    }
    fn pending(&mut self, what: impl Into<String>, owner: &'static str) {
        self.pending.push((what.into(), owner));
    }
}

fn pinned_log(v: &Vectors, setup: &Value, clock: &Clock) -> Membership {
    let labels: Vec<String> = setup["pinned"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap().to_owned())
        .collect();
    let refs: Vec<&str> = labels.iter().map(String::as_str).collect();
    Membership::verify_chain(ACCOUNT, &genesis_hash(), &v.entries(&refs), &clock.now)
        .unwrap()
        .membership
}

// ------------------------------------------------------------ relay side

struct RelayRun<'a> {
    v: &'a Vectors,
    book: &'a Book,
    log: Membership,
    ledger: RelayLedger,
    now: u64,
    replica: String,
    pushes: VecDeque<(Push, String)>,
    desktop_connected: bool,
    immediate: Vec<String>,
    last_verdict: Option<String>,
    last_ack: Option<Value>,
    report: Report,
}

impl RelayRun<'_> {
    fn device(&self, id: &str) -> RecipientInfo {
        RecipientInfo {
            class: if id == "dev-mac" {
                DeviceClass::Desktop
            } else {
                DeviceClass::Mobile
            },
            connected: id == "dev-mac" && self.desktop_connected,
            immediate_mobile: self.immediate.iter().any(|d| d == id),
        }
    }

    fn due(&mut self) {
        let infos: BTreeMap<String, RecipientInfo> = ["dev-mac", "dev-phone", "dev-ipad"]
            .iter()
            .map(|d| (d.to_string(), self.device(d)))
            .collect();
        let pushes = self.ledger.due(self.now, &|d| infos[d]);
        for p in pushes {
            self.pushes.push_back((p, self.replica.clone()));
        }
    }

    fn next_wake(&self) -> Option<u64> {
        let infos: BTreeMap<String, RecipientInfo> = ["dev-mac", "dev-phone", "dev-ipad"]
            .iter()
            .map(|d| (d.to_string(), self.device(d)))
            .collect();
        self.ledger.next_wake(self.now, &|d| infos[d])
    }

    fn advance(&mut self, ms: u64) {
        let to = self.now + ms;
        loop {
            self.due();
            match self.next_wake() {
                Some(w) if w > self.now && w <= to => self.now = w,
                _ => break,
            }
        }
        self.now = to;
        self.due();
    }

    /// The wire object of a vector (a vector may annotate it with `note`
    /// and `*_hex` fields, which aren't part of the object).
    fn object(&self, value: &Value) -> SignedObject {
        let mut wire = value.clone();
        if let Some(o) = wire.as_object_mut() {
            o.retain(|k, _| k != "note" && !k.ends_with("_hex"));
        }
        SignedObject::parse(wire.to_string().as_bytes()).unwrap()
    }

    fn step(&mut self, step: &Value) {
        let captured = BTreeMap::new();
        let step = resolve(step, self.v, &captured);
        let o = step.as_object().unwrap();
        let kind = o
            .keys()
            .find(|k| *k != "tamper" && *k != "plain")
            .unwrap()
            .as_str();
        match kind {
            "relay_receive" => {
                let mut hint = step["relay_receive"].clone();
                if let Some(tamper) = step.get("tamper") {
                    for (path, value) in tamper.as_object().unwrap() {
                        let (a, b) = path.split_once('.').unwrap();
                        hint[a][b] = value.clone();
                    }
                }
                let (verdict, _) =
                    self.ledger
                        .receive_hint(&self.object(&hint), &self.log, self.now);
                self.last_verdict = Some(verdict.code().to_owned());
                self.due();
                self.report.pass();
            }
            "relay_receive_seen" => {
                let seen = self.object(&step["relay_receive_seen"]);
                let (verdict, id) = self.ledger.receive_seen(&seen, &self.log, self.now);
                self.last_verdict = Some(verdict.code().to_owned());
                self.last_ack = Some(push::push_ack(&id.into_iter().collect::<Vec<_>>()));
                self.due();
                self.report.pass();
            }
            "relay_result" => {
                assert_eq!(
                    self.last_verdict.take().as_deref(),
                    step["relay_result"].as_str(),
                    "{}",
                    self.report.name
                );
                self.report.pass();
            }
            "expect_relay_ack" => {
                let want = &step["expect_relay_ack"];
                let got = self.last_ack.take().expect("an ack");
                assert_eq!(got["op"], want["op"]);
                assert_eq!(got["acks"], want["acks"], "{}", self.report.name);
                // Every ack entry parses back to the identity it names.
                for a in got["acks"].as_array().unwrap() {
                    assert_eq!(push::Identity::from_ack(a).unwrap().to_ack(), *a);
                }
                self.report.pass();
            }
            "expect_push" => {
                let want = &step["expect_push"];
                let i = self
                    .pushes
                    .iter()
                    .position(|(p, replica)| {
                        p.device_id == want["device"].as_str().unwrap()
                            && p.kind == want["kind"].as_str().unwrap()
                            && want
                                .get("due_at")
                                .is_none_or(|d| d.as_u64() == Some(p.due_at))
                            && want
                                .get("collapse_id")
                                .is_none_or(|c| c.as_str() == Some(p.collapse_id.as_str()))
                            && want
                                .get("replica")
                                .is_none_or(|r| r.as_str() == Some(replica.as_str()))
                    })
                    .unwrap_or_else(|| {
                        panic!("{}: no push {want} in {:?}", self.report.name, self.pushes)
                    });
                self.pushes.remove(i);
                self.report.pass();
            }
            "expect_no_push" => {
                let for_ms = step["expect_no_push"]["for_ms"].as_u64().unwrap();
                assert!(
                    self.pushes.is_empty(),
                    "{}: {:?}",
                    self.report.name,
                    self.pushes
                );
                assert!(
                    self.next_wake().is_none_or(|w| w >= self.now + for_ms),
                    "{}: something is due within {for_ms} ms",
                    self.report.name
                );
                self.report.pass();
            }
            "advance_ms" => {
                self.advance(step["advance_ms"].as_u64().unwrap());
                self.report.pass();
            }
            "relay_restart" => {
                // The ledger is the durable store: a restart keeps it.
                self.ledger = self.ledger.clone();
                self.report.pass();
            }
            "relay_failover" => {
                assert_eq!(
                    step["relay_failover"]["from"].as_str(),
                    Some(self.replica.as_str())
                );
                self.replica = step["relay_failover"]["to"].as_str().unwrap().to_owned();
                self.report.pass();
            }
            "client_open" => {
                let spec = &step["client_open"];
                let device = spec["device"].as_str().unwrap();
                let object = self.object(&spec["envelope"]);
                let hint = Hint::verify(&object, &self.log, self.now, Verifier::Client).unwrap();
                let plain = hint
                    .open(
                        &self.book.provider,
                        &KeyId::new(format!("{device}/enc")),
                        device,
                    )
                    .unwrap();
                assert_eq!(
                    plain,
                    HintPlain {
                        tool: step["plain"]["tool"].as_str().unwrap().into(),
                        summary: step["plain"]["summary"].as_str().unwrap().into(),
                    }
                );
                self.report.pass();
            }
            other => panic!("{}: unknown relay step {other}", self.report.name),
        }
    }
}

fn run_relay(file: &Value, v: &Vectors, book: &Book) -> Report {
    let setup = &file["setup"];
    let clock = Clock::at(setup["host"]["wall_clock_ms"].as_u64().unwrap());
    let mut run = RelayRun {
        v,
        book,
        log: pinned_log(v, setup, &clock),
        ledger: RelayLedger::new(),
        now: setup["relay_now"].as_u64().unwrap(),
        replica: setup["replicas"][0].as_str().unwrap_or("r1").to_owned(),
        pushes: VecDeque::new(),
        desktop_connected: setup["desktop_connected"] == true,
        immediate: setup["immediate_mobile"]
            .as_array()
            .map(|a| a.iter().map(|d| d.as_str().unwrap().to_owned()).collect())
            .unwrap_or_default(),
        last_verdict: None,
        last_ack: None,
        report: Report {
            name: file["name"].as_str().unwrap().into(),
            ..Default::default()
        },
    };
    for step in file["steps"].as_array().unwrap() {
        run.step(step);
    }
    assert!(
        run.pushes.is_empty(),
        "{}: unexpected pushes {:?}",
        run.report.name,
        run.pushes
    );
    run.report
}

// ------------------------------------------------------------- host side

struct Client {
    identity: Identity,
    log: Membership,
    conn: Option<HostConn>,
    attached: Option<Attached>,
    /// Decrypted messages, oldest first.
    inbox: VecDeque<Value>,
}

struct HostRun<'a> {
    v: &'a Vectors,
    book: &'a Book,
    core: HostCore,
    clients: BTreeMap<String, Client>,
    captured: BTreeMap<String, Value>,
    relay_cursor: usize,
    /// Only connect/welcome are checked; the rest is pending (the
    /// multi-device arbitration is the real host's r8 machinery).
    connect_only: bool,
    report: Report,
}

fn event_json(event: &Event) -> Option<Value> {
    match event {
        Event::Session(m) => Some(wire::to_value(&Envelope::Session(m.clone()))),
        Event::Family(f) => Some(wire::to_value(&Envelope::Family(f.clone()))),
        Event::Error(e) | Event::Fenced(e) => Some(e.to_json()),
        Event::GrantRevoked { re } => {
            Some(json!({"type": "session", "data": {"op": "grant_revoked", "re": re}}))
        }
        Event::Seen { re } => Some(json!({"type": "session", "data": {"op": "seen", "re": re}})),
        Event::MembershipHead { re, head, .. } => Some(
            json!({"type": "session", "data": {"op": "membership_head", "re": re, "head": head.to_json()}}),
        ),
        Event::Registry(_) | Event::Lease { .. } | Event::Outgoing(_) => None,
    }
}

impl HostRun<'_> {
    fn mono(&self) -> u64 {
        self.core.now.mono_ms
    }

    /// Delivers what the host queued for every connection.
    fn pump(&mut self) {
        let names: Vec<String> = self.clients.keys().cloned().collect();
        for name in names {
            let c = self.clients.get_mut(&name).unwrap();
            let Some(conn) = c.conn.as_mut() else {
                continue;
            };
            let out = conn.poll(&mut self.core);
            for f in out.frames {
                if let Some(a) = c.attached.as_mut()
                    && let Ok(events) = a.on_frame(&f, self.core.now.mono_ms)
                {
                    c.inbox.extend(events.iter().filter_map(event_json));
                }
            }
            if out.close {
                c.conn = None;
            }
        }
    }

    fn connect(&mut self, step: &Value) {
        let name = step["connect"].as_str().unwrap().to_owned();
        if let Some(grant) = step.get("grant") {
            let grant = SignedObject::parse(grant.to_string().as_bytes()).unwrap();
            let c = self.clients.get_mut(&name).unwrap();
            c.identity = Identity::browser(grant, KeyId::new("browser/auth")).unwrap();
        }
        let mono = self.mono();
        let c = self.clients.get_mut(&name).unwrap();
        let mut conn = HostConn::new(&mut self.core);
        let (connecting, init) = Connector::new("host-a").start(&c.log, mono).unwrap();
        let accept = conn.on_frame(&mut self.core, &init).frames.remove(0);
        let (await_welcome, finish) = connecting
            .on_accept(&accept, &c.log, &self.book.provider, &c.identity, mono)
            .unwrap();
        let out = conn.on_frame(&mut self.core, &finish);
        let first = out.frames[0].clone();
        match await_welcome.on_frame(&first, &c.log, mono) {
            Ok(attached) => {
                c.inbox.push_back(attached.welcome().to_json());
                c.attached = Some(attached);
                c.conn = Some(conn);
            }
            Err(ConnectError::Refused { error, .. }) => {
                c.inbox.push_back(error.to_json());
                c.attached = None;
                c.conn = None;
            }
            Err(e) => panic!("{}: {name} failed to connect: {e:?}", self.report.name),
        }
        self.pump();
        self.report.pass();
    }

    /// `${binding:c:s}` / `${lease_binding:c:s}`: the client's binding (a
    /// target the harness names, like the fixture runner of r8).
    fn bindings(&self, value: &Value) -> Value {
        match value {
            Value::String(text) => {
                let lease = text.starts_with("${lease_binding:");
                if let Some(rest) = text
                    .strip_prefix("${binding:")
                    .or_else(|| text.strip_prefix("${lease_binding:"))
                    .and_then(|t| t.strip_suffix('}'))
                {
                    let (client, session) = rest.split_once(':').unwrap();
                    let a = self.clients[client].attached.as_ref().unwrap();
                    let s = self
                        .core
                        .sessions
                        .iter()
                        .find(|s| s.session_id == session)
                        .unwrap();
                    let lease_epoch = lease
                        .then(|| a.lease(session).and_then(|l| l.lease_epoch()))
                        .flatten()
                        .or(lease.then_some(1));
                    return json!({"target": support::host::target(&self.core, s),
                        "attachment_gen": a.welcome().attachment_gen,
                        "lease_epoch": lease_epoch})
                    .as_object()
                    .unwrap()
                    .iter()
                    .filter(|(_, v)| !v.is_null())
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect::<serde_json::Map<_, _>>()
                    .into();
                }
                value.clone()
            }
            Value::Array(items) => Value::Array(items.iter().map(|i| self.bindings(i)).collect()),
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(k, x)| (k.clone(), self.bindings(x)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    fn send(&mut self, step: &Value) {
        let name = step["send"].as_str().unwrap().to_owned();
        let message = self.bindings(&step["json"]);
        let mono = self.mono();
        let c = self.clients.get_mut(&name).unwrap();
        let a = c.attached.as_mut().unwrap();
        // The lease client learns of a Send/acquire it makes (as the
        // connect API would record it).
        let frame = a.send(&message, mono).unwrap();
        let out = c.conn.as_mut().unwrap().on_frame(&mut self.core, &frame);
        for f in out.frames {
            if let Ok(events) = a.on_frame(&f, mono) {
                c.inbox.extend(events.iter().filter_map(event_json));
            }
        }
        if out.close {
            c.conn = None;
        }
        self.pump();
        self.report.pass();
    }

    /// Finds the first message matching `want` in the client's inbox
    /// (earlier unexpected ones are tolerated, as in r8's runners).
    fn expect(&mut self, step: &Value) -> bool {
        let name = step["expect"].as_str().unwrap();
        let family = step["type"].as_str().unwrap_or("session");
        let want = &step["match"];
        let c = self.clients.get_mut(name).unwrap();
        let found = c
            .inbox
            .iter()
            .position(|m| m["type"] == family && matches(&m["data"], want));
        match found {
            Some(i) => {
                let m = c.inbox.remove(i).unwrap();
                c.inbox.drain(..i);
                if let Some(cap) = step.get("capture") {
                    for (k, path) in cap.as_object().unwrap() {
                        self.captured
                            .insert(k.clone(), at(&m["data"], path.as_str().unwrap()));
                    }
                }
                true
            }
            None => false,
        }
    }

    fn step(&mut self, raw: &Value) {
        let step = resolve(raw, self.v, &self.captured);
        let kind = step
            .as_object()
            .unwrap()
            .keys()
            .find(|k| {
                ![
                    "match",
                    "capture",
                    "type",
                    "json",
                    "carry",
                    "grant",
                    "transport",
                    "tool",
                    "summary",
                    "reason",
                    "for_ms",
                ]
                .contains(&k.as_str())
            })
            .unwrap()
            .clone();
        if self.connect_only
            && kind != "connect"
            && !(kind == "expect" && step["match"]["op"] == "welcome")
        {
            // The rest, what Atem sends the relay included (its sealed
            // push, §R9.9), runs on the real host.
            self.report.pending(format!("{kind}: {}", raw), T7);
            return;
        }
        match kind.as_str() {
            "connect" => self.connect(&step),
            "send" => self.send(&step),
            "expect" => {
                let op = step["match"]["op"].as_str().unwrap_or_default().to_owned();
                // What only the runtime host sends.
                let host_only = matches!(op.as_str(), "lease_changed" | "approval_closed")
                    || (op == "receipt" && step["match"]["state"] != "accepted");
                if op == "approval_request" {
                    // The card is the runtime's (the host runner); the
                    // approval id is the one the test host opened.
                    if let Some(cap) = step.get("capture") {
                        for k in cap.as_object().unwrap().keys() {
                            let ap = self.core.approvals.keys().last().unwrap().clone();
                            self.captured.insert(k.clone(), json!(ap));
                        }
                    }
                    self.report
                        .pending(format!("expect {}: the approval card", step["expect"]), T7);
                } else if host_only {
                    self.report
                        .pending(format!("expect {}: {op}", step["expect"]), T7);
                } else if self.expect(&step) {
                    self.report.pass();
                } else {
                    panic!(
                        "{}: {} got no {} (inbox {:?})",
                        self.report.name,
                        step["expect"],
                        step["match"],
                        self.clients[step["expect"].as_str().unwrap()].inbox
                    );
                }
            }
            "expect_none" => {
                // No approval card for a client without the approval op: the
                // authority's decision.
                let name = step["expect_none"].as_str().unwrap();
                let a = self.clients[name].attached.as_ref();
                let allows = a.is_some_and(|a| {
                    a.welcome()
                        .scope
                        .as_ref()
                        .is_none_or(|s| s.ops.contains(&AuthOp::Approval))
                });
                assert!(!allows, "{name} would get approval cards");
                let _ = Need::Op(AuthOp::Approval);
                self.report.pass();
            }
            "open_approval" => {
                let plain = HintPlain {
                    tool: step["tool"].as_str().unwrap().into(),
                    summary: step["summary"].as_str().unwrap().into(),
                };
                let id = format!(
                    "8c3e9d6b-1f40-4b52-8dae-{:012x}",
                    self.core.approvals.len() + 1
                );
                let session = step["open_approval"].as_str().unwrap().to_owned();
                self.core.open_approval(&session, &id, &plain);
                self.report.pass();
            }
            "close_approval" => {
                let ap = step["close_approval"].as_str().unwrap().to_owned();
                self.core
                    .close_approval(&ap, step["reason"].as_str().unwrap());
                self.report.pass();
            }
            "expect_relay" => {
                let m = self
                    .core
                    .relay_sent
                    .get(self.relay_cursor)
                    .cloned()
                    .expect("a relay message");
                self.relay_cursor += 1;
                for (path, want) in step["expect_relay"].as_object().unwrap() {
                    assert_eq!(&at(&m, path), want, "{}: relay {path}", self.report.name);
                }
                // Each hint in it verifies as a client would.
                if m["op"] == "push_hint" {
                    for h in m["hints"].as_array().unwrap() {
                        let o = SignedObject::parse(h.to_string().as_bytes()).unwrap();
                        Hint::verify(&o, &self.core.log, self.core.now.wall_ms, Verifier::Client)
                            .unwrap();
                    }
                }
                if let Some(cap) = step.get("capture") {
                    for (k, path) in cap.as_object().unwrap() {
                        self.captured
                            .insert(k.clone(), at(&m, path.as_str().unwrap()));
                    }
                }
                self.report.pass();
            }
            "expect_relay_none" => {
                assert_eq!(
                    self.core.relay_sent.len(),
                    self.relay_cursor,
                    "{}",
                    self.report.name
                );
                self.report.pass();
            }
            "relay_lost" => {
                // The last relay message never reached the relay: no ack
                // comes, so it stays in the host's outbox (resent below).
                assert!(
                    !self.core.outbox.is_empty(),
                    "{}: nothing unacknowledged",
                    self.report.name
                );
                self.report.pass();
            }
            "relay_ack" => {
                assert_eq!(step["relay_ack"]["op"], "push_ack");
                let acks: Vec<push::Identity> = step["relay_ack"]["acks"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|a| push::Identity::from_ack(a).expect("an ack entry names an identity"))
                    .collect();
                let before = self.core.outbox.len();
                self.core.outbox.on_ack(&acks);
                assert!(
                    self.core.outbox.len() < before,
                    "{}: the ack matched nothing",
                    self.report.name
                );
                self.report.pass();
            }
            "advance_ms" => {
                let ms = step["advance_ms"].as_u64().unwrap();
                self.core.now.wall_ms += ms;
                self.core.now.mono_ms += ms;
                self.core.tick();
                self.pump();
                self.report.pass();
            }
            "set_wall_clock" => {
                self.core.now.wall_ms = step["set_wall_clock"].as_u64().unwrap();
                self.core.tick();
                self.pump();
                self.report.pass();
            }
            "assert" => {
                for key in step["assert"].as_object().unwrap().keys() {
                    self.report.pending(format!("assert {key}"), T7);
                }
            }
            "approval_applied" | "turn_complete" => self.report.pending(kind.clone(), T7),
            other => panic!("{}: unknown host step {other}", self.report.name),
        }
    }
}

fn run_host(file: &Value, v: &Vectors, book: &Book) -> Report {
    let name = file["name"].as_str().unwrap();
    let setup = &file["setup"];
    let clock = Clock::at(setup["host"]["wall_clock_ms"].as_u64().unwrap());
    let log = pinned_log(v, setup, &clock);
    let seed = unhex32(
        book.keys["host-a"]["host_key"]["secret_hex"]
            .as_str()
            .unwrap(),
    );
    let sessions = setup["sessions"]
        .as_array()
        .map(|s| {
            s.iter()
                .map(|s| HostSession {
                    session_id: s["session_id"].as_str().unwrap().into(),
                    process_gen: s["process_gen"].as_str().unwrap().into(),
                    project: s["project"].as_str().unwrap_or_default().into(),
                })
                .collect()
        })
        .unwrap_or_default();
    let core = HostCore::new(log.clone(), clock.now.clone(), &seed, sessions);
    let mut clients = BTreeMap::new();
    for c in setup["clients"].as_array().unwrap() {
        let key = c["key"].as_str().unwrap();
        let principal = c["principal"].as_str().unwrap();
        let identity = match principal.split_once(':').unwrap() {
            ("member", id) => Identity::native(id, book.auth(key)),
            ("service", id) => Identity::service(id, book.auth(key)),
            ("browser", _) => {
                let (file, path) = c["grant"].as_str().unwrap().split_once(':').unwrap();
                let grant = SignedObject::parse(load(file)[path].to_string().as_bytes()).unwrap();
                Identity::browser(grant, book.auth(key)).unwrap()
            }
            other => panic!("principal {other:?}"),
        };
        clients.insert(
            c["name"].as_str().unwrap().to_owned(),
            Client {
                identity,
                log: log.clone(),
                conn: None,
                attached: None,
                inbox: VecDeque::new(),
            },
        );
    }
    let mut run = HostRun {
        v,
        book,
        core,
        clients,
        captured: BTreeMap::new(),
        relay_cursor: 0,
        connect_only: name.starts_with("r9-multi-device-"),
        report: Report {
            name: name.into(),
            ..Default::default()
        },
    };
    // Setup connections (invisible to the steps).
    for c in setup["connected"].as_array().cloned().unwrap_or_default() {
        run.connect(&json!({"connect": c}));
        let client = run.clients.get_mut(c.as_str().unwrap()).unwrap();
        client.inbox.clear();
        // Setup connections are full handshakes and admissions: checked.
        assert!(client.attached.is_some(), "{name}: setup connection of {c}");
    }
    if setup.get("holds_lease").is_some() {
        run.report.pending("setup holds_lease", T7);
    }
    for step in file["steps"].as_array().unwrap() {
        run.step(step);
    }
    run.report
}

#[test]
fn r9_push_seen_principal_and_multi_device_scenarios() {
    let v = Vectors::load();
    let book = Book::load();
    let mut names: Vec<String> = std::fs::read_dir(fixtures_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| {
            n.starts_with("r9-push-")
                || n.starts_with("r9-seen-")
                || n.starts_with("r9-multi-device-")
                || [
                    "r9-approval-seen.json",
                    "r9-service-scope-and-expiry.json",
                    "r9-browser-grant.json",
                ]
                .contains(&n.as_str())
        })
        .map(|n| n.trim_end_matches(".json").to_owned())
        .collect();
    names.sort();
    assert_eq!(names.len(), 17, "{names:?}");
    let (mut passed, mut pending) = (0, BTreeMap::<&str, usize>::new());
    for name in &names {
        let file = load(name);
        assert_eq!(file["name"], *name);
        assert_eq!(file["requires"], "r9");
        assert_eq!(file["kind"], "scenario");
        let report = match file["side"].as_str().unwrap() {
            "relay" => run_relay(&file, &v, &book),
            "host" => run_host(&file, &v, &book),
            other => panic!("{name}: side {other}"),
        };
        eprintln!(
            "{name}: {} checked, {} pending",
            report.passed,
            report.pending.len()
        );
        for (what, owner) in &report.pending {
            eprintln!("  PENDING {what}: {owner}");
            *pending.entry(owner).or_default() += 1;
        }
        assert!(report.passed > 0, "{name}");
        passed += report.passed;
    }
    eprintln!("total: {passed} checked, pending {pending:?}");
}

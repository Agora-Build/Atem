//! Runs the r9 push, seen, principal and multi-device scenarios
//! (`designs/protocol/fixtures/r9-push-*`, `r9-seen-*`, `r9-approval-seen`,
//! `r9-service-scope-and-expiry`, `r9-browser-grant`, `r9-multi-device-*`),
//! and the Station's acknowledgment scenarios (`r9-control-ack-*`, test 48).
//!
//! - `side: "relay"` scenarios run in full against the crate's reference
//!   relay (`push::RelayLedger`: verification, the full-identity book, the
//!   schedule from the signed `created_at`, seen, acks), the fixture
//!   playing hosts and devices; a device opens its sealed part with its own
//!   key. The `r9-control-ack-*` ones run against the reference Station
//!   ledger (`control::AckLedger`), the fixture playing the hosts and the
//!   Portal, with the Station's persistence: a transition's next state and
//!   its report intents committed together before any POST, adopted only
//!   after the commit, restarts from the committed state, and replicas
//!   serialized by compare-and-swap.
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

use atem_client::canonical::jcs;
use atem_client::connect::{Attached, ConnectError, Connector, Event, Identity};
use atem_client::control::{
    AckLedger, ControlRecord, LedgerTransition, LinkAssociation, ReportAnswer, ToStation,
};
use atem_client::encoding::Hash32;
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

// --------------------------------------------- Station acknowledgments

/// The Station side of `r9-control-ack-*` (test 48): the reference
/// `AckLedger` with the Station's persistence around it. `committed` is
/// the last state the Station committed; `ledger` is the state it adopted
/// (the committed one, as `from_json` reads it after a restart). The
/// Portal keeps the first body it recorded per `report_id` and answers a
/// repeat with its recorded answer.
struct AckRun {
    /// The vectors' control records, by label.
    records: BTreeMap<String, ControlRecord>,
    links: BTreeMap<String, LinkAssociation>,
    ledger: AckLedger,
    committed: Value,
    now: u64,
    /// The Station's report client ID at Auth (`setup.report_client_id`;
    /// a `resume_reporting` step changes it).
    client_id: Option<String>,
    portal: BTreeMap<String, String>,
    report: Report,
}

impl AckRun {
    fn new(file: &Value) -> Self {
        let setup = &file["setup"];
        let records = load(setup["records"].as_str().unwrap())["records"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                let wire = v["record"].to_string();
                (
                    v["label"].as_str().unwrap().to_owned(),
                    ControlRecord::parse(wire.as_bytes()),
                )
            })
            .filter_map(|(label, parsed)| parsed.ok().map(|r| (label, r)))
            .collect();
        let station = &setup["station"];
        let genesis = |v: &Value| Hash32::from_hex(v.as_str().unwrap()).unwrap();
        let links = setup["links"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, l)| {
                let link = LinkAssociation {
                    account_id: l["account_id"].as_str().unwrap().into(),
                    genesis_hash: genesis(&l["genesis_hash"]),
                    host_id: l["host_id"].as_str().unwrap().into(),
                    host_trust_gen: l["host_trust_gen"].as_u64().unwrap(),
                    connection_id: l["connection_id"].as_str().unwrap().into(),
                };
                (name.clone(), link)
            })
            .collect();
        let ledger = AckLedger::new(
            station["origin"].as_str().unwrap(),
            station["account_id"].as_str().unwrap(),
            genesis(&station["genesis_hash"]),
        )
        .unwrap();
        AckRun {
            records,
            links,
            committed: ledger.to_json(),
            ledger,
            now: setup["station_now_ms"].as_u64().unwrap(),
            client_id: setup["report_client_id"].as_str().map(str::to_owned),
            portal: BTreeMap::new(),
            report: Report {
                name: file["name"].as_str().unwrap().into(),
                ..Default::default()
            },
        }
    }

    fn name(&self) -> &str {
        &self.report.name
    }

    /// The transition an input step makes on `ledger`: a record, an ack
    /// or a tick, at the Station's clock.
    fn input(&self, ledger: &AckLedger, step: &Value) -> Option<LedgerTransition> {
        if let Some(label) = step.get("control_record") {
            let label = label.as_str().unwrap();
            let rec = &self.records[label];
            let covered: Vec<String> = step["covered_hosts"]
                .as_array()
                .unwrap()
                .iter()
                .map(|h| h.as_str().unwrap().to_owned())
                .collect();
            let revoked_at = step
                .get("revoked_at_ms")
                .map_or(self.now, |v| v.as_u64().unwrap());
            let t = ledger.record(rec, revoked_at, &covered, self.now);
            return Some(t.unwrap_or_else(|e| panic!("{}: record {label}: {e}", self.name())));
        }
        if let Some(message) = step.get("control_ack") {
            // The Station reads the bytes as received, strictly.
            let ToStation::ControlAck(ack) = ToStation::decode(message.to_string().as_bytes())
                .unwrap_or_else(|e| panic!("{}: ack: {e}", self.name()))
            else {
                panic!("{}: not a control_ack", self.name());
            };
            let link = &self.links[step["link"].as_str().unwrap()];
            let t = ledger.ack(link, &ack, self.now);
            return match step.get("refused") {
                Some(code) => {
                    let e = t.expect_err("refused");
                    assert_eq!(Some(e.code()), code.as_str(), "{}", self.name());
                    None
                }
                None => Some(t.unwrap_or_else(|e| panic!("{}: ack: {e}", self.name()))),
            };
        }
        if step.get("tick").is_some() {
            return Some(ledger.tick(self.now));
        }
        panic!("{}: not an input step: {step}", self.name())
    }

    fn check_made(&self, t: &LedgerTransition, step: &Value) {
        let made: Vec<String> = t.made.iter().map(|i| i.report_id.clone()).collect();
        let want: Vec<String> = step["made"]
            .as_array()
            .unwrap()
            .iter()
            .map(|id| id.as_str().unwrap().to_owned())
            .collect();
        assert_eq!(made, want, "{}: made by {step}", self.name());
        assert!(t.alerts.is_empty(), "{}", self.name());
    }

    /// Persists `t` (its next state with its intents) and adopts it.
    fn commit(&mut self, t: LedgerTransition) {
        self.committed = t.next.to_json();
        self.ledger = t.next;
    }

    /// The Station POSTs the report `id` (sendable now); `recorded`: the
    /// Portal recorded it (one body per `report_id`, for good).
    fn post(&mut self, id: &str, recorded: bool) {
        let intent = self
            .ledger
            .pending_reports()
            .into_iter()
            .find(|i| i.report_id == id)
            .unwrap_or_else(|| panic!("{}: {id} is not sendable", self.name()));
        if recorded {
            let body = jcs(&intent.report.to_json()).unwrap();
            let name = self.report.name.clone();
            let first = self.portal.entry(id.to_owned()).or_insert(body.clone());
            assert_eq!(*first, body, "{name}: one report_id, one body");
        }
    }

    /// Every step kind and the keys it takes (an unknown step or key
    /// fails the run).
    const KINDS: [(&'static str, &'static [&'static str]); 15] = [
        (
            "control_record",
            &["revoked_at_ms", "covered_hosts", "made", "commit"],
        ),
        ("control_ack", &["link", "made", "commit", "refused"]),
        ("tick", &["made", "commit"]),
        ("replica", &[]),
        ("advance_ms", &[]),
        ("restart", &[]),
        ("expect_report", &[]),
        ("confirm", &[]),
        ("report_failure", &[]),
        ("resume_reporting", &["alerts"]),
        ("expect_resign_alerts", &[]),
        ("expect_refused", &[]),
        ("expect_dropped", &[]),
        ("expect_stopped", &[]),
        ("expect_portal", &[]),
    ];

    /// The step's kind, its keys checked.
    fn kind_of(&self, step: &Value) -> &'static str {
        let o = step.as_object().unwrap();
        let (kind, keys) = AckRun::KINDS
            .iter()
            .find(|(kind, _)| o.contains_key(*kind))
            .unwrap_or_else(|| panic!("{}: unknown step {step}", self.name()));
        for key in o.keys() {
            assert!(
                key == kind || keys.contains(&key.as_str()),
                "{}: unknown key {key} in {step}",
                self.name()
            );
        }
        kind
    }

    fn step(&mut self, step: &Value) {
        match self.kind_of(step) {
            "control_record" | "control_ack" | "tick" => {
                let Some(t) = self.input(&self.ledger, step) else {
                    self.report.pass();
                    return;
                };
                self.check_made(&t, step);
                if step.get("commit") != Some(&json!(false)) {
                    self.commit(t);
                }
            }
            "replica" => {
                // Two replicas load the same committed state and process
                // the same input: the same next state and intents.
                let inner = &step["replica"];
                let r1 = AckLedger::from_json(&self.committed).unwrap();
                let r2 = AckLedger::from_json(&self.committed).unwrap();
                let (t1, t2) = (
                    self.input(&r1, inner).unwrap(),
                    self.input(&r2, inner).unwrap(),
                );
                assert_eq!(t1, t2, "{}", self.name());
                assert_eq!(
                    jcs(&t1.next.to_json()).unwrap(),
                    jcs(&t2.next.to_json()).unwrap()
                );
                self.check_made(&t1, inner);
                // The first commits; the second's compare-and-swap fails,
                // and it processes the input again on the new state.
                self.commit(t1);
                let again = AckLedger::from_json(&self.committed).unwrap();
                let t = self.input(&again, inner).unwrap();
                assert_eq!(t.made, vec![], "{}: the replica that lost", self.name());
                assert_eq!(t.next.to_json(), self.committed, "{}", self.name());
            }
            "advance_ms" => self.now += step["advance_ms"].as_u64().unwrap(),
            "restart" => {
                self.ledger = AckLedger::from_json(&self.committed).unwrap();
                assert_eq!(self.ledger.to_json(), self.committed, "{}", self.name());
            }
            "expect_report" => {
                let got: Vec<Value> = self
                    .ledger
                    .pending_reports()
                    .iter()
                    .map(|i| i.to_json())
                    .collect();
                assert_eq!(json!(got), step["expect_report"], "{}", self.name());
            }
            "confirm" => {
                let id = step["confirm"].as_str().unwrap();
                self.post(id, true);
                let t = self.ledger.confirm(id);
                self.commit(t);
            }
            "report_failure" => {
                let f = &step["report_failure"];
                let known = ["report_id", "status", "code", "reached", "answer", "alerts"];
                assert!(
                    f.as_object()
                        .unwrap()
                        .keys()
                        .all(|k| known.contains(&k.as_str()))
                );
                let id = f["report_id"].as_str().unwrap();
                self.post(id, f["reached"] == json!(true));
                let answer = match &f["status"] {
                    Value::String(s) if s == "no_answer" => ReportAnswer::Retry,
                    status => ReportAnswer::of_status(status.as_u64().unwrap() as u16),
                };
                assert_eq!(Some(answer.code()), f["answer"].as_str(), "{}", self.name());
                let t = match answer {
                    ReportAnswer::Retry => None,
                    ReportAnswer::Refuse => Some(self.ledger.refuse(id)),
                    ReportAnswer::StopReporting => {
                        let id = self.client_id.as_deref().expect("setup.report_client_id");
                        Some(self.ledger.stop_reporting(id).unwrap())
                    }
                    ReportAnswer::Confirm => panic!("{}: a 200 is a confirm step", self.name()),
                };
                let alerts: Vec<Value> = t
                    .iter()
                    .flat_map(|t| t.alerts.iter().map(|a| a.to_json()))
                    .collect();
                assert_eq!(json!(alerts), f.get("alerts").cloned().unwrap_or(json!([])));
                if let Some(t) = t {
                    assert_eq!(t.made, vec![], "{}", self.name());
                    self.commit(t);
                }
            }
            "expect_resign_alerts" => {
                let mut want: Vec<String> = step["expect_resign_alerts"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|l| self.records[l.as_str().unwrap()].record_id().to_owned())
                    .collect();
                want.sort();
                assert_eq!(self.ledger.resign_alerts(), want, "{}", self.name());
            }
            "expect_refused" => {
                assert_eq!(
                    json!(self.ledger.refused_reports()),
                    step["expect_refused"],
                    "{}",
                    self.name()
                );
            }
            "resume_reporting" => {
                // The Station restarts as this report client.
                let id = step["resume_reporting"].as_str().unwrap();
                self.client_id = Some(id.to_owned());
                let t = self.ledger.resume_reporting(id).unwrap();
                let alerts: Vec<Value> = t.alerts.iter().map(|a| a.to_json()).collect();
                assert_eq!(json!(alerts), step["alerts"], "{}", self.name());
                assert_eq!(t.made, vec![], "{}", self.name());
                self.commit(t);
            }
            "expect_dropped" => {
                assert_eq!(
                    json!(self.ledger.dropped_reports()),
                    step["expect_dropped"],
                    "{}",
                    self.name()
                );
            }
            "expect_stopped" => {
                // The stopped report client ID, or `false`.
                let got = self
                    .ledger
                    .stopped_client_id()
                    .map_or(json!(false), |id| json!(id));
                assert_eq!(got, step["expect_stopped"], "{}", self.name());
            }
            "expect_portal" => {
                let got: Vec<&String> = self.portal.keys().collect();
                assert_eq!(json!(got), step["expect_portal"], "{}", self.name());
            }
            _ => unreachable!(),
        }
        self.report.pass();
    }
}

fn run_control_ack(file: &Value) -> Report {
    let mut run = AckRun::new(file);
    for step in file["steps"].as_array().unwrap() {
        run.step(step);
    }
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
        Event::HostPolicy { result, .. } => Some(result.to_json()),
        Event::HostPolicyChanged { change, .. } => Some(change.to_json()),
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

/// Test 48's relay fixtures (`r9-control-ack-*`): the Station's
/// acknowledgment ledger, its persistence and the Portal's answers.
#[test]
fn r9_control_ack_scenarios() {
    let mut names: Vec<String> = std::fs::read_dir(fixtures_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("r9-control-ack-") && n.ends_with(".json"))
        .map(|n| n.trim_end_matches(".json").to_owned())
        .collect();
    names.sort();
    assert_eq!(names.len(), 5, "{names:?}");
    let mut passed = 0;
    for name in &names {
        let file = load(name);
        assert_eq!(file["name"], *name);
        assert_eq!(file["requires"], "r9");
        assert_eq!(file["kind"], "scenario");
        assert_eq!(file["side"], "relay");
        let report = run_control_ack(&file);
        eprintln!("{name}: {} checked", report.passed);
        assert!(report.pending.is_empty() && report.passed > 0, "{name}");
        passed += report.passed;
    }
    eprintln!("total: {passed} checked");
}

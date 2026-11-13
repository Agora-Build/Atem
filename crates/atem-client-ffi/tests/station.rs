//! The Station's side through the bindings (delegated host work I.5.8;
//! host-work-v1 §11.4): the production exports for Station builders. Every
//! acknowledgment fixture (`designs/protocol/fixtures/r9-control-ack-*`)
//! runs through `AckLedgerHandle` as a Station persists it, a call never
//! changes the handle it was called on, the state loads only as written,
//! the relay builders and readers agree and refuse what each other refuses,
//! and the Portal's statuses fall in their classes.
#![cfg(feature = "uniffi")]

#[path = "../../atem-client/tests/support/mod.rs"]
#[allow(unused_imports)]
mod support;

use std::collections::BTreeMap;
use std::sync::Arc;

use atem_client_ffi::AtemError;
use atem_client_ffi::station::{
    AckLedgerHandle, AckTransition, relay_control_ack, relay_control_ack_refused,
    relay_control_sync, relay_control_sync_refused, relay_control_sync_result,
    relay_decode_to_host, relay_decode_to_station, relay_heads, relay_membership_fetch,
    relay_membership_fetch_refused, relay_membership_fetch_result, report_answer,
};
use atem_client_ffi::types::{
    ControlAckInfo, ControlEffectKind, ControlEffectResult, ControlResultKind, LedgerAlertInfo,
    LinkAssociationInfo, LogHead, RelayAckResult, RelayFeedHead, RelayFeedRecord, RelayRefusalCode,
    RelayToHost, RelayToStation, ReportAnswerKind, ReportIntentInfo, StationReport,
};
use serde_json::{Value, json};
use support::*;

fn code(e: AtemError) -> String {
    e.code()
}

fn s(v: &Value) -> String {
    v.as_str().unwrap().to_owned()
}

/// The vectors' control records by label: their wire JSON.
fn records() -> BTreeMap<String, Value> {
    load("r9-vectors-host-work-control")["records"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| (s(&v["label"]), v["record"].clone()))
        .collect()
}

/// An intent as the fixtures write it (`ReportIntent::to_json`).
fn intent_json(i: &ReportIntentInfo) -> Value {
    let report = match &i.report {
        StationReport::RevocationApplied {
            integration_id,
            host,
            record_id,
        } => json!({"kind": "revocation_applied", "integration_id": integration_id,
            "host": host, "record_id": record_id}),
        StationReport::Revoked {
            integration_id,
            outcome,
            pending_hosts,
        } => json!({"kind": "revoked", "integration_id": integration_id,
            "outcome": outcome, "pending_hosts": pending_hosts}),
    };
    json!({"not_before": i.not_before, "report": report, "report_id": i.report_id})
}

fn alert_json(a: &LedgerAlertInfo) -> Value {
    match a {
        LedgerAlertInfo::ReportRefused { report_id } => {
            json!({"kind": "report_refused", "report_id": report_id})
        }
        LedgerAlertInfo::ReportingStopped { client_id } => {
            json!({"kind": "reporting_stopped", "client_id": client_id})
        }
        LedgerAlertInfo::ReportsDropped { client_id, dropped } => {
            json!({"kind": "reports_dropped", "client_id": client_id, "dropped": dropped})
        }
    }
}

fn answer_code(a: ReportAnswerKind) -> &'static str {
    match a {
        ReportAnswerKind::Confirm => "confirm",
        ReportAnswerKind::Retry => "retry",
        ReportAnswerKind::Refuse => "refuse",
        ReportAnswerKind::StopReporting => "stop_reporting",
    }
}

/// A fixture's Station: the adopted handle and the committed state.
struct Station {
    name: String,
    records: BTreeMap<String, Value>,
    links: BTreeMap<String, LinkAssociationInfo>,
    ledger: Arc<AckLedgerHandle>,
    committed: String,
    now: u64,
    client_id: Option<String>,
}

impl Station {
    fn new(file: &Value) -> Self {
        let setup = &file["setup"];
        let st = &setup["station"];
        let ledger = AckLedgerHandle::new(
            s(&st["origin"]),
            s(&st["account_id"]),
            s(&st["genesis_hash"]),
        )
        .unwrap();
        let links = setup["links"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(name, l)| {
                let link = LinkAssociationInfo {
                    account_id: s(&l["account_id"]),
                    genesis_hash: s(&l["genesis_hash"]),
                    host_id: s(&l["host_id"]),
                    host_trust_gen: l["host_trust_gen"].as_u64().unwrap(),
                    connection_id: s(&l["connection_id"]),
                };
                (name.clone(), link)
            })
            .collect();
        Station {
            name: s(&file["name"]),
            records: records(),
            links,
            committed: ledger.to_json(),
            ledger,
            now: setup["station_now_ms"].as_u64().unwrap(),
            client_id: setup["report_client_id"].as_str().map(str::to_owned),
        }
    }

    /// A record, an ack or a tick on `ledger` (`None`: refused, as the
    /// step says).
    fn input(&self, ledger: &AckLedgerHandle, step: &Value) -> Option<AckTransition> {
        if let Some(label) = step.get("control_record") {
            let hosts = step["covered_hosts"]
                .as_array()
                .unwrap()
                .iter()
                .map(s)
                .collect();
            let at = step
                .get("revoked_at_ms")
                .map_or(self.now, |v| v.as_u64().unwrap());
            let record = self.records[label.as_str().unwrap()].to_string();
            return Some(ledger.record(record, at, hosts, self.now).unwrap());
        }
        if let Some(message) = step.get("control_ack") {
            let link = self.links[step["link"].as_str().unwrap()].clone();
            let t = ledger.ack(link, message.to_string(), self.now);
            return match step.get("refused") {
                Some(want) => {
                    assert_eq!(code(t.unwrap_err()), s(want), "{}", self.name);
                    None
                }
                None => Some(t.unwrap()),
            };
        }
        assert!(step.get("tick").is_some(), "{}: {step}", self.name);
        Some(ledger.tick(self.now))
    }

    fn check_made(&self, t: &AckTransition, step: &Value) {
        let made: Vec<&str> = t.made.iter().map(|i| i.report_id.as_str()).collect();
        assert_eq!(json!(made), step["made"], "{}: {step}", self.name);
        assert!(t.alerts.is_empty(), "{}", self.name);
    }

    fn commit(&mut self, t: AckTransition) {
        self.committed = t.next.to_json();
        self.ledger = t.next;
    }

    fn sendable(&self, id: &str) {
        assert!(
            self.ledger
                .pending_reports()
                .iter()
                .any(|i| i.report_id == id),
            "{}: {id} is not sendable",
            self.name
        );
    }

    fn step(&mut self, step: &Value) {
        let o = step.as_object().unwrap();
        if ["control_record", "control_ack", "tick"]
            .iter()
            .any(|k| o.contains_key(*k))
        {
            if let Some(t) = self.input(&self.ledger, step) {
                self.check_made(&t, step);
                if step.get("commit") != Some(&json!(false)) {
                    self.commit(t);
                }
            }
        } else if let Some(inner) = step.get("replica") {
            let r1 = AckLedgerHandle::from_json(self.committed.clone()).unwrap();
            let r2 = AckLedgerHandle::from_json(self.committed.clone()).unwrap();
            let (t1, t2) = (
                self.input(&r1, inner).unwrap(),
                self.input(&r2, inner).unwrap(),
            );
            assert_eq!(t1.next.to_json(), t2.next.to_json(), "{}", self.name);
            assert_eq!(t1.made, t2.made, "{}", self.name);
            self.check_made(&t1, inner);
            self.commit(t1);
            let again = AckLedgerHandle::from_json(self.committed.clone()).unwrap();
            let t = self.input(&again, inner).unwrap();
            assert!(t.made.is_empty(), "{}", self.name);
        } else if let Some(ms) = step.get("advance_ms") {
            self.now += ms.as_u64().unwrap();
        } else if step.get("restart").is_some() {
            self.ledger = AckLedgerHandle::from_json(self.committed.clone()).unwrap();
            assert_eq!(self.ledger.to_json(), self.committed);
        } else if let Some(want) = step.get("expect_report") {
            let got: Vec<Value> = self
                .ledger
                .pending_reports()
                .iter()
                .map(intent_json)
                .collect();
            assert_eq!(json!(got), *want, "{}", self.name);
        } else if let Some(id) = step.get("confirm") {
            self.sendable(id.as_str().unwrap());
            let t = self.ledger.confirm(s(id));
            assert!(t.made.is_empty() && t.alerts.is_empty());
            self.commit(t);
        } else if let Some(f) = step.get("report_failure") {
            let id = s(&f["report_id"]);
            self.sendable(&id);
            let answer = match f["status"].as_u64() {
                Some(status) => answer_code(report_answer(status as u16)),
                None => "retry",
            };
            assert_eq!(answer, f["answer"], "{}", self.name);
            let t = match answer {
                "refuse" => Some(self.ledger.refuse(id)),
                "stop_reporting" => {
                    let id = self.client_id.clone().expect("setup.report_client_id");
                    Some(self.ledger.stop_reporting(id).unwrap())
                }
                _ => None,
            };
            let alerts: Vec<Value> = t
                .iter()
                .flat_map(|t| t.alerts.iter().map(alert_json))
                .collect();
            assert_eq!(json!(alerts), f.get("alerts").cloned().unwrap_or(json!([])));
            if let Some(t) = t {
                self.commit(t);
            }
        } else if let Some(labels) = step.get("expect_resign_alerts") {
            let mut want: Vec<String> = labels
                .as_array()
                .unwrap()
                .iter()
                .map(|l| s(&self.records[l.as_str().unwrap()]["body"]["record_id"]))
                .collect();
            want.sort();
            assert_eq!(self.ledger.resign_alerts(), want, "{}", self.name);
        } else if let Some(want) = step.get("expect_dropped") {
            assert_eq!(json!(self.ledger.dropped_reports()), *want, "{}", self.name);
        } else if let Some(want) = step.get("expect_refused") {
            assert_eq!(json!(self.ledger.refused_reports()), *want, "{}", self.name);
        } else if let Some(id) = step.get("resume_reporting") {
            self.client_id = Some(s(id));
            let t = self.ledger.resume_reporting(s(id)).unwrap();
            let alerts: Vec<Value> = t.alerts.iter().map(alert_json).collect();
            assert_eq!(json!(alerts), step["alerts"], "{}", self.name);
            assert!(t.made.is_empty());
            self.commit(t);
        } else if let Some(want) = step.get("expect_stopped") {
            let got = self
                .ledger
                .stopped_client_id()
                .map_or(json!(false), |id| json!(id));
            assert_eq!(got, *want, "{}", self.name);
            assert_eq!(self.ledger.reporting_stopped(), *want != json!(false));
        } else {
            // The Portal's side: no Portal model here.
            assert!(step.get("expect_portal").is_some(), "{}: {step}", self.name);
        }
    }
}

fn ack_fixtures() -> Vec<Value> {
    let mut names: Vec<String> = std::fs::read_dir(fixtures_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("r9-control-ack-") && n.ends_with(".json"))
        .map(|n| n.trim_end_matches(".json").to_owned())
        .collect();
    names.sort();
    assert_eq!(names.len(), 5);
    names.iter().map(|n| load(n)).collect()
}

#[test]
fn every_ack_fixture_through_the_ledger_handle() {
    for file in ack_fixtures() {
        let mut station = Station::new(&file);
        for step in file["steps"].as_array().unwrap() {
            station.step(step);
        }
    }
}

#[test]
fn a_call_never_changes_its_handle_and_the_state_loads_only_as_written() {
    let file = load("r9-control-ack-per-effect");
    let mut station = Station::new(&file);
    let steps = file["steps"].as_array().unwrap();
    // Up to host-d's revocation_applied, made by the Station's own revoke.
    for step in &steps[..4] {
        station.step(step);
    }
    let before = station.ledger.to_json();
    let ack = steps[6].clone();
    let t1 = station.input(&station.ledger, &ack).unwrap();
    // The commit failed: the handle is as it was, and the same call again
    // gives the same next state and report ids.
    assert_eq!(station.ledger.to_json(), before);
    let t2 = station.input(&station.ledger, &ack).unwrap();
    assert_eq!((t1.next.to_json(), &t1.made), (t2.next.to_json(), &t2.made));
    assert_eq!(t1.made.len(), 1);
    // The same for a final refusal and a stop.
    let id = station.ledger.pending_reports()[0].report_id.clone();
    let refused = station.ledger.refuse(id.clone());
    assert_eq!(station.ledger.to_json(), before);
    assert_eq!(
        refused.alerts,
        vec![LedgerAlertInfo::ReportRefused { report_id: id }]
    );
    let stopped = station.ledger.stop_reporting("station-1".into()).unwrap();
    assert!(stopped.next.reporting_stopped() && !station.ledger.reporting_stopped());
    assert_eq!(
        stopped.next.stopped_client_id().as_deref(),
        Some("station-1")
    );
    assert!(stopped.next.pending_reports().is_empty());
    // The same report client ID keeps every report; another drops them.
    let resumed = stopped.next.resume_reporting("station-1".into()).unwrap();
    assert_eq!(
        resumed.next.pending_reports(),
        station.ledger.pending_reports()
    );
    let other = stopped.next.resume_reporting("station-2".into()).unwrap();
    assert!(matches!(
        &other.alerts[..],
        [LedgerAlertInfo::ReportsDropped { client_id, .. }] if client_id == "station-1"
    ));
    assert!(other.next.pending_reports().is_empty());
    assert_eq!(
        other.next.dropped_client_ids(),
        vec!["station-1".to_owned()]
    );
    assert_eq!(
        other.next.dropped_reports(),
        vec![station.ledger.pending_reports()[0].report_id.clone()]
    );
    let bad = station.ledger.stop_reporting("a b".into());
    assert_eq!(code(bad.unwrap_err()), "malformed");

    // The state loads as written, and only so.
    let text = t1.next.to_json();
    assert_eq!(
        AckLedgerHandle::from_json(text.clone()).unwrap().to_json(),
        text
    );
    assert_eq!(
        code(AckLedgerHandle::from_json("[".into()).unwrap_err()),
        "malformed"
    );
    assert_eq!(
        code(AckLedgerHandle::from_json("{}".into()).unwrap_err()),
        "malformed"
    );
    let v2 = text.replace("\"v\":1", "\"v\":2");
    assert_eq!(
        code(AckLedgerHandle::from_json(v2).unwrap_err()),
        "unsupported_version"
    );
    let extra = text.replacen('{', "{\"extra\":1,", 1);
    assert_eq!(
        code(AckLedgerHandle::from_json(extra).unwrap_err()),
        "stored_invalid"
    );
    let fraction = text.replace("\"v\":1", "\"v\":1.0");
    assert_eq!(
        code(AckLedgerHandle::from_json(fraction).unwrap_err()),
        "malformed"
    );
    let stopped = stopped.next.to_json();
    assert!(
        AckLedgerHandle::from_json(stopped.clone())
            .unwrap()
            .reporting_stopped()
    );
    let bad = stopped.replace("\"stopped\":\"station-1\"", "\"stopped\":true");
    assert_eq!(
        code(AckLedgerHandle::from_json(bad).unwrap_err()),
        "stored_invalid"
    );

    // Refusals at the boundary.
    let st = &file["setup"]["station"];
    let bad = AckLedgerHandle::new(
        "https://Station-dev.agora.build/".into(),
        s(&st["account_id"]),
        s(&st["genesis_hash"]),
    );
    assert_eq!(code(bad.unwrap_err()), "malformed");
    let mut link = station.links["host-b"].clone();
    link.connection_id = String::new();
    let t = station
        .ledger
        .ack(link, steps[6]["control_ack"].to_string(), station.now);
    assert_eq!(code(t.unwrap_err()), "incomplete_link");
    let other = steps[6]["control_ack"]
        .to_string()
        .replace("host-b", "host-c");
    let t = station
        .ledger
        .ack(station.links["host-b"].clone(), other, station.now);
    assert_eq!(code(t.unwrap_err()), "not_the_link");
    let t = station
        .ledger
        .ack(station.links["host-b"].clone(), "{}".into(), station.now);
    assert_eq!(code(t.unwrap_err()), "wrong_message");
    let refused = records()["P4_unknown_field"].to_string();
    let t = station.ledger.record(refused, 0, vec![], station.now);
    assert_eq!(code(t.unwrap_err()), "unknown_field");
}

#[test]
fn relay_calls_round_trip_and_refuse_what_the_readers_refuse() {
    // Every fixture ack, read and written again: the same message.
    for file in ack_fixtures() {
        for step in file["steps"].as_array().unwrap() {
            let step = step.get("replica").unwrap_or(step);
            let Some(message) = step.get("control_ack") else {
                continue;
            };
            let RelayToStation::ControlAck { ack } =
                relay_decode_to_station(message.to_string()).unwrap()
            else {
                panic!("not an ack");
            };
            let again: Value = serde_json::from_str(&relay_control_ack(ack).unwrap()).unwrap();
            assert_eq!(again, *message);
        }
    }
    let records = records();
    let a = &load("r9-vectors-host-work-control")["stations"]["A"];
    let (origin, feed) = (s(&a["origin"]), s(&a["feed_id"]));

    // control_sync, with and without a feed.
    for (feed_id, after) in [(Some(feed.clone()), 7), (None, 0)] {
        let m = relay_control_sync(origin.clone(), feed_id.clone(), after).unwrap();
        let read = relay_decode_to_station(m).unwrap();
        assert_eq!(
            read,
            RelayToStation::ControlSync {
                origin: origin.clone(),
                feed_id,
                after
            }
        );
    }
    assert_eq!(
        code(relay_control_sync(origin.clone(), None, 5).unwrap_err()),
        "malformed"
    );

    // A feed page of the vectors' records, as a host reads it.
    let page: Vec<RelayFeedRecord> = ["S1_cover", "S4_revoke", "M1_revoke"]
        .iter()
        .enumerate()
        .map(|(i, l)| RelayFeedRecord {
            feed_seq: i as u64 + 1,
            record_json: records[*l].to_string(),
        })
        .collect();
    let m = relay_control_sync_result(
        origin.clone(),
        feed.clone(),
        3,
        1_793_620_940_000,
        page.clone(),
    )
    .unwrap();
    let RelayToHost::ControlSyncResult {
        records: read,
        head,
        ..
    } = relay_decode_to_host(m).unwrap()
    else {
        panic!("not a page");
    };
    assert_eq!(head, 3);
    for (got, sent) in read.iter().zip(&page) {
        let got: Value = serde_json::from_str(&got.record_json).unwrap();
        let sent: Value = serde_json::from_str(&sent.record_json).unwrap();
        assert_eq!(got, sent);
    }
    // A record the parser refuses is never served; a position above the
    // head, or out of order, is refused.
    let mut bad = page.clone();
    bad[1].record_json = records["P4_unknown_field"].to_string();
    let e = relay_control_sync_result(origin.clone(), feed.clone(), 3, 0, bad).unwrap_err();
    assert_eq!(code(e), "unknown_field");
    let e =
        relay_control_sync_result(origin.clone(), feed.clone(), 2, 0, page.clone()).unwrap_err();
    assert_eq!(code(e), "malformed");
    let mut reordered = page.clone();
    reordered.swap(0, 1);
    let e = relay_control_sync_result(origin.clone(), feed.clone(), 3, 0, reordered).unwrap_err();
    assert_eq!(code(e), "malformed");

    // heads; a mailbox head isn't read before stage 3.
    let v = Vectors::load();
    let head: LogHead = v.head("E6").into();
    let feeds = vec![RelayFeedHead {
        origin: origin.clone(),
        feed_id: feed.clone(),
        head: 3,
        station_time: 1_793_620_940_000,
    }];
    let m = relay_heads(feeds.clone(), head.clone()).unwrap();
    assert_eq!(
        relay_decode_to_host(m.clone()).unwrap(),
        RelayToHost::Heads {
            feeds: feeds.clone(),
            membership: head.clone()
        }
    );
    let mut with_mailbox: Value = serde_json::from_str(&m).unwrap();
    with_mailbox["mailbox"] = json!({"mailbox_id": feed, "head": 1});
    assert_eq!(
        code(relay_decode_to_host(with_mailbox.to_string()).unwrap_err()),
        "unknown_field"
    );
    let twice = vec![feeds[0].clone(), feeds[0].clone()];
    assert_eq!(
        code(relay_heads(twice, head.clone()).unwrap_err()),
        "malformed"
    );

    // The host's own device-list fetch.
    let m = relay_membership_fetch(2).unwrap();
    assert_eq!(
        relay_decode_to_station(m).unwrap(),
        RelayToStation::MembershipFetch { after: 2 }
    );
    let entries: Vec<String> = ["E3", "E4", "E5", "E6"]
        .iter()
        .map(|l| v.wire(l).to_string())
        .collect();
    let m = relay_membership_fetch_result(head.clone(), entries.clone()).unwrap();
    let RelayToHost::MembershipFetchResult {
        head: got,
        entries: read,
    } = relay_decode_to_host(m).unwrap()
    else {
        panic!("not a fetch result");
    };
    assert_eq!(got, head);
    let read: Vec<Value> = read
        .iter()
        .map(|e| serde_json::from_str(e).unwrap())
        .collect();
    let sent: Vec<Value> = entries
        .iter()
        .map(|e| serde_json::from_str(e).unwrap())
        .collect();
    assert_eq!(read, sent);

    // Each side reads only its own direction, and nothing else on the link.
    let page = relay_control_sync(origin, None, 0).unwrap();
    assert_eq!(
        code(relay_decode_to_host(page).unwrap_err()),
        "wrong_message"
    );
    let hint = json!({"type": "relay", "op": "push_hint", "hints": []}).to_string();
    assert_eq!(
        code(relay_decode_to_station(hint).unwrap_err()),
        "wrong_message"
    );
    assert_eq!(
        code(relay_decode_to_station("{".into()).unwrap_err()),
        "not_strict"
    );
}

#[test]
fn the_portals_statuses_fall_in_their_classes() {
    use ReportAnswerKind as A;
    for (status, want) in [
        (200, A::Confirm),
        (401, A::Retry),
        (408, A::Retry),
        (429, A::Retry),
        (500, A::Retry),
        (503, A::Retry),
        (599, A::Retry),
        (400, A::Refuse),
        (404, A::Refuse),
        (409, A::Refuse),
        (413, A::Refuse),
        (415, A::Refuse),
        (422, A::Refuse),
        (204, A::Refuse),
        (302, A::Refuse),
        (403, A::StopReporting),
    ] {
        assert_eq!(report_answer(status), want, "{status}");
    }
}

/// The Station's refusals (agreed with Astation, 2026-11-11): the three
/// replies exactly, read back strictly as the host's typed refusals; and
/// an ack refused for its stale association, answered
/// `control_ack_refused`, with nothing counted, kept or disclosed.
#[test]
fn the_three_refusals_and_a_stale_association_refused_without_disclosure() {
    use RelayRefusalCode::Forbidden;
    let replies = [
        (
            relay_control_sync_refused(Forbidden).unwrap(),
            "control_sync_refused",
            RelayToHost::ControlSyncRefused { code: Forbidden },
        ),
        (
            relay_membership_fetch_refused(Forbidden).unwrap(),
            "membership_fetch_refused",
            RelayToHost::MembershipFetchRefused { code: Forbidden },
        ),
        (
            relay_control_ack_refused(Forbidden).unwrap(),
            "control_ack_refused",
            RelayToHost::ControlAckRefused { code: Forbidden },
        ),
    ];
    for (message, op, want) in replies {
        let v: Value = serde_json::from_str(&message).unwrap();
        assert_eq!(v, json!({"type": "relay", "op": op, "code": "forbidden"}));
        assert_eq!(relay_decode_to_host(message.clone()).unwrap(), want);
        assert_eq!(
            code(relay_decode_to_station(message).unwrap_err()),
            "wrong_message"
        );
        for (fields, want) in [
            (r#""code":"not_found""#, "malformed"),
            (r#""code":null"#, "malformed"),
            (r#""code":"forbidden","feed_id":"x""#, "unknown_field"),
            (r#""code":"forbidden","code":"forbidden""#, "not_strict"),
        ] {
            let bad = format!(r#"{{"type":"relay","op":"{op}",{fields}}}"#);
            assert_eq!(code(relay_decode_to_host(bad).unwrap_err()), want);
        }
    }

    // A stale association: the link was verified at trust generation 2,
    // the ack claims 1.
    let file = load("r9-control-ack-deadline");
    let st = &file["setup"]["station"];
    let ledger = AckLedgerHandle::new(
        s(&st["origin"]),
        s(&st["account_id"]),
        s(&st["genesis_hash"]),
    )
    .unwrap();
    let s4 = records()["S4_revoke"].to_string();
    let ledger = ledger
        .record(
            s4,
            1_793_620_903_000,
            vec!["host-b".into()],
            1_793_620_940_000,
        )
        .unwrap()
        .next;
    let before = ledger.to_json();
    let ack = file["steps"][1]["control_ack"].to_string();
    let mut link = LinkAssociationInfo {
        account_id: s(&st["account_id"]),
        genesis_hash: s(&st["genesis_hash"]),
        host_id: "host-b".into(),
        host_trust_gen: 2,
        connection_id: "relay-1:host-b".into(),
    };
    let e = ledger
        .ack(link.clone(), ack.clone(), 1_793_620_940_000)
        .unwrap_err();
    assert_eq!(code(e), "not_the_link");
    // Nothing counted or kept: the same state, nothing to send.
    assert_eq!(ledger.to_json(), before);
    assert!(ledger.pending_reports().is_empty());
    // The reply names nothing of the ack, the link or the ledger.
    let reply = relay_control_ack_refused(Forbidden).unwrap();
    for secret in [
        s(&st["account_id"]),
        s(&st["genesis_hash"]),
        s(&st["origin"]),
        "host-b".to_owned(),
        "00000000-0000-4000-8000-000000000004".to_owned(),
    ] {
        assert!(!reply.contains(&secret), "{secret}");
    }
    // Once the link's association is the ack's, it counts.
    link.host_trust_gen = 1;
    let t = ledger.ack(link, ack, 1_793_620_940_000).unwrap();
    assert_eq!(t.made.len(), 2);
}

// ------------------------------------------- the Station calls' byte goldens

/// An effect list as the golden file writes it, for the bindings' types.
fn golden_effects(v: &Value) -> Vec<ControlEffectResult> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|e| ControlEffectResult {
            effect: match s(&e["effect"]).as_str() {
                "revocation" => ControlEffectKind::Revocation,
                "interrupt" => ControlEffectKind::Interrupt,
                "hold" => ControlEffectKind::Hold,
                "release" => ControlEffectKind::Release,
                "cover" => ControlEffectKind::Cover,
                other => panic!("effect {other}"),
            },
            result: match s(&e["result"]).as_str() {
                "applied" => ControlResultKind::Applied,
                "duplicate" => ControlResultKind::Duplicate,
                "pending" => ControlResultKind::Pending,
                "refused" => ControlResultKind::Refused,
                other => panic!("result {other}"),
            },
            why: e.get("why").map(s),
        })
        .collect()
}

fn golden_effects_json(effects: &[ControlEffectResult]) -> Value {
    Value::Array(
        effects
            .iter()
            .map(|e| {
                let effect = match e.effect {
                    ControlEffectKind::Revocation => "revocation",
                    ControlEffectKind::Interrupt => "interrupt",
                    ControlEffectKind::Hold => "hold",
                    ControlEffectKind::Release => "release",
                    ControlEffectKind::Cover => "cover",
                };
                let result = match e.result {
                    ControlResultKind::Applied => "applied",
                    ControlResultKind::Duplicate => "duplicate",
                    ControlResultKind::Pending => "pending",
                    ControlResultKind::Refused => "refused",
                };
                match &e.why {
                    Some(why) => json!({"effect": effect, "result": result, "why": why}),
                    None => json!({"effect": effect, "result": result}),
                }
            })
            .collect(),
    )
}

fn golden_ack(f: &Value) -> ControlAckInfo {
    ControlAckInfo {
        account_id: s(&f["account_id"]),
        genesis_hash: s(&f["genesis_hash"]),
        host_id: s(&f["host_id"]),
        host_trust_gen: f["host_trust_gen"].as_u64().unwrap(),
        origin: s(&f["origin"]),
        feed_id: s(&f["feed_id"]),
        cursor: f["cursor"].as_u64().unwrap(),
        results: f["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| match r.get("entry") {
                Some(entry) => RelayAckResult::Entry {
                    seq: entry["seq"].as_u64().unwrap(),
                    entry_hash: s(&entry["entry_hash"]),
                    applied_seq: r["applied_seq"].as_u64().unwrap(),
                    effects: golden_effects(&r["effects"]),
                },
                None => RelayAckResult::Record {
                    record_id: s(&r["record_id"]),
                    effects: golden_effects(&r["effects"]),
                },
            })
            .collect(),
    }
}

fn golden_ack_json(ack: &ControlAckInfo) -> Value {
    json!({
        "account_id": ack.account_id,
        "genesis_hash": ack.genesis_hash,
        "host_id": ack.host_id,
        "host_trust_gen": ack.host_trust_gen,
        "origin": ack.origin,
        "feed_id": ack.feed_id,
        "cursor": ack.cursor,
        "results": ack.results.iter().map(|r| match r {
            RelayAckResult::Record { record_id, effects } =>
                json!({"record_id": record_id, "effects": golden_effects_json(effects)}),
            RelayAckResult::Entry { seq, entry_hash, applied_seq, effects } => json!({
                "entry": {"seq": seq, "entry_hash": entry_hash},
                "applied_seq": applied_seq,
                "effects": golden_effects_json(effects),
            }),
        }).collect::<Vec<_>>(),
    })
}

/// A golden's message as the production exports build it, from its fields.
fn golden_build(op: &str, f: &Value) -> Result<String, AtemError> {
    let head = |v: &Value| LogHead {
        seq: v["seq"].as_u64().unwrap(),
        hash: s(&v["hash"]),
    };
    match op {
        "control_sync" => relay_control_sync(
            s(&f["origin"]),
            f.get("feed_id").map(s),
            f["after"].as_u64().unwrap(),
        ),
        "control_sync_result" => relay_control_sync_result(
            s(&f["origin"]),
            s(&f["feed_id"]),
            f["head"].as_u64().unwrap(),
            f["station_time"].as_u64().unwrap(),
            f["records"]
                .as_array()
                .unwrap()
                .iter()
                .map(|r| RelayFeedRecord {
                    feed_seq: r["feed_seq"].as_u64().unwrap(),
                    record_json: r["record"].to_string(),
                })
                .collect(),
        ),
        "heads" => relay_heads(
            f["feeds"]
                .as_array()
                .unwrap()
                .iter()
                .map(|feed| RelayFeedHead {
                    origin: s(&feed["origin"]),
                    feed_id: s(&feed["feed_id"]),
                    head: feed["head"].as_u64().unwrap(),
                    station_time: feed["station_time"].as_u64().unwrap(),
                })
                .collect(),
            head(&f["membership"]),
        ),
        "control_ack" => relay_control_ack(golden_ack(f)),
        "membership_fetch" => relay_membership_fetch(f["after"].as_u64().unwrap()),
        "membership_fetch_result" => relay_membership_fetch_result(
            head(&f["head"]),
            f["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(Value::to_string)
                .collect(),
        ),
        "control_sync_refused" => relay_control_sync_refused(RelayRefusalCode::Forbidden),
        "membership_fetch_refused" => relay_membership_fetch_refused(RelayRefusalCode::Forbidden),
        "control_ack_refused" => relay_control_ack_refused(RelayRefusalCode::Forbidden),
        other => panic!("no export for {other}"),
    }
}

/// What a decoded message holds, as the golden file's `fields` write it.
fn golden_describe(direction: &str, wire: &str) -> Result<Value, AtemError> {
    let head = |h: &LogHead| json!({"seq": h.seq, "hash": h.hash});
    Ok(match direction {
        "to_station" => match relay_decode_to_station(wire.to_owned())? {
            RelayToStation::ControlSync {
                origin,
                feed_id,
                after,
            } => {
                let mut f = json!({"origin": origin, "after": after});
                if let Some(feed_id) = feed_id {
                    f["feed_id"] = json!(feed_id);
                }
                f
            }
            RelayToStation::ControlAck { ack } => golden_ack_json(&ack),
            RelayToStation::MembershipFetch { after } => json!({"after": after}),
        },
        "to_host" => match relay_decode_to_host(wire.to_owned())? {
            RelayToHost::ControlSyncResult {
                origin,
                feed_id,
                head,
                station_time,
                records,
            } => json!({
                "origin": origin, "feed_id": feed_id, "head": head, "station_time": station_time,
                "records": records.iter().map(|r| json!({
                    "feed_seq": r.feed_seq,
                    "record": serde_json::from_str::<Value>(&r.record_json).unwrap(),
                })).collect::<Vec<_>>(),
            }),
            RelayToHost::Heads { feeds, membership } => json!({
                "feeds": feeds.iter().map(|f| json!({
                    "origin": f.origin, "feed_id": f.feed_id, "head": f.head,
                    "station_time": f.station_time,
                })).collect::<Vec<_>>(),
                "membership": head(&membership),
            }),
            RelayToHost::MembershipFetchResult { head: h, entries } => json!({
                "head": head(&h),
                "entries": entries.iter()
                    .map(|e| serde_json::from_str::<Value>(e).unwrap())
                    .collect::<Vec<_>>(),
            }),
            RelayToHost::ControlSyncRefused { code }
            | RelayToHost::MembershipFetchRefused { code }
            | RelayToHost::ControlAckRefused { code } => match code {
                RelayRefusalCode::Forbidden => json!({"code": "forbidden"}),
            },
        },
        other => panic!("no reader {other}"),
    })
}

/// A case's text: `wire` as written, or built from its `wire_fill` recipe
/// (`prefix`, `count` times `fill`, `suffix`).
fn golden_wire(case: &Value) -> String {
    match case.get("wire") {
        Some(wire) => s(wire),
        None => {
            let fill = &case["wire_fill"];
            format!(
                "{}{}{}",
                s(&fill["prefix"]),
                s(&fill["fill"]).repeat(fill["count"].as_u64().unwrap() as usize),
                s(&fill["suffix"])
            )
        }
    }
}

/// Typed reasons (O5) through the production exports: a golden's reasons
/// decode as they came (a code this build doesn't know included, its
/// result unchanged), and the builder refuses a reason beside an effect in
/// force or one that isn't well formed, `malformed`.
#[test]
fn reasons_through_the_bindings() {
    let file = load("r9-vectors-station-calls");
    let golden = |name: &str| {
        let case = file["calls"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap();
        let Ok(RelayToStation::ControlAck { ack }) = relay_decode_to_station(s(&case["wire"]))
        else {
            panic!("{name}: an ack")
        };
        ack
    };
    let effects = |r: &RelayAckResult| match r {
        RelayAckResult::Record { effects, .. } | RelayAckResult::Entry { effects, .. } => {
            effects.clone()
        }
    };
    let later = golden("control_ack_with_unrecognized_reasons");
    let first = effects(&later.results[0]).remove(0);
    assert_eq!(
        (first.result, first.why.as_deref()),
        (ControlResultKind::Refused, Some("a_later_reason"))
    );
    let reasoned = golden("control_ack_with_reasons");
    let mut ack = reasoned.clone();
    let bad = |ack: &ControlAckInfo| code(relay_control_ack(ack.clone()).unwrap_err());
    // Beside an effect in force (S1_cover's applied).
    let RelayAckResult::Record { effects, .. } = &mut ack.results[2] else {
        panic!("a record's result")
    };
    effects[0].why = Some("order".into());
    assert_eq!(bad(&ack), "malformed");
    for text in ["", "Order", "not after hold", &"z".repeat(65)] {
        let mut ack = reasoned.clone();
        let RelayAckResult::Record { effects, .. } = &mut ack.results[0] else {
            panic!("a record's result")
        };
        effects[0].why = Some(text.into());
        assert_eq!(bad(&ack), "malformed", "{text:?}");
    }
    assert!(relay_control_ack(reasoned).is_ok());
}

/// `r9-vectors-station-calls` through the production exports: every golden
/// message built byte for byte from its fields, read back to those fields
/// (each page record judged by `parse_control_record` as the file says), a
/// golden's decoded value written again to the same bytes, and every invalid
/// variant refused with its code. A page record the control parser refuses
/// can't be built: a Station serves only what it validated at intake.
#[test]
fn goldens_round_trip_through_the_bindings() {
    use atem_client_ffi::control::parse_control_record;
    let file = load("r9-vectors-station-calls");
    assert_eq!(s(&file["name"]), "r9-vectors-station-calls");
    let calls = file["calls"].as_array().unwrap();
    assert!(calls.len() >= 20, "{} goldens", calls.len());
    for case in calls {
        let name = s(&case["name"]);
        let (op, direction, wire) = (s(&case["op"]), s(&case["direction"]), s(&case["wire"]));
        let fields = &case["fields"];
        let judged = case.get("judged");
        // Built byte for byte, unless a page record doesn't parse.
        let refused = judged.and_then(|j| {
            j.as_array()
                .unwrap()
                .iter()
                .find(|r| r["parses"] == false)
                .map(|r| s(&r["error"]))
        });
        // Only a page with a record the parser refuses is marked as hand
        // assembled, and a builder refuses exactly that one.
        assert_eq!(
            case.get("hand_assembled") == Some(&json!(true)),
            refused.is_some(),
            "{name}: hand_assembled"
        );
        match (golden_build(&op, fields), refused) {
            (Ok(built), None) => assert_eq!(built, wire, "{name}: built"),
            (Err(e), Some(want)) => {
                assert_eq!(code(e), want, "{name}: a record that doesn't parse")
            }
            (other, _) => panic!("{name}: {other:?}"),
        }
        // Read back to its fields.
        assert_eq!(
            golden_describe(&direction, &wire).unwrap(),
            *fields,
            "{name}: decoded"
        );
        // Each page record, judged as the file says.
        for (record, verdict) in fields
            .get("records")
            .and_then(Value::as_array)
            .unwrap_or(&Vec::new())
            .iter()
            .zip(
                judged
                    .map(|j| j.as_array().unwrap().clone())
                    .unwrap_or_default(),
            )
        {
            match parse_control_record(record["record"].to_string()) {
                Ok(body) => {
                    assert_eq!(verdict["parses"], true, "{name}");
                    assert_eq!(s(&verdict["record_id"]), body.record_id, "{name}");
                }
                Err(e) => {
                    assert_eq!(verdict["parses"], false, "{name}");
                    assert_eq!(s(&verdict["error"]), code(e), "{name}");
                }
            }
        }
        // An ack read and written again: the same bytes.
        if let Ok(RelayToStation::ControlAck { ack }) = relay_decode_to_station(wire.clone()) {
            assert_eq!(
                relay_control_ack(ack).unwrap(),
                wire,
                "{name}: written again"
            );
        }
        // The other side's reader refuses it.
        let other = if direction == "to_station" {
            "to_host"
        } else {
            "to_station"
        };
        assert_eq!(
            code(golden_describe(other, &wire).unwrap_err()),
            "wrong_message",
            "{name}"
        );
    }
    // Exactly the bound is read, by the same reader for every call that can
    // carry a large page; `accepts` is what it gives back.
    for case in file["at_the_bound"].as_array().unwrap() {
        let name = s(&case["name"]);
        let wire = golden_wire(case);
        assert_eq!(wire.len(), 262_144, "{name}");
        let fields = golden_describe(&s(&case["direction"]), &wire).unwrap();
        let accepts = &case["accepts"];
        assert_eq!(fields["head"], accepts["head"], "{name}");
        match s(&case["op"]).as_str() {
            "control_sync_result" => {
                let records = fields["records"].as_array().unwrap();
                assert_eq!(records.len() as u64, accepts["records"].as_u64().unwrap());
                let parse = accepts["records_parse"].as_array().unwrap();
                for (r, want) in records.iter().zip(parse) {
                    let parses = parse_control_record(r["record"].to_string()).is_ok();
                    assert_eq!(json!(parses), *want, "{name}");
                }
            }
            _ => assert_eq!(
                fields["entries"].as_array().unwrap().len() as u64,
                accepts["entries"].as_u64().unwrap(),
                "{name}"
            ),
        }
        let other = golden_describe("to_station", &wire).unwrap_err();
        assert_eq!(code(other), "wrong_message", "{name}");
    }
    for case in file["invalid"].as_array().unwrap() {
        let name = s(&case["name"]);
        let wire = golden_wire(case);
        let error = golden_describe(&s(&case["reader"]), &wire).unwrap_err();
        assert_eq!(code(error), s(&case["code"]), "{name}");
    }
}

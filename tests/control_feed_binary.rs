//! The host's Station calls in the real runtime (host-work-v1 §11.4; the
//! delegated host-work design I.5.8; session-v1 R9.3): its own device-list
//! fetch over its one link, against the fake Station
//! (tests/support/station.rs), behind the debug-only `host.delegated` hook
//! (step 4's Decision 11). A temp profile with a pinned device list; the
//! fake Astation as the local link, or as the relay with Astation in the
//! room or routing the link on its host route proof (§R9.7b); the host's
//! state read from the debug state dump; its clocks moved on the debug host
//! clock, never by waiting.
#![cfg(target_os = "linux")]
mod support;

use atem_client::connect::{Event as ClientEvent, Identity};
use atem_client::control::relay::MAX_RELAY_MESSAGE_BYTES;
use atem_client::control::{MembershipFetch, MembershipFetchResult, RefusedCall, ToStation};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;
use support::astation::{ASTATION, FakeAstation, RelayEvent, Reply, write_verified_pairing};
use support::host_clock::HostClock;
use support::r9::{Router, write_pin};
use support::r9log::{TestLog, auth, secret};
use support::station::FakeStation;
use support::{Sandbox, within};

const ACCOUNT: &str = "acct-control-feed";
const HOST: &str = "host-control-feed";
const PHONE: &str = "dev-phone";
/// The local link's relay setting (refused: the link is Astation's
/// `:8080`); the selected Station's origin is this, normalized.
const NO_RELAY: &str = "http://127.0.0.1:1";
/// The longest a "wait until" helper waits; it only bounds a failure.
const WAIT: Duration = Duration::from_secs(60);

/// How the host reaches its Station.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Via {
    /// Astation's local link (`ASTATION_WS`).
    Local,
    /// The relay, Astation authenticating the link in the room.
    Relay,
    /// The relay, routed on the host's route proof, no Astation (§R9.7b).
    Routed,
}

impl Via {
    fn kind(self) -> &'static str {
        match self {
            Via::Local => "local",
            Via::Relay => "relay",
            Via::Routed => "routed",
        }
    }
}

struct Rig {
    sandbox: Sandbox,
    /// The fake Astation (`Local`) or relay (`Relay`, `Routed`).
    astation: FakeAstation,
    _relay_events: Option<mpsc::Receiver<RelayEvent>>,
    /// The account's device list: pinned at the start, then grown where the
    /// Station has more.
    log: TestLog,
    station: FakeStation,
    clock: HostClock,
    runtime: Child,
    /// The host's link (the fake's connection number).
    link: u64,
    via: Via,
}

impl Rig {
    /// A verified host whose pinned list is the Mac, this host and (with
    /// `phone`) a native member; `delegated`: the `host.delegated` hook on.
    /// The fake Station holds the same list until the test grows it.
    fn start(via: Via, delegated: bool, phone: bool) -> Rig {
        let sandbox = Sandbox::new();
        write_verified_pairing(&sandbox.config(), ACCOUNT, HOST, 1);
        let host_seed = secret("control feed host");
        let mut log = TestLog::genesis(ACCOUNT, &secret("control feed astation"));
        log.add_host(HOST, 1, &host_seed);
        if phone {
            log.add_native(PHONE, &["control", "view"]);
        }
        write_pin(&sandbox.config(), &log, HOST, 1, &host_seed);
        let head = log.log.head();
        let head = json!({"seq": head.seq, "hash": head.hash.to_hex()});
        let (astation, relay_events) = match via {
            Via::Local => (FakeAstation::start(), None),
            Via::Relay => {
                let (relay, events) = FakeAstation::start_relay(|_| Reply::AstationFirst {
                    ok: None,
                    reply_first: false,
                });
                (relay, Some(events))
            }
            Via::Routed => {
                let (relay, events) = FakeAstation::start_relay(move |_| Reply::Ok {
                    host_id: HOST.into(),
                    head: head.clone(),
                });
                (relay, Some(events))
            }
        };
        let relay_url = match via {
            Via::Local => NO_RELAY.to_owned(),
            Via::Relay | Via::Routed => astation.url.clone(),
        };
        // Made before the runtime: it takes the host's calls from the start.
        // Its heads only when a test says ([`Rig::announce`]): its heartbeat
        // (30 s, on the real clock) would fetch for the host.
        let mut station = FakeStation::new(&astation, &relay_url, &log, HOST, 1);
        station.silence_heads(true);
        let clock = HostClock::start(sandbox.dir.path(), "host-clock");
        let output = std::fs::File::create(sandbox.dir.path().join("runtime.log")).unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_atem"));
        command.env_clear();
        if delegated {
            command.env("ATEM_TEST_HOST_FEATURES", "host.delegated");
        }
        let local = match via {
            Via::Local => astation.url.clone(),
            Via::Relay | Via::Routed => "ws://127.0.0.1:1/ws".into(),
        };
        let runtime = command
            .arg("runtime")
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &sandbox.home)
            .env("XDG_RUNTIME_DIR", &sandbox.run)
            .env("ASTATION_WS", local)
            .env("ASTATION_RELAY_URL", &relay_url)
            .env(
                "ATEM_TEST_STATE_DUMP",
                sandbox.dir.path().join("state.json"),
            )
            .env("ATEM_TEST_HOST_CLOCK", &clock.path)
            .env("ATEM_TEST_NO_INIT_LIMIT", "1")
            .stdin(Stdio::null())
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .spawn()
            .unwrap();
        let link = match via {
            Via::Local | Via::Relay => Router::new(&astation).link,
            Via::Routed => {
                let events = relay_events.as_ref().unwrap();
                loop {
                    match events.recv_timeout(WAIT) {
                        Ok(RelayEvent::Proof { link, .. }) => break link,
                        Ok(_) => {}
                        Err(_) => panic!("no route proof"),
                    }
                }
            }
        };
        Rig {
            sandbox,
            astation,
            _relay_events: relay_events,
            log,
            station,
            clock,
            runtime,
            link,
            via,
        }
    }

    fn runtime_log(&self) -> String {
        std::fs::read_to_string(self.sandbox.dir.path().join("runtime.log")).unwrap_or_default()
    }

    /// The pinned device list's head `seq`, as written.
    fn head(&self) -> u64 {
        list_head(&self.sandbox.config())
    }

    /// The host's state after its last pass (the debug state dump).
    fn dump(&self) -> Value {
        std::fs::read(self.sandbox.dir.path().join("state.json"))
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(Value::Null)
    }

    /// Waits for the host's Station state to satisfy `done`.
    #[track_caller]
    fn until_station(&self, what: &str, done: impl Fn(&Value) -> bool) -> Value {
        let mut last = Value::Null;
        within(what, || {
            last = self.dump()["station"].clone();
            done(&last)
        });
        last
    }

    /// The Station announces its heads on the host's link now.
    fn announce(&mut self) {
        self.station.serve(self.link);
        self.station.heads_now();
    }

    /// The Station serves the link until the host's list reaches `seq`.
    #[track_caller]
    fn serve_until_head(&mut self, seq: u64) {
        serve_until_head(&mut self.station, &self.sandbox.config(), self.link, seq);
    }

    /// The host's Station calls so far, as the shared reader reads them.
    fn calls(&self) -> Vec<ToStation> {
        self.station
            .sent()
            .iter()
            .map(|bytes| ToStation::decode(bytes.as_bytes()).unwrap())
            .collect()
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        self.sandbox.track();
        let _ = self.runtime.kill();
        let _ = self.runtime.wait();
    }
}

/// The head `seq` of the device list pinned in `config`, as written.
fn list_head(config: &std::path::Path) -> u64 {
    let path = config.join("pairing/membership.json");
    let state: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    state["head"]["seq"].as_u64().unwrap()
}

/// `station` serves `link` until the list pinned in `config` reaches `seq`.
#[track_caller]
fn serve_until_head(station: &mut FakeStation, config: &std::path::Path, link: u64, seq: u64) {
    within(&format!("the host's list at {seq}"), || {
        station.serve(link);
        list_head(config) >= seq
    });
    assert_eq!(list_head(config), seq);
}

fn fetch(after: u64) -> ToStation {
    ToStation::MembershipFetch(MembershipFetch { after })
}

/// session-v1 R9.3, design I.5.8: announced a device-list head beyond its
/// own, the host fetches the entries after its head over its link and
/// applies them as any carriage, with the carriage's own verification and
/// effects: its list grows, and an attachment's channel gets
/// `membership_head` (`R9Host::carried`).
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES and ATEM_TEST_STATE_DUMP hooks"
)]
fn fetch_applies_entries_as_a_carriage() {
    let mut rig = Rig::start(Via::Local, true, true);
    let mut router = Router::on(&rig.astation, rig.link);
    let mut phone = router
        .connect("ph", &rig.log, HOST, &Identity::native(PHONE, auth(PHONE)))
        .expect("the phone");
    assert_eq!(rig.head(), 3);

    rig.log.add_native("dev-tablet", &["view"]);
    rig.station.set_log(&rig.log);
    rig.station.serve(rig.link);
    rig.station.heads_now();
    serve_until_head(&mut rig.station, &rig.sandbox.config(), rig.link, 4);
    assert_eq!(rig.calls(), [fetch(3)]);
    let pinned: Value = serde_json::from_slice(
        &std::fs::read(rig.sandbox.config().join("pairing/membership.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(pinned["head"]["hash"], rig.log.log.head().hash.to_hex());

    // The carriage's effects reach the live attachment.
    let seen = (0..20).find_map(|_| {
        router
            .events("ph", &mut phone)
            .ok()?
            .into_iter()
            .find_map(|e| match e {
                ClientEvent::MembershipHead { re: None, head, .. } => Some(head.seq),
                _ => None,
            })
    });
    assert_eq!(seen, Some(4));
    // Current now: no further call.
    let station = rig.until_station("the fetch settled", |s| s["fetch"]["in_flight"].is_null());
    assert_eq!(station["fetch"]["results"], 1);
}

/// R9.3: a carriage is at most 64 entries (and the result 256 KiB), so a
/// host further behind fetches again from its new head while it is behind
/// the announced head, until it reaches it.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES and ATEM_TEST_STATE_DUMP hooks"
)]
fn fetch_again_while_behind_the_announced_head() {
    let mut rig = Rig::start(Via::Local, true, true);
    let mut n = 0;
    rig.log.grow(|log, head| {
        n += 1;
        (n <= 66).then(|| {
            let scope = atem_client::membership::ServiceScope::new([HOST]).ops(["view"]);
            log.service_body(head, &format!("svc-{n}"), &scope).unwrap()
        })
    });
    assert_eq!(rig.log.log.head().seq, 69);
    rig.station.set_log(&rig.log);
    // Announced once: the host's second fetch is its own.
    rig.announce();
    rig.serve_until_head(69);
    assert_eq!(rig.calls(), [fetch(3), fetch(67)]);
}

/// Decision 20, §11.4 "Refusals": a `membership_fetch_refused` advances
/// nothing (the list's head stays, nothing is applied) and correlates no
/// request; the host fetches again at the next heads only after 30
/// seconds (on its clock), and at once on the next link generation. One
/// runtime.log line an hour.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_STATE_DUMP and ATEM_TEST_HOST_CLOCK hooks"
)]
fn fetch_refused_advances_nothing_and_retries() {
    let mut rig = Rig::start(Via::Local, true, true);
    rig.log.add_native("dev-tablet", &["view"]);
    rig.station.set_log(&rig.log);
    rig.station.refuse(RefusedCall::MembershipFetch, true);
    let link = rig.link;
    rig.announce();
    assert_eq!(rig.station.next_call(link), Ok(fetch(3)));
    let station = rig.until_station("the refusal", |s| s["refusals"]["membership_fetch"] == 1);
    assert!(station["fetch"]["in_flight"].is_null(), "{station}");
    assert_eq!(rig.head(), 3, "nothing advanced");

    // The next heads, within 30 s: no fetch.
    let heads = station["heads"].as_u64().unwrap();
    rig.station.heads_now();
    let station = rig.until_station("the next heads", |s| s["heads"] == heads + 1);
    assert!(station["fetch"]["in_flight"].is_null(), "{station}");
    assert_eq!(station["fetch"]["backoff"], true);
    assert_eq!(rig.calls(), [fetch(3)]);

    // 30 s later on the host's clock: the next heads fetches again.
    rig.station.refuse(RefusedCall::MembershipFetch, false);
    rig.clock.add_mono(30_000);
    rig.station.heads_now();
    rig.serve_until_head(4);
    assert_eq!(rig.calls(), [fetch(3), fetch(3)]);

    // Refused again; Astation authenticates the link again (the next link
    // generation, at once): it fetches at once, the backoff gone with the
    // old generation.
    rig.log.add_native("dev-laptop", &["view"]);
    rig.station.set_log(&rig.log);
    rig.station.refuse(RefusedCall::MembershipFetch, true);
    // The fetches a heads starts: at most one a second (I1).
    rig.clock.add_mono(1_000);
    rig.station.heads_now();
    assert_eq!(rig.station.next_call(link), Ok(fetch(4)));
    rig.until_station("the second refusal", |s| {
        s["refusals"]["membership_fetch"] == 2
    });
    rig.station.refuse(RefusedCall::MembershipFetch, false);
    let generation = rig.dump()["station"]["link"]["gen"].as_u64().unwrap();
    // A new challenge (a repeat of the one answered is spent).
    let challenge = json!({"type": "statusUpdate", "data": {"status": "auth_required",
        "data": {"astation_id": ASTATION, "challenge": "c".repeat(64),
                 "transport": "lan", "protocol": "2"}}});
    rig.astation.send(link, challenge.to_string());
    rig.until_station("the next link generation", |s| {
        s["link"]["gen"].as_u64() > Some(generation)
    });
    // The new generation keeps the fetch's pacing (a second after the last
    // fetch a heads started).
    rig.clock.add_mono(1_000);
    rig.announce();
    rig.serve_until_head(5);
    assert_eq!(rig.calls().last(), Some(&fetch(4)));

    // One runtime.log line for both refusals (an hour apart at most).
    let lines = rig
        .runtime_log()
        .matches("the Station refused this host's membership_fetch (forbidden)")
        .count();
    assert_eq!(lines, 1, "{}", rig.runtime_log());
}

/// §11.4 "Transport", design I.5.8: the fetch runs over whichever link the
/// host has: Astation's local link, the relay with Astation in the room,
/// and a routed relay link with no Astation (§R9.7b, where relay messages
/// already pass). The Station link is the selected Station's normalized
/// origin.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES and ATEM_TEST_STATE_DUMP hooks"
)]
fn fetch_runs_on_relay_local_and_routed_links() {
    for via in [Via::Local, Via::Relay, Via::Routed] {
        let mut rig = Rig::start(via, true, true);
        rig.log.add_native("dev-tablet", &["view"]);
        rig.station.set_log(&rig.log);
        rig.announce();
        rig.serve_until_head(4);
        assert_eq!(rig.calls(), [fetch(3)], "{via:?}");
        let station = rig.until_station("the link", |s| !s["link"].is_null());
        let origin = match via {
            Via::Local => NO_RELAY.to_owned(),
            Via::Relay | Via::Routed => rig.astation.url.clone(),
        };
        assert_eq!(station["link"]["kind"], rig.via.kind(), "{via:?}");
        assert_eq!(station["link"]["origin"], origin, "{via:?}");
    }
}

/// Decision 21 (§11.4 "Bounds"): a `membership_fetch_result` over 256 KiB
/// is dropped unread, like any relay message over the bound; the host
/// keeps waiting for its fetch, and a result within the bound is applied.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES and ATEM_TEST_STATE_DUMP hooks"
)]
fn a_fetch_result_over_256_kib_is_dropped_unread() {
    let mut rig = Rig::start(Via::Local, true, true);
    let mut big = 0;
    rig.log.grow(|log, head| {
        big += 1;
        (big <= 64).then(|| log.near_max_service(head, big))
    });
    rig.station.set_log(&rig.log);
    let link = rig.link;
    // Heads: the host asks; the fake doesn't answer yet.
    rig.announce();
    rig.until_station("the fetch", |s| s["fetch"]["in_flight"] == 3);

    // Every entry after 3 in one result: valid but for its size.
    let head = rig.log.log.head();
    let entries: Vec<Value> = rig.log.entries[3..]
        .iter()
        .map(|e| e.object().to_json())
        .collect();
    let oversize = json!({"type": "relay", "op": "membership_fetch_result",
        "head": {"seq": head.seq, "hash": head.hash.to_hex()}, "entries": entries})
    .to_string();
    assert!(
        oversize.len() > MAX_RELAY_MESSAGE_BYTES,
        "{}",
        oversize.len()
    );
    assert_eq!(
        MembershipFetchResult::decode(oversize.as_bytes()),
        Err(atem_client::control::RelayError::TooLarge)
    );
    rig.astation.send(link, oversize);
    within("the drop", || {
        rig.runtime_log()
            .contains("relay message(s) dropped (over 256 KiB")
    });
    let station = rig.dump()["station"].clone();
    assert_eq!(station["fetch"]["in_flight"], 3, "still waiting: {station}");
    assert_eq!(station["fetch"]["results"], 0);
    // Never read by the Station link: its reader would count it unread.
    assert_eq!(station["unread"], 0, "{station}");
    assert_eq!(rig.head(), 3, "nothing applied");

    // The Station answers within the bound: applied, then the rest.
    rig.serve_until_head(67);
}

/// Decision 11: with `host.delegated` off the host makes no Station call:
/// heads announcing a newer device list are read and dropped, as today.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_STATE_DUMP hook"
)]
fn no_station_call_without_host_delegated() {
    let mut rig = Rig::start(Via::Local, false, true);
    rig.log.add_native("dev-tablet", &["view"]);
    rig.station.set_log(&rig.log);
    let link = rig.link;
    rig.announce();
    // The heads were read: a `push_ack` sent after them was (its line).
    let mut router = Router::on(&rig.astation, link);
    router.send_raw(json!({"type": "relay", "op": "push_ack", "acks": []}).to_string());
    within("the push_ack", || {
        rig.runtime_log()
            .contains("a push_ack acknowledged nothing pending")
    });
    // Anything the host sent then is on the link before this reply.
    router.send_raw(
        json!({"type": "session", "data": {"v": 1, "op": "hello",
            "id": "aaaaaaaa-0000-4000-8000-0000000000c1", "revision": 8}})
        .to_string(),
    );
    let reply = loop {
        let message = router.next_other();
        if message["type"] == "session" {
            break message;
        }
    };
    assert_eq!(reply["data"]["code"], "unsupported_version", "{reply}");
    assert!(rig.station.serve(link).is_empty());
    assert!(rig.station.sent().is_empty());
    assert_eq!(rig.head(), 3);
    assert!(rig.dump()["station"].is_null(), "no Station state");
}

/// The host's `membership_fetch` bytes equal the shared vectors' (PR 2's
/// `r9-vectors-station-calls.json`, case `membership_fetch`: a host whose
/// list is at `seq` 2).
#[test]
#[ignore = "needs PR 2's designs/protocol/fixtures/r9-vectors-station-calls.json, not in this stack (Task 34 removes the ignore)"]
fn the_hosts_fetch_bytes_match_the_goldens() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("designs/protocol/fixtures/r9-vectors-station-calls.json");
    let vectors: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let case = vectors["calls"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "membership_fetch")
        .expect("the membership_fetch case")
        .clone();
    assert_eq!(case["fields"]["after"], 2);
    let mut rig = Rig::start(Via::Local, true, false);
    rig.log.add_native("dev-tablet", &["view"]);
    rig.station.set_log(&rig.log);
    rig.announce();
    rig.serve_until_head(3);
    assert_eq!(rig.station.sent(), [case["wire"].as_str().unwrap()]);
}

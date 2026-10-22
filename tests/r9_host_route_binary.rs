//! The host route proof (atem-session-v1.md §R9.7b) in the real `atem
//! runtime` process, with no Astation anywhere: a temp profile paired with
//! an Astation that is offline (its local URL refuses connections), a
//! pinned device list, and a fake relay (`FakeAstation::start_relay`) that
//! sends `host_challenge` the moment the runtime's relay identity link
//! opens and answers the proof as each test plans. The relay's shared
//! verifier (`atem_client::host_route`) checks every proof for the room and
//! `atem_id` of the link's URL.
//!
//! - `host_route_ok` holds the link with no Astation, well past the old
//!   10 s authentication deadline, for r9 only: a phone is admitted over
//!   it, an r8 `hello` and an Astation operation are not served, and a
//!   later Astation `auth_required` makes it an authenticated link;
//! - an `ok` that isn't for this link's proof (before the challenge,
//!   another host, a head the host doesn't hold, a late one on a retried
//!   link) is ignored and never holds the link;
//! - `host_route_refused` closes it and the runtime retries;
//! - a held host answers no challenge.
#![cfg(target_os = "linux")]

mod support;

use atem_client::connect::Identity;
use atem_client::host_route::verify_host_route_message;
use serde_json::{Value, json};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use support::astation::{
    ASTATION, AuthReply, Event, FakeAstation, RelayEvent, Reply, auth_required,
    write_verified_pairing,
};
use support::r9::{Out, Router, write_pin};
use support::r9log::{TestLog, auth, secret};
use support::{Sandbox, within};

const ACCOUNT: &str = "acct-route";
const HOST: &str = "host-route";
/// The old deadline for Astation's `auth_required` on a new link.
const AUTH_DEADLINE: Duration = Duration::from_secs(10);
/// The runtime's retry after a failed connect.
const RETRY: Duration = Duration::from_secs(30);

struct Rig {
    sandbox: Sandbox,
    log: TestLog,
    relay: FakeAstation,
    seen: mpsc::Receiver<RelayEvent>,
    runtime: Child,
}

fn head_json(log: &TestLog) -> Value {
    let head = log.log.head();
    json!({"seq": head.seq, "hash": head.hash.to_hex()})
}

impl Rig {
    /// Paired with `ASTATION` (offline) and a pinned device list naming
    /// this host and a phone; `held`: a recorded device-list write fault.
    /// `plan(n, head)`: the relay's reply on its `n`th host connection.
    fn start(held: bool, plan: fn(u64, Value) -> Reply) -> Rig {
        Self::start_with(true, held, plan)
    }

    /// [`Rig::start`]; `verified: false`: paired, device not verified yet
    /// (`atem pair verify` then runs as an Astation operation).
    fn start_with(verified: bool, held: bool, plan: fn(u64, Value) -> Reply) -> Rig {
        let sandbox = Sandbox::new();
        if verified {
            write_verified_pairing(&sandbox.config(), ACCOUNT, HOST, 1);
        } else {
            support::profile::write_pairing(&sandbox.config(), ASTATION, 1);
        }
        let host_seed = secret("route host seed");
        let mut log = TestLog::genesis(ACCOUNT, &secret("route astation"));
        log.add_host(HOST, 1, &host_seed);
        log.add_native("dev-phone", &["control", "view"]);
        write_pin(&sandbox.config(), &log, HOST, 1, &host_seed);
        if held {
            std::fs::write(
                sandbox.config().join("pairing").join("membership.fault"),
                br#"{"v":1,"runtime_epoch":1,"file":"membership.json","at":1}"#,
            )
            .unwrap();
        }
        let head = head_json(&log);
        let (relay, seen) = FakeAstation::start_relay(move |n| plan(n, head.clone()));
        let output = std::fs::File::create(sandbox.dir.path().join("runtime.log")).unwrap();
        let runtime = Command::new(env!("CARGO_BIN_EXE_atem"))
            .arg("runtime")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &sandbox.home)
            .env("XDG_RUNTIME_DIR", &sandbox.run)
            // No Astation anywhere: the local link is refused.
            .env("ASTATION_WS", "ws://127.0.0.1:1/ws")
            .env("ASTATION_RELAY_URL", &relay.url)
            .stdin(Stdio::null())
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .spawn()
            .unwrap();
        let config = sandbox.config();
        within("the runtime to listen", || {
            config.join("runtime.socket").exists()
        });
        Rig {
            sandbox,
            log,
            relay,
            seen,
            runtime,
        }
    }

    fn runtime_log(&self) -> String {
        std::fs::read_to_string(self.sandbox.dir.path().join("runtime.log")).unwrap_or_default()
    }

    fn event(&self, wait: Duration) -> Option<RelayEvent> {
        self.seen.recv_timeout(wait).ok()
    }

    /// The proof on connection `n`, verified by the shared verifier.
    fn proof(&self, n: u64, wait: Duration) {
        match self.event(wait) {
            Some(RelayEvent::Proof {
                link,
                query,
                nonce,
                room,
                message,
            }) => {
                assert_eq!(link, n);
                let param = |key: &str| {
                    query
                        .iter()
                        .find(|(k, _)| k == key)
                        .map(|(_, v)| v.clone())
                        .unwrap_or_else(|| panic!("no {key} in {query:?}"))
                };
                assert_eq!(param("role"), "atem");
                assert_eq!(param("code"), ASTATION);
                assert_eq!(room, ASTATION);
                let route = verify_host_route_message(
                    &self.log.log,
                    message.as_bytes(),
                    &nonce,
                    ASTATION,
                    &param("atem_id"),
                )
                .unwrap();
                assert_eq!(route.host_id, HOST);
                assert_eq!(route.head, self.log.log.head());
            }
            other => panic!(
                "no proof on connection {n}: {other:?}\n{}",
                self.runtime_log()
            ),
        }
    }

    /// Connection `n` ends within `wait`.
    fn closed(&self, n: u64, wait: Duration) {
        match self.event(wait) {
            Some(RelayEvent::Closed(link)) => assert_eq!(link, n),
            other => panic!(
                "connection {n} wasn't closed: {other:?}\n{}",
                self.runtime_log()
            ),
        }
    }

    fn status(&self) -> String {
        let (out, err, _) = self.sandbox.atem(&["status"]);
        format!("{out}{err}")
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = self.runtime.kill();
        let _ = self.runtime.wait();
    }
}

fn ok(_: u64, head: Value) -> Reply {
    Reply::Ok {
        host_id: HOST.into(),
        head,
    }
}

/// (a), (d): routed with no Astation, held three times past the old
/// deadline while a phone is admitted over it; r8 and an Astation
/// operation are not served; Astation's later `auth_required` upgrades it.
#[test]
fn a_routed_host_is_held_for_r9_only_until_astation_authenticates_it() {
    let rig = Rig::start(false, ok);
    rig.proof(1, Duration::from_secs(20));
    // Held well past the old deadline: no close, no retry.
    assert!(
        rig.event(AUTH_DEADLINE * 3).is_none(),
        "the routed link was dropped or retried\n{}",
        rig.runtime_log()
    );
    let log = rig.runtime_log();
    assert!(log.contains("host_route ok at head"), "{log}");
    assert!(log.contains("relay route held (no Astation)"), "{log}");
    let status = rig.status();
    assert!(status.contains("r9 routed (no Astation)"), "{status}");
    assert!(status.contains("routed via relay ("), "{status}");

    // A phone is admitted over it (its identity checked as always).
    let mut router = Router::on(&rig.relay, 1);
    let phone = Identity::native("dev-phone", auth("dev-phone"));
    let attached = router.connect("ph1", &rig.log, HOST, &phone);
    assert!(attached.is_ok(), "{:?}", attached.err());
    // An r8 hello is not served on it.
    router.send_raw(
        json!({"type": "session", "data": {"v": 1, "op": "hello", "id": "r8-hello",
                                          "revision": 8}})
        .to_string(),
    );
    let until = Instant::now() + Duration::from_millis(1_500);
    while let Some(v) = router.other_within(until.saturating_duration_since(Instant::now())) {
        assert_ne!(v["type"], "session", "an r8 reply on the routed link: {v}");
    }
    // Astation authenticates the same link later (granting a new session,
    // as on a connect): it becomes Astation's, the session is saved, and
    // the channel opened while it was routed is closed (a new link
    // generation; the phone connects again).
    *rig.relay.auth.lock().unwrap() = AuthReply::Grant {
        session_id: "session-2".into(),
        token: "token-2".into(),
    };
    rig.relay.send(1, auth_required("relay").to_string());
    match router.next("ph1") {
        Out::Close(reason) => assert_eq!(reason.as_deref(), Some("closed")),
        Out::Frame(_) => panic!("ph1 wasn't closed on the upgrade"),
    }
    within("the granted session to be saved", || {
        support::profile::saved_session_id(&rig.sandbox.config()).as_deref() == Some("session-2")
    });
    within("the status to show Astation", || {
        let status = rig.status();
        !status.contains("r9 routed") && status.contains("connected via relay (")
    });
    assert!(
        rig.runtime_log()
            .contains("Astation authenticated the routed relay link")
    );
    assert!(rig.event(Duration::from_millis(500)).is_none(), "same link");
}

/// H1: Astation is online but denies the routed link's authentication:
/// the link stays routed for r9 (the phone stays admitted and served), the
/// session advice is logged and answers a waiting command at once, and
/// nothing reconnects until Astation challenges again.
#[test]
fn a_denied_astation_authentication_keeps_the_routed_link() {
    let rig = Rig::start_with(false, false, ok);
    rig.proof(1, Duration::from_secs(20));
    within("the route to be held", || {
        rig.runtime_log().contains("relay route held (no Astation)")
    });
    let mut router = Router::on(&rig.relay, 1);
    let phone = Identity::native("dev-phone", auth("dev-phone"));
    let mut attached = router
        .connect("ph1", &rig.log, HOST, &phone)
        .unwrap_or_else(|e| panic!("{e:?}"));
    *rig.relay.auth.lock().unwrap() = AuthReply::Deny("session revoked".into());
    rig.relay.send(1, auth_required("relay").to_string());
    within("the denial to be logged", || {
        rig.runtime_log()
            .contains("Astation didn't authenticate the routed relay link")
    });
    let log = rig.runtime_log();
    assert!(log.contains("expired or was refused"), "{log}");
    // The phone is still admitted and served on the same channel.
    assert!(router.list("ph1", &mut attached).is_empty());
    // No reconnect: one connection at the relay, still open.
    assert!(
        rig.event(AUTH_DEADLINE + Duration::from_secs(2)).is_none(),
        "the link was dropped or a new connection opened\n{}",
        rig.runtime_log()
    );
    assert!(rig.status().contains("r9 routed (no Astation)"));
    // An Astation operation gets the advice at once (no 15 s wait).
    let started = Instant::now();
    let (out, err, ok) = rig.sandbox.atem(&["pair", "verify"]);
    let text = format!("{out}{err}");
    assert!(!ok, "{text}");
    assert!(text.contains("expired or was refused"), "{text}");
    assert!(started.elapsed() < Duration::from_secs(10), "{text}");
    // Astation challenges again and accepts: the link becomes Astation's.
    *rig.relay.auth.lock().unwrap() = AuthReply::Authenticated;
    rig.relay.send(
        1,
        auth_required("relay")
            .to_string()
            .replace(&"b".repeat(64), &"c".repeat(64)),
    );
    within("the upgrade", || {
        rig.runtime_log()
            .contains("Astation authenticated the routed relay link")
    });
    assert!(rig.event(Duration::from_millis(500)).is_none(), "same link");
}

/// M1: a later `host_challenge` on a routed link is ignored (one per link).
#[test]
fn a_routed_link_answers_no_second_challenge() {
    let rig = Rig::start(false, ok);
    rig.proof(1, Duration::from_secs(20));
    within("the route to be held", || {
        rig.runtime_log().contains("relay route held (no Astation)")
    });
    let challenge = atem_client::host_route::HostChallenge::new(ASTATION);
    rig.relay.send(1, challenge.to_json().to_string());
    let deadline = Instant::now() + Duration::from_secs(2);
    while let Ok(event) = rig
        .relay
        .events
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
    {
        if let Event::Message(_, v) = event {
            assert_ne!(v["op"], "host_route", "a second proof: {v}");
        }
    }
    let log = rig.runtime_log();
    assert!(
        log.contains("host_challenge ignored: the link is already routed or authenticated"),
        "{log}"
    );
}

/// M2: a `host_route_refused` before this link's proof is not its verdict:
/// ignored, and the proof's `ok` then routes the link.
#[test]
fn a_refusal_before_the_proof_is_ignored() {
    let rig = Rig::start(false, |_, head| Reply::RefusedFirst {
        host_id: HOST.into(),
        head,
    });
    rig.proof(1, Duration::from_secs(20));
    within("the route to be held", || {
        rig.runtime_log().contains("relay route held (no Astation)")
    });
    let log = rig.runtime_log();
    assert!(
        log.contains("host_route refused ignored: no proof was sent on this link"),
        "{log}"
    );
    assert!(rig.event(Duration::from_secs(2)).is_none(), "held");
}

/// Route acknowledgement only carries r9: an Astation operation (`atem
/// pair verify` on a device not verified yet) never runs on a routed link;
/// it waits for an Astation link and fails, and the routed link stays.
#[test]
fn an_astation_operation_is_refused_on_a_routed_link() {
    let rig = Rig::start_with(false, false, ok);
    rig.proof(1, Duration::from_secs(20));
    within("the route to be held", || {
        rig.runtime_log().contains("relay route held (no Astation)")
    });
    let (out, err, ok) = rig.sandbox.atem(&["pair", "verify"]);
    let text = format!("{out}{err}");
    assert!(!ok, "{text}");
    assert!(text.contains("isn't connected to Astation"), "{text}");
    assert!(!rig.relay.events.try_iter().any(|e| matches!(
        e,
        Event::Message(_, v) if v["type"] == "verifyCommit"
    )));
    assert!(
        rig.event(Duration::from_millis(200)).is_none(),
        "the routed link stays"
    );
    assert!(rig.status().contains("r9 routed (no Astation)"));
}

/// (c): `host_route_refused` closes the link; the runtime retries.
#[test]
fn a_refused_route_is_closed_and_retried() {
    let rig = Rig::start(false, |n, head| {
        if n == 1 {
            Reply::Refused("unknown_host")
        } else {
            ok(n, head)
        }
    });
    rig.proof(1, Duration::from_secs(20));
    rig.closed(1, Duration::from_secs(5));
    // The retry: a new connection, a new proof, routed this time.
    rig.proof(2, RETRY + Duration::from_secs(15));
    assert!(rig.event(Duration::from_secs(12)).is_none(), "held");
    let log = rig.runtime_log();
    assert!(log.contains("host_route refused: unknown_host"), "{log}");
}

/// (b): an `ok` before the challenge holds nothing: the link is dropped at
/// the old deadline.
#[test]
fn an_unsolicited_ok_never_holds_the_link() {
    let rig = Rig::start(false, |_, head| Reply::Unsolicited {
        host_id: HOST.into(),
        head,
    });
    rig.proof(1, Duration::from_secs(20));
    rig.closed(1, AUTH_DEADLINE + Duration::from_secs(5));
    let log = rig.runtime_log();
    assert!(log.contains("ok ignored: no proof was sent"), "{log}");
}

/// (b): an `ok` naming another host never holds the link.
#[test]
fn an_ok_for_another_host_never_holds_the_link() {
    let rig = Rig::start(false, |_, head| Reply::Ok {
        host_id: "host-other".into(),
        head,
    });
    rig.proof(1, Duration::from_secs(20));
    rig.closed(1, AUTH_DEADLINE + Duration::from_secs(5));
    let log = rig.runtime_log();
    assert!(log.contains("ok ignored: another host"), "{log}");
}

/// (b): an `ok` naming a head the host doesn't hold never holds the link.
#[test]
fn an_ok_for_an_unknown_head_never_holds_the_link() {
    let rig = Rig::start(false, |_, head| {
        let mut unknown = head;
        unknown["seq"] = json!(unknown["seq"].as_u64().unwrap() + 1);
        Reply::Ok {
            host_id: HOST.into(),
            head: unknown,
        }
    });
    rig.proof(1, Duration::from_secs(20));
    rig.closed(1, AUTH_DEADLINE + Duration::from_secs(5));
    let log = rig.runtime_log();
    assert!(
        log.contains("ok ignored: a head this host doesn't hold"),
        "{log}"
    );
}

/// (b): a late `ok` (sent after the link it was for dropped, arriving on
/// the retried link before its challenge) never holds the new link.
#[test]
fn a_late_ok_on_a_retried_link_never_holds_it() {
    let rig = Rig::start(false, |n, head| {
        if n == 1 {
            Reply::Nothing
        } else {
            Reply::Unsolicited {
                host_id: HOST.into(),
                head,
            }
        }
    });
    rig.proof(1, Duration::from_secs(20));
    rig.closed(1, AUTH_DEADLINE + Duration::from_secs(5));
    rig.proof(2, RETRY + Duration::from_secs(15));
    rig.closed(2, AUTH_DEADLINE + Duration::from_secs(5));
}

/// A held host answers no challenge (§R9.7b).
#[test]
fn a_held_host_answers_no_challenge() {
    let rig = Rig::start(true, ok);
    // No proof: the relay gives up on it.
    match rig.event(Duration::from_secs(20)) {
        Some(RelayEvent::Closed(1)) => {}
        other => panic!("{other:?}"),
    }
    let log = rig.runtime_log();
    assert!(
        log.contains("host_challenge not answered: device list held"),
        "{log}"
    );
}

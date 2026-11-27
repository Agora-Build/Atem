//! The Station's `service_suspended` in the real runtime (the delegated
//! host-work design III.5; session-v1 R9.7b and R9.7a; the `text`, the
//! disclosure order and the host's 10 s drop are Atem's proposal, for
//! Astation's agreement, #120 7207832274): the built-in Station refuses
//! relay service to a disabled or unowned account's hosts. A temp profile
//! with a pinned device list and agent hosting on; the fake Astation as a
//! relay that routes the host on its proof (or as Astation's local link);
//! the fake Station's `suspend` and `restore` (tests/support/station.rs),
//! which close the host's channels (B-3), send the open link's notice (B-2)
//! and refuse the next connections' proofs (B-1). The host reads it, shows
//! it and retries at the normal pace; nothing of its trust or state moves.
//! The host-side reading works in release builds; only its `Control
//! feeds:` line, and what its Station link does, need `host.delegated`
//! (the debug hook).
#![cfg(target_os = "linux")]
mod support;

use atem_client::connect::Identity;
use atem_client::control::{AckResult, ControlAck, ControlAction, ToStation};
use atem_client::membership::ServiceScope;
use serde_json::{Value, json};
use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::time::{Duration, Instant};
use support::Sandbox;
use support::astation::{FakeAstation, RelayEvent, Reply, write_verified_pairing};
use support::delegated::{
    Dev, HostIds, HostRig, WAIT, complete_turn, enqueue, hosting_toml, in_turn, never_ran, private,
    stored, task, wait_stored,
};
use support::host_clock::HostClock;
use support::r9::{Out, Router, write_pin};
use support::r9log::{self, MAC, TestLog, auth, secret};
use support::station::{FakeStation, Pump};

const ACCOUNT: &str = "acct-suspended";
const HOST: &str = "host-suspended";
const PHONE: &str = "dev-phone";
/// The service whose tasks the tests run; delegated while the Station's
/// feed covers it.
const SVC: &str = "svc-work";
const SVC_OPS: [&str; 5] = ["launch", "message", "notify", "prompt", "view"];
/// The local link's relay setting (refused: the link is Astation's
/// `:8080`); the selected Station's origin is this, normalized.
const NO_RELAY: &str = "http://127.0.0.1:1";
const HOUR: u64 = 3_600_000;
/// The Station's text (III.5).
const TEXT: &str = "service suspended: account disabled at Agora.Build";
/// What `atem status` shows of it.
const SHOWN: &str = "service suspended: account disabled at Agora.Build";
const GATE_CLOSED: &str = "revocations not yet checked";
const BEHIND: &str = "waiting for an earlier task on this session";
/// The connect loop's retry after a failed or suspended connect.
const RETRY: Duration = Duration::from_secs(30);
const IDS: HostIds = HostIds {
    account: ACCOUNT,
    host: HOST,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Via {
    /// Astation's local link (`ASTATION_WS`).
    Local,
    /// The relay, routed on the host's route proof, no Astation (§R9.7b).
    Routed,
}

struct Rig {
    sandbox: Sandbox,
    astation: FakeAstation,
    relay_events: Option<mpsc::Receiver<RelayEvent>>,
    log: TestLog,
    station: Arc<Mutex<FakeStation>>,
    pump: Mutex<Option<Pump>>,
    clock: HostClock,
    runtime: Option<Child>,
    link: Cell<u64>,
    via: Via,
    delegated: bool,
    /// `host.senders` too (with `delegated`).
    senders: bool,
    relay_url: String,
    fake: PathBuf,
}

impl HostRig for Rig {
    fn config_dir(&self) -> PathBuf {
        self.sandbox.config()
    }

    fn fake_dir(&self) -> PathBuf {
        self.fake.clone()
    }
}

impl Rig {
    /// A verified host whose pinned list is the Mac, this host, the phone
    /// and [`SVC`]; `delegated`: the `host.delegated` hook on.
    fn start(via: Via, delegated: bool) -> Rig {
        Rig::start_with(via, delegated, false)
    }

    /// [`Rig::start`]; `senders`: `host.senders` on too (the Station's
    /// heads carry the host's mailbox).
    fn start_with(via: Via, delegated: bool, senders: bool) -> Rig {
        let sandbox = Sandbox::new();
        write_verified_pairing(&sandbox.config(), ACCOUNT, HOST, 1);
        let host_seed = secret("suspended host");
        let mut log = TestLog::genesis(ACCOUNT, &secret("suspended astation"));
        log.add_host(HOST, 1, &host_seed);
        log.add_native(PHONE, &["control", "view"]);
        log.enroll_service(
            SVC,
            &ServiceScope::new([HOST]).ops(SVC_OPS),
            r9log::host_now().wall_ms + 4 * HOUR,
        );
        write_pin(&sandbox.config(), &log, HOST, 1, &host_seed);
        let fake = sandbox.dir.path().join("fake");
        std::fs::create_dir_all(&fake).unwrap();
        let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/approvals/fake-agent.py");
        let env_file = sandbox.dir.path().join("provider.json");
        private(
            &env_file,
            &json!({"CLAUDE_CLI_BIN": bin, "FAKE_DIR": fake}).to_string(),
        );
        let principals = [
            format!("member:{MAC}"),
            format!("member:{PHONE}"),
            format!("service:{SVC}"),
        ];
        private(
            &sandbox.config().join("runtime.toml"),
            &hosting_toml(&sandbox.home, &env_file, &principals),
        );
        let head = log.log.head();
        let head = json!({"seq": head.seq, "hash": head.hash.to_hex()});
        let (astation, relay_events) = match via {
            Via::Local => (FakeAstation::start(), None),
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
            Via::Routed => astation.url.clone(),
        };
        let mut station = FakeStation::new(&astation, &relay_url, &log, HOST, 1);
        station.silence_heads(true);
        station.host_lists_senders(senders);
        let clock = HostClock::start(sandbox.dir.path(), "host-clock");
        let mut rig = Rig {
            sandbox,
            astation,
            relay_events,
            log,
            station: Arc::new(Mutex::new(station)),
            pump: Mutex::new(None),
            clock,
            runtime: None,
            link: Cell::new(0),
            via,
            delegated,
            senders,
            relay_url,
            fake,
        };
        rig.runtime = Some(rig.spawn());
        rig.link.set(rig.next_link(0));
        rig
    }

    fn spawn(&self) -> Child {
        let output = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.sandbox.dir.path().join("runtime.log"))
            .unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_atem"));
        command.env_clear();
        if self.delegated {
            let features = if self.senders {
                "host.delegated,host.senders"
            } else {
                "host.delegated"
            };
            command.env("ATEM_TEST_HOST_FEATURES", features);
        }
        let local = match self.via {
            Via::Local => self.astation.url.clone(),
            Via::Routed => "ws://127.0.0.1:1/ws".into(),
        };
        let faults = self.sandbox.dir.path().join("faults");
        std::fs::create_dir_all(&faults).unwrap();
        command
            .arg("runtime")
            .env("ATEM_TEST_PTY_FAULTS", faults)
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.sandbox.home)
            .env("XDG_RUNTIME_DIR", &self.sandbox.run)
            .env("ASTATION_WS", local)
            .env("ASTATION_RELAY_URL", &self.relay_url)
            .env("ATEM_TEST_STATE_DUMP", self.dump_file())
            .env("ATEM_TEST_HOST_CLOCK", &self.clock.path)
            .env("ATEM_TEST_NO_INIT_LIMIT", "1")
            .stdin(Stdio::null())
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .spawn()
            .unwrap()
    }

    /// The runtime's next link after `after`: the one Astation
    /// authenticated (local), or the one the relay took the proof of
    /// (routed; refused or not).
    fn next_link(&self, after: u64) -> u64 {
        let deadline = Instant::now() + WAIT;
        let left = || deadline.saturating_duration_since(Instant::now());
        match self.via {
            Via::Local => loop {
                match self.astation.events.recv_timeout(left()) {
                    Ok(support::astation::Event::Authenticated(link)) if link > after => {
                        break link;
                    }
                    Ok(_) if !left().is_zero() => {}
                    _ => panic!("the runtime's link never authenticated"),
                }
            },
            Via::Routed => loop {
                match self.relay_events.as_ref().unwrap().recv_timeout(left()) {
                    Ok(RelayEvent::Proof { link, .. }) if link > after => break link,
                    Ok(_) if !left().is_zero() => {}
                    _ => panic!("no route proof\n{}", self.runtime_log()),
                }
            },
        }
    }

    /// The relay's next event within `wait`.
    fn relay_event(&self, wait: Duration) -> Option<RelayEvent> {
        self.relay_events.as_ref().unwrap().recv_timeout(wait).ok()
    }

    fn link(&self) -> u64 {
        self.link.get()
    }

    fn origin(&self) -> String {
        self.relay_url.clone()
    }

    fn runtime_log(&self) -> String {
        std::fs::read_to_string(self.sandbox.dir.path().join("runtime.log")).unwrap_or_default()
    }

    fn dump_file(&self) -> PathBuf {
        self.sandbox.dir.path().join("state.json")
    }

    fn dump(&self) -> Value {
        std::fs::read(self.dump_file())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(Value::Null)
    }

    #[track_caller]
    fn within(&self, what: &str, mut done: impl FnMut() -> bool) {
        let deadline = Instant::now() + WAIT;
        while !done() {
            if Instant::now() >= deadline {
                let log = self.runtime_log();
                let tail: Vec<_> = log.lines().rev().take(30).collect();
                panic!(
                    "timed out waiting for {what}\nstation: {}\nlog (newest first):\n{}",
                    self.dump()["station"],
                    tail.join("\n")
                );
            }
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn station(&self) -> MutexGuard<'_, FakeStation> {
        self.station.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn gate_open(&self) -> bool {
        let station = self.dump()["station"].clone();
        station["feed"]["open"] == true && station["list_part"] == true
    }

    /// The Station online on its own ([`Pump`]); waits until the gate is
    /// open.
    fn online(&self) {
        self.station().silence_heads(false);
        *self.pump.lock().unwrap() = Some(Pump::start(self.station.clone()));
        self.within("the host's own Station's gate", || self.gate_open());
    }

    /// A record of the Station's about `service`, at the feed's next
    /// position: its id.
    fn append(&self, service: &str, action: ControlAction) -> String {
        let mut station = self.station();
        let record = station.record_for(service, action);
        let id = atem_client::control::ControlRecord::from_signed(record.clone())
            .unwrap()
            .record_id()
            .to_owned();
        station.append(record);
        id
    }

    /// How many of the host's acks the Station read carry a result for
    /// `record_id`.
    fn acks_naming(&self, record_id: &str) -> usize {
        self.station()
            .acks_sent()
            .iter()
            .filter(|ack| names(ack, record_id))
            .count()
    }

    /// `atem status`'s value of `label`, once it starts with `expected`
    /// (the runtime's look is passive and may lag a pass).
    #[track_caller]
    fn status_line(&self, label: &str, expected: &str) -> String {
        let deadline = Instant::now() + WAIT;
        loop {
            let (out, err, _) = self.sandbox.atem(&["status"]);
            let line = out
                .lines()
                .find_map(|l| l.strip_prefix(label))
                .map(|v| v.trim().to_string())
                .unwrap_or_else(|| format!("(no line) {out}{err}"));
            if line.starts_with(expected) {
                return line;
            }
            assert!(
                Instant::now() < deadline,
                "{label} never started with {expected:?}: {line}\n{out}"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn status(&self) -> String {
        self.sandbox.atem(&["status"]).0
    }

    /// `atem status`'s value of `label` now.
    fn status_value(&self, label: &str) -> String {
        self.status()
            .lines()
            .find_map(|l| l.strip_prefix(label))
            .map(|v| v.trim().to_string())
            .unwrap_or_default()
    }

    /// The host-work store.
    fn db(&self) -> rusqlite::Connection {
        support::delegated::host_db(self)
    }

    /// Everything of the host's trust and state that a suspension must
    /// never move (III.5): the state dump's identity and device list (its
    /// head, standing, members, control generations, recovery key), the
    /// pinned device list file and its carriage, intent, freeze and fault
    /// files, the frozen genesis and the revoked grants' floor, the
    /// journal's device-list files, the host trust generation and its
    /// floor, the host's `host_channel_key`, the pairing record, the
    /// session journal's principals; with the hook, the control parts, the
    /// feeds' cursors and the reset marks; with `host.senders`, the host
    /// encryption key and its record, the mailbox's cursor and owed dones
    /// and the outbox rows (their tables checked to exist); the session
    /// journal's refusal list, lease-epoch floors and runtime epoch. (The
    /// acknowledgments' book is reset in memory by design: its rows go
    /// again.)
    fn kept(&self) -> Value {
        let config = self.sandbox.config();
        let read = |path: &Path| std::fs::read(path).ok().map(hex);
        let rows = |sql: &str| -> Vec<Vec<String>> {
            let db = self.db();
            let Ok(mut q) = db.prepare(sql) else {
                return Vec::new();
            };
            let n = q.column_count();
            q.query_map([], |r| {
                (0..n)
                    .map(|i| {
                        r.get_ref(i).map(|v| match v {
                            rusqlite::types::ValueRef::Null => "null".to_string(),
                            rusqlite::types::ValueRef::Integer(i) => i.to_string(),
                            rusqlite::types::ValueRef::Real(f) => f.to_string(),
                            rusqlite::types::ValueRef::Text(t) => {
                                String::from_utf8_lossy(t).into_owned()
                            }
                            rusqlite::types::ValueRef::Blob(b) => hex(b.to_vec()),
                        })
                    })
                    .collect()
            })
            .unwrap()
            .map(Result::unwrap)
            .collect()
        };
        // With `host.senders` its tables and key exist: a typo in a table's
        // name would compare nothing.
        if self.senders {
            let db = self.db();
            for table in [
                "mailbox_cursor",
                "mailbox_dones",
                "mail_outbox",
                "remote_deliveries",
            ] {
                let found: i64 = db
                    .query_row(
                        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?1",
                        [table],
                        |r| r.get(0),
                    )
                    .unwrap();
                assert_eq!(found, 1, "{table}");
            }
            assert!(config.join("pairing/host_enc_key").exists());
        }
        let dump = self.dump();
        let membership_files: Vec<Option<String>> = [
            "pairing/membership.carriage",
            "pairing/membership.intent",
            "pairing/membership.freeze",
            "pairing/membership.fault",
            "pairing/frozen_genesis",
            "pairing/revoked_floor",
            "runtime/journal/membership_applied",
            "runtime/journal/membership_deferred",
            "runtime/journal/membership_fault",
            "runtime/journal/frozen_genesis",
            // The host encryption key and its record (`host.senders`).
            "pairing/host_enc_key",
            "pairing/host_enc_generated",
            // The session journal beyond its principals.
            "runtime/journal/refused",
            "runtime/journal/floors",
            "runtime/journal/runtime_epoch",
        ]
        .iter()
        .map(|f| read(&config.join(f)))
        .collect();
        json!({
            // The state dump's (ATEM_TEST_STATE_DUMP): the host's identity
            // and trust generation, the device list's head, applied head,
            // standing, members, principals' control generations, keys.
            "dump_host": dump["host"],
            "dump_membership": dump["membership"],
            "membership": read(&config.join("pairing/membership.json")),
            "membership_files": membership_files,
            "trust_gen": read(&config.join("pairing/trust_gen")),
            "trust_gen_floor": read(&config.join("cred/trust_gen_floor")),
            "host_channel_key": read(&config.join("pairing/host_channel_key")),
            "pairing": read(&config.join("pairing/pairing.enc")),
            "principals": read(&config.join("runtime/journal/principals")),
            "control_principals": rows("SELECT principal, part FROM control_principals ORDER BY principal"),
            "control_feeds": rows("SELECT * FROM control_feeds"),
            "control_resets": rows("SELECT * FROM control_resets"),
            "control_unread": rows("SELECT * FROM control_unread"),
            "mailbox_cursor": rows("SELECT * FROM mailbox_cursor"),
            "mailbox_dones": rows("SELECT * FROM mailbox_dones"),
            "mail_outbox": rows("SELECT * FROM mail_outbox"),
            "remote_deliveries": rows("SELECT * FROM remote_deliveries"),
        })
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        drop(self.pump.get_mut().unwrap().take());
        self.sandbox.track();
        if let Some(mut child) = self.runtime.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// A file's or a value's SHA-256, hex (short in a failure's output).
fn hex(bytes: Vec<u8>) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Whether `ack` carries a result for `record_id`.
fn names(ack: &ControlAck, record_id: &str) -> bool {
    ack.results
        .iter()
        .any(|r| matches!(r, AckResult::Record { record_id: id, .. } if id == record_id))
}

/// III.5 on a routed host with `host.delegated` (B-1, B-2, B-3 and the
/// re-enabling): the Station closes the service's channel, sends the open
/// link's notice and closes the link (the channel is gone either way). The host's gate closes at once (the
/// running turn goes on, nothing is cancelled), the next connect waits the
/// usual 30 s (never at once) and is refused at its proof, its status
/// shows the text on both lines, one runtime.log line in all, and nothing
/// of its trust or state moves. A task queued behind the turn then waits
/// behind the closed gate. Restored, the next connect is routed, the feed
/// is read on from its cursor (never from 0), the gate opens and the task
/// runs, and the cover's acknowledgment, sent on the suspended connection,
/// is sent again exactly once.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_HOST_CLOCK and ATEM_TEST_STATE_DUMP hooks"
)]
fn a_suspended_routed_host_keeps_its_state_retries_and_resumes_once_restored() {
    let rig = Rig::start(Via::Routed, true);
    let mut r = Router::on(&rig.astation, rig.link());
    let cover = rig.append(SVC, ControlAction::Cover);
    rig.online();
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    let first = task(IDS, &launch, "SUSPENDED_FIRST", HOUR);
    let second = task(IDS, &launch, "SUSPENDED_SECOND", HOUR);
    for t in [&first, &second] {
        enqueue(&mut svc, &mut r, t);
    }
    in_turn(&rig, &first["task_id"], "SUSPENDED_FIRST");
    wait_stored(&rig, &second["task_id"], "blocked", BEHIND);
    rig.within("the cover's ack", || rig.acks_naming(&cover) == 1);
    let cursor = rig.dump()["station"]["feed"]["synced"]["cursor"].clone();
    let kept = rig.kept();
    let old = rig.link();

    // B-3, B-2 and the close.
    let suspended_at = Instant::now();
    rig.station().suspend(TEXT, &[svc.handle()]);
    rig.within("the gate closed", || {
        let station = rig.dump()["station"].clone();
        station["feed"]["suspensions"] == 1 && station["feed"]["open"] == false
    });
    rig.status_line("Relay:", &format!("not connected ({SHOWN}; retrying)"));
    rig.status_line(
        "Control feeds:",
        &format!("{GATE_CLOSED} ({}: {SHOWN}; retrying)", rig.origin()),
    );
    // The running turn goes on; nothing was cancelled.
    assert_eq!(stored(&rig, &first["task_id"])["state"], "submitted");
    assert_eq!(stored(&rig, &second["task_id"])["state"], "blocked");
    // The service's channel is gone (its router close, or the link's loss
    // right after it: a_router_close_for_a_suspended_service_fences_only_its_channel).
    rig.within("the channels closed", || rig.dump()["channels"] == 0);

    // The next connect: after the usual 30 s, refused at its proof.
    let refused = rig.next_link(old);
    assert!(
        suspended_at.elapsed() >= RETRY - Duration::from_secs(1),
        "reconnected after {:?}",
        suspended_at.elapsed()
    );
    rig.within("the refused connection closed", || {
        matches!(rig.relay_event(Duration::from_millis(100)), Some(RelayEvent::Closed(n)) if n == refused)
    });
    rig.status_line("Relay:", &format!("not connected ({SHOWN}; retrying)"));
    assert!(
        rig.status()
            .contains("Authorization:  not authorized (Astation not connected)")
    );
    assert_eq!(rig.kept(), kept, "no trust or state change");
    let log = rig.runtime_log();
    assert_eq!(
        log.matches(&format!("relay: {SHOWN}; retrying")).count(),
        1,
        "one line per text an hour\n{log}"
    );
    for never in [
        "reconnecting, so the link is authenticated",
        "relay link reconnecting to prove its route",
    ] {
        assert!(!log.contains(never), "{never}\n{log}");
    }

    // The turn ends: the next task waits behind the closed gate.
    complete_turn(&rig, &first["task_id"]);
    wait_stored(&rig, &second["task_id"], "blocked", GATE_CLOSED);
    never_ran(&rig, &second["task_id"], "SUSPENDED_SECOND");

    // Service returns: routed on the next attempt, the gate's full sync.
    rig.station().restore();
    let link = rig.next_link(refused);
    rig.link.set(link);
    rig.within("the routed link", || {
        rig.dump()["station"]["link"]["kind"] == "routed"
    });
    rig.within("the gate open again", || rig.gate_open());
    in_turn(&rig, &second["task_id"], "SUSPENDED_SECOND");
    let relay = rig.status_line("Relay:", "routed via relay");
    assert!(!relay.contains("suspended"), "{relay}");
    rig.status_line("Control feeds:", "revocations checked");
    assert_eq!(rig.dump()["station"]["feed"]["synced"]["cursor"], cursor);
    let after_restore: Vec<ToStation> = rig
        .station()
        .sent_on(link)
        .iter()
        .filter_map(|b| ToStation::decode(b.as_bytes()).ok())
        .collect();
    assert!(
        after_restore
            .iter()
            .all(|c| !matches!(c, ToStation::ControlSync(s) if s.after == 0)),
        "never read from 0 again: {after_restore:?}"
    );
    // The cover's ack, sent on the suspended connection: once more.
    rig.within("the cover's ack again", || rig.acks_naming(&cover) == 2);
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(rig.acks_naming(&cover), 2, "exactly once");
    complete_turn(&rig, &second["task_id"]);
}

/// III.5 with the hook off (a release build's reading; run by release
/// builds too, where the state dump reads as nothing): a routed host's
/// open link gets the notice and the Station leaves the link open. The
/// host drops it 10 s later (not before), the next connect waits the usual
/// 30 s and is refused at its proof; the Relay line shows the text, there
/// is no Control feeds line, and the host makes no Station call. Restored,
/// the next connect is routed and the text is gone.
#[test]
fn with_the_hook_off_the_host_shows_the_text_drops_the_link_after_10_s_and_retries() {
    let rig = Rig::start(Via::Routed, false);
    rig.status_line("Relay:", "routed via relay");
    let kept = rig.kept();
    let old = rig.link();
    let suspended_at = Instant::now();
    rig.station().suspend_leaving_the_link(TEXT);
    // The link still up: the text inside its parentheses.
    rig.within("the routed line's text", || {
        let relay = rig.status_value("Relay:");
        relay.starts_with("routed via relay (")
            && relay.ends_with(&format!("; no Astation; {SHOWN})"))
    });
    // Dropped by the host, 10 s after the notice.
    rig.within("the host dropped the link", || {
        matches!(rig.relay_event(Duration::from_millis(100)), Some(RelayEvent::Closed(n)) if n == old)
    });
    let dropped = suspended_at.elapsed();
    assert!(
        dropped >= Duration::from_secs(9) && dropped < Duration::from_secs(25),
        "dropped after {dropped:?}"
    );
    assert!(
        rig.runtime_log()
            .contains("didn't close this host's link within 10 s of its service_suspended")
    );
    rig.status_line("Relay:", &format!("not connected ({SHOWN}; retrying)"));
    // The next connect: 30 s after the drop, refused at its proof.
    let refused = rig.next_link(old);
    assert!(
        suspended_at.elapsed() >= dropped + RETRY - Duration::from_secs(1),
        "reconnected after {:?}",
        suspended_at.elapsed()
    );
    rig.within("the refused connection closed", || {
        matches!(rig.relay_event(Duration::from_millis(100)), Some(RelayEvent::Closed(n)) if n == refused)
    });
    rig.status_line("Relay:", &format!("not connected ({SHOWN}; retrying)"));
    let status = rig.status();
    assert!(!status.contains("Control feeds:"), "{status}");
    assert!(
        rig.station().sent().is_empty(),
        "no Station call with the hook off"
    );
    assert_eq!(rig.kept(), kept, "no trust or state change");
    rig.station().restore();
    let link = rig.next_link(refused);
    rig.link.set(link);
    let relay = rig.status_line("Relay:", "routed via relay");
    assert!(!relay.contains("suspended"), "{relay}");
}

/// B-3 (R9.7a's router reasons): the router's `close` of one channel
/// with `service_suspended` fences only that channel's attachment, with a
/// runtime.log line naming the reason; the other channel, the link and the
/// host's state stay.
#[test]
fn a_router_close_for_a_suspended_service_fences_only_its_channel() {
    let rig = Rig::start(Via::Routed, false);
    let mut r = Router::on(&rig.astation, rig.link());
    let phone = Identity::native(PHONE, auth(PHONE));
    let mut ph = r.connect("ph-1", &rig.log, HOST, &phone).unwrap();
    std::thread::sleep(Duration::from_millis(1_100));
    let mac = Identity::native(MAC, auth(MAC));
    let mut mac_channel = r.connect("mac-1", &rig.log, HOST, &mac).unwrap();
    let kept = rig.kept();
    r.send_raw(
        json!({"type": "channel", "event": "close", "channel": "ph-1",
               "reason": "service_suspended"})
        .to_string(),
    );
    rig.within("the close logged", || {
        rig.runtime_log()
            .contains("the router closed a channel (service_suspended)")
    });
    // The other channel works; the closed one is unknown now.
    assert!(r.list("mac-1", &mut mac_channel).is_empty());
    let (_, frame) = ph.list(support::r9::client_ms()).unwrap();
    r.frame("ph-1", &frame);
    match r.next("ph-1") {
        Out::Close(reason) => assert_eq!(reason.as_deref(), Some("unknown_channel")),
        Out::Frame(_) => panic!("the closed channel answered"),
    }
    assert!(
        rig.relay_event(Duration::from_millis(500)).is_none(),
        "the link stays"
    );
    assert_eq!(rig.kept(), kept);
}

/// III.5 on Astation's local link with `host.delegated` and
/// `host.senders`: the Station's notice there keeps the link (no
/// reconnect), the gate closes as for a refusal of every call kind (the
/// acks on that connection and the mailbox's dones held), both status lines
/// show the text, and nothing of the host's state moves. The suspended
/// Station keeps announcing its heads and refuses the calls the host asks
/// past the backoff; the holds stay. Restored, the host asks again after
/// the backoff on its clock, the gate opens, the text is gone and the holds
/// end: the held ack goes once on the same link, the dones may go.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_HOST_CLOCK and ATEM_TEST_STATE_DUMP hooks"
)]
fn on_the_local_link_a_suspension_keeps_the_link() {
    let rig = Rig::start_with(Via::Local, true, true);
    let cover = rig.append(SVC, ControlAction::Cover);
    rig.online();
    rig.status_line("Relay:", "connected locally");
    rig.within("the cover's ack", || rig.acks_naming(&cover) == 1);
    let mailbox = |rig: &Rig| rig.dump()["station"]["mailbox"].clone();
    rig.within("the mailbox read", || mailbox(&rig)["open"] == true);
    let kept = rig.kept();
    rig.station().suspend(TEXT, &[]);
    rig.within("the gate closed", || {
        rig.dump()["station"]["feed"]["suspensions"] == 1 && !rig.gate_open()
    });
    // As a refusal of every call kind: the acks and the dones held.
    assert_eq!(rig.dump()["station"]["acks"]["held"], true);
    assert_eq!(mailbox(&rig)["dones_refused"], true);
    // The suspended Station still announces its heads and refuses each
    // call (review N1): past the backoff the host asks again, and its
    // control sync and mailbox sync are refused; the holds stay.
    rig.clock.add_mono(31_000);
    rig.within("calls refused while suspended", || {
        let station = rig.dump()["station"].clone();
        station["refusals"]["control_sync"].as_u64() >= Some(1)
            && station["mailbox"]["refusals"].as_u64() >= Some(1)
    });
    assert_eq!(rig.dump()["station"]["acks"]["held"], true);
    assert_eq!(mailbox(&rig)["dones_refused"], true);
    assert_eq!(rig.acks_naming(&cover), 1);
    rig.status_line("Relay:", &format!("connected locally ({SHOWN})"));
    rig.status_line(
        "Control feeds:",
        &format!("{GATE_CLOSED} ({NO_RELAY}: {SHOWN}; retrying)"),
    );
    // The link stays: no new authentication.
    std::thread::sleep(Duration::from_secs(2));
    while let Ok(event) = rig.astation.events.try_recv() {
        assert!(
            !matches!(event, support::astation::Event::Authenticated(_)),
            "the local link reconnected"
        );
    }
    assert_eq!(rig.dump()["station"]["link"]["kind"], "local");
    // Astation's link refreshes its saved session's activity in the
    // pairing record; nothing of the trust or the control state moves.
    let without_pairing = |mut v: Value| {
        v["pairing"] = Value::Null;
        v
    };
    assert_eq!(without_pairing(rig.kept()), without_pairing(kept));
    rig.station().restore();
    // The refusal's backoff on the host's clock, then the full sync.
    rig.clock.add_mono(31_000);
    rig.within("the gate open again", || rig.gate_open());
    // The text is lifted with the Station serving the link again.
    rig.within("the text lifted", || {
        rig.status_value("Relay:") == "connected locally"
    });
    rig.status_line("Control feeds:", "revocations checked");
    // Review M2: the holds end with the Station serving the link again:
    // the cover's ack, sent on the suspended connection, goes again on the
    // same local link, once, and the mailbox's dones may go.
    rig.within("the cover's ack again", || rig.acks_naming(&cover) == 2);
    rig.within("the dones' hold ended", || {
        mailbox(&rig)["dones_refused"] == false
    });
    assert_eq!(rig.dump()["station"]["acks"]["held"], false);
    std::thread::sleep(Duration::from_secs(2));
    assert_eq!(rig.acks_naming(&cover), 2, "exactly once");
}

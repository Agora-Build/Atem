//! The host's Station calls in the real runtime (host-work-v1 §11.4; the
//! delegated host-work design I.5.2, I.5.8, I.6.5; session-v1 R9.3): its
//! own device-list fetch and the sync of its own Station's control feed
//! over its one link, and the revocation gate they open, against the fake
//! Station (tests/support/station.rs), behind the debug-only
//! `host.delegated` hook (step 4's Decision 11). A temp profile with a
//! pinned device list and agent hosting on (`runtime.toml`: a profile and a
//! route for the Mac, the phone and the service, the fake Claude); the
//! fake Astation as the local link, or as the relay with Astation in the
//! room or routing the link on its host route proof (§R9.7b); encrypted r9
//! clients through `atem-client`; the host's state read from the debug
//! state dump, its store and `atem status`; its clocks moved on the debug
//! host clock, never by waiting. The fake Station answers only when a test
//! says (its own `heads` silenced), so every call and page is the test's,
//! unless the test puts it online as a Station is ([`Rig::online`]).
#![cfg(target_os = "linux")]
mod support;

use atem_client::connect::{Event as ClientEvent, Identity};
use atem_client::control::relay::MAX_RELAY_MESSAGE_BYTES;
use atem_client::control::{
    CallRefused, ControlAction, ControlSync, ControlSyncResult, FeedEntry, MembershipFetch,
    MembershipFetchResult, RefusalCode, RefusedCall, RelayError, ToStation,
};
use atem_client::membership::ServiceScope;
use serde_json::{Value, json};
use std::cell::Cell;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, MutexGuard, mpsc};
use std::time::{Duration, Instant};
use support::astation::{
    ASTATION, AuthReply, Event, FakeAstation, RelayEvent, Reply, write_verified_pairing,
};
use support::delegated::WAIT;
use support::delegated::{
    Dev, HostIds, HostRig, complete_turn, enqueue, enqueue_data, host_db, hosting_toml, in_turn,
    never_ran, private, record, replace, stored, task, uuid, wait_stored,
};
use support::host_clock::HostClock;
use support::r9::{Router, write_pin};
use support::r9log::{self, MAC, TestLog, auth, secret};
use support::station::{FakeStation, Held, OTHER_ACCOUNT, Pump, StaleFeed};
use support::{Sandbox, within};

const ACCOUNT: &str = "acct-control-feed";
const HOST: &str = "host-control-feed";
const PHONE: &str = "dev-phone";
/// The service the tests launch sessions with; delegated only while the
/// fake Station's feed covers it.
const SVC: &str = "svc-work";
/// The local link's relay setting (refused: the link is Astation's
/// `:8080`); the selected Station's origin is this, normalized.
const NO_RELAY: &str = "http://127.0.0.1:1";
const MIN: u64 = 60_000;
const HOUR: u64 = 60 * MIN;
/// What a delegated task waits with while its sender's gate is closed.
const GATE_CLOSED: &str = "revocations not yet checked";
const BEHIND: &str = "waiting for an earlier task on this session";
/// What a held sender's task waits with (§11.6 "Details").
const PAUSED: &str = "paused";
const REVOKED: &str = "sender revoked";
/// The feed part's reasons, as `atem status` gives them (`sync::Closed`).
const REFUSED: &str = "Station refused feed access (forbidden); retrying";
const RESET: &str = "the control feed was reset; reading it again from position 0";
const UNANSWERED: &str =
    "a control_sync went unanswered for 30 s; asked again with a new request id";
const CLOCK_AHEAD: &str = "Station clock ahead of this host";
const NO_HEADS_60S: &str = "no heads from the Station for 60 s";
/// The Station faults' reasons (`sync::fault_text`).
const MALFORMED: &str = "Station sent a page the reader refused (malformed)";
const OTHER_AFTER: &str =
    "Station sent a page that doesn't answer its call (another position asked after)";
const OTHER_FEED: &str = "Station sent a page that doesn't answer its call (another feed)";
const OTHER_ORIGIN: &str = "Station sent a page that doesn't answer its call (another origin)";
const UNSOLICITED: &str = "Station sent a page for a call this host never made";
/// The stored control state that doesn't read (`HostBridge::feeds_status`).
const DAMAGED: &str = "the stored control state doesn't read; no delegated task starts. Restore ";
/// The host the clients name.
const IDS: HostIds = HostIds {
    account: ACCOUNT,
    host: HOST,
};

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
    relay_events: Option<mpsc::Receiver<RelayEvent>>,
    /// The account's device list: pinned at the start, then grown where the
    /// Station has more.
    log: TestLog,
    station: Arc<Mutex<FakeStation>>,
    /// The Station online on its own ([`Rig::online`]).
    pump: Mutex<Option<Pump>>,
    clock: HostClock,
    runtime: Option<Child>,
    /// The host's link (the fake's connection number), the newest.
    link: Cell<u64>,
    via: Via,
    delegated: bool,
    /// The runtime's relay setting: the host's own Station's origin.
    relay_url: String,
    /// The fake agent's directory.
    fake: PathBuf,
}

impl Rig {
    /// A verified host whose pinned list is the Mac, this host and (with
    /// `phone`) a native member; `delegated`: the `host.delegated` hook on.
    /// The fake Station holds the same list until the test grows it.
    fn start(via: Via, delegated: bool, phone: bool) -> Rig {
        Rig::with(via, delegated, phone, false)
    }

    /// [`Rig::start`] with `host.delegated` on, the phone and [`SVC`]
    /// (`launch`, `message`, `notify`, `prompt`, `view`, for four hours).
    fn full(via: Via) -> Rig {
        Rig::with(via, true, true, true)
    }

    fn with(via: Via, delegated: bool, phone: bool, service: bool) -> Rig {
        let sandbox = Sandbox::new();
        write_verified_pairing(&sandbox.config(), ACCOUNT, HOST, 1);
        let host_seed = secret("control feed host");
        let mut log = TestLog::genesis(ACCOUNT, &secret("control feed astation"));
        log.add_host(HOST, 1, &host_seed);
        if phone {
            log.add_native(PHONE, &["control", "view"]);
        }
        if service {
            log.enroll_service(
                SVC,
                &ServiceScope::new([HOST]).ops(["launch", "message", "notify", "prompt", "view"]),
                r9log::host_now().wall_ms + 4 * HOUR,
            );
        }
        write_pin(&sandbox.config(), &log, HOST, 1, &host_seed);
        // Agent hosting on: the feeds load and sync only with it.
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
        // (30 s, on the real clock) would ask for the host.
        let mut station = FakeStation::new(&astation, &relay_url, &log, HOST, 1);
        station.silence_heads(true);
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
            relay_url,
            fake,
        };
        rig.runtime = Some(rig.spawn());
        rig.link.set(rig.next_link(0));
        rig
    }

    /// `atem runtime` with the rig's hooks, its output appended to
    /// `runtime.log`.
    fn spawn(&self) -> Child {
        let output = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.sandbox.dir.path().join("runtime.log"))
            .unwrap();
        let mut command = Command::new(env!("CARGO_BIN_EXE_atem"));
        command.env_clear();
        if self.delegated {
            command.env("ATEM_TEST_HOST_FEATURES", "host.delegated");
        }
        let local = match self.via {
            Via::Local => self.astation.url.clone(),
            Via::Relay | Via::Routed => "ws://127.0.0.1:1/ws".into(),
        };
        // A killed runtime's socket file and state dump aren't the new one's.
        let _ = std::fs::remove_file(self.sandbox.config().join("runtime.socket"));
        let _ = std::fs::remove_file(self.dump_file());
        command
            .arg("runtime")
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

    /// The runtime's next link after `after` (a connection number): the
    /// one Astation authenticated, or the one the relay routed.
    fn next_link(&self, after: u64) -> u64 {
        match self.via {
            Via::Local | Via::Relay => loop {
                match self.astation.events.recv_timeout(WAIT) {
                    Ok(Event::Authenticated(link)) if link > after => break link,
                    Ok(_) => {}
                    Err(_) => panic!("the runtime's link never authenticated"),
                }
            },
            Via::Routed => loop {
                match self.relay_events.as_ref().unwrap().recv_timeout(WAIT) {
                    Ok(RelayEvent::Proof { link, .. }) if link > after => break link,
                    Ok(_) => {}
                    Err(_) => panic!("no route proof"),
                }
            },
        }
    }

    /// The runtime is killed (`SIGKILL`); its workers live on.
    fn kill(&mut self) {
        self.sandbox.track();
        let mut child = self.runtime.take().expect("a runtime");
        child.kill().unwrap();
        child.wait().unwrap();
    }

    /// A runtime again (after [`Rig::kill`]), on a new link.
    fn start_again(&mut self) {
        self.runtime = Some(self.spawn());
        let link = self.next_link(self.link.get());
        self.link.set(link);
    }

    fn link(&self) -> u64 {
        self.link.get()
    }

    /// The host's own Station's origin (exact, as normalized).
    fn origin(&self) -> String {
        self.relay_url.clone()
    }

    fn runtime_log(&self) -> String {
        std::fs::read_to_string(self.sandbox.dir.path().join("runtime.log")).unwrap_or_default()
    }

    /// The pinned device list's head `seq`, as written.
    fn head(&self) -> u64 {
        list_head(&self.sandbox.config())
    }

    fn dump_file(&self) -> PathBuf {
        self.sandbox.dir.path().join("state.json")
    }

    /// The host's state after its last pass (the debug state dump).
    fn dump(&self) -> Value {
        std::fs::read(self.dump_file())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(Value::Null)
    }

    /// Waits up to a minute for `done`; a timeout shows the host's Station
    /// state and the end of its log.
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

    /// Waits for the host's Station state to satisfy `done`.
    #[track_caller]
    fn until_station(&self, what: &str, done: impl Fn(&Value) -> bool) -> Value {
        let mut last = Value::Null;
        self.within(what, || {
            last = self.dump()["station"].clone();
            done(&last)
        });
        last
    }

    /// The feed sync's part of the Station state (`FeedSync::dump`).
    fn feed(&self) -> Value {
        self.dump()["station"]["feed"].clone()
    }

    /// Waits for the feed sync's state to satisfy `done`.
    #[track_caller]
    fn until_feed(&self, what: &str, done: impl Fn(&Value) -> bool) -> Value {
        self.until_station(what, |s| done(&s["feed"]))["feed"].clone()
    }

    /// The feed read so far: its cursor, if the host read the announced
    /// feed (or any).
    fn cursor(&self) -> Option<u64> {
        self.feed()["synced"]["cursor"].as_u64()
    }

    /// The host's own Station's gate: its feed part and its device-list
    /// part (design I.5.8).
    fn gate_open(&self) -> bool {
        let station = self.dump()["station"].clone();
        station["feed"]["open"] == true && station["list_part"] == true
    }

    /// Waits for two passes of the broker begun after now.
    fn two_passes(&self) {
        let pass = |rig: &Rig| rig.dump()["pass"].as_u64().unwrap_or(0);
        let now = pass(self);
        within("two passes", || pass(self) >= now + 2);
    }

    fn station(&self) -> MutexGuard<'_, FakeStation> {
        self.station.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The Station answers what the host asked so far, then announces its
    /// heads on the host's link now.
    fn announce(&self) {
        let mut station = self.station();
        station.serve(self.link());
        station.heads_now();
    }

    /// The Station serves the host's link until `done`.
    #[track_caller]
    fn serve_until(&self, what: &str, done: impl Fn(&Rig) -> bool) {
        self.within(what, || {
            self.station().serve(self.link());
            done(self)
        });
    }

    /// The Station serves the link until the host's list reaches `seq`.
    #[track_caller]
    fn serve_until_head(&self, seq: u64) {
        self.serve_until(&format!("the host's list at {seq}"), |rig| {
            rig.head() >= seq
        });
        assert_eq!(self.head(), seq);
    }

    /// The Station announces (a second apart on the host's clock) and
    /// serves until the host's own Station's gate is open: whatever the
    /// host still has to read again (a reset, the start's recovery). Only
    /// for a gate known closed before (a dump from before the `heads` would
    /// show one open already).
    #[track_caller]
    fn open_gate(&self) {
        let deadline = Instant::now() + WAIT;
        loop {
            for _ in 0..10 {
                self.station().serve(self.link());
                if self.gate_open() {
                    return;
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            assert!(
                Instant::now() < deadline,
                "the gate never opened: {}",
                self.dump()["station"]
            );
            self.clock.add_mono(1_000);
            self.announce();
        }
    }

    /// The Station's feed covers [`SVC`] (a `cover` at its next position),
    /// announced and served until the host read it and the gate is open
    /// (the cursor at the cover: a dump from before the `heads` may show
    /// the gate open already).
    fn cover_and_open(&self) {
        let at = self.append(SVC, ControlAction::Cover);
        self.clock.add_mono(1_000);
        self.announce();
        self.serve_until("the cover read", |rig| {
            rig.cursor() == Some(at) && rig.gate_open()
        });
    }

    /// A record of the Station's about `service:<service>`, stored at the
    /// feed's next position (announced only when the test says).
    fn append(&self, service: &str, action: ControlAction) -> u64 {
        let mut station = self.station();
        let record = station.record_for(service, action);
        station.append(record)
    }

    /// The Station online on its own from now on, as a Station is
    /// ([`Pump`]): every call answered at once, `heads` every second and at
    /// once for a stored record; then waits until the gate is open.
    fn online(&self) {
        self.station().silence_heads(false);
        *self.pump.lock().unwrap() = Some(Pump::start(self.station.clone()));
        within("the host's own Station's gate", || self.gate_open());
    }

    /// The host's Station calls so far, as the shared reader reads them.
    fn calls(&self) -> Vec<ToStation> {
        self.station()
            .sent()
            .iter()
            .map(|bytes| ToStation::decode(bytes.as_bytes()).unwrap())
            .collect()
    }

    /// The host's device-list fetches so far (its feed syncs aside).
    fn fetches(&self) -> Vec<ToStation> {
        self.calls()
            .into_iter()
            .filter(|call| matches!(call, ToStation::MembershipFetch(_)))
            .collect()
    }

    /// The host's feed syncs so far, each `request_id` checked (a
    /// lowercase UUID v4, none twice: wire rule 11) and blanked, as
    /// [`Rig::sync`] writes them.
    fn syncs(&self) -> Vec<ControlSync> {
        let syncs: Vec<ControlSync> = self
            .calls()
            .into_iter()
            .filter_map(|call| match call {
                ToStation::ControlSync(sync) => Some(sync),
                _ => None,
            })
            .collect();
        let ids: std::collections::BTreeSet<_> = syncs.iter().map(|s| &s.request_id).collect();
        assert_eq!(ids.len(), syncs.len(), "a fresh id per call: {syncs:?}");
        syncs.into_iter().map(blank).collect()
    }

    /// A `control_sync` of the served feed (as now) after `after`, its
    /// `request_id` blanked ([`blank`]).
    fn sync(&self, after: u64) -> ControlSync {
        ControlSync {
            request_id: String::new(),
            origin: self.origin(),
            feed_id: Some(self.station().feed_id().to_string()),
            after,
        }
    }

    /// `atem status`'s `Control feeds:` line, until it starts with
    /// `expected` (the runtime's look is passive and may lag a pass).
    #[track_caller]
    fn status_feeds(&self, expected: &str) -> String {
        let mut last = String::new();
        within(&format!("Control feeds: {expected}"), || {
            let (out, err, _) = self.sandbox.atem(&["status"]);
            last = out
                .lines()
                .find_map(|l| l.strip_prefix("Control feeds:"))
                .map(|v| v.trim().to_string())
                .unwrap_or_else(|| format!("(no line) {out}{err}"));
            last.starts_with(expected)
        });
        last
    }

    /// `atem status` has no `Control feeds:` line (the hook off: as main).
    fn status_feeds_absent(&self) {
        let (out, err, _) = self.sandbox.atem(&["status"]);
        assert!(out.contains("Local agents:"), "{out}{err}");
        assert!(!out.contains("Control feeds:"), "{out}");
    }

    /// The host-work store (`runtime/host-work.sqlite`).
    fn db(&self) -> rusqlite::Connection {
        host_db(self)
    }

    /// `principal`'s stored control part (`control_principals`).
    fn part(&self, principal: &str) -> Option<String> {
        self.db()
            .query_row(
                "SELECT part FROM control_principals WHERE principal=?1",
                [principal],
                |r| r.get(0),
            )
            .ok()
    }

    /// Writes `part` as `principal`'s stored control part (the runtime
    /// killed).
    fn set_part(&self, principal: &str, part: &str) {
        let n = self
            .db()
            .execute(
                "UPDATE control_principals SET part=?2 WHERE principal=?1",
                [principal, part],
            )
            .unwrap();
        assert_eq!(n, 1, "{principal}'s part");
    }

    /// The reset marks (`control_resets`: origin, the feed whose read from
    /// 0 began, "" before).
    fn reset_marks(&self) -> Vec<(String, String)> {
        let db = self.db();
        let Ok(mut q) = db.prepare("SELECT origin, restarted FROM control_resets") else {
            return Vec::new();
        };
        q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    /// The reasons of the records kept as evidence, in order.
    fn evidence(&self) -> Vec<String> {
        let db = self.db();
        let Ok(mut q) = db.prepare("SELECT reason FROM control_evidence ORDER BY n") else {
            return Vec::new();
        };
        q.query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect()
    }

    /// The delegated clock's floor as stored (the `clock` record's).
    fn floor(&self) -> Value {
        let state: String = self
            .db()
            .query_row("SELECT state FROM clock WHERE id=1", [], |r| r.get(0))
            .unwrap();
        serde_json::from_str::<Value>(&state).unwrap()["floor"].clone()
    }

    /// The stored floor as what it predicts less the boot-time counter
    /// (ns): a Station time that raises it moves this up; the time passing
    /// leaves it, and a follow-down moves it down (written whenever the
    /// clock next writes its record, so a stored floor may change with no
    /// new Station time: only "never up" says it didn't advance).
    fn floor_offset(&self) -> i128 {
        let floor = self.floor();
        let value = i128::from(floor["value_ms"].as_u64().expect("a floor")) * 1_000_000;
        value - i128::from(floor["boot_ns"].as_u64().expect("a floor"))
    }

    /// What no refusal may move (§11.4 "Refusals"): the feed's cursor, the
    /// device list, the control state, its evidence and reset marks (the
    /// clock floor: [`Rig::floor_offset`]).
    fn unmoved(&self) -> Unmoved {
        let pinned: Value = serde_json::from_slice(
            &std::fs::read(self.sandbox.config().join("pairing/membership.json")).unwrap(),
        )
        .unwrap();
        let db = self.db();
        let mut q = db
            .prepare("SELECT principal, part FROM control_principals ORDER BY principal")
            .unwrap();
        let parts = q
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        Unmoved {
            synced: self.feed()["synced"].clone(),
            list: pinned["head"].clone(),
            parts,
            evidence: self.evidence(),
            resets: self.reset_marks(),
        }
    }
}

/// `sync` with its `request_id` checked (a lowercase UUID v4) and blanked,
/// to compare with [`Rig::sync`].
fn blank(sync: ControlSync) -> ControlSync {
    let id = uuid::Uuid::parse_str(&sync.request_id).expect("a UUID");
    assert_eq!(id.get_version_num(), 4, "{}", sync.request_id);
    assert_eq!(id.hyphenated().to_string(), sync.request_id, "lowercase");
    ControlSync {
        request_id: String::new(),
        ..sync
    }
}

/// The `control_sync` the fake Station holds, as [`blank`] gives it.
#[track_caller]
fn sync_of(held: &Held) -> ControlSync {
    match held.call() {
        Ok(ToStation::ControlSync(sync)) => blank(sync),
        other => panic!("not a control_sync: {other:?}"),
    }
}

/// The `request_id` of the `control_sync` the fake Station holds.
#[track_caller]
fn request_id(held: &Held) -> String {
    match held.call() {
        Ok(ToStation::ControlSync(sync)) => sync.request_id,
        other => panic!("not a control_sync: {other:?}"),
    }
}

/// What a refusal must leave as it was ([`Rig::unmoved`]).
#[derive(Debug, PartialEq)]
struct Unmoved {
    synced: Value,
    list: Value,
    parts: Vec<(String, String)>,
    evidence: Vec<String>,
    resets: Vec<(String, String)>,
}

impl HostRig for Rig {
    fn config_dir(&self) -> PathBuf {
        self.sandbox.config()
    }

    fn fake_dir(&self) -> PathBuf {
        self.fake.clone()
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

/// The head `seq` of the device list pinned in `config`, as written.
fn list_head(config: &Path) -> u64 {
    let path = config.join("pairing/membership.json");
    let state: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    state["head"]["seq"].as_u64().unwrap()
}

fn fetch(after: u64) -> ToStation {
    ToStation::MembershipFetch(MembershipFetch { after })
}

/// The host's next device-list fetch on `link`, answered; its feed syncs
/// on the way answered too.
fn next_fetch(station: &mut FakeStation, link: u64) -> ToStation {
    loop {
        let call = station.next_call(link).unwrap();
        if matches!(call, ToStation::MembershipFetch(_)) {
            return call;
        }
    }
}

/// Astation's `auth_required` on the host's link again: Astation
/// re-authenticates it (a routed link: authenticates it, its upgrade), a
/// new link generation on the same socket (a new challenge: one answered
/// is spent).
fn reauthenticate(rig: &Rig, n: u8) {
    let generation = rig.dump()["station"]["link"]["gen"].as_u64().unwrap();
    let transport = match rig.via {
        Via::Local => "lan",
        Via::Relay | Via::Routed => "relay",
    };
    let challenge = json!({"type": "statusUpdate", "data": {"status": "auth_required",
        "data": {"astation_id": ASTATION, "challenge": format!("{n:x}").repeat(64),
                 "transport": transport, "protocol": "2"}}});
    rig.astation.send(rig.link(), challenge.to_string());
    rig.until_station("the next link generation", |s| {
        s["link"]["gen"].as_u64() > Some(generation)
    });
}

// ── r9 clients and their tasks ──

/// Whether the store holds task `tid`.
fn stored_at_all(rig: &Rig, tid: &Value) -> bool {
    rig.db()
        .query_row(
            "SELECT COUNT(*) FROM work WHERE id=?1",
            [tid.as_str().unwrap()],
            |r| r.get::<_, i64>(0),
        )
        .unwrap()
        > 0
}

/// Task `tid`'s admission record (`None`: v1).
fn admission(rig: &Rig, tid: &Value) -> Value {
    record(rig, tid)["delegated"].clone()
}

// ── The host's own device-list fetch (Task 30) ──

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
    let mut router = Router::on(&rig.astation, rig.link());
    let mut phone = router
        .connect("ph", &rig.log, HOST, &Identity::native(PHONE, auth(PHONE)))
        .expect("the phone");
    assert_eq!(rig.head(), 3);

    rig.log.add_native("dev-tablet", &["view"]);
    rig.station().set_log(&rig.log);
    rig.announce();
    rig.serve_until_head(4);
    assert_eq!(rig.fetches(), [fetch(3)]);
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
    rig.station().set_log(&rig.log);
    // Announced once: the host's second fetch is its own.
    rig.announce();
    rig.serve_until_head(69);
    assert_eq!(rig.fetches(), [fetch(3), fetch(67)]);
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
    rig.station().set_log(&rig.log);
    rig.station().refuse(RefusedCall::MembershipFetch, true);
    let link = rig.link();
    rig.station().on_link(link);
    rig.station().heads_now();
    assert_eq!(next_fetch(&mut rig.station(), link), fetch(3));
    let station = rig.until_station("the refusal", |s| s["refusals"]["membership_fetch"] == 1);
    assert!(station["fetch"]["in_flight"].is_null(), "{station}");
    assert_eq!(rig.head(), 3, "nothing advanced");

    // The next heads, within 30 s: no fetch.
    let heads = station["heads"].as_u64().unwrap();
    rig.station().heads_now();
    let station = rig.until_station("the next heads", |s| s["heads"] == heads + 1);
    assert!(station["fetch"]["in_flight"].is_null(), "{station}");
    assert_eq!(station["fetch"]["backoff"], true);
    rig.station().serve(link);
    assert_eq!(rig.fetches(), [fetch(3)]);

    // 30 s later on the host's clock: the next heads fetches again.
    rig.station().refuse(RefusedCall::MembershipFetch, false);
    rig.clock.add_mono(30_000);
    rig.station().heads_now();
    rig.serve_until_head(4);
    assert_eq!(rig.fetches(), [fetch(3), fetch(3)]);

    // Refused again; Astation authenticates the link again (the next link
    // generation, at once): it fetches at once, the backoff gone with the
    // old generation.
    rig.log.add_native("dev-laptop", &["view"]);
    rig.station().set_log(&rig.log);
    rig.station().refuse(RefusedCall::MembershipFetch, true);
    // The fetches a heads starts: at most one a second (I1).
    rig.clock.add_mono(1_000);
    rig.station().heads_now();
    assert_eq!(next_fetch(&mut rig.station(), link), fetch(4));
    rig.until_station("the second refusal", |s| {
        s["refusals"]["membership_fetch"] == 2
    });
    rig.station().refuse(RefusedCall::MembershipFetch, false);
    reauthenticate(&rig, 0xc);
    // The new generation keeps the fetch's pacing (a second after the last
    // fetch a heads started).
    rig.clock.add_mono(1_000);
    rig.announce();
    rig.serve_until_head(5);
    assert_eq!(rig.fetches().last(), Some(&fetch(4)));

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
        rig.station().set_log(&rig.log);
        rig.announce();
        rig.serve_until_head(4);
        assert_eq!(rig.fetches(), [fetch(3)], "{via:?}");
        let station = rig.until_station("the link", |s| !s["link"].is_null());
        assert_eq!(station["link"]["kind"], rig.via.kind(), "{via:?}");
        assert_eq!(station["link"]["origin"], rig.origin(), "{via:?}");
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
    rig.station().set_log(&rig.log);
    let link = rig.link();
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

/// Decision 11 (hook off = main): with `host.delegated` off the host makes
/// no Station call, agent hosting on or not and whatever its link: heads
/// announcing a newer device list and a feed are read and dropped, as
/// today, on Astation's local link and on a routed relay link (§R9.7b,
/// where today's relay is the peer). No Station state, no feed state.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_STATE_DUMP hook"
)]
fn no_station_call_without_host_delegated() {
    for via in [Via::Local, Via::Routed] {
        let mut rig = Rig::start(via, false, true);
        let link = rig.link();
        let mut router = Router::on(&rig.astation, link);
        let mut phone = router
            .connect("ph", &rig.log, HOST, &Identity::native(PHONE, auth(PHONE)))
            .expect("the phone");
        rig.log.add_native("dev-tablet", &["view"]);
        {
            let mut station = rig.station();
            station.set_log(&rig.log);
            let record = station.record_for(SVC, ControlAction::Cover);
            station.append(record);
        }
        rig.announce();
        // The heads were read: a `push_ack` sent after them was (its line).
        router.send_raw(json!({"type": "relay", "op": "push_ack", "acks": []}).to_string());
        within("the push_ack", || {
            rig.runtime_log()
                .contains("a push_ack acknowledged nothing pending")
        });
        // Anything the host sent then is on the link before this reply.
        let sessions = router.list("ph", &mut phone);
        assert!(sessions.is_empty(), "{sessions:?}");
        assert!(rig.station().serve(link).is_empty(), "{via:?}");
        assert!(rig.station().sent().is_empty(), "{via:?}");
        assert_eq!(rig.head(), 3);
        assert!(rig.dump()["station"].is_null(), "no Station state");
        rig.status_feeds_absent();
        // No new table, row or log line (Task 34 review m1): the store has
        // no control table and no delegated clock, and runtime.log no line
        // of the Station link's.
        let db = rig.db();
        let tables: i64 = db
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name LIKE 'control%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tables, 0, "{via:?}: no control tables");
        let rows: i64 = db
            .query_row("SELECT count(*) FROM clock", [], |r| r.get(0))
            .unwrap();
        assert_eq!(rows, 0, "{via:?}: no clock row");
        let log = rig.runtime_log();
        for line in [
            "Station",
            "control feed",
            "control_sync",
            "membership_fetch",
        ] {
            assert!(!log.contains(line), "{via:?}: {line:?} in {log}");
        }
    }
}

// ── The feed sync and the revocation gate (Tasks 33, 34) ──

/// The host's Station calls equal the shared vectors' bytes (PR 2's
/// `r9-vectors-station-calls.json`), byte for byte: its `membership_fetch`
/// (case `membership_fetch`, a host whose list is at `seq` 2), and every
/// `control_sync` it makes (case `control_sync_with_feed_id`, the fake's
/// feed named as the vectors name it): the first read of a feed it never
/// read (`after: 0`), a continuation (`after: 2`), and the read from 0
/// after the Station rolled the feed back under the same `feed_id` (§11.4
/// "Resets": `after: 0`, the same `feed_id`). Only the calls' bytes are
/// pinned here: that the read from 0 goes unpaced once its mark is written
/// is pinned by `sync_tests` (the host clock can't be frozen here, so a
/// call held back by the 1 s pace would still arrive within the wait). The
/// vectors' origin is the dev Station's, never contacted
/// here: the host's own (the rig's relay setting) takes its place, every
/// other byte the vectors'. `control_sync_without_feed_id` is a call the
/// host never makes (it names the announced feed, §11.4 "Only the
/// announced feed").
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES and ATEM_TEST_STATE_DUMP hooks"
)]
fn the_hosts_station_calls_match_the_goldens() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("designs/protocol/fixtures/r9-vectors-station-calls.json");
    let vectors: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let case = |name: &str| {
        vectors["calls"]
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["name"] == name)
            .unwrap_or_else(|| panic!("the {name} case"))
            .clone()
    };
    let fetch_case = case("membership_fetch");
    assert_eq!(fetch_case["fields"], json!({"after": 2}));
    let sync_case = case("control_sync_with_feed_id");
    assert_eq!(sync_case["fields"]["after"], 2);
    let golden_feed = sync_case["fields"]["feed_id"].as_str().unwrap().to_string();
    let golden_origin = sync_case["fields"]["origin"].as_str().unwrap().to_string();
    let wire = sync_case["wire"].as_str().unwrap();
    let golden_id = sync_case["fields"]["request_id"]
        .as_str()
        .unwrap()
        .to_string();
    let origin_field = format!("\"origin\":\"{golden_origin}\"");
    let id_field = format!("\"request_id\":\"{golden_id}\"");
    assert_eq!(wire.matches(&origin_field).count(), 1, "{wire}");
    assert_eq!(wire.matches(&id_field).count(), 1, "{wire}");
    assert_eq!(wire.matches("\"after\":2,").count(), 1, "{wire}");
    // The vector's wire with the host's origin, `after` and `request_id`
    // (its own, fresh for every call: wire rule 11).
    let sync_wire = |after: u64, request_id: &str| {
        wire.replace(&origin_field, &format!("\"origin\":\"{NO_RELAY}\""))
            .replace("\"after\":2,", &format!("\"after\":{after},"))
            .replace(&id_field, &format!("\"request_id\":\"{request_id}\""))
    };

    let mut rig = Rig::start(Via::Local, true, false);
    assert_eq!(rig.head(), 2);
    {
        let mut station = rig.station();
        station.name_feed(&golden_feed);
        for _ in 0..2 {
            let record = station.record_for(SVC, ControlAction::Cover);
            station.append(record);
        }
    }
    rig.log.add_native("dev-tablet", &["view"]);
    rig.station().set_log(&rig.log);
    // Its first heads: the fetch after 2, the feed read from 0.
    rig.announce();
    rig.serve_until("the list at 3, the feed read to 2", |rig| {
        rig.head() == 3 && rig.cursor() == Some(2)
    });
    // A record more: the read after 2.
    rig.append(SVC, ControlAction::Cover);
    rig.clock.add_mono(1_000);
    rig.announce();
    rig.serve_until("the feed read to 3", |rig| rig.cursor() == Some(3));
    // Rolled back under the same feed_id: read again from 0 (unpaced, as
    // `sync_tests` pins; here only its bytes).
    rig.station().truncate(1);
    rig.announce();
    rig.serve_until("the read from 0", |rig| {
        rig.cursor() == Some(1) && rig.reset_marks().is_empty() && rig.gate_open()
    });
    // Each call's own id: a lowercase UUID v4 ([`blank`] checks it), none
    // twice ([`Rig::syncs`]).
    let sent = rig.station().sent();
    let ids: Vec<String> = sent
        .iter()
        .filter_map(|bytes| match ToStation::decode(bytes.as_bytes()) {
            Ok(ToStation::ControlSync(sync)) => {
                let id = sync.request_id.clone();
                blank(sync);
                Some(id)
            }
            _ => None,
        })
        .collect();
    assert_eq!(ids.len(), 3, "{sent:?}");
    assert_eq!(
        sent,
        [
            fetch_case["wire"].as_str().unwrap().to_string(),
            sync_wire(0, &ids[0]),
            sync_wire(2, &ids[1]),
            sync_wire(0, &ids[2]),
        ]
    );
    // And as the shared reader reads them.
    let feed = Some(golden_feed);
    let syncs: Vec<_> = rig
        .syncs()
        .into_iter()
        .map(|s| (s.feed_id, s.after))
        .collect();
    assert_eq!(
        syncs,
        [(feed.clone(), 0), (feed.clone(), 2), (feed, 0)],
        "{syncs:?}"
    );
}

/// I.5.8, §11.4 "The gate", §11.6 "Details" (VII.A tests 14 and 15's
/// gate): an unstarted remote task of a delegated sender waits `blocked`,
/// `revocations not yet checked`, until the host's own Station's gate
/// opens, and never earlier: not at the Station's `heads`, only once the
/// feed they announce is read to its head (its page, answered by the
/// Station). A native member's task (the phone, its own channel gone)
/// waits for the host's own Station's gate; a service's for the gate of
/// its current coverage's origin, closed again when no `heads` came for 60
/// seconds and opened by the next one. `atem status` says why.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_HOST_CLOCK and ATEM_TEST_STATE_DUMP hooks"
)]
fn a_remote_task_waits_revocations_not_yet_checked_until_the_gate_opens() {
    let rig = Rig::full(Via::Local);
    let mut r = Router::on(&rig.astation, rig.link());
    // No feed covers the service yet: v1, it launches the session and keeps
    // it busy.
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    let busy = task(IDS, &launch, "GATE_BUSY", HOUR);
    enqueue(&mut svc, &mut r, &busy);
    assert!(admission(&rig, &busy["task_id"]).is_null(), "v1");
    in_turn(&rig, &busy["task_id"], "GATE_BUSY");
    // The phone's task (a native member: delegated); the phone goes.
    let mut phone = Dev::new(&mut r, IDS, &rig.log, PHONE, false);
    let native = task(IDS, &launch, "GATE_NATIVE", HOUR);
    enqueue(&mut phone, &mut r, &native);
    assert_eq!(
        admission(&rig, &native["task_id"])["principal"],
        format!("member:{PHONE}")
    );
    phone.close(&mut r);
    complete_turn(&rig, &busy["task_id"]);
    wait_stored(&rig, &native["task_id"], "blocked", GATE_CLOSED);
    rig.status_feeds(&format!("{GATE_CLOSED} (waiting for the Station's heads)"));

    // The Station's heads: the host reads the feed (empty) from its start.
    let held = {
        let mut station = rig.station();
        station.on_link(rig.link());
        station.heads_now();
        station.hold_call(rig.link())
    };
    assert_eq!(sync_of(&held), rig.sync(0));
    // Asked and not answered: still closed.
    rig.two_passes();
    assert!(!rig.gate_open(), "{}", rig.dump()["station"]);
    assert_eq!(stored(&rig, &native["task_id"])["detail"], GATE_CLOSED);
    never_ran(&rig, &native["task_id"], "GATE_NATIVE");
    rig.status_feeds(&format!(
        "{GATE_CLOSED} (reading the control feed (0 of 0))"
    ));
    // The page: the gate opens, the task runs.
    rig.station().answer_held(held).unwrap();
    in_turn(&rig, &native["task_id"], "GATE_NATIVE");
    complete_turn(&rig, &native["task_id"]);
    rig.status_feeds(&format!("revocations checked ({NO_RELAY})"));

    // A feed covering the service from now on: its tasks are delegated,
    // waiting for its coverage's origin's gate.
    rig.cover_and_open();
    // No heads for 60 s on the host's clock: the gate closes.
    rig.clock.add_mono(61_000);
    rig.until_feed("60 s without heads", |f| f["closed"] == NO_HEADS_60S);
    let covered = task(IDS, &launch, "GATE_SERVICE", HOUR);
    enqueue(&mut svc, &mut r, &covered);
    let admitted = admission(&rig, &covered["task_id"]);
    assert_eq!(
        admitted["principal"],
        format!("service:{SVC}"),
        "{admitted}"
    );
    assert_eq!(admitted["feed"]["origin"], NO_RELAY, "{admitted}");
    wait_stored(&rig, &covered["task_id"], "blocked", GATE_CLOSED);
    rig.status_feeds(&format!("{GATE_CLOSED} ({NO_HEADS_60S})"));
    rig.two_passes();
    never_ran(&rig, &covered["task_id"], "GATE_SERVICE");
    // The Station's next heads (the feed read to its head already): open.
    rig.announce();
    in_turn(&rig, &covered["task_id"], "GATE_SERVICE");
}

/// §11.4 "One feed per account", §11.1 (`wrong_account`), session-v1 R9.3:
/// a Station that serves another account's data on the host's link (its
/// heads, its feed and its device list, a feed and a list ahead of the
/// host's) gets nothing applied. Its feed is read (a new `feed_id`: a
/// reset), but every record of it is another account's: kept as evidence
/// (`wrong_account`), the service's own control state untouched, though
/// the records name the same service, signed with its key, a revoke among
/// them. Its device list is fetched, and nothing of it applies or freezes
/// the host's list; the gate stays closed (the host's list doesn't hold the
/// announced head) and the service's task waits. Served the host's own
/// account again, the host reads its own feed from 0 and the task runs:
/// the other account's revoke stopped nothing.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_HOST_CLOCK and ATEM_TEST_STATE_DUMP hooks"
)]
fn another_accounts_records_apply_nothing() {
    let rig = Rig::full(Via::Local);
    let mut r = Router::on(&rig.astation, rig.link());
    rig.cover_and_open();
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    let principal = format!("service:{SVC}");
    let part = rig.part(&principal).expect("the cover's part");
    let pinned = rig.unmoved().list;
    assert!(rig.evidence().is_empty());

    // Another account's list, two entries ahead of this host's.
    let mut other = TestLog::genesis(OTHER_ACCOUNT, &secret("another account's astation"));
    other.add_host(HOST, 1, &secret("another account's host"));
    for n in 0..4 {
        other.add_native(&format!("dev-other-{n}"), &["view"]);
    }
    assert_eq!(other.log.head().seq, 6);
    {
        let mut station = rig.station();
        station.serve_other_account(true);
        station.set_log(&other);
        let cover = station.record_for(SVC, ControlAction::Cover);
        station.append(cover);
        let revoke = station.record_for(
            SVC,
            ControlAction::Revoke {
                interrupt_running: true,
            },
        );
        station.append(revoke);
    }
    rig.clock.add_mono(1_000);
    rig.announce();
    let other_feed = rig.station().feed_id().to_string();
    rig.serve_until("the other account's feed read", |rig| {
        let station = rig.dump()["station"].clone();
        station["fetch"]["results"] == 1
            && station["feed"]["synced"] == json!({"feed_id": other_feed, "cursor": 2})
    });
    // Both kept as evidence (the store writes evidence at most once a
    // minute: the first now, the count in memory).
    assert_eq!(rig.evidence(), ["wrong_account"]);
    rig.status_feeds(&format!(
        "{GATE_CLOSED} (device list behind the Station's head (4 of 6)); 2 kept as evidence, 0 pending"
    ));
    assert_eq!(rig.part(&principal).as_deref(), Some(part.as_str()));
    assert!(rig.fetches().contains(&fetch(4)), "{:?}", rig.fetches());
    // The host's own list, as pinned, not frozen.
    assert_eq!(rig.unmoved().list, pinned);
    let membership = rig.dump()["membership"].clone();
    assert_eq!(membership["frozen"], false, "{membership}");
    assert_eq!(membership["faulted"], false, "{membership}");
    assert!(
        !rig.sandbox
            .config()
            .join("pairing/membership.freeze")
            .exists()
    );
    // The gate stays closed: the service's task waits, never cancelled.
    let t = task(IDS, &launch, "OTHER_ACCOUNT_REVOKE", HOUR);
    enqueue(&mut svc, &mut r, &t);
    wait_stored(&rig, &t["task_id"], "blocked", GATE_CLOSED);
    assert!(!rig.gate_open());

    // The host's own account again: its own feed read from 0, the gate
    // open, the task runs.
    rig.station().serve_other_account(false);
    rig.open_gate();
    in_turn(&rig, &t["task_id"], "OTHER_ACCOUNT_REVOKE");
    assert_eq!(rig.part(&principal).as_deref(), Some(part.as_str()));
    assert_eq!(rig.unmoved().list, pinned);
}

/// Decision 20, §11.4 "Refusals" (all three): a `control_sync_refused`, a
/// `membership_fetch_refused` and a `control_ack_refused` each close the
/// host's own Station's gate and advance nothing: no feed cursor, no
/// device-list head, no clock floor, no control state, evidence or reset
/// mark (the acknowledgment book is Task 36's). The next `heads` within the
/// 30-second backoff asks nothing and opens nothing; the gate stays closed,
/// and `atem status` says the Station refused. Past the backoff the next
/// `heads` asks again, and the gate opens only with a page asked then
/// (the resynchronization), even when the cursor already held the head.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_HOST_CLOCK and ATEM_TEST_STATE_DUMP hooks"
)]
fn each_refusal_keeps_the_gate_closed_and_advances_nothing() {
    for call in [
        RefusedCall::ControlSync,
        RefusedCall::MembershipFetch,
        RefusedCall::ControlAck,
    ] {
        let mut rig = Rig::full(Via::Local);
        rig.cover_and_open();
        let link = rig.link();
        let name = match call {
            RefusedCall::ControlSync => "control_sync",
            RefusedCall::MembershipFetch => "membership_fetch",
            RefusedCall::ControlAck => "control_ack",
        };
        // Something to refuse, and what it would have moved.
        rig.clock.add_mono(1_000);
        match call {
            RefusedCall::ControlSync => {
                rig.append(SVC, ControlAction::Hold);
            }
            RefusedCall::MembershipFetch => {
                rig.log.add_native("dev-tablet", &["view"]);
                rig.station().set_log(&rig.log);
            }
            RefusedCall::ControlAck => {}
        }
        rig.station().refuse(call, true);
        let held = match call {
            RefusedCall::ControlAck => None,
            _ => {
                let mut station = rig.station();
                station.on_link(link);
                station.heads_now();
                Some(station.hold_call(link))
            }
        };
        rig.two_passes();
        let before = rig.unmoved();
        let floor = rig.floor_offset();
        let sent = rig.station().sent().len();
        match held {
            Some(held) => {
                rig.station().answer_held(held).unwrap();
            }
            // The host makes no ack in this version: the refusal comes on
            // its own (it answers no request anyway).
            None => rig.astation.send(
                link,
                CallRefused {
                    call,
                    code: RefusalCode::Forbidden,
                }
                .to_json()
                .unwrap()
                .to_string(),
            ),
        }
        let station = rig.until_station("the refusal", |s| s["refusals"][name] == 1);
        assert_eq!(station["feed"]["closed"], REFUSED, "{name}: {station}");
        assert!(!rig.gate_open(), "{name}");
        assert_eq!(rig.unmoved(), before, "{name}");
        assert!(rig.floor_offset() <= floor, "{name}: the floor advanced");
        rig.status_feeds(&format!("{GATE_CLOSED} ({REFUSED})"));

        // The next heads within the backoff: nothing asked, still closed.
        let heads = station["heads"].as_u64().unwrap();
        rig.clock.add_mono(1_000);
        rig.station().heads_now();
        rig.until_station("the next heads", |s| s["heads"] == heads + 1);
        rig.two_passes();
        rig.station().serve(link);
        assert_eq!(rig.station().sent().len(), sent, "{name}: nothing asked");
        assert_eq!(rig.feed()["closed"], REFUSED, "{name}");
        assert_eq!(rig.unmoved().synced, before.synced, "{name}");

        // Past the backoff: asked again, and open with that page.
        rig.station().refuse(call, false);
        rig.clock.add_mono(30_000);
        rig.announce();
        rig.serve_until(&format!("{name}: open again"), |rig| rig.gate_open());
        let syncs = rig.syncs();
        let last = syncs.last().unwrap();
        assert_eq!(last, &rig.sync(1), "{name}: {syncs:?}");
        assert!(rig.station().sent().len() > sent, "{name}");
        match call {
            RefusedCall::ControlSync => assert_eq!(rig.cursor(), Some(2)),
            RefusedCall::MembershipFetch => assert_eq!(rig.head(), 5),
            RefusedCall::ControlAck => assert_eq!(rig.cursor(), Some(1)),
        }
    }
}

/// VII.A test 16 (design I.5.8, session-v1 R9.7b): a routed host, no
/// Astation online, syncs its own Station's feed over its routed relay link
/// and applies a revocation. The Station online as a Station is: it covers
/// the service, the gate opens (`atem status` says so), the service's
/// session runs a task and queues another; the Station's revoke (no
/// interrupt) cancels the queued one, `sender revoked`, never run, and the
/// running turn goes on to its end.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES and ATEM_TEST_STATE_DUMP hooks"
)]
fn a_routed_host_syncs_the_feed_and_opens_the_gate() {
    let rig = Rig::full(Via::Routed);
    let mut r = Router::on(&rig.astation, rig.link());
    rig.append(SVC, ControlAction::Cover);
    rig.online();
    let station = rig.until_station("the routed link", |s| s["link"]["kind"] == "routed");
    assert_eq!(station["link"]["origin"], rig.origin(), "{station}");
    assert_eq!(rig.cursor(), Some(1));
    rig.status_feeds(&format!("revocations checked ({})", rig.origin()));
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    let first = task(IDS, &launch, "ROUTED_FIRST", HOUR);
    let second = task(IDS, &launch, "ROUTED_SECOND", HOUR);
    for t in [&first, &second] {
        enqueue(&mut svc, &mut r, t);
        assert_eq!(
            admission(&rig, &t["task_id"])["feed"]["origin"],
            rig.origin()
        );
    }
    in_turn(&rig, &first["task_id"], "ROUTED_FIRST");
    wait_stored(&rig, &second["task_id"], "blocked", BEHIND);
    // The Station revokes the service: the host reads it on its routed link.
    rig.append(
        SVC,
        ControlAction::Revoke {
            interrupt_running: false,
        },
    );
    wait_stored(&rig, &second["task_id"], "cancelled", REVOKED);
    assert_eq!(rig.cursor(), Some(2));
    assert_eq!(rig.dump()["station"]["link"]["kind"], "routed");
    // The running turn goes on (no interrupt) and ends on its own.
    assert_eq!(stored(&rig, &first["task_id"])["state"], "submitted");
    complete_turn(&rig, &first["task_id"]);
    never_ran(&rig, &second["task_id"], "ROUTED_SECOND");
    assert!(rig.syncs().iter().all(|s| s.origin == rig.origin()));
}

/// VII.A test 18 (design I.6.5, §11.4 "Station time"): a `heads` with a
/// `station_time` a year ahead moves no clock floor, closes the gate of
/// its origin and raises one owner alert ("Station clock ahead of this
/// host", one runtime.log line); a page a year ahead (its records still
/// apply) and repeated `heads` add none, and `atem status` says why. No
/// task expires: a service's task due in an hour waits, as it would with
/// the floor a year ahead never. A `heads` within the cap opens the gate
/// again, and the task runs.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_HOST_CLOCK and ATEM_TEST_STATE_DUMP hooks"
)]
fn a_station_clock_a_year_ahead_closes_the_gate_alerts_once_and_expires_nothing() {
    let rig = Rig::full(Via::Local);
    let mut r = Router::on(&rig.astation, rig.link());
    rig.cover_and_open();
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    let floor = rig.floor_offset();
    let wall = r9log::host_now().wall_ms;
    let ahead = |rig: &Rig| rig.runtime_log().matches(CLOCK_AHEAD).count();
    assert_eq!(ahead(&rig), 0);

    // The Station's clock a year ahead.
    let year = 365 * 24 * HOUR;
    rig.station().station_time(r9log::host_now().wall_ms + year);
    rig.clock.add_mono(1_000);
    rig.announce();
    rig.until_feed("the clock beyond the cap", |f| f["closed"] == CLOCK_AHEAD);
    assert!(rig.floor_offset() <= floor, "the floor doesn't move");
    let t = task(IDS, &launch, "A_YEAR_AHEAD", HOUR);
    enqueue(&mut svc, &mut r, &t);
    wait_stored(&rig, &t["task_id"], "blocked", GATE_CLOSED);
    // A page a year ahead: its record applies; and heads again.
    rig.append("svc-other", ControlAction::Cover);
    rig.clock.add_mono(1_000);
    rig.announce();
    rig.serve_until("the page a year ahead", |rig| rig.cursor() == Some(2));
    for _ in 0..3 {
        rig.clock.add_mono(1_000);
        rig.announce();
    }
    rig.two_passes();
    assert_eq!(rig.feed()["closed"], CLOCK_AHEAD);
    assert!(rig.floor_offset() <= floor, "the floor doesn't move");
    let value = rig.floor()["value_ms"].as_u64().unwrap();
    assert!(value <= wall + MIN, "not the Station's time: {value}");
    assert_eq!(ahead(&rig), 1, "one alert: {}", rig.runtime_log());
    rig.status_feeds(&format!("{GATE_CLOSED} ({CLOCK_AHEAD})"));
    assert_eq!(
        stored(&rig, &t["task_id"])["state"],
        "blocked",
        "not expired"
    );
    never_ran(&rig, &t["task_id"], "A_YEAR_AHEAD");

    // A heads within the cap: open again, the task runs.
    rig.station().station_time(r9log::host_now().wall_ms);
    rig.clock.add_mono(1_000);
    rig.announce();
    in_turn(&rig, &t["task_id"], "A_YEAR_AHEAD");
    assert_eq!(ahead(&rig), 1);
}

/// VII.A test 10, part 1 (design I.5.2, §11.4 "Resets"): the Station
/// restored from a backup mints a new feed whose snapshot carries its
/// current effective state. The host's call for the old feed, in flight at
/// the restore, is refused (`control_sync_refused`, wire rule 11 as
/// Astation decided on #164: the refusal's backoff, nothing asked before
/// it), or, from a Station that breaks that rule (`StaleFeed::ServeCurrent`),
/// answered on the new feed: a page that doesn't answer its call, a Station
/// fault, nothing of it applied; the next `heads` announces the new feed, a
/// reset read from 0 at once. Either way the gate stays closed (`atem
/// status` says why) until the new feed is read from 0 to its head, and no
/// stop is lost: the service held on the old feed stays held through the
/// snapshot, its task paused, until the new feed releases it.
///
/// Part 2 (ruling T33c, the reset mark across a whole-runtime crash): the
/// Station rolls its feed back under the same `feed_id`; the runtime is
/// killed after the reset's mark is written and before its read from 0
/// completes; the feed regrows past the old cursor with other records, a
/// revoke among them. The restarted host reads the feed from 0 (never
/// after its old cursor), its gate closed until then, and applies the
/// revoke: the service's queued task is cancelled, never run.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_HOST_CLOCK and ATEM_TEST_STATE_DUMP hooks"
)]
fn a_station_restored_from_backup_resyncs_from_its_snapshot() {
    for mode in [StaleFeed::Refuse, StaleFeed::ServeCurrent] {
        restored_from_backup(mode);
    }
    rolled_back_across_a_crash();
}

fn restored_from_backup(mode: StaleFeed) {
    let rig = Rig::full(Via::Local);
    let link = rig.link();
    let mut r = Router::on(&rig.astation, link);
    rig.cover_and_open();
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    // A hold: the service's task waits, paused.
    rig.append(SVC, ControlAction::Hold);
    rig.clock.add_mono(1_000);
    rig.announce();
    rig.serve_until("the hold read", |rig| rig.cursor() == Some(2));
    let held_task = task(IDS, &launch, "HELD_THROUGH_THE_RESTORE", HOUR);
    enqueue(&mut svc, &mut r, &held_task);
    wait_stored(&rig, &held_task["task_id"], "blocked", PAUSED);
    // A record more: the host's call for it in flight when the Station is
    // restored from a backup.
    rig.append("svc-other", ControlAction::Cover);
    rig.clock.add_mono(1_000);
    let call = {
        let mut station = rig.station();
        station.on_link(link);
        station.heads_now();
        station.hold_call(link)
    };
    let old = rig.station().feed_id().to_string();
    assert_eq!(sync_of(&call), rig.sync(2));
    {
        let mut station = rig.station();
        station.stale_feed(mode);
        station.reset();
        assert_ne!(station.feed_id(), old);
        // The snapshot: the service's cover and hold, signed anew.
        let actions: Vec<_> = station
            .records()
            .iter()
            .map(|(_, r)| r.action().name())
            .collect();
        assert_eq!(actions, ["cover", "hold", "cover"], "{mode:?}");
        station.answer_held(call).unwrap();
    }
    let expected = match mode {
        StaleFeed::Refuse => REFUSED,
        StaleFeed::ServeCurrent => OTHER_FEED,
    };
    rig.until_feed("the old call's answer", |f| f["closed"] == expected);
    rig.status_feeds(&format!("{GATE_CLOSED} ({expected})"));
    assert_eq!(rig.cursor(), Some(2), "{mode:?}: nothing of it applied");
    let call = match mode {
        StaleFeed::Refuse => {
            // The next heads (the new feed) within the backoff: nothing
            // asked.
            let sent = rig.station().sent().len();
            rig.clock.add_mono(1_000);
            rig.station().heads_now();
            rig.two_passes();
            rig.station().serve(link);
            assert_eq!(rig.station().sent().len(), sent, "{mode:?}");
            assert!(!rig.gate_open());
            // Past it: the new feed is read from 0; closed until it is.
            rig.clock.add_mono(30_000);
            let mut station = rig.station();
            station.heads_now();
            station.hold_call(link)
        }
        StaleFeed::ServeCurrent => {
            // The next heads announces the new feed: a reset, read from 0
            // at once once marked (a fault's pause holds paced calls only).
            rig.clock.add_mono(1_000);
            let mut station = rig.station();
            station.heads_now();
            station.hold_call(link)
        }
    };
    assert_eq!(sync_of(&call), rig.sync(0));
    rig.two_passes();
    // (A refusal's or a fault's reason stands until a page asked after it
    // reads.)
    assert_eq!(rig.feed()["closed"], expected, "{mode:?}");
    assert_eq!(rig.feed()["reset"]["durable"], true, "{mode:?}");
    assert!(!rig.gate_open());
    rig.status_feeds(&format!("{GATE_CLOSED} ({expected})"));
    rig.station().answer_held(call).unwrap();
    rig.serve_until("the snapshot read", |rig| rig.gate_open());
    let new = rig.station().feed_id().to_string();
    assert_eq!(
        rig.feed()["synced"],
        json!({"feed_id": new, "cursor": 3}),
        "{mode:?}"
    );
    assert!(rig.reset_marks().is_empty());
    // No stop lost: the hold carried over.
    rig.two_passes();
    wait_stored(&rig, &held_task["task_id"], "blocked", PAUSED);
    never_ran(&rig, &held_task["task_id"], "HELD_THROUGH_THE_RESTORE");
    // The new feed releases it.
    rig.append(SVC, ControlAction::Release);
    rig.clock.add_mono(1_000);
    rig.announce();
    rig.serve_until("the release read", |rig| rig.cursor() == Some(4));
    in_turn(&rig, &held_task["task_id"], "HELD_THROUGH_THE_RESTORE");
}

fn rolled_back_across_a_crash() {
    let mut rig = Rig::full(Via::Local);
    let feed;
    let t;
    {
        let link = rig.link();
        let mut r = Router::on(&rig.astation, link);
        rig.cover_and_open();
        let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
        let launch = svc.session(&mut r);
        rig.append(SVC, ControlAction::Hold);
        rig.append(SVC, ControlAction::Release);
        rig.clock.add_mono(1_000);
        rig.announce();
        rig.serve_until("the feed read to 3", |rig| {
            rig.cursor() == Some(3) && rig.gate_open()
        });
        feed = rig.station().feed_id().to_string();
        // Rolled back to 1 under the same feed_id: marked, then read from 0.
        rig.station().truncate(1);
        let call = {
            let mut station = rig.station();
            station.heads_now();
            station.hold_call(link)
        };
        assert_eq!(sync_of(&call), rig.sync(0));
        assert_eq!(rig.reset_marks(), [(NO_RELAY.to_string(), String::new())]);
        t = task(IDS, &launch, "AFTER_THE_ROLLBACK", HOUR);
        enqueue(&mut svc, &mut r, &t);
        wait_stored(&rig, &t["task_id"], "blocked", GATE_CLOSED);
        // Killed with its read from 0 unanswered.
        drop(call);
    }
    rig.kill();
    assert_eq!(rig.reset_marks(), [(NO_RELAY.to_string(), String::new())]);
    // The feed regrows past the old cursor (3), a revoke at 2.
    rig.append(
        SVC,
        ControlAction::Revoke {
            interrupt_running: false,
        },
    );
    rig.append("svc-other", ControlAction::Cover);
    rig.append("svc-third", ControlAction::Cover);
    assert_eq!(rig.station().feed_id(), feed);
    rig.start_again();
    let link = rig.link();
    // The restarted host reads it from 0: the mark it found.
    let call = {
        let mut station = rig.station();
        station.on_link(link);
        station.heads_now();
        station.hold_call(link)
    };
    assert_eq!(sync_of(&call), rig.sync(0));
    rig.two_passes();
    assert!(!rig.gate_open());
    assert_eq!(rig.feed()["closed"], RESET, "{}", rig.feed());
    rig.status_feeds(&format!("{GATE_CLOSED} ({RESET})"));
    wait_stored(&rig, &t["task_id"], "blocked", GATE_CLOSED);
    rig.station().answer_held(call).unwrap();
    wait_stored(&rig, &t["task_id"], "cancelled", REVOKED);
    rig.open_gate();
    assert_eq!(rig.cursor(), Some(4));
    assert!(rig.reset_marks().is_empty());
    never_ran(&rig, &t["task_id"], "AFTER_THE_ROLLBACK");
    assert!(
        rig.syncs().iter().skip(3).all(|s| s.after != 3),
        "never read after the old cursor: {:?}",
        rig.syncs()
    );
}

/// Task 32 review I1 (ruling T32b), whole runtime: a stored control part
/// that doesn't read fails the feeds' load at the next start. A service's
/// enqueue is then `busy` and stores nothing (never v1: its revocation,
/// hold and coverage can't be checked), and `atem status` names the way
/// out. The row repaired and the runtime started again, the same service
/// is what its control state says: covered, so delegated.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES and ATEM_TEST_STATE_DUMP hooks"
)]
fn a_damaged_control_part_keeps_a_services_requests_busy_until_repaired() {
    let mut rig = Rig::full(Via::Local);
    let principal = format!("service:{SVC}");
    let launch = {
        let mut r = Router::on(&rig.astation, rig.link());
        rig.cover_and_open();
        let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
        svc.session(&mut r)
    };
    let part = rig.part(&principal).expect("the cover's part");
    rig.kill();
    rig.set_part(&principal, r#"{"damaged":"#);
    rig.start_again();
    {
        let mut r = Router::on(&rig.astation, rig.link());
        within("the load's refusal", || {
            rig.runtime_log()
                .contains("the stored control state doesn't read")
        });
        rig.announce();
        let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
        let t = task(IDS, &launch, "WHILE_DAMAGED", HOUR);
        let reply = svc.request(&mut r, enqueue_data(IDS, &t));
        assert_eq!(reply["code"], "busy", "{reply}");
        assert!(!stored_at_all(&rig, &t["task_id"]), "nothing stored");
        let line = rig.status_feeds(DAMAGED);
        assert!(
            line.contains("host-work.sqlite from a backup, or pair this host again"),
            "{line}"
        );
    }
    rig.kill();
    rig.set_part(&principal, &part);
    rig.start_again();
    let mut r = Router::on(&rig.astation, rig.link());
    rig.open_gate();
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let t = task(IDS, &launch, "AFTER_THE_REPAIR", HOUR);
    enqueue(&mut svc, &mut r, &t);
    let admitted = admission(&rig, &t["task_id"]);
    assert_eq!(admitted["principal"], principal, "{admitted}");
    assert_eq!(admitted["feed"]["origin"], NO_RELAY, "{admitted}");
    in_turn(&rig, &t["task_id"], "AFTER_THE_REPAIR");
}

/// Task 33 review I1, whole runtime (the gate never opens on an unread
/// page): the link drops while hosting runs (and stays down a while:
/// Astation refuses the next authentication), hosting pauses (a
/// `runtime.toml` that doesn't load), the link comes back, and the Station
/// has rolled its feed back under the same `feed_id`. The sync runs in the
/// pause: the feed is read again from 0, and the gate opens only once that
/// read lowered the cursor (never at the old cursor 3).
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_HOST_CLOCK and ATEM_TEST_STATE_DUMP hooks"
)]
fn a_reset_read_in_a_pause_after_the_link_dropped_lowers_the_cursor_first() {
    let rig = Rig::full(Via::Local);
    rig.cover_and_open();
    rig.append("svc-other", ControlAction::Cover);
    rig.append("svc-third", ControlAction::Cover);
    rig.clock.add_mono(1_000);
    rig.announce();
    rig.serve_until("the feed read to 3", |rig| {
        rig.cursor() == Some(3) && rig.gate_open()
    });
    // The link drops, hosting on, and stays down.
    *rig.astation.auth.lock().unwrap() = AuthReply::Deny("not now".into());
    let dropped = rig.link();
    rig.astation.close(dropped);
    rig.until_station("the link down", |s| s["link"].is_null());
    rig.two_passes();
    // Hosting pauses.
    replace(
        &rig.sandbox.config().join("runtime.toml"),
        "version = 1\nenabled = maybe\n",
    );
    within("the pause", || {
        rig.runtime_log()
            .contains("agent hosting is off until it is fixed")
    });
    // The link comes back (Astation's next authentication: 30 s on).
    *rig.astation.auth.lock().unwrap() = AuthReply::Authenticated;
    let link = rig.next_link(dropped);
    rig.link.set(link);
    rig.until_station("the link back", |s| !s["link"].is_null());
    // The Station rolled its feed back to 1 under the same feed_id.
    rig.station().truncate(1);
    rig.clock.add_mono(1_000);
    let call = {
        let mut station = rig.station();
        station.on_link(link);
        station.heads_now();
        station.hold_call(link)
    };
    assert_eq!(sync_of(&call), rig.sync(0));
    rig.two_passes();
    assert!(!rig.gate_open());
    assert_eq!(rig.cursor(), Some(3));
    rig.station().answer_held(call).unwrap();
    // Whenever the gate is open, the cursor is the rolled-back head.
    within("the gate open at the read from 0", || {
        let station = rig.dump()["station"].clone();
        let open = station["feed"]["open"] == true && station["list_part"] == true;
        if open {
            assert_eq!(station["feed"]["synced"]["cursor"], 1, "{station}");
        }
        open
    });
    assert!(rig.reset_marks().is_empty());
    // Hosting stayed paused throughout.
    assert!(
        !rig.runtime_log().contains("runtime.toml is valid again"),
        "{}",
        rig.runtime_log()
    );
}

/// Ruling C1b-a (wire rule 11; Astation's "same-cursor retries" and
/// "reordered old replies"): a `control_sync` unanswered for 30 seconds is
/// retired, the Station-fault alert goes, `atem status` says so, and the
/// host asks again at once at the same cursor with a fresh `request_id`;
/// so again 30 seconds later. The Station's late answers to the retired
/// calls, the newer first, are drained: nothing of them applies and the
/// gate stays closed. The live call's page applies and the gate opens.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_HOST_CLOCK and ATEM_TEST_STATE_DUMP hooks"
)]
fn same_cursor_retries_apply_only_the_live_ids_page() {
    let rig = Rig::full(Via::Local);
    let link = rig.link();
    rig.cover_and_open();
    let principal = format!("service:{SVC}");
    let covered = rig.part(&principal).unwrap();
    rig.append(SVC, ControlAction::Hold);
    rig.clock.add_mono(1_000);
    let a = {
        let mut station = rig.station();
        station.heads_now();
        station.hold_call(link)
    };
    assert_eq!(sync_of(&a), rig.sync(1));
    // Unanswered for 30 s: retired; asked again at once, a fresh id.
    rig.clock.add_mono(31_000);
    let b = rig.station().hold_call(link);
    assert_eq!(sync_of(&b), rig.sync(1));
    assert_ne!(request_id(&a), request_id(&b));
    rig.until_feed("the timeout", |f| f["timeouts"] == 1);
    assert_eq!(rig.feed()["closed"], UNANSWERED);
    rig.status_feeds(&format!("{GATE_CLOSED} ({UNANSWERED})"));
    within("the alert", || {
        rig.runtime_log().contains(&format!(
            "a control_sync to {NO_RELAY} went unanswered for 30 s"
        ))
    });
    // B unanswered too (the Station's heads keep coming): C.
    rig.clock.add_mono(1_000);
    rig.station().heads_now();
    rig.clock.add_mono(30_000);
    let c = rig.station().hold_call(link);
    assert_eq!(sync_of(&c), rig.sync(1));
    assert_ne!(request_id(&c), request_id(&b));
    // The late answers, reordered: B's, then A's. Drained.
    rig.station().answer_held(b).unwrap();
    rig.station().answer_held(a).unwrap();
    rig.until_feed("both drained", |f| f["drained"] == 2);
    rig.two_passes();
    assert_eq!(
        rig.part(&principal),
        Some(covered.clone()),
        "nothing applied"
    );
    assert_eq!(rig.cursor(), Some(1));
    assert_eq!(rig.feed()["faults"], 0);
    assert!(!rig.gate_open());
    // The live call's page: applied, the gate opens.
    rig.station().answer_held(c).unwrap();
    rig.until_feed("the live page", |f| f["synced"]["cursor"] == 2);
    assert_ne!(rig.part(&principal), Some(covered), "the hold applied");
    rig.serve_until("open again", |rig| rig.gate_open());
    assert_eq!(rig.feed()["drained"], 2);
}

/// Ruling C1b-a, probes F and G at binary level (Astation's "same-socket
/// re-authentication"): Astation re-authenticates the host's link (a new
/// link generation on the same socket) while a `control_sync` is in
/// flight. The call is retired; the new generation asks at its `heads`
/// with a fresh id; the old call's page, arriving after, is drained. Pages
/// of at most 64 records never carry the host past a revoke (F), and a
/// rollback found on the new generation is read from 0 at once, the old
/// continuation's page (from the regrown feed) never taken for it (G). The
/// revokes apply; the service's queued task is cancelled, never run.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_HOST_CLOCK and ATEM_TEST_STATE_DUMP hooks"
)]
fn a_reauthentication_mid_read_never_reads_past_a_revoke() {
    // F: 64-record pages, the revoke on the third.
    {
        let rig = Rig::full(Via::Local);
        let link = rig.link();
        let mut r = Router::on(&rig.astation, link);
        rig.cover_and_open();
        let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
        let launch = svc.session(&mut r);
        for n in 0..128 {
            rig.append(&format!("svc-filler-{n}"), ControlAction::Cover);
        }
        rig.append(
            SVC,
            ControlAction::Revoke {
                interrupt_running: false,
            },
        );
        rig.append("svc-last", ControlAction::Cover);
        rig.clock.add_mono(1_000);
        let first = {
            let mut station = rig.station();
            station.heads_now();
            station.hold_call(link)
        };
        assert_eq!(sync_of(&first), rig.sync(1));
        rig.station().answer_held(first).unwrap();
        let old = rig.station().hold_call(link);
        assert_eq!(sync_of(&old), rig.sync(65));
        let t = task(IDS, &launch, "PAST_THE_REVOKE", HOUR);
        enqueue(&mut svc, &mut r, &t);
        wait_stored(&rig, &t["task_id"], "blocked", GATE_CLOSED);
        // Re-authenticated mid-read: the new generation asks afresh.
        reauthenticate(&rig, 0xd);
        assert_eq!(rig.feed()["in_flight"], Value::Null, "retired");
        rig.clock.add_mono(1_000);
        let new = {
            let mut station = rig.station();
            station.heads_now();
            station.hold_call(link)
        };
        assert_eq!(sync_of(&new), rig.sync(65));
        assert_ne!(request_id(&new), request_id(&old));
        // The old call's page: drained.
        rig.station().answer_held(old).unwrap();
        rig.until_feed("the old page drained", |f| f["drained"] == 1);
        assert_eq!(rig.cursor(), Some(65));
        assert!(!rig.gate_open());
        // The new call's page, then the rest.
        rig.station().answer_held(new).unwrap();
        rig.serve_until("read to the head", |rig| {
            rig.cursor() == Some(131) && rig.gate_open()
        });
        wait_stored(&rig, &t["task_id"], "cancelled", REVOKED);
        let afters: Vec<_> = rig.syncs().iter().map(|s| s.after).collect();
        assert_eq!(afters, [0, 1, 65, 65, 129], "{afters:?}");
        assert_eq!(rig.feed()["faults"], 0);
        never_ran(&rig, &t["task_id"], "PAST_THE_REVOKE");
    }
    // G: a rollback found on the new generation; the old continuation's
    // page from the regrown feed.
    {
        let rig = Rig::full(Via::Local);
        let link = rig.link();
        let mut r = Router::on(&rig.astation, link);
        rig.cover_and_open();
        let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
        let launch = svc.session(&mut r);
        rig.append("svc-other", ControlAction::Cover);
        rig.append("svc-third", ControlAction::Cover);
        rig.clock.add_mono(1_000);
        rig.announce();
        rig.serve_until("the feed read to 3", |rig| rig.cursor() == Some(3));
        rig.append("svc-fourth", ControlAction::Cover);
        rig.append("svc-fifth", ControlAction::Cover);
        rig.clock.add_mono(1_000);
        let old = {
            let mut station = rig.station();
            station.heads_now();
            station.hold_call(link)
        };
        assert_eq!(sync_of(&old), rig.sync(3));
        let t = task(IDS, &launch, "PAST_THE_ROLLBACK", HOUR);
        enqueue(&mut svc, &mut r, &t);
        wait_stored(&rig, &t["task_id"], "blocked", GATE_CLOSED);
        // The Station rolls back to 1; re-authenticated (the service's
        // channel ends with its link generation); the rollback found and
        // read from 0 at once.
        rig.station().truncate(1);
        reauthenticate(&rig, 0xe);
        rig.clock.add_mono(1_000);
        let new = {
            let mut station = rig.station();
            station.heads_now();
            station.hold_call(link)
        };
        assert_eq!(sync_of(&new), rig.sync(0), "the read from 0");
        assert_eq!(rig.reset_marks(), [(NO_RELAY.to_string(), String::new())]);
        rig.until_feed("the reset", |f| f["closed"] == RESET);
        // Regrown with other records, a revoke at 2; then the old call's
        // page: drained.
        rig.append(
            SVC,
            ControlAction::Revoke {
                interrupt_running: false,
            },
        );
        rig.append("svc-new-3", ControlAction::Cover);
        rig.append("svc-new-4", ControlAction::Cover);
        rig.append("svc-new-5", ControlAction::Cover);
        rig.station().answer_held(old).unwrap();
        rig.until_feed("the old page drained", |f| f["drained"] == 1);
        assert_eq!(rig.cursor(), Some(3));
        assert_eq!(rig.reset_marks(), [(NO_RELAY.to_string(), String::new())]);
        // The read from 0.
        rig.station().answer_held(new).unwrap();
        rig.serve_until("read from 0", |rig| {
            rig.reset_marks().is_empty() && rig.gate_open()
        });
        wait_stored(&rig, &t["task_id"], "cancelled", REVOKED);
        let afters: Vec<_> = rig.syncs().iter().map(|s| s.after).collect();
        assert_eq!(afters, [0, 1, 3, 0], "{afters:?}");
        assert_eq!(rig.cursor(), Some(5));
        never_ran(&rig, &t["task_id"], "PAST_THE_ROLLBACK");
    }
}

/// Ruling C1b-a (Astation's "routed upgrade"): a routed host (no Astation
/// in the room) has a `control_sync` in flight when Astation authenticates
/// its routed link: a new link generation on the same socket. The call is
/// retired, and its page, arriving after, is drained; the new generation
/// asks again at its `heads` with a fresh id, and its gate opens only once
/// that page is read.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_HOST_CLOCK and ATEM_TEST_STATE_DUMP hooks"
)]
fn a_routed_upgrade_retires_the_call_and_asks_afresh() {
    let rig = Rig::full(Via::Routed);
    let link = rig.link();
    rig.cover_and_open();
    assert_eq!(rig.dump()["station"]["link"]["kind"], "routed");
    let principal = format!("service:{SVC}");
    let covered = rig.part(&principal).unwrap();
    rig.append(SVC, ControlAction::Hold);
    rig.clock.add_mono(1_000);
    let old = {
        let mut station = rig.station();
        station.heads_now();
        station.hold_call(link)
    };
    assert_eq!(sync_of(&old), rig.sync(1));
    // Astation authenticates the routed link.
    reauthenticate(&rig, 0xa);
    let station = rig.until_station("the upgrade", |s| s["link"]["kind"] == "relay");
    assert_eq!(station["feed"]["in_flight"], Value::Null, "retired");
    rig.clock.add_mono(1_000);
    let new = {
        let mut station = rig.station();
        station.heads_now();
        station.hold_call(link)
    };
    assert_eq!(sync_of(&new), rig.sync(1));
    assert_ne!(request_id(&new), request_id(&old));
    // The old call's page: drained.
    rig.station().answer_held(old).unwrap();
    rig.until_feed("the old page drained", |f| f["drained"] == 1);
    assert_eq!(rig.part(&principal), Some(covered.clone()));
    assert!(!rig.gate_open());
    // The new call's page: read; open.
    rig.station().answer_held(new).unwrap();
    rig.serve_until("open", |rig| rig.cursor() == Some(2) && rig.gate_open());
    assert_ne!(rig.part(&principal), Some(covered));
    assert_eq!(rig.dump()["station"]["link"]["kind"], "relay");
}

/// Ruling C1b-a (Astation's "a reset between call and result"): the Station
/// rolls its feed back under the same id while the host's continuation is
/// in flight, and answers it: its `head` below the echoed `after`, with no
/// record. A reset: the host writes its durable mark, never moves the
/// cursor on that page, and reads the feed from 0 at once (the gate closed
/// until done: the read reaches the head the next `heads` announces).
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_HOST_CLOCK and ATEM_TEST_STATE_DUMP hooks"
)]
fn a_reset_between_call_and_result_is_read_from_0() {
    let rig = Rig::full(Via::Local);
    let link = rig.link();
    rig.cover_and_open();
    rig.append("svc-other", ControlAction::Cover);
    rig.append("svc-third", ControlAction::Cover);
    rig.clock.add_mono(1_000);
    rig.announce();
    rig.serve_until("the feed read to 3", |rig| {
        rig.cursor() == Some(3) && rig.gate_open()
    });
    rig.append("svc-fourth", ControlAction::Cover);
    rig.clock.add_mono(1_000);
    let call = {
        let mut station = rig.station();
        station.heads_now();
        station.hold_call(link)
    };
    assert_eq!(sync_of(&call), rig.sync(3));
    // Rolled back to 1 (no heads), then the call answered: head 1, after 3.
    rig.station().truncate(1);
    let from_0 = {
        let mut station = rig.station();
        station.answer_held(call).unwrap();
        station.hold_call(link)
    };
    assert_eq!(sync_of(&from_0), rig.sync(0), "the read from 0, at once");
    assert_eq!(rig.reset_marks(), [(NO_RELAY.to_string(), String::new())]);
    assert_eq!(rig.cursor(), Some(3), "never moved on that page");
    rig.until_feed("the reset", |f| f["closed"] == RESET);
    assert!(!rig.gate_open());
    // The read from 0, read up to the head announced next.
    rig.station().answer_held(from_0).unwrap();
    rig.serve_until("the read from 0", |rig| rig.cursor() == Some(1));
    rig.clock.add_mono(30_000);
    rig.open_gate();
    assert_eq!(rig.cursor(), Some(1));
    assert!(rig.reset_marks().is_empty());
}

/// Ruling C1b-a (Astation's "mismatched echoes"): a page carrying the live
/// call's id that doesn't answer it (another `after`, feed or origin) is a
/// Station fault: nothing of it applies (the revoke it carries included),
/// the gate stays closed with the fault's alert, and `atem status` says
/// which echo. The call is retired: the Station's own page for it,
/// arriving after, is drained; past the 30-second pause the call goes
/// again with a fresh id. A page with an id the host never sent is
/// unsolicited, a fault too, and the live call stays live: its page
/// applies (the revoke: the queued task is cancelled), and a page asked
/// after the fault opens the gate.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_HOST_CLOCK and ATEM_TEST_STATE_DUMP hooks"
)]
fn mismatched_echoes_and_unsolicited_pages_apply_nothing() {
    let rig = Rig::full(Via::Local);
    let link = rig.link();
    let mut r = Router::on(&rig.astation, link);
    rig.cover_and_open();
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    let principal = format!("service:{SVC}");
    let covered = rig.part(&principal).unwrap();
    rig.append(
        SVC,
        ControlAction::Revoke {
            interrupt_running: false,
        },
    );
    // The Station's page for the held call, as the builder writes it, then
    // `edit`ed.
    let page_for = |held: &Held, edit: &dyn Fn(&mut ControlSyncResult)| {
        let ToStation::ControlSync(call) = held.call().unwrap() else {
            panic!("a control_sync");
        };
        let station = rig.station();
        let records: Vec<FeedEntry> = station
            .records()
            .into_iter()
            .filter(|(seq, _)| *seq > call.after)
            .map(|(seq, record)| FeedEntry::new(seq, record))
            .collect();
        let mut page = ControlSyncResult {
            request_id: call.request_id,
            origin: rig.origin(),
            feed_id: station.feed_id().to_string(),
            after: call.after,
            head: 2,
            station_time: r9log::host_now().wall_ms,
            records,
        };
        edit(&mut page);
        page.to_json().unwrap().to_string()
    };
    let t = task(IDS, &launch, "BEHIND_A_MISMATCH", HOUR);
    let cases = [
        ("after", OTHER_AFTER),
        ("feed", OTHER_FEED),
        ("origin", OTHER_ORIGIN),
    ];
    for (n, (what, text)) in cases.into_iter().enumerate() {
        let edit = |p: &mut ControlSyncResult| match what {
            "after" => p.after = 0,
            "feed" => p.feed_id = uuid(),
            _ => p.origin = "https://station-other.test".into(),
        };
        let n = n as u64 + 1;
        rig.clock.add_mono(if n == 1 { 1_000 } else { 30_000 });
        let held = {
            let mut station = rig.station();
            station.heads_now();
            station.hold_call(link)
        };
        assert_eq!(sync_of(&held), rig.sync(1), "{what}");
        rig.astation.send(link, page_for(&held, &edit));
        rig.until_feed(&format!("the {what} fault"), |f| f["faults"] == n);
        let feed = rig.feed();
        assert_eq!(feed["closed"], text, "{what}");
        assert_eq!(feed["in_flight"], Value::Null, "{what}: retired");
        assert_eq!(rig.cursor(), Some(1), "{what}");
        assert_eq!(rig.part(&principal), Some(covered.clone()), "{what}");
        assert!(!rig.gate_open());
        rig.status_feeds(&format!("{GATE_CLOSED} ({text})"));
        if n == 1 {
            enqueue(&mut svc, &mut r, &t);
            wait_stored(&rig, &t["task_id"], "blocked", GATE_CLOSED);
            within("the fault alert", || {
                rig.runtime_log().contains(OTHER_AFTER)
            });
        }
        // The Station's own page for it, late: drained.
        rig.station().answer_held(held).unwrap();
        rig.until_feed(&format!("{what}: drained"), |f| f["drained"] == n);
        assert_eq!(rig.part(&principal), Some(covered.clone()), "{what}");
    }
    // An id never sent: unsolicited; the live call kept.
    rig.clock.add_mono(30_000);
    let held = {
        let mut station = rig.station();
        station.heads_now();
        station.hold_call(link)
    };
    rig.astation
        .send(link, page_for(&held, &|p| p.request_id = uuid()));
    rig.until_feed("the unsolicited page", |f| f["unsolicited"] == 1);
    assert_eq!(rig.feed()["closed"], UNSOLICITED);
    assert_eq!(rig.feed()["in_flight"]["after"], 1, "the live call kept");
    assert_eq!(rig.part(&principal), Some(covered));
    rig.status_feeds(&format!("{GATE_CLOSED} ({UNSOLICITED})"));
    // Its own page: the revoke applies; a page asked after the fault opens
    // the gate.
    rig.station().answer_held(held).unwrap();
    wait_stored(&rig, &t["task_id"], "cancelled", REVOKED);
    rig.serve_until("open again", |rig| rig.gate_open());
    assert_eq!(rig.cursor(), Some(2));
    never_ran(&rig, &t["task_id"], "BEHIND_A_MISMATCH");
}

/// Wire rule 11, ruling C1b-a: a page holding a record at or below its own
/// `after` doesn't read: the reader refuses it (`malformed`), a Station
/// fault. Nothing of it applies (the revoke it carries included), the
/// cursor stays, the gate stays closed with the fault's alert, and `atem
/// status` says why. Its id can't be read, so it is taken as the live
/// call's answer: that call is retired, and the Station's own page for it,
/// arriving after, is drained. Past the 30-second pause the call goes
/// again with a fresh id, and its page applies the revoke.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_HOST_CLOCK and ATEM_TEST_STATE_DUMP hooks"
)]
fn a_page_that_doesnt_read_applies_nothing_and_retires_the_call() {
    let rig = Rig::full(Via::Local);
    let link = rig.link();
    let mut r = Router::on(&rig.astation, link);
    rig.cover_and_open();
    let mut svc = Dev::new(&mut r, IDS, &rig.log, SVC, true);
    let launch = svc.session(&mut r);
    let principal = format!("service:{SVC}");
    let covered = rig.part(&principal).unwrap();
    rig.append(
        SVC,
        ControlAction::Revoke {
            interrupt_running: false,
        },
    );
    rig.clock.add_mono(1_000);
    let call = {
        let mut station = rig.station();
        station.heads_now();
        station.hold_call(link)
    };
    assert_eq!(sync_of(&call), rig.sync(1));
    // Its id and `after`, records 1 and 2 (1 at its `after`): written by
    // hand, the builder refuses it.
    let page = {
        let station = rig.station();
        let records: Vec<Value> = station
            .records()
            .into_iter()
            .map(|(seq, record)| json!({"feed_seq": seq, "record": FeedEntry::new(seq, record).raw()}))
            .collect();
        json!({"type": "relay", "op": "control_sync_result", "request_id": request_id(&call),
            "origin": rig.origin(), "feed_id": station.feed_id(), "after": 1, "head": 2,
            "station_time": r9log::host_now().wall_ms, "records": records})
        .to_string()
    };
    assert_eq!(
        ControlSyncResult::decode(page.as_bytes()),
        Err(RelayError::Malformed("feed_seq"))
    );
    rig.astation.send(link, page);
    rig.until_feed("the fault", |f| f["faults"] == 1);
    assert_eq!(rig.feed()["closed"], MALFORMED);
    assert_eq!(rig.feed()["in_flight"], Value::Null, "retired");
    assert_eq!(rig.cursor(), Some(1));
    assert_eq!(rig.part(&principal), Some(covered.clone()));
    assert!(!rig.gate_open());
    rig.status_feeds(&format!("{GATE_CLOSED} ({MALFORMED})"));
    within("the fault alert", || rig.runtime_log().contains(MALFORMED));
    let t = task(IDS, &launch, "BEHIND_A_FAULT", HOUR);
    enqueue(&mut svc, &mut r, &t);
    wait_stored(&rig, &t["task_id"], "blocked", GATE_CLOSED);
    // The Station's own page for it: drained.
    rig.station().answer_held(call).unwrap();
    rig.until_feed("drained", |f| f["drained"] == 1);
    assert_eq!(rig.part(&principal), Some(covered));
    // Past the pause: asked again, the revoke applies.
    rig.clock.add_mono(30_000);
    rig.announce();
    rig.serve_until("the revoke read", |rig| rig.cursor() == Some(2));
    wait_stored(&rig, &t["task_id"], "cancelled", REVOKED);
    assert_eq!(rig.syncs().last(), Some(&rig.sync(1)));
    never_ran(&rig, &t["task_id"], "BEHIND_A_FAULT");
}

/// Ruling C1b-a (Astation's "late refusal"): a refusal names a call kind,
/// never a request, so a `control_sync_refused` the Station meant for a
/// retired call retires the live one. That costs liveness only: the live
/// call's page, arriving after, is drained, nothing applies, and the gate
/// stays closed (`atem status` says the Station refused) until a call
/// asked past the backoff, with a fresh id, is read.
#[test]
#[cfg_attr(
    not(debug_assertions),
    ignore = "needs the debug ATEM_TEST_HOST_FEATURES, ATEM_TEST_HOST_CLOCK and ATEM_TEST_STATE_DUMP hooks"
)]
fn a_late_refusal_retires_the_live_call_and_costs_liveness_only() {
    let rig = Rig::full(Via::Local);
    let link = rig.link();
    rig.cover_and_open();
    let principal = format!("service:{SVC}");
    let covered = rig.part(&principal).unwrap();
    rig.append(SVC, ControlAction::Hold);
    rig.clock.add_mono(1_000);
    let a = {
        let mut station = rig.station();
        station.heads_now();
        station.hold_call(link)
    };
    // A unanswered for 30 s: B asked.
    rig.clock.add_mono(31_000);
    let b = rig.station().hold_call(link);
    assert_eq!(sync_of(&b), rig.sync(1));
    assert_ne!(request_id(&a), request_id(&b));
    // A's refusal, late: it retires B.
    rig.astation.send(
        link,
        CallRefused {
            call: RefusedCall::ControlSync,
            code: RefusalCode::Forbidden,
        }
        .to_json()
        .unwrap()
        .to_string(),
    );
    rig.until_station("the refusal", |s| s["refusals"]["control_sync"] == 1);
    assert_eq!(rig.feed()["in_flight"], Value::Null);
    // B's page: drained.
    rig.station().answer_held(b).unwrap();
    rig.until_feed("B's page drained", |f| f["drained"] == 1);
    assert_eq!(rig.part(&principal), Some(covered.clone()));
    assert_eq!(rig.feed()["closed"], REFUSED);
    assert!(!rig.gate_open());
    rig.status_feeds(&format!("{GATE_CLOSED} ({REFUSED})"));
    drop(a);
    // Past the backoff: a fresh call, read; open.
    rig.clock.add_mono(30_000);
    rig.announce();
    rig.serve_until("open again", |rig| rig.gate_open());
    assert_ne!(rig.part(&principal), Some(covered), "the hold applied");
    assert_eq!(rig.syncs().last(), Some(&rig.sync(1)));
}

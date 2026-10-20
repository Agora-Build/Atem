//! The host-side r9 scenarios (`designs/protocol/fixtures/r9-*.json`, `side:
//! "host"`) against the real runtime: the `atem runtime` binary on a temp
//! profile whose device list is pinned to the vectors' log (as `atem pair`
//! writes it) and verified as the fixture's account and host, real `atem
//! worker` processes with the fake Claude Code in their PTYs (chat hooks, a
//! transcript and the real PermissionRequest hook), a local frontend on the
//! runtime's socket for local input, and a fake Astation that authenticates
//! the runtime's link, routes the clients' channels in the §R9.7a envelope
//! and plays the relay (§R9.9). The clients (phones, Macs, services,
//! browsers) speak `atem-ch1` through the envelope with the vectors' keys:
//! every `connect` is a full handshake and a `hello` carrying exactly the
//! fixture's entries; every reply is what the runtime sealed.
//!
//! Host actions, against real processes (debug-only hooks,
//! `src/runtime/test_hooks.rs`):
//! - clocks: the device list's host clock (`ATEM_TEST_HOST_CLOCK`: wall,
//!   monotonic, boot id) and the session host's clock
//!   (`ATEM_TEST_CLOCK_FILE`) are files the harness moves (`advance_ms`
//!   both, `set_wall_clock` the wall only);
//! - device-list faults (`ATEM_TEST_MEMBERSHIP_FAULTS`): `fail_next` for
//!   `fail_next_membership_write`, `crash_after_commit` for
//!   `crash_after_membership_commit` (the runtime kills itself); a lost
//!   rename (`disk: rename_lost`/`write_lost`) puts the file's bytes from
//!   before the faulted write back while the runtime is down;
//! - `hold_dispatch`, `hold_pty_writes`/`flush_pty_writes`: markers the
//!   broker and the workers read (`ATEM_TEST_PTY_FAULTS`);
//! - `restart_runtime` is SIGTERM (an orderly stop), `crash_runtime`
//!   SIGKILL; the next runtime starts with the fixture's epoch and adopts
//!   the workers;
//! - `open_approval`: the fake Claude asks for a tool call (the real hook
//!   runs); `close_approval answered_terminal`: the user allows it in the
//!   agent's dialog; `approval_applied ok`: the agent acts on its hook's
//!   answer by itself; `turn_complete`: the fake Claude ends its turn;
//! - `local_input`: the frontend's `input`;
//! - `unpair`: the real `atem unpair --yes`;
//! - services' `projects` scopes: the session's launch project key is the
//!   runtime's own (`local:work-<n>`, its cwd); its keyed hash comes from a
//!   table naming the fixture's hash (`ATEM_TEST_PROJECT_HASHES`; the
//!   fixtures name hashes, never a `K`).
//!
//! What the fixtures assert of the host is read from the runtime: its state
//! dump (`ATEM_TEST_STATE_DUMP`, written after each pass: the device list,
//! leases, receipts, control generations, channels, attachments), the real
//! files (`frozen_genesis`, `membership_applied`, the fault, carriage and
//! freeze records, cross-checked with the dump) and what the processes did
//! (the fake agent's input and hook answers, `written` acks, approval
//! messages). Runtime-chosen ids (session ids, process generations) are
//! translated both ways.
//!
//! Items that can't be expressed against real processes are listed with a
//! named reason (`Outcome::pending`); a whole scenario that can't be is
//! `not_expressible`. Nothing else is skipped: an unknown step or assert key
//! fails the run.

use super::support::astation::{Event, FakeAstation, write_verified_pairing};
use super::{Frontend, PASTE_END, PASTE_START, find, replace_strings};
use atem_client::canonical::StrictValue;
use atem_client::channel::wire::{self as chwire, Frame};
use atem_client::channel::{Channel, Initiator, Principal};
use atem_client::encoding::{Hash32, b64u};
use atem_client::membership::{Entry, Head, HostNow, Membership};
use atem_client::{KeyId, SignedObject, SoftwareKeys};
use base64::Engine as _;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap, VecDeque};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const WAIT: Duration = Duration::from_secs(20);
/// Time the runtime gets to act on what it was sent.
const SETTLE: Duration = Duration::from_millis(400);
/// How long a host state may take to reach its expected value.
const SETTLE_STATE: Duration = Duration::from_secs(6);
/// What Atem tells the agent for a deny without a message.
const DEFAULT_DENY: &str = "Denied from Astation";

// ── What a run reports ───────────────────────────────────────────────────

/// A scenario's result: items checked and items not expressible, each with
/// its reason.
#[derive(Debug, Default)]
pub struct Outcome {
    pub checked: usize,
    pub pending: Vec<(String, String)>,
}

/// Reasons shared by several items.
const NO_CEREMONY: &str = "re-pairing needs Astation's signed deviceVerified (the §R9.2 ceremony with Touch ID), which the fake Astation can't produce; the frozen-genesis refusal runs on the real store in the in-process host runner (membership::fixtures_tests) against the frozen_genesis file this real runtime wrote, checked by the next assert";
const CLIENT_SIDE: &str =
    "the client's side of the handshake (atem-client's channel_fixtures, on the vectors)";
const VECTOR_BYTES: &str = "the vector's exact bytes (fixed ephemeral keys and nonces: atem-client's channel_fixtures); here the same step runs on a live handshake";
const STALL: &str = "not expressed without a hook that stalls Atem's link writer: the link is a real WebSocket, and a peer that stops reading leaves up to tcp_wmem + tcp_rmem (4 MiB + 6 MiB here) in kernel buffers before Atem's own queue holds anything, so 'queued output passes 4 MiB' can't be produced from outside at a known step; the per-channel 4 MiB bound runs on the engine (r9::fixtures_tests::the_envelope_fixtures_pass_on_the_engine)";
const OUTSIDE_LOG: &str = "host-b's add_host is outside the vectors (the fixture's note): the real runtime opens that device list but refuses every r9 channel to a host its list doesn't name (host_channel_key isn't the key the device list names for host-b), and an add_host signed for it with the vectors' dev-mac key would take seq 6, which E6 and S6_phone need; so its chain side runs on the real runtime B as its own relay fetch (ATEM_TEST_MEMBERSHIP_FAULTS/carry.json, §R9.3: no more trust than any carrier) and is checked on its state, while the welcome or fence a channel would carry can't be";

/// Why a whole file can't run against the real runtime, if it can't: it
/// has no host side (and which runner covers it).
pub fn not_expressible(scenario: &Value) -> Option<String> {
    let name = scenario["name"].as_str().unwrap_or_default();
    if scenario["side"] == "host" && scenario["kind"] == "scenario" {
        return None;
    }
    Some(match (scenario["kind"].as_str(), scenario["side"].as_str()) {
        (Some("vectors"), _) if name == "r9-envelope-vectors" => {
            "known-answer envelope vectors (exact bytes), no host process: src/session_protocol/r9/envelope.rs tests".into()
        }
        (Some("vectors"), _) => "known-answer vectors (exact bytes), no host process: crates/atem-client/tests/vectors.rs (and channel_fixtures.rs for the handshake)".into(),
        (_, Some("client")) if name == "r9-handshake-wrong-head" => {
            "the client refusing an accept with the wrong head: no host acts in it (crates/atem-client/tests/channel_fixtures.rs)".into()
        }
        (_, Some("client")) => "the client's K backup and restore machines (relay CAS, envelopes, the kit): no host acts in it (crates/atem-client/tests/scenarios.rs)".into(),
        (_, Some("relay")) if name.starts_with("r9-chain-") => {
            "the relay's CAS appends: Astation's relay; Atem's reference check is crates/atem-client/tests/scenarios.rs (and membership_e2e::honest_concurrent_appends_never_fork)".into()
        }
        (_, Some("relay")) => "the relay's push schedule, skew and seen handling: Astation's relay; Atem runs it against atem-client's reference relay (crates/atem-client/tests/r9_fixtures.rs)".into(),
        (k, s) => format!("{k:?}/{s:?}: no host side"),
    })
}

// ── Vectors and keys ─────────────────────────────────────────────────────

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("designs/protocol/fixtures")
}

fn load(name: &str) -> Value {
    serde_json::from_slice(&std::fs::read(fixtures_dir().join(format!("{name}.json"))).unwrap())
        .unwrap()
}

struct Vectors {
    by_label: BTreeMap<String, Value>,
}

impl Vectors {
    fn vector(&self, label: &str) -> &Value {
        self.by_label
            .get(label)
            .unwrap_or_else(|| panic!("no vector {label}"))
    }

    fn wire(&self, label: &str) -> &Value {
        &self.vector(label)["entry"]
    }

    fn strict(&self, label: &str) -> StrictValue {
        StrictValue::parse(self.wire(label).to_string().as_bytes(), usize::MAX).unwrap()
    }

    fn entry(&self, label: &str) -> Entry {
        Entry::from_strict(&self.strict(label)).unwrap()
    }

    fn hash(&self, label: &str) -> Hash32 {
        Hash32::from_hex(self.vector(label)["entry_hash"].as_str().unwrap()).unwrap()
    }

    fn head(&self, label: &str) -> Head {
        Head {
            seq: self.wire(label)["body"]["seq"].as_u64().unwrap(),
            hash: self.hash(label),
        }
    }
}

fn vectors() -> &'static Vectors {
    static V: std::sync::OnceLock<Vectors> = std::sync::OnceLock::new();
    V.get_or_init(|| {
        let file = load("r9-vectors-membership-log");
        let mut by_label = BTreeMap::new();
        for list in ["log", "others"] {
            for v in file[list].as_array().unwrap() {
                by_label.insert(v["label"].as_str().unwrap().to_owned(), v.clone());
            }
        }
        Vectors { by_label }
    })
}

/// Every client key of `r9-vectors-keys` as `<name>/auth`.
fn key_book() -> SoftwareKeys {
    let keys = load("r9-vectors-keys")["keys"].clone();
    let mut book = SoftwareKeys::new();
    for (name, entry) in keys.as_object().unwrap() {
        let key = match entry.get("auth") {
            Some(auth) => auth,
            None if entry.get("alg").is_some() && entry.get("secret_hex").is_some() => entry,
            None => continue,
        };
        let secret = Hash32::from_hex(key["secret_hex"].as_str().unwrap())
            .unwrap()
            .0;
        let id = KeyId::new(format!("{name}/auth"));
        match key["alg"].as_str() {
            Some("p256") => book.insert_p256(id, &secret).unwrap(),
            _ => book.insert_ed25519(id, &secret),
        }
    }
    book
}

/// host-a's `host_channel_key` seed (`r9-vectors-keys`).
fn host_a_seed() -> [u8; 32] {
    let hex = load("r9-vectors-keys")["keys"]["host-a"]["host_key"]["secret_hex"]
        .as_str()
        .unwrap()
        .to_owned();
    Hash32::from_hex(&hex).unwrap().0
}

/// `a.b` paths in a JSON object (`x.#` is an array's length).
fn get_path(v: &Value, path: &str) -> Option<Value> {
    if let Some(found) = v.get(path) {
        return Some(found.clone());
    }
    let mut at = v;
    for part in path.split('.') {
        if part == "#" {
            return at.as_array().map(|a| json!(a.len()));
        }
        at = match part.parse::<usize>() {
            Ok(i) => at.get(i)?,
            Err(_) => at.get(part)?,
        };
    }
    Some(at.clone())
}

/// `${vector:<file>:<path>}`: a value of a vectors file.
fn vector_value(reference: &str) -> Value {
    let (file, path) = reference.split_once(':').unwrap();
    get_path(&load(file), path).unwrap_or_else(|| panic!("no {reference}"))
}

fn labels(v: &Value) -> Vec<String> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap().to_owned())
        .collect()
}

/// A record's plaintext as the inbox holds it: its `data`, with its
/// envelope type under `__type`.
fn record_value(plain: &[u8]) -> Value {
    let v: Value = serde_json::from_slice(plain).unwrap_or(Value::Null);
    let mut data = v.get("data").cloned().unwrap_or(Value::Null);
    if let Some(o) = data.as_object_mut() {
        o.insert("__type".into(), v["type"].clone());
    }
    data
}

fn client_ms() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64 + 1
}

fn private_dir(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
}

fn private_file(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

/// Writes `path` atomically (readers never see half of it).
fn replace(path: &Path, text: &str) {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, text).unwrap();
    std::fs::rename(&tmp, path).unwrap();
}

// ── One real host ────────────────────────────────────────────────────────

/// What Atem sent on a channel.
enum Out {
    Frame(Vec<u8>),
    Close(Option<String>),
}

/// A client's channel on one host.
struct Chan {
    handle: String,
    channel: Option<Channel>,
    /// Its `welcome.attachment_gen` and `controller_session`, once welcomed.
    attachment: Option<String>,
    controller: Option<String>,
    /// Frames before the channel opened (handshake replies).
    raw: VecDeque<Vec<u8>>,
    /// Atem closed it (with this reason).
    closed: Option<Option<String>>,
    finish: Option<Vec<u8>>,
    /// The records Atem sent on it, as received.
    received: Vec<Vec<u8>>,
    /// The records this client sent, as sent.
    sent: Vec<Vec<u8>>,
    listed: bool,
}

struct Sess {
    fixture_id: String,
    real_id: String,
    real_gen: String,
    dir: PathBuf,
}

/// A tool call the fake agent asked for (`ask-<n>.json`).
struct Ask {
    n: usize,
    dir: PathBuf,
    approval_id: String,
}

struct Rt {
    name: String,
    sandbox: super::Sandbox,
    astation: FakeAstation,
    frontend: Option<Frontend>,
    host_clock: PathBuf,
    mfaults: PathBuf,
    dump: PathBuf,
    projects: PathBuf,
    env_limit: bool,
    spec: Value,
    host_id: String,
    account: String,
    /// The vectors' log this host was pinned to (a client's view of it
    /// before anything was carried).
    in_log: bool,
    now: HostNow,
    session_clock: u64,
    link: u64,
    authenticated: u64,
    /// What arrived per handle and isn't taken yet.
    out: HashMap<String, VecDeque<Out>>,
    /// Envelopes Atem sent, in order (close envelopes for `expect_envelope`).
    envelopes: Vec<Value>,
    /// Link messages that aren't envelopes or relay messages (r8 replies).
    other: VecDeque<Value>,
    /// Relay messages (§R9.9) no `expect_relay` took yet.
    relay: VecDeque<Value>,
    sessions: Vec<Sess>,
    ids: Vec<(String, String)>,
    chans: BTreeMap<String, Chan>,
    handles: u64,
    asks: Vec<Ask>,
    /// Terminal input sent, in order: (real session id, local, bytes).
    chunks: Vec<(String, bool, Vec<u8>)>,
    dropped_acks: u64,
    approvals_opened: Vec<String>,
    approvals_closed: HashMap<String, String>,
    /// A `disk` mode's undo: the file's bytes before the faulted write.
    snapshot: Option<(PathBuf, Option<Vec<u8>>)>,
    restarts: u32,
}

impl Rt {
    fn config(&self) -> PathBuf {
        self.sandbox.config()
    }

    fn pairing(&self) -> PathBuf {
        self.config().join("pairing")
    }

    fn journal(&self) -> PathBuf {
        self.config().join("runtime").join("journal")
    }

    fn write_clocks(&self) {
        replace(
            &self.host_clock,
            &format!(
                "{} {} {}",
                self.now.wall_ms, self.now.mono_ms, self.now.boot_id
            ),
        );
        replace(&self.sandbox.clock, &self.session_clock.to_string());
    }

    fn start_runtime(&mut self) {
        let log = std::fs::File::create(
            self.sandbox
                .dir
                .path()
                .join(format!("runtime-{}.log", self.restarts)),
        )
        .unwrap();
        self.restarts += 1;
        self.sandbox.restarts = self.restarts;
        let mut command = Command::new(env!("CARGO_BIN_EXE_atem"));
        command
            .arg("runtime")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.sandbox.home)
            .env("XDG_RUNTIME_DIR", &self.sandbox.run)
            .env("ASTATION_WS", &self.astation.url)
            .env("ASTATION_RELAY_URL", "http://127.0.0.1:1")
            .env("ATEM_TEST_CLOCK_FILE", &self.sandbox.clock)
            .env("ATEM_TEST_PTY_FAULTS", &self.sandbox.faults)
            .env("ATEM_TEST_HOST_CLOCK", &self.host_clock)
            .env("ATEM_TEST_MEMBERSHIP_FAULTS", &self.mfaults)
            .env("ATEM_TEST_STATE_DUMP", &self.dump)
            .env("ATEM_TEST_PROJECT_HASHES", &self.projects)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log);
        if !self.env_limit {
            command.env("ATEM_TEST_NO_INIT_LIMIT", "1");
        }
        let _ = std::fs::remove_file(&self.dump);
        self.sandbox.runtime = Some(command.spawn().unwrap());
        self.frontend = Some(Frontend::connect(&self.sandbox.socket()));
        // `list` answers once the surviving workers are adopted.
        self.frontend.as_mut().unwrap().list();
    }

    fn frontend(&mut self) -> &mut Frontend {
        self.frontend.as_mut().unwrap()
    }

    fn logs(&self) -> String {
        let mut text = String::new();
        for i in 0..self.restarts {
            let path = self.sandbox.dir.path().join(format!("runtime-{i}.log"));
            text.push_str(&std::fs::read_to_string(path).unwrap_or_default());
        }
        text
    }

    /// The runtime stopped by itself (`crash_after_commit`).
    fn exited(&mut self) -> bool {
        self.sandbox
            .runtime
            .as_mut()
            .is_some_and(|c: &mut Child| c.try_wait().ok().flatten().is_some())
    }

    /// Takes in what the runtime sent for `time`.
    fn pump(&mut self, time: Duration) {
        let deadline = Instant::now() + time;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.astation.events.recv_timeout(left) {
                Ok(event) => self.event_in(event),
                Err(_) => return,
            }
        }
    }

    /// Takes in what already arrived (no wait).
    fn poll(&mut self) {
        while let Ok(event) = self.astation.events.try_recv() {
            self.event_in(event);
        }
    }

    fn event_in(&mut self, event: Event) {
        match event {
            Event::Authenticated(n) => self.authenticated = self.authenticated.max(n),
            Event::Message(n, value) if n == self.link => {
                if value["type"] == "channel" {
                    let handle = value["channel"].as_str().unwrap_or_default().to_string();
                    let out = match value["event"].as_str() {
                        Some("frame") => Out::Frame(serde_json::to_vec(&value["frame"]).unwrap()),
                        _ => Out::Close(value["reason"].as_str().map(str::to_string)),
                    };
                    if value["event"] != "frame" {
                        self.envelopes.push(value.clone());
                    }
                    self.out.entry(handle).or_default().push_back(out);
                } else if value["type"] == "relay" {
                    let mut value = value;
                    replace_strings(&mut value, &self.ids, false);
                    self.relay.push_back(value);
                } else {
                    self.other.push_back(value);
                }
            }
            Event::Message(..) => {}
        }
    }

    /// Waits for the runtime's next authenticated link.
    fn wait_link(&mut self) {
        let deadline = Instant::now() + WAIT;
        while self.authenticated <= self.link {
            let left = deadline.saturating_duration_since(Instant::now());
            assert!(
                !left.is_zero(),
                "{}: the link never authenticated",
                self.name
            );
            match self.astation.events.recv_timeout(left) {
                Ok(event) => self.event_in(event),
                Err(_) => panic!("{}: the link never authenticated", self.name),
            }
        }
        self.link = self.authenticated;
        self.out.clear();
    }

    fn send_raw(&self, text: String) {
        self.astation.send(self.link, text);
    }

    fn send_frame(&self, handle: &str, frame: &[u8]) {
        let frame = std::str::from_utf8(frame).unwrap();
        self.send_raw(format!(
            r#"{{"type":"channel","event":"frame","channel":{},"frame":{frame}}}"#,
            json!(handle)
        ));
    }

    /// The next thing Atem sent on `handle` within `wait`.
    fn next_on(&mut self, handle: &str, wait: Duration) -> Option<Out> {
        let deadline = Instant::now() + wait;
        loop {
            if let Some(out) = self.out.get_mut(handle).and_then(VecDeque::pop_front) {
                return Some(out);
            }
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return None;
            }
            if let Ok(event) = self
                .astation
                .events
                .recv_timeout(left.min(Duration::from_millis(50)))
            {
                self.event_in(event);
            }
        }
    }

    /// The runtime's state dump (`ATEM_TEST_STATE_DUMP`).
    fn state(&self) -> Value {
        std::fs::read_to_string(&self.dump)
            .ok()
            .and_then(|t| serde_json::from_str(&t).ok())
            .unwrap_or(Value::Null)
    }

    fn real(&self, fixture: &str) -> String {
        self.ids
            .iter()
            .find(|(f, _)| f == fixture)
            .map_or(fixture.to_string(), |(_, r)| r.clone())
    }

    fn client_of_handle(&self, handle: &str) -> Option<String> {
        self.chans
            .iter()
            .find(|(_, c)| c.handle == handle)
            .map(|(n, _)| n.clone())
    }

    fn client_of_attachment(&self, att: &str) -> Option<String> {
        self.chans
            .iter()
            .find(|(_, c)| c.attachment.as_deref() == Some(att))
            .map(|(n, _)| n.clone())
    }

    /// Records of open channels, decoded (fixture ids), for the inboxes;
    /// handshake frames kept for the connect; closes noted.
    fn records(&mut self) -> Vec<(String, Value)> {
        self.poll();
        let mut got = Vec::new();
        let handles: Vec<String> = self.out.keys().cloned().collect();
        for handle in handles {
            let Some(client) = self.client_of_handle(&handle) else {
                continue;
            };
            let queue: Vec<Out> = self.out.get_mut(&handle).unwrap().drain(..).collect();
            for out in queue {
                let chan = self.chans.get_mut(&client).unwrap();
                match out {
                    Out::Close(reason) => chan.closed = Some(reason),
                    Out::Frame(frame) => {
                        chan.received.push(frame.clone());
                        match (&mut chan.channel, &chan.attachment) {
                            (Some(ch), Some(_)) => match ch.open(&frame, client_ms()) {
                                Ok(plain) => got.push((client.clone(), record_value(&plain))),
                                Err(_) => chan.closed = Some(Some("unreadable".into())),
                            },
                            _ => chan.raw.push_back(frame),
                        }
                    }
                }
            }
        }
        let mut out = Vec::new();
        for (client, mut value) in got {
            replace_strings(&mut value, &self.ids, false);
            let op = value["op"].as_str().unwrap_or_default().to_string();
            let ty = value["__type"].as_str().unwrap_or_default().to_string();
            let id = value["approval_id"]
                .as_str()
                .unwrap_or_default()
                .to_string();
            match (ty.as_str(), op.as_str()) {
                ("terminal", "frame") => continue,
                ("terminal", "written") => {
                    if value["error"] == "control changed; not written" {
                        self.dropped_acks += 1;
                    }
                    continue;
                }
                ("session", "approval_request") if !self.approvals_opened.contains(&id) => {
                    self.approvals_opened.push(id)
                }
                ("session", "approval_closed") => {
                    let reason = value["reason"].as_str().unwrap_or_default().to_string();
                    self.approvals_closed.insert(id, reason);
                }
                _ => {}
            }
            out.push((client, value));
        }
        out
    }

    /// What each hook answered, in order: `(ask, behavior, decision)`.
    fn answers(&self) -> Vec<(&Ask, String, Value)> {
        let mut out = Vec::new();
        for s in &self.sessions {
            let events = std::fs::read_to_string(s.dir.join("events")).unwrap_or_default();
            for line in events.lines() {
                let mut parts = line.splitn(3, ' ');
                if parts.next() != Some("answer") {
                    continue;
                }
                let n: usize = parts.next().and_then(|n| n.parse().ok()).unwrap_or(0);
                let behavior = parts
                    .next()
                    .unwrap_or_default()
                    .split(' ')
                    .next()
                    .unwrap_or_default()
                    .to_string();
                let Some(ask) = self.asks.iter().find(|a| a.n == n && a.dir == s.dir) else {
                    continue;
                };
                let raw = std::fs::read_to_string(s.dir.join(format!("answer-{n}.json")))
                    .unwrap_or_default();
                let decision = serde_json::from_str::<Value>(&raw)
                    .map(|v| v["hookSpecificOutput"]["decision"].clone())
                    .unwrap_or(Value::Null);
                out.push((ask, behavior, decision));
            }
        }
        out
    }

    fn approval_decisions(&self) -> Value {
        let mut decisions = Vec::new();
        for (ask, behavior, decision) in self.answers() {
            let mut d = json!({"approval_id": ask.approval_id});
            match behavior.as_str() {
                "allow" => match decision["updatedPermissions"].as_array() {
                    Some(_) => d["decision"] = json!("allow_always"),
                    None => d["decision"] = json!("allow_once"),
                },
                "deny" => {
                    d["decision"] = json!("deny");
                    let message = decision["message"].as_str().unwrap_or_default();
                    if message != DEFAULT_DENY {
                        d["message"] = json!(message);
                    }
                }
                _ => continue,
            }
            decisions.push(d);
        }
        Value::from(decisions)
    }

    /// Counters from what the processes did (as the r8 runner counts them).
    fn counter(&mut self, key: &str) -> Value {
        let mut dispatches = 0u64;
        let (mut local, mut remote) = (0u64, 0u64);
        for s in &self.sessions {
            let input = std::fs::read(s.dir.join("input")).unwrap_or_default();
            let mut terminal = Vec::new();
            let mut rest = &input[..];
            while let Some(start) = find(rest, PASTE_START) {
                terminal.extend_from_slice(&rest[..start]);
                dispatches += 1;
                let after = &rest[start..];
                let end = find(after, PASTE_END).map_or(after.len(), |e| e + PASTE_END.len());
                rest = &after[end..];
            }
            terminal.extend_from_slice(rest);
            let mut at = 0;
            for (sid, is_local, bytes) in &self.chunks {
                if *sid == s.real_id && terminal[at..].starts_with(bytes) {
                    at += bytes.len();
                    if *is_local {
                        local += 1;
                    } else {
                        remote += 1;
                    }
                }
            }
            assert_eq!(
                at,
                terminal.len(),
                "{}: {} got input nobody sent: {:?}",
                self.name,
                s.fixture_id,
                String::from_utf8_lossy(&terminal[at..])
            );
        }
        let answers = self.answers();
        dispatches += answers.iter().filter(|(_, b, _)| b != "none").count() as u64;
        match key {
            "dispatches" => json!(dispatches),
            "pty_writes" => json!(local + remote),
            "pty_writes_local" => json!(local),
            "pty_writes_remote" => json!(remote),
            "pty_writes_dropped" => json!(self.dropped_acks),
            "approvals_pending" => json!(
                self.approvals_opened
                    .iter()
                    .filter(|id| !self.approvals_closed.contains_key(*id))
                    .count()
            ),
            "approval_decisions" => self.approval_decisions(),
            other => panic!("{}: counter {other}", self.name),
        }
    }
}

impl Drop for Rt {
    fn drop(&mut self) {
        // Hooks waiting on a held write never hang the sandbox's cleanup.
        let _ = std::fs::remove_file(self.sandbox.faults.join("hold"));
    }
}

// ── The runner ───────────────────────────────────────────────────────────

#[derive(Clone)]
struct ClientSpec {
    principal: String,
    key: String,
}

struct Runner {
    name: String,
    v: &'static Vectors,
    keys: SoftwareKeys,
    hosts: BTreeMap<String, Rt>,
    current: String,
    clients: BTreeMap<String, ClientSpec>,
    /// Messages each client got and no `expect` took yet.
    inbox: BTreeMap<String, Vec<Value>>,
    /// Messages each client got since the last action step.
    fresh: BTreeMap<String, usize>,
    outcome: Outcome,
    /// `crash_after_membership_commit` armed: the runtime gen and epoch of
    /// the restart after it.
    crash: Option<(String, u64)>,
    gens: u64,
    captures: BTreeMap<String, Value>,
    sessions: Vec<String>,
    /// Ids of the harness's own requests: their replies are invisible.
    harness_ids: BTreeSet<String>,
    stall: Stall,
    /// Clients admitted on a host outside the vectors' log, by host.
    outside: BTreeMap<String, String>,
    /// A client's next `expect` is about its admission on that host.
    outside_expect: BTreeMap<String, String>,
}

/// `stall_link` (not expressible, `STALL`): the steps up to the first
/// `assert` after `unstall_link` depend on it.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Stall {
    None,
    Skipped,
    After,
}

impl Runner {
    fn host(&mut self) -> &mut Rt {
        let name = self.current.clone();
        self.hosts.get_mut(&name).unwrap()
    }

    fn pass(&mut self) {
        self.outcome.checked += 1;
    }

    fn later(&mut self, what: impl Into<String>, why: &str) {
        self.outcome.pending.push((what.into(), why.into()));
    }

    fn uuid(&mut self) -> String {
        self.gens += 1;
        format!(
            "abcdef00-0000-4000-8000-{:012}",
            self.gens + (u64::from(std::process::id()) % 1000) * 1_000_000
        )
    }

    /// Strings with `${hash:L}`, `${vector:f:p}` and captures replaced.
    fn resolve(&self, value: &Value) -> Value {
        match value {
            Value::String(s) => {
                if let Some(label) = s.strip_prefix("${hash:").and_then(|t| t.strip_suffix('}')) {
                    return json!(self.v.hash(label).to_hex());
                }
                if let Some(r) = s
                    .strip_prefix("${vector:")
                    .and_then(|t| t.strip_suffix('}'))
                {
                    return vector_value(r);
                }
                if let Some(name) = s.strip_prefix("${").and_then(|t| t.strip_suffix('}'))
                    && let Some(v) = self.captures.get(name)
                {
                    return v.clone();
                }
                value.clone()
            }
            Value::Array(items) => Value::Array(items.iter().map(|i| self.resolve(i)).collect()),
            Value::Object(map) => Value::Object(
                map.iter()
                    .map(|(k, x)| (k.clone(), self.resolve(x)))
                    .collect(),
            ),
            other => other.clone(),
        }
    }

    fn setup(&mut self, file: &Value) {
        let setup = &file["setup"];
        let pinned_labels = labels(&setup["pinned"]);
        for client in setup["clients"].as_array().unwrap() {
            self.clients.insert(
                client["name"].as_str().unwrap().to_owned(),
                ClientSpec {
                    principal: client["principal"].as_str().unwrap().to_owned(),
                    key: client["key"].as_str().unwrap_or_default().to_owned(),
                },
            );
        }
        let steps = file["steps"].as_array().unwrap();
        let hold_dispatch = steps.iter().any(|s| s.get("hold_dispatch").is_some());
        // The envelope fixtures check the one-init-a-second limit (and
        // space their inits on the host clock); the others connect back to
        // back.
        let env_limit = steps.iter().any(|s| s.get("link_up").is_some());
        let mut specs = Vec::new();
        if let Some(host) = setup.get("host") {
            specs.push((String::new(), host.clone()));
        }
        if let Some(hosts) = setup.get("hosts") {
            for host in hosts.as_array().unwrap() {
                specs.push((host["name"].as_str().unwrap().to_owned(), host.clone()));
            }
            self.current = specs[0].0.clone();
        }
        let sessions: Vec<Value> = setup
            .get("sessions")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        self.sessions = sessions
            .iter()
            .map(|s| s["session_id"].as_str().unwrap().to_owned())
            .collect();
        let entries: Vec<Entry> = pinned_labels.iter().map(|l| self.v.entry(l)).collect();
        for (name, spec) in specs {
            let now = HostNow {
                wall_ms: spec["wall_clock_ms"].as_u64().unwrap(),
                mono_ms: 1_000,
                boot_id: "boot-1".into(),
            };
            let account = spec["account_id"].as_str().unwrap().to_owned();
            let host_id = spec["host_id"].as_str().unwrap().to_owned();
            let trust_gen = spec["host_trust_gen"].as_u64().unwrap();
            let m = Membership::verify_chain(&account, &self.v.hash("E1"), &entries, &now)
                .unwrap()
                .membership;
            let in_log = m.host(&host_id).is_some();
            let sandbox = super::Sandbox::new();
            let config = sandbox.config();
            write_verified_pairing(
                &config,
                &account,
                spec["atem_device_id"].as_str().unwrap(),
                trust_gen,
            );
            sandbox.next_epoch(spec["runtime_epoch"].as_u64().unwrap());
            // The pin, as `MembershipHost::pin` writes it.
            let pairing = config.join("pairing");
            let journal = config.join("runtime").join("journal");
            private_dir(&pairing);
            private_dir(&journal);
            let seed = host_a_seed();
            let host_pub = ed25519_dalek::SigningKey::from_bytes(&seed)
                .verifying_key()
                .to_bytes();
            private_file(
                &pairing.join("host_channel_key"),
                json!({"v": 1, "seed": b64u(&seed), "pub": b64u(&host_pub)})
                    .to_string()
                    .as_bytes(),
            );
            private_file(
                &journal.join("membership_applied"),
                json!({"seq": m.head().seq, "hash": m.head().hash.to_hex()})
                    .to_string()
                    .as_bytes(),
            );
            let mut state =
                json!({"v": 1, "host": {"host_id": host_id, "host_trust_gen": trust_gen}});
            for (k, v) in m.to_stored().as_object().unwrap() {
                state[k] = v.clone();
            }
            let tmp = pairing.join("membership.json.pin");
            private_file(&tmp, state.to_string().as_bytes());
            std::fs::rename(&tmp, pairing.join("membership.json")).unwrap();

            let mfaults = sandbox.dir.path().join("mfaults");
            std::fs::create_dir_all(&mfaults).unwrap();
            if hold_dispatch {
                std::fs::write(sandbox.faults.join("hold_dispatch"), "").unwrap();
            }
            // The launch project keys (the runtime's own: `local:<cwd's
            // name>`) and the fixture's hash of each.
            let mut table = serde_json::Map::new();
            for (i, s) in sessions.iter().enumerate() {
                if let Some(hash) = s["project"].as_str()
                    && let Some((kid, _)) = hash.strip_prefix("h1.").and_then(|r| r.split_once('.'))
                {
                    table.insert(format!("local:work-{i}"), json!({kid: hash}));
                }
            }
            let projects = sandbox.dir.path().join("projects.json");
            std::fs::write(&projects, Value::Object(table).to_string()).unwrap();
            let mut rt = Rt {
                name: format!("{} host {name}", self.name),
                host_clock: sandbox.dir.path().join("host-clock"),
                dump: sandbox.dir.path().join("state.json"),
                mfaults,
                projects,
                env_limit,
                astation: FakeAstation::start(),
                frontend: None,
                sandbox,
                spec: spec.clone(),
                host_id,
                account,
                in_log,
                now,
                session_clock: 0,
                link: 0,
                authenticated: 0,
                out: HashMap::new(),
                envelopes: Vec::new(),
                other: VecDeque::new(),
                relay: VecDeque::new(),
                sessions: Vec::new(),
                ids: Vec::new(),
                chans: BTreeMap::new(),
                handles: 0,
                asks: Vec::new(),
                chunks: Vec::new(),
                dropped_acks: 0,
                approvals_opened: Vec::new(),
                approvals_closed: HashMap::new(),
                snapshot: None,
                restarts: 0,
            };
            rt.write_clocks();
            rt.start_runtime();
            for (i, s) in sessions.iter().enumerate() {
                let dir = rt.sandbox.dir.path().join(format!("agent-{i}"));
                let work = rt.sandbox.home.join(format!("work-{i}"));
                std::fs::create_dir_all(&work).unwrap();
                let (agent, home) = (rt.sandbox.agent.clone(), rt.sandbox.home.clone());
                let frontend = rt.frontend();
                frontend.send(json!({
                    "op": "launch", "provider": "claude", "args": [], "cwd": work,
                    "env": [["PATH", "/usr/bin:/bin"], ["CLAUDE_CLI_BIN", agent],
                            ["FAKE_DIR", dir], ["HOME", home],
                            ["ATEM_TEST_SESSION_ID", s["session_id"]]],
                    "rows": 24, "cols": 80,
                }));
                let launched = frontend.until("launched", |_| true);
                let real_id = launched["session"]["id"].as_str().unwrap().to_string();
                let real_gen = launched["session"]["generation"]
                    .as_str()
                    .unwrap()
                    .to_string();
                frontend
                    .send(json!({"op": "attach", "session_id": real_id, "rows": 24, "cols": 80}));
                frontend.until("attached", |_| true);
                rt.ids
                    .push((s["session_id"].as_str().unwrap().into(), real_id.clone()));
                rt.ids
                    .push((s["process_gen"].as_str().unwrap().into(), real_gen.clone()));
                rt.sessions.push(Sess {
                    fixture_id: s["session_id"].as_str().unwrap().into(),
                    real_id,
                    real_gen,
                    dir,
                });
            }
            wait_sessions_ready(&mut rt);
            rt.wait_link();
            self.hosts.insert(name, rt);
        }
        // Wait for the project scopes' hashes (a service's first `list`).
        if sessions.iter().any(|s| s.get("project").is_some()) {
            std::thread::sleep(SETTLE);
        }
        let connected: Vec<String> = setup.get("connected").map(labels).unwrap_or_default();
        let leases: BTreeMap<String, u64> = setup
            .get("holds_lease")
            .and_then(Value::as_object)
            .map(|o| {
                o.iter()
                    .map(|(k, v)| (k.clone(), v.as_u64().unwrap()))
                    .collect()
            })
            .unwrap_or_default();
        let names: Vec<String> = self.clients.keys().cloned().collect();
        for c in &names {
            if connected.contains(c) || leases.contains_key(c) {
                let grant = setup["clients"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|x| x["name"] == c.as_str())
                    .and_then(|x| x.get("grant"))
                    .and_then(Value::as_str)
                    .map(|g| json!(format!("${{vector:{g}}}")));
                let mut step = json!({"connect": c, "carry": []});
                if let Some(g) = grant {
                    step["grant"] = g;
                }
                self.connect(&step);
                let welcomed = self
                    .inbox
                    .get(c)
                    .is_some_and(|i| i.iter().any(|m| m["op"] == "welcome"));
                assert!(
                    welcomed,
                    "{}: setup {c} wasn't welcomed: {:?}",
                    self.name,
                    self.inbox.get(c)
                );
                self.subscribe(c);
            }
        }
        for (c, epoch) in &leases {
            let sid = self.sessions[0].clone();
            let binding = self.binding(c, &sid, false);
            let id = self.uuid();
            self.harness_ids.insert(id.clone());
            let json = json!({"type": "session", "data": {"v": 1, "op": "acquire", "id": id,
                "binding": binding, "takeover": false}});
            self.send_json(c, &json);
            let real = self.host().real(&sid);
            self.settle_state(&format!("setup holds_lease {c}"), |s| {
                s["leases"][&real]["epoch"] == json!(epoch)
            });
        }
        self.drain();
        self.inbox.clear();
        self.fresh.clear();
        self.pass();
    }

    /// Waits until the dump satisfies `ok` (`SETTLE_STATE` at most).
    fn settle_state(&mut self, what: &str, ok: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + SETTLE_STATE;
        loop {
            self.drain();
            let state = self.host().state();
            if ok(&state) {
                return state;
            }
            if Instant::now() > deadline {
                panic!("{}: {what}: the runtime's state is {state}", self.name);
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Moves what every host sent its clients into their inboxes.
    fn drain(&mut self) {
        let names: Vec<String> = self.hosts.keys().cloned().collect();
        for name in names {
            let out = self.hosts.get_mut(&name).unwrap().records();
            for (client, value) in out {
                self.deliver(&client, value);
            }
        }
    }

    fn deliver(&mut self, client: &str, fields: Value) {
        if fields
            .get("re")
            .and_then(Value::as_str)
            .is_some_and(|re| self.harness_ids.contains(re))
        {
            return;
        }
        *self.fresh.entry(client.to_owned()).or_default() += 1;
        self.inbox
            .entry(client.to_owned())
            .or_default()
            .push(fields);
    }

    fn principal(&self, client: &str, grant: Option<&SignedObject>) -> Principal {
        let p = &self.clients[client].principal;
        match p.split_once(':').unwrap() {
            ("member", d) => Principal::Native {
                device_id: d.into(),
            },
            ("service", d) => Principal::Service {
                device_id: d.into(),
            },
            ("browser", _) => {
                Principal::browser(grant.expect("a browser connects with its grant")).unwrap()
            }
            other => panic!("principal {other:?}"),
        }
    }

    /// The device list the runtime holds now (`membership.json`): a
    /// client's verified view of it.
    fn host_log(&mut self) -> Membership {
        let host = self.host();
        let path = host.pairing().join("membership.json");
        let stored: Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        Membership::from_stored(&host.account, &vectors().hash("E1"), &stored)
            .unwrap_or_else(|e| panic!("membership.json: {e:?}"))
    }

    /// A full `atem-ch1` handshake through the envelope, then a `hello`
    /// carrying exactly the step's entries. `tamper` (handshake fixtures)
    /// spoils one part on the wire.
    fn connect(&mut self, step: &Value) {
        let client = step["connect"]
            .as_str()
            .or_else(|| step["reconnect"].as_str())
            .or_else(|| step["handshake"].as_str())
            .unwrap()
            .to_owned();
        if let Some(host) = step.get("host") {
            self.current = host.as_str().unwrap().to_owned();
        }
        if !self.host().in_log {
            return self.connect_outside_log(&client, step);
        }
        let transport = step
            .get("transport")
            .and_then(Value::as_str)
            .unwrap_or("relay")
            .to_owned();
        let tamper = step.get("tamper").cloned().unwrap_or(Value::Null);
        let carry = step.get("carry").map(labels).unwrap_or_default();
        let more = step.get("more").and_then(Value::as_bool).unwrap_or(false);
        let grant_json = step.get("grant").map(|g| self.resolve(g));
        let grant = grant_json.as_ref().map(|g| {
            SignedObject::from_strict(
                &StrictValue::parse(g.to_string().as_bytes(), usize::MAX).unwrap(),
            )
            .unwrap()
        });
        let principal = self.principal(&client, grant.as_ref());
        let key = KeyId::new(format!("{}/auth", self.clients[&client].key));
        let log = self.host_log();
        let v = self.v;
        let name = self.name.clone();
        let host = self.host();
        // A client that reconnects leaves its old channel (the router
        // closes it).
        if let Some(old) = host.chans.get(&client)
            && old.closed.is_none()
        {
            let close = json!({"type": "channel", "event": "close", "channel": old.handle,
                               "reason": "client_gone"});
            host.send_raw(close.to_string());
        }
        host.handles += 1;
        let handle = match step.get("channel").and_then(Value::as_str) {
            Some(h) => h.to_owned(),
            None => format!("{client}-{}", host.handles),
        };
        host.chans.insert(
            client.clone(),
            Chan {
                handle: handle.clone(),
                channel: None,
                attachment: None,
                controller: None,
                raw: VecDeque::new(),
                closed: None,
                finish: None,
                received: Vec::new(),
                sent: Vec::new(),
                listed: false,
            },
        );
        host.send_raw(
            json!({"type": "channel", "event": "open", "channel": handle,
                   "transport": transport})
            .to_string(),
        );
        let (await_accept, mut init) =
            Initiator::start(&log, &host.host_id, client_ms()).expect("the host is in the log");
        if let Some(e) = tamper.get("init.e").and_then(Value::as_str) {
            let mut frame: Value = serde_json::from_slice(&init).unwrap();
            frame["e"] = json!(e);
            init = frame.to_string().into_bytes();
        }
        host.send_frame(&handle, &init);
        let at_init = |code: &str| json!({"op": "channel_error", "code": code, "at": "init"});
        let accept = match host.next_on(&handle, WAIT) {
            Some(Out::Frame(f)) => f,
            Some(Out::Close(reason)) => {
                host.chans.get_mut(&client).unwrap().closed = Some(reason.clone());
                self.deliver(
                    &client,
                    json!({"op": "channel_error", "code": "closed", "at": "init", "reason": reason}),
                );
                self.pass();
                return;
            }
            None => panic!("{name}: {client}: no reply to init"),
        };
        host.chans
            .get_mut(&client)
            .unwrap()
            .received
            .push(accept.clone());
        if let Ok(Frame::Error { code }) = chwire::parse_frame(&accept) {
            self.deliver(&client, at_init(&code));
            self.pass();
            return;
        }
        let accepted = await_accept
            .on_frame(&accept, &log, client_ms())
            .unwrap_or_else(|e| panic!("{name}: {client}: accept refused: {e:?}"));
        let signed = accepted
            .sign(principal.clone(), &self.keys, &key)
            .unwrap_or_else(|e| panic!("{name}: {client}: signing: {e:?}"));
        let head = match step.get("client_head").and_then(Value::as_str) {
            Some(label) => v.head(label),
            None => match carry.last() {
                Some(label) => v.head(label),
                None => log.head(),
            },
        };
        let mut membership = json!({"head": head.to_json(),
            "entries": carry.iter().map(|l| v.wire(l).clone()).collect::<Vec<_>>()});
        if more {
            membership["more"] = json!(true);
        }
        let mut data = json!({"v": 1, "op": "hello", "id": self.uuid(), "revision": 9,
            "proof": {"principal": principal.to_json(), "sig": b64u(signed.sig_c())},
            "membership": membership});
        if let Some(g) = &grant_json {
            data["grant"] = g.clone();
        }
        if let Some(over) = step.get("hello").and_then(Value::as_object) {
            for (k, x) in over {
                data[k] = x.clone();
            }
        }
        if let Some(p) = tamper.get("hello.proof.principal") {
            data["proof"]["principal"] = p.clone();
        }
        let hello = atem_client::canonical::jcs(&json!({"type": "session", "data": data}))
            .unwrap()
            .into_bytes();
        let (channel, mut finish) = signed.finish(&hello, client_ms()).unwrap();
        if tamper.get("finish.ct").is_some() {
            let mut frame: Value = serde_json::from_slice(&finish).unwrap();
            let ct = frame["ct"].as_str().unwrap().to_string();
            let flipped = if ct.starts_with('A') { "B" } else { "A" };
            frame["ct"] = json!(format!("{flipped}{}", &ct[1..]));
            finish = frame.to_string().into_bytes();
        }
        let host = self.host();
        {
            let chan = host.chans.get_mut(&client).unwrap();
            chan.channel = Some(channel);
            chan.finish = Some(finish.clone());
        }
        host.send_frame(&handle, &finish);
        let first = host.next_on(&handle, WAIT);
        if self.crashed_now() {
            return;
        }
        let host = self.host();
        let ids = host.ids.clone();
        let chan = host.chans.get_mut(&client).unwrap();
        let mut mine = Vec::new();
        match first {
            None => panic!("{name}: {client}: no reply to finish"),
            Some(Out::Close(reason)) => {
                chan.closed = Some(reason.clone());
                mine.push(
                    json!({"op": "channel_error", "code": "closed", "at": "finish", "reason": reason}),
                );
            }
            Some(Out::Frame(frame)) => {
                chan.received.push(frame.clone());
                match chwire::parse_frame(&frame) {
                    Ok(Frame::Error { code }) => {
                        mine.push(json!({"op": "channel_error", "code": code, "at": "finish"}))
                    }
                    _ => {
                        let ch = chan.channel.as_mut().unwrap();
                        match ch.open(&frame, client_ms()) {
                            Ok(plain) => {
                                let mut value = record_value(&plain);
                                replace_strings(&mut value, &ids, false);
                                if value["op"] == "welcome" {
                                    chan.attachment =
                                        value["attachment_gen"].as_str().map(str::to_owned);
                                    chan.controller =
                                        value["controller_session"].as_str().map(str::to_owned);
                                }
                                mine.push(value);
                            }
                            Err(_) => mine.push(
                                json!({"op": "channel_error", "code": "handshake_failed", "at": "finish"}),
                            ),
                        }
                    }
                }
            }
        }
        for m in mine {
            self.deliver(&client, m);
        }
        // Records queued behind the welcome, and a refusal's close.
        self.host().pump(Duration::from_millis(100));
        self.drain();
        self.pass();
    }

    /// A host outside the vectors' log (the fixture's note): the entries
    /// reach the real runtime as its own relay fetch; the head it applied
    /// stands for the welcome's.
    fn connect_outside_log(&mut self, client: &str, step: &Value) {
        let carry = step.get("carry").map(labels).unwrap_or_default();
        let entries: Vec<Value> = carry.iter().map(|l| self.v.wire(l).clone()).collect();
        let host = self.host();
        let carried = host.mfaults.join("carried");
        let before = std::fs::read_to_string(&carried)
            .unwrap_or_default()
            .lines()
            .count();
        replace(
            &host.mfaults.join("carry.json"),
            &json!({ "entries": entries }).to_string(),
        );
        let deadline = Instant::now() + WAIT;
        loop {
            let lines = std::fs::read_to_string(&carried).unwrap_or_default();
            if lines.lines().count() > before {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "{}: the carriage never ran",
                self.name
            );
            std::thread::sleep(Duration::from_millis(50));
        }
        self.later(
            format!("{client}'s channel to host {}", self.current),
            OUTSIDE_LOG,
        );
        // No reply is made up: the `expect` that follows checks what B's
        // state can show (its head) and lists the rest not expressible.
        let host_name = self.current.clone();
        if self.host().state()["membership"]["frozen"] != true {
            self.outside.insert(client.to_owned(), host_name.clone());
        }
        self.outside_expect.insert(client.to_owned(), host_name);
        self.pass();
    }

    /// The `expect` right after an admission on a host outside the log:
    /// a welcome's `head` is checked against that host's real state; every
    /// other field, and a refusal, is not expressible (no channel carries
    /// it; a freeze is checked by the scenario's own `frozen` assert).
    fn expect_outside(&mut self, client: &str, host: &str, want: &Value) {
        let state = self.hosts[host].state();
        let head = &state["membership"]["head"];
        let mut checked = false;
        for (key, value) in want.as_object().unwrap() {
            let real = match key.as_str() {
                "head.seq" if want["op"] == "welcome" => &head["seq"],
                "head.hash" if want["op"] == "welcome" => &head["hash"],
                _ => {
                    self.later(format!("{client}: {key} on host {host}"), OUTSIDE_LOG);
                    continue;
                }
            };
            assert_eq!(real, value, "{}: host {host}'s {key}", self.name);
            checked = true;
        }
        if checked {
            self.pass();
        }
    }

    /// A crash armed by `crash_after_membership_commit` happened in the
    /// step just run: the runtime restarts (nothing it sent after counts).
    fn crashed_now(&mut self) -> bool {
        if self.crash.is_none() {
            return false;
        }
        let host = self.host();
        host.pump(SETTLE);
        let used = std::fs::read_to_string(host.mfaults.join("used")).unwrap_or_default();
        if !used.contains("crash_after_commit") {
            return false;
        }
        let deadline = Instant::now() + WAIT;
        while !host.exited() {
            assert!(Instant::now() < deadline, "the runtime didn't crash");
            std::thread::sleep(Duration::from_millis(20));
        }
        let (gen_, epoch) = self.crash.take().unwrap();
        self.restart(&gen_, epoch, None, None);
        self.pass();
        true
    }

    /// `client` sends `json` as a record on its channel.
    fn send_json(&mut self, client: &str, json: &Value) {
        let host = self.host();
        let mut json = json.clone();
        replace_strings(&mut json, &host.ids, true);
        let bytes = serde_json::to_vec(&json).unwrap();
        let chan = host
            .chans
            .get_mut(client)
            .unwrap_or_else(|| panic!("{client} has no channel"));
        let frame = chan
            .channel
            .as_mut()
            .unwrap()
            .seal(&bytes, client_ms())
            .unwrap_or_else(|e| panic!("{client}: can't send: {e:?}"));
        chan.sent.push(frame.clone());
        let handle = chan.handle.clone();
        host.send_frame(&handle, &frame);
        host.pump(Duration::from_millis(150));
        if self.crashed_now() {
            return;
        }
        self.drain();
    }

    fn send_membership(&mut self, step: &Value) {
        let client = step["send_membership"].as_str().unwrap().to_owned();
        let entries: Vec<Value> = labels(&step["entries"])
            .iter()
            .map(|l| self.v.wire(l).clone())
            .collect();
        let id = self.uuid();
        let json = json!({"type": "session", "data": {"v": 1, "op": "membership", "id": id,
            "entries": entries}});
        self.send_json(&client, &json);
        self.pass();
    }

    fn expect(&mut self, client: &str, want: &Value, kind: Option<&str>, capture: Option<&Value>) {
        let want = self.resolve(want);
        if let Some(host) = self.outside_expect.remove(client) {
            return self.expect_outside(client, &host, &want);
        }
        let op = want.get("op").and_then(Value::as_str);
        let picks = |m: &Value| {
            kind.is_none_or(|t| m["__type"] == t)
                && op.is_none_or(|op| m.get("op").and_then(Value::as_str) == Some(op))
                && ["code", "detail", "reason", "state", "re"].iter().all(|k| {
                    want.get(*k)
                        .is_none_or(|w| get_path(m, k).as_ref() == Some(w))
                })
        };
        // A client admitted on a host outside the vectors' log has no
        // channel there: the fence that host's freeze would send it can't
        // arrive (checked on the host's real state instead).
        let outside = self.outside.get(client).cloned();
        let wait = if outside.is_some() {
            Duration::from_secs(2)
        } else {
            WAIT
        };
        let deadline = Instant::now() + wait;
        let i = loop {
            self.drain();
            let inbox = self.inbox.entry(client.to_owned()).or_default();
            if let Some(i) = inbox.iter().position(picks) {
                break i;
            }
            if let Some(host) = &outside
                && Instant::now() > deadline
                && want["code"] == "account_frozen"
                && self.hosts[host].state()["membership"]["frozen"] == true
            {
                self.outside.remove(client);
                self.later(
                    format!("{client}: the account_frozen fence of its admission on host {host}"),
                    OUTSIDE_LOG,
                );
                return;
            }
            if Instant::now() > deadline {
                panic!(
                    "{}: {client} got no {want} (inbox {:?})",
                    self.name, self.inbox[client]
                );
            }
            self.host().pump(Duration::from_millis(50));
        };
        let got = self.inbox.get_mut(client).unwrap().remove(i);
        for (key, value) in want.as_object().unwrap() {
            match get_path(&got, key) {
                Some(g) => assert_eq!(&g, value, "{}: {client} {key} in {got}", self.name),
                None => panic!("{}: {client}: {key} not produced in {got}", self.name),
            }
        }
        if let Some(capture) = capture {
            for (name, path) in capture.as_object().unwrap() {
                let path = path.as_str().unwrap();
                let value = get_path(&got, path)
                    .unwrap_or_else(|| panic!("{}: capture {path} in {got}", self.name));
                self.captures.insert(name.clone(), value);
            }
        }
        self.pass();
    }

    fn restart(
        &mut self,
        runtime_gen: &str,
        epoch: u64,
        orderly: Option<bool>,
        disk: Option<&str>,
    ) {
        let name = self.name.clone();
        let host = self.host();
        match orderly {
            Some(true) => {
                host.sandbox.stop_runtime();
            }
            Some(false) => host.sandbox.kill_runtime(),
            // It ended by itself (crash_after_commit).
            None => {
                if let Some(mut child) = host.sandbox.runtime.take() {
                    let _ = child.wait();
                }
            }
        }
        match disk {
            None | Some("as_written") | Some("rename_kept") => {}
            Some("rename_lost") | Some("write_lost") => {
                // Only a rename whose directory fsync failed can be lost.
                if let Some((path, before)) = host.snapshot.take() {
                    match before {
                        Some(bytes) => private_file(&path, &bytes),
                        None => {
                            let _ = std::fs::remove_file(&path);
                        }
                    }
                }
            }
            Some(other) => panic!("{name}: disk {other}"),
        }
        host.sandbox.next_epoch(epoch);
        host.ids.retain(|(f, _)| f != runtime_gen);
        host.chans.clear();
        host.out.clear();
        host.start_runtime();
        let sessions: Vec<String> = host.sessions.iter().map(|s| s.real_id.clone()).collect();
        for sid in sessions {
            let frontend = host.frontend();
            frontend.send(json!({"op": "attach", "session_id": sid, "rows": 24, "cols": 80}));
            frontend.until("attached", |_| true);
        }
        host.wait_link();
        self.inbox.clear();
    }

    fn advance(&mut self, ms: u64, wall_only: bool) {
        for host in self.hosts.values_mut() {
            host.now.wall_ms += ms;
            if !wall_only {
                host.now.mono_ms += ms;
                host.session_clock += ms;
            }
            host.write_clocks();
        }
        // The runtime acts on a clock at its next 100 ms pass.
        for host in self.hosts.values_mut() {
            host.pump(SETTLE);
        }
        self.drain();
    }

    /// The client subscribes to the registry (`list`), as a client does
    /// before it names a session: its reply is the harness's.
    fn subscribe(&mut self, client: &str) {
        let host = self.host();
        let Some(chan) = host.chans.get(client) else {
            return;
        };
        if chan.listed || chan.attachment.is_none() || chan.closed.is_some() {
            return;
        }
        let id = self.uuid();
        self.harness_ids.insert(id.clone());
        let json = json!({"type": "session", "data": {"v": 1, "op": "list", "id": id}});
        self.send_json(client, &json);
        self.host().chans.get_mut(client).unwrap().listed = true;
    }

    /// `client`'s binding for `sid` (fixture ids; translated on the way).
    fn binding(&mut self, client: &str, sid: &str, lease: bool) -> Value {
        self.subscribe(client);
        let host = self.host();
        let spec = host.spec.clone();
        let session = host
            .sessions
            .iter()
            .find(|s| s.fixture_id == sid)
            .unwrap_or_else(|| panic!("no session {sid}"));
        let (real, gen_) = (session.real_id.clone(), session.real_gen.clone());
        let attachment = host.chans.get(client).and_then(|c| c.attachment.clone());
        let mut b = json!({"target": {"account_id": spec["account_id"],
                "atem_device_id": spec["atem_device_id"], "host_trust_gen": spec["host_trust_gen"],
                "session_id": real, "process_gen": gen_},
            "attachment_gen": attachment});
        if lease {
            let state = host.state();
            b["lease_epoch"] = state["leases"][&real]["epoch"].clone();
        }
        b
    }

    fn substitute(&mut self, v: &mut Value) {
        match v {
            Value::String(s) => {
                for (prefix, lease) in [("${lease_binding:", true), ("${binding:", false)] {
                    if let Some(rest) = s.strip_prefix(prefix).and_then(|r| r.strip_suffix('}')) {
                        let (client, sid) = rest.split_once(':').unwrap();
                        let (client, sid) = (client.to_owned(), sid.to_owned());
                        *v = self.binding(&client, &sid, lease);
                        return;
                    }
                }
                *v = self.resolve(v);
            }
            Value::Array(items) => items.iter_mut().for_each(|i| self.substitute(i)),
            Value::Object(map) => map.values_mut().for_each(|i| self.substitute(i)),
            _ => {}
        }
    }

    /// A host assertion, re-read until it holds (`SETTLE_STATE`): the
    /// processes act asynchronously.
    fn assert(&mut self, assert: &Value) {
        if let Some(name) = assert.get("host") {
            self.current = name.as_str().unwrap().to_owned();
        }
        let assert = self.resolve(assert);
        // A barrier: the dump read must come from a pass after this step
        // began (one from before it could show a state about to change).
        let pass_of = |rt: &Rt| rt.state()["pass"].as_u64().unwrap_or(0);
        let start = pass_of(self.host());
        let deadline = Instant::now() + WAIT;
        while pass_of(self.host()) < start + 2 {
            assert!(
                Instant::now() < deadline,
                "{}: the runtime's state dump stopped",
                self.name
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        let deadline = Instant::now() + SETTLE_STATE;
        loop {
            self.drain();
            match self.check(&assert) {
                Ok(later) => {
                    self.pass();
                    for (k, why) in later {
                        self.later(format!("assert {k}"), why);
                    }
                    return;
                }
                Err(e) if Instant::now() > deadline => panic!("{}: {e}", self.name),
                Err(_) => self.host().pump(Duration::from_millis(100)),
            }
        }
    }

    fn check(&mut self, assert: &Value) -> Result<Vec<(String, &'static str)>, String> {
        let v = self.v;
        let sid = self.sessions.first().cloned();
        let mut later = Vec::new();
        let host_name = self.current.clone();
        let host = self.hosts.get_mut(&host_name).unwrap();
        let state = host.state();
        let m = &state["membership"];
        let head = |label: &str| {
            let h = v.head(label);
            json!({"seq": h.seq, "hash": h.hash.to_hex()})
        };
        let pairing = host.pairing();
        let file = |name: &str| pairing.join(name).exists();
        let mut errors = Vec::new();
        for (key, want) in assert.as_object().unwrap() {
            let got: Value = match key.as_str() {
                "host" => continue,
                "head" => {
                    if m["head"] != head(want.as_str().unwrap()) {
                        errors.push(format!("head {} != {want}", m["head"]));
                    }
                    continue;
                }
                "membership_applied" => {
                    let want = head(want.as_str().unwrap());
                    let on_disk: Value =
                        std::fs::read_to_string(host.journal().join("membership_applied"))
                            .ok()
                            .and_then(|t| serde_json::from_str(&t).ok())
                            .unwrap_or(Value::Null);
                    if m["applied"] != want || on_disk != want {
                        errors.push(format!(
                            "membership_applied {} (file {on_disk}) != {want}",
                            m["applied"]
                        ));
                    }
                    continue;
                }
                "frozen" => m["frozen"].clone(),
                "frozen_durable" => {
                    if m["frozen_durable"] != json!(file("membership.freeze")) {
                        errors.push("frozen_durable: the dump and the file disagree".into());
                    }
                    m["frozen_durable"].clone()
                }
                "membership_halted" => {
                    json!(m["faulted"] == true && state["journal_halted"] == true)
                }
                "membership_held" => m["held"].clone(),
                "membership_unclean" => match want {
                    Value::Null => m["unclean"].clone(),
                    l => {
                        if m["unclean"] != head(l.as_str().unwrap()) {
                            errors.push(format!("unclean {} != {l}", m["unclean"]));
                        }
                        continue;
                    }
                },
                "carriage_record" => {
                    if m["carriage_record"] != json!(file("membership.carriage")) {
                        errors.push("carriage_record: the dump and the file disagree".into());
                    }
                    m["carriage_record"].clone()
                }
                "fault_record" => {
                    if m["fault_record"] != json!(file("membership.fault")) {
                        errors.push("fault_record: the dump and the file disagree".into());
                    }
                    m["fault_record"].clone()
                }
                "control_gen" => {
                    for (p, n) in want.as_object().unwrap() {
                        // The dump names every principal the session host
                        // has a control state for; one it never saw has
                        // `control_gen` 1 (`SessionHost::control_gen`).
                        let got = m["control_gen"].get(p).cloned().unwrap_or(json!(1));
                        if got != *n {
                            errors.push(format!("control_gen {p}: {got} != {n}"));
                        }
                    }
                    continue;
                }
                "attachments" => state["attachments"].clone(),
                "channels" => state["channels"].clone(),
                "pty_writes" | "pty_writes_local" | "pty_writes_remote" | "pty_writes_dropped"
                | "dispatches" | "approvals_pending" | "approval_decisions" => host.counter(key),
                "approval_decisions.#" => json!(
                    host.counter("approval_decisions")
                        .as_array()
                        .map_or(0, Vec::len)
                ),
                "lease_holder" => {
                    let real = host.real(sid.as_deref().expect("a session"));
                    match state["leases"][&real]["holder"].as_str() {
                        Some(att) => json!(host.client_of_attachment(att)),
                        None => Value::Null,
                    }
                }
                "receipts_visible" => {
                    for (c, n) in want.as_object().unwrap() {
                        let att = host.chans[c].attachment.clone().unwrap();
                        let got = state["receipts_visible"][&att].clone();
                        if got != *n {
                            errors.push(format!("receipts_visible {c}: {got} != {n}"));
                        }
                    }
                    continue;
                }
                "receipts" => {
                    for (rid, r) in want.as_object().unwrap() {
                        let got = &state["receipts"][rid];
                        if got["state"] != r["state"] || got["detail"] != r["detail"] {
                            errors.push(format!("receipt {rid}: {got} != {r}"));
                        }
                    }
                    continue;
                }
                "evidence_count" => m["evidence"]["count"].clone(),
                "evidence_reason" => m["evidence"]["reason"].clone(),
                "frozen_genesis" => {
                    let text = std::fs::read_to_string(host.pairing().join("frozen_genesis"))
                        .unwrap_or_default();
                    serde_json::from_str::<Value>(&text).unwrap_or(Value::Null)["genesis"].clone()
                }
                "members" => m["members"].clone(),
                "pending" => {
                    for (label, st) in want.as_object().unwrap() {
                        let got = m["records"][v.hash(label).to_hex()].clone();
                        if got != *st {
                            errors.push(format!("pending {label}: {got} != {st}"));
                        }
                    }
                    if want.as_object().unwrap().is_empty()
                        && m["records"]
                            .as_object()
                            .is_some_and(|r| r.values().any(|s| s == "pending"))
                    {
                        errors.push(format!("pending: {} still pending", m["records"]));
                    }
                    continue;
                }
                "stored_sig" => {
                    let label = want.as_str().unwrap();
                    let seq = v.head(label).seq;
                    let stored: Value = serde_json::from_slice(
                        &std::fs::read(host.pairing().join("membership.json")).unwrap(),
                    )
                    .unwrap();
                    let entry = stored["entries"]
                        .as_array()
                        .unwrap()
                        .iter()
                        .find(|e| e["body"]["seq"] == seq)
                        .cloned()
                        .unwrap_or(Value::Null);
                    if entry["sig"] != v.wire(label)["sig"] {
                        errors.push(format!("stored_sig: {} != {label}'s", entry["sig"]));
                    }
                    continue;
                }
                "recovery_key" => {
                    let keys = load("r9-vectors-keys");
                    let hex = keys["keys"][want.as_str().unwrap()]["sign_pub_hex"]
                        .as_str()
                        .unwrap()
                        .to_owned();
                    let want_b64 = b64u(&Hash32::from_hex(&hex).unwrap().0);
                    if m["recovery_key"] != json!(want_b64) {
                        errors.push(format!("recovery_key {} != {want}", m["recovery_key"]));
                    }
                    continue;
                }
                "k_backup" => {
                    let got = &m["k_backup"];
                    if got["blob_version"] != want["blob_version"]
                        || got["backup_hash"] != want["backup_hash"]
                    {
                        errors.push(format!("k_backup {got} != {want}"));
                    }
                    continue;
                }
                "channel_id" => {
                    let chan = host.chans.values().last().expect("a channel");
                    let id = chan.channel.as_ref().unwrap().channel_id().to_string();
                    if id.len() != 32 {
                        errors.push(format!("channel_id {id}"));
                    }
                    later.push(("channel_id: the vector's exact value".into(), VECTOR_BYTES));
                    continue;
                }
                "carried_ever" => {
                    later.push((key.clone(), CLIENT_SIDE));
                    continue;
                }
                other => panic!("{}: unknown assert key {other}", self.name),
            };
            if got != *want {
                errors.push(format!("{key}: {got} != {want}"));
            }
        }
        if errors.is_empty() {
            Ok(later)
        } else {
            Err(format!(
                "assert {assert}: {} (state {state})",
                errors.join("; ")
            ))
        }
    }

    fn step(&mut self, step: &Value) {
        let object = step.as_object().unwrap();
        let kinds = [
            "connect",
            "reconnect",
            "handshake",
            "client_handshake",
            "send_membership",
            "expect",
            "expect_channel_error",
            "expect_channel_or_session_error",
            "expect_none",
            "expect_record",
            "expect_closed",
            "expect_plain",
            "plain_frame",
            "send_record",
            "replay",
            "advance_ms",
            "set_wall_clock",
            "assert",
            "expect_local_status",
            "restart_runtime",
            "crash_runtime",
            "fail_next_membership_write",
            "crash_after_membership_commit",
            "send",
            "hold_dispatch",
            "hold_pty_writes",
            "flush_pty_writes",
            "local_input",
            "unpair",
            "pair",
            "open_approval",
            "close_approval",
            "approval_applied",
            "turn_complete",
            "expect_relay",
            "expect_relay_none",
            "relay_ack",
            "relay_lost",
            "expect_client_refusal",
            "link_up",
            "link_down",
            "envelope_in",
            "envelope_in_bytes",
            "expect_envelope",
            "expect_no_envelope",
            "expect_channel_open",
            "close_channel",
            "send_frame",
            "stall_link",
            "unstall_link",
            "fill_queue",
        ];
        let kind = kinds
            .into_iter()
            .find(|k| object.contains_key(*k))
            .unwrap_or_else(|| panic!("{}: unknown step {step}", self.name));
        if !kind.starts_with("expect") && kind != "assert" {
            self.fresh.clear();
        }
        match kind {
            "connect" | "reconnect" | "handshake" => {
                if let Some(code) = step.get("expect_init_refused").and_then(Value::as_str) {
                    self.connect(step);
                    let client = step["connect"].as_str().unwrap().to_owned();
                    let want = json!({"op": "channel_error", "code": code, "at": "init"});
                    self.expect(&client, &want, None, None);
                } else {
                    self.connect(step);
                }
            }
            "client_handshake" | "expect_client_refusal" => {
                self.later(format!("{kind}: the client's side"), CLIENT_SIDE)
            }
            "send_membership" => self.send_membership(step),
            "expect" => {
                let client = step["expect"].as_str().unwrap().to_owned();
                let kind = step.get("type").and_then(Value::as_str);
                self.expect(&client, &step["match"], kind, step.get("capture"));
            }
            "expect_channel_error" => {
                let client = step["expect_channel_error"].as_str().unwrap().to_owned();
                let want = json!({"op": "channel_error", "code": step["code"], "at": step["at"]});
                self.expect(&client, &want, None, None);
            }
            "expect_channel_or_session_error" => {
                let client = step["expect_channel_or_session_error"]
                    .as_str()
                    .unwrap()
                    .to_owned();
                let code = step["code"].clone();
                let deadline = Instant::now() + WAIT;
                loop {
                    self.drain();
                    let inbox = self.inbox.entry(client.clone()).or_default();
                    let at = inbox.iter().position(|m| {
                        (m["op"] == "error" || m["op"] == "channel_error")
                            && m["code"] == code
                            && step.get("detail").is_none_or(|d| m["detail"] == *d)
                    });
                    if let Some(at) = at {
                        inbox.remove(at);
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "{}: {client}: no {step} in {inbox:?}",
                        self.name
                    );
                    self.host().pump(Duration::from_millis(50));
                }
                self.pass();
            }
            "expect_none" => {
                let client = step["expect_none"].as_str().unwrap().to_owned();
                let ms = step["for_ms"].as_u64().unwrap_or(0);
                if ms > 0 {
                    self.advance(ms, false);
                }
                self.host().pump(SETTLE);
                self.drain();
                let got = self.fresh.get(&client).copied().unwrap_or(0);
                assert_eq!(
                    got,
                    0,
                    "{}: {client} got {:?}",
                    self.name,
                    self.inbox.get(&client)
                );
                self.pass();
            }
            "expect_record" => {
                let client = step["expect_record"].as_str().unwrap().to_owned();
                self.drain();
                let welcome = self
                    .inbox
                    .get_mut(&client)
                    .and_then(|i| {
                        let at = i.iter().position(|m| m["op"] == "welcome")?;
                        Some(i.remove(at))
                    })
                    .unwrap_or_else(|| panic!("{}: {client}: no welcome", self.name));
                self.check_welcome(&client, &welcome);
                self.pass();
                self.later(
                    "expect_record: the vector's exact record bytes",
                    VECTOR_BYTES,
                );
            }
            "send_record" => self.send_record(step),
            "expect_closed" => {
                let client = step["expect_closed"].as_str().unwrap().to_owned();
                let deadline = Instant::now() + WAIT;
                loop {
                    self.drain();
                    if self.host().chans[&client].closed.is_some() {
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "{}: {client} not closed",
                        self.name
                    );
                    self.host().pump(Duration::from_millis(50));
                }
                assert_eq!(
                    self.fresh.get(&client).copied().unwrap_or(0),
                    0,
                    "{}: {client}: a reply before the close: {:?}",
                    self.name,
                    self.inbox.get(&client)
                );
                self.pass();
            }
            "replay" => self.replay(step),
            "plain_frame" => {
                let json = step["json"].clone();
                self.host().send_raw(json.to_string());
                self.pass();
            }
            "expect_plain" => {
                let want = step["match"].clone();
                let deadline = Instant::now() + WAIT;
                let host = self.host();
                let found = loop {
                    host.poll();
                    let found = host.other.iter().position(|m| {
                        want.as_object()
                            .unwrap()
                            .iter()
                            .all(|(k, w)| get_path(&m["data"], k).as_ref() == Some(w))
                    });
                    if let Some(at) = found {
                        break host.other.remove(at);
                    }
                    if Instant::now() > deadline {
                        break None;
                    }
                    host.pump(Duration::from_millis(50));
                };
                let name = self.name.clone();
                let other = self.host().other.clone();
                assert!(found.is_some(), "{name}: expect_plain {want} in {other:?}");
                self.pass();
            }
            "advance_ms" => {
                self.advance(step["advance_ms"].as_u64().unwrap(), false);
                self.pass();
            }
            "set_wall_clock" => {
                let wall = step["set_wall_clock"].as_u64().unwrap();
                let now = self.host().now.wall_ms;
                assert!(wall >= now, "the fixtures only move it forward");
                self.advance(wall - now, true);
                self.pass();
            }
            // The channel count right after a stall that couldn't be made
            // depends on it.
            "assert" if self.stall != Stall::None => {
                self.stall = Stall::None;
                self.later(format!("assert {} after the stall", step["assert"]), STALL);
            }
            "assert" => self.assert(&step["assert"]),
            "expect_local_status" => self.local_status(step),
            "restart_runtime" | "crash_runtime" => {
                let spec = &step[kind];
                self.restart(
                    spec["runtime_gen"].as_str().unwrap(),
                    spec["runtime_epoch"].as_u64().unwrap(),
                    Some(kind == "restart_runtime"),
                    step.get("disk").and_then(Value::as_str),
                );
                self.pass();
            }
            "fail_next_membership_write" => {
                let spec = &step[kind];
                let (file, at) = match spec {
                    Value::Bool(true) => ("state".to_string(), "temp_write".to_string()),
                    spec => {
                        let at = spec["at"].as_str().unwrap().to_owned();
                        match spec.get("file").and_then(Value::as_str) {
                            Some(file) => (file.to_owned(), at),
                            None if at == "intent" => ("intent".into(), "temp_write".into()),
                            None => ("state".into(), at),
                        }
                    }
                };
                let host = self.host();
                if at == "directory_fsync" {
                    let name = match file.as_str() {
                        "state" | "membership" => "membership.json",
                        "carriage" => "membership.carriage",
                        "intent" => "membership.intent",
                        "freeze" => "membership.freeze",
                        "fault" => "membership.fault",
                        other => panic!("file {other}"),
                    };
                    let path = host.pairing().join(name);
                    let before = std::fs::read(&path).ok();
                    host.snapshot = Some((path, before));
                }
                std::fs::write(host.mfaults.join("fail_next"), format!("{file}:{at}")).unwrap();
                self.pass();
            }
            "crash_after_membership_commit" => {
                let spec = &step[kind];
                self.crash = Some((
                    spec["runtime_gen"].as_str().unwrap().to_owned(),
                    spec["runtime_epoch"].as_u64().unwrap(),
                ));
                let host = self.host();
                std::fs::write(host.mfaults.join("crash_after_commit"), "").unwrap();
                self.pass();
            }
            "send" => {
                let client = step["send"].as_str().unwrap().to_owned();
                let mut json = step["json"].clone();
                self.substitute(&mut json);
                if json["type"] == "terminal" && json["data"]["op"] == "input" {
                    // Input needs the client's stream: the harness
                    // subscribes first and uses the stream the host opened.
                    let sid = json["data"]["terminal_id"].as_str().unwrap().to_owned();
                    let read = self.binding(&client, &sid, false);
                    let subscribe = json!({"type": "terminal", "data": {"v": 1, "op": "subscribe",
                        "terminal_id": sid, "generation": json["data"]["generation"], "binding": read}});
                    self.send_json(&client, &subscribe);
                    self.host().pump(SETTLE);
                    self.drain();
                    let inbox = self.inbox.entry(client.clone()).or_default();
                    if let Some(at) = inbox
                        .iter()
                        .position(|m| m["__type"] == "terminal" && m["op"] == "attached")
                    {
                        let attached = inbox.remove(at);
                        json["data"]["stream_id"] = attached["stream_id"].clone();
                    }
                    let bytes = base64::engine::general_purpose::STANDARD
                        .decode(json["data"]["bytes"].as_str().unwrap_or(""))
                        .unwrap_or_default();
                    let real = self.host().real(&sid);
                    self.host().chunks.push((real, false, bytes));
                }
                if json["type"] == "session"
                    && json["data"]["op"] == "list"
                    && let Some(chan) = self.host().chans.get_mut(&client)
                {
                    chan.listed = true;
                }
                self.send_json(&client, &json);
                self.pass();
            }
            "hold_dispatch" => {
                // Set from the start (the runner's pre-scan): the work
                // accepted before this step stays queued too.
                self.pass();
            }
            "hold_pty_writes" => {
                let host = self.host();
                std::fs::write(host.sandbox.faults.join("hold"), "").unwrap();
                host.pump(SETTLE);
                self.pass();
            }
            "flush_pty_writes" => {
                let host = self.host();
                let _ = std::fs::remove_file(host.sandbox.faults.join("hold"));
                host.pump(SETTLE);
                self.drain();
                self.pass();
            }
            "local_input" => {
                let fixture = step["local_input"].as_str().unwrap().to_owned();
                let text = step["bytes"].as_str().unwrap().to_owned();
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(&text)
                    .unwrap();
                let host = self.host();
                let real = host.real(&fixture);
                host.chunks.push((real.clone(), true, bytes));
                host.frontend()
                    .send(json!({"op": "input", "session_id": real, "bytes": text}));
                host.pump(SETTLE);
                self.drain();
                self.pass();
            }
            "open_approval" => self.open_approval(step),
            "close_approval" => {
                let id = self.resolve(&step["close_approval"]);
                let id = id.as_str().unwrap().to_owned();
                let reason = step["reason"].as_str().unwrap();
                assert_eq!(
                    reason, "answered_terminal",
                    "{}: only the terminal's answer is expressible",
                    self.name
                );
                let host = self.host();
                let ask = host
                    .asks
                    .iter()
                    .find(|a| a.approval_id == id)
                    .unwrap_or_else(|| panic!("unknown approval {id}"));
                std::fs::write(ask.dir.join(format!("terminal-yes-{}", ask.n)), "").unwrap();
                host.pump(SETTLE);
                self.drain();
                self.pass();
            }
            "approval_applied" => {
                // The agent acts on the decision its hook got by itself.
                assert_eq!(step["ok"], true, "{}: approval_applied ok:false", self.name);
                let id = self.resolve(&step["approval_applied"]);
                let host = self.host();
                assert!(
                    host.asks.iter().any(|a| json!(a.approval_id) == id),
                    "unknown approval {id}"
                );
                host.pump(SETTLE);
                self.drain();
                self.pass();
            }
            "turn_complete" => {
                let fixture = step["turn_complete"].as_str().unwrap().to_owned();
                let turn = step["turn_id"].as_str().unwrap();
                let host = self.host();
                let dir = host
                    .sessions
                    .iter()
                    .find(|s| s.fixture_id == fixture)
                    .unwrap()
                    .dir
                    .clone();
                std::fs::write(dir.join("complete"), turn).unwrap();
                host.pump(SETTLE);
                self.drain();
                self.pass();
            }
            "expect_relay" => self.expect_relay(step),
            "expect_relay_none" => {
                let host = self.host();
                host.pump(SETTLE);
                let left = std::mem::take(&mut host.relay);
                assert!(
                    left.is_empty(),
                    "{}: Atem sent the relay {left:?}",
                    self.name
                );
                self.pass();
            }
            "relay_ack" => {
                let ack = self.resolve(&step["relay_ack"]);
                let identities = atem_client::push::parse_push_ack(&json!({
                    "type": "relay", "op": ack["op"], "acks": ack["acks"]}));
                assert_eq!(
                    identities.len(),
                    ack["acks"].as_array().unwrap().len(),
                    "{}: every ack entry names an identity",
                    self.name
                );
                let mut ack = json!({"type": "relay", "op": ack["op"], "acks": ack["acks"]});
                let host = self.host();
                replace_strings(&mut ack, &host.ids, true);
                host.send_raw(ack.to_string());
                host.pump(SETTLE);
                self.pass();
            }
            "relay_lost" => {
                // The host can't tell: what it sent stays unacknowledged
                // (the next `expect_relay` takes its resend).
                self.pass();
            }
            "unpair" => {
                let host = self.host();
                let out = Command::new(env!("CARGO_BIN_EXE_atem"))
                    .args(["unpair", "--yes"])
                    .env_clear()
                    .env("PATH", "/usr/bin:/bin")
                    .env("HOME", &host.sandbox.home)
                    .env("XDG_RUNTIME_DIR", &host.sandbox.run)
                    .stdin(Stdio::null())
                    .output()
                    .unwrap();
                assert!(
                    out.status.success(),
                    "{}: atem unpair: {}",
                    self.name,
                    String::from_utf8_lossy(&out.stderr)
                );
                assert!(!host.pairing().join("membership.json").exists());
                self.pass();
            }
            "pair" => {
                assert_eq!(step["result"], "refused");
                self.later(format!("pair: refused {}", step["detail"]), NO_CEREMONY);
            }
            // §R9.7a: the link is already up at the start; after a drop,
            // the runtime's reconnect.
            "link_up" => {
                let host = self.host();
                if host.authenticated <= host.link {
                    let deadline = Instant::now() + WAIT;
                    while host.authenticated <= host.link && Instant::now() < deadline {
                        host.pump(Duration::from_millis(50));
                    }
                }
                if host.authenticated > host.link {
                    host.wait_link();
                }
                self.pass();
            }
            "link_down" => {
                let host = self.host();
                host.astation.close(host.link);
                for chan in host.chans.values_mut() {
                    chan.closed.get_or_insert(Some("link_down".into()));
                }
                host.pump(SETTLE);
                self.pass();
            }
            "envelope_in" => {
                let text = step["envelope_in"].to_string();
                self.host().send_raw(text);
                self.host().pump(Duration::from_millis(150));
                self.pass();
            }
            "envelope_in_bytes" => {
                let e = &step["envelope_in_bytes"];
                let h = e["channel"].as_str().unwrap();
                let n = e["bytes"].as_u64().unwrap() as usize;
                let mut text = format!(
                    r#"{{"type":"channel","event":"frame","channel":{},"frame":{}}}"#,
                    json!(h),
                    r#"{"ch":"atem-ch1","op":"rec","ct":"AAAAAAAAAAAAAAAAAAAAAA"}"#
                );
                let pad = n - text.len();
                text.insert_str(text.len() - 1, &" ".repeat(pad));
                assert_eq!(text.len(), n);
                self.host().send_raw(text);
                self.host().pump(Duration::from_millis(150));
                self.pass();
            }
            "expect_envelope" => {
                if step.get("after_unstall").is_some() {
                    self.later("expect_envelope after the stall", STALL);
                    return;
                }
                let want = step["expect_envelope"]["match"].clone();
                let deadline = Instant::now() + WAIT;
                let name = self.name.clone();
                loop {
                    let host = self.host();
                    host.poll();
                    let found = host.envelopes.iter().any(|e| {
                        want.as_object()
                            .unwrap()
                            .iter()
                            .all(|(k, w)| e.get(k) == Some(w))
                    });
                    if found {
                        break;
                    }
                    assert!(
                        Instant::now() < deadline,
                        "{name}: no envelope {want} in {:?}",
                        host.envelopes
                    );
                    host.pump(Duration::from_millis(50));
                }
                // The close also ends the client's channel.
                self.drain();
                self.pass();
            }
            "expect_no_envelope" => {
                let e = &step["expect_no_envelope"];
                let h = e["channel"].as_str().unwrap().to_owned();
                let ms = e["for_ms"].as_u64().unwrap_or(100);
                let name = self.name.clone();
                let host = self.host();
                let before = host
                    .envelopes
                    .iter()
                    .filter(|e| e["channel"] == h.as_str())
                    .count();
                host.pump(Duration::from_millis(ms.max(300)));
                let frames = host.out.get(&h).map_or(0, |q| {
                    q.iter().filter(|o| matches!(o, Out::Frame(_))).count()
                });
                let after = host
                    .envelopes
                    .iter()
                    .filter(|e| e["channel"] == h.as_str())
                    .count();
                assert!(
                    after == before && (host.client_of_handle(&h).is_some() || frames == 0),
                    "{name}: Atem sent on {h}: {:?}",
                    host.envelopes
                );
                self.drain();
                self.pass();
            }
            "expect_channel_open" => {
                let c = step["expect_channel_open"].as_str().unwrap().to_owned();
                self.host().pump(SETTLE);
                self.drain();
                let name = self.name.clone();
                let chan = &self.host().chans[&c];
                assert!(
                    chan.closed.is_none() && chan.attachment.is_some(),
                    "{name}: {c}'s channel closed ({:?})",
                    chan.closed
                );
                self.pass();
            }
            "close_channel" => {
                let h = step["close_channel"].as_str().unwrap().to_owned();
                let reason = step["reason"].clone();
                let host = self.host();
                host.send_raw(
                    json!({"type": "channel", "event": "close", "channel": h, "reason": reason})
                        .to_string(),
                );
                if let Some(c) = host.client_of_handle(&h) {
                    host.chans.get_mut(&c).unwrap().closed = Some(reason.as_str().map(Into::into));
                }
                host.pump(SETTLE);
                self.pass();
            }
            "send_frame" => self.send_frame(step),
            "stall_link" | "fill_queue" => {
                self.stall = Stall::Skipped;
                self.later(kind, STALL);
            }
            "unstall_link" => {
                self.stall = Stall::After;
                self.later(kind, STALL);
            }
            other => panic!("{}: unhandled step {other}", self.name),
        }
    }

    /// `send_frame`: a record of exactly `n` plaintext bytes (a padded
    /// `list`), or one past the sender's own bound (`unchecked`).
    fn send_frame(&mut self, step: &Value) {
        let c = step["send_frame"].as_str().unwrap().to_owned();
        let n = step["frame_of_plaintext_bytes"].as_u64().unwrap() as usize;
        let host = self.host();
        let handle = host.chans[&c].handle.clone();
        let frame = if step.get("unchecked").is_some() {
            // Past the sender's own bound: a record no sender makes.
            let ct = b64u(&vec![7u8; n + 16]);
            json!({"ch": "atem-ch1", "op": "rec", "ct": ct})
                .to_string()
                .into_bytes()
        } else {
            let mut msg = json!({"type": "session", "data": {"v": 1, "op": "list",
                "id": uuid::Uuid::new_v4().to_string(), "pad": ""}});
            let base = msg.to_string().len();
            msg["data"]["pad"] = json!("x".repeat(n - base));
            assert_eq!(msg.to_string().len(), n);
            let chan = host.chans.get_mut(&c).unwrap();
            let frame = chan
                .channel
                .as_mut()
                .unwrap()
                .seal(msg.to_string().as_bytes(), client_ms())
                .unwrap();
            chan.sent.push(frame.clone());
            frame
        };
        let text = format!(
            r#"{{"type":"channel","event":"frame","channel":{},"frame":{}}}"#,
            json!(handle),
            std::str::from_utf8(&frame).unwrap()
        );
        if let Some(m) = step.get("expect_envelope_bytes").and_then(Value::as_u64) {
            assert_eq!(text.len() as u64, m, "{}: the compact envelope", self.name);
        }
        host.send_raw(text);
        host.pump(SETTLE);
        self.drain();
        self.pass();
    }

    /// The fake Claude asks for a tool call that needs permission; its hook
    /// reports it and the runtime opens the approval.
    fn open_approval(&mut self, step: &Value) {
        let fixture = step["open_approval"].as_str().unwrap().to_owned();
        let tool = step["tool"].as_str().unwrap();
        let summary = step["summary"].as_str().unwrap();
        let name = self.name.clone();
        let host = self.host();
        let dir = host
            .sessions
            .iter()
            .find(|s| s.fixture_id == fixture)
            .unwrap()
            .dir
            .clone();
        let n = host.asks.len() + 1;
        let request = json!({"tool_name": tool, "tool_input": {"command": summary},
                             "permission_suggestions": [], "quiet": true});
        let temp = dir.join(format!("tmp-ask-{n}"));
        std::fs::write(&temp, request.to_string()).unwrap();
        std::fs::rename(&temp, dir.join(format!("ask-{n}.json"))).unwrap();
        let known: Vec<String> = host.asks.iter().map(|a| a.approval_id.clone()).collect();
        let _ = name;
        self.open_approval_wait(n, dir, known);
    }

    fn open_approval_wait(&mut self, n: usize, dir: PathBuf, known: Vec<String>) {
        let name = self.name.clone();
        let deadline = Instant::now() + WAIT;
        let id = loop {
            self.drain();
            let host = self.host();
            if let Some(id) = host
                .approvals_opened
                .iter()
                .find(|id| !known.contains(id))
                .cloned()
            {
                break id;
            }
            assert!(Instant::now() < deadline, "{name}: no approval opened");
            host.pump(Duration::from_millis(50));
        };
        self.host().asks.push(Ask {
            n,
            dir,
            approval_id: id,
        });
        self.pass();
    }

    /// `expect_relay`: the next relay message Atem sent matches each
    /// `path: value`; `capture` takes values by path.
    fn expect_relay(&mut self, step: &Value) {
        let name = self.name.clone();
        let host = self.host();
        let deadline = Instant::now() + WAIT;
        let got = loop {
            host.poll();
            if let Some(got) = host.relay.pop_front() {
                break got;
            }
            assert!(
                Instant::now() < deadline,
                "{name}: Atem sent the relay nothing ({step})"
            );
            host.pump(Duration::from_millis(50));
        };
        let want = self.resolve(&step["expect_relay"]);
        for (path, value) in want.as_object().unwrap() {
            assert_eq!(
                get_path(&got, path).as_ref(),
                Some(value),
                "{name}: {path} of {got}"
            );
        }
        if let Some(capture) = step.get("capture").and_then(Value::as_object) {
            for (label, path) in capture {
                let v = get_path(&got, path.as_str().unwrap()).unwrap_or(Value::Null);
                assert!(!v.is_null(), "{name}: nothing at {path} of {got}");
                self.captures.insert(label.clone(), v);
            }
        }
        self.pass();
    }

    /// The welcome on the wire: r9 revision, kind, permissions and the
    /// principal the client proved.
    fn check_welcome(&self, client: &str, welcome: &Value) {
        let principal = &self.clients[client].principal;
        assert_eq!(welcome["revision"], 9, "{}: {welcome}", self.name);
        assert_eq!(welcome["principal"], principal.as_str());
        let kind = match principal.split_once(':').unwrap().0 {
            "member" => "native",
            other => other,
        };
        assert_eq!(welcome["client_kind"], kind);
        assert!(welcome["features"].as_array().unwrap().len() >= 14);
        assert!(
            welcome["channel_id"]
                .as_str()
                .is_some_and(|c| c.len() == 32)
        );
        assert!(welcome.get("pending_recovery").is_some());
    }

    /// `send_record` of the handshake fixtures, live: a `list` on the
    /// client's channel, the same record again (`as_counter`: a replay), the
    /// host's own record sent back (`ct_from: "h2c"`), or a record whose tag
    /// has one bit flipped (`tamper: "tag"`).
    fn send_record(&mut self, step: &Value) {
        let client = step["send_record"].as_str().unwrap().to_owned();
        if step.get("ct_from").and_then(Value::as_str) == Some("h2c") {
            let host = self.host();
            let chan = &host.chans[&client];
            // The host's first record on the channel (its welcome).
            let frame = chan
                .received
                .iter()
                .find(|f| matches!(chwire::parse_frame(f), Ok(Frame::Rec { .. })))
                .cloned()
                .expect("a record from the host");
            let handle = chan.handle.clone();
            host.send_frame(&handle, &frame);
            host.pump(SETTLE);
            self.drain();
        } else if step.get("as_counter").is_some() {
            let host = self.host();
            let chan = &host.chans[&client];
            let frame = chan.sent.last().unwrap().clone();
            let handle = chan.handle.clone();
            host.send_frame(&handle, &frame);
            host.pump(SETTLE);
            self.drain();
        } else if step.get("tamper").and_then(Value::as_str) == Some("tag") {
            let id = self.uuid();
            let json = json!({"type": "session", "data": {"v": 1, "op": "list", "id": id}});
            let host = self.host();
            let chan = host.chans.get_mut(&client).unwrap();
            let frame = chan
                .channel
                .as_mut()
                .unwrap()
                .seal(json.to_string().as_bytes(), client_ms())
                .unwrap();
            let mut value: Value = serde_json::from_slice(&frame).unwrap();
            let ct = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(value["ct"].as_str().unwrap())
                .unwrap();
            let mut ct = ct;
            let last = ct.len() - 1;
            ct[last] ^= 1;
            value["ct"] = json!(b64u(&ct));
            let handle = chan.handle.clone();
            host.send_frame(&handle, value.to_string().as_bytes());
            host.pump(SETTLE);
            self.drain();
        } else {
            let id = self.uuid();
            let json = json!({"type": "session", "data": {"v": 1, "op": "list", "id": id}});
            self.send_json(&client, &json);
            self.later("send_record: the vector's exact record bytes", VECTOR_BYTES);
        }
        self.pass();
    }

    /// `replay{finish_of: previous, into_new_channel}`: the previous
    /// channel's `finish` sent again in a new channel after its own `init`
    /// and `accept` (the transcript differs).
    fn replay(&mut self, step: &Value) {
        let client = self.clients.keys().next().cloned().expect("a client");
        assert_eq!(step["replay"]["finish_of"], "previous");
        let log = self.host_log();
        let name = self.name.clone();
        let host = self.host();
        let old = host.chans[&client].finish.clone().expect("a finish");
        host.handles += 1;
        let handle = format!("{client}-{}", host.handles);
        host.send_raw(
            json!({"type": "channel", "event": "open", "channel": handle, "transport": "relay"})
                .to_string(),
        );
        let (_, init) = Initiator::start(&log, &host.host_id, client_ms()).unwrap();
        host.send_frame(&handle, &init);
        match host.next_on(&handle, WAIT) {
            Some(Out::Frame(_)) => {}
            _ => panic!("{name}: no accept"),
        }
        host.send_frame(&handle, &old);
        let code = match host.next_on(&handle, WAIT) {
            Some(Out::Frame(f)) => match chwire::parse_frame(&f) {
                Ok(Frame::Error { code }) => code,
                other => panic!("{name}: replayed finish: {other:?}"),
            },
            other => panic!(
                "{name}: replayed finish: {:?}",
                other.map(|o| matches!(o, Out::Close(_)))
            ),
        };
        // The new channel's close follows its error.
        host.pump(Duration::from_millis(100));
        host.out.remove(&handle);
        self.deliver(
            &client,
            json!({"op": "channel_error", "code": code, "at": "finish"}),
        );
        self.pass();
        self.later("replay: the vector's fixed e_h/n_h", VECTOR_BYTES);
    }

    /// `expect_local_status{recovery_pending}`: `atem status`'s `Device
    /// list:` line, from the real CLI against the running runtime.
    fn local_status(&mut self, step: &Value) {
        let want = step["expect_local_status"]["recovery_pending"]
            .as_bool()
            .unwrap();
        let name = self.name.clone();
        let host = self.host();
        let deadline = Instant::now() + SETTLE_STATE;
        loop {
            let out = Command::new(env!("CARGO_BIN_EXE_atem"))
                .arg("status")
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", &host.sandbox.home)
                .env("XDG_RUNTIME_DIR", &host.sandbox.run)
                .env("ATEM_TEST_HOST_CLOCK", &host.host_clock)
                .stdin(Stdio::null())
                .output()
                .unwrap();
            let text = String::from_utf8_lossy(&out.stdout).to_string();
            let line = text
                .lines()
                .find(|l| l.contains("Device list"))
                .unwrap_or_default()
                .to_string();
            if line.contains("recovery pending: ") == want && !line.is_empty() {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "{name}: atem status: {line:?} ({text})"
            );
            std::thread::sleep(Duration::from_millis(200));
        }
        self.pass();
    }
}

/// Every agent started; Claude's chat is ready.
fn wait_sessions_ready(rt: &mut Rt) {
    let deadline = Instant::now() + WAIT;
    loop {
        let listed = rt.frontend().list();
        let ready = rt.sessions.iter().all(|s| {
            let started =
                std::fs::read_to_string(s.dir.join("events")).is_ok_and(|e| e.contains("started"));
            listed
                .iter()
                .find(|l| l["id"] == s.real_id.as_str())
                .is_some_and(|l| started && l["state"] == "running" && l["status"] == "ready")
        });
        if ready {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{}: sessions never became ready: {listed:?}",
            rt.name
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Runs one host scenario against the real runtime. A failure carries the
/// runtimes' logs.
pub fn run(scenario: &Value) -> Result<Outcome, String> {
    let name = scenario["name"].as_str().unwrap().to_owned();
    let runner = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
    let logs = runner.clone();
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut r = Runner {
            name: name.clone(),
            v: vectors(),
            keys: key_book(),
            hosts: BTreeMap::new(),
            current: String::new(),
            clients: BTreeMap::new(),
            inbox: BTreeMap::new(),
            fresh: BTreeMap::new(),
            outcome: Outcome::default(),
            crash: None,
            gens: 0,
            captures: BTreeMap::new(),
            sessions: Vec::new(),
            harness_ids: BTreeSet::new(),
            stall: Stall::None,
            outside: BTreeMap::new(),
            outside_expect: BTreeMap::new(),
        };
        let steps = scenario["steps"].as_array().unwrap().clone();
        let message = |e: Box<dyn std::any::Any + Send>| {
            e.downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default()
        };
        let fail = |r: &Runner, what: String| {
            let mut text = what;
            for h in r.hosts.values() {
                text.push_str(&format!("\n--- {} runtime log ---\n{}", h.name, h.logs()));
            }
            *logs.lock().unwrap() = Some(text);
            std::panic::resume_unwind(Box::new("failed"));
        };
        if let Err(e) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| r.setup(scenario)))
        {
            fail(&r, format!("setup: {}", message(e)));
        }
        for (i, step) in steps.iter().enumerate() {
            let out = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| r.step(step)));
            if let Err(e) = out {
                fail(&r, format!("step {i} {step}: {}", message(e)));
            }
        }
        std::mem::take(&mut r.outcome)
    }));
    match result {
        Ok(outcome) => Ok(outcome),
        Err(e) => Err(runner.lock().unwrap().take().unwrap_or_else(|| {
            e.downcast_ref::<String>()
                .cloned()
                .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_else(|| "panicked".into())
        })),
    }
}

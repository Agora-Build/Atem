//! The shared atem-session fixtures (`designs/protocol/fixtures/*.json`,
//! format in `fixtures/schema.md`) against the real runtime: the `atem
//! runtime` binary on a temp profile, real `atem worker` processes with a
//! fake agent in their PTYs, a frontend on the runtime's local socket for
//! local input, and a fake Astation WebSocket peer that authenticates the
//! runtime's link and plays the fixture's client on it. Everything goes
//! broker → SessionHost → FileJournal → worker → PTY.
//!
//! The fixture's identifiers are the runtime's: the profile is paired and
//! verified as the fixture's account and device in its trust generation, and
//! the runtime epoch file is primed with the fixture's epoch. What the
//! runtime picks itself (session ids, process generations, runtime
//! generations, attachment generations) is translated both ways.
//!
//! Actions, against real processes:
//! - `advance_ms`: the runtime's session clock is the fixture clock
//!   (`ATEM_TEST_CLOCK_FILE`, debug builds). `timers: false` can't be
//!   honoured: the broker's own loop runs `advance` whenever the clock moved
//!   100 ms since its last one, so the host may see the time without a
//!   message.
//! - `local_input`: a local frontend attached to the session sends `input`.
//! - `crash_worker`: SIGKILL to the session's worker process.
//! - `restart_runtime`: SIGKILL to the runtime; the next one (with the
//!   fixture's runtime epoch) adopts the surviving workers.
//! - `reconnect`: the fake Astation closes the link; the runtime reconnects
//!   and authenticates again (a new attachment).
//! - `hold_pty_writes`/`flush_pty_writes`, `fail_next_pty_enqueue`,
//!   `fail_next_pty_write_after_partial`: markers the workers' PTY writer
//!   reads (`ATEM_TEST_PTY_FAULTS`, debug builds; `src/runtime/test_hooks.rs`).
//! - `turn_complete`: the fake Claude ends its running turn (its prompt ids
//!   are `turn-<n>`, which the chat adapter reports as turn ids).
//!
//! Not honoured (the scenario is reported, with the reason, and not run):
//! more than one client (the runtime holds one Astation link, so one
//! attachment at a time), `close_session` (the runtime never closes a
//! running session), `disconnect`/`resume` (no resume in compatibility
//! mode), `fail_next_fsync` and `change_trust_gen`.
//!
//! A scenario the real runtime fails would be listed in `KNOWN_DEVIATIONS`
//! with the failure it must keep showing, and why (none today).
//!
//! Messages the fixtures don't model are not queued for `expect`: terminal-v1
//! `frame`s and `written` acknowledgements (the latter are counted for
//! `pty_writes_dropped`), and anything outside the session, terminal and
//! agentChat families.
//!
//! Counters come from what the processes did: the fake agent logs every
//! byte its PTY delivered (pastes are dispatches; other bytes are matched
//! against the terminal input the fixture sent, in order), the fault markers
//! used, the `written` acks, the agent's signals (a stop reaches it while its
//! worker lives; SIGWINCH is a resize), and the runtime's local `list` (lease
//! holder).
#![cfg(target_os = "linux")]

use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Map, Value, json};
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex, mpsc};
use std::time::{Duration, Instant};
use tokio_tungstenite::tungstenite::Message;

const ASTATION: &str = "astation-fixtures";
const WAIT: Duration = Duration::from_secs(15);
/// Time the runtime gets to act on what it was sent before the next event.
const SETTLE: Duration = Duration::from_millis(400);
const PASTE_START: &[u8] = b"\x1b[200~";
const PASTE_END: &[u8] = b"\x1b[201~\r";

/// Stands in for the Claude and Codex CLIs. Logs every byte read from its
/// terminal (raw mode) to `$FAKE_DIR/input` and its signals to
/// `$FAKE_DIR/events`. With `--settings` (Claude with Atem's chat hooks) each
/// bracketed paste is a prompt `turn-<n>`: it fires the hooks and writes the
/// transcript as Claude Code does, and the turn ends when `$FAKE_DIR/complete`
/// appears.
const FAKE_AGENT: &str = r#"#!/usr/bin/python3 -I
import json, os, select, signal, subprocess, sys, time, tty
args = sys.argv[1:]
settings = session = None
i = 0
while i < len(args):
    if args[i] == "--settings":
        settings = args[i + 1]; i += 1
    elif args[i] == "--session-id":
        session = args[i + 1]; i += 1
    i += 1
ctl = os.environ["FAKE_DIR"]
os.makedirs(ctl, exist_ok=True)
log_in = open(os.path.join(ctl, "input"), "ab", buffering=0)
events = open(os.path.join(ctl, "events"), "a", buffering=1)
parent = os.getppid()
def ended(signum, frame):
    time.sleep(0.1)
    events.write("signal %d worker_alive=%s\n" % (signum, os.getppid() == parent))
    os._exit(0)
signal.signal(signal.SIGWINCH, lambda signum, frame: events.write("winch\n"))
signal.signal(signal.SIGHUP, ended)
signal.signal(signal.SIGTERM, ended)
try:
    tty.setraw(0)
except Exception:
    pass
hook = transcript = None
if settings:
    hook = json.load(open(settings))["hooks"]["Stop"][0]["hooks"][0]["command"]
    session = session or "fake-session"
    transcript = os.path.join(os.path.dirname(os.path.dirname(settings)), "transcripts", session + ".jsonl")
    os.makedirs(os.path.dirname(transcript), exist_ok=True)
    open(transcript, "a").close()
def fire(event):
    event["session_id"] = session
    subprocess.run(["sh", "-c", hook], input=json.dumps(event).encode(), check=False)
def log(record):
    with open(transcript, "a") as f:
        f.write(json.dumps(record) + "\n")
TS = "2026-10-16T00:00:00.000Z"
if hook:
    fire({"hook_event_name": "SessionStart", "transcript_path": transcript, "source": "startup"})
events.write("started\n")
os.write(1, b"READY\r\n")
START, END = b"\x1b[200~", b"\x1b[201~\r"
buf, n, turns = b"", 0, []
while True:
    ready, _, _ = select.select([0], [], [], 0.02)
    if ready:
        data = os.read(0, 65536)
        if not data:
            break
        log_in.write(data)
        buf += data
        while hook:
            s = buf.find(START)
            e = buf.find(END, s + 1) if s >= 0 else -1
            if e < 0:
                break
            text = buf[s + len(START):e].decode("utf-8", "replace")
            buf = buf[e + len(END):]
            n += 1
            turn = "turn-%d" % n
            fire({"hook_event_name": "UserPromptSubmit", "prompt": text, "prompt_id": turn})
            log({"type": "user", "uuid": "u-%d" % n, "promptId": turn, "timestamp": TS,
                 "message": {"role": "user", "content": text}})
            turns.append(turn)
    complete = os.path.join(ctl, "complete")
    if turns and os.path.exists(complete):
        os.remove(complete)
        turn = turns.pop(0)
        log({"type": "assistant", "uuid": "a-" + turn, "promptId": turn, "timestamp": TS,
             "message": {"id": "msg-" + turn, "role": "assistant",
                         "content": [{"type": "text", "text": "done"}], "stop_reason": "end_turn"}})
        fire({"hook_event_name": "Stop"})
        events.write("completed %s\n" % turn)
"#;

// ── The fake Astation ─────────────────────────────────────────────────────

enum Event {
    /// Connection `n` authenticated.
    Authenticated(u64),
    Message(u64, Value),
}

enum Cmd {
    Send(String),
    Close,
}

struct FakeAstation {
    url: String,
    events: mpsc::Receiver<Event>,
    /// The command channel of each connection, by number.
    links: Arc<Mutex<HashMap<u64, tokio::sync::mpsc::UnboundedSender<Cmd>>>>,
}

impl FakeAstation {
    fn start() -> Self {
        let (url_tx, url_rx) = mpsc::channel();
        let (events_tx, events) = mpsc::channel();
        let links: Arc<Mutex<HashMap<u64, tokio::sync::mpsc::UnboundedSender<Cmd>>>> =
            Arc::default();
        let shared = links.clone();
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                url_tx
                    .send(format!("ws://{}/ws", listener.local_addr().unwrap()))
                    .unwrap();
                let mut next = 0u64;
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    next += 1;
                    let n = next;
                    let events = events_tx.clone();
                    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
                    shared.lock().unwrap().insert(n, cmd_tx);
                    tokio::spawn(link(n, stream, events, cmd_rx));
                }
            });
        });
        let url = url_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        Self { url, events, links }
    }

    fn send(&self, link: u64, text: String) {
        if let Some(tx) = self.links.lock().unwrap().get(&link) {
            let _ = tx.send(Cmd::Send(text));
        }
    }

    fn close(&self, link: u64) {
        if let Some(tx) = self.links.lock().unwrap().remove(&link) {
            let _ = tx.send(Cmd::Close);
        }
    }
}

/// One link: authenticates the runtime (any proof), then relays.
async fn link(
    n: u64,
    stream: tokio::net::TcpStream,
    events: mpsc::Sender<Event>,
    mut commands: tokio::sync::mpsc::UnboundedReceiver<Cmd>,
) {
    let Ok(mut socket) = tokio_tungstenite::accept_async(stream).await else {
        return;
    };
    let challenge = json!({"type": "statusUpdate", "data": {"status": "auth_required",
        "data": {"astation_id": ASTATION, "challenge": "b".repeat(64),
                 "transport": "lan", "protocol": "2"}}});
    if socket
        .send(Message::Text(challenge.to_string()))
        .await
        .is_err()
    {
        return;
    }
    loop {
        tokio::select! {
            frame = socket.next() => {
                let Some(Ok(frame)) = frame else { return };
                let Message::Text(text) = frame else { continue };
                let Ok(value) = serde_json::from_str::<Value>(&text) else { continue };
                if value["type"] == "statusUpdate" && value["data"]["status"] == "auth" {
                    let ok = json!({"type": "statusUpdate",
                                    "data": {"status": "authenticated", "data": {}}});
                    if socket.send(Message::Text(ok.to_string())).await.is_err() {
                        return;
                    }
                    let _ = events.send(Event::Authenticated(n));
                } else {
                    let _ = events.send(Event::Message(n, value));
                }
            }
            command = commands.recv() => match command {
                Some(Cmd::Send(text)) => {
                    if socket.send(Message::Text(text)).await.is_err() {
                        return;
                    }
                }
                Some(Cmd::Close) | None => {
                    let _ = socket.close(None).await;
                    return;
                }
            },
        }
    }
}

// ── The local frontend ────────────────────────────────────────────────────

struct Frontend {
    stream: UnixStream,
    messages: mpsc::Receiver<Value>,
}

impl Frontend {
    fn connect(socket: &Path) -> Self {
        let deadline = Instant::now() + WAIT;
        let stream = loop {
            if let Ok(stream) = UnixStream::connect(socket) {
                break stream;
            }
            assert!(Instant::now() < deadline, "the runtime didn't listen");
            std::thread::sleep(Duration::from_millis(50));
        };
        let (tx, messages) = mpsc::channel();
        let reader = BufReader::new(stream.try_clone().unwrap());
        // Drained continuously, so output never blocks the runtime.
        std::thread::spawn(move || {
            for line in reader.lines() {
                let Ok(line) = line else { return };
                let Ok(value) = serde_json::from_str::<Value>(&line) else {
                    continue;
                };
                if tx.send(value).is_err() {
                    return;
                }
            }
        });
        let mut frontend = Self { stream, messages };
        frontend.send(json!({"op": "hello", "protocol": 1, "build": "fixtures"}));
        frontend.until("welcome", |_| true);
        frontend
    }

    fn send(&mut self, mut message: Value) {
        message["v"] = json!(1);
        self.stream
            .write_all(format!("{message}\n").as_bytes())
            .unwrap();
    }

    /// The next message with `op` that `pick` accepts (errors fail).
    fn until(&mut self, op: &str, pick: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + WAIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let message = self
                .messages
                .recv_timeout(left)
                .unwrap_or_else(|_| panic!("the runtime never sent {op}"));
            assert_ne!(message["op"], "error", "{message}");
            if message["op"] == op && pick(&message) {
                return message;
            }
        }
    }

    fn list(&mut self) -> Vec<Value> {
        while self.messages.try_recv().is_ok() {}
        self.send(json!({"op": "list"}));
        self.until("sessions", |_| true)["sessions"]
            .as_array()
            .unwrap()
            .clone()
    }
}

// ── The sandbox and the runtime ───────────────────────────────────────────

struct Session {
    fixture_id: String,
    fixture_gen: String,
    real_id: String,
    chat: bool,
    dir: PathBuf,
}

struct Sandbox {
    dir: tempfile::TempDir,
    home: PathBuf,
    run: PathBuf,
    agent: PathBuf,
    clock: PathBuf,
    faults: PathBuf,
    runtime: Option<Child>,
    restarts: u32,
}

impl Sandbox {
    fn new() -> Self {
        // Unix socket paths are short: keep the sandbox in /tmp.
        let dir = tempfile::Builder::new()
            .prefix("atem-fx")
            .tempdir_in("/tmp")
            .unwrap();
        let home = dir.path().join("home");
        let run = dir.path().join("run");
        let faults = dir.path().join("faults");
        for d in [&home, &run, &faults] {
            std::fs::create_dir_all(d).unwrap();
        }
        std::fs::set_permissions(&run, std::fs::Permissions::from_mode(0o700)).unwrap();
        let agent = dir.path().join("fake-agent");
        std::fs::write(&agent, FAKE_AGENT).unwrap();
        std::fs::set_permissions(&agent, std::fs::Permissions::from_mode(0o700)).unwrap();
        let clock = dir.path().join("clock");
        std::fs::write(&clock, "0").unwrap();
        Self {
            dir,
            home,
            run,
            agent,
            clock,
            faults,
            runtime: None,
            restarts: 0,
        }
    }

    fn config(&self) -> PathBuf {
        self.home.join(".config").join("atem")
    }

    fn socket(&self) -> PathBuf {
        self.run.join("atem").join("runtime.sock")
    }

    /// Paired with `ASTATION` in `trust_gen` and verified as `account` /
    /// `device`; the next runtime epoch is `epoch`.
    fn profile(&self, account: &str, device: &str, trust_gen: u64, epoch: u64) {
        let config = self.config();
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(
            config.join("pairing.json"),
            json!({"version": 1, "host_trust_gen": trust_gen, "binding_id": "binding-1",
                   "astation_id": ASTATION, "created_at": 1})
            .to_string(),
        )
        .unwrap();
        let entry = json!({
            "device_id": device, "data_account": account, "sign_gen": 1,
            "astation_sign_pub": "", "astation_enc_pub": "", "recovery_sign_pub": "",
            "device_pub": "", "device_sign_pub": "", "unlock_auth_pub": "",
            "safety_code": "", "epoch_floor": 0, "account_state": null, "account_epoch": 0,
        });
        std::fs::write(
            config.join("cred_state.json"),
            json!({"version": 1, "astations": {ASTATION: entry}}).to_string(),
        )
        .unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        std::fs::write(
            config.join("sessions.json"),
            json!({"sessions": {ASTATION: {"session_id": "session-1", "token": "token-1",
                   "astation_id": ASTATION, "hostname": "h", "last_activity": now}}})
            .to_string(),
        )
        .unwrap();
        self.next_epoch(epoch);
    }

    /// The runtime that starts next takes `epoch` (it adds one to the file).
    fn next_epoch(&self, epoch: u64) {
        let journal = self.config().join("runtime").join("journal");
        std::fs::create_dir_all(&journal).unwrap();
        for d in [self.config().join("runtime"), journal.clone()] {
            std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let file = journal.join("runtime_epoch");
        std::fs::write(&file, (epoch - 1).to_string()).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn start_runtime(&mut self, astation: &str) {
        let log = std::fs::File::create(
            self.dir
                .path()
                .join(format!("runtime-{}.log", self.restarts)),
        )
        .unwrap();
        self.restarts += 1;
        let child = Command::new(env!("CARGO_BIN_EXE_atem"))
            .arg("runtime")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &self.home)
            .env("XDG_RUNTIME_DIR", &self.run)
            .env("ASTATION_WS", astation)
            .env("ASTATION_RELAY_URL", "http://127.0.0.1:1")
            .env("ATEM_TEST_CLOCK_FILE", &self.clock)
            .env("ATEM_TEST_PTY_FAULTS", &self.faults)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        self.runtime = Some(child);
    }

    fn kill_runtime(&mut self) {
        if let Some(mut child) = self.runtime.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    fn logs(&self) -> String {
        let mut text = String::new();
        for i in 0..self.restarts {
            let path = self.dir.path().join(format!("runtime-{i}.log"));
            text.push_str(&std::fs::read_to_string(path).unwrap_or_default());
        }
        text
    }

    fn worker_record(&self, sid: &str) -> Value {
        let path = self
            .config()
            .join("runtime")
            .join("workers")
            .join(format!("{sid}.json"));
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
    }
}

impl Drop for Sandbox {
    /// Ends the runtime and every process that carries this sandbox's path
    /// in its command line or environment (its workers and agents) — only
    /// those.
    fn drop(&mut self) {
        self.kill_runtime();
        let marker = self.dir.path().as_os_str().as_encoded_bytes().to_vec();
        let own = std::process::id();
        for _ in 0..3 {
            let Ok(entries) = std::fs::read_dir("/proc") else {
                return;
            };
            for entry in entries.flatten() {
                let Some(pid) = entry
                    .file_name()
                    .to_str()
                    .and_then(|s| s.parse::<u32>().ok())
                else {
                    continue;
                };
                if pid == own {
                    continue;
                }
                let carries = ["cmdline", "environ"].iter().any(|f| {
                    std::fs::read(format!("/proc/{pid}/{f}"))
                        .is_ok_and(|b| b.windows(marker.len()).any(|w| w == marker))
                });
                if carries {
                    unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

// ── The host under test ───────────────────────────────────────────────────

struct Host {
    sandbox: Sandbox,
    astation: FakeAstation,
    link: u64,
    /// The newest link that authenticated.
    authenticated: u64,
    frontend: Frontend,
    client: String,
    client_setup: Value,
    host: Value,
    sessions: Vec<Session>,
    /// (fixture value, runtime value) pairs, translated in both directions.
    ids: Vec<(String, String)>,
    /// The runtime generation the next welcome maps to.
    next_runtime_gen: String,
    clock: u64,
    /// Host→client messages not expected yet (fixture identifiers).
    queue: VecDeque<Value>,
    holds: Vec<String>,
    held: Vec<Value>,
    vars: HashMap<String, Value>,
    /// Terminal input sent, in order: (real session id, local, bytes).
    chunks: Vec<(String, bool, Vec<u8>)>,
    dropped_acks: u64,
}

fn replace_strings(v: &mut Value, pairs: &[(String, String)], forward: bool) {
    match v {
        Value::String(s) => {
            for (fixture, real) in pairs {
                let (from, to) = if forward {
                    (fixture, real)
                } else {
                    (real, fixture)
                };
                if s.contains(from.as_str()) {
                    *s = s.replace(from.as_str(), to);
                }
            }
        }
        Value::Array(a) => a
            .iter_mut()
            .for_each(|c| replace_strings(c, pairs, forward)),
        Value::Object(m) => m
            .values_mut()
            .for_each(|c| replace_strings(c, pairs, forward)),
        _ => {}
    }
}

/// `${name}` in every string (a string that is exactly one placeholder takes
/// the value itself).
fn substitute(v: &mut Value, vars: &HashMap<String, Value>) -> Result<(), String> {
    match v {
        Value::String(s) if s.contains("${") => {
            if let Some(name) = s.strip_prefix("${").and_then(|r| r.strip_suffix('}'))
                && !name.contains(['$', '{', '}'])
            {
                *v = vars
                    .get(name)
                    .cloned()
                    .ok_or(format!("${{{name}}} not captured"))?;
                return Ok(());
            }
            let mut out = String::new();
            let mut rest = s.as_str();
            while let Some(start) = rest.find("${") {
                out.push_str(&rest[..start]);
                let end = rest[start..].find('}').ok_or("unterminated ${")? + start;
                let name = &rest[start + 2..end];
                match vars.get(name) {
                    Some(Value::String(t)) => out.push_str(t),
                    Some(other) => out.push_str(&other.to_string()),
                    None => return Err(format!("${{{name}}} not captured")),
                }
                rest = &rest[end + 1..];
            }
            out.push_str(rest);
            *s = out;
            Ok(())
        }
        Value::Array(a) => a.iter_mut().try_for_each(|c| substitute(c, vars)),
        Value::Object(m) => m.values_mut().try_for_each(|c| substitute(c, vars)),
        _ => Ok(()),
    }
}

/// Dotted path into `data` (`receipts.0.state`; `#` is an array's length).
fn lookup(data: &Value, path: &str) -> Option<Value> {
    path.split('.').try_fold(data.clone(), |v, part| match v {
        Value::Object(mut m) => m.remove(part),
        Value::Array(a) if part == "#" => Some(Value::from(a.len())),
        Value::Array(mut a) => part
            .parse::<usize>()
            .ok()
            .filter(|i| *i < a.len())
            .map(|i| a.swap_remove(i)),
        _ => None,
    })
}

fn uuid() -> String {
    // Unique enough for request ids the harness sends itself.
    use std::sync::atomic::{AtomicU64, Ordering};
    static N: AtomicU64 = AtomicU64::new(1);
    let n = N.fetch_add(1, Ordering::SeqCst);
    format!(
        "eeeeeeee-eeee-4eee-8eee-{:012x}",
        n + ((std::process::id() as u64) << 24)
    )
}

/// Why a scenario can't run against the real runtime, if it can't.
fn unsupported(scenario: &Value) -> Option<String> {
    let clients = scenario["setup"]["clients"].as_array().map_or(0, Vec::len);
    if clients != 1 {
        return Some(format!(
            "{clients} clients: the runtime holds one Astation link, so one attachment at a time"
        ));
    }
    for step in scenario["steps"].as_array().into_iter().flatten() {
        for (action, why) in [
            (
                "close_session",
                "the runtime never closes a running session",
            ),
            ("disconnect", "no resume in compatibility mode"),
            ("resume", "no resume in compatibility mode"),
            ("fail_next_fsync", "no fsync fault on the real journal"),
            (
                "change_trust_gen",
                "trust generations change only by pairing",
            ),
            (
                "open_approval",
                "approvals are core-only until the runtime wires permission hooks",
            ),
        ] {
            if step.get(action).is_some() {
                return Some(format!("{action}: {why}"));
            }
        }
    }
    None
}

impl Host {
    fn start(scenario: &Value) -> Result<Self, String> {
        let setup = &scenario["setup"];
        let host = setup["host"].clone();
        let client_setup = setup["clients"][0].clone();
        let mut sandbox = Sandbox::new();
        sandbox.profile(
            host["account_id"].as_str().unwrap(),
            host["atem_device_id"].as_str().unwrap(),
            host["host_trust_gen"].as_u64().unwrap(),
            host["runtime_epoch"].as_u64().unwrap(),
        );
        let astation = FakeAstation::start();
        sandbox.start_runtime(&astation.url);
        let mut frontend = Frontend::connect(&sandbox.socket());
        let work = sandbox.home.join("work");
        std::fs::create_dir_all(&work).unwrap();
        let mut sessions = Vec::new();
        let mut ids = Vec::new();
        for (i, s) in setup["sessions"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            let chat = s["chat"].as_bool().unwrap_or(false);
            let dir = sandbox.dir.path().join(format!("agent-{i}"));
            let (provider, bin) = if chat {
                ("claude", "CLAUDE_CLI_BIN")
            } else {
                ("codex", "CODEX_CLI_BIN")
            };
            frontend.send(json!({
                "op": "launch", "provider": provider, "args": [], "cwd": work,
                "env": [["PATH", "/usr/bin:/bin"], [bin, sandbox.agent],
                        ["FAKE_DIR", dir], ["HOME", sandbox.home]],
                "rows": 24, "cols": 80,
            }));
            let launched = frontend.until("launched", |_| true);
            let real_id = launched["session"]["id"].as_str().unwrap().to_string();
            let generation = launched["session"]["generation"].as_str().unwrap();
            ids.push((
                s["session_id"].as_str().unwrap().to_string(),
                real_id.clone(),
            ));
            ids.push((
                s["process_gen"].as_str().unwrap().to_string(),
                generation.into(),
            ));
            frontend.send(json!({"op": "attach", "session_id": real_id, "rows": 24, "cols": 80}));
            frontend.until("attached", |_| true);
            sessions.push(Session {
                fixture_id: s["session_id"].as_str().unwrap().into(),
                fixture_gen: s["process_gen"].as_str().unwrap().into(),
                real_id,
                chat,
                dir,
            });
        }
        let mut me = Self {
            sandbox,
            astation,
            link: 0,
            authenticated: 0,
            frontend,
            client: client_setup["name"].as_str().unwrap().into(),
            client_setup,
            next_runtime_gen: host["runtime_gen"].as_str().unwrap().into(),
            host,
            sessions,
            ids,
            clock: 0,
            queue: VecDeque::new(),
            holds: Vec::new(),
            held: Vec::new(),
            vars: HashMap::new(),
            chunks: Vec::new(),
            dropped_acks: 0,
        };
        me.wait_sessions_ready()?;
        let attachment = me.client_setup["attachment_gen"]
            .as_str()
            .unwrap()
            .to_string();
        me.attach(&attachment)?;
        if let Some(epoch) = me.client_setup["holds_lease_epoch"].as_u64() {
            me.setup_lease(epoch)?;
        }
        Ok(me)
    }

    /// Every agent started; Claude's chat is ready.
    fn wait_sessions_ready(&mut self) -> Result<(), String> {
        let deadline = Instant::now() + WAIT;
        loop {
            let listed = self.frontend.list();
            let ready = self.sessions.iter().all(|s| {
                let started = std::fs::read_to_string(s.dir.join("events"))
                    .is_ok_and(|e| e.contains("started"));
                let summary = listed.iter().find(|l| l["id"] == s.real_id.as_str());
                started
                    && summary.is_some_and(|l| {
                        l["state"] == "running" && (!s.chat || l["status"] == "ready")
                    })
            });
            if ready {
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err(format!("sessions never became ready: {listed:?}"));
            }
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// The next authenticated link, then hello → welcome on it (retried
    /// until the runtime attached the link); maps the attachment to the
    /// fixture's `attachment_gen`.
    fn attach(&mut self, attachment_gen: &str) -> Result<(), String> {
        let deadline = Instant::now() + WAIT;
        while self.authenticated <= self.link {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.astation.events.recv_timeout(left) {
                Ok(event) => self.event_in(event),
                Err(_) => return Err("the runtime's link never authenticated".into()),
            }
        }
        self.link = self.authenticated;
        loop {
            let id = uuid();
            let hello = json!({"type": "session", "data": {"v": 1, "op": "hello", "id": id}});
            self.astation.send(self.link, hello.to_string());
            let reply = self.raw_reply(&id)?;
            if reply["op"] == "error" && reply["code"] == "unauthorized" {
                if Instant::now() > deadline {
                    return Err("the link was never attached".into());
                }
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            if reply["op"] != "welcome" {
                return Err(format!("hello: {reply}"));
            }
            for key in ["account_id", "atem_device_id", "host_trust_gen"] {
                if reply[key] != self.host[key] {
                    return Err(format!(
                        "welcome {key}: {} vs {}",
                        reply[key], self.host[key]
                    ));
                }
            }
            if reply["client_kind"] != self.client_setup["client_kind"] {
                return Err(format!("welcome client_kind {}", reply["client_kind"]));
            }
            let granted: Vec<&Value> = reply["permissions"].as_array().unwrap().iter().collect();
            for p in self.client_setup["permissions"].as_array().unwrap() {
                if !granted.contains(&p) {
                    return Err(format!("welcome lacks permission {p}"));
                }
            }
            let real_gen = reply["runtime_gen"].as_str().unwrap().to_string();
            if !self.ids.iter().any(|(_, r)| *r == real_gen) {
                self.ids.push((self.next_runtime_gen.clone(), real_gen));
            }
            let real_attachment = reply["attachment_gen"].as_str().unwrap().to_string();
            self.ids.push((attachment_gen.to_string(), real_attachment));
            return Ok(());
        }
    }

    /// The session reply to the harness's own request `id` (runtime ids),
    /// taken out of the stream; other messages are queued as usual.
    fn raw_reply(&mut self, id: &str) -> Result<Value, String> {
        let deadline = Instant::now() + WAIT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            let event = self
                .astation
                .events
                .recv_timeout(left)
                .map_err(|_| format!("no reply to {id}"))?;
            match event {
                Event::Message(n, value)
                    if n == self.link
                        && value["type"] == "session"
                        && value["data"]["re"] == id =>
                {
                    return Ok(value["data"].clone());
                }
                event => self.event_in(event),
            }
        }
    }

    fn setup_lease(&mut self, epoch: u64) -> Result<(), String> {
        let [session] = self.sessions.as_slice() else {
            return Err("holds_lease_epoch needs exactly one session".into());
        };
        let id = uuid();
        let mut acquire = json!({"type": "session", "data": {"v": 1, "op": "acquire", "id": id,
            "takeover": false, "binding": self.binding(session)}});
        replace_strings(&mut acquire, &self.ids, true);
        self.astation.send(self.link, acquire.to_string());
        let reply = self.raw_reply(&id)?;
        if reply["op"] != "lease" || reply["binding"]["lease_epoch"] != epoch {
            return Err(format!("setup acquire: {reply}"));
        }
        Ok(())
    }

    /// The binding of the fixture's client for `session` (fixture ids).
    fn binding(&self, session: &Session) -> Value {
        json!({"target": {"account_id": self.host["account_id"],
                          "atem_device_id": self.host["atem_device_id"],
                          "host_trust_gen": self.host["host_trust_gen"],
                          "session_id": session.fixture_id, "process_gen": session.fixture_gen},
               "attachment_gen": self.client_setup["attachment_gen"]})
    }

    /// A message from the runtime: translated, filtered, held or queued.
    fn incoming(&mut self, mut value: Value) {
        let family = value["type"].as_str().unwrap_or_default().to_string();
        if !matches!(family.as_str(), "session" | "terminal" | "agentChat") {
            return;
        }
        let op = value["data"]["op"].as_str().unwrap_or_default().to_string();
        if family == "terminal" && op == "frame" {
            return;
        }
        if family == "terminal" && op == "written" {
            if value["data"]["error"] == "control changed; not written" {
                self.dropped_acks += 1;
            }
            return;
        }
        replace_strings(&mut value, &self.ids, false);
        if let Some(i) = self.holds.iter().position(|o| *o == op) {
            self.holds.remove(i);
            self.held.push(value);
        } else {
            self.queue.push_back(value);
        }
    }

    /// Takes in what the runtime sent for `time`.
    fn pump(&mut self, time: Duration) {
        let deadline = Instant::now() + time;
        while let Ok(event) = self
            .astation
            .events
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            self.event_in(event);
        }
    }

    fn event_in(&mut self, event: Event) {
        match event {
            Event::Authenticated(n) => self.authenticated = self.authenticated.max(n),
            // Only the current link's messages reach the client.
            Event::Message(n, value) if n == self.link => self.incoming(value),
            Event::Message(..) => {}
        }
    }

    fn send(&mut self, json: &Value) {
        let mut message = json.clone();
        if message["type"] == "terminal" && message["data"]["op"] == "input" {
            let sid = message["data"]["terminal_id"].as_str().unwrap_or_default();
            let real = self.real(sid);
            if let Ok(bytes) = STANDARD.decode(message["data"]["bytes"].as_str().unwrap_or("")) {
                self.chunks.push((real, false, bytes));
            }
        }
        replace_strings(&mut message, &self.ids, true);
        self.astation.send(self.link, message.to_string());
    }

    fn real(&self, fixture: &str) -> String {
        self.ids
            .iter()
            .find(|(f, _)| f == fixture)
            .map_or(fixture.to_string(), |(_, r)| r.clone())
    }

    fn session(&self, fixture: &str) -> Result<&Session, String> {
        self.sessions
            .iter()
            .find(|s| s.fixture_id == fixture)
            .ok_or(format!("unknown session {fixture}"))
    }

    fn expect(&mut self, ty: Option<&str>, matches: &Map<String, Value>) -> Result<Value, String> {
        let op = matches.get("op");
        let deadline = Instant::now() + WAIT;
        loop {
            let selected = self.queue.iter().position(|m| {
                ty.is_none_or(|t| m["type"] == t) && op.is_none_or(|o| &m["data"]["op"] == o)
            });
            if let Some(i) = selected {
                let msg = self.queue.remove(i).unwrap();
                let data = msg["data"].clone();
                for (path, expected) in matches {
                    let got = lookup(&data, path);
                    if got.as_ref() != Some(expected) {
                        return Err(format!("{path}: expected {expected}, got {got:?} in {msg}"));
                    }
                }
                return Ok(data);
            }
            if Instant::now() > deadline {
                return Err(format!(
                    "no {} message{}; queued: {:?}",
                    ty.unwrap_or("matching"),
                    op.map_or(String::new(), |o| format!(" with op {o}")),
                    self.queue
                ));
            }
            self.pump(Duration::from_millis(50));
        }
    }

    fn advance(&mut self, ms: u64) {
        self.clock += ms;
        let temp = self.sandbox.clock.with_extension("tmp");
        std::fs::write(&temp, self.clock.to_string()).unwrap();
        std::fs::rename(&temp, &self.sandbox.clock).unwrap();
    }

    fn marker(&self, name: &str, on: bool) {
        let path = self.sandbox.faults.join(name);
        if on {
            std::fs::write(path, "").unwrap();
        } else {
            let _ = std::fs::remove_file(path);
        }
    }

    fn event(
        &mut self,
        action: &str,
        arg: &Value,
        step: &Map<String, Value>,
    ) -> Result<(), String> {
        self.pump(SETTLE);
        match action {
            "local_input" => {
                let session = self
                    .session(arg.as_str().unwrap_or_default())?
                    .real_id
                    .clone();
                let text = step["bytes"].as_str().ok_or("bytes")?;
                let bytes = STANDARD.decode(text).map_err(|e| e.to_string())?;
                self.chunks.push((session.clone(), true, bytes));
                self.frontend
                    .send(json!({"op": "input", "session_id": session, "bytes": text}));
            }
            "crash_worker" => {
                let session = self
                    .session(arg.as_str().unwrap_or_default())?
                    .real_id
                    .clone();
                let pid = self.sandbox.worker_record(&session)["worker_pid"]
                    .as_u64()
                    .ok_or("no worker pid")?;
                unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
            }
            "restart_runtime" => {
                self.sandbox.kill_runtime();
                self.sandbox
                    .next_epoch(arg["runtime_epoch"].as_u64().ok_or("runtime_epoch")?);
                self.next_runtime_gen = arg["runtime_gen"].as_str().ok_or("runtime_gen")?.into();
                let url = self.astation.url.clone();
                self.sandbox.start_runtime(&url);
                self.frontend = Frontend::connect(&self.sandbox.socket());
                // `list` answers once the surviving workers are adopted.
                self.frontend.list();
                for s in &self.sessions {
                    self.frontend.send(
                        json!({"op": "attach", "session_id": s.real_id, "rows": 24, "cols": 80}),
                    );
                    self.frontend.until("attached", |_| true);
                }
            }
            "reconnect" => {
                let attachment = step["attachment_gen"].as_str().ok_or("attachment_gen")?;
                // After a restart the old link is gone already.
                self.astation.close(self.link);
                self.attach(attachment)?;
            }
            "hold_pty_writes" => self.marker("hold", true),
            "flush_pty_writes" => self.marker("hold", false),
            "fail_next_pty_enqueue" => self.marker("fail_next_enqueue", true),
            "fail_next_pty_write_after_partial" => self.marker("fail_next_partial", true),
            "turn_complete" => {
                let dir = self.session(arg.as_str().unwrap_or_default())?.dir.clone();
                let turn = step["turn_id"].as_str().ok_or("turn_id")?;
                std::fs::write(dir.join("complete"), turn).unwrap();
            }
            other => return Err(format!("{other} is not supported against the real runtime")),
        }
        self.pump(SETTLE);
        Ok(())
    }

    fn counter(&mut self, key: &str) -> Result<Value, String> {
        let used = std::fs::read_to_string(self.sandbox.faults.join("used")).unwrap_or_default();
        let mut dispatches = 0u64;
        let mut paste_bytes = 0usize;
        let (mut local, mut remote) = (0u64, 0u64);
        let mut stops = 0u64;
        let mut resizes = 0u64;
        for s in &self.sessions {
            let input = std::fs::read(s.dir.join("input")).unwrap_or_default();
            let mut terminal = Vec::new();
            let mut rest = &input[..];
            while let Some(start) = find(rest, PASTE_START) {
                terminal.extend_from_slice(&rest[..start]);
                dispatches += 1;
                let after = &rest[start..];
                let end = find(after, PASTE_END).map_or(after.len(), |e| e + PASTE_END.len());
                paste_bytes += end;
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
            if at != terminal.len() {
                return Err(format!(
                    "{}: the agent got input nobody sent: {:?}",
                    s.fixture_id,
                    String::from_utf8_lossy(&terminal[at..])
                ));
            }
            let events = std::fs::read_to_string(s.dir.join("events")).unwrap_or_default();
            stops += events.matches("worker_alive=True").count() as u64;
            resizes += events.matches("winch").count() as u64;
        }
        let enqueue_faults = used.matches("fail_next_enqueue").count() as u64;
        Ok(match key {
            "dispatches" => json!(dispatches),
            "dispatch_attempts" => json!(dispatches + enqueue_faults),
            "pty_bytes_written" if used.contains("fail_next_partial") => json!("unknown"),
            "pty_bytes_written" => json!(paste_bytes),
            "pty_writes" => json!(local + remote),
            "pty_writes_local" => json!(local),
            "pty_writes_remote" => json!(remote),
            "pty_writes_dropped" => json!(self.dropped_acks),
            "stops" => json!(stops),
            "resizes" => json!(resizes),
            "lease_holder" => {
                let listed = self.frontend.list();
                let held = listed.iter().any(|s| s["remote_controlled"] == true);
                if held {
                    json!(self.client)
                } else {
                    Value::Null
                }
            }
            other => return Err(format!("{other} is not observable on the real runtime")),
        })
    }

    fn step(&mut self, raw: &Value) -> Result<(), String> {
        let mut step = raw.clone();
        substitute(&mut step, &self.vars)?;
        let Value::Object(step) = step else {
            return Err("a step must be an object".into());
        };
        const COMPANIONS: &[&str] = &[
            "json",
            "type",
            "match",
            "capture",
            "for_ms",
            "timers",
            "bytes",
            "attachment_gen",
            "turn_id",
        ];
        let actions: Vec<&String> = step
            .keys()
            .filter(|k| !COMPANIONS.contains(&k.as_str()))
            .collect();
        let [action] = actions.as_slice() else {
            return Err(format!("expected one action, found {actions:?}"));
        };
        let action = action.as_str();
        let arg = &step[action];
        let client_ok = |v: &Value| -> Result<(), String> {
            if v.as_str() == Some(self.client.as_str()) {
                Ok(())
            } else {
                Err(format!("unknown client {v}"))
            }
        };
        match action {
            "send" => {
                client_ok(arg)?;
                self.send(&step["json"]);
                self.pump(Duration::from_millis(50));
            }
            "expect" | "expect_all" => {
                let (ty, matches) = if action == "expect" {
                    client_ok(arg)?;
                    (
                        step.get("type").and_then(Value::as_str),
                        step.get("match").cloned().unwrap_or(json!({})),
                    )
                } else {
                    (None, arg.clone())
                };
                let matches = matches
                    .as_object()
                    .ok_or("match must be an object")?
                    .clone();
                let ty = ty.map(str::to_string);
                let data = self.expect(ty.as_deref(), &matches)?;
                if let Some(capture) = step.get("capture").and_then(Value::as_object) {
                    for (name, path) in capture {
                        let path = path.as_str().ok_or("capture path")?;
                        let v = lookup(&data, path).ok_or(format!("capture {path}: missing"))?;
                        self.vars.insert(name.clone(), v);
                    }
                }
            }
            "expect_none" => {
                client_ok(arg)?;
                self.advance(step["for_ms"].as_u64().ok_or("for_ms")?);
                self.pump(SETTLE);
                if let Some(m) = self.queue.front() {
                    return Err(format!("{} received {m}", self.client));
                }
            }
            "advance_ms" => {
                self.advance(arg.as_u64().ok_or("advance_ms")?);
                self.pump(SETTLE);
            }
            "hold" => {
                let to = arg.get("to").ok_or("hold.to")?;
                client_ok(to)?;
                let op = arg["op"].as_str().ok_or("hold.op")?;
                self.holds.push(op.into());
            }
            "deliver" => {
                if self.held.is_empty() {
                    return Err("nothing held".into());
                }
                let held = std::mem::take(&mut self.held);
                self.queue.extend(held);
            }
            "assert" => {
                self.pump(SETTLE);
                for (key, expected) in arg.as_object().ok_or("assert must be an object")? {
                    let got = self.counter(key)?;
                    if &got != expected {
                        let all: Vec<String> = [
                            "pty_writes_local",
                            "pty_writes_remote",
                            "pty_writes_dropped",
                            "dispatch_attempts",
                            "dispatches",
                        ]
                        .iter()
                        .map(|k| format!("{k}={}", self.counter(k).unwrap_or_default()))
                        .collect();
                        return Err(format!(
                            "{key}: expected {expected}, got {got} ({})",
                            all.join(", ")
                        ));
                    }
                }
            }
            _ => self.event(action, arg, &step)?,
        }
        Ok(())
    }

    fn finish(&mut self) -> Result<(), String> {
        self.pump(SETTLE);
        if let Some(m) = self.held.first() {
            return Err(format!("held message never delivered: {m}"));
        }
        if let Some(m) = self.queue.front() {
            return Err(format!(
                "{} has {} unexpected message(s), first: {m}",
                self.client,
                self.queue.len()
            ));
        }
        Ok(())
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

fn run(scenario: &Value) -> Result<(), String> {
    let mut host = Host::start(scenario)?;
    let result = (|| {
        for (i, step) in scenario["steps"].as_array().unwrap().iter().enumerate() {
            host.step(step)
                .map_err(|e| format!("step {i} {step}: {e}"))?;
        }
        host.finish()
    })();
    result.map_err(|e| format!("{e}\n--- runtime log ---\n{}", host.sandbox.logs()))
}

fn scenarios() -> Vec<Value> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("designs/protocol/fixtures");
    let mut files: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "json"))
        .filter(|p| p.file_name().is_some_and(|n| n != "digest-vectors.json"))
        .collect();
    files.sort();
    files
        .iter()
        .map(|p| serde_json::from_slice(&std::fs::read(p).unwrap()).unwrap())
        .filter(|v: &Value| v.get("side").is_none_or(|s| s == "host"))
        .collect()
}

/// The host scenarios that can't be honoured against real processes (the
/// reason is printed); every other scenario runs.
const NOT_RUN: &[&str] = &[
    // Approvals (contract r7) run in the core harness only until the runtime
    // opens approvals from the agents' permission hooks.
    "approval-allow-always-must-name-an-offered-rule",
    "approval-allow-once-is-handed-to-the-agent-and-completes",
    "approval-answered-in-the-terminal-first-refuses-the-late-remote-answer",
    "approval-closes-when-the-lease-is-lost",
    "approval-deny-carries-the-message-to-the-agent",
    "approval-duplicate-submit-returns-the-receipt",
    "approval-needs-control-and-the-lease",
    "approval-pending-is-sent-again-after-list",
    "approval-survives-takeover",
    "closed-session-refuses-work-before-the-lease-check",
    "receipt-query-is-scoped-to-the-exact-target",
    "removed-ops-have-no-effect",
    "takeover-moves-control-and-the-old-holder-becomes-a-viewer",
];

/// Scenarios the real runtime fails, each with the failure it must still
/// show (a fix makes the test fail until the entry is removed). None today.
const KNOWN_DEVIATIONS: &[(&str, &str)] = &[];

fn run_named(scenarios: &[Value], only: Option<&str>) -> Vec<(String, Result<(), String>)> {
    std::thread::scope(|scope| {
        let handles: Vec<_> = scenarios
            .iter()
            .filter(|s| only.is_none_or(|o| s["name"] == o))
            .map(|s| {
                let name = s["name"].as_str().unwrap().to_string();
                let handle = scope.spawn(move || match unsupported(s) {
                    Some(why) => Err(format!("not run: {why}")),
                    None => run(s),
                });
                (name, handle)
            })
            .collect();
        handles
            .into_iter()
            .map(|(name, h)| (name, h.join().unwrap_or_else(|_| Err("panicked".into()))))
            .collect()
    })
}

#[test]
fn shared_host_fixtures_run_against_the_real_runtime() {
    let scenarios = scenarios();
    assert!(scenarios.len() >= 13, "host fixtures missing");
    let only = std::env::var("ATEM_FIXTURE").ok();
    let results = run_named(&scenarios, only.as_deref());
    let mut failed = Vec::new();
    for (name, result) in &results {
        let known = KNOWN_DEVIATIONS.iter().find(|(n, _)| n == name);
        let not_run = NOT_RUN.contains(&name.as_str());
        match (result, known) {
            (Err(e), _) if e.starts_with("not run:") && not_run => {
                eprintln!("NOT RUN  {name} ({})", &e["not run: ".len()..])
            }
            (Err(e), Some((_, failure))) if e.contains(failure) => {
                eprintln!("KNOWN    {name} ({failure})")
            }
            (Ok(()), None) if !not_run => eprintln!("PASS     {name}"),
            (Ok(()), _) => {
                eprintln!("FAIL     {name}");
                failed.push(format!(
                    "{name}: passes now; take it off NOT_RUN/KNOWN_DEVIATIONS"
                ));
            }
            (Err(e), _) => {
                eprintln!("FAIL     {name}");
                failed.push(format!("{name}: {e}"));
            }
        }
    }
    assert!(failed.is_empty(), "{}", failed.join("\n\n"));
}

/// The harness fails a scenario whose expectation or counter is changed, so
/// a pass means the runtime produced what the fixture says.
#[test]
fn a_changed_expectation_fails_against_the_real_runtime() {
    let scenarios = scenarios();
    let named = |name: &str| {
        scenarios
            .iter()
            .find(|s| s["name"] == name)
            .unwrap()
            .clone()
    };
    let mut lease = named("lease-expires-without-renewal");
    let step = lease["steps"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|s| s["match"]["reason"] == "expired")
        .unwrap();
    step["match"]["lease_epoch"] = json!(3);
    let mut dispatch = named("dispatch-failure-before-any-effect-is-rejected");
    let last = dispatch["steps"]
        .as_array_mut()
        .unwrap()
        .last_mut()
        .unwrap();
    last["assert"]["dispatch_attempts"] = json!(2);
    let results = run_named(&[lease, dispatch], None);
    for (name, result) in results {
        let error = result.expect_err(&name);
        assert!(error.contains("expected"), "{name}: {error}");
    }
}

/// `scenario` with client `from` folded into client `into`: one attachment
/// plays both (their sends and expectations, with `from`'s attachment
/// generation replaced by `into`'s), minus what only a second attachment
/// would hear (`lease_changed` for `from`).
fn one_attachment(scenario: &Value, into: &str, from: &str) -> Value {
    let mut s = scenario.clone();
    let clients = s["setup"]["clients"].as_array().unwrap().clone();
    let gen_of = |name: &str| {
        clients.iter().find(|c| c["name"] == name).unwrap()["attachment_gen"]
            .as_str()
            .unwrap()
            .to_string()
    };
    let (keep, drop) = (gen_of(into), gen_of(from));
    s["setup"]["clients"] = json!(
        clients
            .into_iter()
            .filter(|c| c["name"] == into)
            .collect::<Vec<_>>()
    );
    let steps: Vec<Value> = s["steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|step| !(step["expect"] == from && step["match"]["op"] == "lease_changed"))
        .map(|step| {
            let text = step
                .to_string()
                .replace(&drop, &keep)
                .replace(
                    &format!("\"send\":\"{from}\""),
                    &format!("\"send\":\"{into}\""),
                )
                .replace(
                    &format!("\"expect\":\"{from}\""),
                    &format!("\"expect\":\"{into}\""),
                );
            serde_json::from_str(&text).unwrap()
        })
        .collect();
    s["steps"] = json!(steps);
    s
}

/// removed-ops-have-no-effect needs two clients; one attachment can still
/// express it: the lease holder itself sends every removed op, with and
/// without the lease, and local input still works.
#[test]
fn removed_ops_have_no_effect_on_one_attachment() {
    let scenario = scenarios()
        .into_iter()
        .find(|s| s["name"] == "removed-ops-have-no-effect")
        .unwrap();
    let single = one_attachment(&scenario, "up", "other");
    if let Err(e) = run(&single) {
        panic!("{e}");
    }
}

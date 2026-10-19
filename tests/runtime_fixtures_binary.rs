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
//! - `restart_runtime`: SIGTERM to the runtime (an orderly stop, r8: it
//!   writes its journal's clean close), `crash_runtime`: SIGKILL; the next
//!   one (with the fixture's runtime epoch) adopts the surviving workers.
//! - `reconnect`: the fake Astation closes the link; the runtime reconnects
//!   and authenticates again (a new attachment).
//! - `hold_pty_writes`/`flush_pty_writes`, `fail_next_pty_enqueue`,
//!   `fail_next_pty_write_after_partial`: markers the workers' PTY writer
//!   reads (`ATEM_TEST_PTY_FAULTS`, debug builds; `src/runtime/test_hooks.rs`).
//!
//!   The scenarios need the clock and these markers, which release builds
//!   compile out (the runtime then runs on its real clock and never fails a
//!   PTY write): under `cargo test --release` the tests that run scenarios
//!   are ignored rather than failed or passed vacuously.
//! - `turn_complete`: the fake Claude ends its running turn (its prompt ids
//!   are `turn-<n>`, which the chat adapter reports as turn ids).
//! - `open_approval`: the fake Claude (a scenario with approvals runs its
//!   session as Claude) asks for a tool call: the real `PermissionRequest`
//!   hook Atem configured runs with it (rules from the fixture's labels
//!   `Tool(content)`; the runtime's rule ids, labels — "Allow …" — and scopes
//!   are translated like other identifiers). `close_approval` with
//!   `answered_terminal`: the user allows it in the agent's own dialog (the
//!   tool runs); `approval_applied` with `ok: true`: nothing to do, the agent
//!   acts on the decision its hook got by itself.
//! - `chat_history`/`chat_message`/`chat_turn` (local origin): the fake
//!   Claude appends the messages to its transcript as Claude Code writes
//!   them (`transcript-<n>.jsonl`; no hook runs, so the chat status stays as
//!   it is); after `chat_history` the harness waits until a probe
//!   conversation's newest page holds them (the probe never reaches the
//!   client or the counters). `expect_live` and `recover` work as in the
//!   core runner; `chat_opens`/`chat_closes`/`chat_conversations` count the
//!   `opened`/`close` the link carried (and the client's own `close`).
//!
//! Not honoured (the scenario is reported, with the reason, and not run):
//! more than one client (the runtime holds one Astation link, so one
//! attachment at a time), `close_session` (the runtime never closes a
//! running session), `disconnect`/`resume` (no resume in compatibility
//! mode), `fail_next_fsync`/`fail_fsync_of`/`crash_after_accepted` (no
//! journal faults in the real runtime), `set_permissions` (the link's one
//! principal always has `control`), `drop`, `replace_process`,
//! `change_trust_gen`, `approval_rules` (session
//! rules come only from a Codex session), `chat_evict` (retention evicts
//! only past 500 messages / 8 MiB), `worker_gap` (no backlog fault in the
//! worker), `chat_turn` of a remote prompt (the real adapter's status events
//! around the turn are sequenced too), and approval closes other
//! than `answered_terminal`/`interrupted` or `approval_applied` with `ok:
//! false`. An `r8-*` scenario runs once the host work it needs is
//! implemented (`src/session_protocol/revision.rs`, shared with the core
//! runner), else it is reported as not run with what it still needs.
//! The harness's `hello` carries `revision: 8` and the welcome must echo it
//! and advertise exactly this host's features.
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
//! worker lives; SIGWINCH is a resize), the runtime's local `list` (lease
//! holder), what the hooks answered (decisions handed over, which are also
//! dispatches), and what the link carried: `approval_request`/`approval_closed`
//! (pending approvals), the relay's push requests, and the receipts the
//! client was told about (`receipts_visible`). Counters are re-read for up
//! to 5 s until they match (`SETTLE_COUNTERS`).
#![cfg(target_os = "linux")]

mod support;

/// r8 revision and features, and which `r8-*` fixtures can run: the same
/// list the core runner gates on.
#[allow(dead_code)]
#[path = "../src/session_protocol/revision.rs"]
mod revision;

use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Map, Value, json};
use std::collections::{HashMap, VecDeque};
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use support::astation::{Event, FakeAstation, write_verified_pairing};

const WAIT: Duration = Duration::from_secs(15);
/// Time the runtime gets to act on what it was sent before the next event.
const SETTLE: Duration = Duration::from_millis(400);
/// How long a counter may take to reach its expected value. The slowest
/// chain a counter waits for is a decision reaching the agent: the worker
/// writes it at once, the hook polls every 100 ms, the worker's approval
/// poll runs every 200 ms and the fake agent's every 20 ms — about 0.4 s in
/// all. 5 s leaves more than 10× for a loaded machine; a counter that should
/// stay unchanged is compared at once either way.
const SETTLE_COUNTERS: Duration = Duration::from_secs(5);
const PASTE_START: &[u8] = b"\x1b[200~";
const PASTE_END: &[u8] = b"\x1b[201~\r";

/// Stands in for the Claude and Codex CLIs (`tests/fixtures/approvals/
/// fake-agent.py`). Logs every byte read from its terminal (raw mode) to
/// `$FAKE_DIR/input` and its signals to `$FAKE_DIR/events`. With
/// `--settings` (Claude with Atem's chat hooks) each bracketed paste is a
/// prompt `turn-<n>`: it fires the hooks and writes the transcript as Claude
/// Code does, and the turn ends when `$FAKE_DIR/complete` appears. A tool
/// call asked for in `$FAKE_DIR/ask-<n>.json` runs the real
/// `PermissionRequest` hook Atem configured and acts on its answer.
const FAKE_AGENT: &str = include_str!("fixtures/approvals/fake-agent.py");

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
    /// `transcript-<n>.jsonl` files handed to the fake agent so far.
    transcribed: usize,
    /// Parts written per assistant message id (a later version of the
    /// message adds only its new parts).
    parts: HashMap<String, usize>,
}

/// A tool call the fake agent asked for (`ask-<n>.json`).
struct Ask {
    n: usize,
    dir: PathBuf,
    approval_id: String,
    /// The suggestions it offered, and the runtime's rule ids for them.
    suggestions: Vec<Value>,
    rule_ids: Vec<String>,
}

/// What Atem says a deny without a message tells the agent.
const DEFAULT_DENY: &str = "Denied from Astation";

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
        write_verified_pairing(&self.config(), account, device, trust_gen);
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

    /// An orderly stop (SIGTERM): the runtime writes its journal's clean
    /// close when the journal is healthy, then exits; its workers stay.
    fn stop_runtime(&mut self) {
        if let Some(mut child) = self.runtime.take() {
            unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
            let deadline = Instant::now() + WAIT;
            while child.try_wait().ok().flatten().is_none() {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("the runtime didn't stop on SIGTERM");
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
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
    asks: Vec<Ask>,
    /// Approval ids the link opened, and how each closed.
    approvals_opened: Vec<String>,
    approvals_closed: HashMap<String, String>,
    /// Push requests the link carried for the relay.
    pushes: Vec<Value>,
    /// Request ids of the receipts the client was told about.
    receipts_seen: Vec<String>,
    /// The current link was welcomed (its one attachment).
    welcomed: bool,
    /// agentChat `opened`/`close` the link carried, and the conversations
    /// open on it (the client's own `close` ends one too).
    chat_opens: u64,
    chat_closes: u64,
    conversations: Vec<String>,
    /// The harness's probe of the history: its page so far and its end.
    probe_page: Vec<Value>,
    probed: Option<Value>,
    /// The scenario opens a chat: the fake Claude's tool calls write no
    /// tool_use message (the fixture's conversation has none).
    quiet_asks: bool,
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
            ("fail_fsync_of", "no fsync fault on the real journal"),
            (
                "crash_after_accepted",
                "no crash hook between the runtime's journal writes",
            ),
            (
                "set_permissions",
                "the runtime's one principal (the paired Astation) always has control",
            ),
            ("drop", "the fake Astation link loses no message"),
            (
                "replace_process",
                "the runtime replaces a process only when its agent restarts",
            ),
            (
                "change_trust_gen",
                "trust generations change only by pairing",
            ),
            (
                "approval_rules",
                "session rules come from a Codex session's allow_always (the fixture agent is Claude); covered by the core harness and the real-agent Codex test",
            ),
            (
                "chat_evict",
                "the real chat session evicts only past 500 messages / 8 MiB, which would put hundreds of messages the fixture doesn't name into its pages; covered by the core harness and chat::history tests",
            ),
            (
                "worker_gap",
                "no backlog fault in the real worker (its backlog drops only past 4096 items / 8 MiB, and its reload then finds everything); covered by the core harness and broker_tests",
            ),
        ] {
            if step.get(action).is_some() {
                return Some(format!("{action}: {why}"));
            }
        }
        if step.get("chat_turn").is_some() && step.get("request_id").is_some() {
            return Some("chat_turn of a remote prompt: the real Claude adapter sends status working, then ready, in the conversation around the prompt's turn (UserPromptSubmit, Stop), sequenced events the fixture's sequence numbers don't model; receipt.result is covered by the core harness, host_bridge_tests and the real-agent Codex test".into());
        }
        let content = step
            .get("messages")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .chain(step.get("message"));
        for m in content {
            let text = m["parts"]
                .as_array()
                .is_some_and(|p| p.iter().all(|p| p["kind"] == "text"));
            if !text || (m["role"] == "user" && m["origin"] != "local") {
                return Some(format!(
                    "{}: only local user messages and text parts can be written to the transcript",
                    m["messageId"]
                ));
            }
        }
        let reason = step["reason"].as_str().unwrap_or_default();
        if step.get("close_approval").is_some()
            && !matches!(reason, "answered_terminal" | "interrupted")
        {
            return Some(format!(
                "close_approval {reason}: only the terminal's answer or an interrupt"
            ));
        }
        if step.get("approval_applied").is_some() && step["ok"] != true {
            return Some("approval_applied ok:false: the fake agent never contradicts".into());
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
        // Approvals (rules, the terminal's answer) are Claude's.
        let approvals = scenario["steps"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|s| s.get("open_approval").is_some());
        for (i, s) in setup["sessions"]
            .as_array()
            .into_iter()
            .flatten()
            .enumerate()
        {
            let chat = s["chat"].as_bool().unwrap_or(false) || approvals;
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
                transcribed: 0,
                parts: HashMap::new(),
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
            asks: Vec::new(),
            approvals_opened: Vec::new(),
            approvals_closed: HashMap::new(),
            pushes: Vec::new(),
            receipts_seen: Vec::new(),
            welcomed: false,
            chat_opens: 0,
            chat_closes: 0,
            conversations: Vec::new(),
            probe_page: Vec::new(),
            probed: None,
            quiet_asks: scenario["steps"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|s| s["json"]["type"] == "agentChat" && s["json"]["data"]["op"] == "open"),
        };
        me.wait_sessions_ready()?;
        let attachment = me.client_setup["attachment_gen"]
            .as_str()
            .unwrap()
            .to_string();
        if me.client_setup["welcome"] == false {
            // r8: the steps send this client's `hello`.
            me.authenticated_link()?;
            me.attached_unwelcomed()?;
        } else {
            me.attach(&attachment)?;
        }
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
    /// Waits for the runtime's next authenticated link and makes it the
    /// client's (not welcomed yet).
    fn authenticated_link(&mut self) -> Result<(), String> {
        let deadline = Instant::now() + WAIT;
        while self.authenticated <= self.link {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.astation.events.recv_timeout(left) {
                Ok(event) => self.event_in(event),
                Err(_) => return Err("the runtime's link never authenticated".into()),
            }
        }
        self.link = self.authenticated;
        self.welcomed = false;
        Ok(())
    }

    /// Waits until the runtime attached the link (a session request is
    /// then refused as before `welcome`, not `unauthorized`); sends no
    /// `hello`.
    fn attached_unwelcomed(&mut self) -> Result<(), String> {
        let deadline = Instant::now() + WAIT;
        loop {
            let id = uuid();
            let probe = json!({"type": "session", "data": {"v": 1, "op": "list", "id": id}});
            self.astation.send(self.link, probe.to_string());
            let reply = self.raw_reply(&id)?;
            match reply["code"].as_str() {
                Some("unsupported_version") => return Ok(()),
                Some("unauthorized") if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(100))
                }
                _ => return Err(format!("probe: {reply}")),
            }
        }
    }

    fn attach(&mut self, attachment_gen: &str) -> Result<(), String> {
        let deadline = Instant::now() + WAIT;
        self.authenticated_link()?;
        loop {
            let id = uuid();
            let hello = json!({"type": "session",
                "data": {"v": 1, "op": "hello", "id": id, "revision": 8}});
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
            if reply["revision"] != revision::REVISION
                || reply["features"] != json!(revision::FEATURES)
            {
                return Err(format!(
                    "welcome revision {} features {}",
                    reply["revision"], reply["features"]
                ));
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
            self.welcomed = true;
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
        let op = value["data"]["op"].as_str().unwrap_or_default().to_string();
        if family == "relay" {
            let mut push = json!({"op": op, "approval_id": value["data"]["approval_id"]});
            if op == "push_resolved" {
                push["reason"] = value["data"]["reason"].clone();
            }
            replace_strings(&mut push, &self.ids, false);
            self.pushes.push(push);
            return;
        }
        if !matches!(family.as_str(), "session" | "terminal" | "agentChat") {
            return;
        }
        let data = &value["data"];
        let conversation = data["conversationId"]
            .as_str()
            .unwrap_or_default()
            .to_string();
        if family == "agentChat" && conversation.starts_with(PROBE) {
            // The harness's own look at the history (`chat_history`).
            if op == "history_end" {
                self.probed = Some(data.clone());
            } else if op == "message" {
                self.probe_page.push(data.clone());
            }
            return;
        }
        let id = data["approval_id"].as_str().unwrap_or_default().to_string();
        match (family.as_str(), op.as_str()) {
            ("agentChat", "opened") => {
                self.chat_opens += 1;
                self.conversations.retain(|c| *c != conversation);
                self.conversations.push(conversation);
            }
            ("agentChat", "close") => {
                self.chat_closes += 1;
                self.conversations.retain(|c| *c != conversation);
            }
            ("session", "approval_request") if !self.approvals_opened.contains(&id) => {
                self.approvals_opened.push(id)
            }
            ("session", "approval_closed") => {
                let reason = data["reason"].as_str().unwrap_or_default().to_string();
                self.approvals_closed.insert(id, reason);
            }
            ("session", "welcome") => self.welcomed = true,
            ("session", "receipt") => {
                let rid = data["request_id"].as_str().unwrap_or_default().to_string();
                if !self.receipts_seen.contains(&rid) {
                    self.receipts_seen.push(rid);
                }
            }
            _ => {}
        }
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
        if message["type"] == "agentChat" && message["data"]["op"] == "close" {
            let conversation = &message["data"]["conversationId"];
            self.conversations.retain(|c| conversation != c.as_str());
        }
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
            "restart_runtime" | "crash_runtime" => {
                if action == "restart_runtime" {
                    self.sandbox.stop_runtime();
                    // The orderly stop recorded it in the journal (r8 §H).
                    if !self
                        .sandbox
                        .logs()
                        .contains("session journal closed cleanly")
                    {
                        return Err("the orderly stop didn't close the journal cleanly".into());
                    }
                } else {
                    self.sandbox.kill_runtime();
                }
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
            "open_approval" => self.open_approval(arg, step)?,
            "chat_history" => {
                let session = arg.as_str().unwrap_or_default().to_string();
                let messages = step["messages"].as_array().ok_or("messages")?.clone();
                self.transcribe(&session, &messages)?;
                self.probe(&session, &messages)?;
            }
            "chat_message" => {
                let session = arg.as_str().unwrap_or_default().to_string();
                self.transcribe(&session, &[step["message"].clone()])?;
            }
            "chat_turn" => {
                let session = arg.as_str().unwrap_or_default().to_string();
                let turn = step["turn_id"].as_str().ok_or("turn_id")?;
                let n = step["assistant_messages"]
                    .as_u64()
                    .ok_or("assistant_messages")?;
                let bytes = step["text_bytes"].as_u64().ok_or("text_bytes")? as usize;
                let fill = if step["escape"] == "control" {
                    '\u{1}'
                } else {
                    'x'
                };
                let text: String = std::iter::repeat_n(fill, bytes).collect();
                let at = 1_760_600_000_000u64;
                let mut messages = vec![json!({"messageId": format!("{turn}-u"), "role": "user",
                    "turnId": turn, "createdAt": at, "origin": step["origin"],
                    "parts": [{"id": "p1", "kind": "text", "markdown": format!("prompt {turn}")}]})];
                for k in 1..=n {
                    messages.push(json!({"messageId": format!("{turn}-a-{k:04}"),
                        "role": "assistant", "turnId": turn, "createdAt": at,
                        "parts": [{"id": "p1", "kind": "text", "markdown": text}]}));
                }
                self.transcribe(&session, &messages)?;
            }
            "close_approval" => {
                let ask = self.ask(arg.as_str().unwrap_or_default())?;
                let what = match step["reason"].as_str() {
                    Some("answered_terminal") => "terminal-yes",
                    Some("interrupted") => "kill",
                    other => return Err(format!("close_approval {other:?} is not supported")),
                };
                std::fs::write(ask.dir.join(format!("{what}-{}", ask.n)), "").unwrap();
            }
            // The agent acts on the decision its hook got by itself.
            "approval_applied" if step["ok"] == true => {
                self.ask(arg.as_str().unwrap_or_default())?;
            }
            other => return Err(format!("{other} is not supported against the real runtime")),
        }
        self.pump(SETTLE);
        Ok(())
    }

    /// The fake agent asks for a tool call that needs permission; its hook
    /// reports it and the runtime's `approval_request` arrives (its rule ids,
    /// labels and scopes are then translated to the fixture's).
    fn open_approval(&mut self, arg: &Value, step: &Map<String, Value>) -> Result<(), String> {
        let session = self.session(arg.as_str().unwrap_or_default())?;
        if !session.chat {
            return Err("approvals need the Claude session".into());
        }
        let dir = session.dir.clone();
        let tool = step["tool"].as_str().ok_or("tool")?;
        let summary = step["summary"].as_str().ok_or("summary")?;
        let rules = step
            .get("always_rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut suggestions = Vec::new();
        for rule in &rules {
            let label = rule["label"].as_str().ok_or("label")?;
            let (rule_tool, content) = label
                .strip_suffix(')')
                .and_then(|l| l.split_once('('))
                .ok_or(format!("label {label:?} is not Tool(content)"))?;
            suggestions.push(json!({"type": "addRules", "behavior": "allow",
                "rules": [{"toolName": rule_tool, "ruleContent": content}],
                "destination": "localSettings"}));
        }
        let n = self.asks.len() + 1;
        let request = json!({"tool_name": tool, "tool_input": {"command": summary},
                             "permission_suggestions": suggestions, "quiet": self.quiet_asks});
        let temp = dir.join(format!("tmp-ask-{n}"));
        std::fs::write(&temp, request.to_string()).unwrap();
        std::fs::rename(&temp, dir.join(format!("ask-{n}.json"))).unwrap();
        let deadline = Instant::now() + WAIT;
        let known: Vec<String> = self.asks.iter().map(|a| a.approval_id.clone()).collect();
        let at = loop {
            let found = self.queue.iter().position(|m| {
                m["data"]["op"] == "approval_request"
                    && m["data"]["approval_id"]
                        .as_str()
                        .is_some_and(|id| !known.iter().any(|k| k == id))
            });
            if let Some(at) = found {
                break at;
            }
            if Instant::now() > deadline {
                return Err(format!("no approval_request; queued: {:?}", self.queue));
            }
            self.pump(Duration::from_millis(50));
        };
        let real = self.queue[at]["data"].clone();
        let real_rules = real["always_rules"].as_array().cloned().unwrap_or_default();
        if real_rules.len() != rules.len() {
            return Err(format!("rules offered: {real}"));
        }
        let mut rule_ids = Vec::new();
        for (fixture, real) in rules.iter().zip(&real_rules) {
            rule_ids.push(real["rule_id"].as_str().unwrap_or_default().to_string());
            for key in ["rule_id", "label", "scope"] {
                let pair = (
                    fixture[key].as_str().unwrap_or_default().to_string(),
                    real[key].as_str().unwrap_or_default().to_string(),
                );
                if pair.0 != pair.1 && !self.ids.contains(&pair) {
                    self.ids.push(pair);
                }
            }
        }
        replace_strings(&mut self.queue[at], &self.ids, false);
        self.asks.push(Ask {
            n,
            dir,
            approval_id: real["approval_id"].as_str().unwrap_or_default().to_string(),
            suggestions,
            rule_ids,
        });
        Ok(())
    }

    /// Chat content the fixture names, written to the Claude session's
    /// transcript by the fake agent (no hook runs, so the chat status stays
    /// as it is), as Claude Code writes it: a user message is a user entry
    /// (`uuid` = message id, `promptId` = turn id); an assistant message is
    /// an entry with `message.id` = message id and one text block per part
    /// (a later version adds an entry with its new parts).
    fn transcribe(&mut self, fixture: &str, messages: &[Value]) -> Result<(), String> {
        let session = self
            .sessions
            .iter_mut()
            .find(|s| s.fixture_id == fixture)
            .ok_or(format!("unknown session {fixture}"))?;
        if !session.chat {
            return Err("chat content needs the Claude session".into());
        }
        let mut lines = String::new();
        for m in messages {
            let id = m["messageId"].as_str().ok_or("messageId")?;
            let turn = m["turnId"].as_str().ok_or("turnId")?;
            let stamp = rfc3339(m["createdAt"].as_u64().ok_or("createdAt")?);
            let mut texts = Vec::new();
            for part in m["parts"].as_array().ok_or("parts")? {
                if part["kind"] != "text" {
                    return Err(format!("{id}: only text parts can be written"));
                }
                texts.push(part["markdown"].as_str().ok_or("markdown")?.to_string());
            }
            let entry = match m["role"].as_str() {
                Some("user") if m["origin"] == "local" => {
                    json!({"type": "user", "uuid": id, "promptId": turn, "timestamp": stamp,
                           "message": {"role": "user", "content": texts.join("\n")}})
                }
                Some("assistant") => {
                    let written = session.parts.entry(id.to_string()).or_insert(0);
                    if *written >= texts.len() {
                        continue;
                    }
                    let blocks: Vec<Value> = texts[*written..]
                        .iter()
                        .map(|t| json!({"type": "text", "text": t}))
                        .collect();
                    let uuid = format!("{id}.{written}");
                    *written = texts.len();
                    json!({"type": "assistant", "uuid": uuid, "promptId": turn, "timestamp": stamp,
                           "message": {"id": id, "role": "assistant", "content": blocks}})
                }
                _ => return Err(format!("{id}: only local user and assistant messages")),
            };
            lines.push_str(&entry.to_string());
            lines.push('\n');
        }
        session.transcribed += 1;
        let (n, dir) = (session.transcribed, session.dir.clone());
        let temp = dir.join(format!("tmp-transcript-{n}"));
        std::fs::write(&temp, lines).unwrap();
        std::fs::rename(&temp, dir.join(format!("transcript-{n}.jsonl"))).unwrap();
        let deadline = Instant::now() + WAIT;
        let done = format!("transcribed {n}\n");
        while !std::fs::read_to_string(dir.join("events")).is_ok_and(|e| e.contains(&done)) {
            if Instant::now() > deadline {
                return Err(format!("the fake agent never wrote transcript {n}"));
            }
            self.pump(Duration::from_millis(50));
        }
        Ok(())
    }

    /// Waits until the runtime's history holds `messages` (the newest
    /// page of a probe conversation, closed after; nothing of it reaches
    /// the client or the counters): the worker reads the transcript on its
    /// own schedule.
    fn probe(&mut self, fixture: &str, messages: &[Value]) -> Result<(), String> {
        let Some(last) = messages.last() else {
            return Ok(());
        };
        let session = self.session(fixture)?;
        let binding = self.binding(session);
        let deadline = Instant::now() + WAIT;
        loop {
            let conversation = format!("{PROBE}{}", uuid());
            self.probe_page.clear();
            self.probed = None;
            self.send(&json!({"type": "agentChat", "data": {"v": 1, "op": "open",
                "conversationId": conversation, "agentId": fixture, "binding": binding}}));
            while self.probed.is_none() {
                if Instant::now() > deadline {
                    return Err("the probe's page never came".into());
                }
                self.pump(Duration::from_millis(50));
            }
            self.send(&json!({"type": "agentChat", "data": {"v": 1, "op": "close",
                "conversationId": conversation, "agentId": fixture}}));
            let parts = last["parts"].as_array().map_or(0, Vec::len);
            let held = self.probe_page.iter().any(|m| {
                m["messageId"] == last["messageId"]
                    && m["parts"].as_array().is_some_and(|p| p.len() >= parts)
            });
            if held {
                self.pump(SETTLE);
                return Ok(());
            }
            if Instant::now() > deadline {
                return Err(format!("the history never held {}", last["messageId"]));
            }
            self.pump(Duration::from_millis(200));
        }
    }

    /// The next agentChat message (whole, fixture identifiers).
    fn next_chat(&mut self) -> Result<Value, String> {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(i) = self.queue.iter().position(|m| m["type"] == "agentChat") {
                return Ok(self.queue.remove(i).unwrap());
            }
            if Instant::now() > deadline {
                return Err("the page ended early".into());
            }
            self.pump(Duration::from_millis(50));
        }
    }

    /// r8 `recover` (as the core runner does it): sends `request`, takes
    /// its pages following each `history_end`'s `next` until `end`, checks
    /// each page's sequences and bounds; the messages must be
    /// `message_ids` exactly.
    fn recover(&mut self, step: &Map<String, Value>) -> Result<(), String> {
        let request = step["request"].clone();
        let data = request["data"].clone();
        let want = step["message_ids"].clone();
        let num = |k: &str| step[k].as_u64().ok_or(k.to_string());
        let (min_pages, max_count) = (num("min_pages")?, num("max_count")?);
        let (max_content, max_wire) = (num("max_content_bytes")?, num("max_wire_bytes")?);
        let base = data["page_id"].as_str().unwrap_or("open").to_string();
        self.send(&request);
        let mut generation = data.get("generation").cloned();
        if data["op"] == "open" {
            let opened = self.expect(
                Some("agentChat"),
                json!({"op": "opened"}).as_object().unwrap(),
            )?;
            if opened["sequence"] != 0 {
                return Err(format!("opened at {}", opened["sequence"]));
            }
            generation = opened.get("generation").cloned();
        }
        let mut pages: Vec<Vec<Value>> = Vec::new();
        let mut backwards;
        loop {
            let mut ids = Vec::new();
            let (mut content, mut wire) = (0u64, 0u64);
            let mut sequence: Option<u64> = None;
            let end = loop {
                let msg = self.next_chat()?;
                wire += serde_json::to_vec(&msg).map_or(0, |v| v.len()) as u64;
                let d = &msg["data"];
                let seq = d["sequence"].as_u64().ok_or(format!("unsequenced {msg}"))?;
                if sequence.is_some_and(|s| seq != s + 1) {
                    return Err(format!("sequence {seq} after {sequence:?}"));
                }
                sequence = Some(seq);
                match d["op"].as_str() {
                    Some("message") if d["history"] == true => {
                        ids.push(d["messageId"].clone());
                        content += content_bytes(d);
                    }
                    Some("history_end") => break d.clone(),
                    _ => return Err(format!("not part of a page: {msg}")),
                }
            };
            let page = &end["page"];
            if page["count"] != ids.len() {
                return Err(format!(
                    "page.count {} for {} messages",
                    page["count"],
                    ids.len()
                ));
            }
            if ids.len() as u64 > max_count || content > max_content || wire > max_wire {
                return Err(format!(
                    "page {} over its bounds: {} messages, {content} content bytes, {wire} wire bytes",
                    pages.len() + 1,
                    ids.len()
                ));
            }
            backwards = matches!(page["selector"].as_str(), Some("newest" | "before"));
            pages.push(ids);
            if page["end"] == true {
                for (path, expected) in step["end"].as_object().ok_or("end")? {
                    let got = lookup(&end, path);
                    if got.as_ref() != Some(expected) {
                        return Err(format!(
                            "last history_end {path}: expected {expected}, got {got:?}"
                        ));
                    }
                }
                break;
            }
            let next = page["next"].as_str().ok_or("no next before the end")?;
            let mut more = json!({"v": 1, "op": "history",
                "conversationId": data["conversationId"], "agentId": data["agentId"],
                "generation": generation.clone().unwrap_or(Value::Null),
                "page_id": format!("{base}-{}", pages.len() + 1),
                "binding": data["binding"], "next": next});
            if more["generation"].is_null() {
                more.as_object_mut().unwrap().remove("generation");
            }
            self.send(&json!({"type": "agentChat", "data": more}));
        }
        if (pages.len() as u64) < min_pages {
            return Err(format!(
                "{} pages, expected at least {min_pages}",
                pages.len()
            ));
        }
        if backwards {
            pages.reverse();
        }
        let got = Value::from(pages.into_iter().flatten().collect::<Vec<_>>());
        if got != want {
            return Err(format!("recovered {got}, expected {want}"));
        }
        Ok(())
    }

    fn ask(&self, approval_id: &str) -> Result<&Ask, String> {
        self.asks
            .iter()
            .find(|a| a.approval_id == approval_id)
            .ok_or(format!("unknown approval {approval_id}"))
    }

    /// What each hook answered, in order: `(ask, behavior, decision)`.
    fn answers(&self) -> Vec<(&Ask, String, Value)> {
        let mut out = Vec::new();
        let mut lines = Vec::new();
        for s in &self.sessions {
            let events = std::fs::read_to_string(s.dir.join("events")).unwrap_or_default();
            lines.extend(events.lines().map(|l| (s.dir.clone(), l.to_string())));
        }
        for (dir, line) in lines {
            let mut parts = line.splitn(3, ' ');
            if parts.next() != Some("answer") {
                continue;
            }
            let n: usize = parts.next().and_then(|n| n.parse().ok()).unwrap_or(0);
            let behavior = parts.next().unwrap_or_default();
            let behavior = behavior.split(' ').next().unwrap_or_default().to_string();
            let Some(ask) = self.asks.iter().find(|a| a.n == n && a.dir == dir) else {
                continue;
            };
            let raw =
                std::fs::read_to_string(dir.join(format!("answer-{n}.json"))).unwrap_or_default();
            let decision = serde_json::from_str::<Value>(&raw)
                .map(|v| v["hookSpecificOutput"]["decision"].clone())
                .unwrap_or(Value::Null);
            out.push((ask, behavior, decision));
        }
        out
    }

    /// Decisions the hooks got, as the fixture writes them.
    fn approval_decisions(&self) -> Value {
        let mut decisions = Vec::new();
        for (ask, behavior, decision) in self.answers() {
            let mut d = json!({"approval_id": ask.approval_id});
            match behavior.as_str() {
                "allow" => match decision["updatedPermissions"].as_array() {
                    Some(rules) => {
                        let i = ask
                            .suggestions
                            .iter()
                            .position(|s| Some(s) == rules.first());
                        d["decision"] = json!("allow_always");
                        d["rule_id"] = json!(i.map_or("?", |i| ask.rule_ids[i].as_str()));
                    }
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
        let mut decisions = Value::from(decisions);
        replace_strings(&mut decisions, &self.ids, false);
        decisions
    }

    /// `counter` until it equals `expected` (`SETTLE_COUNTERS` at most): the
    /// processes act asynchronously.
    fn counter_settled(&mut self, key: &str, expected: &Value) -> Result<Value, String> {
        let deadline = Instant::now() + SETTLE_COUNTERS;
        loop {
            let got = self.counter(key)?;
            if &got == expected || Instant::now() > deadline {
                return Ok(got);
            }
            self.pump(Duration::from_millis(100));
        }
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
        // A decision handed to the agent counts as a dispatch.
        let answers = self.answers();
        dispatches += answers.iter().filter(|(_, b, _)| b != "none").count() as u64;
        Ok(match key {
            "dispatches" => json!(dispatches),
            "dispatch_attempts" => json!(dispatches + enqueue_faults),
            "approval_decisions" => self.approval_decisions(),
            "approvals_pending" => json!(
                self.approvals_opened
                    .iter()
                    .filter(|id| !self.approvals_closed.contains_key(*id))
                    .count()
            ),
            // Hooks answered "no decision" the host chose (not the
            // terminal's answer, an interrupt, a timeout or a release).
            "approvals_released" => json!(
                answers
                    .iter()
                    .filter(|(ask, b, _)| {
                        b == "none"
                            && !matches!(
                                self.approvals_closed
                                    .get(&ask.approval_id)
                                    .map(String::as_str),
                                Some(
                                    "answered_terminal" | "interrupted" | "timed_out" | "released"
                                )
                            )
                    })
                    .count()
            ),
            "pushes" => json!(self.pushes),
            "receipts_visible" => json!({self.client.clone(): self.receipts_seen.len()}),
            // The runtime holds one link: its attachment, once welcomed.
            "attachments" => json!(u64::from(self.welcomed)),
            "chat_opens" => json!(self.chat_opens),
            "chat_closes" => json!(self.chat_closes),
            "chat_conversations" => json!(self.conversations.len()),
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
            "tool",
            "summary",
            "always_rules",
            "reason",
            "ok",
            "messages",
            "message",
            "request_id",
            "origin",
            "assistant_messages",
            "text_bytes",
            "escape",
            "message_ids",
            "sequence_from",
            "request",
            "min_pages",
            "max_count",
            "max_content_bytes",
            "max_wire_bytes",
            "end",
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
            "expect_live" => {
                client_ok(arg)?;
                let ids = step["message_ids"].as_array().ok_or("message_ids")?;
                let from = step["sequence_from"].as_u64().ok_or("sequence_from")?;
                for (k, id) in ids.iter().enumerate() {
                    let data = self.expect(
                        Some("agentChat"),
                        json!({"op": "message"}).as_object().unwrap(),
                    )?;
                    if data.get("history").is_some() {
                        return Err(format!("{id}: a history message, expected a live one"));
                    }
                    if &data["messageId"] != id || data["sequence"] != from + k as u64 {
                        return Err(format!(
                            "expected live {id} at {}, got {} at {}",
                            from + k as u64,
                            data["messageId"],
                            data["sequence"]
                        ));
                    }
                }
            }
            "recover" => {
                client_ok(arg)?;
                self.recover(&step)?;
            }
            "assert" => {
                self.pump(SETTLE);
                for (key, expected) in arg.as_object().ok_or("assert must be an object")? {
                    let got = self.counter_settled(key, expected)?;
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

/// Conversations the harness opens to look at the history (`probe`).
const PROBE: &str = "probe-";

/// Content bytes of a chat message as the fixtures count them.
fn content_bytes(message: &Value) -> u64 {
    let len = |v: &Value| v.as_str().map_or(0, str::len) as u64;
    message["parts"]
        .as_array()
        .into_iter()
        .flatten()
        .map(|p| match p["kind"].as_str() {
            Some("text") => len(&p["markdown"]),
            Some("tool") => len(&p["name"]) + len(&p["summary"]),
            Some("approval") => len(&p["tool"]) + len(&p["summary"]),
            _ => 0,
        })
        .sum()
}

/// Unix milliseconds as an RFC 3339 UTC timestamp (transcript `timestamp`).
fn rfc3339(ms: u64) -> String {
    let (secs, millis) = (ms / 1000, ms % 1000);
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
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
    result.map_err(|e| {
        let agents: String = host
            .sessions
            .iter()
            .map(|s| {
                let events = std::fs::read_to_string(s.dir.join("events")).unwrap_or_default();
                format!("--- agent {} events ---\n{events}", s.fixture_id)
            })
            .collect();
        format!("{e}\n--- runtime log ---\n{}{agents}", host.sandbox.logs())
    })
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

/// Why a scenario waits for host work (an `r8-*` one whose work isn't
/// implemented).
fn waiting(scenario: &Value) -> Option<String> {
    let name = scenario["name"].as_str().unwrap();
    if revision::is_r9_fixture(name) {
        Some(revision::R9_NOT_RUN.to_string())
    } else if name.starts_with("r8-") {
        revision::r8_fixture_runnable(name).err()
    } else {
        None
    }
}

/// The host scenarios that can't be honoured against real processes (the
/// reason is printed); every other scenario runs.
const NOT_RUN: &[&str] = &[
    "approval-needs-control-and-the-lease",
    "approval-rule-revoke-needs-control-not-the-lease",
    "closed-session-refuses-work-before-the-lease-check",
    "receipt-query-is-scoped-to-the-exact-target",
    "removed-ops-have-no-effect",
    "takeover-moves-control-and-the-old-holder-becomes-a-viewer",
    // r8 scenarios with two or three attachments (core harness only).
    "r8-approval-answer-by-a-non-holder-leaves-the-lease",
    "r8-approval-answer-keeps-the-holders-deadline",
    "r8-approval-answer-to-a-closed-request-is-stale-target",
    "r8-approval-answer-with-acquire-is-refused",
    "r8-approval-answers-crossing-first-wins",
    "r8-approval-survives-takeover",
    "r8-clean-close-runs-queued-work-once-its-principal-is-confirmed",
    "r8-control-fence-holds-when-a-rejection-write-fails",
    "r8-crash-after-durable-acceptance-grants-no-lease",
    "r8-crash-rejects-queued-work-whose-history-is-unknown",
    "r8-delayed-send-reply-does-not-regrant-lost-control",
    "r8-disconnect-right-after-acceptance",
    "r8-double-write-failure-takeover-never-runs",
    "r8-duplicate-send-never-reacquires-or-replays",
    "r8-expired-lease-is-checked-at-admission",
    "r8-failed-fence-write-rejects-queued-work-at-once",
    "r8-failed-fence-write-then-control-restored-never-runs",
    "r8-failed-persistence-changes-no-lease",
    "r8-local-input-wins-over-a-send",
    "r8-ownership-is-checked-at-admission-not-as-displayed",
    "r8-process-replaced-before-dispatch",
    "r8-recovered-work-needs-its-principal-confirmed",
    "r8-revoked-control-fences-work-across-reconnect-and-restart",
    "r8-revoked-control-refuses-the-send-and-its-queued-prompt",
    "r8-send-acquire-wire-rules",
    "r8-send-acquires-an-unowned-session",
    "r8-send-refused-while-another-holds-then-takeover",
    "r8-send-under-the-own-lease-checks-the-epoch",
    "r8-stale-takeover-confirmation-is-refused",
    "r8-two-simultaneous-sends-acquire-once",
    // r8 history scenarios the fake Claude's transcript can't express (each
    // reason is printed: eviction, a backlog fault, a remote turn's status
    // events).
    "r8-backlog-hole-is-reported-not-reopened",
    "r8-receipt-result-bounds-reply-message-ids",
    "r8-stale-or-foreign-next-token-is-stale-target",
    "r8-truncated-history-reopens-once-then-stays-live",
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
                let handle = scope.spawn(move || match waiting(s) {
                    Some(why) => Err(format!("not run: {why}")),
                    None => match unsupported(s) {
                        Some(why) => Err(format!("not run: {why}")),
                        None => run(s),
                    },
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
#[cfg_attr(not(debug_assertions), ignore = "needs the fixture clock and PTY faults of a debug build (src/runtime/test_hooks.rs)")]
fn shared_host_fixtures_run_against_the_real_runtime() {
    let scenarios = scenarios();
    assert!(scenarios.len() >= 13, "host fixtures missing");
    let only = std::env::var("ATEM_FIXTURE").ok();
    let results = run_named(&scenarios, only.as_deref());
    let draft: Vec<&str> = scenarios
        .iter()
        .filter(|s| waiting(s).is_some())
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    let mut failed = Vec::new();
    for (name, result) in &results {
        let known = KNOWN_DEVIATIONS.iter().find(|(n, _)| n == name);
        let not_run = NOT_RUN.contains(&name.as_str()) || draft.contains(&name.as_str());
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
#[cfg_attr(not(debug_assertions), ignore = "needs the fixture clock and PTY faults of a debug build (src/runtime/test_hooks.rs)")]
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
    // The decision the real hook got is checked, message included.
    let mut deny = named("approval-deny-carries-the-message-to-the-agent");
    let step = deny["steps"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|s| s["assert"].get("approval_decisions").is_some())
        .unwrap();
    step["assert"]["approval_decisions"][0]["message"] = json!("something else");
    // History written through the fake Claude's transcript: a page and a
    // recovery are checked against what the runtime sent.
    let mut before = named("r8-open-with-before-is-refused");
    let step = before["steps"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|s| s["match"]["op"] == "history_end")
        .unwrap();
    step["match"]["page.count"] = json!(5);
    let mut long = named("r8-long-turn-is-recovered-in-bounded-pages");
    let step = long["steps"]
        .as_array_mut()
        .unwrap()
        .iter_mut()
        .find(|s| s.get("recover").is_some())
        .unwrap();
    step["message_ids"].as_array_mut().unwrap().pop();
    let results = run_named(&[lease, dispatch, deny, before, long], None);
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

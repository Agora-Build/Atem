//! Push-based approvals, and Codex chat, end to end with the REAL Claude
//! Code and Codex CLIs: `atem agent launch` in a PTY (the local frontend),
//! the real `atem runtime` and `atem worker`s, and a fake Astation on the
//! runtime's link that answers the approvals (`kind:"approval"`
//! submissions), records the relay pushes and drives chat-v1.
//!
//! Costs real API calls, so it never runs in a normal `cargo test`:
//!
//! ```sh
//! set -a; source ~/.config/.env; set +a
//! ATEM_REAL_AGENTS=1 cargo test --test approvals_real_agents -- --ignored --nocapture --test-threads=1
//! ```
//!
//! Claude needs `ANTHROPIC_AUTH_TOKEN` (or `ANTHROPIC_API_KEY`) and
//! optionally `ANTHROPIC_BASE_URL`; Codex runs `--profile oss` with the
//! `oss` provider copied (non-secret fields only) from `~/.codex/config.toml`
//! and its key from the environment variable that provider names. Both run in
//! a temp HOME, XDG_RUNTIME_DIR and CODEX_HOME; nothing of the real profile
//! is read or written except those two config files, read-only.
//! `ATEM_REAL_CLAUDE_MODEL` picks Claude's model (default `haiku`).
//!
//! Screens are only ever printed redacted (`redact`).
#![cfg(target_os = "linux")]

mod support;

use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use support::astation::{Event, FakeAstation, write_verified_pairing};
use support::{Frontend, Sandbox};

const ACCOUNT: &str = "account-real";
const DEVICE: &str = "device-real";
const TRUST_GEN: u64 = 1;
/// A real model turn: generous.
const TURN: Duration = Duration::from_secs(180);

fn enabled() -> bool {
    if std::env::var("ATEM_REAL_AGENTS").as_deref() == Ok("1") {
        return true;
    }
    eprintln!("skipped: set ATEM_REAL_AGENTS=1 (real Claude Code and Codex, real API calls)");
    false
}

/// Key-like tokens (8+ characters mixing letters and digits, 24+ of any,
/// or containing `sk-`) replaced, so no credential fragment can reach the
/// test output.
fn redact(text: &str) -> String {
    let mut out = String::new();
    let mut token = String::new();
    let flush = |token: &mut String, out: &mut String| {
        let letters = token.chars().any(|c| c.is_ascii_alphabetic());
        let digits = token.chars().any(|c| c.is_ascii_digit());
        if token.contains("sk-") || token.len() >= 24 || (token.len() >= 8 && letters && digits) {
            out.push_str("<redacted>");
        } else {
            out.push_str(token);
        }
        token.clear();
    };
    for c in text.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '+' | '=' | '.') {
            token.push(c);
        } else {
            flush(&mut token, &mut out);
            out.push(c);
        }
    }
    flush(&mut token, &mut out);
    out
}

/// Every JSONL transcript under `dir`, as text.
fn transcripts(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            out.extend(transcripts(&path));
        } else if path.extension().is_some_and(|x| x == "jsonl") {
            out.extend(std::fs::read_to_string(&path).ok());
        }
    }
    out
}

fn which(name: &str) -> PathBuf {
    std::env::var_os("PATH")
        .and_then(|path| {
            std::env::split_paths(&path)
                .map(|dir| dir.join(name))
                .find(|p| p.is_file())
        })
        .unwrap_or_else(|| panic!("{name} is not on PATH"))
}

fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

/// Waits up to `time` for the frontend's screen to satisfy `done`.
fn screen_until(frontend: &Frontend, what: &str, time: Duration, done: impl Fn(&str) -> bool) {
    let deadline = Instant::now() + time;
    loop {
        let text = frontend.text();
        if done(&text) {
            return;
        }
        if Instant::now() > deadline {
            panic!(
                "the screen never showed {what}; it shows (redacted):\n{}",
                redact(&text)
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Types `text` as a user would, then Enter.
fn type_line(frontend: &mut Frontend, text: &str) {
    for chunk in text.as_bytes().chunks(8) {
        frontend.send(chunk);
        std::thread::sleep(Duration::from_millis(30));
    }
    std::thread::sleep(Duration::from_millis(400));
    frontend.send(b"\r");
}

// ── The rig: sandbox, runtime, fake Astation attachment ──────────────────

struct Rig {
    sb: Sandbox,
    astation: FakeAstation,
    runtime: Child,
    link: u64,
    attachment_gen: String,
    /// Everything the current link carried (session, terminal frames left
    /// out, agentChat, relay).
    seen: Vec<Value>,
    /// The lease epoch the last `answer` took.
    last_lease: u64,
}

impl Rig {
    fn new(codex_consent: bool) -> Self {
        let sb = Sandbox::new();
        let config = sb.config();
        if codex_consent {
            // `atem agent launch codex` asks.
            std::fs::remove_file(config.join("config.toml")).unwrap();
        }
        write_verified_pairing(&config, ACCOUNT, DEVICE, TRUST_GEN);
        let astation = FakeAstation::start();
        let log = std::fs::File::create(sb.dir.path().join("runtime.out")).unwrap();
        let runtime = Command::new(env!("CARGO_BIN_EXE_atem"))
            .arg("runtime")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &sb.home)
            .env("XDG_RUNTIME_DIR", &sb.run)
            .env("ASTATION_WS", &astation.url)
            .env("ASTATION_RELAY_URL", "http://127.0.0.1:1")
            .current_dir(&sb.home)
            .stdin(Stdio::null())
            .stdout(log.try_clone().unwrap())
            .stderr(log)
            .spawn()
            .unwrap();
        let mut rig = Self {
            sb,
            astation,
            runtime,
            link: 0,
            attachment_gen: String::new(),
            seen: Vec::new(),
            last_lease: 0,
        };
        rig.attach();
        rig
    }

    /// The authenticated link, `hello` until attached, then `list`.
    fn attach(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while self.link == 0 {
            match self.astation.events.recv_timeout(Duration::from_secs(20)) {
                Ok(Event::Authenticated(n)) => self.link = n,
                Ok(_) => {}
                Err(_) => panic!("the runtime's link never authenticated"),
            }
        }
        loop {
            let id = uuid();
            self.send(json!({"type": "session",
                "data": {"v": 1, "op": "hello", "id": id, "revision": 8}}));
            let reply = self.wait(Duration::from_secs(10), "welcome", |m| {
                m["type"] == "session" && m["data"]["re"] == id.as_str()
            });
            if reply["data"]["op"] == "welcome" {
                assert_eq!(reply["data"]["account_id"], ACCOUNT);
                assert_eq!(reply["data"]["atem_device_id"], DEVICE);
                self.attachment_gen = reply["data"]["attachment_gen"].as_str().unwrap().into();
                break;
            }
            assert!(Instant::now() < deadline, "never attached: {reply}");
            std::thread::sleep(Duration::from_millis(200));
        }
        let id = uuid();
        self.send(json!({"type": "session", "data": {"v": 1, "op": "list", "id": id}}));
        self.wait(Duration::from_secs(10), "sessions", |m| {
            m["data"]["op"] == "sessions"
        });
    }

    fn send(&self, message: Value) {
        self.astation.send(self.link, message.to_string());
    }

    /// Takes in what arrived (for up to `time`).
    fn pump(&mut self, time: Duration) {
        let deadline = Instant::now() + time;
        while let Ok(event) = self
            .astation
            .events
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        {
            if let Event::Message(n, value) = event
                && n == self.link
            {
                if value["type"] == "terminal" && value["data"]["op"] == "frame" {
                    continue;
                }
                self.seen.push(value);
            }
        }
    }

    /// The first message seen (from the start) that `pick` accepts, waiting
    /// up to `time`.
    #[track_caller]
    fn wait(&mut self, time: Duration, what: &str, pick: impl Fn(&Value) -> bool) -> Value {
        let deadline = Instant::now() + time;
        loop {
            if let Some(found) = self.seen.iter().find(|m| pick(m)) {
                return found.clone();
            }
            if Instant::now() > deadline {
                let ops: Vec<String> = self
                    .seen
                    .iter()
                    .rev()
                    .take(30)
                    .map(|m| format!("{}/{}", m["type"], m["data"]["op"]))
                    .collect();
                let tail: Vec<String> = self
                    .seen
                    .iter()
                    .rev()
                    .take(8)
                    .map(|m| redact(&m.to_string()).chars().take(700).collect())
                    .collect();
                panic!(
                    "never got {what}; last ops: {ops:?}\nlast messages:\n{}",
                    tail.join("\n")
                );
            }
            self.pump(Duration::from_millis(100));
        }
    }

    fn has(&self, pick: impl Fn(&Value) -> bool) -> bool {
        self.seen.iter().any(pick)
    }

    /// The newest descriptor of `sid`.
    fn descriptor(&self, sid: &str) -> Option<Value> {
        self.seen
            .iter()
            .rev()
            .find_map(|m| match m["data"]["op"].as_str() {
                Some("session_changed") if m["data"]["descriptor"]["session_id"] == sid => {
                    Some(m["data"]["descriptor"].clone())
                }
                Some("sessions") => m["data"]["sessions"]
                    .as_array()
                    .and_then(|all| all.iter().find(|d| d["session_id"] == sid).cloned()),
                _ => None,
            })
    }

    /// The session `atem agent launch` started (the only new one).
    fn new_session(&mut self, known: &[String]) -> (String, String) {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            self.pump(Duration::from_millis(200));
            let found = self.seen.iter().rev().find_map(|m| {
                let d = &m["data"]["descriptor"];
                (m["data"]["op"] == "session_changed"
                    && d["state"] == "running"
                    && !known.iter().any(|k| d["session_id"] == k.as_str()))
                .then(|| {
                    (
                        d["session_id"].as_str().unwrap().to_string(),
                        d["process_gen"].as_str().unwrap().to_string(),
                    )
                })
            });
            if let Some(found) = found {
                return found;
            }
            assert!(Instant::now() < deadline, "no new session appeared");
        }
    }

    fn binding(&self, sid: &str, generation: &str) -> Value {
        json!({"target": {"account_id": ACCOUNT, "atem_device_id": DEVICE,
                          "host_trust_gen": TRUST_GEN, "session_id": sid,
                          "process_gen": generation},
               "attachment_gen": self.attachment_gen})
    }

    /// A lease on `sid` for this attachment; its epoch.
    fn acquire(&mut self, sid: &str, generation: &str) -> u64 {
        let id = uuid();
        self.send(
            json!({"type": "session", "data": {"v": 1, "op": "acquire", "id": id,
            "binding": self.binding(sid, generation), "takeover": true}}),
        );
        let lease = self.wait(Duration::from_secs(10), "lease", |m| {
            m["type"] == "session" && m["data"]["re"] == id.as_str()
        });
        assert_eq!(lease["data"]["op"], "lease", "{lease}");
        lease["data"]["binding"]["lease_epoch"].as_u64().unwrap()
    }

    /// Submits `text` in chat conversation `conversation` under `lease`;
    /// the request id.
    fn chat_submit(
        &mut self,
        conversation: &str,
        sid: &str,
        generation: &str,
        lease: u64,
        text: &str,
    ) -> String {
        let request_id = uuid();
        let mut binding = self.binding(sid, generation);
        binding["lease_epoch"] = lease.into();
        self.send(json!({"type": "agentChat", "data": {"v": 1, "op": "submit",
            "conversationId": conversation, "agentId": sid, "binding": binding,
            "generation": generation, "requestId": request_id, "text": text}}));
        request_id
    }

    /// The `complete` or `error` of chat request `request_id`.
    fn chat_done(&mut self, request_id: &str, time: Duration) -> Value {
        let rid = request_id.to_string();
        self.wait(time, "the chat request's end", |m| {
            m["type"] == "agentChat"
                && matches!(m["data"]["op"].as_str(), Some("complete" | "error"))
                && m["data"]["requestId"] == rid.as_str()
        })["data"]
            .clone()
    }

    /// Waits until `sid`'s activity is `activity`.
    fn activity(&mut self, sid: &str, activity: &str, time: Duration) {
        let deadline = Instant::now() + time;
        loop {
            self.pump(Duration::from_millis(200));
            if self
                .descriptor(sid)
                .is_some_and(|d| d["activity"] == activity)
            {
                return;
            }
            assert!(Instant::now() < deadline, "{sid} never became {activity}");
        }
    }

    /// The next `approval_request` for `sid` not in `known`.
    fn approval(&mut self, sid: &str, known: &[String], time: Duration) -> Value {
        let known = known.to_vec();
        self.wait(time, "approval_request", |m| {
            m["data"]["op"] == "approval_request"
                && m["data"]["session_id"] == sid
                && !known.iter().any(|k| m["data"]["approval_id"] == k.as_str())
        })["data"]
            .clone()
    }

    /// Takes control (an explicit `acquire`: answers need the lease until
    /// r8's lease-free answers ship; r7's `acquire` on the answer is gone),
    /// then answers `approval_id` under that lease; returns the submit's id
    /// and the request id. `last_lease` keeps the epoch.
    // TODO(r8 task 3): answer without the lease (`approval.lease_free`).
    fn answer(&mut self, sid: &str, generation: &str, payload: Value) -> (String, String) {
        let lease = self.acquire(sid, generation);
        self.last_lease = lease;
        let id = uuid();
        let request_id = uuid();
        let mut binding = self.binding(sid, generation);
        binding["lease_epoch"] = lease.into();
        self.send(
            json!({"type": "session", "data": {"v": 1, "op": "submit", "id": id,
            "binding": binding, "request_id": request_id,
            "kind": "approval", "payload": payload}}),
        );
        (id, request_id)
    }

    /// The final receipt of `request_id` (and every state it went through).
    fn receipt_final(&mut self, request_id: &str, time: Duration) -> (Value, Vec<String>) {
        let rid = request_id.to_string();
        let last = self.wait(time, "a final receipt", |m| {
            m["data"]["op"] == "receipt"
                && m["data"]["request_id"] == rid.as_str()
                && matches!(
                    m["data"]["state"].as_str(),
                    Some("completed" | "rejected" | "outcome_unknown")
                )
        });
        let states = self
            .seen
            .iter()
            .filter(|m| m["data"]["op"] == "receipt" && m["data"]["request_id"] == rid.as_str())
            .map(|m| m["data"]["state"].as_str().unwrap_or_default().to_string())
            .collect();
        (last["data"].clone(), states)
    }

    fn closed(&mut self, approval_id: &str, time: Duration) -> String {
        let aid = approval_id.to_string();
        self.wait(time, "approval_closed", |m| {
            m["data"]["op"] == "approval_closed" && m["data"]["approval_id"] == aid.as_str()
        })["data"]["reason"]
            .as_str()
            .unwrap()
            .to_string()
    }

    fn push(&mut self, op: &str, approval_id: &str, time: Duration) -> Value {
        let (op, aid) = (op.to_string(), approval_id.to_string());
        self.wait(time, &op.clone(), |m| {
            m["type"] == "relay"
                && m["data"]["op"] == op.as_str()
                && m["data"]["approval_id"] == aid.as_str()
        })["data"]
            .clone()
    }

    /// Waits until `sid`'s activity is `ready` (the turn ended).
    fn ready(&mut self, sid: &str, time: Duration) {
        let deadline = Instant::now() + time;
        loop {
            self.pump(Duration::from_millis(200));
            if self
                .descriptor(sid)
                .is_some_and(|d| d["activity"] == "ready")
            {
                return;
            }
            assert!(Instant::now() < deadline, "{sid} never became ready");
        }
    }

    fn runtime_log(&self) -> String {
        let mut text =
            std::fs::read_to_string(self.sb.dir.path().join("runtime.out")).unwrap_or_default();
        text.push_str(
            &std::fs::read_to_string(self.sb.config().join("runtime.log")).unwrap_or_default(),
        );
        redact(&text)
    }
}

impl Drop for Rig {
    /// The runtime, then every process carrying the sandbox's path in its
    /// command line or environment (workers, agents and their children) —
    /// only those.
    fn drop(&mut self) {
        let _ = self.runtime.kill();
        let _ = self.runtime.wait();
        let marker = self.sb.dir.path().as_os_str().as_encoded_bytes().to_vec();
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

/// Checks a `push_approval` for `request` (an `approval_request`).
fn check_push(push: &Value, request: &Value, sid: &str, hook_secs: u64) {
    assert_eq!(push["atem_device_id"], DEVICE, "{push}");
    assert_eq!(push["session_id"], sid, "{push}");
    assert_eq!(push["tool"], request["tool"], "{push}");
    assert_eq!(push["summary"], request["summary"], "{push}");
    let expires = push["expires_at"].as_u64().expect("expires_at");
    let created = request["created_at"].as_u64().expect("created_at");
    let expected = created + hook_secs * 1000;
    assert!(
        expires.abs_diff(expected) < 5_000,
        "expires_at {expires} vs created_at {created} + {hook_secs} s"
    );
    let summary = push["summary"].as_str().unwrap();
    assert!(
        summary.len() <= 200 && !summary.contains('\n'),
        "{summary:?}"
    );
}

// ── Claude Code ───────────────────────────────────────────────────────────

/// The environment a real Claude launch gets on top of the sandbox's.
fn claude_env() -> Vec<(String, String)> {
    let claude = which("claude");
    let mut env = vec![
        ("CLAUDE_CLI_BIN".to_string(), claude.display().to_string()),
        ("DISABLE_AUTOUPDATER".into(), "1".into()),
        ("PATH".into(), "/usr/bin:/bin".into()),
    ];
    for name in [
        "ANTHROPIC_BASE_URL",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_API_KEY",
        "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
    ] {
        if let Ok(value) = std::env::var(name) {
            env.push((name.into(), value));
        }
    }
    env
}

/// Claude's own first-run state in the sandbox: onboarding done and `work`
/// trusted, so it starts straight into its prompt.
fn claude_first_run(sb: &Sandbox, work: &Path) {
    let state = json!({
        "hasCompletedOnboarding": true,
        "theme": "dark",
        "numStartups": 5,
        "projects": {work.display().to_string(): {
            "hasTrustDialogAccepted": true, "allowedTools": [],
            "hasCompletedProjectOnboarding": true}},
    });
    std::fs::write(sb.home.join(".claude.json"), state.to_string()).unwrap();
}

fn claude_prompt_up(text: &str) -> bool {
    text.contains("for shortcuts") || text.lines().any(|l| l.trim_start().starts_with('❯'))
}

/// Asks Claude for one Bash command, verbatim.
fn ask_claude(frontend: &mut Frontend, command: &str) {
    type_line(
        frontend,
        &format!("Use the Bash tool to run exactly this command and nothing else: {command}"),
    );
}

#[test]
#[ignore = "real Claude Code; ATEM_REAL_AGENTS=1"]
fn claude_approvals_end_to_end() {
    if !enabled() {
        return;
    }
    let mut rig = Rig::new(false);
    let work = rig.sb.home.join("proj");
    std::fs::create_dir_all(&work).unwrap();
    claude_first_run(&rig.sb, &work);
    let model = std::env::var("ATEM_REAL_CLAUDE_MODEL").unwrap_or_else(|_| "haiku".into());
    let env = claude_env();
    let extra: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
    let mut fe = rig.sb.spawn(
        &[
            "agent",
            "launch",
            "claude",
            "--model",
            &model,
            "--permission-mode",
            "default",
        ],
        &work,
        &extra,
    );
    let (sid, generation) = rig.new_session(&[]);
    screen_until(
        &fe,
        "Claude's prompt",
        Duration::from_secs(60),
        claude_prompt_up,
    );
    // Chat is ready once SessionStart arrived.
    rig.ready(&sid, Duration::from_secs(30));
    eprintln!("claude up (redacted):\n{}", redact(&fe.text()));

    // A chat conversation, for the card.
    rig.send(json!({"type": "agentChat", "data": {"v": 1, "op": "open",
        "conversationId": "conv-1", "agentId": sid, "binding": rig.binding(&sid, &generation)}}));
    rig.wait(Duration::from_secs(10), "chat opened", |m| {
        m["type"] == "agentChat" && m["data"]["op"] == "opened"
    });

    let mut known: Vec<String> = Vec::new();
    let mut report: Vec<String> = Vec::new();

    // 1. allow_once from the non-holder, with acquire.
    ask_claude(&mut fe, "touch allow-once.txt");
    let request = rig.approval(&sid, &known, TURN);
    let aid = request["approval_id"].as_str().unwrap().to_string();
    known.push(aid.clone());
    assert_eq!(request["tool"], "Bash", "{request}");
    assert_eq!(request["summary"], "touch allow-once.txt", "{request}");
    assert_eq!(request["process_gen"], generation.as_str());
    let push = rig.push("push_approval", &aid, Duration::from_secs(10));
    check_push(&push, &request, &sid, 600);
    // The dialog is up in the terminal too.
    let (_, rid) = rig.answer(
        &sid,
        &generation,
        json!({"approval_id": aid, "decision": "allow_once"}),
    );
    let (receipt, states) = rig.receipt_final(&rid, Duration::from_secs(30));
    assert_eq!(receipt["state"], "completed", "{receipt} {states:?}");
    assert_eq!(rig.closed(&aid, Duration::from_secs(10)), "answered_remote");
    let lease = rig.last_lease;
    let resolved = rig.push("push_resolved", &aid, Duration::from_secs(10));
    assert_eq!(resolved["reason"], "answered_remote");
    let card_id = format!("approval-{aid}");
    let card = rig.wait(Duration::from_secs(10), "the allowed card", |m| {
        m["type"] == "agentChat"
            && m["data"]["op"] == "message"
            && m["data"]["messageId"] == card_id.as_str()
            && m["data"]["parts"][0]["state"] == "allowed"
    });
    let had_pending = rig.has(|m| {
        m["data"]["messageId"] == card_id.as_str() && m["data"]["parts"][0]["state"] == "pending"
    });
    assert!(had_pending, "no pending card before {card}");
    rig.ready(&sid, TURN);
    assert!(
        work.join("allow-once.txt").exists(),
        "allow-once.txt was not created"
    );
    report.push(format!(
        "1 allow_once: receipt {states:?}; closed answered_remote; answered under lease epoch {lease} (acquired first); card pending→allowed; file created; push expires_at={}, resolved={}",
        push["expires_at"], resolved["reason"]
    ));

    // 2. deny with a message: not run, the model sees the message.
    let message = "atem-e2e-deny: this command is not allowed";
    // The command carries AWS's documented example key: the summaries
    // (request, push, card) must show it redacted.
    ask_claude(&mut fe, "touch denied.txt # AKIAIOSFODNN7EXAMPLE");
    let request = rig.approval(&sid, &known, TURN);
    let aid = request["approval_id"].as_str().unwrap().to_string();
    known.push(aid.clone());
    assert_eq!(
        request["summary"], "touch denied.txt # [redacted]",
        "{request}"
    );
    let push = rig.push("push_approval", &aid, Duration::from_secs(10));
    check_push(&push, &request, &sid, 600);
    let card_id = format!("approval-{aid}");
    assert!(!rig.has(|m| m["data"]["messageId"] == card_id.as_str()
        && m.to_string().contains("AKIAIOSFODNN7EXAMPLE")));
    let (_, rid) = rig.answer(
        &sid,
        &generation,
        json!({"approval_id": aid, "decision": "deny", "message": message}),
    );
    let (receipt, states) = rig.receipt_final(&rid, Duration::from_secs(30));
    assert_eq!(receipt["state"], "completed", "{receipt} {states:?}");
    assert_eq!(rig.closed(&aid, Duration::from_secs(10)), "answered_remote");
    assert_eq!(
        rig.push("push_resolved", &aid, Duration::from_secs(10))["reason"],
        "answered_remote"
    );
    let card_id = format!("approval-{aid}");
    rig.wait(Duration::from_secs(10), "the denied card", |m| {
        m["data"]["messageId"] == card_id.as_str() && m["data"]["parts"][0]["state"] == "denied"
    });
    rig.ready(&sid, TURN);
    assert!(!work.join("denied.txt").exists(), "denied.txt was created");
    let seen_by_model = transcripts(&rig.sb.home.join(".claude"))
        .iter()
        .any(|t| t.contains(message) && t.contains("tool_result"));
    assert!(
        seen_by_model,
        "the deny message never reached the transcript"
    );
    report.push(format!(
        "2 deny+message: summary {:?} (example key redacted in request, push and card); receipt {states:?}; closed answered_remote; card denied; file not created; message in the tool_result of the transcript", request["summary"]
    ));

    // 4. the terminal answers first; a late remote answer is stale_target.
    ask_claude(&mut fe, "touch terminal.txt");
    let request = rig.approval(&sid, &known, TURN);
    let aid = request["approval_id"].as_str().unwrap().to_string();
    known.push(aid.clone());
    screen_until(&fe, "Claude's own dialog", Duration::from_secs(20), |t| {
        t.contains("Do you want to proceed")
    });
    fe.send(b"\r");
    assert_eq!(
        rig.closed(&aid, Duration::from_secs(30)),
        "answered_terminal"
    );
    assert_eq!(
        rig.push("push_resolved", &aid, Duration::from_secs(10))["reason"],
        "answered_terminal"
    );
    let card_id = format!("approval-{aid}");
    rig.wait(Duration::from_secs(10), "the answered_terminal card", |m| {
        m["data"]["messageId"] == card_id.as_str()
            && m["data"]["parts"][0]["state"] == "answered_terminal"
    });
    let (id, rid) = rig.answer(
        &sid,
        &generation,
        json!({"approval_id": aid, "decision": "allow_once"}),
    );
    let reply = rig.wait(Duration::from_secs(10), "the late answer's reply", |m| {
        m["data"]["re"] == id.as_str()
    });
    assert_eq!(reply["data"]["op"], "error", "{reply}");
    assert_eq!(reply["data"]["code"], "stale_target", "{reply}");
    rig.ready(&sid, TURN);
    rig.pump(Duration::from_secs(2));
    assert!(!rig.has(|m| m["data"]["op"] == "receipt" && m["data"]["request_id"] == rid.as_str()));
    assert!(
        work.join("terminal.txt").exists(),
        "terminal.txt was not created"
    );
    report.push("4 terminal first: closed answered_terminal; push_resolved answered_terminal; card answered_terminal; late allow_once → error stale_target, no receipt; file created by the terminal's Yes".into());

    // 3. allow_always with an offered rule.
    ask_claude(&mut fe, "touch always.txt");
    let request = rig.approval(&sid, &known, TURN);
    let aid = request["approval_id"].as_str().unwrap().to_string();
    known.push(aid.clone());
    let rules = request["always_rules"]
        .as_array()
        .cloned()
        .unwrap_or_default();
    assert!(!rules.is_empty(), "Claude offered no rule: {request}");
    let rule = rules[0].clone();
    let (_, rid) = rig.answer(
        &sid,
        &generation,
        json!({"approval_id": aid, "decision": "allow_always", "rule_id": rule["rule_id"]}),
    );
    let (receipt, states) = rig.receipt_final(&rid, Duration::from_secs(30));
    assert_eq!(receipt["state"], "completed", "{receipt} {states:?}");
    assert_eq!(rig.closed(&aid, Duration::from_secs(10)), "answered_remote");
    let card_id = format!("approval-{aid}");
    rig.wait(Duration::from_secs(10), "the always_allowed card", |m| {
        m["data"]["messageId"] == card_id.as_str()
            && m["data"]["parts"][0]["state"] == "always_allowed"
    });
    rig.ready(&sid, TURN);
    assert!(
        work.join("always.txt").exists(),
        "always.txt was not created"
    );
    let mut persisted = Vec::new();
    for file in [
        work.join(".claude").join("settings.local.json"),
        work.join(".claude").join("settings.json"),
        rig.sb.home.join(".claude").join("settings.json"),
    ] {
        if let Ok(text) = std::fs::read_to_string(&file) {
            persisted.push(format!("{}: {}", file.display(), redact(&text)));
        }
    }
    let labels: Vec<String> = rules
        .iter()
        .map(|r| {
            format!(
                "{} [{}]",
                r["label"].as_str().unwrap_or(""),
                r["scope"].as_str().unwrap_or("")
            )
        })
        .collect();
    report.push(format!(
        "3 allow_always: offered {labels:?}; chose {:?}; receipt {states:?}; card always_allowed; file created; settings files: {}",
        rule["label"],
        if persisted.is_empty() { "none written".to_string() } else { persisted.join(" | ") }
    ));

    eprintln!("CLAUDE REPORT:\n{}", report.join("\n"));
    eprintln!(
        "runtime log tail:\n{}",
        rig.runtime_log()
            .lines()
            .rev()
            .take(20)
            .collect::<Vec<_>>()
            .join("\n")
    );
}

// ── Codex ─────────────────────────────────────────────────────────────────

/// A hooks.json that was there before Atem: the merge must keep it.
const CODEX_HOOKS_BEFORE: &str = "{\n  \"hooks\": {\n    \"Stop\": [\n      {\"hooks\": [{\"type\": \"command\", \"command\": \"true\"}]}\n    ]\n  }\n}\n";

/// A temp CODEX_HOME with the `oss` profile: the provider's non-secret
/// fields copied from `~/.codex/config.toml` (its key comes from the
/// environment variable it names), `work` trusted, no update check. Returns
/// the name of the key's variable.
fn codex_home(dir: &Path, work: &Path) -> String {
    let real = dirs_home().join(".codex");
    let config: toml::Table = std::fs::read_to_string(real.join("config.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let profile: toml::Table = std::fs::read_to_string(real.join("oss.config.toml"))
        .unwrap()
        .parse()
        .unwrap();
    let provider = config["model_providers"]["oss"].as_table().unwrap();
    let mut oss = toml::Table::new();
    for key in ["name", "base_url", "env_key", "wire_api"] {
        if let Some(v) = provider.get(key) {
            oss.insert(key.into(), v.clone());
        }
    }
    let env_key = oss["env_key"].as_str().unwrap().to_string();
    // The key comes from env_key, never an OpenAI login.
    oss.insert("requires_openai_auth".into(), false.into());
    let mut top = toml::Table::new();
    top.insert("check_for_update_on_startup".into(), false.into());
    let mut providers = toml::Table::new();
    providers.insert("oss".into(), oss.into());
    top.insert("model_providers".into(), providers.into());
    let mut projects = toml::Table::new();
    let mut trusted = toml::Table::new();
    trusted.insert("trust_level".into(), "trusted".into());
    projects.insert(work.display().to_string(), trusted.into());
    top.insert("projects".into(), projects.into());
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("config.toml"), toml::to_string(&top).unwrap()).unwrap();
    let mut oss_profile = toml::Table::new();
    for key in ["model_provider", "model"] {
        oss_profile.insert(key.into(), profile[key].clone());
    }
    oss_profile.insert("model_reasoning_effort".into(), "low".into());
    let mut projects = toml::Table::new();
    let mut trusted = toml::Table::new();
    trusted.insert("trust_level".into(), "trusted".into());
    projects.insert(work.display().to_string(), trusted.into());
    oss_profile.insert("projects".into(), projects.into());
    std::fs::write(
        dir.join("oss.config.toml"),
        toml::to_string(&oss_profile).unwrap(),
    )
    .unwrap();
    std::fs::write(dir.join("hooks.json"), CODEX_HOOKS_BEFORE).unwrap();
    env_key
}

/// The real home (read-only: Codex's provider settings).
fn dirs_home() -> PathBuf {
    PathBuf::from(std::env::var_os("HOME").expect("HOME"))
}

fn codex_idle(text: &str) -> bool {
    !text.contains("esc to interrupt") && !text.contains("Working") && text.contains("›")
}

/// A Codex session launched through `atem agent launch codex` in the
/// sandbox, its hooks consented to, merged and trusted, at its prompt.
struct CodexRun {
    fe: Frontend,
    sid: String,
    generation: String,
    home: PathBuf,
    work: PathBuf,
    /// What the consent and hook review did (for the report).
    setup: String,
}

/// Launches the real Codex (`--profile oss`, on-request approvals,
/// read-only sandbox) in a temp CODEX_HOME: answers Atem's consent
/// question, checks the hooks.json merge and trusts the hooks in Codex.
fn launch_codex(rig: &mut Rig) -> CodexRun {
    let work = rig.sb.home.join("cproj");
    std::fs::create_dir_all(&work).unwrap();
    let home = rig.sb.dir.path().join("codex-home");
    let env_key = codex_home(&home, &work);
    let codex = which("codex");
    let node_dir = which("node").parent().unwrap().display().to_string();
    let mut env = vec![
        ("CODEX_HOME".to_string(), home.display().to_string()),
        ("CODEX_CLI_BIN".into(), codex.display().to_string()),
        ("PATH".into(), format!("{node_dir}:/usr/bin:/bin")),
    ];
    if let Ok(value) = std::env::var(&env_key) {
        env.push((env_key.clone(), value));
    }
    let extra: Vec<(&str, &str)> = env.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();

    // Consent and the hooks.json merge.
    let mut fe = rig.sb.spawn(
        &[
            "agent",
            "launch",
            "codex",
            "--profile",
            "oss",
            "-a",
            "on-request",
            "-s",
            "read-only",
        ],
        &work,
        &extra,
    );
    screen_until(&fe, "the consent question", Duration::from_secs(20), |t| {
        t.contains("Let Astation follow Codex sessions")
    });
    fe.send(b"y\r");
    let (sid, generation) = rig.new_session(&[]);
    let hooks = std::fs::read_to_string(home.join("hooks.json")).unwrap();
    let backup = std::fs::read_to_string(home.join("hooks.json.atem-bak")).unwrap();
    assert_eq!(backup, CODEX_HOOKS_BEFORE);
    let parsed: Value = serde_json::from_str(&hooks).unwrap();
    assert_eq!(
        parsed["hooks"]["Stop"][0]["hooks"][0]["command"], "true",
        "{hooks}"
    );
    let ours = parsed["hooks"]["PermissionRequest"][0]["hooks"][0]["command"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    assert!(ours.starts_with(": atem-approval-hook;"), "{hooks}");
    let atem_config =
        std::fs::read_to_string(rig.sb.config().join("config.toml")).unwrap_or_default();
    assert!(atem_config.contains("hooks = true"), "{atem_config}");
    assert!(
        fe.written().contains("Added Atem's hooks to"),
        "no setup notice"
    );

    // Codex's own hook review: trust them all. It may come up a moment
    // after the prompt (as the startup screen or as the /hooks page).
    screen_until(&fe, "Codex's prompt", Duration::from_secs(60), |t| {
        t.contains("for shortcuts") || t.contains("need review")
    });
    let deadline = Instant::now() + Duration::from_secs(15);
    while !fe.text().contains("need review") && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
    let reviewed = fe.text().contains("need review");
    if reviewed {
        eprintln!("codex hook review (redacted):\n{}", redact(&fe.text()));
        trust_hooks(&mut fe);
    }
    screen_until(&fe, "Codex's prompt", Duration::from_secs(60), |t| {
        t.contains("for shortcuts") && !t.contains("need review") && !t.contains("esc close")
    });
    let trusted = std::fs::read_to_string(home.join("oss.config.toml")).unwrap_or_default()
        + &std::fs::read_to_string(home.join("config.toml")).unwrap_or_default();
    let trust_entries = trusted.matches("trusted_hash").count();
    let setup = format!(
        "consent: asked once, y → [codex] hooks = true; hooks.json merged (Stop hook kept, backup = original); review screen shown: {reviewed}; trusted_hash entries written: {trust_entries}"
    );
    CodexRun {
        fe,
        sid,
        generation,
        home,
        work,
        setup,
    }
}

#[test]
#[ignore = "real Codex; ATEM_REAL_AGENTS=1"]
fn codex_approvals_end_to_end() {
    if !enabled() {
        return;
    }
    let mut rig = Rig::new(true);
    let CodexRun {
        mut fe,
        sid,
        generation,
        home,
        work,
        setup,
    } = launch_codex(&mut rig);
    let mut report: Vec<String> = vec![format!("5 {setup}")];

    let mut known: Vec<String> = Vec::new();

    // 6. allow_once.
    type_line(
        &mut fe,
        "Run the shell command: touch codex-allow.txt . Do nothing else.",
    );
    let request = approval_or_screen(&mut rig, &fe, &sid, &known);
    let aid = request["approval_id"].as_str().unwrap().to_string();
    known.push(aid.clone());
    assert_eq!(request["process_gen"], generation.as_str());
    // Codex's chat status while the hook waits (the worker's open approval).
    rig.activity(&sid, "waiting", Duration::from_secs(10));
    // Codex takes no persistent rule: the card offers an Atem session rule.
    assert!(
        request["always_rules"]
            .as_array()
            .is_some_and(|r| r.len() == 1 && r[0]["scope"] == "session"),
        "{request}"
    );
    let push = rig.push("push_approval", &aid, Duration::from_secs(10));
    check_push(&push, &request, &sid, 300);
    let (_, rid) = rig.answer(
        &sid,
        &generation,
        json!({"approval_id": aid, "decision": "allow_once"}),
    );
    let (receipt, states) = rig.receipt_final(&rid, Duration::from_secs(30));
    assert_eq!(rig.closed(&aid, Duration::from_secs(10)), "answered_remote");
    assert_eq!(
        rig.push("push_resolved", &aid, Duration::from_secs(10))["reason"],
        "answered_remote"
    );
    within_secs("codex-allow.txt", 120, || {
        work.join("codex-allow.txt").exists()
    });
    screen_until(&fe, "Codex idle", TURN, codex_idle);
    report.push(format!(
        "6 allow_once: request tool={} summary={:?} rules={}; receipt {states:?} (final {}); closed answered_remote; push expires_at-created_at={} ms; file created",
        request["tool"], request["summary"], request["always_rules"], receipt["state"],
        push["expires_at"].as_u64().unwrap_or(0).saturating_sub(request["created_at"].as_u64().unwrap_or(0))
    ));
    assert_eq!(receipt["state"], "completed", "{receipt} {states:?}");

    // 7. deny with a message.
    let message = "atem-e2e-deny: this command is not allowed";
    type_line(
        &mut fe,
        "Run the shell command: touch codex-denied.txt . Do nothing else.",
    );
    let request = approval_or_screen(&mut rig, &fe, &sid, &known);
    let aid = request["approval_id"].as_str().unwrap().to_string();
    known.push(aid.clone());
    let (_, rid) = rig.answer(
        &sid,
        &generation,
        json!({"approval_id": aid, "decision": "deny", "message": message}),
    );
    let (receipt, states) = rig.receipt_final(&rid, Duration::from_secs(30));
    assert_eq!(rig.closed(&aid, Duration::from_secs(10)), "answered_remote");
    screen_until(&fe, "Codex idle", TURN, codex_idle);
    std::thread::sleep(Duration::from_secs(1));
    let shown = fe.text().contains(message);
    let in_transcript = transcripts(&home.join("sessions"))
        .iter()
        .any(|t| t.contains(message));
    report.push(format!(
        "7 deny+message: receipt {states:?}; closed answered_remote; file created: {}; message on screen: {shown}; in transcript: {in_transcript}",
        work.join("codex-denied.txt").exists()
    ));
    assert_eq!(receipt["state"], "completed", "{receipt} {states:?}");
    assert!(!work.join("codex-denied.txt").exists());
    assert!(
        shown || in_transcript,
        "the model never saw the deny message"
    );

    // 8. a local key while the hook waits: it releases the hook and is
    //    consumed (the user saw only "Running hook", never the dialog), so
    //    even a 'y' approves nothing; Codex's own dialog then takes the key.
    type_line(
        &mut fe,
        "Run the shell command: touch codex-local.txt . Do nothing else.",
    );
    let request = approval_or_screen(&mut rig, &fe, &sid, &known);
    let aid = request["approval_id"].as_str().unwrap().to_string();
    known.push(aid.clone());
    std::thread::sleep(Duration::from_secs(1));
    let dialog_before = fe.text().contains("Yes, proceed");
    fe.send(b"y");
    let reason = rig.closed(&aid, Duration::from_secs(10));
    let resolved = rig.push("push_resolved", &aid, Duration::from_secs(10));
    screen_until(&fe, "Codex's own dialog", Duration::from_secs(30), |t| {
        t.contains("Yes, proceed")
    });
    std::thread::sleep(Duration::from_secs(1));
    let consumed = !work.join("codex-local.txt").exists();
    fe.send(b"y");
    within_secs("codex-local.txt", 60, || {
        work.join("codex-local.txt").exists()
    });
    screen_until(&fe, "Codex idle", TURN, codex_idle);
    report.push(format!(
        "8 local key while the hook waits: dialog visible before: {dialog_before}; closed {reason}; push_resolved {}; first 'y' consumed: {consumed}; 'y' at Codex's own dialog created the file",
        resolved["reason"]
    ));
    assert_eq!(reason, "released");
    assert_eq!(resolved["reason"], "released");
    assert!(consumed, "the releasing key answered Codex's dialog");

    // 9. "Always allow this command" (an Atem session rule): the same
    //    command then runs with no approval, shown as an auto_allowed card.
    rig.send(json!({"type": "agentChat", "data": {"v": 1, "op": "open",
        "conversationId": "conv-rules", "agentId": sid,
        "binding": rig.binding(&sid, &generation)}}));
    rig.wait(Duration::from_secs(10), "chat opened", |m| {
        m["type"] == "agentChat"
            && m["data"]["op"] == "opened"
            && m["data"]["conversationId"] == "conv-rules"
    });
    let always =
        "Run exactly this shell command, unchanged: touch codex-always.txt . Do nothing else.";
    type_line(&mut fe, always);
    let request = approval_or_screen(&mut rig, &fe, &sid, &known);
    let aid = request["approval_id"].as_str().unwrap().to_string();
    known.push(aid.clone());
    let rule = request["always_rules"][0].clone();
    assert_eq!(rule["scope"], "session", "{request}");
    let rule_id = rule["rule_id"].as_str().unwrap().to_string();
    let (_, rid) = rig.answer(
        &sid,
        &generation,
        json!({"approval_id": aid, "decision": "allow_always", "rule_id": rule_id}),
    );
    let (receipt, states) = rig.receipt_final(&rid, Duration::from_secs(30));
    assert_eq!(receipt["state"], "completed", "{receipt} {states:?}");
    within_secs("codex-always.txt", 120, || {
        work.join("codex-always.txt").exists()
    });
    let r = rule_id.clone();
    rig.wait(Duration::from_secs(10), "approval_rules", move |m| {
        m["data"]["op"] == "approval_rules" && m["data"]["rules"][0]["rule_id"] == r.as_str()
    });
    screen_until(&fe, "Codex idle", TURN, codex_idle);
    std::fs::remove_file(work.join("codex-always.txt")).unwrap();
    let before = rig.seen.len();
    type_line(&mut fe, always);
    within_secs("codex-always.txt again", 120, || {
        rig.pump(Duration::from_millis(100));
        work.join("codex-always.txt").exists()
    });
    let r = rule_id.clone();
    let card = rig.wait(Duration::from_secs(10), "auto_allowed card", move |m| {
        m["type"] == "agentChat"
            && m["data"]["op"] == "message"
            && m["data"]["parts"][0]["state"] == "auto_allowed"
            && m["data"]["parts"][0]["rule_id"] == r.as_str()
    });
    screen_until(&fe, "Codex idle", TURN, codex_idle);
    rig.pump(Duration::from_millis(500));
    let new_cards = rig.seen[before..]
        .iter()
        .filter(|m| m["data"]["op"] == "approval_request")
        .count();
    // (runtime_log() redacts ids, the rule's too.)
    let log = rig.runtime_log();
    let logged = log.lines().any(|l| l.contains("allowed by session rule"));
    let leaked = log
        .lines()
        .filter(|l| l.contains("allowed by session rule"))
        .any(|l| l.contains("touch") || l.contains("codex-always"));
    report.push(format!(
        "9 always allow (session rule {}): receipt {states:?}; rule listed; same command ran again with {new_cards} approval_request(s); auto_allowed card summary {:?}; runtime.log line: {logged}, command text in it: {leaked}",
        rule["label"], card["data"]["parts"][0]["summary"]
    ));
    assert_eq!(new_cards, 0, "the same command asked again");
    assert!(logged && !leaked, "runtime.log: {logged} {leaked}");

    eprintln!("CODEX REPORT:\n{}", report.join("\n"));
}

/// The texts of the assistant messages chat delivered for `turn`.
fn assistant_texts(rig: &Rig, turn: &str) -> Vec<String> {
    rig.seen
        .iter()
        .filter(|m| {
            m["type"] == "agentChat"
                && m["data"]["op"] == "message"
                && m["data"]["role"] == "assistant"
                && m["data"]["turnId"] == turn
        })
        .flat_map(|m| {
            m["data"]["parts"]
                .as_array()
                .cloned()
                .unwrap_or_default()
                .into_iter()
                .filter_map(|p| p["markdown"].as_str().map(str::to_string))
        })
        .collect()
}

#[test]
#[ignore = "real Codex; ATEM_REAL_AGENTS=1"]
fn codex_chat_end_to_end() {
    if !enabled() {
        return;
    }
    let mut rig = Rig::new(true);
    let CodexRun {
        mut fe,
        sid,
        generation,
        setup,
        ..
    } = launch_codex(&mut rig);
    let mut report: Vec<String> = vec![setup];

    // 1. Chat opens before Codex's first prompt: unknown, with the hint,
    //    and what Codex chat can't provide; a prompt is refused.
    rig.send(json!({"type": "agentChat", "data": {"v": 1, "op": "open",
        "conversationId": "conv-1", "agentId": sid, "binding": rig.binding(&sid, &generation)}}));
    let opened = rig.wait(Duration::from_secs(10), "chat opened", |m| {
        m["type"] == "agentChat" && m["data"]["op"] == "opened"
    })["data"]
        .clone();
    assert_eq!(opened["status"]["state"], "unknown", "{opened}");
    assert!(
        opened["status"]["detail"]
            .as_str()
            .is_some_and(|d| d.contains("type a first prompt in the terminal")),
        "{opened}"
    );
    assert_eq!(
        opened["unavailable"],
        json!(["streaming", "reasoning", "error_details"])
    );
    let lease = rig.acquire(&sid, &generation);
    let early = rig.chat_submit(
        "conv-1",
        &sid,
        &generation,
        lease,
        "Reply with exactly the word: early",
    );
    let refused = rig.chat_done(&early, Duration::from_secs(10));
    assert_eq!(refused["code"], "rejected", "{refused}");
    report.push(format!(
        "1 before the first prompt: opened unknown ({:?}), unavailable {}; submit refused: {:?}",
        opened["status"]["detail"], opened["unavailable"], refused["text"]
    ));

    // 2. The first prompt, typed in the terminal (the lease goes back to
    //    the terminal).
    type_line(&mut fe, "Reply with exactly the word: pong");
    let local = rig.wait(TURN, "the local prompt in chat", |m| {
        m["type"] == "agentChat"
            && m["data"]["op"] == "message"
            && m["data"]["origin"] == "local"
            && m.to_string().contains("pong")
    })["data"]
        .clone();
    let turn1 = local["turnId"].as_str().unwrap().to_string();
    rig.activity(&sid, "ready", TURN);
    let reply1 = assistant_texts(&rig, &turn1);
    report.push(format!(
        "2 local first prompt: turn {turn1}; reply {:?}; activity ready",
        reply1.iter().map(|t| redact(t)).collect::<Vec<_>>()
    ));
    assert!(!reply1.is_empty(), "no reply for the local prompt");

    // 3. A remote chat prompt: accepted, the reply, complete.
    let lease = rig.acquire(&sid, &generation);
    let rid = rig.chat_submit(
        "conv-1",
        &sid,
        &generation,
        lease,
        "Reply with exactly the word: ping",
    );
    let user = rig.wait(TURN, "the remote prompt's message", |m| {
        m["type"] == "agentChat"
            && m["data"]["op"] == "message"
            && m["data"]["role"] == "user"
            && m["data"]["requestId"] == rid.as_str()
    })["data"]
        .clone();
    let done = rig.chat_done(&rid, TURN);
    assert_eq!(done["outcome"], "done", "{done}");
    let turn2 = done["turnId"].as_str().unwrap_or_default().to_string();
    assert_eq!(user["turnId"], turn2.as_str());
    let reply2 = assistant_texts(&rig, &turn2);
    report.push(format!(
        "3 remote prompt: user message origin {} with requestId; complete {} turn {turn2}; reply {:?}",
        user["origin"],
        done["outcome"],
        reply2.iter().map(|t| redact(t)).collect::<Vec<_>>()
    ));
    assert!(!reply2.is_empty(), "no reply for the remote prompt");
    assert!(rig.has(|m| m["type"] == "agentChat"
        && m["data"]["op"] == "accepted"
        && m["data"]["requestId"] == rid.as_str()));
    rig.activity(&sid, "ready", TURN);

    // 4. An interrupt while a remote turn runs: Esc, completed at the
    //    turn's end, the chat request interrupted.
    let rid = rig.chat_submit(
        "conv-1",
        &sid,
        &generation,
        lease,
        "Write a 600-word essay about the history of terminals. Do not run any commands.",
    );
    rig.wait(TURN, "the essay prompt's message", |m| {
        m["type"] == "agentChat"
            && m["data"]["op"] == "message"
            && m["data"]["requestId"] == rid.as_str()
    });
    rig.activity(&sid, "working", Duration::from_secs(30));
    std::thread::sleep(Duration::from_millis(1500));
    let interrupt = uuid();
    let id = uuid();
    let mut binding = rig.binding(&sid, &generation);
    binding["lease_epoch"] = lease.into();
    rig.send(
        json!({"type": "session", "data": {"v": 1, "op": "submit", "id": id,
        "binding": binding, "request_id": interrupt, "kind": "interrupt", "payload": {}}}),
    );
    let (receipt, states) = rig.receipt_final(&interrupt, Duration::from_secs(60));
    let done = rig.chat_done(&rid, Duration::from_secs(60));
    report.push(format!(
        "4 interrupt: receipt {states:?} (final {}); chat request {} outcome {}",
        receipt["state"], done["op"], done["outcome"]
    ));
    rig.activity(&sid, "ready", TURN);
    assert_eq!(receipt["state"], "completed", "{receipt} {states:?}");
    assert_eq!(done["outcome"], "interrupted", "{done}");

    // 5. /new (npm's codex: the hooks come from the real binary under the
    //    node wrapper): chat follows the new session, local and remote.
    type_line(&mut fe, "/new");
    std::thread::sleep(Duration::from_secs(2));
    type_line(&mut fe, "Reply with exactly the word: fresh");
    let local = rig.wait(TURN, "the local prompt after /new", |m| {
        m["type"] == "agentChat"
            && m["data"]["op"] == "message"
            && m["data"]["origin"] == "local"
            && m.to_string().contains("fresh")
    })["data"]
        .clone();
    let turn5 = local["turnId"].as_str().unwrap().to_string();
    rig.activity(&sid, "ready", TURN);
    let lease = rig.acquire(&sid, &generation);
    let rid = rig.chat_submit(
        "conv-1",
        &sid,
        &generation,
        lease,
        "Reply with exactly the word: again",
    );
    let done = rig.chat_done(&rid, TURN);
    let turn6 = done["turnId"].as_str().unwrap_or_default().to_string();
    report.push(format!(
        "5 /new: local prompt in the new session turn {turn5} (reply {:?}); remote prompt {} outcome {} (reply {:?})",
        assistant_texts(&rig, &turn5).iter().map(|t| redact(t)).collect::<Vec<_>>(),
        done["op"],
        done["outcome"],
        assistant_texts(&rig, &turn6).iter().map(|t| redact(t)).collect::<Vec<_>>()
    ));
    eprintln!("CODEX CHAT REPORT:\n{}", report.join("\n"));
    assert_eq!(done["outcome"], "done", "{done}");
}

/// The next approval of `sid`; on a timeout the panic shows the screen.
fn approval_or_screen(rig: &mut Rig, fe: &Frontend, sid: &str, known: &[String]) -> Value {
    let deadline = Instant::now() + TURN;
    loop {
        let found = rig.seen.iter().find(|m| {
            m["data"]["op"] == "approval_request"
                && m["data"]["session_id"] == sid
                && !known.iter().any(|k| m["data"]["approval_id"] == k.as_str())
        });
        if let Some(found) = found {
            return found["data"].clone();
        }
        if Instant::now() > deadline {
            panic!(
                "no approval_request; the screen (redacted):\n{}",
                redact(&fe.text())
            );
        }
        rig.pump(Duration::from_millis(200));
    }
}

#[track_caller]
fn within_secs(what: &str, secs: u64, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(secs);
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Codex's hook review: `t` (trust all) on the /hooks page, or "Trust all
/// and continue" on the startup screen; then the page is closed.
fn trust_hooks(fe: &mut Frontend) {
    let text = fe.text();
    if text.contains("t trust all") {
        fe.send(b"t");
    } else {
        let line = text
            .lines()
            .find(|l| l.contains("Trust all"))
            .unwrap_or_else(|| panic!("no 'Trust all' choice:\n{}", redact(&text)));
        let number = line
            .trim_start_matches(|c: char| !c.is_ascii_digit())
            .chars()
            .next()
            .filter(char::is_ascii_digit)
            .unwrap_or_else(|| panic!("can't pick 'Trust all':\n{}", redact(&text)));
        fe.send(number.to_string().as_bytes());
        std::thread::sleep(Duration::from_millis(300));
        // The number selects; Enter confirms.
        fe.send(b"\r");
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while fe.text().contains("need review") && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(200));
    }
    eprintln!("after trusting (redacted):\n{}", redact(&fe.text()));
    if fe.text().contains("esc close") {
        fe.send(b"\x1b");
    }
}

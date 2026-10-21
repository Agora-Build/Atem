//! The session host in the broker, in process: a real `serve` (workers in
//! this process, fake agents) whose App holds a link to a fake Astation
//! WebSocket peer, driven with real session-v1, terminal-v1 and chat-v1
//! messages. The profile (pairing, verification) lives in a temp dir.
use super::Clock;
use crate::app::App;
use crate::runtime::broker::{InProcess, Launcher};
use crate::runtime::client::RuntimeClient;
use crate::runtime::protocol::{ClientMsg, LaunchEnv, RuntimeMsg, SessionSummary};
use crate::runtime::server::{Options, serve};
use crate::websocket_client::AstationClient;
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;

const ASTATION: &str = "astation-host-test";
const ACCOUNT: &str = "acct-1";
const DEVICE: &str = "device-1";
const TRUST_GEN: u64 = 3;
const WAIT: Duration = Duration::from_secs(20);

thread_local! {
    /// This thread's sandboxes, for `HookSweep`.
    static SANDBOXES: std::cell::RefCell<Vec<PathBuf>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Unix socket paths are limited to ~100 bytes; keep them short.
fn short_dir() -> tempfile::TempDir {
    let dir = tempfile::Builder::new()
        .prefix("atem-hb")
        .tempdir_in("/tmp")
        .unwrap();
    SANDBOXES.with(|s| s.borrow_mut().push(dir.path().to_path_buf()));
    dir
}

/// The approval hooks (`approval-hook.sh`) running from under `dir`: their
/// pids and command lines. Only ever this test's own sandbox.
fn hooks_under(dir: &Path) -> Vec<(i32, String)> {
    let out = std::process::Command::new("ps")
        .args(["-axo", "pid=,args="])
        .output()
        .unwrap();
    let dir = format!("{}/", dir.display());
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter(|l| l.contains(&dir) && l.contains("approval-hook.sh"))
        .filter_map(|l| {
            let l = l.trim_start();
            let (pid, args) = l.split_once(' ')?;
            Some((pid.parse().ok()?, args.to_string()))
        })
        .collect()
}

/// Regression check (dropped last): no approval hook started under this
/// thread's sandboxes outlives its test. Hooks still there after 5 s are
/// killed (only those) and the test fails, unless it already failed.
struct HookSweep;

impl Drop for HookSweep {
    fn drop(&mut self) {
        let dirs = SANDBOXES.with(|s| std::mem::take(&mut *s.borrow_mut()));
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut left = Vec::new();
        for dir in &dirs {
            let mut hooks = hooks_under(dir);
            while !hooks.is_empty() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(50));
                hooks = hooks_under(dir);
            }
            for (pid, _) in &hooks {
                unsafe {
                    libc::kill(*pid, libc::SIGKILL);
                }
            }
            left.extend(hooks.into_iter().map(|(_, args)| args));
        }
        if !left.is_empty() && !std::thread::panicking() {
            panic!("approval hooks outlived the test: {left:?}");
        }
    }
}

/// `body` on a current-thread runtime with a `LocalSet` (the App stays on one task).
fn local<F: std::future::Future>(body: F) -> F::Output {
    // Dropped after the runtime (and its workers).
    let _sweep = HookSweep;
    // Never the user's profile (src/test_profile.rs).
    let profile = tempfile::tempdir().unwrap();
    let _profile = crate::test_profile::use_dir(profile.path());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    tokio::task::LocalSet::new().block_on(&runtime, body)
}

fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// Echoes its input (the PTY echo is off; `cat` writes it back).
fn echo_agent(dir: &Path) -> PathBuf {
    script(
        dir,
        "echo-agent",
        "stty -echo\nprintf 'READY\\r\\n'\nexec cat",
    )
}

/// The fake agents are Python (`/usr/bin/python3 -I`, also run by
/// fake-claude.sh). Its first start on a machine can take far longer than
/// any wait in these tests: under Rosetta (the x86_64-apple-darwin tests on
/// an arm64 Mac, where children of this process run as x86_64 too) every
/// binary and library is translated on its first use, while the tests that
/// need it all start at once. It is started once, from this process (so as
/// the same architecture), with the modules the fake agents import, before
/// any test launches one: that one-time cost then counts against no wait
/// for what a test checks. Bounded: 300 s.
fn python_ready() {
    static READY: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    READY.get_or_init(|| {
        let mut child = std::process::Command::new("/usr/bin/python3")
            .args([
                "-I",
                "-c",
                "import json, os, select, signal, subprocess, sys, time, tty, uuid",
            ])
            .env("PATH", "/usr/bin:/bin")
            .stdin(std::process::Stdio::null())
            .spawn()
            .expect("the fake agents need /usr/bin/python3");
        let deadline = Instant::now() + Duration::from_secs(300);
        loop {
            match child.try_wait().unwrap() {
                Some(status) => {
                    assert!(status.success(), "python3 failed: {status}");
                    break;
                }
                None if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
                None => {
                    let _ = child.kill();
                    let _ = child.wait();
                    panic!("python3 did not start within 300 s");
                }
            }
        }
    });
}

fn fake_claude() -> PathBuf {
    python_ready();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/chat/fake-claude.sh");
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    if perms.mode() & 0o111 != 0o111 {
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
    }
    path
}

/// A profile paired with `ASTATION` in trust generation 3, verified as
/// `ACCOUNT`/`DEVICE` unless `verified` is false.
fn profile(dir: &Path, verified: bool) {
    std::fs::create_dir_all(dir).unwrap();
    crate::pairing::tests::write_bound(
        dir,
        ASTATION,
        TRUST_GEN,
        "binding-1",
        ("session-1", "token-1"),
    );
    if verified {
        let entry = json!({
            "device_id": DEVICE, "data_account": ACCOUNT, "sign_gen": 1,
            "astation_sign_pub": "", "astation_enc_pub": "", "recovery_sign_pub": "",
            "device_pub": "", "device_sign_pub": "", "unlock_auth_pub": "",
            "safety_code": "", "epoch_floor": 0, "account_state": null, "account_epoch": 0,
        });
        crate::paths::write_test_file(
            &crate::paths::CredPaths::in_dir(dir).trust,
            json!({"version":1,"astations":{ASTATION: entry}}).to_string(),
        );
    }
}

/// The Astation end of the link.
struct Peer {
    to_atem: mpsc::UnboundedSender<String>,
    from_atem: mpsc::UnboundedReceiver<Value>,
    seen: Vec<Value>,
    attachment: String,
    /// The viewer: frames applied up to `view_at`.
    view: vt100::Parser,
    view_at: usize,
}

impl Peer {
    fn send(&self, message: Value) {
        self.to_atem.send(message.to_string()).unwrap();
    }

    /// A session-v1 request; its id.
    fn request(&self, op: &str, fields: Value) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let mut data = json!({"v": 1, "op": op, "id": id});
        for (k, v) in fields.as_object().unwrap() {
            data[k] = v.clone();
        }
        self.send(json!({"type": "session", "data": data}));
        id
    }

    /// The first message from `from` on that `pick` accepts; its index.
    async fn wait_from(&mut self, from: usize, pick: impl Fn(&Value) -> bool) -> usize {
        tokio::time::timeout(WAIT, async {
            let mut at = from;
            loop {
                while at < self.seen.len() {
                    if pick(&self.seen[at]) {
                        return at;
                    }
                    at += 1;
                }
                let message = self.from_atem.recv().await.expect("the link closed");
                self.seen.push(message);
            }
        })
        .await
        .unwrap_or_else(|_| panic!("timed out; Atem sent: {:#?}", self.seen))
    }

    /// The next message (from now) `pick` accepts.
    async fn wait(&mut self, pick: impl Fn(&Value) -> bool) -> Value {
        let from = self.seen.len();
        let at = self.wait_from(from, pick).await;
        self.seen[at].clone()
    }

    /// The session-v1 reply to request `id`.
    async fn reply(&mut self, id: &str) -> Value {
        let at = self
            .wait_from(0, |v| v["type"] == "session" && v["data"]["re"] == id)
            .await;
        self.seen[at]["data"].clone()
    }

    /// Everything received within `time`.
    async fn drain(&mut self, time: Duration) {
        let deadline = tokio::time::Instant::now() + time;
        while let Ok(Some(message)) = tokio::time::timeout_at(deadline, self.from_atem.recv()).await
        {
            self.seen.push(message);
        }
    }

    async fn hello(&mut self) -> Value {
        let id = self.request("hello", json!({"revision": 8}));
        let welcome = self.reply(&id).await;
        assert_eq!(welcome["op"], "welcome", "{welcome}");
        self.attachment = welcome["attachment_gen"].as_str().unwrap().to_string();
        welcome
    }

    fn binding(&self, sid: &str, process_gen: &str, lease: Option<u64>) -> Value {
        let mut binding = json!({
            "target": {"account_id": ACCOUNT, "atem_device_id": DEVICE,
                       "host_trust_gen": TRUST_GEN, "session_id": sid, "process_gen": process_gen},
            "attachment_gen": self.attachment,
        });
        if let Some(epoch) = lease {
            binding["lease_epoch"] = epoch.into();
        }
        binding
    }

    async fn acquire(&mut self, sid: &str, process_gen: &str) -> u64 {
        let id = self.request(
            "acquire",
            json!({"binding": self.binding(sid, process_gen, None), "takeover": false}),
        );
        let lease = self.reply(&id).await;
        assert_eq!(lease["op"], "lease", "{lease}");
        lease["binding"]["lease_epoch"].as_u64().unwrap()
    }

    fn terminal(&self, op: &str, sid: &str, process_gen: &str, fields: Value, lease: Option<u64>) {
        let mut data = json!({"v": 1, "op": op, "terminal_id": sid, "generation": process_gen,
                              "binding": self.binding(sid, process_gen, lease)});
        for (k, v) in fields.as_object().unwrap() {
            data[k] = v.clone();
        }
        self.send(json!({"type": "terminal", "data": data}));
    }

    fn chat(&self, op: &str, conversation: &str, sid: &str, process_gen: &str, fields: Value) {
        let lease = fields.get("lease_epoch").and_then(Value::as_u64);
        let mut data = json!({"v": 1, "op": op, "conversationId": conversation, "agentId": sid,
                              "binding": self.binding(sid, process_gen, lease)});
        for (k, v) in fields.as_object().unwrap() {
            if k != "lease_epoch" {
                data[k] = v.clone();
            }
        }
        self.send(json!({"type": "agentChat", "data": data}));
    }
}

fn is_session(v: &Value, op: &str) -> bool {
    v["type"] == "session" && v["data"]["op"] == op
}

fn is_chat(v: &Value, op: &str) -> bool {
    v["type"] == "agentChat" && v["data"]["op"] == op
}

fn is_terminal(v: &Value, op: &str) -> bool {
    v["type"] == "terminal" && v["data"]["op"] == op
}

struct Runtime {
    dir: Rc<tempfile::TempDir>,
    socket: PathBuf,
    clock: Clock,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    server: tokio::task::JoinHandle<anyhow::Result<()>>,
    peer: Peer,
}

impl Runtime {
    /// A broker in a fresh dir, linked to a fake Astation; `verified`: the
    /// profile is verified with it.
    async fn start(verified: bool) -> Self {
        let dir = Rc::new(short_dir());
        profile(&dir.path().join("profile"), verified);
        Self::start_in(dir, "rt.sock").await
    }

    /// Another broker of the same state dir (a restart).
    async fn start_in(dir: Rc<tempfile::TempDir>, socket: &str) -> Self {
        Self::start_with(dir, socket, true).await
    }

    /// `profile_at_start`: the broker reads the profile's identity at start
    /// (else it starts unpaired and takes it from the first verified link).
    async fn start_with(dir: Rc<tempfile::TempDir>, socket: &str, profile_at_start: bool) -> Self {
        let root = dir.path();
        let profile_dir = root.join("profile");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (to_atem, mut outgoing) = mpsc::unbounded_channel::<String>();
        let (incoming, from_atem) = mpsc::unbounded_channel::<Value>();
        tokio::task::spawn_local(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            loop {
                tokio::select! {
                    message = outgoing.recv() => {
                        let Some(text) = message else { break };
                        if socket.send(WsMessage::Text(text)).await.is_err() { break; }
                    }
                    received = socket.next() => {
                        let Some(Ok(received)) = received else { break };
                        if let WsMessage::Text(text) = received
                            && let Ok(value) = serde_json::from_str::<Value>(&text)
                        {
                            let _ = incoming.send(value);
                        }
                    }
                }
            }
        });
        let mut app = App::new();
        // Never the user's profile.
        app.last_session_refresh = Some(Instant::now());
        app.astation_client = AstationClient::new_with_test_state("atem-host-test", &profile_dir);
        app.astation_client
            .connect_raw(&format!("ws://{address}"))
            .await
            .unwrap();
        // The connect-time authentication is covered by websocket_client tests.
        app.astation_client.pin_astation_for_test(ASTATION);
        app.astation_connected = true;
        app.astation_link_gen = 1;
        // Never reconnect to a real Astation from a test.
        app.astation_reconnect = false;
        let socket = root.join(socket);
        let _ = std::fs::remove_file(&socket);
        let unix = tokio::net::UnixListener::bind(&socket).unwrap();
        let clock = Clock::default();
        let options = Options {
            idle: Duration::from_secs(600),
            uid: unsafe { libc::getuid() },
            launcher: Launcher::InProcess(InProcess {
                state: root.join("state"),
                socket_dir: root.join("ws"),
                chat_root: root.join("run"),
            }),
            profile: profile_at_start.then(|| crate::profile::Sources::in_dir(&profile_dir)),
            clock: clock.clone(),
            ops: crate::runtime::ops::OpEnv::unavailable(),
        };
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::task::spawn_local(serve(app, unix, options, async {
            let _ = stopped.await;
        }));
        Self {
            dir,
            socket,
            clock,
            stop: Some(stop),
            server,
            peer: Peer {
                to_atem,
                from_atem,
                seen: Vec::new(),
                attachment: String::new(),
                view: vt100::Parser::new(24, 80, 0),
                view_at: 0,
            },
        }
    }

    async fn client(&self) -> RuntimeClient {
        RuntimeClient::connect_at(&self.socket).await.unwrap()
    }

    async fn shutdown(mut self) -> Rc<tempfile::TempDir> {
        let _ = self.stop.take().unwrap().send(());
        tokio::time::timeout(Duration::from_secs(10), &mut self.server)
            .await
            .expect("the server stops")
            .unwrap()
            .unwrap();
        self.dir
    }

    /// Launches `provider` running `binary` in `cwd` (default: the dir).
    async fn launch(
        &self,
        client: &mut RuntimeClient,
        provider: &str,
        binary: &Path,
        cwd: Option<&Path>,
    ) -> SessionSummary {
        let var = if provider == "claude" {
            "CLAUDE_CLI_BIN"
        } else {
            "CODEX_CLI_BIN"
        };
        client
            .send(&ClientMsg::Launch {
                provider: provider.into(),
                args: vec![],
                cwd: cwd.unwrap_or(self.dir.path()).to_path_buf(),
                env: LaunchEnv(vec![
                    ("PATH".into(), "/usr/bin:/bin".into()),
                    (var.into(), binary.display().to_string()),
                ]),
                rows: 24,
                cols: 80,
            })
            .await
            .unwrap();
        expect(client, |m| match m {
            RuntimeMsg::Launched { session } => Some(session),
            RuntimeMsg::Error { text, .. } => panic!("launch failed: {text}"),
            _ => None,
        })
        .await
    }
}

async fn expect<T>(client: &mut RuntimeClient, mut pick: impl FnMut(RuntimeMsg) -> Option<T>) -> T {
    tokio::time::timeout(WAIT, async {
        loop {
            let message = client.recv().await.unwrap().expect("the runtime closed");
            if let Some(value) = pick(message) {
                return value;
            }
        }
    })
    .await
    .expect("timed out waiting for a runtime message")
}

/// The session's descriptor from a fresh `list`.
async fn listed(peer: &mut Peer, sid: &str) -> Value {
    let id = peer.request("list", json!({}));
    let sessions = peer.reply(&id).await;
    assert_eq!(sessions["op"], "sessions", "{sessions}");
    sessions["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["session_id"] == sid)
        .cloned()
        .unwrap_or_else(|| panic!("{sid} not listed: {sessions}"))
}

/// Applies frames (acknowledging each) until the viewer's screen shows `text`.
async fn screen_until(peer: &mut Peer, sid: &str, process_gen: &str, text: &str) {
    tokio::time::timeout(WAIT, async {
        loop {
            if peer.view.screen().contents().contains(text) {
                return;
            }
            let at = peer
                .wait_from(peer.view_at, |v| {
                    is_terminal(v, "frame") && v["data"]["terminal_id"] == sid
                })
                .await;
            let frame = peer.seen[at]["data"].clone();
            peer.view_at = at + 1;
            if frame["reset"] == true {
                peer.view = vt100::Parser::new(
                    frame["rows"].as_u64().unwrap() as u16,
                    frame["cols"].as_u64().unwrap() as u16,
                    0,
                );
            }
            let bytes = STANDARD.decode(frame["bytes"].as_str().unwrap()).unwrap();
            peer.view.process(&bytes);
            let offset = frame["offset"].as_u64().unwrap() + bytes.len() as u64;
            peer.terminal(
                "ack",
                sid,
                process_gen,
                json!({"stream_id": frame["stream_id"], "offset": offset}),
                None,
            );
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{text:?} never appeared"));
}

#[test]
fn welcome_list_leases_terminal_input_and_local_input() {
    local(async {
        let mut rt = Runtime::start(true).await;
        let mut client = rt.client().await;
        let agent = echo_agent(rt.dir.path());
        let session = rt.launch(&mut client, "codex", &agent, None).await;
        let (sid, pg) = (session.id.clone(), session.generation.clone());
        let peer = &mut rt.peer;

        let welcome = peer.hello().await;
        assert_eq!(welcome["account_id"], ACCOUNT);
        assert_eq!(welcome["atem_device_id"], DEVICE);
        assert_eq!(welcome["host_trust_gen"], TRUST_GEN);
        assert_eq!(welcome["client_kind"], "native");
        assert_eq!(welcome["permissions"], json!(["view", "control"]));

        let descriptor = listed(peer, &sid).await;
        assert_eq!(descriptor["process_gen"], pg.as_str());
        assert_eq!(descriptor["provider"], "codex");
        assert_eq!(descriptor["state"], "running");
        assert_eq!(descriptor["controller"], Value::Null);
        assert_eq!(
            descriptor["cwd_label"],
            rt.dir.path().file_name().unwrap().to_str().unwrap()
        );

        // A duplicate of a session message (same id) is handled once.
        let id = uuid::Uuid::new_v4().to_string();
        let list = json!({"type":"session","data":{"v":1,"op":"list","id":id}});
        peer.send(list.clone());
        peer.send(list);
        peer.reply(&id).await;
        peer.drain(Duration::from_millis(500)).await;
        let replies = peer
            .seen
            .iter()
            .filter(|v| v["data"]["re"] == id.as_str())
            .count();
        assert_eq!(replies, 1);
        // The same id with other content is another message: it is handled.
        peer.send(json!({"type":"session","data":{"v":1,"op":"list","id":id,"extra":1}}));
        peer.drain(Duration::from_millis(500)).await;
        let replies = peer
            .seen
            .iter()
            .filter(|v| v["data"]["re"] == id.as_str())
            .count();
        assert_eq!(replies, 2);

        // View, then control: input goes through the worker.
        peer.terminal("subscribe", &sid, &pg, json!({}), None);
        let attached = peer.wait(|v| is_terminal(v, "attached")).await;
        let stream = attached["data"]["stream_id"].as_str().unwrap().to_string();
        screen_until(peer, &sid, &pg, "READY").await;
        // Without a lease input is refused.
        peer.terminal(
            "input",
            &sid,
            &pg,
            json!({"stream_id": stream, "sequence": 0, "bytes": STANDARD.encode("NOLEASE\r")}),
            Some(1),
        );
        let refused = peer.wait(|v| is_terminal(v, "error")).await;
        assert_eq!(refused["data"]["code"], "stale_lease");
        let epoch = peer.acquire(&sid, &pg).await;
        peer.terminal(
            "input",
            &sid,
            &pg,
            json!({"stream_id": stream, "sequence": 1, "bytes": STANDARD.encode("REMOTE-1\r")}),
            Some(epoch),
        );
        let written = peer.wait(|v| is_terminal(v, "written")).await;
        assert_eq!(written["data"]["sequence"], 1);
        assert_eq!(written["data"]["error"], Value::Null);
        screen_until(peer, &sid, &pg, "REMOTE-1").await;
        assert_eq!(listed(peer, &sid).await["controller"]["lease_epoch"], epoch);

        // Renewal, then expiry at 15 s without one.
        let id = peer.request(
            "renew",
            json!({"binding": peer.binding(&sid, &pg, Some(epoch))}),
        );
        assert_eq!(peer.reply(&id).await["op"], "lease");
        rt.clock.skip(15_001);
        let peer = &mut rt.peer;
        let changed = peer.wait(|v| is_session(v, "lease_changed")).await;
        assert_eq!(changed["data"]["reason"], "expired");
        let id = peer.request(
            "renew",
            json!({"binding": peer.binding(&sid, &pg, Some(epoch))}),
        );
        let error = peer.reply(&id).await;
        assert_eq!(error["code"], "stale_lease");
        peer.terminal(
            "input",
            &sid,
            &pg,
            json!({"stream_id": stream, "sequence": 2, "bytes": STANDARD.encode("EXPIRED\r")}),
            Some(epoch),
        );
        let refused = peer.wait(|v| is_terminal(v, "error")).await;
        assert_eq!(refused["data"]["code"], "stale_lease");

        // Local input wins: it revokes the lease before it is written.
        let epoch = peer.acquire(&sid, &pg).await;
        client
            .send(&ClientMsg::Attach {
                session_id: sid.clone(),
                rows: 24,
                cols: 80,
            })
            .await
            .unwrap();
        expect(&mut client, |m| {
            matches!(m, RuntimeMsg::Attached { .. }).then_some(())
        })
        .await;
        client
            .send(&ClientMsg::input(&sid, b"LOCAL-1\r"))
            .await
            .unwrap();
        let peer = &mut rt.peer;
        let changed = peer.wait(|v| is_session(v, "lease_changed")).await;
        assert_eq!(changed["data"]["reason"], "local_input");
        assert_eq!(changed["data"]["controller"], Value::Null);
        screen_until(peer, &sid, &pg, "LOCAL-1").await;
        peer.terminal(
            "input",
            &sid,
            &pg,
            json!({"stream_id": stream, "sequence": 3, "bytes": STANDARD.encode("STALE\r")}),
            Some(epoch),
        );
        let refused = peer.wait(|v| is_terminal(v, "error")).await;
        assert_eq!(refused["data"]["code"], "stale_lease");
        assert!(
            !peer
                .seen
                .iter()
                .any(|v| v.to_string().contains(&STANDARD.encode("EXPIRED"))),
        );
        rt.shutdown().await;
    });
}

#[test]
fn queued_remote_bytes_are_dropped_at_the_worker_when_local_input_takes_over() {
    local(async {
        let mut rt = Runtime::start(true).await;
        let mut client = rt.client().await;
        // Raw, no echo: reads nothing for two seconds, so writes queue.
        let agent = script(
            rt.dir.path(),
            "sleepy",
            "stty raw -echo\nprintf 'SLEEPING\\r\\n'\nsleep 2\nexec cat",
        );
        let session = rt.launch(&mut client, "codex", &agent, None).await;
        let (sid, pg) = (session.id.clone(), session.generation.clone());
        let peer = &mut rt.peer;
        peer.hello().await;
        peer.terminal("subscribe", &sid, &pg, json!({}), None);
        let attached = peer.wait(|v| is_terminal(v, "attached")).await;
        let stream = attached["data"]["stream_id"].as_str().unwrap().to_string();
        screen_until(peer, &sid, &pg, "SLEEPING").await;
        let epoch = peer.acquire(&sid, &pg).await;
        let chunk = STANDARD.encode([b'r'; 8 * 1024]);
        for sequence in 0..24 {
            peer.terminal(
                "input",
                &sid,
                &pg,
                json!({"stream_id": stream, "sequence": sequence, "bytes": chunk}),
                Some(epoch),
            );
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
        client
            .send(&ClientMsg::Attach {
                session_id: sid.clone(),
                rows: 24,
                cols: 80,
            })
            .await
            .unwrap();
        client.send(&ClientMsg::input(&sid, b"L")).await.unwrap();
        let peer = &mut rt.peer;
        let changed = peer.wait(|v| is_session(v, "lease_changed")).await;
        assert_eq!(changed["data"]["reason"], "local_input");
        // Every remote chunk is answered; those still queued were dropped.
        let mut answered = 0;
        let mut dropped = 0;
        let mut at = 0;
        while answered < 24 {
            at = peer.wait_from(at, |v| is_terminal(v, "written")).await;
            let error = peer.seen[at]["data"]["error"].clone();
            if error
                .as_str()
                .is_some_and(|e| e.contains("control changed"))
            {
                dropped += 1;
            }
            answered += 1;
            at += 1;
        }
        assert!(dropped > 0, "nothing queued was dropped: {:#?}", peer.seen);
        rt.shutdown().await;
    });
}

/// Opens `conversation` once chat is available; returns `opened`.
async fn open_chat(peer: &mut Peer, conversation: &str, sid: &str, pg: &str) -> Value {
    tokio::time::timeout(WAIT, async {
        loop {
            let from = peer.seen.len();
            peer.chat("open", conversation, sid, pg, json!({}));
            let at = peer
                .wait_from(from, |v| {
                    v["type"] == "agentChat"
                        && v["data"]["conversationId"] == conversation
                        && (v["data"]["op"] == "opened" || v["data"]["op"] == "error")
                })
                .await;
            if peer.seen[at]["data"]["op"] == "opened"
                && peer.seen[at]["data"]["status"]["state"] == "ready"
            {
                return peer.seen[at].clone();
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await
    .expect("chat never became available")
}

/// Submits `text` as `request_id` and waits for its `complete`.
async fn submit_until_complete(
    peer: &mut Peer,
    conversation: &str,
    sid: &str,
    pg: &str,
    lease: u64,
    request_id: &str,
    text: &str,
) -> Vec<Value> {
    let from = peer.seen.len();
    peer.chat(
        "submit",
        conversation,
        sid,
        pg,
        json!({"generation": pg, "requestId": request_id, "text": text, "lease_epoch": lease}),
    );
    let done = peer
        .wait_from(from, |v| {
            (is_chat(v, "complete") || is_chat(v, "error")) && v["data"]["requestId"] == request_id
        })
        .await;
    peer.seen[from..=done].to_vec()
}

#[test]
fn chat_submit_completes_through_its_receipt_and_survives_a_broker_restart() {
    local(async {
        let mut rt = Runtime::start(true).await;
        let mut client = rt.client().await;
        let session = rt.launch(&mut client, "claude", &fake_claude(), None).await;
        let (sid, pg) = (session.id.clone(), session.generation.clone());
        let peer = &mut rt.peer;
        peer.hello().await;
        let descriptor = listed(peer, &sid).await;
        assert_eq!(
            descriptor["capabilities"],
            json!(["terminal-v1", "chat-v1"])
        );
        open_chat(peer, "conv-1", &sid, &pg).await;

        // Without a lease the submit is refused, and nothing is typed.
        let request_id = uuid::Uuid::new_v4().to_string();
        let refused =
            submit_until_complete(peer, "conv-1", &sid, &pg, 1, &request_id, "no lease").await;
        let refused = refused.last().unwrap();
        assert_eq!(refused["data"]["code"], "stale_lease", "{refused}");

        let lease = peer.acquire(&sid, &pg).await;
        let request_id = uuid::Uuid::new_v4().to_string();
        let events = submit_until_complete(
            peer,
            "conv-1",
            &sid,
            &pg,
            lease,
            &request_id,
            "run the tests",
        )
        .await;
        let accepted = events
            .iter()
            .position(|v| is_chat(v, "accepted") && v["data"]["requestId"] == request_id.as_str())
            .expect("accepted");
        let reply = events
            .iter()
            .position(|v| v["type"] == "agentChat" && v.to_string().contains("reply 1"))
            .expect("the agent's reply");
        let complete = events.last().unwrap();
        assert!(is_chat(complete, "complete"), "{complete}");
        assert_eq!(complete["data"]["outcome"], "done");
        assert!(accepted < reply);
        // The user's message carries the request id.
        assert!(events.iter().any(|v| is_chat(v, "message")
            && v["data"]["role"] == "user"
            && v["data"]["requestId"] == request_id.as_str()));

        // A duplicate is answered from its receipt, never typed again.
        let again = submit_until_complete(
            peer,
            "conv-1",
            &sid,
            &pg,
            lease,
            &request_id,
            "run the tests",
        )
        .await;
        assert!(is_chat(again.last().unwrap(), "complete"));
        assert!(!again.iter().any(|v| v.to_string().contains("reply 2")));
        // Another text under the same id is a reused id.
        let reused =
            submit_until_complete(peer, "conv-1", &sid, &pg, lease, &request_id, "other").await;
        assert_eq!(reused.last().unwrap()["data"]["code"], "request_id_reused");
        let id = peer.request(
            "receipt_query",
            json!({"binding": peer.binding(&sid, &pg, None), "request_ids": [request_id]}),
        );
        let receipts = peer.reply(&id).await;
        assert_eq!(receipts["receipts"][0]["state"], "completed", "{receipts}");
        assert_eq!(receipts["receipts"][0]["detail"], "done", "{receipts}");
        // r8 §D: its turn, its user message and its replies, from history.
        let user_message = events
            .iter()
            .find(|v| {
                is_chat(v, "message")
                    && v["data"]["role"] == "user"
                    && v["data"]["requestId"] == request_id.as_str()
            })
            .unwrap()["data"]["messageId"]
            .clone();
        let turn = complete["data"]["turnId"].clone();
        let mut replies: Vec<Value> = Vec::new();
        for v in &events {
            if is_chat(v, "message")
                && v["data"]["role"] == "assistant"
                && v["data"]["turnId"] == turn
                && !replies.contains(&v["data"]["messageId"])
            {
                replies.push(v["data"]["messageId"].clone());
            }
        }
        assert!(!replies.is_empty());
        let want = json!({"turn_id": turn, "user_message_id": user_message, "outcome": "done",
                          "reply_message_ids": replies, "more": false, "replies": "complete"});
        assert_eq!(receipts["receipts"][0]["result"], want, "{receipts}");
        // The journal keeps no prompt text once the request left `accepted`.
        let journal = rt.dir.path().join("state").join("journal");
        let mut files = 0;
        let mut stack = vec![journal];
        while let Some(path) = stack.pop() {
            if path.is_dir() {
                stack.extend(std::fs::read_dir(&path).unwrap().map(|e| e.unwrap().path()));
            } else {
                files += 1;
                let bytes = std::fs::read(&path).unwrap();
                let text = String::from_utf8_lossy(&bytes);
                assert!(!text.contains("run the tests"), "{}", path.display());
                assert!(!text.contains("no lease"), "{}", path.display());
            }
        }
        assert!(files > 0, "no journal files");
        let peer = &mut rt.peer;
        let old_attachment = peer.attachment.clone();

        // The broker restarts; its worker survives and is adopted.
        drop(client);
        let dir = rt.shutdown().await;
        let mut rt = Runtime::start_in(dir, "rt2.sock").await;
        let peer = &mut rt.peer;
        peer.hello().await;
        assert_ne!(peer.attachment, old_attachment);
        let descriptor = listed(peer, &sid).await;
        assert_eq!(descriptor["process_gen"], pg.as_str());
        assert_eq!(descriptor["state"], "running");
        // The receipt is still there, under the same target.
        let id = peer.request(
            "receipt_query",
            json!({"binding": peer.binding(&sid, &pg, None), "request_ids": [request_id]}),
        );
        let receipts = peer.reply(&id).await;
        assert_eq!(receipts["receipts"][0]["state"], "completed", "{receipts}");
        // The same result: ids from the journal, replies from the adopted
        // worker's history (once its snapshot is in).
        let mut tries = 0;
        let mut receipts = receipts;
        while receipts["receipts"][0]["result"] != want && tries < 50 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            let id = peer.request(
                "receipt_query",
                json!({"binding": peer.binding(&sid, &pg, None), "request_ids": [request_id]}),
            );
            receipts = peer.reply(&id).await;
            tries += 1;
        }
        assert_eq!(receipts["receipts"][0]["result"], want, "{receipts}");
        // The old attachment is gone: requests naming it are refused.
        let mut stale = peer.binding(&sid, &pg, None);
        stale["attachment_gen"] = Value::String(old_attachment);
        let id = peer.request("acquire", json!({"binding": stale, "takeover": false}));
        assert_eq!(peer.reply(&id).await["code"], "stale_target");
        // A duplicate session-v1 submit returns it too.
        let lease = peer.acquire(&sid, &pg).await;
        let mut b = peer.binding(&sid, &pg, None);
        b["lease_epoch"] = lease.into();
        let id = peer.request(
            "submit",
            json!({"binding": b, "request_id": request_id, "kind": "prompt",
                   "payload": {"text": "run the tests"}}),
        );
        assert_eq!(peer.reply(&id).await["result"], want);
        // The duplicate submit returns the recorded receipt; nothing is typed.
        let again = submit_until_complete(
            peer,
            "conv-2",
            &sid,
            &pg,
            lease,
            &request_id,
            "run the tests",
        )
        .await;
        assert!(is_chat(again.last().unwrap(), "complete"));
        assert!(!again.iter().any(|v| v.to_string().contains("reply 2")));
        // Chat goes on in the adopted session: its history, and a new prompt.
        let from = peer.seen.len();
        open_chat(peer, "conv-3", &sid, &pg).await;
        peer.drain(Duration::from_millis(300)).await;
        assert!(
            peer.seen[from..].iter().any(|v| is_chat(v, "message")
                && v["data"]["conversationId"] == "conv-3"
                && v["data"]["history"] == true
                && v.to_string().contains("run the tests")),
            "no history after the restart"
        );
        let request_id = uuid::Uuid::new_v4().to_string();
        let events = submit_until_complete(
            peer,
            "conv-3",
            &sid,
            &pg,
            lease,
            &request_id,
            "after restart",
        )
        .await;
        let complete = events.last().unwrap();
        assert!(is_chat(complete, "complete"), "{complete}");
        assert!(events.iter().any(|v| v.to_string().contains("reply 2")));
        rt.shutdown().await;
    });
}

/// The sequences `conversation` got, in arrival order (`opened` is 0).
fn sequences(seen: &[Value], conversation: &str) -> Vec<u64> {
    seen.iter()
        .filter(|v| v["type"] == "agentChat" && v["data"]["conversationId"] == conversation)
        .filter_map(|v| v["data"]["sequence"].as_u64())
        .collect()
}

/// The page `page_id` (`None`: an open's) of `conversation` from `from`:
/// its messages and its `history_end`.
async fn take_page(
    peer: &mut Peer,
    from: usize,
    conversation: &str,
    page_id: Option<&str>,
) -> (Vec<Value>, Value) {
    let (c, p) = (conversation.to_string(), page_id.map(str::to_string));
    let at = peer
        .wait_from(from, move |v| {
            is_chat(v, "history_end")
                && v["data"]["conversationId"] == c.as_str()
                && v["data"].get("page_id").and_then(Value::as_str) == p.as_deref()
        })
        .await;
    let messages = peer.seen[from..at]
        .iter()
        .filter(|v| {
            is_chat(v, "message")
                && v["data"]["conversationId"] == conversation
                && v["data"]["history"] == true
                && v["data"].get("page_id").and_then(Value::as_str) == page_id
        })
        .map(|v| v["data"].clone())
        .collect();
    (messages, peer.seen[at]["data"].clone())
}

/// r8 §B over the runtime: an open ends with `history_end`; a lookup by
/// `request_id` pages that turn from its user message; `before` pages the
/// older history; an invalid selector and a stale `next` are errors in the
/// stream with their `page_id`; nothing resets (sequences consecutive).
#[test]
fn history_pages_and_lookups_come_in_the_conversation_stream() {
    local(async {
        let mut rt = Runtime::start(true).await;
        let mut client = rt.client().await;
        let session = rt.launch(&mut client, "claude", &fake_claude(), None).await;
        let (sid, pg) = (session.id.clone(), session.generation.clone());
        let peer = &mut rt.peer;
        peer.hello().await;
        listed(peer, &sid).await;
        open_chat(peer, "conv-1", &sid, &pg).await;
        let lease = peer.acquire(&sid, &pg).await;
        let mut rids = Vec::new();
        for text in ["first", "second"] {
            let rid = uuid::Uuid::new_v4().to_string();
            submit_until_complete(peer, "conv-1", &sid, &pg, lease, &rid, text).await;
            rids.push(rid);
        }
        peer.drain(Duration::from_millis(300)).await;

        let from = peer.seen.len();
        open_chat_any(peer, "conv-2", &sid, &pg).await;
        let (newest, end) = take_page(peer, from, "conv-2", None).await;
        let page = &end["page"];
        assert_eq!(page["selector"], "newest", "{end}");
        assert_eq!(page["end"], true);
        assert_eq!(page["coverage"], "complete");
        assert_eq!(page["truncated"], false);
        assert_eq!(page["count"], newest.len());
        assert!(newest.len() >= 4, "two turns: {newest:#?}");
        let user_of = |rid: &str| {
            newest
                .iter()
                .find(|m| m["role"] == "user" && m["requestId"] == rid)
                .unwrap_or_else(|| panic!("no user message for {rid}: {newest:#?}"))
                .clone()
        };
        let (first, second) = (user_of(&rids[0]), user_of(&rids[1]));

        // The first prompt's turn, from its user message.
        let from = peer.seen.len();
        peer.chat(
            "history",
            "conv-2",
            &sid,
            &pg,
            json!({"generation": pg, "page_id": "p1", "request_id": rids[0]}),
        );
        let (turn, end) = take_page(peer, from, "conv-2", Some("p1")).await;
        assert_eq!(end["page"]["selector"], "request_id");
        assert_eq!(end["page"]["coverage"], "complete");
        assert_eq!(end["page"]["end"], true);
        assert_eq!(turn[0]["messageId"], first["messageId"]);
        assert!(turn.len() >= 2 && turn.iter().all(|m| m["turnId"] == first["turnId"]));

        // Older than the second prompt: the first turn's messages.
        let from = peer.seen.len();
        peer.chat(
            "history",
            "conv-2",
            &sid,
            &pg,
            json!({"generation": pg, "page_id": "p2", "before": second["messageId"]}),
        );
        let (older, end) = take_page(peer, from, "conv-2", Some("p2")).await;
        assert_eq!(end["page"]["selector"], "before");
        assert_eq!(end["page"]["end"], true);
        let position = |id: &Value| newest.iter().position(|m| &m["messageId"] == id).unwrap();
        assert!(!older.is_empty());
        assert!(
            older
                .iter()
                .all(|m| position(&m["messageId"]) < position(&second["messageId"]))
        );

        // Errors in the stream, with their page ids.
        for (page_id, fields, code) in [
            (
                "p3",
                json!({"before": first["messageId"], "turn_id": "t"}),
                "invalid_request",
            ),
            ("p4", json!({"next": "AAAA"}), "stale_target"),
        ] {
            let from = peer.seen.len();
            let mut fields = fields;
            fields["generation"] = json!(pg);
            fields["page_id"] = json!(page_id);
            peer.chat("history", "conv-2", &sid, &pg, fields);
            let at = peer
                .wait_from(from, |v| {
                    is_chat(v, "error") && v["data"]["conversationId"] == "conv-2"
                })
                .await;
            let error = &peer.seen[at]["data"];
            assert_eq!(error["code"], code, "{error}");
            assert_eq!(error["page_id"], page_id);
            assert!(error["sequence"].is_u64());
        }
        peer.drain(Duration::from_millis(300)).await;
        let all = sequences(&peer.seen, "conv-2");
        assert_eq!(all, (0..all.len() as u64).collect::<Vec<_>>(), "one stream");
        rt.shutdown().await;
    });
}

#[test]
fn open_with_before_is_refused_and_the_conversation_goes_on() {
    local(async {
        let mut rt = Runtime::start(true).await;
        let mut client = rt.client().await;
        let session = rt.launch(&mut client, "claude", &fake_claude(), None).await;
        let (sid, pg) = (session.id.clone(), session.generation.clone());
        let peer = &mut rt.peer;
        peer.hello().await;
        listed(peer, &sid).await;
        open_chat(peer, "conv-1", &sid, &pg).await;
        let lease = peer.acquire(&sid, &pg).await;
        for text in ["first", "second"] {
            let rid = uuid::Uuid::new_v4().to_string();
            let events = submit_until_complete(peer, "conv-1", &sid, &pg, lease, &rid, text).await;
            assert!(is_chat(events.last().unwrap(), "complete"));
        }
        peer.drain(Duration::from_millis(300)).await;
        let live = sequences(&peer.seen, "conv-1");

        // r8 §A: `open.before`/`open.generation` (the r7.2 paging form) are
        // removed: refused (unsupported, unsequenced), never a page, the
        // open conversation not reset and no new one opened.
        for (conversation, extra) in [
            ("conv-1", json!({"before": "u-2"})),
            ("conv-1", json!({"before": "u-1", "generation": pg})),
            ("conv-2", json!({"before": "u-2"})),
        ] {
            let from = peer.seen.len();
            peer.chat("open", conversation, &sid, &pg, extra.clone());
            let at = peer
                .wait_from(from, |v| {
                    v["type"] == "agentChat" && v["data"]["conversationId"] == conversation
                })
                .await;
            let error = peer.seen[at]["data"].clone();
            assert_eq!(error["op"], "error", "{extra}: {error}");
            assert_eq!(error["code"], "unsupported_version");
            assert!(error.get("sequence").is_none(), "{error}");
        }
        peer.drain(Duration::from_millis(300)).await;
        assert!(
            !peer.seen.iter().any(|v| v["type"] == "agentChat"
                && v["data"]["conversationId"] == "conv-2"
                && v["data"]["op"] != "error"),
            "conv-2 never opened"
        );
        // No page but the first open's.
        let pages = peer
            .seen
            .iter()
            .filter(|v| is_chat(v, "history_end"))
            .count();
        assert_eq!(pages, 1);

        // Live events go on at the next sequences.
        let rid = uuid::Uuid::new_v4().to_string();
        submit_until_complete(peer, "conv-1", &sid, &pg, lease, &rid, "third").await;
        peer.drain(Duration::from_millis(300)).await;
        let all = sequences(&peer.seen, "conv-1");
        assert!(all.len() > live.len());
        assert_eq!(
            all,
            (0..all.len() as u64).collect::<Vec<_>>(),
            "never reset or reused"
        );
        rt.shutdown().await;
    });
}

#[test]
fn a_link_that_is_not_a_verified_pairing_gets_no_attachment() {
    local(async {
        let mut rt = Runtime::start(false).await;
        let peer = &mut rt.peer;
        let id = peer.request("hello", json!({"revision": 8}));
        let error = peer.reply(&id).await;
        assert_eq!(error["op"], "error");
        assert_eq!(error["code"], "unauthorized");
        rt.shutdown().await;
    });
}

#[test]
fn mark_tasks_wait_for_a_remote_lease_holder_and_are_written_without_one() {
    local(async {
        let mut rt = Runtime::start(true).await;
        let mut client = rt.client().await;
        let project = rt.dir.path().join("project");
        std::fs::create_dir_all(project.join(".chisel/tasks")).unwrap();
        std::fs::write(
            project.join(".chisel/tasks/t1.json"),
            json!({"title": "Project B"}).to_string(),
        )
        .unwrap();
        // Claude as an agent that records what it is typed.
        let agent = script(
            rt.dir.path(),
            "recorder",
            "stty -echo\nprintf 'READY\\r\\n'\nsleep 1\nexec cat >> typed.txt",
        );
        let typed = project.join("typed.txt");
        let session = rt
            .launch(&mut client, "claude", &agent, Some(&project))
            .await;
        let (sid, pg) = (session.id.clone(), session.generation.clone());
        let peer = &mut rt.peer;
        peer.hello().await;
        peer.terminal("subscribe", &sid, &pg, json!({}), None);
        peer.wait(|v| is_terminal(v, "attached")).await;
        screen_until(peer, &sid, &pg, "READY").await;

        // A remote lease holder exists: the task waits.
        let epoch = peer.acquire(&sid, &pg).await;
        // Let the broker mirror the lease to the App.
        tokio::time::sleep(Duration::from_millis(200)).await;
        peer.send(json!({"type":"markTaskAssignment","data":{"taskId":"t1","receivedAtMs":0}}));
        peer.drain(Duration::from_millis(800)).await;
        let text = std::fs::read_to_string(&typed).unwrap_or_default();
        assert!(!text.contains("Page title"), "{text:?}");

        // Released: the task is typed, as local-origin input.
        let id = peer.request(
            "release",
            json!({"binding": peer.binding(&sid, &pg, Some(epoch))}),
        );
        assert_eq!(peer.reply(&id).await["op"], "lease_released");
        // A local reclaim right after (no remote lease, no remote bytes)
        // never drops the queued prompt.
        client
            .send(&ClientMsg::Attach {
                session_id: sid.clone(),
                rows: 24,
                cols: 80,
            })
            .await
            .unwrap();
        for _ in 0..5 {
            client
                .send(&ClientMsg::Reclaim {
                    session_id: sid.clone(),
                })
                .await
                .unwrap();
        }
        tokio::time::timeout(WAIT, async {
            loop {
                let text = std::fs::read_to_string(&typed).unwrap_or_default();
                if text.contains("Page title: Project B") {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the mark task was never typed");
        // No lease was revoked or granted by it.
        assert!(
            !peer
                .seen
                .iter()
                .any(|v| is_session(v, "lease_changed") && v["data"]["reason"] == "local_input")
        );
        rt.shutdown().await;
    });
}

#[test]
fn re_authentication_fences_the_attachment_and_its_lease_expires() {
    local(async {
        let mut rt = Runtime::start(true).await;
        let mut client = rt.client().await;
        let agent = echo_agent(rt.dir.path());
        let session = rt.launch(&mut client, "codex", &agent, None).await;
        let (sid, pg) = (session.id.clone(), session.generation.clone());
        let peer = &mut rt.peer;
        let hello_id = uuid::Uuid::new_v4().to_string();
        let hello =
            json!({"type":"session","data":{"v":1,"op":"hello","id":hello_id,"revision":8}});
        peer.send(hello.clone());
        let welcome = peer.reply(&hello_id).await;
        peer.attachment = welcome["attachment_gen"].as_str().unwrap().to_string();
        let epoch = peer.acquire(&sid, &pg).await;
        let old = peer.binding(&sid, &pg, Some(epoch));

        // Astation challenges the open socket again, then accepts the proof.
        let status = |status: &str, data: Value| json!({"type": "statusUpdate", "data": {"status": status, "data": data}});
        peer.send(status(
            "auth_required",
            json!({"astation_id": ASTATION, "challenge": "b".repeat(64),
                   "transport": "relay", "protocol": "2"}),
        ));
        peer.wait(|v| v["type"] == "statusUpdate" && v["data"]["status"] == "auth")
            .await;
        peer.send(status("authenticated", json!({"method": "session_proof"})));
        tokio::time::sleep(Duration::from_millis(300)).await;

        // A new attachment: the same hello again is a retry there, handled.
        let from = peer.seen.len();
        peer.send(hello);
        let at = peer
            .wait_from(from, |v| {
                v["type"] == "session" && v["data"]["re"] == hello_id.as_str()
            })
            .await;
        let welcome = peer.seen[at]["data"].clone();
        assert_eq!(welcome["op"], "welcome", "{welcome}");
        peer.attachment = welcome["attachment_gen"].as_str().unwrap().to_string();
        assert_ne!(welcome["attachment_gen"], old["attachment_gen"]);
        let id = peer.request("renew", json!({"binding": old}));
        assert_eq!(peer.reply(&id).await["code"], "stale_target");
        // Its lease is not released; it expires (nothing renews it).
        let descriptor = listed(peer, &sid).await;
        assert_eq!(descriptor["controller"]["lease_epoch"], epoch);
        rt.clock.skip(15_001);
        let peer = &mut rt.peer;
        let changed = peer.wait(|v| is_session(v, "lease_changed")).await;
        assert_eq!(changed["data"]["reason"], "expired");
        assert!(peer.acquire(&sid, &pg).await > epoch);
        rt.shutdown().await;
    });
}

/// Astation reset its session client (e.g. after the Mac slept) and says
/// `hello` again on the same authenticated link: the attachment is replaced.
#[test]
fn a_second_hello_on_the_link_replaces_the_attachment() {
    local(async {
        let mut rt = Runtime::start(true).await;
        let mut client = rt.client().await;
        let agent = echo_agent(rt.dir.path());
        let session = rt.launch(&mut client, "codex", &agent, None).await;
        let (sid, pg) = (session.id.clone(), session.generation.clone());
        let peer = &mut rt.peer;
        let first = peer.hello().await;
        peer.terminal("subscribe", &sid, &pg, json!({}), None);
        let attached = peer.wait(|v| is_terminal(v, "attached")).await;
        let stream = attached["data"]["stream_id"].as_str().unwrap().to_string();
        let epoch = peer.acquire(&sid, &pg).await;
        let old = peer.binding(&sid, &pg, Some(epoch));
        let request_id = uuid::Uuid::new_v4().to_string();
        let id = peer.request(
            "submit",
            json!({"binding": old, "request_id": request_id, "kind": "interrupt", "payload": {}}),
        );
        assert_eq!(peer.reply(&id).await["state"], "accepted");

        let welcome = peer.hello().await;
        assert_ne!(welcome["attachment_gen"], first["attachment_gen"]);
        assert_ne!(welcome["controller_session"], first["controller_session"]);
        assert_eq!(welcome["permissions"], first["permissions"]);
        assert!(
            welcome["authorization_ms_left"].as_u64().unwrap()
                <= first["authorization_ms_left"].as_u64().unwrap()
        );
        // No lease carried over; the old attachment_gen is stale.
        assert_eq!(listed(peer, &sid).await["controller"], Value::Null);
        let id = peer.request("renew", json!({"binding": old}));
        assert_eq!(peer.reply(&id).await["code"], "stale_target");
        let from = peer.seen.len();
        let mut input = json!({"v": 1, "op": "input", "terminal_id": sid, "generation": pg,
            "binding": old, "stream_id": stream, "sequence": 0,
            "bytes": STANDARD.encode("OLD\r")});
        input["binding"]["lease_epoch"] = epoch.into();
        peer.send(json!({"type": "terminal", "data": input}));
        let refused = peer.wait_from(from, |v| is_terminal(v, "error")).await;
        assert_eq!(peer.seen[refused]["data"]["code"], "stale_target");
        // The receipt is still there.
        let id = peer.request(
            "receipt_query",
            json!({"binding": peer.binding(&sid, &pg, None), "request_ids": [request_id]}),
        );
        let receipts = peer.reply(&id).await;
        assert_eq!(receipts["receipts"][0]["request_id"], request_id.as_str());
        // Control again without takeover.
        assert!(peer.acquire(&sid, &pg).await > epoch);
        // At most one replacement a second.
        let id = peer.request("hello", json!({"revision": 8}));
        assert_eq!(peer.reply(&id).await["code"], "busy");
        rt.clock.skip(1_000);
        let again = rt.peer.hello().await;
        assert_ne!(again["attachment_gen"], welcome["attachment_gen"]);
        rt.shutdown().await;
    });
}

#[test]
fn a_stop_submission_completes_when_the_agent_exits() {
    local(async {
        let mut rt = Runtime::start(true).await;
        let mut client = rt.client().await;
        let agent = echo_agent(rt.dir.path());
        let session = rt.launch(&mut client, "codex", &agent, None).await;
        let (sid, pg) = (session.id.clone(), session.generation.clone());
        let peer = &mut rt.peer;
        peer.hello().await;
        listed(peer, &sid).await;
        let epoch = peer.acquire(&sid, &pg).await;
        let request_id = uuid::Uuid::new_v4().to_string();
        let id = peer.request(
            "submit",
            json!({"binding": peer.binding(&sid, &pg, Some(epoch)), "request_id": request_id,
                   "kind": "stop", "payload": {}}),
        );
        let receipt = peer.reply(&id).await;
        assert_eq!(receipt["op"], "receipt", "{receipt}");
        assert_eq!(receipt["state"], "accepted");
        let done = peer
            .wait_from(0, |v| {
                is_session(v, "receipt")
                    && v["data"]["request_id"] == request_id.as_str()
                    && v["data"]["state"] == "completed"
            })
            .await;
        assert!(done > 0);
        let exited = peer
            .wait_from(0, |v| {
                is_session(v, "session_changed")
                    && v["data"]["descriptor"]["session_id"] == sid.as_str()
                    && v["data"]["descriptor"]["state"] == "exited"
            })
            .await;
        assert!(exited > 0);
        rt.shutdown().await;
    });
}

/// A session the broker started, in a worker in this process.
async fn broker_session(dir: &Path) -> crate::runtime::broker::BrokerSession {
    use crate::runtime::adopt::SpawnRequest;
    let agent = echo_agent(dir);
    let launcher = Launcher::InProcess(InProcess {
        state: dir.join("state"),
        socket_dir: dir.join("ws"),
        chat_root: dir.join("chat"),
    });
    let request = SpawnRequest {
        session_id: crate::session::SessionId::new(),
        process_gen: uuid::Uuid::new_v4().to_string(),
        provider: crate::session::Provider::Codex,
        args: vec![],
        cwd: dir.to_path_buf(),
        rows: 24,
        cols: 80,
    };
    let env = LaunchEnv(vec![
        ("PATH".into(), "/usr/bin:/bin".into()),
        ("CODEX_CLI_BIN".into(), agent.display().to_string()),
    ]);
    let (handle, created_at_ms) = launcher.spawn(request.clone(), env).await.unwrap();
    crate::runtime::broker::BrokerSession::launched(handle, &request, created_at_ms)
}

#[tokio::test]
async fn adoption_refuses_a_worker_epoch_beyond_the_reserved_block() {
    use crate::runtime::broker::SessionState;
    let dir = short_dir();
    let mut bridge =
        super::HostBridge::open(&dir.path().join("journal"), None, Clock::default()).unwrap();
    // Within the block of an empty journal (floor 0): adopted as it is.
    let mut fine = broker_session(dir.path()).await;
    fine.raise_input_epoch_to(super::LEASE_EPOCH_BLOCK).unwrap();
    bridge.check_adoption(&mut fine);
    assert!(fine.is_live());
    assert_eq!(fine.input_epoch(), super::LEASE_EPOCH_BLOCK);
    // Beyond it: an epoch no broker of this journal granted.
    let mut ahead = broker_session(dir.path()).await;
    ahead
        .raise_input_epoch_to(super::LEASE_EPOCH_BLOCK + 1)
        .unwrap();
    bridge.check_adoption(&mut ahead);
    assert!(!ahead.is_live());
    assert_eq!(ahead.state, SessionState::RecoveryRequired);
    // The runtime epoch moves on with every start of the journal's broker.
    let first = bridge.host().context().runtime_epoch;
    drop(bridge);
    let again =
        super::HostBridge::open(&dir.path().join("journal"), None, Clock::default()).unwrap();
    assert_eq!(again.host().context().runtime_epoch, first + 1);
}

/// r8 §H: an orderly stop writes the journal's clean close for its runtime
/// epoch, and the next start (reading the previous epoch before taking the
/// next) finds it; a run that just ends (a crash) leaves none.
#[test]
fn an_orderly_stop_closes_the_journal_cleanly_for_the_next_start() {
    let dir = short_dir();
    let journal = dir.path().join("journal");
    let mut bridge = super::HostBridge::open(&journal, None, Clock::default()).unwrap();
    assert!(!bridge.host().previous_run_clean());
    let epoch = bridge.host().context().runtime_epoch;
    bridge.close_cleanly();
    drop(bridge);
    let text = std::fs::read_to_string(journal.join("clean_close")).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&text).unwrap(),
        serde_json::json!({ "runtime_epoch": epoch })
    );
    let bridge = super::HostBridge::open(&journal, None, Clock::default()).unwrap();
    assert!(bridge.host().previous_run_clean());
    assert!(!journal.join("clean_close").exists());
    assert!(bridge.host_error().is_none());
    drop(bridge);
    let bridge = super::HostBridge::open(&journal, None, Clock::default()).unwrap();
    assert!(
        !bridge.host().previous_run_clean(),
        "the last run didn't stop in order"
    );
}

/// The link's principal is the paired Astation within the verified account,
/// always an opaque id.
#[test]
fn the_link_principal_is_the_paired_astation_in_its_account() {
    let identity = super::Identity {
        account_id: "account-a".into(),
        atem_device_id: "host-a".into(),
        host_trust_gen: 1,
    };
    let p = super::link_principal(&identity, "astation-1").unwrap();
    assert_eq!(p, "astation:account-a:astation-1");
    let odd = super::link_principal(&identity, "a station/1").unwrap();
    assert!(crate::session_protocol::wire::is_opaque_id(&odd), "{odd}");
    assert_eq!(
        super::link_principal(&identity, "a station/1").unwrap(),
        odd
    );
    assert_ne!(
        super::link_principal(&identity, "a station/2").unwrap(),
        odd
    );
    assert_eq!(super::link_principal(&identity, ""), None);
}

#[test]
fn classification_follows_section_6() {
    use super::super::broker::WriteOutcome;
    use crate::session_protocol::host::DispatchReport;
    let outcome = |ok, dropped, no_effect| WriteOutcome {
        seq: 0,
        ok,
        dropped,
        no_effect,
        consumed: false,
        error: None,
    };
    assert_eq!(super::classify(&outcome(true, false, false)), None);
    assert_eq!(
        super::classify(&outcome(false, true, false)),
        Some(DispatchReport::FailedNoEffect)
    );
    assert_eq!(
        super::classify(&outcome(false, false, true)),
        Some(DispatchReport::FailedNoEffect)
    );
    assert_eq!(
        super::classify(&outcome(false, false, false)),
        Some(DispatchReport::FailedAfterPossibleEffect)
    );
}

#[test]
fn the_submitter_hears_the_turns_real_outcome() {
    let env = super::complete_envelope(
        "c1",
        "ses-aaaaaaaaaaaa",
        None,
        "r1".into(),
        Some("t1".into()),
        crate::chat::adapter::Outcome::Interrupted,
    );
    assert_eq!(env.op, "complete");
    assert_eq!(env.body["outcome"], "interrupted");
    assert_eq!(env.body["turnId"], "t1");
}

#[test]
fn congestion_keeps_written_acks_and_drops_only_frames() {
    use super::Queued;
    let mut queue = std::collections::VecDeque::from(vec![
        Queued::Frame("f1".into()),
        Queued::Other("written-1".into()),
        Queued::Frame("f2".into()),
        Queued::Other("written-2".into()),
    ]);
    super::drop_frames(&mut queue);
    assert_eq!(
        Vec::from(queue),
        [
            Queued::Other("written-1".into()),
            Queued::Other("written-2".into())
        ]
    );
}

#[tokio::test]
async fn repeated_reclaims_never_push_the_worker_epoch_past_the_block() {
    let _profile = crate::test_profile::temp();
    let dir = short_dir();
    let mut bridge =
        super::HostBridge::open(&dir.path().join("journal"), None, Clock::default()).unwrap();
    let session = broker_session(dir.path()).await;
    let sid = session.id.clone();
    let mut sessions = std::collections::BTreeMap::new();
    sessions.insert(sid.clone(), session);
    let mut app = App::new();
    app.hosted = Some(Default::default());
    app.astation_reconnect = false;
    bridge.tick(&mut app, &mut sessions, false);
    // Local writes in flight (a mark task's prompt, typing) are never dropped
    // by a reclaim without a remote lease.
    sessions.get_mut(&sid).unwrap().write(b"keep me\n").unwrap();
    for _ in 0..(2 * super::LEASE_EPOCH_BLOCK) {
        bridge
            .local_input(&sid, Vec::new(), &app.astation_client, &mut sessions)
            .unwrap();
    }
    assert_eq!(sessions[&sid].input_epoch(), 0);
}

#[test]
fn a_new_identity_restarts_the_host_under_it() {
    local(async {
        let dir = Rc::new(short_dir());
        profile(&dir.path().join("profile"), true);
        // Started unpaired; the first verified link names the identity.
        let mut rt = Runtime::start_with(dir, "rt.sock", false).await;
        let peer = &mut rt.peer;
        let welcome = peer.hello().await;
        assert_eq!(welcome["account_id"], ACCOUNT);
        assert_eq!(welcome["atem_device_id"], DEVICE);
        assert_eq!(welcome["host_trust_gen"], TRUST_GEN);
        let id = peer.request("list", json!({}));
        let sessions = peer.reply(&id).await;
        // Epoch 1 at start, 2 for the new identity.
        assert_eq!(sessions["runtime_epoch"], 2, "{sessions}");
        rt.shutdown().await;
    });
}

/// The first receipt of `rid` past accepted/executing.
async fn final_receipt(peer: &mut Peer, rid: &str) -> Value {
    let rid = rid.to_string();
    let at = peer
        .wait_from(0, move |v| {
            is_session(v, "receipt")
                && v["data"]["request_id"] == rid.as_str()
                && v["data"]["state"] != "accepted"
                && v["data"]["state"] != "executing"
        })
        .await;
    peer.seen[at]["data"].clone()
}

/// An agent writing every byte its terminal delivers to `input`.
fn recording_agent(dir: &Path, input: &Path) -> PathBuf {
    script(
        dir,
        "recording-agent",
        &format!(
            "stty raw -echo\nprintf 'READY\\r\\n'\nexec cat > '{}'",
            input.display()
        ),
    )
}

/// Esc is written only while a turn is known to run: Claude ready and
/// Codex before its first prompt (status unknown) complete at once with
/// nothing written; Codex without chat (its hooks off) has no turn state:
/// interrupts and prompts are refused with the reason, and its descriptor
/// offers terminal-v1 only.
#[test]
fn interrupts_write_esc_only_while_a_turn_is_known_to_run() {
    local(async {
        let mut rt = Runtime::start(true).await;
        let mut client = rt.client().await;
        let claude = rt.launch(&mut client, "claude", &fake_claude(), None).await;
        let unknown_input = rt.dir.path().join("codex-unknown.input");
        let agent = recording_agent(rt.dir.path(), &unknown_input);
        let codex = rt.launch(&mut client, "codex", &agent, None).await;
        let off_input = rt.dir.path().join("codex-off.input");
        let off_agent = script(
            rt.dir.path(),
            "recording-agent-off",
            &format!(
                "stty raw -echo\nprintf 'READY\\r\\n'\nexec cat > '{}'",
                off_input.display()
            ),
        );
        client
            .send(&ClientMsg::Launch {
                provider: "codex".into(),
                args: vec![],
                cwd: rt.dir.path().to_path_buf(),
                env: LaunchEnv(vec![
                    ("PATH".into(), "/usr/bin:/bin".into()),
                    ("CODEX_CLI_BIN".into(), off_agent.display().to_string()),
                    (crate::runtime::broker::NO_CODEX_HOOKS.into(), "1".into()),
                ]),
                rows: 24,
                cols: 80,
            })
            .await
            .unwrap();
        let off = expect(&mut client, |m| match m {
            RuntimeMsg::Launched { session } => Some(session),
            RuntimeMsg::Error { text, .. } => panic!("launch failed: {text}"),
            _ => None,
        })
        .await;
        let peer = &mut rt.peer;
        peer.hello().await;
        assert_eq!(
            listed(peer, &codex.id).await["capabilities"],
            json!(["terminal-v1", "chat-v1"])
        );
        assert_eq!(
            listed(peer, &off.id).await["capabilities"],
            json!(["terminal-v1"])
        );
        open_chat(peer, "conv-1", &claude.id, &claude.generation).await;
        let mut ids = Vec::new();
        for session in [&claude, &codex, &off] {
            let epoch = peer.acquire(&session.id, &session.generation).await;
            let request_id = uuid::Uuid::new_v4().to_string();
            let id = peer.request(
                "submit",
                json!({"binding": peer.binding(&session.id, &session.generation, Some(epoch)),
                       "request_id": request_id, "kind": "interrupt", "payload": {}}),
            );
            assert_eq!(peer.reply(&id).await["state"], "accepted");
            ids.push(request_id);
        }
        for rid in &ids[..2] {
            let done = final_receipt(peer, rid).await;
            assert_eq!(done["state"], "completed", "{done}");
            assert_eq!(done["detail"], "no turn was running");
        }
        let refused = final_receipt(peer, &ids[2]).await;
        assert_eq!(refused["state"], "rejected", "{refused}");
        assert_eq!(refused["detail"], "no turn state; use the terminal");
        // A prompt to the session without chat: refused, with the reason.
        let epoch = peer.acquire(&off.id, &off.generation).await;
        let request_id = uuid::Uuid::new_v4().to_string();
        let id = peer.request(
            "submit",
            json!({"binding": peer.binding(&off.id, &off.generation, Some(epoch)),
                   "request_id": request_id, "kind": "prompt", "payload": {"text": "hi"}}),
        );
        peer.reply(&id).await;
        let refused = final_receipt(peer, &request_id).await;
        assert_eq!(refused["state"], "rejected", "{refused}");
        assert_eq!(
            refused["detail"],
            "chat is not available for this agent; use the terminal"
        );
        // Neither Codex got a byte.
        peer.drain(Duration::from_millis(300)).await;
        for input in [&unknown_input, &off_input] {
            assert_eq!(std::fs::read(input).unwrap_or_default(), b"", "{input:?}");
        }
        rt.shutdown().await;
    });
}

#[test]
fn the_link_is_fenced_and_dropped_at_its_authorization_deadline() {
    local(async {
        let mut rt = Runtime::start(true).await;
        rt.peer.hello().await;
        rt.clock.skip(super::LINK_AUTHORIZATION_MS + 1);
        // The broker drops the link (a reconnect authenticates it again).
        tokio::time::timeout(WAIT, async {
            while rt.peer.from_atem.recv().await.is_some() {}
        })
        .await
        .expect("the link stayed open past its authorization");
        rt.shutdown().await;
    });
}

/// `atem unpair` took effect without telling the runtime (no `reload`
/// delivered): the broker notices the changed pairing on its own and drops
/// the link with its attachment.
#[test]
fn a_changed_pairing_drops_the_link_without_a_reload() {
    local(async {
        let mut rt = Runtime::start(true).await;
        rt.peer.hello().await;
        let profile = crate::profile::Sources::in_dir(&rt.dir.path().join("profile"));
        crate::pairing::unpair(&profile).unwrap();
        tokio::time::timeout(WAIT, async {
            while rt.peer.from_atem.recv().await.is_some() {}
        })
        .await
        .expect("the link of a removed pairing stayed open");
        rt.shutdown().await;
    });
}

/// A suspended machine: the monotonic clock stood still, wall time passed
/// the 24 h. The authorization holds in wall time too.
#[test]
fn the_link_is_dropped_when_wall_time_passes_its_authorization() {
    local(async {
        let mut rt = Runtime::start(true).await;
        rt.peer.hello().await;
        rt.clock.skip_wall(super::LINK_AUTHORIZATION_MS + 1);
        tokio::time::timeout(WAIT, async {
            while rt.peer.from_atem.recv().await.is_some() {}
        })
        .await
        .expect("the link stayed open past its wall-clock authorization");
        rt.shutdown().await;
    });
}

/// Every message `client` gets within `time`.
async fn collect(client: &mut RuntimeClient, time: Duration) -> Vec<RuntimeMsg> {
    let mut messages = Vec::new();
    let deadline = tokio::time::Instant::now() + time;
    while let Ok(Ok(Some(message))) = tokio::time::timeout_at(deadline, client.recv()).await {
        messages.push(message);
    }
    messages
}

async fn attach_client(
    client: &mut RuntimeClient,
    sid: &str,
    rows: u16,
    cols: u16,
) -> SessionSummary {
    client
        .send(&ClientMsg::Attach {
            session_id: sid.to_string(),
            rows,
            cols,
        })
        .await
        .unwrap();
    expect(client, |m| match m {
        RuntimeMsg::Attached { session, .. } => Some(session),
        _ => None,
    })
    .await
}

#[test]
fn a_local_paste_is_written_whole_while_astation_types() {
    local(async {
        let mut rt = Runtime::start(true).await;
        let mut client = rt.client().await;
        let typed = rt.dir.path().join("typed.bin");
        // Raw, bracketed paste on: records every byte it is typed.
        let agent = script(
            rt.dir.path(),
            "recorder",
            &format!(
                "stty raw -echo\nprintf '\\033[?2004hREADY\\r\\n'\nexec cat > '{}'",
                typed.display()
            ),
        );
        let session = rt.launch(&mut client, "codex", &agent, None).await;
        let (sid, pg) = (session.id.clone(), session.generation.clone());
        let peer = &mut rt.peer;
        peer.hello().await;
        peer.terminal("subscribe", &sid, &pg, json!({}), None);
        let attached = peer.wait(|v| is_terminal(v, "attached")).await;
        let stream = attached["data"]["stream_id"].as_str().unwrap().to_string();
        screen_until(peer, &sid, &pg, "READY").await;
        attach_client(&mut client, &sid, 24, 80).await;

        // Astation holds the lease and types.
        let epoch = peer.acquire(&sid, &pg).await;
        let remote = STANDARD.encode([b'R'; 1000]);
        for sequence in 0..4 {
            peer.terminal(
                "input",
                &sid,
                &pg,
                json!({"stream_id": stream, "sequence": sequence, "bytes": remote}),
                Some(epoch),
            );
        }
        // A local paste larger than one input, while Astation keeps
        // taking the lease back and typing.
        let text = "P".repeat(40 * 1024);
        client
            .send(&ClientMsg::Paste {
                session_id: sid.clone(),
                bytes: STANDARD.encode(&text),
            })
            .await
            .unwrap();
        let peer = &mut rt.peer;
        for round in 0..5u64 {
            let id = peer.request(
                "acquire",
                json!({"binding": peer.binding(&sid, &pg, None), "takeover": false}),
            );
            let lease = peer.reply(&id).await;
            if lease["op"] == "lease" {
                let epoch = lease["binding"]["lease_epoch"].as_u64().unwrap();
                peer.terminal(
                    "input",
                    &sid,
                    &pg,
                    json!({"stream_id": stream, "sequence": 10 + round, "bytes": remote}),
                    Some(epoch),
                );
            }
        }
        let changed = peer
            .wait_from(0, |v| {
                is_session(v, "lease_changed") && v["data"]["reason"] == "local_input"
            })
            .await;
        assert!(changed > 0);
        let expected = format!("\x1b[200~{text}\x1b[201~");
        tokio::time::timeout(WAIT, async {
            loop {
                let written = std::fs::read(&typed).unwrap_or_default();
                if String::from_utf8_lossy(&written).contains("\x1b[201~") {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the paste never arrived");
        tokio::time::sleep(Duration::from_millis(500)).await;
        let written = String::from_utf8(std::fs::read(&typed).unwrap()).unwrap();
        // Intact and contiguous: no remote byte inside it.
        assert!(
            written.contains(&expected),
            "the paste was split or interleaved"
        );
        assert_eq!(written.matches('P').count(), text.len());
        rt.shutdown().await;
    });
}

#[test]
fn a_local_resize_under_a_remote_lease_waits_for_the_reclaim() {
    local(async {
        let mut rt = Runtime::start(true).await;
        let mut client = rt.client().await;
        let agent = echo_agent(rt.dir.path());
        let session = rt.launch(&mut client, "codex", &agent, None).await;
        let (sid, pg) = (session.id.clone(), session.generation.clone());
        let peer = &mut rt.peer;
        peer.hello().await;
        peer.terminal("subscribe", &sid, &pg, json!({}), None);
        peer.wait(|v| is_terminal(v, "attached")).await;
        screen_until(peer, &sid, &pg, "READY").await;
        let attached = attach_client(&mut client, &sid, 24, 80).await;
        assert_eq!((attached.rows, attached.cols), (24, 80));
        peer.acquire(&sid, &pg).await;
        tokio::time::sleep(Duration::from_millis(200)).await;

        // The remote controller owns the size: a local resize is kept for later.
        client
            .send(&ClientMsg::Resize {
                session_id: sid.clone(),
                rows: 30,
                cols: 100,
            })
            .await
            .unwrap();
        let heard = collect(&mut client, Duration::from_millis(500)).await;
        assert!(
            !heard
                .iter()
                .any(|m| matches!(m, RuntimeMsg::Attached { session, .. } if session.rows == 30)),
            "{heard:?}"
        );
        client.send(&ClientMsg::List).await.unwrap();
        let sessions = expect(&mut client, |m| match m {
            RuntimeMsg::Sessions { sessions } => Some(sessions),
            _ => None,
        })
        .await;
        let listed = sessions.iter().find(|s| s.id == sid).unwrap();
        assert_eq!((listed.rows, listed.cols), (24, 80));

        // Reclaim: the local size applies.
        client
            .send(&ClientMsg::Reclaim {
                session_id: sid.clone(),
            })
            .await
            .unwrap();
        let session = expect(&mut client, |m| match m {
            RuntimeMsg::Attached { session, .. } if session.rows == 30 => Some(session),
            _ => None,
        })
        .await;
        assert_eq!((session.rows, session.cols), (30, 100));
        rt.shutdown().await;
    });
}

#[test]
fn mark_task_notices_reach_only_the_frontend_of_their_session() {
    local(async {
        let mut rt = Runtime::start(true).await;
        let mut client = rt.client().await;
        let mut other = rt.client().await;
        let project = rt.dir.path().join("project");
        std::fs::create_dir_all(project.join(".chisel/tasks")).unwrap();
        std::fs::write(
            project.join(".chisel/tasks/t1.json"),
            json!({"title": "Project B"}).to_string(),
        )
        .unwrap();
        let agent = echo_agent(rt.dir.path());
        let claude = rt
            .launch(&mut client, "claude", &agent, Some(&project))
            .await;
        let codex = rt.launch(&mut other, "codex", &agent, None).await;
        attach_client(&mut client, &claude.id, 24, 80).await;
        attach_client(&mut other, &codex.id, 24, 80).await;
        rt.peer.hello().await;
        rt.peer
            .send(json!({"type":"markTaskAssignment","data":{"taskId":"t1","receivedAtMs":0}}));
        let notice = expect(&mut client, |m| match m {
            RuntimeMsg::Notice { text } if text.contains("t1") && text.contains("Claude") => {
                Some(text)
            }
            _ => None,
        })
        .await;
        assert!(notice.contains("t1"));
        let heard = collect(&mut other, Duration::from_millis(800)).await;
        assert!(
            !heard
                .iter()
                .any(|m| matches!(m, RuntimeMsg::Notice { text } if text.contains("t1"))),
            "another session's frontend got the task's notice: {heard:?}"
        );
        rt.shutdown().await;
    });
}

/// Duplicate detection remembers at most `MAX_SEEN` messages; the oldest
/// go first.
#[test]
fn the_duplicate_window_is_bounded() {
    let profile = tempfile::tempdir().unwrap();
    let _profile = crate::test_profile::use_dir(profile.path());
    let dir = short_dir();
    let mut bridge =
        super::HostBridge::open(&dir.path().join("journal"), None, Clock::default()).unwrap();
    for i in 0..=super::MAX_SEEN {
        assert!(!bridge.duplicate(&format!("m{i}"), 0));
    }
    assert_eq!(bridge.seen.len(), super::MAX_SEEN);
    assert_eq!(bridge.seen_order.len(), super::MAX_SEEN);
    // The newest is still remembered; the oldest was evicted.
    assert!(bridge.duplicate(&format!("m{}", super::MAX_SEEN), 0));
    assert!(!bridge.duplicate("m0", 0));
}

// ── Approvals (§6a): the real hook script under a fake agent ──

/// `tests/fixtures/approvals/fake-agent.py`: runs the real permission hook.
fn approval_agent() -> PathBuf {
    python_ready();
    let path =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/approvals/fake-agent.py");
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    if perms.mode() & 0o111 != 0o111 {
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
    }
    path
}

/// The fake agent's next tool call `n` needing permission.
fn ask(fake: &Path, n: u32, request: Value) {
    let tmp = fake.join(format!("tmp-ask-{n}"));
    std::fs::write(&tmp, request.to_string()).unwrap();
    std::fs::rename(&tmp, fake.join(format!("ask-{n}.json"))).unwrap();
}

fn npm_test() -> Value {
    json!({"tool_name": "Bash",
           "tool_input": {"command": "npm test\nnpm run lint", "description": "run the tests"},
           "permission_suggestions": [{"type": "addRules", "behavior": "allow",
               "rules": [{"toolName": "Bash", "ruleContent": "npm test:*"}],
               "destination": "localSettings"}]})
}

/// Waits until the fake agent's events show `line`.
async fn agent_event(fake: &Path, line: &str) {
    let events = fake.join("events");
    tokio::time::timeout(WAIT, async {
        loop {
            let text = std::fs::read_to_string(&events).unwrap_or_default();
            if text.lines().any(|l| l.trim_end() == line.trim_end()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| {
        panic!(
            "the agent never showed {line:?}: {}",
            std::fs::read_to_string(&events).unwrap_or_default()
        )
    });
}

/// Waits until the fake agent's terminal delivered exactly `bytes`.
async fn agent_input(fake: &Path, bytes: &[u8]) {
    let path = fake.join("input");
    tokio::time::timeout(WAIT, async {
        while std::fs::read(&path).unwrap_or_default() != bytes {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the agent's input: {:?}", std::fs::read(&path)));
}

fn is_relay(v: &Value, op: &str, approval_id: &str) -> bool {
    v["type"] == "relay" && v["data"]["op"] == op && v["data"]["approval_id"] == approval_id
}

/// The chat-v1 card of `approval_id` in `state`.
fn is_card(v: &Value, approval_id: &str, state: &str) -> bool {
    is_chat(v, "message")
        && v["data"]["messageId"] == format!("approval-{approval_id}")
        && v["data"]["parts"][0]["kind"] == "approval"
        && v["data"]["parts"][0]["state"] == state
}

impl Runtime {
    /// Launches `provider` running the approval fake agent (control files
    /// in `fake`).
    async fn launch_approval_agent(
        &self,
        client: &mut RuntimeClient,
        provider: &str,
        fake: &Path,
    ) -> SessionSummary {
        let var = if provider == "claude" {
            "CLAUDE_CLI_BIN"
        } else {
            "CODEX_CLI_BIN"
        };
        let hook = crate::chat::codex::hook_command(&self.dir.path().join("run/approval-hook.sh"));
        client
            .send(&ClientMsg::Launch {
                provider: provider.into(),
                args: vec![],
                cwd: self.dir.path().to_path_buf(),
                env: LaunchEnv(vec![
                    ("PATH".into(), "/usr/bin:/bin".into()),
                    (var.into(), approval_agent().display().to_string()),
                    ("FAKE_DIR".into(), fake.display().to_string()),
                    ("FAKE_CODEX_HOOK".into(), hook),
                ]),
                rows: 24,
                cols: 80,
            })
            .await
            .unwrap();
        let session = expect(client, |m| match m {
            RuntimeMsg::Launched { session } => Some(session),
            RuntimeMsg::Error { text, .. } => panic!("launch failed: {text}"),
            _ => None,
        })
        .await;
        agent_event(fake, "started").await;
        session
    }
}

#[test]
fn an_approval_without_a_lease_holder_is_carded_pushed_and_answered_from_chat() {
    local(async {
        let mut rt = Runtime::start(true).await;
        let mut client = rt.client().await;
        let fake = rt.dir.path().join("fake");
        let session = rt.launch_approval_agent(&mut client, "claude", &fake).await;
        let (sid, pg) = (session.id.clone(), session.generation.clone());
        let peer = &mut rt.peer;
        peer.hello().await;
        assert_eq!(listed(peer, &sid).await["controller"], Value::Null);
        open_chat(peer, "conv-1", &sid, &pg).await;

        ask(&fake, 1, npm_test());
        let request = peer.wait(|v| is_session(v, "approval_request")).await["data"].clone();
        assert_eq!(request["session_id"], sid.as_str());
        assert_eq!(request["process_gen"], pg.as_str());
        assert_eq!(request["tool"], "Bash");
        assert_eq!(request["summary"], "npm test", "the first line only");
        let rules = request["always_rules"].as_array().unwrap();
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["label"], "Allow Bash(npm test:*)");
        let aid = request["approval_id"].as_str().unwrap().to_string();
        // Pushed to the account's devices over the link: redacted only.
        let at = peer
            .wait_from(0, |v| is_relay(v, "push_approval", &aid))
            .await;
        let push = peer.seen[at]["data"].clone();
        assert_eq!(push["atem_device_id"], DEVICE);
        assert_eq!(push["session_id"], sid.as_str());
        assert_eq!(push["tool"], "Bash");
        assert_eq!(push["summary"], "npm test");
        assert_eq!(
            push["expires_at"].as_u64().unwrap(),
            request["created_at"].as_u64().unwrap() + 600_000
        );
        assert!(!push.to_string().contains("npm run lint"), "{push}");
        // The chat card, pending.
        let at = peer.wait_from(0, |v| is_card(v, &aid, "pending")).await;
        let card = peer.seen[at]["data"]["parts"][0].clone();
        assert_eq!(card["tool"], "Bash");
        assert_eq!(card["summary"], "npm test");
        assert_eq!(card["always_rules"], request["always_rules"]);
        assert!(card.get("reason").is_none(), "pending: no reason {card}");

        // r8 removed `acquire` on an answer: refused, nothing taken.
        let refused_id = uuid::Uuid::new_v4().to_string();
        peer.chat(
            "submit",
            "conv-1",
            &sid,
            &pg,
            json!({"generation": pg, "requestId": refused_id,
                   "approval": {"approval_id": aid, "decision": "allow_once", "acquire": true}}),
        );
        let refused = peer
            .wait(|v| is_session(v, "error") && v["data"]["code"] == "unsupported_version")
            .await;
        assert!(refused["data"].get("re").is_none(), "{refused}");
        assert_eq!(listed(peer, &sid).await["controller"], Value::Null);
        // r8 §G: answered from chat without the lease, which stays free.
        let request_id = uuid::Uuid::new_v4().to_string();
        peer.chat(
            "submit",
            "conv-1",
            &sid,
            &pg,
            json!({"generation": pg, "requestId": request_id,
                   "approval": {"approval_id": aid, "decision": "allow_once"}}),
        );
        let rid = request_id.clone();
        peer.wait(move |v| is_chat(v, "accepted") && v["data"]["requestId"] == rid.as_str())
            .await;
        agent_event(&fake, "answer 1 allow ").await;
        let rid = request_id.clone();
        let done = peer
            .wait(move |v| {
                (is_chat(v, "complete") || is_chat(v, "error"))
                    && v["data"]["requestId"] == rid.as_str()
            })
            .await;
        assert_eq!(done["data"]["op"], "complete", "{done}");
        let at = peer.wait_from(0, |v| is_card(v, &aid, "allowed")).await;
        // r8 `approval.card_reason`: the final card says why it closed.
        assert_eq!(
            peer.seen[at]["data"]["parts"][0]["reason"],
            "answered_remote"
        );
        let at = peer
            .wait_from(0, |v| is_relay(v, "push_resolved", &aid))
            .await;
        assert_eq!(peer.seen[at]["data"]["reason"], "answered_remote");
        let closed = peer
            .seen
            .iter()
            .find(|v| is_session(v, "approval_closed"))
            .unwrap();
        assert_eq!(closed["data"]["reason"], "answered_remote");
        assert_eq!(listed(peer, &sid).await["controller"], Value::Null);
        rt.shutdown().await;
    });
}

#[test]
fn a_denial_carries_the_message_and_a_terminal_answer_resolves_the_push() {
    local(async {
        let mut rt = Runtime::start(true).await;
        let mut client = rt.client().await;
        let fake = rt.dir.path().join("fake");
        let session = rt.launch_approval_agent(&mut client, "claude", &fake).await;
        let (sid, pg) = (session.id.clone(), session.generation.clone());
        let peer = &mut rt.peer;
        peer.hello().await;
        listed(peer, &sid).await;
        open_chat(peer, "conv-1", &sid, &pg).await;
        let lease = peer.acquire(&sid, &pg).await;

        // The lease holder denies with a message: a session-v1 submission.
        ask(&fake, 1, npm_test());
        let request = peer.wait(|v| is_session(v, "approval_request")).await;
        let aid = request["data"]["approval_id"].as_str().unwrap().to_string();
        let request_id = uuid::Uuid::new_v4().to_string();
        let id = peer.request(
            "submit",
            json!({"binding": peer.binding(&sid, &pg, Some(lease)), "request_id": request_id,
                   "kind": "approval",
                   "payload": {"approval_id": aid, "decision": "deny",
                               "message": "use the staging config"}}),
        );
        assert_eq!(peer.reply(&id).await["state"], "accepted");
        agent_event(&fake, "answer 1 deny use the staging config").await;
        let rid = request_id.clone();
        let done = peer
            .wait(move |v| {
                is_session(v, "receipt")
                    && v["data"]["request_id"] == rid.as_str()
                    && !matches!(v["data"]["state"].as_str(), Some("accepted" | "executing"))
            })
            .await;
        assert_eq!(done["data"]["state"], "completed", "{done}");
        let at = peer.wait_from(0, |v| is_card(v, &aid, "denied")).await;
        assert_eq!(
            peer.seen[at]["data"]["parts"][0]["reason"],
            "answered_remote"
        );

        // Answered in the agent's own dialog first: the card and the push
        // resolve, and the hook gets no decision.
        ask(&fake, 2, npm_test());
        let from = peer.seen.len();
        let at = peer
            .wait_from(from, |v| is_session(v, "approval_request"))
            .await;
        let aid = peer.seen[at]["data"]["approval_id"]
            .as_str()
            .unwrap()
            .to_string();
        std::fs::write(fake.join("terminal-yes-2"), "").unwrap();
        let a = aid.clone();
        let closed = peer
            .wait(move |v| {
                is_session(v, "approval_closed") && v["data"]["approval_id"] == a.as_str()
            })
            .await;
        assert_eq!(closed["data"]["reason"], "answered_terminal");
        let at = peer
            .wait_from(0, |v| is_relay(v, "push_resolved", &aid))
            .await;
        assert_eq!(peer.seen[at]["data"]["reason"], "answered_terminal");
        let at = peer
            .wait_from(0, |v| is_card(v, &aid, "answered_terminal"))
            .await;
        assert_eq!(
            peer.seen[at]["data"]["parts"][0]["reason"],
            "answered_terminal"
        );
        agent_event(&fake, "answer 2 none ").await;
        // A late answer is refused.
        let id = peer.request(
            "submit",
            json!({"binding": peer.binding(&sid, &pg, Some(lease)), "request_id": uuid::Uuid::new_v4().to_string(),
                   "kind": "approval",
                   "payload": {"approval_id": aid, "decision": "allow_once"}}),
        );
        assert_eq!(peer.reply(&id).await["code"], "stale_target");
        rt.shutdown().await;
    });
}

#[test]
fn input_to_codex_releases_its_waiting_hooks_first() {
    local(async {
        let mut rt = Runtime::start(true).await;
        let mut client = rt.client().await;
        let fake = rt.dir.path().join("fake");
        let session = rt.launch_approval_agent(&mut client, "codex", &fake).await;
        let (sid, pg) = (session.id.clone(), session.generation.clone());
        let peer = &mut rt.peer;
        peer.hello().await;
        listed(peer, &sid).await;

        // Local input: Codex hides its prompt while the hook waits, so the
        // hook is released first and the card closes `released`; the key
        // itself is consumed (the user never saw Codex's dialog).
        ask(
            &fake,
            1,
            json!({"tool_name": "shell", "tool_input": {"command": "cargo build"}}),
        );
        let request = peer.wait(|v| is_session(v, "approval_request")).await;
        let aid = request["data"]["approval_id"].as_str().unwrap().to_string();
        assert_eq!(
            request["data"]["always_rules"],
            json!([]),
            "Codex offers none"
        );
        let at = peer
            .wait_from(0, |v| is_relay(v, "push_approval", &aid))
            .await;
        assert_eq!(
            peer.seen[at]["data"]["expires_at"].as_u64().unwrap(),
            request["data"]["created_at"].as_u64().unwrap() + 300_000
        );
        attach_client(&mut client, &sid, 24, 80).await;
        client.send(&ClientMsg::input(&sid, b"L")).await.unwrap();
        let peer = &mut rt.peer;
        let a = aid.clone();
        let closed = peer
            .wait(move |v| {
                is_session(v, "approval_closed") && v["data"]["approval_id"] == a.as_str()
            })
            .await;
        assert_eq!(closed["data"]["reason"], "released");
        agent_event(&fake, "answer 1 none ").await;
        let at = peer
            .wait_from(0, |v| is_relay(v, "push_resolved", &aid))
            .await;
        assert_eq!(peer.seen[at]["data"]["reason"], "released");
        expect(&mut client, |m| match m {
            RuntimeMsg::Notice { text }
                if text == crate::runtime::worker_protocol::APPROVAL_HANDED_NOTICE =>
            {
                Some(())
            }
            _ => None,
        })
        .await;
        // The next key reaches Codex's own dialog.
        client.send(&ClientMsg::input(&sid, b"M")).await.unwrap();
        agent_input(&fake, b"M").await;
        let peer = &mut rt.peer;

        // The lease holder's terminal input releases it the same way.
        ask(
            &fake,
            2,
            json!({"tool_name": "shell", "tool_input": {"command": "cargo test"}}),
        );
        let from = peer.seen.len();
        let at = peer
            .wait_from(from, |v| is_session(v, "approval_request"))
            .await;
        let aid = peer.seen[at]["data"]["approval_id"]
            .as_str()
            .unwrap()
            .to_string();
        let lease = peer.acquire(&sid, &pg).await;
        peer.terminal("subscribe", &sid, &pg, json!({}), None);
        let attached = peer.wait(|v| is_terminal(v, "attached")).await;
        let stream = attached["data"]["stream_id"].as_str().unwrap().to_string();
        peer.terminal(
            "input",
            &sid,
            &pg,
            json!({"stream_id": stream, "sequence": 0, "bytes": STANDARD.encode("R")}),
            Some(lease),
        );
        let a = aid.clone();
        let closed = peer
            .wait(move |v| {
                is_session(v, "approval_closed") && v["data"]["approval_id"] == a.as_str()
            })
            .await;
        assert_eq!(closed["data"]["reason"], "released");
        // Acked as not written.
        let at = peer.wait_from(0, |v| is_terminal(v, "written")).await;
        let written = &peer.seen[at];
        assert_eq!(written["data"]["sequence"], 0);
        assert_eq!(
            written["data"]["error"],
            crate::runtime::worker_protocol::APPROVAL_HANDED
        );
        agent_event(&fake, "answer 2 none ").await;
        // The next one is written.
        peer.terminal(
            "input",
            &sid,
            &pg,
            json!({"stream_id": stream, "sequence": 1, "bytes": STANDARD.encode("S")}),
            Some(lease),
        );
        let from = peer.seen.len();
        let at = peer.wait_from(from, |v| is_terminal(v, "written")).await;
        assert_eq!(peer.seen[at]["data"]["sequence"], 1);
        assert_eq!(peer.seen[at]["data"]["error"], Value::Null);
        agent_input(&fake, b"MS").await;
        // Only the keys typed at Codex's own dialog reached it.
        let input = std::fs::read(fake.join("input")).unwrap_or_default();
        assert_eq!(input, b"MS", "{input:?}");
        let events = std::fs::read_to_string(fake.join("events")).unwrap();
        let lines: Vec<&str> = events.lines().collect();
        let at = |prefix: &str| lines.iter().position(|l| l.starts_with(prefix)).unwrap();
        let inputs: Vec<usize> = (0..lines.len())
            .filter(|i| lines[*i].starts_with("input "))
            .collect();
        assert_eq!(inputs.len(), 2, "{events}");
        assert!(at("answer 1 none") < inputs[0], "{events}");
        assert!(at("answer 2 none") < inputs[1], "{events}");
        rt.shutdown().await;
    });
}

#[tokio::test]
async fn adoption_tells_the_worker_which_approvals_the_broker_knows() {
    use crate::runtime::adopt::SpawnRequest;
    use crate::runtime::worker_approvals::Event;
    let _sweep = HookSweep;
    let dir = short_dir();
    let fake = dir.path().join("fake");
    let launcher = Launcher::InProcess(InProcess {
        state: dir.path().join("state"),
        socket_dir: dir.path().join("ws"),
        chat_root: dir.path().join("chat"),
    });
    let request = SpawnRequest {
        session_id: crate::session::SessionId::new(),
        process_gen: uuid::Uuid::new_v4().to_string(),
        provider: crate::session::Provider::Codex,
        args: vec![],
        cwd: dir.path().to_path_buf(),
        rows: 24,
        cols: 80,
    };
    let hook = crate::chat::codex::hook_command(&dir.path().join("chat/approval-hook.sh"));
    let env = LaunchEnv(vec![
        ("PATH".into(), "/usr/bin:/bin".into()),
        (
            "CODEX_CLI_BIN".into(),
            approval_agent().display().to_string(),
        ),
        ("FAKE_DIR".into(), fake.display().to_string()),
        ("FAKE_CODEX_HOOK".into(), hook),
    ]);
    let (handle, created_at_ms) = launcher.spawn(request.clone(), env).await.unwrap();
    let mut session =
        crate::runtime::broker::BrokerSession::launched(handle, &request, created_at_ms);
    agent_event(&fake, "started").await;
    ask(
        &fake,
        1,
        json!({"tool_name": "shell", "tool_input": {"command": "ls"}}),
    );
    // The worker reports it to this connection (as it did to a broker that
    // went away without answering).
    let worker_id = tokio::time::timeout(WAIT, async {
        loop {
            session.pump();
            if let Some(Event::Request { request_id, .. }) = session.take_approvals().pop() {
                return request_id;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("no approval request");
    let mut bridge =
        super::HostBridge::open(&dir.path().join("journal"), None, Clock::default()).unwrap();
    bridge.check_adoption(&mut session);
    agent_event(&fake, "answer 1 none ").await;
    // The worker closes it `released`.
    let closed = tokio::time::timeout(WAIT, async {
        loop {
            session.pump();
            if let Some(event) = session.take_approvals().pop() {
                return event;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("no close");
    assert_eq!(
        closed,
        Event::Closed {
            request_id: worker_id,
            reason: crate::session_protocol::wire::ApprovalCloseReason::Released
        }
    );
    assert!(bridge.open_approvals().is_empty());
    let _ = session.stop();
}

#[test]
fn a_view_only_link_gets_no_approval_requests_and_no_cards() {
    local(async {
        super::VIEW_ONLY_LINK.with(|v| v.set(true));
        let mut rt = Runtime::start(true).await;
        let mut client = rt.client().await;
        let fake = rt.dir.path().join("fake");
        let session = rt.launch_approval_agent(&mut client, "claude", &fake).await;
        let (sid, pg) = (session.id.clone(), session.generation.clone());
        let peer = &mut rt.peer;
        let welcome = peer.hello().await;
        assert_eq!(welcome["permissions"], json!(["view"]));
        listed(peer, &sid).await;
        open_chat(peer, "conv-1", &sid, &pg).await;
        ask(&fake, 1, npm_test());
        // The push still goes out (the account's devices with control).
        let push = peer.wait(|v| v["type"] == "relay").await;
        assert_eq!(push["data"]["op"], "push_approval");
        let aid = push["data"]["approval_id"].as_str().unwrap().to_string();
        peer.drain(Duration::from_millis(800)).await;
        assert!(
            !peer.seen.iter().any(|v| is_session(v, "approval_request")),
            "{:#?}",
            peer.seen
        );
        assert!(!peer.seen.iter().any(|v| is_card(v, &aid, "pending")));
        // Nor in the history of a conversation opened now.
        let from = peer.seen.len();
        open_chat(peer, "conv-2", &sid, &pg).await;
        peer.drain(Duration::from_millis(500)).await;
        assert!(
            !peer.seen[from..]
                .iter()
                .any(|v| v.to_string().contains(&format!("approval-{aid}")))
        );
        super::VIEW_ONLY_LINK.with(|v| v.set(false));
        rt.shutdown().await;
    });
}

#[test]
fn a_hand_off_the_agent_never_confirms_closes_its_card_at_the_deadline() {
    local(async {
        let mut rt = Runtime::start(true).await;
        let mut client = rt.client().await;
        let fake = rt.dir.path().join("fake");
        let session = rt.launch_approval_agent(&mut client, "claude", &fake).await;
        let (sid, pg) = (session.id.clone(), session.generation.clone());
        let peer = &mut rt.peer;
        peer.hello().await;
        listed(peer, &sid).await;
        open_chat(peer, "conv-1", &sid, &pg).await;
        ask(&fake, 1, npm_test());
        let request = peer.wait(|v| is_session(v, "approval_request")).await;
        let aid = request["data"]["approval_id"].as_str().unwrap().to_string();
        // The hook stops: the decision is handed over but never taken.
        std::fs::write(fake.join("stop-1"), "").unwrap();
        agent_event(&fake, "stopped 1").await;
        let request_id = uuid::Uuid::new_v4().to_string();
        let lease = peer.acquire(&sid, &pg).await;
        peer.chat(
            "submit",
            "conv-1",
            &sid,
            &pg,
            json!({"generation": pg, "lease_epoch": lease, "requestId": request_id,
                   "approval": {"approval_id": aid, "decision": "allow_once"}}),
        );
        peer.wait_from(0, |v| is_card(v, &aid, "allowed")).await;
        rt.clock
            .skip(crate::session_protocol::host::APPROVAL_HANDOFF_MS + 1);
        let peer = &mut rt.peer;
        let rid = request_id.clone();
        let done = peer
            .wait(move |v| is_chat(v, "error") && v["data"]["requestId"] == rid.as_str())
            .await;
        assert_eq!(done["data"]["code"], "outcome_unknown", "{done}");
        let at = peer.wait_from(0, |v| is_card(v, &aid, "closed")).await;
        // Closed after the remote answer: the close reason stays that one.
        assert_eq!(
            peer.seen[at]["data"]["parts"][0]["reason"],
            "answered_remote"
        );
        rt.shutdown().await;
    });
}

fn fixture_program(name: &str) -> PathBuf {
    python_ready();
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/chat")
        .join(name);
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    if perms.mode() & 0o111 != 0o111 {
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).unwrap();
    }
    path
}

fn fake_codex() -> PathBuf {
    fixture_program("fake-codex.py")
}

/// npm's `codex` stand-in: runs fake-codex.py as its child.
fn codex_wrapper() -> PathBuf {
    fake_codex();
    fixture_program("codex-wrapper.py")
}

impl Runtime {
    /// Launches Codex as the fake Codex TUI (control files in `fake`), with
    /// Atem's hooks installed in its own `CODEX_HOME` as `atem agent launch
    /// codex` installs them.
    async fn launch_fake_codex(
        &self,
        client: &mut RuntimeClient,
        fake: &Path,
        binary: &Path,
    ) -> SessionSummary {
        let home = self.dir.path().join("codex-home");
        crate::chat::codex::install(&home, &self.dir.path().join("run/approval-hook.sh")).unwrap();
        client
            .send(&ClientMsg::Launch {
                provider: "codex".into(),
                args: vec![],
                cwd: self.dir.path().to_path_buf(),
                env: LaunchEnv(vec![
                    ("PATH".into(), "/usr/bin:/bin".into()),
                    ("CODEX_CLI_BIN".into(), binary.display().to_string()),
                    ("CODEX_HOME".into(), home.display().to_string()),
                    ("FAKE_DIR".into(), fake.display().to_string()),
                ]),
                rows: 24,
                cols: 80,
            })
            .await
            .unwrap();
        let session = expect(client, |m| match m {
            RuntimeMsg::Launched { session } => Some(session),
            RuntimeMsg::Error { text, .. } => panic!("launch failed: {text}"),
            _ => None,
        })
        .await;
        agent_event(fake, "started").await;
        session
    }
}

/// Waits until the session's descriptor shows `activity`.
async fn activity_until(peer: &mut Peer, sid: &str, activity: &str) {
    tokio::time::timeout(WAIT, async {
        loop {
            if listed(peer, sid).await["activity"] == activity {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("the activity never became {activity}"));
}

#[test]
fn codex_chat_first_prompt_local_then_remote_prompts_an_interrupt_and_an_approval() {
    local(async {
        let mut rt = Runtime::start(true).await;
        let mut client = rt.client().await;
        let fake = rt.dir.path().join("fake");
        let session = rt
            .launch_fake_codex(&mut client, &fake, &fake_codex())
            .await;
        let (sid, pg) = (session.id.clone(), session.generation.clone());
        let peer = &mut rt.peer;
        peer.hello().await;
        let descriptor = listed(peer, &sid).await;
        assert_eq!(
            descriptor["capabilities"],
            json!(["terminal-v1", "chat-v1"])
        );
        assert_eq!(descriptor["activity"], "unknown");

        // Before Codex's first prompt: chat opens (status unknown, with the
        // hint) and says what it can't provide; a prompt is refused, never
        // typed.
        peer.chat("open", "conv-1", &sid, &pg, json!({}));
        let opened = peer.wait(|v| is_chat(v, "opened")).await;
        assert_eq!(opened["data"]["status"]["state"], "unknown", "{opened}");
        let detail = opened["data"]["status"]["detail"].as_str().unwrap();
        assert!(
            detail.contains("type a first prompt in the terminal"),
            "{detail}"
        );
        assert_eq!(
            opened["data"]["unavailable"],
            json!(["streaming", "reasoning", "error_details"])
        );
        let lease = peer.acquire(&sid, &pg).await;
        let request_id = uuid::Uuid::new_v4().to_string();
        let refused =
            submit_until_complete(peer, "conv-1", &sid, &pg, lease, &request_id, "too early").await;
        let refused = &refused.last().unwrap()["data"];
        assert_eq!(refused["code"], "rejected", "{refused}");
        assert!(
            refused["text"]
                .as_str()
                .unwrap()
                .contains("type a first prompt"),
            "{refused}"
        );

        // The first prompt, typed in the terminal (a local turn).
        attach_client(&mut client, &sid, 24, 80).await;
        client
            .send(&ClientMsg::input(&sid, b"local one\r"))
            .await
            .unwrap();
        agent_event(&fake, "prompt turn-1 local one").await;
        let peer = &mut rt.peer;
        peer.wait_from(0, |v| {
            is_chat(v, "message")
                && v["data"]["origin"] == "local"
                && v.to_string().contains("local one")
        })
        .await;
        activity_until(peer, &sid, "working").await;
        std::fs::write(fake.join("complete"), "").unwrap();
        agent_event(&fake, "completed turn-1").await;
        peer.wait_from(0, |v| {
            is_chat(v, "message") && v.to_string().contains("reply 1")
        })
        .await;
        activity_until(peer, &sid, "ready").await;

        // A remote prompt: pasted through the worker, accepted once the
        // hook and the rollout both named it, its reply, its completion.
        let lease = peer.acquire(&sid, &pg).await;
        let send = |peer: &mut Peer, rid: &str, text: &str| {
            peer.chat(
                "submit",
                "conv-1",
                &sid,
                &pg,
                json!({"generation": pg, "requestId": rid, "text": text, "lease_epoch": lease}),
            )
        };
        let accepted = |rid: String| {
            move |v: &Value| is_chat(v, "accepted") && v["data"]["requestId"] == rid.as_str()
        };
        let completed = |rid: String| {
            move |v: &Value| {
                (is_chat(v, "complete") || is_chat(v, "error"))
                    && v["data"]["requestId"] == rid.as_str()
            }
        };
        let r2 = uuid::Uuid::new_v4().to_string();
        let from = peer.seen.len();
        send(peer, &r2, "remote two");
        let at_accepted = peer.wait_from(from, accepted(r2.clone())).await;
        agent_event(&fake, "prompt turn-2 remote two").await;
        // The prompt's own message carries the request id (the hook and
        // the rollout both named it).
        let rid = r2.clone();
        peer.wait_from(from, move |v| {
            is_chat(v, "message")
                && v["data"]["role"] == "user"
                && v["data"]["requestId"] == rid.as_str()
        })
        .await;
        std::fs::write(fake.join("complete"), "").unwrap();
        let at_done = peer.wait_from(from, completed(r2.clone())).await;
        let done = peer.seen[at_done].clone();
        assert!(is_chat(&done, "complete"), "{done}");
        assert_eq!(done["data"]["outcome"], "done");
        assert_eq!(done["data"]["turnId"], "turn-2");
        let reply = peer.seen[from..]
            .iter()
            .position(|v| is_chat(v, "message") && v.to_string().contains("reply 2"))
            .expect("the agent's reply")
            + from;
        assert!(at_accepted < reply && reply < at_done);
        activity_until(peer, &sid, "ready").await;

        // An interrupt while a turn runs: Esc, completed at the turn's end.
        let r3 = uuid::Uuid::new_v4().to_string();
        let from = peer.seen.len();
        send(peer, &r3, "remote three");
        peer.wait_from(from, accepted(r3.clone())).await;
        activity_until(peer, &sid, "working").await;
        let interrupt = uuid::Uuid::new_v4().to_string();
        let id = peer.request(
            "submit",
            json!({"binding": peer.binding(&sid, &pg, Some(lease)),
                   "request_id": interrupt, "kind": "interrupt", "payload": {}}),
        );
        assert_eq!(peer.reply(&id).await["state"], "accepted");
        agent_event(&fake, "interrupted turn-3").await;
        let i = interrupt.clone();
        peer.wait_from(from, move |v| {
            is_session(v, "receipt")
                && v["data"]["request_id"] == i.as_str()
                && v["data"]["state"] == "completed"
        })
        .await;
        let at_done = peer.wait_from(from, completed(r3.clone())).await;
        assert_eq!(peer.seen[at_done]["data"]["outcome"], "interrupted");
        // The prompt's receipt carries the outcome too (journaled, no text).
        let id = peer.request(
            "receipt_query",
            json!({"binding": peer.binding(&sid, &pg, None), "request_ids": [r3]}),
        );
        let receipts = peer.reply(&id).await;
        assert_eq!(receipts["receipts"][0]["state"], "completed", "{receipts}");
        assert_eq!(
            receipts["receipts"][0]["detail"], "interrupted",
            "{receipts}"
        );
        activity_until(peer, &sid, "ready").await;

        // An approval in a remote turn: waiting, its card, answered from
        // chat; the turn goes on and completes.
        let r4 = uuid::Uuid::new_v4().to_string();
        let from = peer.seen.len();
        send(peer, &r4, "remote four");
        peer.wait_from(from, accepted(r4.clone())).await;
        ask(
            &fake,
            1,
            json!({"tool_name": "Bash", "tool_input": {"command": "touch made.txt"}}),
        );
        let request = peer.wait(|v| is_session(v, "approval_request")).await["data"].clone();
        let aid = request["approval_id"].as_str().unwrap().to_string();
        assert_eq!(request["summary"], "touch made.txt");
        activity_until(peer, &sid, "waiting").await;
        peer.wait_from(from, |v| is_card(v, &aid, "pending")).await;
        let answer = uuid::Uuid::new_v4().to_string();
        peer.chat(
            "submit",
            "conv-1",
            &sid,
            &pg,
            json!({"generation": pg, "lease_epoch": lease, "requestId": answer,
                   "approval": {"approval_id": aid, "decision": "allow_once"}}),
        );
        agent_event(&fake, "answer 1 allow").await;
        let peer = &mut rt.peer;
        activity_until(peer, &sid, "working").await;
        std::fs::write(fake.join("complete"), "").unwrap();
        let at_done = peer.wait_from(from, completed(r4.clone())).await;
        assert!(is_chat(&peer.seen[at_done], "complete"));
        assert!(peer.seen[from..].iter().any(|v| is_chat(v, "message")
            && v["data"]["parts"][0]["kind"] == "tool"
            && v.to_string().contains("touch made.txt")));
        activity_until(peer, &sid, "ready").await;

        // An interrupt Codex ignores: no turn end within 10 s, unknown.
        std::fs::write(fake.join("deaf"), "").unwrap();
        let lease = peer.acquire(&sid, &pg).await;
        let r5 = uuid::Uuid::new_v4().to_string();
        let from = peer.seen.len();
        peer.chat(
            "submit",
            "conv-1",
            &sid,
            &pg,
            json!({"generation": pg, "requestId": r5, "text": "remote five", "lease_epoch": lease}),
        );
        agent_event(&fake, "prompt turn-5 remote five").await;
        let peer = &mut rt.peer;
        activity_until(peer, &sid, "working").await;
        let interrupt = uuid::Uuid::new_v4().to_string();
        let id = peer.request(
            "submit",
            json!({"binding": peer.binding(&sid, &pg, Some(lease)),
                   "request_id": interrupt, "kind": "interrupt", "payload": {}}),
        );
        assert_eq!(peer.reply(&id).await["state"], "accepted");
        peer.drain(Duration::from_millis(300)).await;
        rt.clock.skip(10_001);
        let peer = &mut rt.peer;
        let unknown = final_receipt(peer, &interrupt).await;
        assert_eq!(unknown["state"], "outcome_unknown", "{unknown}");
        assert_eq!(unknown["detail"], "no interrupt observed");
        let _ = from;
        rt.shutdown().await;
    });
}

/// Local input gives a waiting Codex approval back to Codex's own dialog
/// ("no decision"): the session stays waiting until the tool runs there.
#[test]
fn codex_stays_waiting_at_its_own_dialog_after_a_release() {
    local(async {
        let mut rt = Runtime::start(true).await;
        let mut client = rt.client().await;
        let fake = rt.dir.path().join("fake");
        let session = rt
            .launch_fake_codex(&mut client, &fake, &fake_codex())
            .await;
        let sid = session.id.clone();
        rt.peer.hello().await;
        listed(&mut rt.peer, &sid).await;
        attach_client(&mut client, &sid, 24, 80).await;
        client
            .send(&ClientMsg::input(&sid, b"one\r"))
            .await
            .unwrap();
        agent_event(&fake, "prompt turn-1 one").await;
        ask(
            &fake,
            1,
            json!({"tool_name": "Bash", "tool_input": {"command": "touch one.txt"}}),
        );
        let peer = &mut rt.peer;
        peer.wait(|v| is_session(v, "approval_request")).await;
        activity_until(peer, &sid, "waiting").await;
        // typing in the terminal releases it (the key is consumed): Codex
        // shows its own dialog
        client.send(&ClientMsg::input(&sid, b"a")).await.unwrap();
        agent_event(&fake, "answer 1 none").await;
        let peer = &mut rt.peer;
        peer.drain(Duration::from_millis(500)).await;
        assert_eq!(listed(peer, &sid).await["activity"], "waiting");
        // allowed there: the tool runs (PostToolUse), working again
        client.send(&ClientMsg::input(&sid, b"y")).await.unwrap();
        agent_event(&fake, "dialog 1 allow").await;
        activity_until(&mut rt.peer, &sid, "working").await;
        rt.shutdown().await;
    });
}

/// Codex behind npm's wrapper (the agent is the wrapper, the real binary
/// its child): `/new` re-pins chat and approvals, and remote prompts and
/// approvals go on in the new session.
#[test]
fn codex_behind_a_wrapper_keeps_chat_and_approvals_across_new() {
    local(async {
        let mut rt = Runtime::start(true).await;
        let mut client = rt.client().await;
        let fake = rt.dir.path().join("fake");
        let session = rt
            .launch_fake_codex(&mut client, &fake, &codex_wrapper())
            .await;
        let (sid, pg) = (session.id.clone(), session.generation.clone());
        rt.peer.hello().await;
        listed(&mut rt.peer, &sid).await;
        open_chat_any(&mut rt.peer, "conv-1", &sid, &pg).await;
        attach_client(&mut client, &sid, 24, 80).await;
        client
            .send(&ClientMsg::input(&sid, b"one\r"))
            .await
            .unwrap();
        agent_event(&fake, "prompt turn-1 one").await;
        // an approval in the first session (pins the approvals through the
        // wrapper)
        ask(
            &fake,
            1,
            json!({"tool_name": "Bash", "tool_input": {"command": "touch one.txt"}}),
        );
        let peer = &mut rt.peer;
        let request = peer.wait(|v| is_session(v, "approval_request")).await["data"].clone();
        let aid = request["approval_id"].as_str().unwrap().to_string();
        activity_until(peer, &sid, "waiting").await;
        let lease = peer.acquire(&sid, &pg).await;
        let id = peer.request(
            "submit",
            json!({"binding": peer.binding(&sid, &pg, Some(lease)), "request_id": uuid::Uuid::new_v4().to_string(),
                   "kind": "approval", "payload": {"approval_id": aid, "decision": "allow_once"}}),
        );
        peer.reply(&id).await;
        agent_event(&fake, "answer 1 allow").await;
        std::fs::write(fake.join("complete"), "").unwrap();
        agent_event(&fake, "completed turn-1").await;
        activity_until(&mut rt.peer, &sid, "ready").await;
        // /new, then a prompt typed in the new session
        client
            .send(&ClientMsg::input(&sid, b"/new\r"))
            .await
            .unwrap();
        client
            .send(&ClientMsg::input(&sid, b"two\r"))
            .await
            .unwrap();
        agent_event(&fake, "prompt turn-2 two").await;
        let peer = &mut rt.peer;
        peer.wait_from(0, |v| {
            is_chat(v, "message")
                && v["data"]["origin"] == "local"
                && v.to_string().contains("\"two\"")
        })
        .await;
        activity_until(peer, &sid, "working").await;
        std::fs::write(fake.join("complete"), "").unwrap();
        agent_event(&fake, "completed turn-2").await;
        let peer = &mut rt.peer;
        activity_until(peer, &sid, "ready").await;
        // a remote prompt in the new session: accepted, completed
        let lease = peer.acquire(&sid, &pg).await;
        let rid = uuid::Uuid::new_v4().to_string();
        let from = peer.seen.len();
        peer.chat(
            "submit",
            "conv-1",
            &sid,
            &pg,
            json!({"generation": pg, "requestId": rid, "text": "three", "lease_epoch": lease}),
        );
        let r = rid.clone();
        peer.wait_from(from, move |v| {
            is_chat(v, "message")
                && v["data"]["role"] == "user"
                && v["data"]["requestId"] == r.as_str()
        })
        .await;
        // and an approval of the new session: reported, waiting
        ask(
            &fake,
            2,
            json!({"tool_name": "Bash", "tool_input": {"command": "touch three.txt"}}),
        );
        let peer = &mut rt.peer;
        let request = peer
            .wait_from(from, |v| is_session(v, "approval_request"))
            .await;
        let aid = peer.seen[request]["data"]["approval_id"]
            .as_str()
            .unwrap()
            .to_string();
        activity_until(peer, &sid, "waiting").await;
        let id = peer.request(
            "submit",
            json!({"binding": peer.binding(&sid, &pg, Some(lease)), "request_id": uuid::Uuid::new_v4().to_string(),
                   "kind": "approval", "payload": {"approval_id": aid, "decision": "deny"}}),
        );
        peer.reply(&id).await;
        agent_event(&fake, "answer 2 deny").await;
        let peer = &mut rt.peer;
        activity_until(peer, &sid, "working").await;
        std::fs::write(fake.join("complete"), "").unwrap();
        let r = rid.clone();
        let done = peer
            .wait_from(from, move |v| {
                (is_chat(v, "complete") || is_chat(v, "error"))
                    && v["data"]["requestId"] == r.as_str()
            })
            .await;
        assert!(is_chat(&peer.seen[done], "complete"), "{}", peer.seen[done]);
        assert_eq!(peer.seen[done]["data"]["turnId"], "turn-3");
        rt.shutdown().await;
    });
}

/// Opens `conversation` (any status).
async fn open_chat_any(peer: &mut Peer, conversation: &str, sid: &str, pg: &str) -> Value {
    let from = peer.seen.len();
    peer.chat("open", conversation, sid, pg, json!({}));
    let c = conversation.to_string();
    let at = peer
        .wait_from(from, move |v| {
            is_chat(v, "opened") && v["data"]["conversationId"] == c.as_str()
        })
        .await;
    peer.seen[at].clone()
}

/// Atem session rules (§6a r7.2): a Codex card's "Always allow this
/// command" keeps a rule in the worker; the same command then runs with no
/// approval (an `auto_allowed` card), the rule is listed in session-v1 and
/// chat-v1 until it is revoked from chat; an interrupt that only hands a
/// waiting approval to Codex's dialog says so.
#[test]
fn codex_session_rules_allow_the_same_command_until_revoked() {
    local(async {
        let mut rt = Runtime::start(true).await;
        let mut client = rt.client().await;
        let fake = rt.dir.path().join("fake");
        let session = rt
            .launch_fake_codex(&mut client, &fake, &fake_codex())
            .await;
        let (sid, pg) = (session.id.clone(), session.generation.clone());
        rt.peer.hello().await;
        listed(&mut rt.peer, &sid).await;
        attach_client(&mut client, &sid, 24, 80).await;
        client
            .send(&ClientMsg::input(&sid, b"one\r"))
            .await
            .unwrap();
        agent_event(&fake, "prompt turn-1 one").await;
        let peer = &mut rt.peer;
        peer.chat("open", "conv-1", &sid, &pg, json!({}));
        let opened = peer.wait(|v| is_chat(v, "opened")).await;
        assert_eq!(opened["data"]["approvalRules"], json!([]));

        // The card offers a session rule; allow_always keeps it.
        let touch = json!({"tool_name": "Bash", "tool_input": {"command": "touch a.txt"}});
        ask(&fake, 1, touch.clone());
        let request = peer.wait(|v| is_session(v, "approval_request")).await["data"].clone();
        let aid = request["approval_id"].as_str().unwrap().to_string();
        let rule = request["always_rules"][0].clone();
        assert_eq!(rule["scope"], "session", "{request}");
        assert!(
            rule["label"]
                .as_str()
                .unwrap()
                .starts_with("Always allow `touch a.txt` in "),
            "{rule}"
        );
        let rule_id = rule["rule_id"].as_str().unwrap().to_string();
        let from = peer.seen.len();
        let lease = peer.acquire(&sid, &pg).await;
        peer.chat(
            "submit",
            "conv-1",
            &sid,
            &pg,
            json!({"generation": pg, "lease_epoch": lease, "requestId": uuid::Uuid::new_v4().to_string(),
                   "approval": {"approval_id": aid, "decision": "allow_always",
                                "rule_id": rule_id}}),
        );
        agent_event(&fake, "answer 1 allow").await;
        let peer = &mut rt.peer;
        let r = rule_id.clone();
        let listed_rules = peer
            .wait_from(from, move |v| {
                is_session(v, "approval_rules") && v["data"]["rules"][0]["rule_id"] == r.as_str()
            })
            .await;
        assert_eq!(peer.seen[listed_rules]["data"]["process_gen"], pg.as_str());
        let r = rule_id.clone();
        peer.wait_from(from, move |v| {
            is_chat(v, "rules") && v["data"]["approvalRules"][0]["rule_id"] == r.as_str()
        })
        .await;

        // The same command again: allowed by the worker, no approval.
        let from = peer.seen.len();
        ask(&fake, 2, touch.clone());
        agent_event(&fake, "answer 2 allow").await;
        let peer = &mut rt.peer;
        let r = rule_id.clone();
        let card = peer
            .wait_from(from, move |v| {
                is_chat(v, "message")
                    && v["data"]["parts"][0]["state"] == "auto_allowed"
                    && v["data"]["parts"][0]["rule_id"] == r.as_str()
            })
            .await;
        assert_eq!(
            peer.seen[card]["data"]["parts"][0]["summary"],
            "touch a.txt"
        );
        peer.drain(Duration::from_millis(300)).await;
        assert!(
            !peer.seen[from..]
                .iter()
                .any(|v| is_session(v, "approval_request") || v["type"] == "relay"),
            "no approval and no push for an auto-allowed request"
        );
        // A new conversation lists the rule.
        peer.chat("open", "conv-2", &sid, &pg, json!({}));
        let opened = peer
            .wait(|v| is_chat(v, "opened") && v["data"]["conversationId"] == "conv-2")
            .await;
        assert_eq!(
            opened["data"]["approvalRules"][0]["rule_id"],
            rule_id.as_str()
        );

        // The broker restarts: the worker kept the rule, the new broker
        // lists it after the snapshot and it still allows the command.
        drop(client);
        let dir = rt.shutdown().await;
        let mut rt = Runtime::start_in(dir, "rt2.sock").await;
        let peer = &mut rt.peer;
        peer.hello().await;
        let from = peer.seen.len();
        listed(peer, &sid).await;
        let r = rule_id.clone();
        peer.wait_from(from, move |v| {
            is_session(v, "approval_rules") && v["data"]["rules"][0]["rule_id"] == r.as_str()
        })
        .await;
        peer.chat("open", "conv-3", &sid, &pg, json!({}));
        let opened = peer
            .wait(|v| is_chat(v, "opened") && v["data"]["conversationId"] == "conv-3")
            .await;
        assert_eq!(
            opened["data"]["approvalRules"][0]["rule_id"],
            rule_id.as_str()
        );
        let from = peer.seen.len();
        ask(&fake, 4, touch.clone());
        agent_event(&fake, "answer 4 allow").await;
        let peer = &mut rt.peer;
        let r = rule_id.clone();
        peer.wait_from(from, move |v| {
            is_chat(v, "message")
                && v["data"]["parts"][0]["state"] == "auto_allowed"
                && v["data"]["parts"][0]["rule_id"] == r.as_str()
        })
        .await;

        // Revoked from chat without the lease (r7.3: `control` is enough;
        // no lease is held after the restart): completed, the list empties,
        // and still no lease is held.
        let revoke = uuid::Uuid::new_v4().to_string();
        let from = peer.seen.len();
        peer.chat(
            "submit",
            "conv-1",
            &sid,
            &pg,
            json!({"generation": pg, "requestId": revoke,
                   "approval_rule_revoke": {"rule_id": rule_id}}),
        );
        let rv = revoke.clone();
        peer.wait_from(from, move |v| {
            is_chat(v, "complete") && v["data"]["requestId"] == rv.as_str()
        })
        .await;
        peer.wait_from(from, |v| {
            is_session(v, "approval_rules") && v["data"]["rules"] == json!([])
        })
        .await;
        assert!(
            !peer.seen[from..]
                .iter()
                .any(|v| is_session(v, "lease") || is_session(v, "lease_changed")),
            "a revoke never takes or moves the lease"
        );
        let lease = peer.acquire(&sid, &pg).await;

        // The worker stops allowing at once: the same command asks again; an interrupt now only hands the
        // waiting approval to Codex's dialog, and says so.
        ask(&fake, 5, touch);
        let peer = &mut rt.peer;
        let from = peer.seen.len();
        peer.wait_from(from, |v| is_session(v, "approval_request"))
            .await;
        activity_until(peer, &sid, "waiting").await;
        let interrupt = uuid::Uuid::new_v4().to_string();
        let id = peer.request(
            "submit",
            json!({"binding": peer.binding(&sid, &pg, Some(lease)),
                   "request_id": interrupt, "kind": "interrupt", "payload": {}}),
        );
        assert_eq!(peer.reply(&id).await["state"], "accepted");
        let rejected = final_receipt(peer, &interrupt).await;
        assert_eq!(rejected["state"], "rejected", "{rejected}");
        assert_eq!(
            rejected["detail"],
            "the approval was handed to the terminal; interrupt again to stop the turn"
        );
        agent_event(&fake, "answer 5 none").await;
        rt.shutdown().await;
    });
}

/// A session rule outlives a broker restart only under the same identity
/// and trust: after `atem unpair` then `atem pair` (a new trust generation)
/// or under another account, the new broker drops the adopted worker's rule
/// and the same command asks again.
#[test]
fn adopted_session_rules_of_another_identity_or_trust_are_dropped() {
    for change in ["trust", "account"] {
        local(adopted_rules_dropped_after(change));
    }
}

async fn adopted_rules_dropped_after(change: &str) {
    let mut rt = Runtime::start(true).await;
    let mut client = rt.client().await;
    let fake = rt.dir.path().join("fake");
    let session = rt
        .launch_fake_codex(&mut client, &fake, &fake_codex())
        .await;
    let (sid, pg) = (session.id.clone(), session.generation.clone());
    rt.peer.hello().await;
    listed(&mut rt.peer, &sid).await;
    attach_client(&mut client, &sid, 24, 80).await;
    client
        .send(&ClientMsg::input(&sid, b"one\r"))
        .await
        .unwrap();
    agent_event(&fake, "prompt turn-1 one").await;
    let peer = &mut rt.peer;
    peer.chat("open", "conv-1", &sid, &pg, json!({}));
    peer.wait(|v| is_chat(v, "opened")).await;
    let touch = json!({"tool_name": "Bash", "tool_input": {"command": "touch a.txt"}});
    ask(&fake, 1, touch.clone());
    let request = peer.wait(|v| is_session(v, "approval_request")).await["data"].clone();
    let aid = request["approval_id"].as_str().unwrap().to_string();
    let rule_id = request["always_rules"][0]["rule_id"]
        .as_str()
        .unwrap()
        .to_string();
    let from = peer.seen.len();
    let lease = peer.acquire(&sid, &pg).await;
    peer.chat(
        "submit",
        "conv-1",
        &sid,
        &pg,
        json!({"generation": pg, "lease_epoch": lease, "requestId": uuid::Uuid::new_v4().to_string(),
               "approval": {"approval_id": aid, "decision": "allow_always",
                            "rule_id": rule_id}}),
    );
    agent_event(&fake, "answer 1 allow").await;
    let peer = &mut rt.peer;
    let r = rule_id.clone();
    peer.wait_from(from, move |v| {
        is_session(v, "approval_rules") && v["data"]["rules"][0]["rule_id"] == r.as_str()
    })
    .await;

    // The broker stops; the profile changes; a new broker adopts the worker.
    drop(client);
    let dir = rt.shutdown().await;
    let profile = dir.path().join("profile");
    match change {
        "trust" => crate::pairing::tests::write_bound(
            &profile,
            ASTATION,
            TRUST_GEN + 1,
            "binding-2",
            ("session-1", "token-1"),
        ),
        _ => {
            let path = crate::paths::CredPaths::in_dir(&profile).trust;
            let mut state: Value =
                serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
            state["astations"][ASTATION]["data_account"] = json!("account-other");
            state["astations"][ASTATION]["device_id"] = json!("device-other");
            std::fs::write(&path, state.to_string()).unwrap();
        }
    }
    let mut rt = Runtime::start_in(dir, "rt2.sock").await;
    let peer = &mut rt.peer;
    let welcome = peer.hello().await;
    match change {
        "trust" => assert_eq!(welcome["host_trust_gen"], TRUST_GEN + 1, "{welcome}"),
        _ => assert_eq!(welcome["account_id"], "account-other", "{welcome}"),
    }
    listed(peer, &sid).await;
    // The same command asks: no auto-allow, and the rule is gone.
    let from = peer.seen.len();
    ask(&fake, 2, touch);
    let peer = &mut rt.peer;
    let at = peer
        .wait_from(from, |v| {
            is_session(v, "approval_request")
                || (is_chat(v, "message") && v["data"]["parts"][0]["state"] == "auto_allowed")
        })
        .await;
    assert!(
        is_session(&peer.seen[at], "approval_request"),
        "{}",
        peer.seen[at]
    );
    peer.drain(Duration::from_millis(300)).await;
    let r = rule_id.clone();
    assert!(
        !peer.seen[from..]
            .iter()
            .any(|v| is_session(v, "approval_rules")
                && v["data"]["rules"][0]["rule_id"] == r.as_str()),
        "the old rule is never listed"
    );
    rt.shutdown().await;
}

#[test]
fn the_revoke_log_line_names_the_rule_and_session_only() {
    assert_eq!(
        super::rule_revoked_line("ses-aaaaaaaaaaaa", "s-0123456789abcdef", true),
        "atem runtime: ses-aaaaaaaaaaaa: session rule s-0123456789abcdef revoked"
    );
    assert_eq!(
        super::rule_revoked_line("ses-aaaaaaaaaaaa", "s-0123456789abcdef", false),
        "atem runtime: ses-aaaaaaaaaaaa: session rule s-0123456789abcdef not revoked (no longer active)"
    );
}

#[test]
fn the_auto_allowed_log_line_names_the_rule_never_the_command() {
    let line = super::auto_allowed_line("ses-aaaaaaaaaaaa", "Bash", "s-0123456789abcdef");
    assert_eq!(
        line,
        "atem runtime: ses-aaaaaaaaaaaa: Bash allowed by session rule s-0123456789abcdef"
    );
}

/// The worker's next session-rules report (`approval_rules`), skipping
/// other approval events.
async fn next_rules(
    sessions: &mut std::collections::BTreeMap<
        crate::session::SessionId,
        crate::runtime::broker::BrokerSession,
    >,
) -> Vec<crate::runtime::worker_protocol::HeldRule> {
    use crate::runtime::worker_approvals::Event;
    tokio::time::timeout(WAIT, async {
        loop {
            for session in sessions.values_mut() {
                session.pump();
                for event in session.take_approvals() {
                    if let Event::Rules(rules) = event {
                        return rules;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("no approval_rules")
}

/// Has the worker of the only session keep a session rule for `command`
/// (a Codex card answered `allow_always`, the `n`th tool call).
async fn keep_a_rule(
    sessions: &mut std::collections::BTreeMap<
        crate::session::SessionId,
        crate::runtime::broker::BrokerSession,
    >,
    fake: &Path,
    n: u32,
    command: &str,
) -> String {
    use crate::runtime::worker_approvals::Event;
    ask(
        fake,
        n,
        json!({"tool_name": "Bash", "cwd": "/p", "tool_input": {"command": command}}),
    );
    let session = sessions.values_mut().next().unwrap();
    let (worker_id, rule_id) = tokio::time::timeout(WAIT, async {
        loop {
            session.pump();
            for event in session.take_approvals() {
                if let Event::Request { request_id, info } = event {
                    return (request_id, info.always_rules[0].rule_id.clone());
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("no approval request");
    session
        .approval_decision(
            &worker_id,
            crate::session_protocol::wire::ApprovalDecision::AllowAlways,
            Some((
                rule_id.clone(),
                crate::runtime::worker_protocol::RuleGrant {
                    account_id: "account-a".into(),
                    atem_device_id: "device-a".into(),
                    host_trust_gen: 1,
                },
            )),
            None,
        )
        .unwrap();
    agent_event(fake, &format!("answer {n} allow ")).await;
    let rules = next_rules(sessions).await;
    assert!(rules.iter().any(|r| r.rule.rule_id == rule_id), "{rules:?}");
    rule_id
}

/// Session rules across host rebinds: a new account/device or a new trust
/// generation makes every worker drop them all.
#[tokio::test]
async fn host_rebinds_drop_the_workers_session_rules() {
    use crate::runtime::adopt::SpawnRequest;
    let _sweep = HookSweep;
    let dir = short_dir();
    let fake = dir.path().join("fake");
    let launcher = Launcher::InProcess(InProcess {
        state: dir.path().join("state"),
        socket_dir: dir.path().join("ws"),
        chat_root: dir.path().join("chat"),
    });
    let request = SpawnRequest {
        session_id: crate::session::SessionId::new(),
        process_gen: uuid::Uuid::new_v4().to_string(),
        provider: crate::session::Provider::Codex,
        args: vec![],
        cwd: dir.path().to_path_buf(),
        rows: 24,
        cols: 80,
    };
    let hook = crate::chat::codex::hook_command(&dir.path().join("chat/approval-hook.sh"));
    let env = LaunchEnv(vec![
        ("PATH".into(), "/usr/bin:/bin".into()),
        (
            "CODEX_CLI_BIN".into(),
            approval_agent().display().to_string(),
        ),
        ("FAKE_DIR".into(), fake.display().to_string()),
        ("FAKE_CODEX_HOOK".into(), hook),
    ]);
    let (handle, created_at_ms) = launcher.spawn(request.clone(), env).await.unwrap();
    let session = crate::runtime::broker::BrokerSession::launched(handle, &request, created_at_ms);
    agent_event(&fake, "started").await;
    let mut sessions = std::collections::BTreeMap::new();
    sessions.insert(session.id.clone(), session);
    keep_a_rule(&mut sessions, &fake, 1, "npm test").await;

    let mut bridge =
        super::HostBridge::open(&dir.path().join("journal"), None, Clock::default()).unwrap();
    let client = AstationClient::new();
    // Another account and device: every rule dropped.
    let other = super::Identity {
        account_id: "account-b".into(),
        atem_device_id: "device-b".into(),
        host_trust_gen: 1,
    };
    {
        let mut cx = super::Cx {
            client: &client,
            sessions: &mut sessions,
        };
        assert!(bridge.adopt_identity(&other, &mut cx));
    }
    assert!(next_rules(&mut sessions).await.is_empty());
    assert!(
        bridge
            .host
            .approval_rules(request.session_id.as_str())
            .is_empty()
    );

    // A new trust generation under that identity: dropped as well.
    keep_a_rule(&mut sessions, &fake, 2, "make").await;
    let newer = super::Identity {
        host_trust_gen: 2,
        ..other
    };
    {
        let mut cx = super::Cx {
            client: &client,
            sessions: &mut sessions,
        };
        assert!(bridge.adopt_identity(&newer, &mut cx));
    }
    assert!(next_rules(&mut sessions).await.is_empty());
    for session in sessions.values() {
        let _ = session.stop();
    }
}

// ── Refusal lines in runtime.log ──

const MARKER: &str = "SECRET-MARKER-7f3a";

/// The refusal lines written on this thread so far.
fn refusal_lines() -> Vec<String> {
    super::refusal_log::WRITTEN.with(|w| w.borrow().clone())
}

/// Waits until a refusal line `pick` accepts was written; that line.
async fn refusal_line(pick: impl Fn(&str) -> bool) -> String {
    tokio::time::timeout(WAIT, async {
        loop {
            if let Some(line) = refusal_lines().into_iter().find(|l| pick(l)) {
                return line;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or_else(|_| panic!("no such refusal line; written: {:#?}", refusal_lines()))
}

#[test]
fn refused_requests_are_logged_by_family_op_and_code_without_their_content() {
    local(async {
        super::refusal_log::WRITTEN.with(|w| w.borrow_mut().clear());
        let mut rt = Runtime::start(true).await;
        let mut client = rt.client().await;
        let agent = echo_agent(rt.dir.path());
        let session = rt.launch(&mut client, "codex", &agent, None).await;
        let (sid, pg) = (session.id.clone(), session.generation.clone());
        let peer = &mut rt.peer;
        peer.hello().await;

        // A chat-v1 revoke of the wrong shape: a decode failure whose serde
        // error names the field (and would echo values).
        peer.chat(
            "submit",
            "conv-1",
            &sid,
            &pg,
            json!({"generation": pg, "requestId": uuid::Uuid::new_v4().to_string(),
                   "approval_rule_revoke": {"rule": MARKER}}),
        );
        let line = refusal_line(|l| l.contains("refused agentChat/submit")).await;
        assert_eq!(
            line,
            format!(
                "atem runtime: refused agentChat/submit kind=approval_rule_revoke \
                 unsupported_version session={sid} \
                 (decode: agentChat: approval_rule_revoke: unknown field `rule`)"
            )
        );

        // A session-v1 submit whose kind is a value serde would echo.
        let id = peer.request(
            "submit",
            json!({"binding": peer.binding(&sid, &pg, None),
                   "request_id": uuid::Uuid::new_v4().to_string(),
                   "kind": MARKER, "payload": {"text": MARKER}}),
        );
        assert_eq!(peer.reply(&id).await["code"], "unsupported_version");
        let line = refusal_line(|l| l.contains("refused session/submit")).await;
        assert_eq!(
            line,
            format!(
                "atem runtime: refused session/submit unsupported_version session={sid} \
                 (decode: unknown variant)"
            )
        );

        // A session-v1 revoke whose payload has the wrong shape.
        let id = peer.request(
            "submit",
            json!({"binding": peer.binding(&sid, &pg, None),
                   "request_id": uuid::Uuid::new_v4().to_string(),
                   "kind": "approval_rule_revoke", "payload": {"rule": MARKER}}),
        );
        let reply = peer.reply(&id).await;
        let code = match reply["op"].as_str() {
            Some("error") => reply["code"].as_str().unwrap().to_string(),
            _ => reply["state"].as_str().unwrap().to_string(),
        };
        let line = refusal_line(|l| {
            l.contains("kind=approval_rule_revoke") && l.contains("session/submit")
        })
        .await;
        assert!(
            line.starts_with(&format!(
                "atem runtime: refused session/submit kind=approval_rule_revoke {code} session={sid}"
            )),
            "{line}"
        );

        // A terminal-v1 subscribe to another process generation.
        let other = uuid::Uuid::new_v4().to_string();
        peer.terminal("subscribe", &sid, &other, json!({}), None);
        let line = refusal_line(|l| l.contains("refused terminal/subscribe")).await;
        assert_eq!(
            line,
            format!("atem runtime: refused terminal/subscribe stale_target session={sid}")
        );

        for line in refusal_lines() {
            assert!(!line.contains(MARKER), "{line}");
            assert!(!line.contains('{'), "{line}");
        }
        rt.shutdown().await;
    });
}

#[test]
fn a_link_without_an_attachment_logs_its_refusals() {
    local(async {
        super::refusal_log::WRITTEN.with(|w| w.borrow_mut().clear());
        let mut rt = Runtime::start(false).await;
        let peer = &mut rt.peer;
        let id = uuid::Uuid::new_v4().to_string();
        peer.send(json!({"type":"session","data":{"v":1,"op":"list","id":id,"x":MARKER}}));
        assert_eq!(peer.reply(&id).await["code"], "unauthorized");
        let line = refusal_line(|l| l.contains("refused session/")).await;
        assert_eq!(
            line,
            "atem runtime: refused session/list unauthorized (no attachment)"
        );
        assert!(refusal_lines().iter().all(|l| !l.contains(MARKER)));
        rt.shutdown().await;
    });
}

#[test]
fn a_looping_client_gets_twenty_refusal_lines_per_window_and_a_summary() {
    local(async {
        super::refusal_log::WRITTEN.with(|w| w.borrow_mut().clear());
        let mut rt = Runtime::start(true).await;
        let peer = &mut rt.peer;
        peer.hello().await;
        let mut last = String::new();
        for _ in 0..35 {
            last = uuid::Uuid::new_v4().to_string();
            peer.send(json!({"type":"session","data":{"v":2,"op":"list","id":last,"x":MARKER}}));
        }
        peer.reply(&last).await;
        let refused = |lines: &[String]| lines.iter().filter(|l| l.contains("refused ")).count();
        assert_eq!(refused(&refusal_lines()), 20, "{:#?}", refusal_lines());
        assert!(!refusal_lines().iter().any(|l| l.contains("suppressed")));
        // The window ends: one summary line for the other 15.
        rt.clock.skip(super::refusal_log::WINDOW_MS);
        let line = refusal_line(|l| l.contains("suppressed")).await;
        assert_eq!(line, "atem runtime: \u{2026} 15 more refusals suppressed");
        assert_eq!(refused(&refusal_lines()), 20);
        rt.shutdown().await;
    });
}

// ── receipt result replies (r8 §D) ──

fn message(
    id: &str,
    role: crate::chat::session::Role,
    turn: &str,
) -> crate::chat::session::ChatMessage {
    crate::chat::session::ChatMessage {
        message_id: id.into(),
        role,
        origin: None,
        turn_id: turn.into(),
        request_id: None,
        created_at_ms: 0,
        parts: vec![crate::chat::adapter::Part::Text {
            id: "text".into(),
            markdown: "x".into(),
        }],
    }
}

fn chat_with(history: Vec<crate::chat::session::ChatMessage>) -> crate::chat::session::ChatSession {
    let mut snapshot = crate::chat::session::ChatSession::new("g".into(), 0).snapshot(0, 0);
    snapshot.history = history;
    crate::chat::session::ChatSession::restore("g".into(), snapshot)
}

/// A turn's replies from the retained history: its assistant messages
/// without cards, timeline order; complete while its user message is
/// retained, partial once it was evicted (or an id can't be named),
/// unavailable when nothing of the turn is left.
#[test]
fn turn_replies_follow_the_retained_history() {
    use crate::chat::adapter::{ApprovalCard, ApprovalCardState, Part};
    use crate::chat::session::{MAX_HISTORY_MESSAGES, Role};
    use crate::session_protocol::wire::Coverage;
    let mut card = message("approval-a1", Role::Assistant, "t7");
    card.parts = vec![Part::Approval(ApprovalCard {
        id: "approval".into(),
        approval_id: "a1".into(),
        tool: "Bash".into(),
        summary: "ls".into(),
        always_rules: Vec::new(),
        state: ApprovalCardState::Pending,
        rule_id: None,
        note: None,
        reason: None,
    })];
    let history = vec![
        message("t6-u", Role::User, "t6"),
        message("t6-a", Role::Assistant, "t6"),
        message("t7-u", Role::User, "t7"),
        message("t7-a-1", Role::Assistant, "t7"),
        card,
        message("t7-a-2", Role::Assistant, "t7"),
    ];
    let chat = chat_with(history.clone());
    let r = crate::chat::history::turn_replies(&chat, "t7", "t7-u");
    assert_eq!(r.ids, vec!["t7-a-1", "t7-a-2"]);
    assert_eq!(r.coverage, Coverage::Complete);
    assert_eq!(
        crate::chat::history::turn_replies(&chat, "t9", "t9-u").coverage,
        Coverage::Unavailable
    );

    // Late content shows; an id that can't be named makes it partial.
    let mut more = history.clone();
    more.push(message("t7-a-3", Role::Assistant, "t7"));
    more.push(message("t7 bad", Role::Assistant, "t7"));
    let r = crate::chat::history::turn_replies(&chat_with(more), "t7", "t7-u");
    assert_eq!(r.ids, vec!["t7-a-1", "t7-a-2", "t7-a-3"]);
    assert_eq!(r.coverage, Coverage::Partial);

    // Eviction (oldest first): the user message and the first reply go.
    let mut long = vec![
        message("t7-u", Role::User, "t7"),
        message("t7-a-1", Role::Assistant, "t7"),
    ];
    for i in 0..MAX_HISTORY_MESSAGES {
        long.push(message(&format!("t7-b-{i}"), Role::Assistant, "t7"));
    }
    let chat = chat_with(long);
    let r = crate::chat::history::turn_replies(&chat, "t7", "t7-u");
    assert_eq!(r.ids.len(), MAX_HISTORY_MESSAGES);
    assert_eq!(r.ids[0], "t7-b-0");
    assert_eq!(r.coverage, Coverage::Partial);
}

async fn status(client: &mut RuntimeClient) -> crate::runtime::protocol::RuntimeStatus {
    client.send(&ClientMsg::Status).await.unwrap();
    expect(client, |m| match m {
        RuntimeMsg::Status { status } => Some(status),
        _ => None,
    })
    .await
}

/// The runtime's `status` (`atem status`): the link, its attachment, the
/// last refused `hello` and the welcome with what is left of its
/// authorization.
#[test]
fn status_reports_the_attachment_its_refusals_and_its_welcome() {
    local(async {
        let mut rt = Runtime::start(true).await;
        let mut client = rt.client().await;
        // Wait for the broker to consider the link.
        let mut first = status(&mut client).await;
        while !first.attachment {
            tokio::time::sleep(Duration::from_millis(20)).await;
            first = status(&mut client).await;
        }
        assert!(first.astation && first.welcomed.is_none() && first.refused.is_none());
        assert!(!first.journal_halted && first.host_error.is_none());
        // A hello of revision 7 is refused and remembered.
        let id = rt.peer.request("hello", json!({"revision": 7}));
        assert_eq!(rt.peer.reply(&id).await["code"], "unsupported_version");
        let refused = status(&mut client).await;
        let refusal = refused.refused.expect("the refusal is reported");
        assert_eq!((refusal.revision, refusal.needs), (Some(7), 8));
        assert!(refused.welcomed.is_none());
        // A welcome clears it and reports the revision and time left.
        rt.peer.hello().await;
        rt.clock.skip(3_600_000);
        let welcomed = status(&mut client).await;
        assert!(welcomed.refused.is_none());
        let welcome = welcomed.welcomed.expect("the welcome is reported");
        assert_eq!(welcome.revision, 8);
        let left = super::LINK_AUTHORIZATION_MS - 3_600_000;
        assert!(
            welcome.ms_left <= left && welcome.ms_left > left - 10_000,
            "{}",
            welcome.ms_left
        );
        assert!(welcome.at_ms > 0);
        rt.shutdown().await;
    });
}

#[test]
fn the_welcome_line_names_the_trust_generation() {
    assert_eq!(
        super::welcome_line(None, "a1b2c3d4", 5),
        "welcome (attachment a1b2c3d4, trust gen 5)"
    );
    assert_eq!(
        super::welcome_line(Some(("a1b2c3d4", "e5f6a7b8")), "e5f6a7b8", 6),
        "replaced attachment a1b2c3d4 with e5f6a7b8; welcome (trust gen 6)"
    );
}

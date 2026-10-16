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

/// Unix socket paths are limited to ~100 bytes; keep them short.
fn short_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("atem-hb")
        .tempdir_in("/tmp")
        .unwrap()
}

/// `body` on a current-thread runtime with a `LocalSet` (the App stays on one task).
fn local<F: std::future::Future>(body: F) -> F::Output {
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

fn fake_claude() -> PathBuf {
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
    std::fs::write(
        dir.join("pairing.json"),
        json!({"version":1,"host_trust_gen":TRUST_GEN,"binding_id":"binding-1",
               "astation_id":ASTATION,"created_at":1})
        .to_string(),
    )
    .unwrap();
    if verified {
        let entry = json!({
            "device_id": DEVICE, "data_account": ACCOUNT, "sign_gen": 1,
            "astation_sign_pub": "", "astation_enc_pub": "", "recovery_sign_pub": "",
            "device_pub": "", "device_sign_pub": "", "unlock_auth_pub": "",
            "safety_code": "", "epoch_floor": 0, "account_state": null, "account_epoch": 0,
        });
        std::fs::write(
            dir.join("cred_state.json"),
            json!({"version":1,"astations":{ASTATION: entry}}).to_string(),
        )
        .unwrap();
    }
    let mut sessions = crate::auth::SessionManager::default();
    sessions.insert_session(crate::auth::AuthSession::new(
        "session-1".into(),
        "token-1".into(),
        ASTATION.into(),
        "test-machine".into(),
    ));
    sessions.save_to(&dir.join("sessions.json")).unwrap();
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
        let id = self.request("hello", json!({}));
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
        app.chat_root = root.join("run");
        app.logs_dir = root.join("logs");
        // Never the user's sessions.json.
        app.last_session_refresh = Some(Instant::now());
        app.astation_client = AstationClient::new_with_test_state(
            "atem-host-test",
            profile_dir.join("sessions.json"),
        );
        app.astation_client
            .connect_raw(&format!("ws://{address}"))
            .await
            .unwrap();
        // The connect-time authentication is covered by websocket_client tests.
        app.astation_client.pin_astation_for_test(ASTATION);
        app.astation_connected = true;
        app.astation_link_gen = 1;
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
            profile: Some(crate::status::Sources::in_dir(&profile_dir)),
            clock: clock.clone(),
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
        assert_eq!(
            welcome["permissions"],
            json!(["view", "control", "approve"])
        );

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
            (is_chat(v, "complete") || is_chat(v, "error"))
                && v["data"]["requestId"] == request_id
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
        // The old attachment is gone: requests naming it are refused.
        let mut stale = peer.binding(&sid, &pg, None);
        stale["attachment_gen"] = Value::String(old_attachment);
        let id = peer.request("acquire", json!({"binding": stale, "takeover": false}));
        assert_eq!(peer.reply(&id).await["code"], "stale_target");
        // The duplicate submit returns the recorded receipt; nothing is typed.
        let lease = peer.acquire(&sid, &pg).await;
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
        rt.shutdown().await;
    });
}

#[test]
fn a_link_that_is_not_a_verified_pairing_gets_no_attachment() {
    local(async {
        let mut rt = Runtime::start(false).await;
        let peer = &mut rt.peer;
        let id = peer.request("hello", json!({}));
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
            "stty -echo\nprintf 'READY\\r\\n'\nexec cat >> typed.txt",
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
        peer.hello().await;
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

        // A new attachment: hello again; the old one is gone.
        let welcome = peer.hello().await;
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

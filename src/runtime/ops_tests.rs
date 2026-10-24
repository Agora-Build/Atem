//! Astation operations in the broker, in process: a real `serve` (workers in
//! this process, fake agents) whose App links to a fake Astation WebSocket
//! peer, and a client that runs `astation_op` like the CLI does. The profile
//! and the cred agent are temp ones (`OpEnv`).
use crate::app::App;
use crate::memory::cred_agent::{CredAgentApi, test_agent};
use crate::memory::statements::{AccountState, DeviceVerified, FakeAstation, SignedWire};
use crate::memory::verification::transcript_for;
use crate::paths::CredPaths;
use crate::runtime::broker::{InProcess, Launcher};
use crate::runtime::client::RuntimeClient;
use crate::runtime::ops::{BUSY, OpEnv};
use crate::runtime::protocol::{
    AnswerValue, AskKind, ClientMsg, LaunchEnv, OpKind, OpOptions, PrintLevel, RuntimeMsg,
    SessionSummary,
};
use crate::runtime::server::{Options, serve};
use crate::websocket_client::{AstationClient, AstationMessage};
use base64::{Engine, engine::general_purpose::STANDARD};
use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::Message as WsMessage;

const ASTATION: &str = "astation-1";
const ATEM_ID: &str = "atem-op-test";
const WAIT: Duration = Duration::from_secs(20);
/// Sent to the peer task: close the WebSocket.
const CLOSE: &str = "\u{0}close";

fn short_dir() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("atem-op")
        .tempdir_in("/tmp")
        .unwrap()
}

/// `body` on a current-thread runtime with a `LocalSet` (the App stays on one task).
fn local<F: std::future::Future>(body: F) -> F::Output {
    // Never the user's profile (src/test_profile.rs).
    let profile = tempfile::tempdir().unwrap();
    let _profile = crate::test_profile::use_dir(profile.path());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    tokio::task::LocalSet::new().block_on(&runtime, body)
}

/// Echoes its input (the PTY echo is off; `cat` writes it back).
fn echo_agent(dir: &Path) -> PathBuf {
    let path = dir.join("echo-agent");
    std::fs::write(
        &path,
        "#!/bin/sh\nstty -echo\nprintf 'READY\\r\\n'\nexec cat\n",
    )
    .unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path
}

/// A pairing with `ASTATION` (binding and saved session), not verified.
fn paired(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    crate::pairing::tests::write_bound(dir, ASTATION, 3, "binding-1", ("session-1", "token-1"));
}

/// The shared tokens of the profile at `dir`, when fresh.
fn fresh_shared(dir: &Path) -> Option<crate::records::Tokens> {
    crate::sso_auth::fresh_shared(
        &crate::paths::ProfilePaths::in_dir(dir).pairing,
        "https://sso2.agora.io",
        ASTATION,
    )
}

/// The pairing record of the profile at `dir`.
fn record(dir: &Path) -> crate::records::PairingRecord {
    crate::records::PairingRecord::load(&crate::paths::ProfilePaths::in_dir(dir).pairing)
        .unwrap()
        .unwrap()
}

/// The Astation end of a link.
struct Peer {
    to_atem: mpsc::UnboundedSender<String>,
    from_atem: mpsc::UnboundedReceiver<Value>,
    seen: Vec<Value>,
    closed: bool,
    /// From the session-v1 welcome.
    welcome: Value,
    /// The viewer's screen: frames applied up to `view_at`.
    view: vt100::Parser,
    view_at: usize,
}

impl Peer {
    /// A WebSocket listener for one connection; its URL.
    async fn listen() -> (String, Self) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (to_atem, mut outgoing) = mpsc::unbounded_channel::<String>();
        let (incoming, from_atem) = mpsc::unbounded_channel::<Value>();
        tokio::task::spawn_local(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            loop {
                tokio::select! {
                    message = outgoing.recv() => {
                        let Some(text) = message else { break };
                        if text == CLOSE {
                            let _ = socket.close(None).await;
                            break;
                        }
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
        let peer = Self {
            to_atem,
            from_atem,
            seen: Vec::new(),
            closed: false,
            welcome: Value::Null,
            view: vt100::Parser::new(24, 80, 0),
            view_at: 0,
        };
        (format!("ws://{address}/ws"), peer)
    }

    fn send(&self, message: &AstationMessage) {
        self.to_atem
            .send(serde_json::to_string(message).unwrap())
            .unwrap();
    }

    fn send_json(&self, message: Value) {
        self.to_atem.send(message.to_string()).unwrap();
    }

    fn close(&self) {
        let _ = self.to_atem.send(CLOSE.into());
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

    /// The next message (from now) of wire type `kind`.
    async fn next(&mut self, kind: &str) -> Value {
        let from = self.seen.len();
        let at = self.wait_from(from, |v| v["type"] == kind).await;
        self.seen[at].clone()
    }

    /// Everything received within `time`; whether the link closed.
    async fn drain(&mut self, time: Duration) -> bool {
        let deadline = tokio::time::Instant::now() + time;
        loop {
            match tokio::time::timeout_at(deadline, self.from_atem.recv()).await {
                Ok(Some(message)) => self.seen.push(message),
                Ok(None) => {
                    self.closed = true;
                    return true;
                }
                Err(_) => return self.closed,
            }
        }
    }

    /// A session-v1 request; its id.
    fn request(&self, op: &str, fields: Value) -> String {
        let id = uuid::Uuid::new_v4().to_string();
        let mut data = json!({"v": 1, "op": op, "id": id});
        for (k, v) in fields.as_object().unwrap() {
            data[k] = v.clone();
        }
        self.send_json(json!({"type": "session", "data": data}));
        id
    }

    async fn reply(&mut self, id: &str) -> Value {
        let at = self
            .wait_from(0, |v| v["type"] == "session" && v["data"]["re"] == id)
            .await;
        self.seen[at]["data"].clone()
    }

    /// session-v1 hello; the welcome (or the error).
    async fn hello(&mut self) -> Value {
        let id = self.request("hello", json!({"revision": 8}));
        let reply = self.reply(&id).await;
        if reply["op"] == "welcome" {
            self.welcome = reply.clone();
        }
        reply
    }

    fn binding(&self, sid: &str, process_gen: &str) -> Value {
        json!({
            "target": {"account_id": self.welcome["account_id"],
                       "atem_device_id": self.welcome["atem_device_id"],
                       "host_trust_gen": self.welcome["host_trust_gen"],
                       "session_id": sid, "process_gen": process_gen},
            "attachment_gen": self.welcome["attachment_gen"],
        })
    }

    /// Subscribes to `sid`'s terminal and waits until its screen shows `text`.
    async fn subscribe_until(&mut self, sid: &str, process_gen: &str, text: &str) {
        self.send_json(json!({"type": "terminal", "data": {
            "v": 1, "op": "subscribe", "terminal_id": sid, "generation": process_gen,
            "binding": self.binding(sid, process_gen)}}));
        self.frames_until(sid, text).await;
    }

    /// Applies `sid`'s frames (acknowledging each) until the viewer's
    /// screen shows `text`.
    async fn frames_until(&mut self, sid: &str, text: &str) {
        tokio::time::timeout(WAIT, async {
            loop {
                if self.view.screen().contents().contains(text) {
                    return;
                }
                let at = self
                    .wait_from(self.view_at, |v| {
                        v["type"] == "terminal"
                            && v["data"]["op"] == "frame"
                            && v["data"]["terminal_id"] == sid
                    })
                    .await;
                let frame = self.seen[at]["data"].clone();
                self.view_at = at + 1;
                if frame["reset"] == true {
                    self.view = vt100::Parser::new(
                        frame["rows"].as_u64().unwrap() as u16,
                        frame["cols"].as_u64().unwrap() as u16,
                        0,
                    );
                }
                let bytes = STANDARD.decode(frame["bytes"].as_str().unwrap()).unwrap();
                self.view.process(&bytes);
                let offset = frame["offset"].as_u64().unwrap() + bytes.len() as u64;
                let generation = frame["generation"].clone();
                let process_gen = generation.as_str().unwrap_or_default().to_string();
                self.send_json(json!({"type": "terminal", "data": {
                    "v": 1, "op": "ack", "terminal_id": sid, "generation": process_gen,
                    "binding": self.binding(sid, &process_gen),
                    "stream_id": frame["stream_id"], "offset": offset}}));
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{text:?} never appeared"));
    }
}

/// Astation's side of a device verification.
struct Verifier {
    fake: FakeAstation,
    commitment: [u8; 32],
    device_id: String,
    nonce_s: [u8; 32],
    account: String,
}

impl Verifier {
    /// Waits for `verifyCommit`, answers with `verifyKeys`.
    async fn keys(peer: &mut Peer, account: &str) -> Self {
        let commit = peer.next("verifyCommit").await;
        let commitment: [u8; 32] = STANDARD
            .decode(commit["data"]["commitment"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        let fake = FakeAstation::new();
        let nonce_s = [7u8; 32];
        peer.send(&AstationMessage::VerifyKeys {
            sign_pub: STANDARD.encode(fake.sign_pub()),
            enc_pub: STANDARD.encode(fake.enc_pub()),
            recovery_sign_pub: STANDARD.encode([6u8; 32]),
            nonce: STANDARD.encode(nonce_s),
        });
        Self {
            fake,
            commitment,
            device_id: commit["data"]["device_id"].as_str().unwrap().to_string(),
            nonce_s,
            account: account.to_string(),
        }
    }

    /// Waits for `verifyReveal`; the signed `deviceVerified` for it.
    async fn certificate(&self, peer: &mut Peer) -> AstationMessage {
        let reveal = peer.next("verifyReveal").await;
        let key = |name: &str| -> [u8; 32] {
            STANDARD
                .decode(reveal["data"][name].as_str().unwrap())
                .unwrap()
                .try_into()
                .unwrap()
        };
        let certificate = DeviceVerified {
            account: self.account.clone(),
            sign_gen: 1,
            device_id: self.device_id.clone(),
            device_pub: key("device_pub"),
            device_sign_pub: key("device_sign_pub"),
            unlock_auth_pub: key("unlock_auth_pub"),
            transcript: transcript_for(&self.commitment, &key("nonce"), &self.nonce_s),
            epoch: 1,
        };
        let state = AccountState {
            account: self.account.clone(),
            sign_gen: 1,
            mode: crate::memory::crypto::EncryptionMode::Off,
            kid: None,
            epoch: 1,
        };
        AstationMessage::DeviceVerified {
            device_verified: self.fake.sign(&certificate.encode()),
            account_state: self.fake.sign(&state.encode()),
            grants: Vec::new(),
        }
    }
}

/// A broker linked (or not) to a fake Astation, its profile in `profile`.
struct Runtime {
    dir: Rc<tempfile::TempDir>,
    profile: PathBuf,
    socket: PathBuf,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    server: tokio::task::JoinHandle<anyhow::Result<()>>,
    /// The profile and cred agent stand in for the user's on this thread.
    _scopes: (crate::test_profile::Scope, crate::test_profile::Scope),
}

impl Runtime {
    /// The App linked to `peer_url` (already authenticated with `ASTATION`)
    /// when given; else unlinked. `agent`: the cred agent of the profile.
    async fn start(
        dir: Rc<tempfile::TempDir>,
        peer_url: Option<&str>,
        agent: Arc<dyn CredAgentApi>,
    ) -> Self {
        let root = dir.path();
        let profile = root.join("profile");
        std::fs::create_dir_all(&profile).unwrap();
        let scopes = (
            crate::test_profile::use_dir(&profile),
            crate::test_profile::use_agent(agent.clone()),
        );
        let mut app = App::new();
        // Never the user's profile, never a real Astation.
        app.last_session_refresh = Some(Instant::now());
        app.astation_reconnect = false;
        app.astation_client =
            AstationClient::new_with_test_state(ATEM_ID, &profile).with_agent(agent.clone());
        if let Some(url) = peer_url {
            app.astation_client.connect_raw(url).await.unwrap();
            app.astation_client.pin_astation_for_test(ASTATION);
            app.astation_connected = true;
            app.astation_link_gen = 1;
        }
        let socket = root.join("rt.sock");
        let unix = tokio::net::UnixListener::bind(&socket).unwrap();
        let options = Options {
            idle: Duration::from_secs(600),
            uid: unsafe { libc::getuid() },
            launcher: Launcher::InProcess(InProcess {
                state: root.join("state"),
                socket_dir: root.join("ws"),
                chat_root: root.join("run"),
            }),
            profile: Some(crate::profile::Sources::in_dir(&profile)),
            clock: Default::default(),
            // A link that's gone is reported well within the test's wait.
            ops: OpEnv::for_profile(crate::profile::Sources::in_dir(&profile), agent)
                .with_link_wait(Duration::from_secs(3)),
        };
        let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::task::spawn_local(serve(app, unix, options, async {
            let _ = stopped.await;
        }));
        Self {
            dir,
            profile,
            socket,
            stop: Some(stop),
            server,
            _scopes: scopes,
        }
    }

    fn keys(&self) -> CredPaths {
        CredPaths::in_dir(&self.profile)
    }

    async fn client(&self) -> RuntimeClient {
        RuntimeClient::connect_at(&self.socket).await.unwrap()
    }

    async fn shutdown(mut self) {
        let _ = self.stop.take().unwrap().send(());
        tokio::time::timeout(Duration::from_secs(10), &mut self.server)
            .await
            .expect("the server stops")
            .unwrap()
            .unwrap();
    }

    /// An echo agent session, attached by `client`, showing READY.
    async fn attached_session(&self, client: &mut RuntimeClient) -> SessionSummary {
        let agent = echo_agent(self.dir.path());
        client
            .send(&ClientMsg::Launch {
                provider: "codex".into(),
                args: vec![],
                cwd: self.dir.path().to_path_buf(),
                env: LaunchEnv(vec![
                    ("PATH".into(), "/usr/bin:/bin".into()),
                    ("CODEX_CLI_BIN".into(), agent.display().to_string()),
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
        client
            .send(&ClientMsg::Attach {
                session_id: session.id.clone(),
                rows: 24,
                cols: 80,
            })
            .await
            .unwrap();
        expect(client, |m| {
            matches!(m, RuntimeMsg::Attached { .. }).then_some(())
        })
        .await;
        shows(client, "READY").await;
        session
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

/// Waits until the attached session's output shows `text`.
async fn shows(client: &mut RuntimeClient, text: &str) {
    let mut seen = String::new();
    expect(client, |m| {
        let bytes = match m {
            RuntimeMsg::Output { bytes, .. } => bytes,
            RuntimeMsg::Attached { restore, .. } => restore,
            _ => return None,
        };
        seen.push_str(&String::from_utf8_lossy(&STANDARD.decode(bytes).unwrap()));
        seen.contains(text).then_some(())
    })
    .await
}

/// A client running one operation, as the CLI does.
struct Op {
    client: RuntimeClient,
    request_id: String,
    printed: Vec<String>,
}

impl Op {
    async fn start(mut client: RuntimeClient, kind: OpKind, options: OpOptions) -> Self {
        let request_id = uuid::Uuid::new_v4().to_string();
        client
            .send(&ClientMsg::AstationOp {
                request_id: request_id.clone(),
                kind,
                options,
            })
            .await
            .unwrap();
        Self {
            client,
            request_id,
            printed: Vec::new(),
        }
    }

    /// The next `ask` (its question id), keeping prints.
    async fn ask(&mut self) -> (u64, AskKind, String) {
        let id = self.request_id.clone();
        let printed = &mut self.printed;
        expect(&mut self.client, |m| match m {
            RuntimeMsg::Print {
                request_id, text, ..
            } if request_id == id => {
                printed.push(text);
                None
            }
            RuntimeMsg::Ask {
                request_id,
                question_id,
                kind,
                text,
            } if request_id == id => Some((question_id, kind, text)),
            RuntimeMsg::Done { error, .. } => panic!("done before a question: {error:?}"),
            _ => None,
        })
        .await
    }

    async fn answer(&mut self, question_id: u64, value: AnswerValue) {
        self.client
            .send(&ClientMsg::Answer {
                request_id: self.request_id.clone(),
                question_id,
                value,
            })
            .await
            .unwrap();
    }

    /// Prints until one contains `text`.
    async fn printed(&mut self, text: &str) {
        let id = self.request_id.clone();
        let printed = &mut self.printed;
        expect(&mut self.client, |m| match m {
            RuntimeMsg::Print {
                request_id,
                text: line,
                ..
            } if request_id == id => {
                let found = line.contains(text);
                printed.push(line);
                found.then_some(())
            }
            RuntimeMsg::Done { error, .. } => panic!("done before {text:?}: {error:?}"),
            _ => None,
        })
        .await
    }

    /// `done`: Ok, or its error.
    async fn done(&mut self) -> Result<(), String> {
        let id = self.request_id.clone();
        let printed = &mut self.printed;
        expect(&mut self.client, |m| match m {
            RuntimeMsg::Print {
                request_id, text, ..
            } if request_id == id => {
                printed.push(text);
                None
            }
            RuntimeMsg::Done {
                request_id,
                ok,
                error,
            } if request_id == id => Some(if ok {
                Ok(())
            } else {
                Err(error.unwrap_or_default())
            }),
            _ => None,
        })
        .await
    }
}

/// Verification of the profile with `ASTATION` as `account`.
fn verified_as(keys: &CredPaths, account: &str) -> bool {
    crate::memory::trust::TrustStore::load_from(&keys.trust)
        .ok()
        .and_then(|trust| trust.verified(ASTATION).map(|e| e.data_account == account))
        .unwrap_or(false)
}

/// A pending pin (a verification under way) is on disk.
fn pending(keys: &CredPaths) -> bool {
    std::fs::read_to_string(&keys.trust)
        .ok()
        .and_then(|text| serde_json::from_str::<Value>(&text).ok())
        .is_some_and(|trust| trust["pending"].as_object().is_some_and(|p| !p.is_empty()))
}

/// Up to the safety-code question: Astation's keys sent, the reveal and its
/// certificate ready.
async fn verify_until_the_question(
    rt: &Runtime,
    peer: &mut Peer,
    account: &str,
) -> (Op, u64, AstationMessage) {
    let op = Op::start(rt.client().await, OpKind::PairVerify, OpOptions::default()).await;
    let verifier = Verifier::keys(peer, account).await;
    let certificate = verifier.certificate(peer).await;
    let mut op = op;
    let (question, kind, text) = op.ask().await;
    assert_eq!(kind, AskKind::YesNo);
    assert_eq!(text, crate::pair_verify::CODES_QUESTION);
    assert!(
        op.printed
            .iter()
            .any(|line| line.starts_with("Safety code:")),
        "{:?}",
        op.printed
    );
    (op, question, certificate)
}

#[test]
fn pair_verify_runs_on_the_runtimes_link_and_sessions_stay_attached() {
    local(async {
        let dir = Rc::new(short_dir());
        paired(&dir.path().join("profile"));
        let (url, mut peer) = Peer::listen().await;
        let keys = CredPaths::in_dir(&dir.path().join("profile"));
        let rt = Runtime::start(dir, Some(&url), Arc::new(test_agent(&keys))).await;
        let mut frontend = rt.client().await;
        let session = rt.attached_session(&mut frontend).await;
        // An unverified link gets no session attachment.
        assert_eq!(peer.hello().await["op"], "error");

        let (mut op, question, certificate) =
            verify_until_the_question(&rt, &mut peer, "acct-op").await;
        op.answer(question, AnswerValue::Yes).await;
        op.printed("Waiting for your Mac").await;
        peer.send(&certificate);
        // The first escrow: refused here (the storage key stays on the device).
        peer.next("storageKeyRotate").await;
        peer.send(&AstationMessage::StorageKeyRejected {
            reason: "not now".into(),
            pending_kid: None,
        });
        op.done().await.unwrap();
        assert!(
            op.printed.iter().any(|l| l.contains("Device verified")),
            "{:?}",
            op.printed
        );
        assert!(verified_as(&rt.keys(), "acct-op"));

        // The same link (never reconnected) is now a verified pairing: it
        // attaches, and sees the session the local frontend kept attached.
        assert!(
            !peer.drain(Duration::from_millis(200)).await,
            "the link closed"
        );
        let welcome = peer.hello().await;
        assert_eq!(welcome["op"], "welcome", "{welcome}");
        assert_eq!(welcome["account_id"], "acct-op");
        assert_eq!(welcome["atem_device_id"], ATEM_ID);
        frontend
            .send(&ClientMsg::input(&session.id, b"AFTER\r"))
            .await
            .unwrap();
        shows(&mut frontend, "AFTER").await;
        peer.subscribe_until(&session.id, &session.generation, "AFTER")
            .await;
        rt.shutdown().await;
    });
}

#[test]
fn a_cli_gone_mid_verification_aborts_it_and_a_late_certificate_is_dropped() {
    local(async {
        let dir = Rc::new(short_dir());
        paired(&dir.path().join("profile"));
        let (url, mut peer) = Peer::listen().await;
        let keys = CredPaths::in_dir(&dir.path().join("profile"));
        let rt = Runtime::start(dir, Some(&url), Arc::new(test_agent(&keys))).await;
        let (mut op, question, certificate) =
            verify_until_the_question(&rt, &mut peer, "acct-op").await;
        op.answer(question, AnswerValue::Yes).await;
        op.printed("Waiting for your Mac").await;
        // Ctrl-C: the CLI's connection closes.
        drop(op);
        let abort = peer.next("verifyAbort").await;
        assert_eq!(abort["data"]["reason"], "atem was interrupted");
        assert!(!pending(&rt.keys()), "the pending pin stays dropped");
        // Astation's certificate arrives after the abort: never applied.
        peer.send(&certificate);
        peer.drain(Duration::from_millis(500)).await;
        assert!(!verified_as(&rt.keys(), "acct-op"));
        // The operation ended: another one runs.
        let mut next = Op::start(rt.client().await, OpKind::PairVerify, OpOptions::default()).await;
        next.printed("Verifying this device").await;
        rt.shutdown().await;
    });
}

#[test]
fn a_lost_link_fails_the_verification_without_replay() {
    local(async {
        let dir = Rc::new(short_dir());
        paired(&dir.path().join("profile"));
        let (url, mut peer) = Peer::listen().await;
        let keys = CredPaths::in_dir(&dir.path().join("profile"));
        let rt = Runtime::start(dir, Some(&url), Arc::new(test_agent(&keys))).await;
        let mut frontend = rt.client().await;
        let session = rt.attached_session(&mut frontend).await;
        let (mut op, question, _certificate) =
            verify_until_the_question(&rt, &mut peer, "acct-op").await;
        op.answer(question, AnswerValue::Yes).await;
        op.printed("Waiting for your Mac").await;
        peer.close();
        let error = op.done().await.unwrap_err();
        assert_eq!(error, "device verification failed");
        assert!(
            op.printed.iter().any(|l| l.contains("connection closed")),
            "{:?}",
            op.printed
        );
        assert!(!pending(&rt.keys()));
        assert!(!verified_as(&rt.keys(), "acct-op"));
        // The session and its local frontend carry on.
        frontend
            .send(&ClientMsg::input(&session.id, b"STILL\r"))
            .await
            .unwrap();
        shows(&mut frontend, "STILL").await;
        // Nothing is replayed: a new verification needs the link, which is gone.
        let mut again =
            Op::start(rt.client().await, OpKind::PairVerify, OpOptions::default()).await;
        let error = again.done().await.unwrap_err();
        assert!(error.contains("isn't connected to Astation"), "{error}");
        rt.shutdown().await;
    });
}

#[test]
fn a_second_operation_is_refused_while_one_runs() {
    local(async {
        let dir = Rc::new(short_dir());
        paired(&dir.path().join("profile"));
        let (url, mut peer) = Peer::listen().await;
        let keys = CredPaths::in_dir(&dir.path().join("profile"));
        let rt = Runtime::start(dir, Some(&url), Arc::new(test_agent(&keys))).await;
        let (mut op, question, _) = verify_until_the_question(&rt, &mut peer, "acct-op").await;
        for kind in [OpKind::CredUnlock, OpKind::Pair, OpKind::PairVerify] {
            let mut second = Op::start(rt.client().await, kind, OpOptions::default()).await;
            assert_eq!(second.done().await.unwrap_err(), BUSY);
        }
        // The first one is unaffected: a refusal of the code ends it.
        op.answer(question, AnswerValue::No).await;
        let error = op.done().await.unwrap_err();
        assert_eq!(error, "device verification failed");
        let abort = peer.next("verifyAbort").await;
        assert_eq!(abort["data"]["reason"], "codes didn't match on atem");
        rt.shutdown().await;
    });
}

#[test]
fn a_reply_without_an_operation_is_dropped() {
    local(async {
        let dir = Rc::new(short_dir());
        paired(&dir.path().join("profile"));
        let (url, peer) = Peer::listen().await;
        let keys = CredPaths::in_dir(&dir.path().join("profile"));
        let rt = Runtime::start(dir, Some(&url), Arc::new(test_agent(&keys))).await;
        let verifier = FakeAstation::new();
        peer.send(&AstationMessage::DeviceVerified {
            device_verified: verifier.sign(b"x"),
            account_state: verifier.sign(b"y"),
            grants: Vec::new(),
        });
        peer.send(&AstationMessage::UnlockDenied {
            reason: "no".into(),
            revoked: true,
        });
        // Handled in order: once the hello after them is answered, they were.
        let mut peer = peer;
        peer.hello().await;
        assert!(!rt.keys().trust.exists(), "nothing was applied");
        rt.shutdown().await;
    });
}

#[test]
fn cred_unlock_runs_on_the_runtimes_link_while_sessions_stay_attached() {
    use crate::memory::fake_astation::sealed_device;
    use crate::memory::storage_key::StorageRotation;
    local(async {
        let dir = Rc::new(short_dir());
        let profile = dir.path().join("profile");
        paired(&profile);
        let (keys, mut server, _) = sealed_device(&profile, "0a1b2c3d");
        let agent: Arc<dyn CredAgentApi> = Arc::new(test_agent(&keys));
        let (url, mut peer) = Peer::listen().await;
        let rt = Runtime::start(dir, Some(&url), agent.clone()).await;
        let mut frontend = rt.client().await;
        let session = rt.attached_session(&mut frontend).await;
        // Verified: the link attaches and views the session.
        let welcome = peer.hello().await;
        assert_eq!(welcome["op"], "welcome", "{welcome}");
        peer.subscribe_until(&session.id, &session.generation, "READY")
            .await;

        let mut op = Op::start(rt.client().await, OpKind::CredUnlock, OpOptions::default()).await;
        let request = peer.next("unlockRequest").await;
        let grant = server
            .grant_unlock_confirming(&SignedWire {
                statement: request["data"]["request"].as_str().unwrap().into(),
                signature: request["data"]["signature"].as_str().unwrap().into(),
            })
            .unwrap();
        peer.send(&AstationMessage::UnlockGrant {
            grant: grant.grant,
            encapped_key: grant.encapped_key,
            ciphertext: grant.ciphertext,
        });
        let rotate = peer.next("storageKeyRotate").await;
        let rotation: StorageRotation = serde_json::from_value(rotate["data"].clone()).unwrap();
        let ack = server.accept_rotation(&rotation).unwrap();
        peer.send(&AstationMessage::StorageKeyAck { ack });
        let confirm = peer.next("storageKeyConfirm").await;
        server
            .confirm(&serde_json::from_value(confirm["data"]["confirm"].clone()).unwrap())
            .unwrap();
        op.done().await.unwrap();
        assert!(
            op.printed.iter().any(|l| l.contains("Unlocked")),
            "{:?}",
            op.printed
        );
        let status = agent.status().unwrap();
        assert!(status.unlocked && status.escrowed);
        assert_ne!(status.storage_kid.as_deref(), Some("0a1b2c3d"), "rotated");

        // The viewer and the local frontend are still attached.
        frontend
            .send(&ClientMsg::input(&session.id, b"UNLOCKED\r"))
            .await
            .unwrap();
        shows(&mut frontend, "UNLOCKED").await;
        peer.frames_until(&session.id, "UNLOCKED").await;
        rt.shutdown().await;
    });
}

#[test]
fn first_pairing_pairs_makes_the_connection_the_link_and_verifies_on_it() {
    first_pairing(None);
}

/// A record without a binding (left by v0.7.2's background reconnect) is
/// not a pairing: `atem pair` proceeds and replaces it.
#[test]
fn pair_replaces_a_record_without_a_binding() {
    first_pairing(Some(ASTATION));
    first_pairing(Some("astation-other"));
}

fn first_pairing(leftover: Option<&str>) {
    local(async {
        let dir = Rc::new(short_dir());
        let profile = dir.path().join("profile");
        std::fs::create_dir_all(&profile).unwrap();
        if let Some(astation_id) = leftover {
            crate::pairing::tests::set_session(&profile, astation_id, "leftover", "leftover-token");
        }
        let (url, mut peer) = Peer::listen().await;
        // Local first: the fake is the local Astation; the relay is unreachable.
        std::fs::write(
            profile.join("config.toml"),
            format!(
                "astation_ws = \"{url}\"\nastation_relay_url = \"http://127.0.0.1:1\"\natem_id = \"{ATEM_ID}\"\n"
            ),
        )
        .unwrap();
        let keys = CredPaths::in_dir(&profile);
        let rt = Runtime::start(dir, None, Arc::new(test_agent(&keys))).await;
        let mut op = Op::start(rt.client().await, OpKind::Pair, OpOptions::default()).await;

        // Astation challenges; atem answers with a pairing code shown by the CLI.
        peer.send(&AstationMessage::StatusUpdate {
            status: "auth_required".into(),
            data: [
                ("astation_id", ASTATION),
                ("challenge", &"a".repeat(64)),
                ("transport", "lan"),
                ("protocol", "2"),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        });
        let auth = peer.next("statusUpdate").await;
        let code = auth["data"]["data"]["pairing_code"]
            .as_str()
            .unwrap()
            .to_string();
        op.printed(&code).await;
        peer.send(&AstationMessage::StatusUpdate {
            status: "auth".into(),
            data: [
                ("status", "granted"),
                ("session_id", "session-new"),
                ("token", "token-new"),
            ]
            .into_iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
        });
        let (question, kind, text) = op.ask().await;
        assert_eq!(kind, AskKind::YesNo);
        assert!(text.contains("Save credentials"), "{text}");
        op.answer(question, AnswerValue::Yes).await;
        let preference = peer.next("pairSavePreference").await;
        assert_eq!(preference["data"]["save_credentials"], true);
        peer.send(&AstationMessage::CredentialSync {
            access_token: "access".into(),
            refresh_token: "refresh".into(),
            expires_at: crate::credentials::now_secs() + 3600,
            login_id: Some("me".into()),
            astation_id: ASTATION.into(),
            save_credentials: true,
        });
        // Verification on the same connection, now the runtime's link.
        let verifier = Verifier::keys(&mut peer, "acct-new").await;
        let certificate = verifier.certificate(&mut peer).await;
        let (question, _, _) = op.ask().await;
        op.answer(question, AnswerValue::Yes).await;
        op.printed("Waiting for your Mac").await;
        peer.send(&certificate);
        peer.next("storageKeyRotate").await;
        peer.send(&AstationMessage::StorageKeyRejected {
            reason: "not now".into(),
            pending_kid: None,
        });
        op.done().await.unwrap();
        assert!(
            op.printed
                .iter()
                .any(|l| l.contains("Paired with Astation. (SSO: me)"))
        );

        let src = crate::profile::Sources::in_dir(&rt.profile);
        let binding = crate::pairing::load(&src).unwrap().binding.unwrap();
        assert_eq!(binding.astation_id, ASTATION);
        assert!(fresh_shared(&rt.profile).is_some());
        assert!(record(&rt.profile).save_credentials);
        assert_eq!(record(&rt.profile).astation_id, ASTATION);
        assert_eq!(
            record(&rt.profile).session.unwrap().session_id,
            "session-new",
            "the pairing saved the granted session"
        );
        assert!(verified_as(&rt.keys(), "acct-new"));
        // The pairing connection is the runtime's link: it attaches.
        let welcome = peer.hello().await;
        assert_eq!(welcome["op"], "welcome", "{welcome}");
        assert_eq!(welcome["account_id"], "acct-new");
        rt.shutdown().await;
    });
}

#[test]
fn the_token_op_saves_the_credentials_astation_sends() {
    local(async {
        let dir = Rc::new(short_dir());
        let profile = dir.path().join("profile");
        paired(&profile);
        crate::pairing::tests::edit(&profile, |record| {
            record.shared.as_mut().unwrap().tokens.expires_at = crate::credentials::now_secs() + 10;
        });
        let (url, mut peer) = Peer::listen().await;
        let keys = CredPaths::in_dir(&profile);
        let rt = Runtime::start(dir, Some(&url), Arc::new(test_agent(&keys))).await;
        assert!(fresh_shared(&profile).is_none());
        let options = OpOptions {
            astation_id: Some(ASTATION.into()),
            ..OpOptions::default()
        };
        let mut op = Op::start(rt.client().await, OpKind::Token, options).await;
        op.printed("Waiting for Astation's credentials").await;
        peer.send(&AstationMessage::CredentialSync {
            access_token: "fresh".into(),
            refresh_token: "fresh-refresh".into(),
            expires_at: crate::credentials::now_secs() + 3600,
            login_id: None,
            astation_id: ASTATION.into(),
            save_credentials: true,
        });
        op.done().await.unwrap();
        assert_eq!(fresh_shared(&profile).unwrap().access_token, "fresh");
        // Fresh already: answered without waiting.
        let options = OpOptions {
            astation_id: Some(ASTATION.into()),
            ..OpOptions::default()
        };
        let mut op = Op::start(rt.client().await, OpKind::Token, options).await;
        op.done().await.unwrap();
        peer.drain(Duration::from_millis(100)).await;
        rt.shutdown().await;
    });
}

#[test]
fn unpair_then_reload_drops_the_link_and_its_attachment() {
    use crate::memory::fake_astation::sealed_device;
    local(async {
        let dir = Rc::new(short_dir());
        let profile = dir.path().join("profile");
        paired(&profile);
        let (keys, _, _) = sealed_device(&profile, "0a1b2c3d");
        let (url, mut peer) = Peer::listen().await;
        let rt = Runtime::start(dir, Some(&url), Arc::new(test_agent(&keys))).await;
        let mut frontend = rt.client().await;
        let session = rt.attached_session(&mut frontend).await;
        assert_eq!(peer.hello().await["op"], "welcome");
        // A reload without a change keeps the link.
        let mut client = rt.client().await;
        client.send(&ClientMsg::Reload).await.unwrap();
        expect(&mut client, |m| {
            matches!(m, RuntimeMsg::Notice { ref text } if text == "Reloaded").then_some(())
        })
        .await;
        assert!(!peer.drain(Duration::from_millis(300)).await);
        // `atem unpair` commits a new trust generation, then reloads.
        crate::pairing::unpair(&crate::profile::Sources::in_dir(&rt.profile)).unwrap();
        client.send(&ClientMsg::Reload).await.unwrap();
        expect(&mut client, |m| {
            matches!(m, RuntimeMsg::Notice { ref text } if text == "Reloaded").then_some(())
        })
        .await;
        assert!(peer.drain(WAIT).await, "the link was dropped");
        // The session and its local frontend stay.
        frontend
            .send(&ClientMsg::input(&session.id, b"KEPT\r"))
            .await
            .unwrap();
        shows(&mut frontend, "KEPT").await;
        rt.shutdown().await;
    });
}

#[test]
fn session_errors_get_the_advice() {
    use crate::runtime::ops::session_advice;
    use crate::websocket_client::{SessionError, SessionProblem};
    let refused = anyhow::Error::new(SessionError::new(
        SessionProblem::Refused,
        false,
        "Authentication denied: no".into(),
    ));
    assert_eq!(
        format!("{:#}", session_advice(refused)),
        format!("Authentication denied: no. {}", crate::status::SESSION_GONE)
    );
    let advised = anyhow::Error::new(SessionError::new(
        SessionProblem::PairingRequired,
        true,
        format!("Pairing required. {}", crate::status::SESSION_GONE),
    ));
    assert_eq!(
        format!("{:#}", session_advice(advised)),
        format!("Pairing required. {}", crate::status::SESSION_GONE)
    );
    let network = anyhow::anyhow!("Pairing required? WebSocket connection timed out after 5s");
    assert_eq!(
        format!("{:#}", session_advice(network)),
        "Pairing required? WebSocket connection timed out after 5s"
    );
}

/// The CLI side renders prints, answers questions and returns `done`.
#[test]
fn the_cli_side_renders_answers_and_ends_with_done() {
    use crate::runtime::op_client::{CliUi, run_with};
    struct Script {
        printed: Vec<(PrintLevel, String)>,
        asked: Vec<String>,
    }
    impl CliUi for Script {
        fn print(&mut self, level: PrintLevel, text: &str) {
            self.printed.push((level, text.to_string()));
        }
        async fn ask(&mut self, _: AskKind, text: &str) -> AnswerValue {
            self.asked.push(text.to_string());
            AnswerValue::NoTerminal("no tty".into())
        }
    }
    local(async {
        let dir = Rc::new(short_dir());
        paired(&dir.path().join("profile"));
        let (url, mut peer) = Peer::listen().await;
        let keys = CredPaths::in_dir(&dir.path().join("profile"));
        let rt = Runtime::start(dir, Some(&url), Arc::new(test_agent(&keys))).await;
        let client = rt.client().await;
        let mut script = Script {
            printed: Vec::new(),
            asked: Vec::new(),
        };
        let run = run_with(
            client,
            OpKind::PairVerify,
            OpOptions::default(),
            &mut script,
        );
        let astation = async {
            let _verifier = Verifier::keys(&mut peer, "acct-op").await;
            peer.next("verifyReveal").await;
            peer.next("verifyAbort").await
        };
        let (result, abort) = tokio::join!(run, astation);
        assert_eq!(
            result.unwrap_err().to_string(),
            "device verification failed"
        );
        assert_eq!(abort["data"]["reason"], "no terminal to compare the code");
        assert_eq!(script.asked, [crate::pair_verify::CODES_QUESTION]);
        assert!(
            script.printed.iter().any(
                |(level, text)| *level == PrintLevel::Warn && text.contains("atem pair verify")
            ),
            "{:?}",
            script.printed
        );
        rt.shutdown().await;
    });
}

#[test]
fn routing_is_by_operation_and_link() {
    let profile = tempfile::tempdir().unwrap();
    let _profile = crate::test_profile::use_dir(profile.path());
    let mut app = App::new();
    app.astation_link_gen = 4;
    let verify_abort = || AstationMessage::VerifyAbort { reason: "r".into() };
    let mode = || AstationMessage::EncryptionMode {
        account_state: None,
    };
    // No operation: operation replies are dropped, the rest goes on.
    assert!(app.route_to_op(verify_abort()).is_none());
    assert!(app.route_to_op(mode()).is_some());
    let (tx, mut rx) = mpsc::channel(4);
    app.op_route = Some(crate::app::op_route::OpRoute {
        link_gen: 4,
        tx,
        encryption: true,
        credentials: false,
    });
    assert!(app.route_to_op(verify_abort()).is_none());
    assert!(app.route_to_op(mode()).is_none());
    assert!(
        app.route_to_op(AstationMessage::Heartbeat {
            timestamp: "1".into()
        })
        .is_some()
    );
    assert!(matches!(
        rx.try_recv(),
        Ok(AstationMessage::VerifyAbort { .. })
    ));
    assert!(matches!(
        rx.try_recv(),
        Ok(AstationMessage::EncryptionMode { .. })
    ));
    // Another link's replies never reach it.
    app.astation_link_gen = 5;
    assert!(app.route_to_op(verify_abort()).is_none());
    assert!(rx.try_recv().is_err());
}

/// A device whose account is migrating to encryption (K held, unlocked and
/// escrowed), its relay data in a stub relay, paired with `ASTATION`.
async fn migrating_device(
    profile: &Path,
) -> (
    crate::memory::fake_astation::UnlockedDevice,
    Arc<std::sync::Mutex<crate::memory::e2e_tests::RelayState>>,
) {
    use crate::memory::crypto::EncryptionMode;
    use crate::memory::e2e_tests::{RelayState, stub_relay};
    paired(profile);
    let relay = Arc::new(std::sync::Mutex::new(RelayState::seeded()));
    let base = stub_relay(relay.clone()).await;
    std::fs::write(
        profile.join("config.toml"),
        format!("astation_relay_url = \"{base}\"\ninstance_id = \"atem-1\"\n"),
    )
    .unwrap();
    let mut device = crate::memory::fake_astation::UnlockedDevice::new(profile);
    device.set_key(EncryptionMode::Enabling, "0123abcd", [7; 32]);
    (device, relay)
}

#[test]
fn cred_unlock_finishes_a_pending_migration_on_the_runtimes_link() {
    local(async {
        let dir = Rc::new(short_dir());
        let profile = dir.path().join("profile");
        let (device, relay) = migrating_device(&profile).await;
        let (url, mut peer) = Peer::listen().await;
        let rt = Runtime::start(dir, Some(&url), device.agent.clone()).await;
        let mut op = Op::start(rt.client().await, OpKind::CredUnlock, OpOptions::default()).await;
        let complete = peer.next("encryptionMigrationComplete").await;
        assert_eq!(complete["data"]["mode"], "on");
        assert_eq!(complete["data"]["kid"], "0123abcd");
        op.done().await.unwrap();
        for line in [
            "Already unlocked",
            "Finishing the encryption migration",
            "Encryption migration complete",
        ] {
            assert!(
                op.printed.iter().any(|l| l.contains(line)),
                "{line}: {:?}",
                op.printed
            );
        }
        crate::memory::e2e_tests::assert_all_encrypted_with(&relay.lock().unwrap(), "0123abcd");
        rt.shutdown().await;
    });
}

#[test]
fn the_link_leaves_a_migration_to_the_operation_running_one() {
    local(async {
        let dir = short_dir();
        let profile = dir.path().join("profile");
        let (device, _relay) = migrating_device(&profile).await;
        let (url, _peer) = Peer::listen().await;
        let mut link =
            AstationClient::new_with_test_state(ATEM_ID, &profile).with_agent(device.agent.clone());
        link.connect_raw(&url).await.unwrap();
        link.pin_astation_for_test(ASTATION);
        // An operation (or another finish) is running one.
        let running = crate::websocket_client::MIGRATION.lock().await;
        let status = link.finish_pending_migration(ASTATION).await.unwrap();
        assert_eq!(
            status.as_deref(),
            Some("An encryption migration is already running")
        );
        // An operation's handle waits for it instead.
        let (view, _routed) = link.op_view();
        let waiting = view.finish_pending_migration(ASTATION);
        tokio::pin!(waiting);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut waiting)
                .await
                .is_err(),
            "the operation waits"
        );
        drop(running);
        let status = tokio::time::timeout(WAIT, waiting).await.unwrap().unwrap();
        assert_eq!(
            status.as_deref(),
            Some("Encryption migration complete; requesting on")
        );
    });
}

#[test]
fn credentials_astation_sends_go_to_the_links_profile() {
    local(async {
        let elsewhere = crate::config::AtemConfig::config_dir();
        let dir = short_dir();
        let profile = dir.path().join("profile");
        paired(&profile);
        let (url, _peer) = Peer::listen().await;
        let mut app = App::new();
        app.last_session_refresh = Some(Instant::now());
        app.astation_reconnect = false;
        app.astation_client = AstationClient::new_with_test_state(ATEM_ID, &profile);
        app.astation_client.connect_raw(&url).await.unwrap();
        app.astation_client.pin_astation_for_test(ASTATION);
        app.astation_connected = true;
        app.handle_astation_message(AstationMessage::CredentialSync {
            access_token: "synced".into(),
            refresh_token: "r".into(),
            expires_at: crate::credentials::now_secs() + 3600,
            login_id: None,
            astation_id: ASTATION.into(),
            save_credentials: false,
        })
        .await;
        assert_eq!(fresh_shared(&profile).unwrap().access_token, "synced");
        assert!(!record(&profile).save_credentials);
        app.on_astation_disconnect();
        assert!(record(&profile).disconnected_at.is_some());
        assert!(
            !crate::paths::ProfilePaths::in_dir(&elsewhere)
                .pairing
                .record
                .exists(),
            "only the link's profile"
        );
    });
}

/// An App on a link to the fake Astation for the bound profile at `profile`,
/// reached `via`.
async fn linked_app(profile: &Path, via: crate::websocket_client::LinkVia) -> (App, Peer) {
    let (url, peer) = Peer::listen().await;
    let mut app = App::new();
    app.last_session_refresh = Some(Instant::now());
    app.astation_reconnect = false;
    app.astation_client = link_to(profile, &url, via).await;
    app.astation_connected = true;
    (app, peer)
}

/// A client authenticated (pinned) with `ASTATION` over `url`.
async fn link_to(
    profile: &Path,
    url: &str,
    via: crate::websocket_client::LinkVia,
) -> AstationClient {
    let mut client = AstationClient::new_with_test_state(ATEM_ID, profile);
    client.connect_raw(url).await.unwrap();
    client.pin_astation_for_test(ASTATION);
    client.set_via_for_test(via);
    client
}

fn relay() -> crate::websocket_client::LinkVia {
    crate::websocket_client::LinkVia::Relay {
        label: "relay".into(),
    }
}

fn local_via() -> crate::websocket_client::LinkVia {
    crate::websocket_client::LinkVia::Local
}

fn stored(relay_only: bool) -> Value {
    json!({"relay_only": relay_only, "stored": true})
}

fn not_stored(relay_only: bool, reason: &str) -> Value {
    json!({"relay_only": relay_only, "stored": false, "reason": reason})
}

fn acks(peer: &Peer) -> Vec<Value> {
    peer.seen
        .iter()
        .filter(|m| m["type"] == "transportPolicyAck")
        .map(|m| m["data"].clone())
        .collect()
}

/// `transportPolicy` is kept in the link's bound pairing and acknowledged
/// `stored: true` with the value stored; a repeat is the same no-op, a relay
/// link stays, and `false` clears it.
#[test]
fn transport_policy_is_kept_in_the_bound_pairing_and_acknowledged() {
    local(async {
        let dir = short_dir();
        let profile = dir.path().join("profile");
        paired(&profile);
        let (mut app, mut peer) = linked_app(&profile, relay()).await;
        for relay_only in [true, true, false, false] {
            app.handle_astation_message(AstationMessage::TransportPolicy { relay_only })
                .await;
            let ack = peer.next("transportPolicyAck").await;
            assert_eq!(ack["data"], stored(relay_only));
            assert_eq!(record(&profile).relay_only, relay_only);
            assert!(app.astation_connected, "a relay link stays");
        }
    });
}

/// A link without a bound pairing (the loopback proof on a profile never
/// paired) stores nothing, creates no pairing and says `not_paired`.
#[test]
fn transport_policy_on_a_link_without_a_pairing_is_not_paired() {
    local(async {
        let dir = short_dir();
        let profile = dir.path().join("profile");
        std::fs::create_dir_all(&profile).unwrap();
        let (mut app, mut peer) = linked_app(&profile, local_via()).await;
        app.handle_astation_message(AstationMessage::TransportPolicy { relay_only: true })
            .await;
        let ack = peer.next("transportPolicyAck").await;
        assert_eq!(ack["data"], not_stored(true, "not_paired"));
        let paths = crate::paths::ProfilePaths::in_dir(&profile).pairing;
        assert!(!paths.record.exists(), "never creates a pairing");
        assert!(
            app.astation_connected,
            "nothing stored: the local link stays"
        );
    });
}

/// A stale link (its pairing removed, or replaced by a new pairing) gets
/// `pairing_changed`; the new binding is never touched and nothing comes back.
#[test]
fn transport_policy_on_a_stale_link_is_pairing_changed() {
    for re_pair in [false, true] {
        local(async {
            let dir = short_dir();
            let profile = dir.path().join("profile");
            paired(&profile);
            let (mut app, mut peer) = linked_app(&profile, relay()).await;
            let src = crate::profile::Sources::in_dir(&profile);
            crate::pairing::unpair(&src).unwrap();
            if re_pair {
                let before = crate::pairing::capture(&src).unwrap();
                crate::pairing::bind_new(&src, &before, ASTATION).unwrap();
            }
            app.handle_astation_message(AstationMessage::TransportPolicy { relay_only: true })
                .await;
            let ack = peer.next("transportPolicyAck").await;
            assert_eq!(
                ack["data"],
                not_stored(true, "pairing_changed"),
                "re_pair {re_pair}"
            );
            let paths = crate::paths::ProfilePaths::in_dir(&profile).pairing;
            if re_pair {
                assert!(!record(&profile).relay_only, "the new binding is untouched");
            } else {
                assert!(!paths.record.exists(), "never re-creates the pairing");
            }
            assert!(
                app.status_message
                    .unwrap()
                    .starts_with("Transport policy not saved")
            );
        });
    }
}

/// Relay only arriving on a local link: stored, acknowledged, then the
/// local link is dropped so the reconnect goes through the relay.
#[test]
fn relay_only_drops_a_local_link_after_the_ack() {
    local(async {
        let dir = short_dir();
        let profile = dir.path().join("profile");
        paired(&profile);
        let (mut app, mut peer) = linked_app(&profile, local_via()).await;
        app.handle_astation_message(AstationMessage::TransportPolicy { relay_only: true })
            .await;
        let ack = peer.next("transportPolicyAck").await;
        assert_eq!(ack["data"], stored(true));
        assert!(record(&profile).relay_only);
        assert!(!app.astation_connected);
        assert!(app.astation_reconnect_at.is_some(), "the normal reconnect");
        assert!(peer.drain(WAIT).await, "the local socket closed");
        // Relay only off on a local link: kept, no reconnect.
        let (mut app, mut peer) = linked_app(&profile, local_via()).await;
        app.handle_astation_message(AstationMessage::TransportPolicy { relay_only: false })
            .await;
        assert_eq!(peer.next("transportPolicyAck").await["data"], stored(false));
        assert!(!record(&profile).relay_only);
        assert!(app.astation_connected);
    });
}

/// While an Astation operation runs on the local link, relay only is stored
/// and acknowledged at once (a repeat too) but the link stays until the
/// operation ends; then it is dropped, once.
#[test]
fn relay_only_waits_for_the_operation_on_the_local_link() {
    local(async {
        let dir = short_dir();
        let profile = dir.path().join("profile");
        paired(&profile);
        let (mut app, mut peer) = linked_app(&profile, local_via()).await;
        let (tx, _op) = mpsc::channel(4);
        app.op_route = Some(crate::app::op_route::OpRoute {
            link_gen: app.astation_link_gen,
            tx,
            encryption: false,
            credentials: false,
        });
        for _ in 0..2 {
            app.handle_astation_message(AstationMessage::TransportPolicy { relay_only: true })
                .await;
            assert_eq!(peer.next("transportPolicyAck").await["data"], stored(true));
        }
        assert!(record(&profile).relay_only);
        app.process_astation_messages().await;
        assert!(app.astation_connected, "the operation keeps its link");
        assert!(!peer.drain(Duration::from_millis(200)).await);
        app.close_op_route();
        app.process_astation_messages().await;
        assert!(!app.astation_connected, "dropped once the operation ended");
        assert!(app.astation_reconnect_at.is_some());
        assert_eq!(app.relay_only_drop, None);
        assert!(peer.drain(WAIT).await, "the local socket closed");
        assert_eq!(acks(&peer).len(), 2);
    });
}

/// A policy arriving while the link re-authenticates is dropped like every
/// other request; Astation's resend after the authentication is applied.
#[test]
fn transport_policy_during_re_authentication_is_dropped_then_applied() {
    local(async {
        let dir = short_dir();
        let profile = dir.path().join("profile");
        paired(&profile);
        let (mut app, mut peer) = linked_app(&profile, relay()).await;
        app.astation_reauth = Some(Instant::now() + Duration::from_secs(15));
        app.handle_astation_message(AstationMessage::TransportPolicy { relay_only: true })
            .await;
        peer.drain(Duration::from_millis(200)).await;
        assert!(acks(&peer).is_empty(), "{:#?}", peer.seen);
        assert!(!record(&profile).relay_only);
        // Authenticated again; Astation sends it after every authentication.
        app.astation_reauth = None;
        app.handle_astation_message(AstationMessage::TransportPolicy { relay_only: true })
            .await;
        assert_eq!(peer.next("transportPolicyAck").await["data"], stored(true));
        assert!(record(&profile).relay_only);
    });
}

/// A replaced connection: what the old link still had queued is never read
/// (no ack, no effect); the new link's policies apply in order, the later
/// one winning.
#[test]
fn the_later_link_s_transport_policy_wins() {
    local(async {
        let dir = short_dir();
        let profile = dir.path().join("profile");
        paired(&profile);
        let (mut app, mut old) = linked_app(&profile, relay()).await;
        old.send(&AstationMessage::TransportPolicy { relay_only: true });
        tokio::time::sleep(Duration::from_millis(200)).await;
        // The link is replaced (a reconnect) before the old one's message is read.
        app.drop_astation_link("replaced".into());
        let (url, mut new) = Peer::listen().await;
        app.astation_client = link_to(&profile, &url, relay()).await;
        app.astation_connected = true;
        app.astation_link_gen += 1;
        new.send(&AstationMessage::TransportPolicy { relay_only: true });
        new.send(&AstationMessage::TransportPolicy { relay_only: false });
        for _ in 0..50 {
            app.process_astation_messages().await;
            if acks(&new).len() == 2 {
                break;
            }
            new.drain(Duration::from_millis(20)).await;
        }
        assert_eq!(acks(&new), vec![stored(true), stored(false)]);
        assert!(!record(&profile).relay_only, "the later value");
        old.drain(Duration::from_millis(200)).await;
        assert!(
            acks(&old).is_empty(),
            "the old link's message was never applied"
        );
    });
}

/// The ack's flush gives up after 5 s (a writer that never writes): the
/// local link is dropped anyway, with the policy stored.
#[test]
fn relay_only_drops_the_local_link_when_the_ack_flush_times_out() {
    local(async {
        let dir = short_dir();
        let profile = dir.path().join("profile");
        paired(&profile);
        let (mut app, _peer) = linked_app(&profile, local_via()).await;
        let _stalled = app.astation_client.stall_writer_for_test();
        let started = Instant::now();
        app.handle_astation_message(AstationMessage::TransportPolicy { relay_only: true })
            .await;
        assert!(started.elapsed() >= Duration::from_secs(5));
        assert!(record(&profile).relay_only);
        assert!(!app.astation_connected);
        assert!(app.astation_reconnect_at.is_some());
    });
}

/// The connect loop skips the local `astation_ws` while the stored policy
/// says relay only, also in a new App (a restarted runtime); with the relay
/// unreachable it fails without trying local and retries in 30 s (no spin).
/// Without relay only it tries local.
#[test]
fn the_connect_loop_skips_local_while_relay_only() {
    for relay_only in [true, false] {
        local(async {
            let config = crate::config::AtemConfig::config_dir();
            paired(&config);
            {
                // Stored by an earlier runtime's link.
                let (mut app, mut peer) = linked_app(&config, relay()).await;
                app.handle_astation_message(AstationMessage::TransportPolicy { relay_only })
                    .await;
                assert_eq!(
                    peer.next("transportPolicyAck").await["data"],
                    stored(relay_only)
                );
            }
            let local = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            std::fs::write(
                config.join("config.toml"),
                format!(
                    "astation_ws = \"ws://{}/ws\"\nastation_relay_url = \"http://127.0.0.1:1\"\natem_id = \"{ATEM_ID}\"\n",
                    local.local_addr().unwrap()
                ),
            )
            .unwrap();
            let mut app = App::new();
            app.spawn_astation_connect();
            let tried = tokio::time::timeout(Duration::from_millis(500), local.accept())
                .await
                .is_ok();
            assert_eq!(tried, !relay_only, "relay_only {relay_only}");
            if relay_only {
                let started = Instant::now();
                while app.astation_connect_rx.is_some() {
                    assert!(started.elapsed() < WAIT);
                    app.poll_astation_connect();
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                assert!(!app.astation_connected);
                let retry = app.astation_reconnect_at.expect("a retry");
                assert!(retry >= Instant::now() + Duration::from_secs(25), "no spin");
            }
        });
    }
}

/// A runtime of another build is never replaced while an Astation
/// operation runs: `restart` is refused and the client keeps it, saying why.
#[test]
fn the_runtime_is_not_replaced_while_an_operation_runs() {
    local(async {
        let dir = Rc::new(short_dir());
        paired(&dir.path().join("profile"));
        let (url, mut peer) = Peer::listen().await;
        let keys = CredPaths::in_dir(&dir.path().join("profile"));
        let rt = Runtime::start(dir.clone(), Some(&url), Arc::new(test_agent(&keys))).await;
        let (mut op, question, _) = verify_until_the_question(&rt, &mut peer, "acct-op").await;
        let mut other = rt.client().await;
        other.send(&ClientMsg::Restart).await.unwrap();
        let refused = expect(&mut other, |m| match m {
            RuntimeMsg::Error { text, op } if op.as_deref() == Some("restart") => Some(text),
            _ => None,
        })
        .await;
        assert!(
            refused.starts_with(crate::runtime::client::BUSY_RESTART),
            "{refused}"
        );
        // The client's replacement keeps it and says why.
        let locator = crate::runtime::client::Locator::in_dir(dir.path());
        let start = || anyhow::bail!("never started while the runtime runs");
        let mut notes = Vec::new();
        let client = crate::runtime::client::replace_other_build(
            rt.client().await,
            &locator,
            "0.0.0+another-build",
            &start,
            Duration::from_secs(5),
            |line| notes.push(line),
        )
        .await
        .unwrap();
        assert_eq!(client.welcome.pid, std::process::id());
        assert_eq!(notes.len(), 1, "{notes:?}");
        assert!(notes[0].contains("Astation operation"), "{notes:?}");
        assert!(!locator.replaced.exists(), "no replacement recorded");
        // The operation goes on.
        op.answer(question, AnswerValue::No).await;
        assert_eq!(op.done().await.unwrap_err(), "device verification failed");
        rt.shutdown().await;
    });
}

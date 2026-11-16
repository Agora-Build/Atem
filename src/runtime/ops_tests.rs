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
/// The longest a "wait until" helper waits. A passing run never gets near it;
/// a slow runner (the Intel macOS CI one takes ~340 s for ~45 s of tests) needs
/// the slack, and a hung test still ends.
const WAIT: Duration = Duration::from_secs(60);
/// Sent to the peer task: close the WebSocket.
const CLOSE: &str = "\u{0}close";
/// Sent to the peer task: close the WebSocket with 1013, as the Station
/// closes a just-verified host's socket so it reconnects and proves its
/// route under the new device list.
const CLOSE_AGAIN: &str = "\u{0}close-1013";

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
    /// r9: per channel handle, the index in `seen` read up to.
    channel_at: std::collections::HashMap<String, usize>,
}

/// A client's monotonic ms (its own clock).
fn client_ms() -> u64 {
    static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    START.get_or_init(Instant::now).elapsed().as_millis() as u64 + 1
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
                        if text == CLOSE_AGAIN {
                            use tokio_tungstenite::tungstenite::protocol::CloseFrame;
                            use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
                            let _ = socket
                                .close(Some(CloseFrame {
                                    code: CloseCode::Again,
                                    reason: "reconnect/reprove".into(),
                                }))
                                .await;
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
            channel_at: Default::default(),
        };
        (format!("ws://{address}/ws"), peer)
    }

    /// r9 (§R9.7a): the next `frame` Atem sends on `handle` (its inner
    /// frame's bytes), or `Err(reason)` for its `close`.
    async fn channel_next(&mut self, handle: &str) -> Result<Vec<u8>, Option<String>> {
        let from = self.channel_at.get(handle).copied().unwrap_or(0);
        let h = handle.to_string();
        let at = self
            .wait_from(from, |v| {
                v["type"] == "channel" && v["channel"] == h.as_str()
            })
            .await;
        self.channel_at.insert(handle.to_string(), at + 1);
        let v = self.seen[at].clone();
        match v["event"].as_str() {
            Some("frame") => Ok(serde_json::to_vec(&v["frame"]).unwrap()),
            _ => Err(v["reason"].as_str().map(str::to_string)),
        }
    }

    /// The router side: one client frame on `handle`.
    fn channel_send(&self, handle: &str, frame: &[u8]) {
        self.to_atem
            .send(crate::session_protocol::r9::envelope::frame(handle, frame))
            .unwrap();
    }

    /// Opens `handle` and runs a full `atem-ch1` handshake for `identity`
    /// with `log`'s keys; the attachment, or the refusal's code and detail.
    async fn r9_connect(
        &mut self,
        handle: &str,
        log: &crate::session_protocol::membership::r9log::TestLog,
        host_id: &str,
        identity: atem_client::connect::Identity,
    ) -> Result<atem_client::connect::Attached, (String, Option<String>)> {
        use crate::session_protocol::r9::envelope;
        self.to_atem
            .send(envelope::open(handle, envelope::Transport::Direct))
            .unwrap();
        let (connecting, init) = atem_client::connect::Connector::new(host_id)
            .start(&log.log, client_ms())
            .map_err(|e| (format!("{e:?}"), None))?;
        self.channel_send(handle, &init);
        let accept = self
            .channel_next(handle)
            .await
            .map_err(|r| ("closed".into(), r))?;
        if let Ok(atem_client::channel::wire::Frame::Error { code }) =
            atem_client::channel::wire::parse_frame(&accept)
        {
            return Err((code, None));
        }
        let (welcoming, finish) = connecting
            .on_accept(&accept, &log.log, &log.keys, &identity, client_ms())
            .map_err(|e| (format!("{e:?}"), None))?;
        self.channel_send(handle, &finish);
        let first = self
            .channel_next(handle)
            .await
            .map_err(|r| ("closed".into(), r))?;
        match welcoming.on_frame(&first, &log.log, client_ms()) {
            Ok(attached) => Ok(attached),
            Err(atem_client::connect::ConnectError::Refused { error, .. }) => {
                Err((error.code.clone(), error.detail.clone()))
            }
            Err(e) => Err((format!("{e:?}"), None)),
        }
    }

    /// Sends `frame` on `handle` and returns the events of Atem's next record.
    async fn r9_round(
        &mut self,
        handle: &str,
        attached: &mut atem_client::connect::Attached,
        frame: &[u8],
    ) -> Vec<atem_client::connect::Event> {
        self.channel_send(handle, frame);
        let reply = self.channel_next(handle).await.expect("a record");
        attached.on_frame(&reply, client_ms()).unwrap()
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

    /// Closes the WebSocket with 1013 ("try again later").
    fn close_again(&self) {
        let _ = self.to_atem.send(CLOSE_AGAIN.into());
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
    /// r9: the account's device list (the Mac genesis, signed by `fake`).
    log: std::cell::RefCell<crate::session_protocol::membership::r9log::TestLog>,
    /// `verifyCommit.host_trust_gen` (§R9.2).
    advertised: u64,
}

/// The host trust generation of the profile at `dir`.
fn trust_gen(dir: &Path) -> u64 {
    crate::pairing::load(&crate::profile::Sources::in_dir(dir))
        .unwrap()
        .binding
        .unwrap()
        .host_trust_gen
}

impl Verifier {
    /// Waits for `verifyCommit`, answers with `verifyKeys`.
    async fn keys(peer: &mut Peer, account: &str) -> Self {
        let fake = FakeAstation::new();
        let log = crate::session_protocol::membership::r9log::TestLog::genesis(
            account,
            &fake.sign_secret_bytes(),
        );
        Self::answer_commit(peer, fake, log, account).await
    }

    /// A re-verify with the same Astation: waits for the next
    /// `verifyCommit` and answers it with the same keys and the account's
    /// device list as it stands (this ceremony's `add_host` grows it).
    async fn again(self, peer: &mut Peer) -> Self {
        let account = self.account.clone();
        Self::answer_commit(peer, self.fake, self.log.into_inner(), &account).await
    }

    async fn answer_commit(
        peer: &mut Peer,
        fake: FakeAstation,
        log: crate::session_protocol::membership::r9log::TestLog,
        account: &str,
    ) -> Self {
        let commit = peer.next("verifyCommit").await;
        let commitment: [u8; 32] = STANDARD
            .decode(commit["data"]["commitment"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap();
        // r9: the advertised generation, as Astation must read it.
        let advertised =
            atem_client::ceremony::verify_commit_host_trust_gen(commit.to_string().as_bytes())
                .expect("verifyCommit carries host_trust_gen");
        let nonce_s = [7u8; 32];
        peer.send(&AstationMessage::VerifyKeys {
            sign_pub: STANDARD.encode(fake.sign_pub()),
            enc_pub: STANDARD.encode(fake.enc_pub()),
            recovery_sign_pub: STANDARD.encode([6u8; 32]),
            nonce: STANDARD.encode(nonce_s),
            genesis_hash: Some(log.genesis_hash().to_hex()),
            account_id: Some(json!(account)),
        });
        Self {
            fake,
            commitment,
            device_id: commit["data"]["device_id"].as_str().unwrap().to_string(),
            nonce_s,
            account: account.to_string(),
            log: std::cell::RefCell::new(log),
            advertised,
        }
    }

    /// The signed `deviceVerified` for `reveal` (its list as it stands).
    fn certificate_for(&self, reveal: &Value) -> AstationMessage {
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
            membership: Some(json!({"entries": self.log.borrow().wire()})),
        }
    }

    /// Astation's checks of the reveal's `host_enc_key` (host-work-v1
    /// §11.5): its public half and `enc_sig`.
    fn revealed_key(&self, reveal: &Value) -> ([u8; 32], [u8; 64]) {
        crate::session_protocol::membership::r9log::reveal_host_enc_key(
            &reveal["data"],
            &self.account,
            &self.log.borrow().genesis_hash(),
            &self.device_id,
            self.advertised,
        )
        .unwrap_or_else(|e| panic!("Astation refuses the reveal: {e}"))
    }

    /// Waits for `verifyReveal`; the signed `deviceVerified` for it, with
    /// the device list ending at this host's `add_host` (trust generation
    /// `host_trust_gen`, the revealed host channel key).
    async fn certificate(&self, peer: &mut Peer, host_trust_gen: u64) -> AstationMessage {
        let reveal = peer.next("verifyReveal").await;
        let host_pub: [u8; 32] = atem_client::encoding::b64u_decode(
            reveal["data"]["host_channel_pub"].as_str().unwrap(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        // Astation copies the advertised generation into the add_host.
        assert_eq!(self.advertised, host_trust_gen, "the binding's generation");
        self.revealed_key(&reveal);
        self.log
            .borrow_mut()
            .add_host_pub(&self.device_id, self.advertised, &host_pub);
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
            membership: Some(json!({"entries": self.log.borrow().wire()})),
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
        Self::start_with(dir, peer_url, agent, |_| {}).await
    }

    /// [`Runtime::start`], with `configure` applied to the App before it is
    /// served.
    async fn start_with(
        dir: Rc<tempfile::TempDir>,
        peer_url: Option<&str>,
        agent: Arc<dyn CredAgentApi>,
        configure: impl FnOnce(&mut App),
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
        configure(&mut app);
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
        tokio::time::timeout(WAIT, &mut self.server)
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
) -> (Op, u64, AstationMessage, Verifier) {
    let op = Op::start(rt.client().await, OpKind::PairVerify, OpOptions::default()).await;
    let verifier = Verifier::keys(peer, account).await;
    let certificate = verifier.certificate(peer, trust_gen(&rt.profile)).await;
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
    (op, question, certificate, verifier)
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

        let (mut op, question, certificate, verifier) =
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
        // r9: the ceremony pinned the account's device list and this host's
        // channel key.
        let pairing = crate::paths::ProfilePaths::in_dir(&rt.profile).pairing;
        assert!(pairing.membership.exists(), "the device list is pinned");
        assert!(
            pairing.host_channel_key.exists(),
            "with the host channel key"
        );

        // The same link (never reconnected) carries r9 now: the device
        // list pinned while the runtime ran is picked up, an r8 hello is
        // refused (no compatibility) and the Mac, the list's genesis member,
        // is admitted through the channel envelope on that link.
        assert!(
            !peer.drain(Duration::from_millis(200)).await,
            "the link closed"
        );
        let refused = peer.hello().await;
        assert_eq!(refused["op"], "error", "{refused}");
        assert_eq!(refused["code"], "unsupported_version");
        assert_eq!(refused["revision"], 9);
        let mac = atem_client::connect::Identity::native(
            crate::session_protocol::membership::r9log::MAC,
            crate::session_protocol::membership::r9log::auth(
                crate::session_protocol::membership::r9log::MAC,
            ),
        );
        let log = verifier.log.into_inner();
        let mut attached = peer
            .r9_connect("mac-1", &log, ATEM_ID, mac)
            .await
            .unwrap_or_else(|e| panic!("refused: {e:?}"));
        let w = attached.welcome().clone();
        assert_eq!(w.account_id, "acct-op");
        assert_eq!(w.atem_device_id, ATEM_ID);
        assert_eq!(w.principal, "member:dev-mac");
        assert_eq!(w.head, log.log.head());
        let (_, frame) = attached.list(client_ms()).unwrap();
        let events = peer.r9_round("mac-1", &mut attached, &frame).await;
        assert!(
            events
                .iter()
                .any(|e| matches!(e, atem_client::connect::Event::Session(m)
                if matches!(&m.op, crate::session_protocol::wire::Op::Sessions { sessions, .. }
                    if sessions.iter().any(|d| d.session_id == session.id.as_str())))),
            "{events:?}"
        );
        frontend
            .send(&ClientMsg::input(&session.id, b"AFTER\r"))
            .await
            .unwrap();
        shows(&mut frontend, "AFTER").await;
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
        let (mut op, question, certificate, _) =
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
        let (mut op, question, _certificate, _) =
            verify_until_the_question(&rt, &mut peer, "acct-op").await;
        op.answer(question, AnswerValue::Yes).await;
        op.printed("Waiting for your Mac").await;
        peer.close();
        let error = op.done().await.unwrap_err();
        assert_eq!(error, crate::pair_verify::PAIRED_NOT_VERIFIED);
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

/// Astation PR #81: on a re-verify the Station delivers `deviceVerified`,
/// flushes it and closes the socket with 1013, so the host reconnects and
/// proves its route under the new device list. The certificate came before
/// the close: it is applied and the verification succeeds; nothing is
/// aborted. Also behind 40 other messages (more than the App's pump takes
/// in one pass).
#[test]
fn a_certificate_then_a_1013_close_still_verifies() {
    for ahead in [0, 40] {
        a_certificate_then_a_1013_close_verifies(ahead);
    }
}

fn a_certificate_then_a_1013_close_verifies(ahead: usize) {
    local(async {
        let dir = Rc::new(short_dir());
        paired(&dir.path().join("profile"));
        let (url, mut peer) = Peer::listen().await;
        let keys = CredPaths::in_dir(&dir.path().join("profile"));
        let rt = Runtime::start(dir, Some(&url), Arc::new(test_agent(&keys))).await;
        let (mut op, question, certificate, _) =
            verify_until_the_question(&rt, &mut peer, "acct-op").await;
        op.answer(question, AnswerValue::Yes).await;
        op.printed("Waiting for your Mac").await;
        for n in 0..ahead {
            peer.send(&AstationMessage::Heartbeat {
                timestamp: n.to_string(),
            });
        }
        peer.send(&certificate);
        peer.close_again();
        op.done()
            .await
            .unwrap_or_else(|error| panic!("{ahead} ahead: {error}"));
        assert!(
            op.printed.iter().any(|l| l.contains("Device verified")),
            "{:?}",
            op.printed
        );
        assert!(verified_as(&rt.keys(), "acct-op"));
        let pairing = crate::paths::ProfilePaths::in_dir(&rt.profile).pairing;
        assert!(pairing.membership.exists(), "the device list is pinned");
        assert!(
            pairing.host_channel_key.exists(),
            "with the host channel key"
        );
        assert!(!pending(&rt.keys()), "no pending pin");
        assert!(peer.drain(Duration::from_millis(200)).await, "closed");
        assert!(
            !peer.seen.iter().any(|m| m["type"] == "verifyAbort"),
            "{:#?}",
            peer.seen
        );
        rt.shutdown().await;
    });
}

/// The App's pump hands on every message the reader decoded before the
/// socket closed, in order, before it calls the link down: a certificate
/// behind 40 others (more than one pass takes) still reaches its
/// operation; each pass takes at most 32, the rest waits for the next.
#[test]
fn the_pump_routes_a_certificate_queued_behind_a_backlog() {
    local(async {
        let profile = crate::config::AtemConfig::config_dir();
        paired(&profile);
        let (mut app, peer) = linked_app(&profile, relay()).await;
        let mut op = op_on_link(&mut app);
        for n in 0..40 {
            peer.send(&AstationMessage::Heartbeat {
                timestamp: n.to_string(),
            });
        }
        let signer = FakeAstation::new();
        peer.send(&AstationMessage::DeviceVerified {
            device_verified: signer.sign(b"x"),
            account_state: signer.sign(b"y"),
            grants: Vec::new(),
            membership: None,
        });
        peer.close_again();
        // The reader has queued all 41 and read the close.
        tokio::time::timeout(WAIT, async {
            while !app.astation_client.transport_ended() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("the socket closed");
        pass(&mut app).await;
        assert!(app.astation_connected, "9 messages are still queued");
        assert!(op.try_recv().is_err(), "the certificate is the 41st");
        pass(&mut app).await;
        assert!(
            matches!(op.try_recv(), Ok(AstationMessage::DeviceVerified { .. })),
            "the certificate reached the operation"
        );
        assert!(!app.astation_connected, "then the link is down");
        assert!(app.astation_reconnect_at.is_some(), "the normal reconnect");
    });
}

/// The profile's verification with `ASTATION` forgotten (its device list
/// and host channel key stay), so `atem pair verify` runs the ceremony
/// again, as Astation's re-verify of a route-proved host does.
fn unverify(keys: &CredPaths) {
    let mut trust: Value =
        serde_json::from_str(&std::fs::read_to_string(&keys.trust).unwrap()).unwrap();
    trust["astations"]
        .as_object_mut()
        .unwrap()
        .remove(ASTATION)
        .expect("verified");
    std::fs::write(&keys.trust, trust.to_string()).unwrap();
}

/// What the fake relay saw, in order.
#[derive(Debug)]
enum RelayEvent {
    /// Connection `n` (from 1) opened.
    Connected(usize),
    /// Connection `n`'s `host_route` answer, with its challenge.
    Proof(usize, atem_client::host_route::HostChallenge, String),
    /// Connection `n` closed.
    Closed(usize),
}

/// The fake relay's next event.
async fn relay_event(relay: &mut mpsc::UnboundedReceiver<RelayEvent>) -> RelayEvent {
    tokio::time::timeout(WAIT, relay.recv())
        .await
        .expect("a relay event")
        .unwrap()
}

/// A fake relay at the URL returned: every connection gets a
/// `host_challenge` for `ASTATION`'s room at once (§R9.7b). Each
/// `host_route` answer is checked against `log` (once set) and answered
/// `host_route_ok` or `host_route_refused`, as the relay does, so a proved
/// link is held routed. Everything it sees is reported.
async fn challenging_relay(
    log: Rc<std::cell::RefCell<Option<atem_client::membership::Membership>>>,
) -> (String, mpsc::UnboundedReceiver<RelayEvent>) {
    use atem_client::host_route::{HostChallenge, RelayReply, verify_host_route_message};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    tokio::task::spawn_local(async move {
        let mut n = 0;
        while let Ok((stream, _)) = listener.accept().await {
            n += 1;
            let (tx, log) = (tx.clone(), log.clone());
            tokio::task::spawn_local(async move {
                let Ok(mut socket) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                let _ = tx.send(RelayEvent::Connected(n));
                let challenge = HostChallenge::new(ASTATION);
                let text = challenge.to_json().to_string();
                if socket.send(WsMessage::Text(text)).await.is_ok() {
                    while let Some(Ok(message)) = socket.next().await {
                        let WsMessage::Text(text) = message else {
                            continue;
                        };
                        if !serde_json::from_str::<Value>(&text)
                            .is_ok_and(|v| v["op"] == "host_route")
                        {
                            continue;
                        }
                        let reply = log.borrow().as_ref().map(|log| {
                            let verdict = verify_host_route_message(
                                log,
                                text.as_bytes(),
                                &challenge.nonce,
                                ASTATION,
                                ATEM_ID,
                            );
                            match verdict {
                                Ok(route) => RelayReply::ok(&route),
                                Err(refusal) => RelayReply::refused(&refusal),
                            }
                            .to_json()
                            .to_string()
                        });
                        let _ = tx.send(RelayEvent::Proof(n, challenge.clone(), text));
                        if let Some(reply) = reply
                            && socket.send(WsMessage::Text(reply)).await.is_err()
                        {
                            break;
                        }
                    }
                }
                let _ = tx.send(RelayEvent::Closed(n));
            });
        }
    });
    (format!("http://{address}"), rx)
}

/// Astation PR #81: a re-verify of a host whose list is pinned, on a relay
/// link; the Station delivers `deviceVerified`, then closes the socket with
/// 1013, and the host reconnects. The new link answers the relay's
/// challenge with the new `host_channel_key` at the new head (the list the
/// verification pinned), never the old ones: the reconnect waits for the
/// operation to end and for the host's next pass to read the new list.
#[test]
fn the_reconnect_after_a_reverify_proves_its_route_with_the_new_key() {
    local(async {
        let dir = Rc::new(short_dir());
        let profile = dir.path().join("profile");
        paired(&profile);
        let keys = CredPaths::in_dir(&profile);
        let agent: Arc<dyn CredAgentApi> = Arc::new(test_agent(&keys));
        // A first verification pins the list with this host's first key.
        let (url, mut peer) = Peer::listen().await;
        let rt = Runtime::start(dir.clone(), Some(&url), agent.clone()).await;
        let (mut op, question, certificate, verifier) =
            verify_until_the_question(&rt, &mut peer, "acct-op").await;
        op.answer(question, AnswerValue::Yes).await;
        op.printed("Waiting for your Mac").await;
        peer.send(&certificate);
        peer.next("storageKeyRotate").await;
        peer.send(&AstationMessage::StorageKeyRejected {
            reason: "not now".into(),
            pending_kid: None,
        });
        op.done().await.unwrap();
        let old_head = verifier.log.borrow().log.head();
        rt.shutdown().await;
        let _ = std::fs::remove_file(dir.path().join("rt.sock"));
        unverify(&keys);
        // No local Astation; the relay challenges every connection at once
        // and routes a host whose proof its log verifies.
        let relay_log = Rc::new(std::cell::RefCell::new(None));
        let (relay_url, mut seen) = challenging_relay(relay_log.clone()).await;
        std::fs::write(
            profile.join("config.toml"),
            format!(
                "astation_ws = \"ws://127.0.0.1:1/ws\"\nastation_relay_url = \"{relay_url}\"\natem_id = \"{ATEM_ID}\"\n"
            ),
        )
        .unwrap();
        // The runtime on a relay link that reconnects as in production.
        let (url, mut peer) = Peer::listen().await;
        let rt = Runtime::start_with(dir, Some(&url), agent, |app| {
            app.astation_reconnect = true;
            app.astation_client.set_via_for_test(relay());
        })
        .await;
        let mut op = Op::start(rt.client().await, OpKind::PairVerify, OpOptions::default()).await;
        let verifier = verifier.again(&mut peer).await;
        let certificate = verifier
            .certificate(&mut peer, trust_gen(&rt.profile))
            .await;
        // The relay holds the grown list (Astation published the add_host).
        let new_head = verifier.log.borrow().log.head();
        *relay_log.borrow_mut() = Some(verifier.log.into_inner().log);
        let (question, _, _) = op.ask().await;
        op.answer(question, AnswerValue::Yes).await;
        op.printed("Waiting for your Mac").await;
        peer.send(&certificate);
        peer.close_again();
        op.done().await.unwrap();
        let first = relay_event(&mut seen).await;
        assert!(matches!(first, RelayEvent::Connected(1)), "{first:?}");
        let RelayEvent::Proof(1, challenge, answer) = relay_event(&mut seen).await else {
            panic!("the reconnect answered the relay's challenge");
        };
        let route = atem_client::host_route::verify_host_route_message(
            relay_log.borrow().as_ref().unwrap(),
            answer.as_bytes(),
            &challenge.nonce,
            ASTATION,
            ATEM_ID,
        )
        .unwrap_or_else(|refusal| panic!("refused: {}", refusal.code()));
        assert_eq!(route.head, new_head, "at the new head");
        assert_ne!(route.head, old_head);
        // One reconnect: the routed link stays (a second reconnect would
        // close it, or open another connection, within a pass or two).
        match tokio::time::timeout(Duration::from_secs(2), seen.recv()).await {
            Err(_) => {}
            Ok(Some(RelayEvent::Closed(n))) => panic!("one reconnect: connection {n} closed"),
            Ok(event) => panic!("one reconnect: {event:?}"),
        }
        let mut status = rt.client().await;
        status.send(&ClientMsg::Status).await.unwrap();
        let status = expect(&mut status, |m| match m {
            RuntimeMsg::Status { status } => Some(status),
            _ => None,
        })
        .await;
        assert!(status.routed, "held routed on its proof");
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
        let (mut op, question, _, _) = verify_until_the_question(&rt, &mut peer, "acct-op").await;
        for kind in [OpKind::CredUnlock, OpKind::Pair, OpKind::PairVerify] {
            let mut second = Op::start(rt.client().await, kind, OpOptions::default()).await;
            assert_eq!(second.done().await.unwrap_err(), BUSY);
        }
        // The first one is unaffected: a refusal of the code ends it.
        op.answer(question, AnswerValue::No).await;
        let error = op.done().await.unwrap_err();
        assert_eq!(error, crate::pair_verify::PAIRED_NOT_VERIFIED);
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
            membership: None,
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

/// The pairing bootstrap's receive path: what the link's reader makes of
/// raw frames (the contract's 4096-byte bound including, exact shapes, no
/// unknown or duplicate fields, UUID ids, v1), before `atem pair` sees them.
#[test]
fn pairing_frames_are_read_strictly_on_the_receive_path() {
    local(async {
        let dir = short_dir();
        let profile = dir.path().join("profile");
        paired(&profile);
        let (url, peer) = Peer::listen().await;
        let mut client = link_to(&profile, &url, relay()).await;
        const ID: &str = "1dc7bd24-391c-4d16-8b6e-1121e75a2af8";
        let intro = format!(
            r#"{{"type":"pairing","data":{{"v":1,"op":"introduction","id":"{ID}","astation_id":"{ASTATION}"}}}}"#
        );
        let padded = |len: usize| format!("{intro}{}", " ".repeat(len - intro.len()));
        let cases: Vec<(String, bool)> = vec![
            (intro.clone(), true),
            (intro.clone(), true), // a retransmitted reply reads the same
            (padded(4096), true),
            (padded(4097), false),
            (intro.replace(r#""v":1"#, r#""v":2"#), false),
            (intro.replace(ID, "not-a-uuid"), false),
            (
                intro.replace(r#"}}"#, r#","code":"pairing_cancelled"}}"#),
                false,
            ),
            (intro.replace(r#"}}"#, r#","extra":1}}"#), false),
            (
                intro.replace(
                    r#""astation_id""#,
                    r#""astation_id":"astation-x","astation_id""#,
                ),
                false,
            ),
            (
                format!(
                    r#"{{"type":"pairing","data":{{"v":1,"op":"error","id":"{ID}","code":"not_signed_in"}}}}"#
                ),
                true,
            ),
        ];
        for (frame, valid) in &cases {
            peer.to_atem.send(frame.clone()).unwrap();
            let message = tokio::time::timeout(WAIT, client.recv_message_async())
                .await
                .expect("a message")
                .expect("the link is open");
            match message {
                AstationMessage::Pairing { .. } => assert!(valid, "accepted: {frame}"),
                AstationMessage::PairingInvalid { .. } => assert!(!valid, "refused: {frame}"),
                other => panic!("{other:?} for {frame}"),
            }
        }
    });
}

/// A record without a binding (left by v0.7.2's background reconnect) is
/// not a pairing: `atem pair` proceeds and replaces it.
#[test]
fn pair_replaces_a_record_without_a_binding() {
    first_pairing(Some(ASTATION));
    first_pairing(Some("astation-other"));
}

/// Astation's side of a first local pairing up to the granted session: the
/// authenticated loopback challenge, the pairing code `atem pair` shows, and
/// the grant. The verification follows on the same connection.
async fn grant_a_local_pairing(peer: &mut Peer, op: &mut Op) {
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

        grant_a_local_pairing(&mut peer, &mut op).await;
        // Local pairing: the authenticated loopback challenge named
        // Astation, so no bootstrap hello and no credentials (the
        // token-free design); the verification below establishes trust.
        // Verification on the same connection, now the runtime's link.
        let verifier = Verifier::keys(&mut peer, "acct-new").await;
        let certificate = verifier
            .certificate(&mut peer, trust_gen(&rt.profile))
            .await;
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
        assert!(op.printed.iter().any(|l| l == "Paired with Astation."));
        assert!(
            !peer.seen.iter().any(|m| m["type"] == "pairing"),
            "no bootstrap on a local link"
        );
        assert!(!op.printed.iter().any(|l| l.contains("SSO")));

        let src = crate::profile::Sources::in_dir(&rt.profile);
        let binding = crate::pairing::load(&src).unwrap().binding.unwrap();
        assert_eq!(binding.astation_id, ASTATION);
        // No Login fabricated, nothing to save without `--save`.
        assert!(fresh_shared(&rt.profile).is_none());
        assert!(record(&rt.profile).shared.is_none());
        assert!(!record(&rt.profile).save_credentials);
        assert_eq!(record(&rt.profile).astation_id, ASTATION);
        assert_eq!(
            record(&rt.profile).session.unwrap().session_id,
            "session-new",
            "the pairing saved the granted session"
        );
        assert!(verified_as(&rt.keys(), "acct-new"));
        // The pairing pinned a device list: the link's r8 hello is refused
        // (no compatibility; r9 clients come through the channel).
        let refused = peer.hello().await;
        assert_eq!(refused["op"], "error", "{refused}");
        assert_eq!(refused["revision"], 9);
        rt.shutdown().await;
    });
}

/// Where the first printed line containing `needle` is.
fn line_with(printed: &[String], needle: &str) -> usize {
    printed
        .iter()
        .position(|line| line.contains(needle))
        .unwrap_or_else(|| panic!("no line with {needle:?}: {printed:#?}"))
}

/// What Astation says when it stops the verification (the real run that
/// motivated the wording: Astation wasn't signed in).
const SIGN_IN_FIRST: &str = "Sign in to Agora.Build in Settings > Account to continue.";

/// The output of a verification Astation stopped, for `atem pair` and
/// `atem pair verify` alike: the encryption status the held message
/// produced comes first, then the reason as the last printed line, then the
/// error that says the device is paired but not verified. Nothing lands
/// between the reason and the error, and no line says the pairing failed.
fn assert_stopped_verification_output(printed: &[String], error: &str, after: &str) {
    assert_eq!(error, crate::pair_verify::PAIRED_NOT_VERIFIED);
    assert!(error.starts_with("Paired, but"), "{error}");
    assert!(
        error.contains("'atem pair verify'"),
        "the next step is in the error: {error}"
    );
    let reason = line_with(printed, "Astation stopped device verification");
    assert!(printed[reason].contains(SIGN_IN_FIRST), "{printed:#?}");
    assert_eq!(
        reason,
        printed.len() - 1,
        "the reason is the last line: {printed:#?}"
    );
    let status = line_with(printed, "Ignored an unsigned encryption mode");
    assert!(line_with(printed, after) < status, "{printed:#?}");
    assert!(
        status < reason,
        "status before the failure's lines: {printed:#?}"
    );
    for line in printed {
        assert!(!line.contains("device verification failed"), "{line}");
        assert!(
            !line.contains("Pairing is saved"),
            "said once, in the error: {line}"
        );
    }
}

/// `atem pair` whose verification Astation stops: paired, not verified.
#[test]
fn a_stopped_verification_ends_atem_pair_with_one_clear_message() {
    local(async {
        let dir = Rc::new(short_dir());
        let profile = dir.path().join("profile");
        std::fs::create_dir_all(&profile).unwrap();
        let (url, mut peer) = Peer::listen().await;
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
        grant_a_local_pairing(&mut peer, &mut op).await;
        peer.next("verifyCommit").await;
        // An encryption message during the ceremony is applied after it.
        peer.send(&AstationMessage::EncryptionMode {
            account_state: None,
        });
        peer.send(&AstationMessage::VerifyAbort {
            reason: SIGN_IN_FIRST.into(),
        });
        let error = op.done().await.unwrap_err();
        assert_stopped_verification_output(&op.printed, &error, "Paired with Astation.");
        // The pairing stays saved; the device isn't verified.
        let src = crate::profile::Sources::in_dir(&rt.profile);
        assert_eq!(
            crate::pairing::load(&src)
                .unwrap()
                .binding
                .unwrap()
                .astation_id,
            ASTATION
        );
        assert!(!verified_as(&rt.keys(), "acct-new"));
        rt.shutdown().await;
    });
}

/// `atem pair verify` on an existing pairing ends with the same message.
#[test]
fn a_stopped_verification_ends_atem_pair_verify_with_the_same_message() {
    local(async {
        let dir = Rc::new(short_dir());
        paired(&dir.path().join("profile"));
        let (url, mut peer) = Peer::listen().await;
        let keys = CredPaths::in_dir(&dir.path().join("profile"));
        let rt = Runtime::start(dir, Some(&url), Arc::new(test_agent(&keys))).await;
        let mut op = Op::start(rt.client().await, OpKind::PairVerify, OpOptions::default()).await;
        peer.next("verifyCommit").await;
        peer.send(&AstationMessage::EncryptionMode {
            account_state: None,
        });
        peer.send(&AstationMessage::VerifyAbort {
            reason: SIGN_IN_FIRST.into(),
        });
        let error = op.done().await.unwrap_err();
        assert_stopped_verification_output(&op.printed, &error, "Verifying this device");
        assert!(!verified_as(&rt.keys(), "acct-op"));
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
            crate::pair_verify::PAIRED_NOT_VERIFIED
        );
        assert_eq!(abort["data"]["reason"], "no terminal to compare the code");
        assert_eq!(script.asked, [crate::pair_verify::CODES_QUESTION]);
        // The reason is one warning line; the next step is in the error that
        // ends the command, not repeated beside it.
        let warnings: Vec<_> = script
            .printed
            .iter()
            .filter(|(level, _)| *level == PrintLevel::Warn)
            .map(|(_, text)| text.as_str())
            .collect();
        assert_eq!(warnings.len(), 1, "{:?}", script.printed);
        assert!(
            warnings[0].contains("needs a terminal to compare the safety code"),
            "{warnings:?}"
        );
        assert!(
            !script
                .printed
                .iter()
                .any(|(_, text)| text.contains("Pairing is saved")),
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
        let running = crate::websocket_client::migration_lock(&crate::paths::ProfilePaths::in_dir(&profile).cred)
            .lock_owned()
            .await;
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

/// The profile's host policy, as a commit leaves it (§R9.8a).
fn set_policy(profile: &Path, relay_only: bool) {
    crate::session_protocol::r9::host_policy::write_for_test(
        &crate::paths::ProfilePaths::in_dir(profile).pairing,
        relay_only,
    );
}

/// A commit of `relay_only` as the host bridge reports it: the policy is
/// stored, the App told, and (`Some`) the channel's result frame handed to
/// the writer with its receipt. Returns the frame's text.
fn commit(app: &mut App, profile: &Path, relay_only: bool, written: bool) {
    set_policy(profile, relay_only);
    app.host_policy_changed(relay_only);
    if written {
        let text = format!(
            r#"{{"type":"channel","data":{{"op":"frame","channel":"c","frame":"{relay_only}"}}}}"#
        );
        let (sent, receipt) = app.astation_client.try_send_channel_with(text, true);
        assert!(sent);
        app.relay_only_receipt(receipt.expect("asked for"));
    }
}

/// The channel frames the peer got (the policy results in these tests).
fn results(peer: &Peer) -> usize {
    peer.seen.iter().filter(|m| m["type"] == "channel").count()
}

/// A relay link stays on any commit; `false` on a local link keeps it.
#[test]
fn a_relay_link_and_a_false_commit_never_drop() {
    local(async {
        // The runtime's own profile: relay-only decisions read it.
        let profile = crate::config::AtemConfig::config_dir();
        paired(&profile);
        let (mut app, mut peer) = linked_app(&profile, relay()).await;
        commit(&mut app, &profile, true, true);
        assert!(app.relay_only_drop.is_none(), "a relay link stays");
        let (mut local_app, mut local_peer) = linked_app(&profile, local_via()).await;
        commit(&mut local_app, &profile, false, true);
        assert!(local_app.relay_only_drop.is_none());
        for _ in 0..5 {
            app.process_astation_messages().await;
            local_app.process_astation_messages().await;
        }
        assert!(app.astation_connected && local_app.astation_connected);
        assert!(!peer.drain(Duration::from_millis(100)).await);
        assert!(!local_peer.drain(Duration::from_millis(100)).await);
    });
}

/// Relay only committed on a local link: the result is written, then the
/// local link is dropped so the reconnect goes through the relay.
#[test]
fn relay_only_drops_a_local_link_after_the_result() {
    local(async {
        // The runtime's own profile: relay-only decisions read it.
        let profile = crate::config::AtemConfig::config_dir();
        paired(&profile);
        let (mut app, mut peer) = linked_app(&profile, local_via()).await;
        commit(&mut app, &profile, true, true);
        assert!(app.relay_only_drop_pending());
        pass_until_dropped(&mut app, WAIT).await;
        assert_eq!(app.status_message.as_deref(), Some(RELAY_ONLY_RECONNECT));
        assert!(app.astation_reconnect_at.is_some(), "the normal reconnect");
        assert!(peer.drain(WAIT).await, "the local socket closed");
        assert_eq!(results(&peer), 1, "the result arrived before the close");
    });
}

/// While an Astation operation runs on the local link, the drop waits until
/// it ends; then the link is dropped, once.
#[test]
fn relay_only_waits_for_the_operation_on_the_local_link() {
    local(async {
        // The runtime's own profile: relay-only decisions read it.
        let profile = crate::config::AtemConfig::config_dir();
        paired(&profile);
        let (mut app, mut peer) = linked_app(&profile, local_via()).await;
        let _op = op_on_link(&mut app);
        commit(&mut app, &profile, true, true);
        commit(&mut app, &profile, true, true);
        app.process_astation_messages().await;
        assert!(app.astation_connected, "the operation keeps its link");
        assert!(!peer.drain(Duration::from_millis(200)).await);
        app.close_op_route();
        pass_until_dropped(&mut app, WAIT).await;
        assert!(app.astation_reconnect_at.is_some());
        assert!(peer.drain(WAIT).await, "the local socket closed");
        assert_eq!(results(&peer), 2);
    });
}

/// The status after relay only dropped a local link.
const RELAY_ONLY_RECONNECT: &str = "Astation allows only the relay; reconnecting through it";

/// Runs passes until the Astation link is dropped, within `limit`.
async fn pass_until_dropped(app: &mut App, limit: Duration) {
    let started = Instant::now();
    while app.astation_connected {
        assert!(started.elapsed() < limit, "the link was not dropped");
        pass(app).await;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(app.relay_only_drop.is_none());
}

/// One pass. It never waits for the result: the tests whose writer holds
/// it check that passes return with the link kept, which a pass waiting for
/// the write (or for the 5 s) couldn't. No time bound on the pass itself: it
/// reads the profile's files (the first pass derives the machine key five
/// times for the pairing record, each an `ioreg` run on macOS), which took
/// over 1 s on a loaded runner. `WAIT` only turns a pass that awaits
/// something into a failure instead of a hang.
async fn pass(app: &mut App) {
    tokio::time::timeout(WAIT, app.process_astation_messages())
        .await
        .expect("the pass never waits");
}

/// The pass returns at once while the writer holds the result and keeps the
/// link; once the result is written the link is dropped; the peer gets the
/// result, then the close.
#[test]
fn relay_only_drop_waits_for_the_result_without_holding_the_pass() {
    local(async {
        // The runtime's own profile: relay-only decisions read it.
        let profile = crate::config::AtemConfig::config_dir();
        paired(&profile);
        let (mut app, mut peer) = linked_app(&profile, local_via()).await;
        let paused = app.astation_client.pause_writer_for_test();
        commit(&mut app, &profile, true, true);
        for _ in 0..10 {
            pass(&mut app).await;
            assert!(app.astation_connected, "the result isn't written yet");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(!peer.drain(Duration::from_millis(100)).await);
        assert_eq!(results(&peer), 0, "held by the writer");
        paused.resume();
        pass_until_dropped(&mut app, WAIT).await;
        assert_eq!(app.status_message.as_deref(), Some(RELAY_ONLY_RECONNECT));
        assert!(peer.drain(WAIT).await, "the local socket closed");
        assert_eq!(results(&peer), 1, "the result arrived before the close");
    });
}

/// An operation running on `app`'s current link.
fn op_on_link(app: &mut App) -> mpsc::Receiver<AstationMessage> {
    let (tx, rx) = mpsc::channel(4);
    app.op_route = Some(crate::app::op_route::OpRoute {
        link_gen: app.astation_link_gen,
        tx,
        encryption: false,
        credentials: false,
    });
    rx
}

/// A `deviceVerified` as the App's pump sees it (its signatures are the
/// operation's to check).
fn any_certificate() -> AstationMessage {
    let signer = FakeAstation::new();
    AstationMessage::DeviceVerified {
        device_verified: signer.sign(b"x"),
        account_state: signer.sign(b"y"),
        grants: Vec::new(),
        membership: None,
    }
}

/// The profile's config.toml names no reachable Astation (local or relay),
/// so a reconnect the App starts goes nowhere.
fn nothing_reachable(profile: &Path) {
    std::fs::write(
        profile.join("config.toml"),
        format!(
            "astation_ws = \"ws://127.0.0.1:1/ws\"\nastation_relay_url = \"http://127.0.0.1:1\"\natem_id = \"{ATEM_ID}\"\n"
        ),
    )
    .unwrap();
}

/// A verification's certificate went to its operation over a relay link:
/// when that link drops (the Station's 1013 close), its reconnect waits
/// until the operation ended and, when it ended ok, until the host's next
/// pass (which reads the list it pinned); a failed operation releases it
/// at once, and so does the hold's bound when the operation doesn't end. A
/// local link, or a drop with no certificate routed (nothing finishing, or
/// an operation that waits for a link), reconnects at once as before.
#[test]
fn a_verifications_relay_reconnect_waits_for_the_operation() {
    for case in ["ok", "failed", "never ends", "local", "no certificate"] {
        local(async {
            let profile = crate::config::AtemConfig::config_dir();
            paired(&profile);
            nothing_reachable(&profile);
            let via = if case == "local" {
                local_via()
            } else {
                relay()
            };
            let (mut app, peer) = linked_app(&profile, via).await;
            app.astation_reconnect = true;
            let mut op = op_on_link(&mut app);
            if case != "no certificate" {
                peer.send(&any_certificate());
            }
            peer.close_again();
            pass_until_dropped(&mut app, WAIT).await;
            if case != "no certificate" {
                assert!(
                    matches!(op.try_recv(), Ok(AstationMessage::DeviceVerified { .. })),
                    "{case}"
                );
            }
            app.close_op_route();
            app.check_astation_reconnect();
            let held = matches!(case, "ok" | "failed" | "never ends");
            assert_eq!(app.astation_connect_rx.is_none(), held, "{case}");
            if !held {
                return;
            }
            match case {
                "ok" => {
                    assert!(app.verification_ended(true), "the list is checked");
                    app.check_astation_reconnect();
                    assert!(app.astation_connect_rx.is_none(), "until the pass");
                    app.verify_hold_pass();
                }
                "failed" => assert!(!app.verification_ended(false), "nothing to check"),
                _ => {
                    let hold = app.verify_hold.as_mut().expect("held");
                    hold.since -= crate::app::op_route::VERIFY_HOLD;
                }
            }
            app.check_astation_reconnect();
            assert!(app.astation_connect_rx.is_some(), "{case}: reconnecting");
            assert!(app.verify_hold.is_none(), "{case}");
        });
    }
}

/// The Station's 1013 close right after a verification's certificate on a
/// relay link (it asks the host to prove its route under the new device
/// list) reconnects at once, even when the link was up less than 10 s; any
/// other short-lived link still backs off 30 s: a 1013 with no certificate,
/// a plain close after one.
#[test]
fn a_reproof_close_skips_the_short_link_backoff() {
    for case in ["1013 after a certificate", "1013 alone", "plain close"] {
        local(async {
            let profile = crate::config::AtemConfig::config_dir();
            paired(&profile);
            let (mut app, peer) = linked_app(&profile, relay()).await;
            app.astation_connected_at = Some(Instant::now());
            let _op = op_on_link(&mut app);
            if case != "1013 alone" {
                peer.send(&any_certificate());
            }
            if case == "plain close" {
                peer.close();
            } else {
                peer.close_again();
            }
            pass_until_dropped(&mut app, WAIT).await;
            let retry = app.astation_reconnect_at.expect("a reconnect");
            let at_once = retry <= Instant::now();
            assert_eq!(at_once, case == "1013 after a certificate", "{case}");
            if !at_once {
                assert!(retry >= Instant::now() + Duration::from_secs(25), "{case}");
            }
        });
    }
}

/// A result never written (the writer holds it), or never even handed to
/// the writer (its channel's queue is behind): the drop still happens, 5 s
/// after no operation runs on the link.
#[test]
fn relay_only_gives_up_on_the_result_after_5_s() {
    for written in [true, false] {
        local(async {
            let profile = crate::config::AtemConfig::config_dir();
            paired(&profile);
            let (mut app, _peer) = linked_app(&profile, local_via()).await;
            let _op = op_on_link(&mut app);
            // Held, never resumed (the real writer stays alive).
            let _paused = app.astation_client.pause_writer_for_test();
            commit(&mut app, &profile, true, written);
            app.close_op_route();
            let ended = Instant::now();
            // The first pass sets the drop due 5 s on and returns at once
            // (it never waits for the result) with the link kept...
            pass(&mut app).await;
            let due_by = Instant::now() + Duration::from_secs(5);
            assert!(app.astation_connected, "written {written}");
            assert!(app.relay_only_drop.is_some(), "written {written}");
            // ...and the first pass to begin after that drops it, however
            // long the passes take.
            loop {
                tokio::time::sleep(Duration::from_millis(10)).await;
                let began = Instant::now();
                pass(&mut app).await;
                if !app.astation_connected {
                    break;
                }
                assert!(began < due_by, "kept past the 5 s: written {written}");
            }
            assert!(app.relay_only_drop.is_none());
            assert!(
                ended.elapsed() >= Duration::from_secs(5),
                "written {written}"
            );
            assert!(app.astation_reconnect_at.is_some());
            assert_eq!(
                app.status_message.as_deref(),
                Some(RELAY_ONLY_RECONNECT),
                "dropped for relay only, not a closed socket"
            );
        });
    }
}

/// A drop is cancelled by a later committed `false` (also while the `true`
/// result is held), checked again at the close (a policy that allows local
/// by then), and forgotten when its link is replaced.
#[test]
fn relay_only_drop_is_cancelled_by_false_and_fenced_by_a_new_link() {
    local(async {
        // The runtime's own profile: relay-only decisions read it.
        let profile = crate::config::AtemConfig::config_dir();
        paired(&profile);
        // Cancelled by false.
        let (mut app, mut peer) = linked_app(&profile, local_via()).await;
        let paused = app.astation_client.pause_writer_for_test();
        commit(&mut app, &profile, true, true);
        app.process_astation_messages().await;
        assert!(app.relay_only_drop.is_some(), "waiting for the result");
        commit(&mut app, &profile, false, true);
        assert!(app.relay_only_drop.is_none(), "cancelled");
        paused.resume();
        for _ in 0..20 {
            app.process_astation_messages().await;
            peer.drain(Duration::from_millis(20)).await;
        }
        assert!(app.astation_connected, "kept");
        assert!(!peer.closed);
        assert_eq!(results(&peer), 2);
        // The policy allows local by the close (changed without a commit
        // reaching the App): the close is skipped.
        let (mut app, _peer) = linked_app(&profile, local_via()).await;
        commit(&mut app, &profile, true, true);
        set_policy(&profile, false);
        for _ in 0..20 {
            app.process_astation_messages().await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(app.astation_connected, "checked again at the close");
        assert!(app.relay_only_drop.is_none());
        // Fenced: the link is replaced before the operation ends.
        let (mut app, _old) = linked_app(&profile, local_via()).await;
        let _op = op_on_link(&mut app);
        commit(&mut app, &profile, true, false);
        assert!(app.relay_only_drop.is_some());
        set_policy(&profile, false);
        let (url, mut new) = Peer::listen().await;
        app.astation_client = link_to(&profile, &url, local_via()).await;
        app.astation_link_gen += 1;
        app.close_op_route();
        app.process_astation_messages().await;
        assert!(app.relay_only_drop.is_none(), "forgotten with its link");
        assert!(app.astation_connected, "the new link is not dropped");
        assert!(!new.drain(Duration::from_millis(200)).await);
    });
}

/// A link the connect loop hands over (`poll_astation_connect`) like a
/// runtime's, authenticated with `ASTATION` over `url`, reached locally.
/// Its profile is then forgotten: `profile()` fails, as a runtime client's
/// does when config.toml doesn't load; relay-only decisions never need it.
async fn land_local_link(app: &mut App, url: &str) {
    let config = crate::config::AtemConfig::config_dir();
    let mut client = link_to(&config, url, local_via()).await;
    client.forget_profile_for_test();
    let (tx, rx) = tokio::sync::oneshot::channel();
    tx.send(Ok((client, Some("local".to_string()))))
        .ok()
        .unwrap();
    app.astation_connect_rx = Some(rx);
}

/// A local link landing while the host policy says relay only (it changed
/// after the connect loop read it), or a write of it is uncertain, is
/// dropped by the next pass.
#[test]
fn a_local_link_landing_under_relay_only_is_dropped() {
    for pending in [false, true] {
        local(async {
            let config = crate::config::AtemConfig::config_dir();
            paired(&config);
            let (url, mut peer) = Peer::listen().await;
            let mut app = App::new();
            app.last_session_refresh = Some(Instant::now());
            app.astation_reconnect = false;
            land_local_link(&mut app, &url).await;
            if pending {
                let paths = crate::paths::ProfilePaths::in_dir(&config).pairing;
                std::fs::write(&paths.host_policy_pending, b"{}").unwrap();
            } else {
                set_policy(&config, true);
            }
            app.poll_astation_connect();
            assert!(app.astation_connected);
            assert!(app.relay_only_drop_pending());
            pass_until_dropped(&mut app, WAIT).await;
            assert_eq!(app.status_message.as_deref(), Some(RELAY_ONLY_RECONNECT));
            assert!(peer.drain(WAIT).await, "the local socket closed");
        });
    }
}

/// A config.toml that doesn't parse is not a damaged pairing record: a
/// local link landing under a readable record and no policy stays (no
/// drop, so no reconnect loop).
#[test]
fn a_broken_config_toml_never_drops_a_local_link() {
    local(async {
        let config = crate::config::AtemConfig::config_dir();
        paired(&config);
        let (url, mut peer) = Peer::listen().await;
        let mut app = App::new();
        app.last_session_refresh = Some(Instant::now());
        app.astation_reconnect = false;
        land_local_link(&mut app, &url).await;
        std::fs::write(config.join("config.toml"), "astation_ws = [not toml").unwrap();
        assert!(
            crate::profile::Sources::current().is_err(),
            "the profile can't load"
        );
        app.poll_astation_connect();
        assert!(app.astation_connected);
        assert!(!app.relay_only_drop_pending());
        for _ in 0..10 {
            app.process_astation_messages().await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(app.astation_connected, "kept");
        assert!(app.astation_reconnect_at.is_none(), "no reconnect");
        assert!(!peer.drain(Duration::from_millis(200)).await);
    });
}

/// No Astation operation is handed a local link relay only is about to
/// drop: it waits for the next link.
#[test]
fn no_operation_gets_a_link_relay_only_is_dropping() {
    local(async {
        // The runtime's own profile: relay-only decisions read it.
        let profile = crate::config::AtemConfig::config_dir();
        paired(&profile);
        let (mut app, _peer) = linked_app(&profile, local_via()).await;
        let _paused = app.astation_client.pause_writer_for_test();
        commit(&mut app, &profile, true, true);
        assert!(app.relay_only_drop_pending());
        assert!(app.open_op_route(false, false).is_none());
        assert!(app.op_route.is_none());
        // A relay link (the next one) is handed out.
        let (mut app, _peer) = linked_app(&profile, relay()).await;
        commit(&mut app, &profile, true, true);
        assert!(!app.relay_only_drop_pending());
        assert!(app.open_op_route(false, false).is_some());
    });
}

/// The plaintext policy of earlier builds is refused as a removed op: no
/// effect, nothing stored, the local link stays (§R9.8a).
#[test]
fn the_plaintext_transport_policy_is_refused_with_no_effect() {
    local(async {
        // The runtime's own profile: relay-only decisions read it.
        let profile = crate::config::AtemConfig::config_dir();
        paired(&profile);
        let (mut app, mut peer) = linked_app(&profile, local_via()).await;
        peer.to_atem
            .send(r#"{"type":"transportPolicy","data":{"relay_only":true}}"#.into())
            .unwrap();
        for _ in 0..10 {
            app.process_astation_messages().await;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        peer.drain(Duration::from_millis(200)).await;
        let refusal = peer
            .seen
            .iter()
            .find(|m| m["type"] == "session")
            .expect("answered");
        assert_eq!(refusal["data"]["code"], "unsupported_version", "{refusal}");
        assert_eq!(
            refusal["data"]["detail"],
            crate::app::hosted::REMOVED_POLICY_OP
        );
        let paths = crate::paths::ProfilePaths::in_dir(&profile).pairing;
        assert!(!paths.host_policy.exists(), "nothing stored");
        assert!(app.astation_connected && app.relay_only_drop.is_none());
    });
}

/// The connect loop skips the local `astation_ws` while the host policy
/// says relay only, also in a new App (a restarted runtime); with the relay
/// unreachable it fails without trying local and retries in 30 s (no spin).
/// Without relay only it tries local.
#[test]
fn the_connect_loop_skips_local_while_relay_only() {
    for relay_only in [true, false] {
        local(async {
            let config = crate::config::AtemConfig::config_dir();
            paired(&config);
            set_policy(&config, relay_only);
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

/// An unreadable pairing record is not "no pairing": the connect loop
/// tries neither the local `astation_ws` nor the relay (no Astation id),
/// says why (to a waiting operation and in the status) and retries in 30 s;
/// a new App (a restarted runtime) does the same. A missing record tries
/// local (first pairing); a readable record under relay only tries only the
/// relay (the listeners do see attempts).
#[test]
fn the_connect_loop_never_tries_local_with_an_unreadable_record() {
    for case in ["damaged", "missing", "relay_only"] {
        local(async {
            let config = crate::config::AtemConfig::config_dir();
            std::fs::create_dir_all(&config).unwrap();
            let paths = crate::paths::ProfilePaths::in_dir(&config).pairing;
            match case {
                "damaged" => {
                    paired(&config);
                    std::fs::write(&paths.record, b"not a sealed record").unwrap();
                }
                "relay_only" => {
                    paired(&config);
                    set_policy(&config, true);
                }
                _ => {}
            }
            let local = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let relay = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            std::fs::write(
                config.join("config.toml"),
                format!(
                    "astation_ws = \"ws://{}/ws\"\nastation_relay_url = \"http://{}\"\natem_id = \"{ATEM_ID}\"\n",
                    local.local_addr().unwrap(),
                    relay.local_addr().unwrap()
                ),
            )
            .unwrap();
            for _restart in 0..2 {
                let mut app = App::new();
                app.spawn_astation_connect();
                let tried_local = accepted(&local).await;
                assert_eq!(tried_local, case == "missing", "{case}: local");
                if case != "damaged" {
                    if case == "relay_only" {
                        assert!(accepted(&relay).await, "{case}: the relay is tried");
                    }
                    break;
                }
                let started = Instant::now();
                while app.astation_connect_rx.is_some() {
                    assert!(started.elapsed() < WAIT);
                    app.poll_astation_connect();
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                assert!(!accepted(&relay).await, "no relay attempt either");
                assert!(!app.astation_connected);
                let retry = app.astation_reconnect_at.expect("a retry");
                assert!(retry >= Instant::now() + Duration::from_secs(25), "no spin");
                let error = app
                    .astation_connect_error
                    .clone()
                    .expect("the reason, for an operation");
                assert!(error.starts_with(crate::app::PAIRING_UNREADABLE), "{error}");
                let status = app.status_message.clone().unwrap();
                assert!(status.contains(crate::app::PAIRING_UNREADABLE), "{status}");
                assert_eq!(app.pairing_unreadable.as_deref(), Some(error.as_str()));
                // More retries on the same App: the same error is not new,
                // so it is not logged again.
                for _retry in 0..2 {
                    app.spawn_astation_connect();
                    while app.astation_connect_rx.is_some() {
                        assert!(started.elapsed() < WAIT);
                        app.poll_astation_connect();
                        tokio::time::sleep(Duration::from_millis(10)).await;
                    }
                    assert_eq!(app.pairing_unreadable.as_deref(), Some(error.as_str()));
                }
                assert_eq!(
                    app.pairing_unreadable_logged, 1,
                    "logged once in 3 failures"
                );
                assert_eq!(
                    std::fs::read(&paths.record).unwrap(),
                    b"not a sealed record",
                    "left as it was"
                );
            }
        });
    }
}

/// Whether `listener` gets a connection within 500 ms.
async fn accepted(listener: &tokio::net::TcpListener) -> bool {
    tokio::time::timeout(Duration::from_millis(500), listener.accept())
        .await
        .is_ok()
}

/// The unreadable record is logged on the first failure and when the error
/// changes, not at every retry.
#[test]
fn an_unreadable_record_is_logged_once_per_error() {
    local(async {
        let mut app = App::new();
        let first = format!("{} (one)", crate::app::PAIRING_UNREADABLE);
        let second = format!("{} (two)", crate::app::PAIRING_UNREADABLE);
        assert!(app.note_pairing_unreadable(&first));
        assert!(!app.note_pairing_unreadable(&first), "the same error again");
        assert!(app.note_pairing_unreadable(&second), "a new error");
        assert!(!app.note_pairing_unreadable(&second));
    });
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
        let (mut op, question, _, _) = verify_until_the_question(&rt, &mut peer, "acct-op").await;
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
        assert_eq!(
            op.done().await.unwrap_err(),
            crate::pair_verify::PAIRED_NOT_VERIFIED
        );
        rt.shutdown().await;
    });
}

/// r9 (no compatibility): an Astation whose `verifyKeys` names no device
/// list can't pair; Atem aborts the verification and pins nothing.
#[test]
fn a_verify_keys_without_a_genesis_is_refused() {
    local(async {
        let dir = Rc::new(short_dir());
        paired(&dir.path().join("profile"));
        let (url, mut peer) = Peer::listen().await;
        let keys = CredPaths::in_dir(&dir.path().join("profile"));
        let rt = Runtime::start(dir, Some(&url), Arc::new(test_agent(&keys))).await;
        let mut op = Op::start(rt.client().await, OpKind::PairVerify, OpOptions::default()).await;
        peer.next("verifyCommit").await;
        let fake = FakeAstation::new();
        peer.send(&AstationMessage::VerifyKeys {
            sign_pub: STANDARD.encode(fake.sign_pub()),
            enc_pub: STANDARD.encode(fake.enc_pub()),
            recovery_sign_pub: STANDARD.encode([6u8; 32]),
            nonce: STANDARD.encode([7u8; 32]),
            genesis_hash: None,
            account_id: Some(json!("acct-op")),
        });
        let abort = peer.next("verifyAbort").await;
        assert_eq!(
            abort["data"]["reason"],
            "Atem needs a device list (atem-session r9)"
        );
        assert_eq!(
            op.done().await.unwrap_err(),
            crate::pair_verify::PAIRED_NOT_VERIFIED
        );
        let pairing = crate::paths::ProfilePaths::in_dir(&rt.profile).pairing;
        assert!(!pairing.membership.exists() && !pairing.host_channel_key.exists());
        assert!(!pending(&rt.keys()), "no pending pin");
        rt.shutdown().await;
    });
}

/// host-work-v1 §11.5 (no compatibility): `verifyKeys` names the account
/// (`account_id`), whose device list the host's `enc_sig` binds before the
/// reveal. A `verifyKeys` without one, or with one that isn't an opaque id
/// (R9.1), fails the ceremony: Atem aborts with a short reason before the
/// reveal, records no key and pins nothing.
#[test]
fn a_verify_keys_without_a_valid_account_is_refused() {
    const NEEDED: &str = "Atem needs the account in verifyKeys (account_id)";
    const MALFORMED: &str = "atem refused verifyKeys: account_id isn't an account id";
    for (account, reason) in [
        (None, NEEDED),
        (Some(json!(null)), NEEDED),
        (Some(json!(7)), MALFORMED),
        (Some(json!("")), MALFORMED),
        (Some(json!("acct op")), MALFORMED),
        (Some(json!("a".repeat(129))), MALFORMED),
    ] {
        local(async {
            let dir = Rc::new(short_dir());
            paired(&dir.path().join("profile"));
            let (url, mut peer) = Peer::listen().await;
            let keys = CredPaths::in_dir(&dir.path().join("profile"));
            let rt = Runtime::start(dir, Some(&url), Arc::new(test_agent(&keys))).await;
            let mut op =
                Op::start(rt.client().await, OpKind::PairVerify, OpOptions::default()).await;
            peer.next("verifyCommit").await;
            let fake = FakeAstation::new();
            peer.send(&AstationMessage::VerifyKeys {
                sign_pub: STANDARD.encode(fake.sign_pub()),
                enc_pub: STANDARD.encode(fake.enc_pub()),
                recovery_sign_pub: STANDARD.encode([6u8; 32]),
                nonce: STANDARD.encode([7u8; 32]),
                genesis_hash: Some("ab".repeat(32)),
                account_id: account.clone(),
            });
            let abort = peer.next("verifyAbort").await;
            assert_eq!(abort["data"]["reason"], reason, "{account:?}");
            assert!(
                !peer.seen.iter().any(|m| m["type"] == "verifyReveal"),
                "{account:?}: aborted before the reveal"
            );
            assert_eq!(
                op.done().await.unwrap_err(),
                crate::pair_verify::PAIRED_NOT_VERIFIED
            );
            let pairing = crate::paths::ProfilePaths::in_dir(&rt.profile).pairing;
            assert!(!pairing.membership.exists() && !pairing.host_channel_key.exists());
            assert!(
                !pairing.host_enc_key.exists() && !pairing.host_enc_generated.exists(),
                "{account:?}: no key made or recorded"
            );
            assert!(!pending(&rt.keys()), "no pending pin");
            rt.shutdown().await;
        });
    }
}

/// `pairing/host_enc_generated` (the record of the host encryption keys
/// made), as JSON.
fn enc_record(profile: &Path) -> Option<Value> {
    let path = crate::paths::ProfilePaths::in_dir(profile)
        .pairing
        .host_enc_generated;
    std::fs::read(path)
        .ok()
        .map(|bytes| serde_json::from_slice(&bytes).unwrap())
}

/// R9.9's `enc_kid` of an X25519 public half.
fn kid_of(enc_pub: &[u8; 32]) -> String {
    let key = atem_client::PublicKey::new(atem_client::Alg::X25519, enc_pub).unwrap();
    atem_client::keys::enc_kid(&key).unwrap()
}

/// host-work-v1 §11.5: after `verifyKeys` the host makes a new encryption
/// key for the ceremony's trust generation and records its `enc_kid`
/// durably before it sends the reveal, which carries it as
/// `host_enc_key{host_id, host_trust_gen, enc_key, enc_sig}`: the commit's
/// host and generation, `enc_sig` by the revealed `host_channel_key` for
/// the account and genesis `verifyKeys` named (Astation's checks, as it
/// makes them). No key file before the pin. An aborted ceremony keeps the
/// record (the key's id was handed out) and pins nothing; the next ceremony
/// makes a new key for its own generation.
#[test]
fn the_reveal_carries_a_new_encryption_key_recorded_before_it() {
    local(async {
        let dir = Rc::new(short_dir());
        paired(&dir.path().join("profile"));
        let (url, mut peer) = Peer::listen().await;
        let keys = CredPaths::in_dir(&dir.path().join("profile"));
        let rt = Runtime::start(dir, Some(&url), Arc::new(test_agent(&keys))).await;
        let pairing = crate::paths::ProfilePaths::in_dir(&rt.profile).pairing;
        let mut revealed = Vec::new();
        for attempt in 1..=2 {
            let mut op =
                Op::start(rt.client().await, OpKind::PairVerify, OpOptions::default()).await;
            let verifier = Verifier::keys(&mut peer, "acct-op").await;
            let reveal = peer.next("verifyReveal").await;
            let (enc_pub, _) = verifier.revealed_key(&reveal);
            // Durable before the reveal went: on disk as it arrives.
            let recorded = json!({"v": 1, "host_trust_gen": verifier.advertised,
                "kids": [kid_of(&enc_pub)]});
            assert_eq!(enc_record(&rt.profile), Some(recorded.clone()), "{attempt}");
            assert!(
                !pairing.host_enc_key.exists(),
                "the key file only at the pin"
            );
            // The code refused: the ceremony aborts.
            let (question, _, _) = op.ask().await;
            op.answer(question, AnswerValue::No).await;
            let abort = peer.next("verifyAbort").await;
            assert_eq!(abort["data"]["reason"], "codes didn't match on atem");
            assert!(op.done().await.is_err());
            assert!(!pairing.membership.exists(), "nothing pinned");
            assert!(!pairing.host_enc_key.exists(), "no key kept");
            assert_eq!(
                enc_record(&rt.profile),
                Some(recorded),
                "{attempt}: the record stays (the id was handed out)"
            );
            revealed.push((verifier.advertised, enc_pub));
        }
        assert_eq!(revealed[1].0, revealed[0].0 + 1, "the next generation");
        assert_ne!(revealed[1].1, revealed[0].1, "with a new key");
        rt.shutdown().await;
    });
}

/// host-work-v1 §11.5: a key whose id can't be recorded is never handed
/// out: the ceremony aborts after `verifyKeys` with a short reason, sends
/// no reveal, and pins nothing.
#[test]
fn a_key_whose_id_cant_be_recorded_is_never_revealed() {
    local(async {
        let dir = Rc::new(short_dir());
        paired(&dir.path().join("profile"));
        let pairing = crate::paths::ProfilePaths::in_dir(&dir.path().join("profile")).pairing;
        // A directory where the record goes: its write fails.
        std::fs::create_dir_all(pairing.host_enc_generated.join("in-the-way")).unwrap();
        let (url, mut peer) = Peer::listen().await;
        let keys = CredPaths::in_dir(&dir.path().join("profile"));
        let rt = Runtime::start(dir, Some(&url), Arc::new(test_agent(&keys))).await;
        let mut op = Op::start(rt.client().await, OpKind::PairVerify, OpOptions::default()).await;
        let _verifier = Verifier::keys(&mut peer, "acct-op").await;
        let abort = peer.next("verifyAbort").await;
        assert_eq!(
            abort["data"]["reason"],
            crate::runtime::ops::ENC_KEY_NOT_RECORDED
        );
        assert!(
            !peer.seen.iter().any(|m| m["type"] == "verifyReveal"),
            "no reveal: the key was never handed out"
        );
        op.printed("Couldn't record this host's new encryption key")
            .await;
        assert_eq!(
            op.done().await.unwrap_err(),
            crate::pair_verify::PAIRED_NOT_VERIFIED
        );
        assert!(!pairing.membership.exists() && !pairing.host_enc_key.exists());
        assert!(!pending(&rt.keys()), "no pending pin");
        rt.shutdown().await;
    });
}

/// host-work-v1 §11.5: Atem refuses a `deviceVerified` whose signed
/// certificate names another account than `verifyKeys` did (the account
/// its `enc_sig` was made for): the verification fails and nothing is
/// pinned or trusted.
#[test]
fn a_certificate_for_another_account_than_verify_keys_named_is_refused() {
    local(async {
        let dir = Rc::new(short_dir());
        paired(&dir.path().join("profile"));
        let (url, mut peer) = Peer::listen().await;
        let keys = CredPaths::in_dir(&dir.path().join("profile"));
        let rt = Runtime::start(dir, Some(&url), Arc::new(test_agent(&keys))).await;
        let mut op = Op::start(rt.client().await, OpKind::PairVerify, OpOptions::default()).await;
        let mut verifier = Verifier::keys(&mut peer, "acct-op").await;
        let reveal = peer.next("verifyReveal").await;
        verifier.revealed_key(&reveal);
        // The certificate (and its list) name another account than the
        // keys did.
        verifier.account = "acct-other".into();
        let mut log = crate::session_protocol::membership::r9log::TestLog::genesis(
            "acct-other",
            &verifier.fake.sign_secret_bytes(),
        );
        let host_pub: [u8; 32] = atem_client::encoding::b64u_decode(
            reveal["data"]["host_channel_pub"].as_str().unwrap(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        log.add_host_pub(&verifier.device_id, verifier.advertised, &host_pub);
        verifier.log = std::cell::RefCell::new(log);
        let certificate = verifier.certificate_for(&reveal);
        let (question, _, _) = op.ask().await;
        op.answer(question, AnswerValue::Yes).await;
        op.printed("Waiting for your Mac").await;
        peer.send(&certificate);
        let abort = peer.next("verifyAbort").await;
        assert!(
            abort["data"]["reason"]
                .as_str()
                .unwrap()
                .contains("names another account (acct-other) than its keys did (acct-op)"),
            "{abort}"
        );
        assert_eq!(
            op.done().await.unwrap_err(),
            crate::pair_verify::PAIRED_NOT_VERIFIED
        );
        let pairing = crate::paths::ProfilePaths::in_dir(&rt.profile).pairing;
        assert!(!pairing.membership.exists() && !pairing.host_channel_key.exists());
        assert!(!pairing.host_enc_key.exists(), "no key kept");
        assert!(!verified_as(&rt.keys(), "acct-op"), "nothing trusted");
        assert!(!verified_as(&rt.keys(), "acct-other"), "nothing trusted");
        rt.shutdown().await;
    });
}

/// Every `atem pair verify` ceremony runs in the next host trust
/// generation (durable before `verifyCommit`): a retry after an aborted
/// ceremony reveals a fresh `host_channel_key`, which Astation can only add
/// at a higher generation than an `add_host` it may already have signed.
/// The pairing (Astation, session) is kept and the link stays current.
#[test]
fn each_verification_runs_in_the_next_trust_generation_and_keeps_the_pairing() {
    local(async {
        let dir = Rc::new(short_dir());
        paired(&dir.path().join("profile"));
        let (url, mut peer) = Peer::listen().await;
        let keys = CredPaths::in_dir(&dir.path().join("profile"));
        let rt = Runtime::start(dir, Some(&url), Arc::new(test_agent(&keys))).await;
        let start = trust_gen(&rt.profile);
        let session = record(&rt.profile).session.unwrap().session_id;
        for attempt in 1..=2u64 {
            let mut op =
                Op::start(rt.client().await, OpKind::PairVerify, OpOptions::default()).await;
            let commit = peer.next("verifyCommit").await;
            assert_eq!(
                commit["data"]["host_trust_gen"],
                start + attempt,
                "attempt {attempt}: {commit}"
            );
            assert_eq!(trust_gen(&rt.profile), start + attempt, "durable first");
            // Astation cancels this attempt (as an aborted ceremony).
            peer.send(&AstationMessage::VerifyAbort {
                reason: "cancelled".into(),
            });
            assert!(op.done().await.is_err());
            assert_eq!(record(&rt.profile).astation_id, ASTATION);
            assert_eq!(
                record(&rt.profile).session.unwrap().session_id,
                session,
                "the pairing and its session stay"
            );
        }
        rt.shutdown().await;
    });
}

/// The rebind persists across a runtime restart: after an aborted
/// ceremony the runtime stops; a new runtime's `pair verify` goes one
/// generation higher again.
#[test]
fn the_next_generation_survives_a_runtime_restart() {
    local(async {
        let dir = Rc::new(short_dir());
        paired(&dir.path().join("profile"));
        let (url, mut peer) = Peer::listen().await;
        let keys = CredPaths::in_dir(&dir.path().join("profile"));
        let rt = Runtime::start(dir.clone(), Some(&url), Arc::new(test_agent(&keys))).await;
        let start = trust_gen(&rt.profile);
        let mut op = Op::start(rt.client().await, OpKind::PairVerify, OpOptions::default()).await;
        assert_eq!(
            peer.next("verifyCommit").await["data"]["host_trust_gen"],
            start + 1
        );
        peer.send(&AstationMessage::VerifyAbort {
            reason: "cancelled".into(),
        });
        assert!(op.done().await.is_err());
        rt.shutdown().await;
        // The old runtime's socket file (a real restart replaces it too).
        let _ = std::fs::remove_file(dir.path().join("rt.sock"));
        let (url, mut peer) = Peer::listen().await;
        let rt = Runtime::start(dir, Some(&url), Arc::new(test_agent(&keys))).await;
        assert_eq!(
            trust_gen(&rt.profile),
            start + 1,
            "durable across the restart"
        );
        let mut op = Op::start(rt.client().await, OpKind::PairVerify, OpOptions::default()).await;
        assert_eq!(
            peer.next("verifyCommit").await["data"]["host_trust_gen"],
            start + 2
        );
        peer.send(&AstationMessage::VerifyAbort {
            reason: "cancelled".into(),
        });
        assert!(op.done().await.is_err());
        rt.shutdown().await;
    });
}

/// A save error during the rebind (before or after the rename) ends the
/// operation before `verifyCommit`: nothing is sent, nothing is lowered.
#[test]
fn a_failed_rebind_sends_no_verify_commit() {
    for after_rename in [false, true] {
        local(async {
            let dir = Rc::new(short_dir());
            paired(&dir.path().join("profile"));
            let (url, mut peer) = Peer::listen().await;
            let keys = CredPaths::in_dir(&dir.path().join("profile"));
            let rt = Runtime::start(dir, Some(&url), Arc::new(test_agent(&keys))).await;
            let start = trust_gen(&rt.profile);
            let record = crate::paths::ProfilePaths::in_dir(&rt.profile)
                .pairing
                .record;
            let (_before, _after);
            if after_rename {
                _after = Some(crate::memory::crypto::fail_after_rename(&record));
            } else {
                _before = Some(crate::memory::crypto::fail_writes_to(&record));
            }
            let mut op =
                Op::start(rt.client().await, OpKind::PairVerify, OpOptions::default()).await;
            assert!(op.done().await.is_err(), "after_rename {after_rename}");
            peer.drain(Duration::from_millis(300)).await;
            assert!(
                !peer.seen.iter().any(|m| m["type"] == "verifyCommit"),
                "after_rename {after_rename}: no verifyCommit"
            );
            assert!(trust_gen(&rt.profile) >= start, "never lower");
            rt.shutdown().await;
        });
    }
}

/// r9: a device list whose `add_host` names another key than the one this
/// ceremony revealed is refused; the verification fails and nothing is
/// pinned or trusted.
#[test]
fn a_device_list_for_another_host_key_fails_the_verification() {
    local(async {
        let dir = Rc::new(short_dir());
        paired(&dir.path().join("profile"));
        let (url, mut peer) = Peer::listen().await;
        let keys = CredPaths::in_dir(&dir.path().join("profile"));
        let rt = Runtime::start(dir, Some(&url), Arc::new(test_agent(&keys))).await;
        let mut op = Op::start(rt.client().await, OpKind::PairVerify, OpOptions::default()).await;
        let verifier = Verifier::keys(&mut peer, "acct-op").await;
        let reveal = peer.next("verifyReveal").await;
        assert!(reveal["data"]["host_channel_pub"].is_string());
        verifier.log.borrow_mut().add_host_pub(
            &verifier.device_id,
            trust_gen(&rt.profile),
            &[9; 32],
        );
        let (question, _, _) = op.ask().await;
        op.answer(question, AnswerValue::Yes).await;
        op.printed("Waiting for your Mac").await;
        let certificate = match verifier.certificate_for(&reveal) {
            AstationMessage::DeviceVerified {
                device_verified,
                account_state,
                grants,
                ..
            } => AstationMessage::DeviceVerified {
                device_verified,
                account_state,
                grants,
                membership: Some(json!({"entries": verifier.log.borrow().wire()})),
            },
            _ => unreachable!(),
        };
        peer.send(&certificate);
        let abort = peer.next("verifyAbort").await;
        assert!(
            abort["data"]["reason"]
                .as_str()
                .unwrap()
                .contains("host key or trust generation"),
            "{abort}"
        );
        assert_eq!(
            op.done().await.unwrap_err(),
            crate::pair_verify::PAIRED_NOT_VERIFIED
        );
        let pairing = crate::paths::ProfilePaths::in_dir(&rt.profile).pairing;
        assert!(!pairing.membership.exists() && !pairing.host_channel_key.exists());
        assert!(!verified_as(&rt.keys(), "acct-op"), "nothing trusted");
        rt.shutdown().await;
    });
}

/// r9 (§R9.2, `r9-vectors-pairing` "another generation"): an `add_host`
/// naming another generation than `verifyCommit` advertised (tampered or
/// mismatched) is refused; nothing is pinned or trusted.
#[test]
fn an_add_host_for_another_generation_fails_the_verification() {
    local(async {
        let dir = Rc::new(short_dir());
        paired(&dir.path().join("profile"));
        let (url, mut peer) = Peer::listen().await;
        let keys = CredPaths::in_dir(&dir.path().join("profile"));
        let rt = Runtime::start(dir, Some(&url), Arc::new(test_agent(&keys))).await;
        let mut op = Op::start(rt.client().await, OpKind::PairVerify, OpOptions::default()).await;
        let verifier = Verifier::keys(&mut peer, "acct-op").await;
        assert_eq!(verifier.advertised, trust_gen(&rt.profile));
        let reveal = peer.next("verifyReveal").await;
        let host_pub: [u8; 32] = atem_client::encoding::b64u_decode(
            reveal["data"]["host_channel_pub"].as_str().unwrap(),
        )
        .unwrap()
        .try_into()
        .unwrap();
        verifier.log.borrow_mut().add_host_pub(
            &verifier.device_id,
            verifier.advertised + 1,
            &host_pub,
        );
        let (question, _, _) = op.ask().await;
        op.answer(question, AnswerValue::Yes).await;
        op.printed("Waiting for your Mac").await;
        peer.send(&verifier.certificate_for(&reveal));
        let abort = peer.next("verifyAbort").await;
        assert!(
            abort["data"]["reason"]
                .as_str()
                .unwrap()
                .contains("host key or trust generation"),
            "{abort}"
        );
        assert_eq!(
            op.done().await.unwrap_err(),
            crate::pair_verify::PAIRED_NOT_VERIFIED
        );
        let pairing = crate::paths::ProfilePaths::in_dir(&rt.profile).pairing;
        assert!(!pairing.membership.exists());
        assert!(!verified_as(&rt.keys(), "acct-op"), "nothing trusted");
        rt.shutdown().await;
    });
}

/// Re-review F4: an unreadable `frozen_genesis` is found before the codes
/// are compared and Touch ID is asked: Atem aborts right after
/// `verifyKeys` with a short reason (no local path), shows the remedy
/// locally, and pins nothing.
#[test]
fn an_unreadable_frozen_genesis_aborts_before_touch_id() {
    local(async {
        let dir = Rc::new(short_dir());
        paired(&dir.path().join("profile"));
        let pairing = crate::paths::ProfilePaths::in_dir(&dir.path().join("profile")).pairing;
        crate::paths::write_test_file(&pairing.frozen_genesis, b"{not json");
        let (url, mut peer) = Peer::listen().await;
        let keys = CredPaths::in_dir(&dir.path().join("profile"));
        let rt = Runtime::start(dir, Some(&url), Arc::new(test_agent(&keys))).await;
        let mut op = Op::start(rt.client().await, OpKind::PairVerify, OpOptions::default()).await;
        let _verifier = Verifier::keys(&mut peer, "acct-op").await;
        // The next message is the abort: no reveal, no question.
        let abort = peer.next("verifyAbort").await;
        assert!(
            !peer.seen.iter().any(|m| m["type"] == "verifyReveal"),
            "aborted before the reveal (no codes, no Touch ID)"
        );
        let reason = abort["data"]["reason"].as_str().unwrap();
        assert_eq!(reason, crate::runtime::ops::FROZEN_GENESIS_UNREADABLE);
        assert!(
            reason.chars().count() <= 200 && !reason.contains('/'),
            "{reason}"
        );
        op.printed(
            "remove pairing/frozen_genesis and runtime/journal/frozen_genesis in Atem's config \
             directory (~/.config/atem by default)",
        )
        .await;
        assert_eq!(
            op.done().await.unwrap_err(),
            crate::pair_verify::PAIRED_NOT_VERIFIED
        );
        assert!(!pairing.membership.exists() && !pairing.host_channel_key.exists());
        assert!(!pending(&rt.keys()), "no pending pin");
        rt.shutdown().await;
    });
}

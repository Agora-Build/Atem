//! A fake Astation WebSocket peer that authenticates any runtime link, and
//! the profile files of a paired, verified device for it.
#![allow(dead_code)]

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;
use tokio_tungstenite::tungstenite::Message;

/// The Astation id the fake peer announces.
pub const ASTATION: &str = "astation-fixtures";

/// The pairing code the fake relay's `POST /api/pair` hands out.
pub const PAIR_CODE: &str = "PAIRCODE";

pub enum Event {
    /// Connection `n` authenticated.
    Authenticated(u64),
    Message(u64, Value),
}

enum Cmd {
    Send(String),
    Close,
}

/// How the fake answers Atem's `auth` (its proof).
#[derive(Clone, Debug, Default)]
pub enum AuthReply {
    /// `authenticated` (no session granted).
    #[default]
    Authenticated,
    /// `auth{status: granted}` with a new session to save.
    Grant { session_id: String, token: String },
    /// `auth{status: denied}` with this message.
    Deny(String),
}

pub struct FakeAstation {
    pub url: String,
    pub events: mpsc::Receiver<Event>,
    /// How every link answers an `auth` from now on.
    pub auth: Arc<Mutex<AuthReply>>,
    /// The command channel of each connection, by number.
    links: Arc<Mutex<HashMap<u64, tokio::sync::mpsc::UnboundedSender<Cmd>>>>,
}

impl FakeAstation {
    pub fn start() -> Self {
        let (url_tx, url_rx) = mpsc::channel();
        let (events_tx, events) = mpsc::channel();
        let links: Arc<Mutex<HashMap<u64, tokio::sync::mpsc::UnboundedSender<Cmd>>>> =
            Arc::default();
        let shared = links.clone();
        let auth: Arc<Mutex<AuthReply>> = Arc::default();
        let answers = auth.clone();
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
                    tokio::spawn(link(n, stream, events, cmd_rx, answers.clone()));
                }
            });
        });
        let url = url_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        Self {
            url,
            events,
            auth,
            links,
        }
    }

    pub fn send(&self, link: u64, text: String) {
        if let Some(tx) = self.links.lock().unwrap().get(&link) {
            let _ = tx.send(Cmd::Send(text));
        }
    }

    pub fn close(&self, link: u64) {
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
    commands: tokio::sync::mpsc::UnboundedReceiver<Cmd>,
    auth: Arc<Mutex<AuthReply>>,
) {
    let Ok(mut socket) = tokio_tungstenite::accept_async(stream).await else {
        return;
    };
    if socket
        .send(Message::Text(auth_required("lan").to_string()))
        .await
        .is_err()
    {
        return;
    }
    serve(n, socket, events, commands, auth).await;
}

/// Astation's `auth_required` for a link over `transport`.
pub fn auth_required(transport: &str) -> Value {
    json!({"type": "statusUpdate", "data": {"status": "auth_required",
        "data": {"astation_id": ASTATION, "challenge": "b".repeat(64),
                 "transport": transport, "protocol": "2"}}})
}

/// The rest of a link: Atem's messages as events (an `auth` answered
/// `authenticated`), the test's commands sent.
async fn serve(
    n: u64,
    mut socket: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    events: mpsc::Sender<Event>,
    mut commands: tokio::sync::mpsc::UnboundedReceiver<Cmd>,
    auth: Arc<Mutex<AuthReply>>,
) {
    loop {
        tokio::select! {
            frame = socket.next() => {
                let Some(Ok(frame)) = frame else { return };
                let Message::Text(text) = frame else { continue };
                let Ok(value) = serde_json::from_str::<Value>(&text) else { continue };
                if is_auth(&value) {
                    if !answer_auth(n, &mut socket, &events, &auth, value).await {
                        return;
                    }
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

fn is_auth(value: &Value) -> bool {
    value["type"] == "statusUpdate" && value["data"]["status"] == "auth"
}

/// Answers Atem's `auth` (`value`) as `auth` says: `Event::Authenticated`
/// when accepted, else the `auth` as a message. `false`: the socket failed.
async fn answer_auth(
    n: u64,
    socket: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    events: &mpsc::Sender<Event>,
    auth: &Arc<Mutex<AuthReply>>,
    value: Value,
) -> bool {
    let answer = auth.lock().unwrap().clone();
    let (reply, accepted) = match answer {
        AuthReply::Authenticated => (
            json!({"type": "statusUpdate", "data": {"status": "authenticated", "data": {}}}),
            true,
        ),
        AuthReply::Grant { session_id, token } => (
            json!({"type": "statusUpdate", "data": {"status": "auth", "data": {"status": "granted",
                "session_id": session_id, "token": token}}}),
            true,
        ),
        AuthReply::Deny(message) => (
            json!({"type": "statusUpdate", "data": {"status": "auth", "data": {"status": "denied",
                "message": message}}}),
            false,
        ),
    };
    if socket.send(Message::Text(reply.to_string())).await.is_err() {
        return false;
    }
    let _ = events.send(if accepted {
        Event::Authenticated(n)
    } else {
        Event::Message(n, value)
    });
    true
}

/// Writes `config` (an atem config dir) as paired with `ASTATION` in
/// `trust_gen` and verified as `account` / `device`, with a saved session.
pub fn write_verified_pairing(config: &Path, account: &str, device: &str, trust_gen: u64) {
    super::profile::write_pairing(config, ASTATION, trust_gen);
    let entry = json!({
        "device_id": device, "data_account": account, "sign_gen": 1,
        "astation_sign_pub": "", "astation_enc_pub": "", "recovery_sign_pub": "",
        "device_pub": "", "device_sign_pub": "", "unlock_auth_pub": "",
        "safety_code": "", "epoch_floor": 0, "account_state": null, "account_epoch": 0,
    });
    std::fs::create_dir_all(super::profile::CredPaths::in_dir(config).dir).unwrap();
    std::fs::write(
        super::profile::CredPaths::in_dir(config).trust,
        json!({"version": 1, "astations": {ASTATION: entry}}).to_string(),
    )
    .unwrap();
}

/// How the fake relay answers a host connection's route proof (§R9.7b).
#[derive(Clone, Debug)]
pub enum Reply {
    /// `host_route_ok` for this host and head after the proof.
    Ok { host_id: String, head: Value },
    /// `host_route_ok` before any challenge, then the challenge and no
    /// reply to the proof.
    Unsolicited { host_id: String, head: Value },
    /// `host_route_refused` with this code, then the relay closes.
    Refused(&'static str),
    /// `host_route_refused` before the challenge (not for any proof), then
    /// the challenge and `host_route_ok` for the proof.
    RefusedFirst { host_id: String, head: Value },
    /// No reply to the proof.
    Nothing,
    /// `host_route_ok`, then the relay closes the connection at once.
    OkThenClose { host_id: String, head: Value },
    /// No verdict and no proof expected: after the challenge the link
    /// carries what the test sends (a pairing-code room's link, which
    /// answers no challenge, gets `credentialSync` from the test).
    Serve,
    /// The room's owner is in the room (carrier A): `host_challenge`, then
    /// Astation's `auth_required` at once (before any verdict). Atem's
    /// `auth` is answered as `auth` says. `ok`: once both the proof and the
    /// `auth` arrived, `host_route_ok` is sent before Astation's reply, or
    /// after it with `reply_first`. `None`: no verdict (a proof is still
    /// reported); Astation's reply as soon as the `auth` arrives.
    AstationFirst {
        ok: Option<(String, Value)>,
        reply_first: bool,
    },
}

/// What the fake relay saw of one host connection.
#[derive(Debug)]
pub enum RelayEvent {
    /// The proof Atem sent for this connection's challenge.
    Proof {
        link: u64,
        query: Vec<(String, String)>,
        nonce: [u8; 32],
        room: String,
        message: String,
    },
    /// The connection ended (either side).
    Closed(u64),
}

impl FakeAstation {
    /// A relay with no Astation behind it: every host connection
    /// (`/ws?role=atem&code=…&atem_id=…`) gets `host_challenge` for its
    /// `code` first and `plan(n)`'s reply to the proof; the link then
    /// carries what the test sends (an `auth_required` from Astation
    /// included: an `auth` is answered `authenticated`).
    pub fn start_relay(
        plan: impl Fn(u64) -> Reply + Send + Sync + 'static,
    ) -> (Self, mpsc::Receiver<RelayEvent>) {
        let (url_tx, url_rx) = mpsc::channel();
        let (events_tx, events) = mpsc::channel();
        let (relay_tx, relay) = mpsc::channel();
        let links: Arc<Mutex<HashMap<u64, tokio::sync::mpsc::UnboundedSender<Cmd>>>> =
            Arc::default();
        let shared = links.clone();
        let auth: Arc<Mutex<AuthReply>> = Arc::default();
        let answers = auth.clone();
        let plan = Arc::new(plan);
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                url_tx
                    .send(format!("http://{}", listener.local_addr().unwrap()))
                    .unwrap();
                let mut next = 0u64;
                loop {
                    let Ok((stream, _)) = listener.accept().await else {
                        return;
                    };
                    // `atem pair`'s registration: no host connection.
                    let mut head = [0u8; 5];
                    if matches!(stream.peek(&mut head).await, Ok(5)) && &head == b"POST " {
                        tokio::spawn(pair_registration(stream));
                        continue;
                    }
                    next += 1;
                    let n = next;
                    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
                    shared.lock().unwrap().insert(n, cmd_tx);
                    let reply = plan(n);
                    tokio::spawn(relay_link(
                        n,
                        stream,
                        reply,
                        events_tx.clone(),
                        relay_tx.clone(),
                        cmd_rx,
                        answers.clone(),
                    ));
                }
            });
        });
        let url = url_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        (
            Self {
                url,
                events,
                auth,
                links,
            },
            relay,
        )
    }
}

/// `POST /api/pair`: `{"code": PAIR_CODE}` (the request is read to its
/// end, headers and `Content-Length` body).
async fn pair_registration(mut stream: tokio::net::TcpStream) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut request = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let Ok(n) = stream.read(&mut buf).await else {
            return;
        };
        if n == 0 {
            return;
        }
        request.extend_from_slice(&buf[..n]);
        let text = String::from_utf8_lossy(&request);
        if let Some(end) = text.find("\r\n\r\n") {
            let length = text[..end]
                .lines()
                .find_map(|l| {
                    let (k, v) = l.split_once(':')?;
                    k.eq_ignore_ascii_case("content-length")
                        .then(|| v.trim().parse::<usize>().ok())?
                })
                .unwrap_or(0);
            if request.len() >= end + 4 + length {
                break;
            }
        }
    }
    let body = json!({"code": PAIR_CODE}).to_string();
    let response = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes()).await;
    let _ = stream.shutdown().await;
}

fn ok_message(host_id: &str, head: &Value) -> String {
    json!({"type": "relay", "op": "host_route_ok", "v": 1, "host_id": host_id, "head": head})
        .to_string()
}

// The handshake callback's `Err` is tungstenite's own response type.
#[allow(clippy::result_large_err)]
async fn relay_link(
    n: u64,
    stream: tokio::net::TcpStream,
    reply: Reply,
    events: mpsc::Sender<Event>,
    relay: mpsc::Sender<RelayEvent>,
    commands: tokio::sync::mpsc::UnboundedReceiver<Cmd>,
    auth: Arc<Mutex<AuthReply>>,
) {
    let mut query = String::new();
    let callback = |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                    response| {
        query = request.uri().query().unwrap_or_default().to_owned();
        Ok(response)
    };
    let Ok(mut socket) = tokio_tungstenite::accept_hdr_async(stream, callback).await else {
        return;
    };
    let query: Vec<(String, String)> = query
        .split('&')
        .filter_map(|kv| kv.split_once('='))
        .map(|(k, v)| (k.to_owned(), urlencoding::decode(v).unwrap().into_owned()))
        .collect();
    let room = query
        .iter()
        .find(|(k, _)| k == "code")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    if let Reply::Unsolicited { host_id, head } = &reply {
        let _ = socket.send(Message::Text(ok_message(host_id, head))).await;
    }
    if let Reply::RefusedFirst { .. } = &reply {
        let refused =
            json!({"type": "relay", "op": "host_route_refused", "v": 1, "code": "unknown_host"});
        let _ = socket.send(Message::Text(refused.to_string())).await;
    }
    let challenge = atem_client::host_route::HostChallenge::new(&room);
    if socket
        .send(Message::Text(challenge.to_json().to_string()))
        .await
        .is_err()
    {
        let _ = relay.send(RelayEvent::Closed(n));
        return;
    }
    if let Reply::Serve = reply {
        serve(n, socket, events, commands, auth).await;
        let _ = relay.send(RelayEvent::Closed(n));
        return;
    }
    if let Reply::AstationFirst { ok, reply_first } = reply {
        astation_first(
            n,
            socket,
            query,
            room,
            challenge.nonce,
            (ok, reply_first),
            (events, relay, commands, auth),
        )
        .await;
        return;
    }
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let proof = loop {
        let frame = tokio::time::timeout_at(deadline, socket.next()).await;
        let Ok(Some(Ok(frame))) = frame else {
            break None;
        };
        let Message::Text(text) = frame else { continue };
        if text.contains("\"host_route\"") {
            break Some(text);
        }
        if let Ok(value) = serde_json::from_str::<Value>(&text) {
            let _ = events.send(Event::Message(n, value));
        }
    };
    let Some(message) = proof else {
        let _ = socket.close(None).await;
        let _ = relay.send(RelayEvent::Closed(n));
        return;
    };
    let _ = relay.send(RelayEvent::Proof {
        link: n,
        query,
        nonce: challenge.nonce,
        room,
        message,
    });
    match reply {
        Reply::Ok { host_id, head } | Reply::RefusedFirst { host_id, head } => {
            if socket
                .send(Message::Text(ok_message(&host_id, &head)))
                .await
                .is_err()
            {
                let _ = relay.send(RelayEvent::Closed(n));
                return;
            }
        }
        Reply::Refused(code) => {
            let refused =
                json!({"type": "relay", "op": "host_route_refused", "v": 1, "code": code});
            let _ = socket.send(Message::Text(refused.to_string())).await;
            let _ = socket.close(None).await;
            let _ = relay.send(RelayEvent::Closed(n));
            return;
        }
        Reply::OkThenClose { host_id, head } => {
            let _ = socket
                .send(Message::Text(ok_message(&host_id, &head)))
                .await;
            let _ = socket.close(None).await;
            let _ = relay.send(RelayEvent::Closed(n));
            return;
        }
        Reply::Unsolicited { .. } | Reply::Nothing | Reply::AstationFirst { .. } | Reply::Serve => {
        }
    }
    serve(n, socket, events, commands, auth).await;
    let _ = relay.send(RelayEvent::Closed(n));
}

/// [`Reply::AstationFirst`]: the rest of a host connection whose room's
/// owner challenges it before the relay's verdict.
#[allow(clippy::type_complexity)]
async fn astation_first(
    n: u64,
    mut socket: tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    query: Vec<(String, String)>,
    room: String,
    nonce: [u8; 32],
    (ok, reply_first): (Option<(String, Value)>, bool),
    (events, relay, commands, auth): (
        mpsc::Sender<Event>,
        mpsc::Sender<RelayEvent>,
        tokio::sync::mpsc::UnboundedReceiver<Cmd>,
        Arc<Mutex<AuthReply>>,
    ),
) {
    if socket
        .send(Message::Text(auth_required("relay").to_string()))
        .await
        .is_err()
    {
        let _ = relay.send(RelayEvent::Closed(n));
        return;
    }
    let mut proof = false;
    let mut pending_auth: Option<Value> = None;
    let mut answered = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(15);
    let mut query = Some(query);
    while !(answered && (proof || ok.is_none())) {
        let frame = tokio::time::timeout_at(deadline, socket.next()).await;
        let Ok(Some(Ok(frame))) = frame else {
            let _ = socket.close(None).await;
            let _ = relay.send(RelayEvent::Closed(n));
            return;
        };
        let Message::Text(text) = frame else { continue };
        let Ok(value) = serde_json::from_str::<Value>(&text) else {
            continue;
        };
        if value["op"] == "host_route" {
            proof = true;
            let _ = relay.send(RelayEvent::Proof {
                link: n,
                query: query.take().unwrap_or_default(),
                nonce,
                room: room.clone(),
                message: text.to_string(),
            });
        } else if is_auth(&value) {
            pending_auth = Some(value);
        } else {
            let _ = events.send(Event::Message(n, value));
        }
        // Astation answers at once without a verdict to order; else once
        // the proof and the `auth` both arrived, in the planned order.
        let ready = ok.is_none() || proof;
        if ready && let Some(value) = pending_auth.take() {
            let verdict = ok.as_ref().map(|(host_id, head)| ok_message(host_id, head));
            if !reply_first && let Some(verdict) = &verdict {
                let _ = socket.send(Message::Text(verdict.clone())).await;
            }
            if !answer_auth(n, &mut socket, &events, &auth, value).await {
                let _ = relay.send(RelayEvent::Closed(n));
                return;
            }
            if reply_first && let Some(verdict) = &verdict {
                let _ = socket.send(Message::Text(verdict.clone())).await;
            }
            answered = true;
        }
    }
    serve(n, socket, events, commands, auth).await;
    let _ = relay.send(RelayEvent::Closed(n));
}

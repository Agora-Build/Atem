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

pub enum Event {
    /// Connection `n` authenticated.
    Authenticated(u64),
    Message(u64, Value),
}

enum Cmd {
    Send(String),
    Close,
}

pub struct FakeAstation {
    pub url: String,
    pub events: mpsc::Receiver<Event>,
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

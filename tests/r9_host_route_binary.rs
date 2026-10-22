//! The host route proof (atem-session-v1.md §R9.7b) in the real `atem
//! runtime` process: a temp profile paired with a fake Astation that is
//! offline (its local URL refuses connections), a pinned device list, and a
//! fake relay that sends `host_challenge` the moment the runtime's relay
//! identity link opens. The runtime answers before any Astation could
//! authenticate it, and the relay's shared verifier
//! (`atem_client::host_route`) accepts the proof against the host's log,
//! for the room and `atem_id` of the link's URL. A held host answers
//! nothing.
#![cfg(target_os = "linux")]

mod support;

use atem_client::host_route::{HostChallenge, verify_host_route_message};
use futures_util::{SinkExt, StreamExt};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;
use support::astation::{ASTATION, write_verified_pairing};
use support::r9::write_pin;
use support::r9log::{TestLog, secret};
use support::{Sandbox, within};
use tokio_tungstenite::tungstenite::Message;

const ACCOUNT: &str = "acct-route";
const HOST: &str = "host-route";

/// What the fake relay saw on one host connection.
struct Seen {
    /// The query of the connection's URL (`role`, `code`, `atem_id`).
    query: Vec<(String, String)>,
    challenge: HostChallenge,
    /// The first `host_route` Atem sent within 5 s.
    answer: Option<String>,
}

/// A relay that challenges every host connection, then closes it.
// The handshake callback's `Err` is tungstenite's own response type.
#[allow(clippy::result_large_err)]
fn fake_relay() -> (String, mpsc::Receiver<Seen>) {
    let (url_tx, url_rx) = mpsc::channel();
    let (seen_tx, seen) = mpsc::channel();
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
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let mut query = String::new();
                let callback =
                    |request: &tokio_tungstenite::tungstenite::handshake::server::Request,
                     response| {
                        query = request.uri().query().unwrap_or_default().to_owned();
                        Ok(response)
                    };
                let Ok(mut socket) = tokio_tungstenite::accept_hdr_async(stream, callback).await
                else {
                    continue;
                };
                let query: Vec<(String, String)> = query
                    .split('&')
                    .filter_map(|kv| kv.split_once('='))
                    .map(|(k, v)| (k.to_owned(), urlencoding::decode(v).unwrap().into_owned()))
                    .collect();
                let code = query
                    .iter()
                    .find(|(k, _)| k == "code")
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();
                let challenge = HostChallenge::new(&code);
                if socket
                    .send(Message::Text(challenge.to_json().to_string()))
                    .await
                    .is_err()
                {
                    continue;
                }
                let answer = tokio::time::timeout(Duration::from_secs(5), async {
                    while let Some(Ok(frame)) = socket.next().await {
                        if let Message::Text(text) = frame
                            && text.contains("\"host_route\"")
                        {
                            return Some(text);
                        }
                    }
                    None
                })
                .await
                .ok()
                .flatten();
                let _ = socket.close(None).await;
                let _ = seen_tx.send(Seen {
                    query,
                    challenge,
                    answer,
                });
            }
        });
    });
    (url_rx.recv_timeout(Duration::from_secs(5)).unwrap(), seen)
}

struct Rig {
    sandbox: Sandbox,
    log: TestLog,
    relay: mpsc::Receiver<Seen>,
    runtime: Child,
}

impl Rig {
    /// Paired with `ASTATION` (offline) and a pinned device list naming
    /// this host; `held`: a recorded device-list write fault.
    fn start(held: bool) -> Rig {
        let sandbox = Sandbox::new();
        write_verified_pairing(&sandbox.config(), ACCOUNT, HOST, 1);
        let host_seed = secret("route host seed");
        let mut log = TestLog::genesis(ACCOUNT, &secret("route astation"));
        log.add_host(HOST, 1, &host_seed);
        log.add_native("dev-phone", &["control", "view"]);
        write_pin(&sandbox.config(), &log, HOST, 1, &host_seed);
        if held {
            std::fs::write(
                sandbox.config().join("pairing").join("membership.fault"),
                br#"{"v":1,"runtime_epoch":1,"file":"membership.json","at":1}"#,
            )
            .unwrap();
        }
        let (relay_url, relay) = fake_relay();
        let output = std::fs::File::create(sandbox.dir.path().join("runtime.log")).unwrap();
        let runtime = Command::new(env!("CARGO_BIN_EXE_atem"))
            .arg("runtime")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", &sandbox.home)
            .env("XDG_RUNTIME_DIR", &sandbox.run)
            // No Astation anywhere: the local link is refused.
            .env("ASTATION_WS", "ws://127.0.0.1:1/ws")
            .env("ASTATION_RELAY_URL", &relay_url)
            .stdin(Stdio::null())
            .stdout(output.try_clone().unwrap())
            .stderr(output)
            .spawn()
            .unwrap();
        let config = sandbox.config();
        within("the runtime to listen", || {
            config.join("runtime.socket").exists()
        });
        Rig {
            sandbox,
            log,
            relay,
            runtime,
        }
    }

    fn runtime_log(&self) -> String {
        std::fs::read_to_string(self.sandbox.dir.path().join("runtime.log")).unwrap_or_default()
    }

    fn next_connection(&self) -> Seen {
        self.relay
            .recv_timeout(Duration::from_secs(20))
            .unwrap_or_else(|_| panic!("no relay connection: {}", self.runtime_log()))
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        let _ = self.runtime.kill();
        let _ = self.runtime.wait();
    }
}

fn param<'a>(seen: &'a Seen, key: &str) -> &'a str {
    seen.query
        .iter()
        .find(|(k, _)| k == key)
        .map(|(_, v)| v.as_str())
        .unwrap_or_else(|| panic!("no {key} in {:?}", seen.query))
}

#[test]
fn a_pinned_host_proves_its_route_with_no_astation_online() {
    let rig = Rig::start(false);
    let seen = rig.next_connection();
    assert_eq!(param(&seen, "role"), "atem");
    assert_eq!(param(&seen, "code"), ASTATION);
    let answer = seen
        .answer
        .as_deref()
        .unwrap_or_else(|| panic!("no host_route: {}", rig.runtime_log()));
    let route = verify_host_route_message(
        &rig.log.log,
        answer.as_bytes(),
        &seen.challenge.nonce,
        ASTATION,
        param(&seen, "atem_id"),
    )
    .unwrap();
    assert_eq!(route.host_id, HOST);
    assert_eq!(route.head, rig.log.log.head());
    // Never content in the log: the line names the head only.
    let log = rig.runtime_log();
    assert!(log.contains("host_challenge answered at head"), "{log}");
    assert!(!log.contains(&atem_client::encoding::b64u(&seen.challenge.nonce)));
}

#[test]
fn a_held_host_answers_no_challenge() {
    let rig = Rig::start(true);
    let seen = rig.next_connection();
    assert_eq!(seen.answer, None);
    let log = rig.runtime_log();
    assert!(
        log.contains("host_challenge not answered: device list held"),
        "{log}"
    );
}

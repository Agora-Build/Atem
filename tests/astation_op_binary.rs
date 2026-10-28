//! `atem pair verify` through the real binary: the CLI starts the runtime,
//! whose own Astation link (to a fake Astation) carries the verification;
//! the CLI only shows it and answers from its terminal.
#![cfg(target_os = "linux")]

mod support;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use std::sync::mpsc;
use std::time::Duration;
use support::Sandbox;
use tokio_tungstenite::tungstenite::Message;

const ASTATION: &str = "astation-bin";
/// The P-256 generator, uncompressed: a valid Astation signing key.
const SIGN_PUB: &str = "046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";

fn b64(bytes: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn hex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// A profile paired with `ASTATION` (binding and saved session), not verified.
fn paired(config: &std::path::Path) {
    support::profile::write_pairing(config, ASTATION, 1);
}

/// A fake local Astation on its own thread: authenticates the runtime's
/// connection, answers `verifyCommit` with its keys, and reports every
/// message type atem sends (with the `verifyAbort` reason).
fn fake_astation() -> (String, mpsc::Receiver<(String, Value)>) {
    let (url_tx, url_rx) = mpsc::channel();
    let (seen_tx, seen_rx) = mpsc::channel();
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
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let Ok(mut socket) = tokio_tungstenite::accept_async(stream).await else {
                    continue;
                };
                let challenge = json!({"type": "statusUpdate", "data": {"status": "auth_required",
                    "data": {"astation_id": ASTATION, "challenge": "b".repeat(64),
                             "transport": "lan", "protocol": "2"}}});
                let _ = socket.send(Message::Text(challenge.to_string())).await;
                while let Some(Ok(frame)) = socket.next().await {
                    let Message::Text(text) = frame else { continue };
                    let Ok(value) = serde_json::from_str::<Value>(&text) else {
                        continue;
                    };
                    let kind = value["type"].as_str().unwrap_or_default().to_string();
                    let reply = match kind.as_str() {
                        "statusUpdate" if value["data"]["status"] == "auth" => {
                            Some(json!({"type": "statusUpdate",
                                        "data": {"status": "authenticated", "data": {}}}))
                        }
                        "verifyCommit" => Some(json!({"type": "verifyKeys", "data": {
                            "sign_pub": b64(&hex(SIGN_PUB)), "enc_pub": b64(&[5; 32]),
                            "recovery_sign_pub": b64(&[6; 32]), "nonce": b64(&[7; 32]),
                            "genesis_hash": "ab".repeat(32)}})),
                        _ => None,
                    };
                    let _ = seen_tx.send((kind, value["data"].clone()));
                    if let Some(reply) = reply
                        && socket.send(Message::Text(reply.to_string())).await.is_err()
                    {
                        break;
                    }
                }
            }
        });
    });
    let url = url_rx.recv_timeout(Duration::from_secs(5)).unwrap();
    (url, seen_rx)
}

/// The next message of type `kind` the fake saw (within 20 s).
fn saw(seen: &mpsc::Receiver<(String, Value)>, kind: &str) -> Value {
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        let (seen_kind, data) = seen
            .recv_timeout(left)
            .unwrap_or_else(|_| panic!("Astation never got {kind}"));
        if seen_kind == kind {
            return data;
        }
    }
}

#[test]
fn pair_verify_runs_through_the_auto_started_runtime() {
    let sandbox = Sandbox::new();
    paired(&sandbox.config());
    let (url, seen) = fake_astation();
    let mut cli = sandbox.spawn(&["pair", "verify"], &sandbox.home, &[("ASTATION_WS", &url)]);
    // The runtime (started by the CLI) authenticates its link and verifies on it.
    let commit = saw(&seen, "verifyCommit");
    // r9: the binding's generation, public (§R9.2): `pair verify` runs in
    // the next one (the profile was paired at 1; a fresh host_channel_key).
    assert_eq!(commit["host_trust_gen"], 2, "{commit}");
    // r9: the reveal carries this pairing's host channel key.
    let reveal = saw(&seen, "verifyReveal");
    assert_eq!(reveal["host_channel_pub"].as_str().map(str::len), Some(43));
    cli.shows("Safety code:");
    cli.shows("Does the code on your Mac match? Type y or n:");
    // The CLI answers from its terminal; a refusal reaches Astation.
    cli.send(b"n\r");
    let abort = saw(&seen, "verifyAbort");
    assert_eq!(abort["reason"], "codes didn't match on atem");
    assert!(!cli.exits(), "a refused code fails the command");
    let written = cli.written();
    assert!(written.contains("device verification failed"), "{written}");
    assert!(sandbox.runtime_pid().is_some(), "the runtime ran it");
}

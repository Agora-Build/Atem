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

/// The longest a "wait until" helper waits. A passing run never gets near it;
/// a slow runner (the Intel macOS CI one takes ~340 s for ~45 s of tests) needs
/// the slack, and a hung test still ends.
const WAIT: Duration = Duration::from_secs(60);
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

/// The next message of type `kind` the fake saw (within `WAIT`).
fn saw(seen: &mpsc::Receiver<(String, Value)>, kind: &str) -> Value {
    let deadline = std::time::Instant::now() + WAIT;
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
    // Paired already: the last line says so, with the next step, instead of
    // reading as if pairing failed.
    assert!(
        written.contains("Paired, but this device isn't verified yet."),
        "{written}"
    );
    assert!(written.contains("run 'atem pair verify'"), "{written}");
    assert!(!written.contains("device verification failed"), "{written}");
    assert!(sandbox.runtime_pid().is_some(), "the runtime ran it");
}

/// A device's keys from fixed secrets: the plain `cred/device_keys` file
/// (before its first escrow; the cred agent seals it when it starts) and
/// the public keys a verification pinned (base64).
struct Keys {
    device_pub: String,
    device_sign_pub: String,
    unlock_auth_pub: String,
}

fn device_keys(config: &std::path::Path) -> Keys {
    let (device, sign, unlock) = ([1u8; 32], [2u8; 32], [3u8; 32]);
    let ed = |secret: [u8; 32]| {
        b64(&ed25519_dalek::SigningKey::from_bytes(&secret)
            .verifying_key()
            .to_bytes())
    };
    let keys = Keys {
        device_pub: b64(
            x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(device)).as_bytes(),
        ),
        device_sign_pub: ed(sign),
        unlock_auth_pub: ed(unlock),
    };
    let cred = support::profile::CredPaths::in_dir(config);
    std::fs::create_dir_all(&cred.dir).unwrap();
    std::fs::write(
        &cred.device_keys,
        json!({"version": 1, "device": b64(&device), "device_sign": b64(&sign),
               "unlock_auth": b64(&unlock)})
        .to_string(),
    )
    .unwrap();
    keys
}

/// `config`'s trust state: verified with `ASTATION` (safety code `code`)
/// with `keys` (none: empty), as a verification made before device lists
/// were pinned left it; `home` recorded or not (older stores have none).
fn verified_before_lists(config: &std::path::Path, code: &str, keys: Option<&Keys>, home: bool) {
    let (device_pub, device_sign_pub, unlock_auth_pub) = keys.map_or(("", "", ""), |k| {
        (&*k.device_pub, &*k.device_sign_pub, &*k.unlock_auth_pub)
    });
    let entry = json!({
        "device_id": "atem-bin", "data_account": "acct-bin", "sign_gen": 1,
        "astation_sign_pub": "", "astation_enc_pub": "", "recovery_sign_pub": "",
        "device_pub": device_pub, "device_sign_pub": device_sign_pub,
        "unlock_auth_pub": unlock_auth_pub,
        "safety_code": code, "epoch_floor": 0, "account_state": null, "account_epoch": 0,
    });
    let mut store = json!({"version": 1, "astations": {ASTATION: entry}});
    if home {
        store["home_astation"] = json!(ASTATION);
    }
    let trust = support::profile::CredPaths::in_dir(config);
    std::fs::create_dir_all(&trust.dir).unwrap();
    std::fs::write(&trust.trust, store.to_string()).unwrap();
}

/// The note `atem pair verify` prints before a rerun, line by line.
const RERUN_NOTE_START: &str =
    "This device was verified before device lists were pinned; verifying again pins one.";

/// Owner decision 2026-11-08 (#128): `atem pair verify` on a pairing
/// verified before device lists were pinned (no device-list file) says
/// why and what starting does, asks to continue, then runs the ceremony
/// again in the next trust generation with the device's own keys: the
/// cred agent the runtime starts seals the plain key file and reveals the
/// keys Astation pinned (never fresh ones). Refused at the code here, it
/// keeps the earlier verification, and the last line says the device
/// stays verified with no list yet.
#[test]
fn pair_verify_verifies_again_with_the_devices_own_keys() {
    let sandbox = Sandbox::new();
    paired(&sandbox.config());
    let keys = device_keys(&sandbox.config());
    verified_before_lists(&sandbox.config(), "MN3H-A74N-FJE4", Some(&keys), false);
    let (url, seen) = fake_astation();
    let mut cli = sandbox.spawn(&["pair", "verify"], &sandbox.home, &[("ASTATION_WS", &url)]);
    cli.shows("Continue? [y/N]");
    let written = cli.written();
    assert!(written.contains(RERUN_NOTE_START), "{written}");
    assert!(written.contains("even if you cancel"), "{written}");
    cli.send(b"y\r");
    let commit = saw(&seen, "verifyCommit");
    assert_eq!(commit["host_trust_gen"], 2, "{commit}");
    let reveal = saw(&seen, "verifyReveal");
    // The keys Astation pinned, from the cred agent: never fresh ones.
    assert_eq!(reveal["device_pub"], keys.device_pub.as_str(), "{reveal}");
    assert_eq!(reveal["device_sign_pub"], keys.device_sign_pub.as_str());
    assert_eq!(reveal["unlock_auth_pub"], keys.unlock_auth_pub.as_str());
    cli.shows("Does the code on your Mac match? Type y or n:");
    cli.send(b"n\r");
    let abort = saw(&seen, "verifyAbort");
    assert_eq!(abort["reason"], "codes didn't match on atem");
    assert!(!cli.exits(), "a refused code fails the command");
    let written = cli.written();
    assert!(
        written.contains(
            "This device stays verified, but no device list is pinned yet. Fix the problem above, then run 'atem pair verify'."
        ),
        "{written}"
    );
    assert!(!written.contains("isn't verified yet"), "{written}");
    // The earlier verification is kept; nothing is pinned.
    let trust: Value = serde_json::from_slice(
        &std::fs::read(support::profile::CredPaths::in_dir(&sandbox.config()).trust).unwrap(),
    )
    .unwrap();
    assert_eq!(
        trust["astations"][ASTATION]["safety_code"], "MN3H-A74N-FJE4",
        "{trust}"
    );
    assert_eq!(
        trust["astations"][ASTATION]["device_pub"],
        keys.device_pub.as_str()
    );
    assert!(
        trust["pending"].as_object().is_none_or(|p| p.is_empty()),
        "{trust}"
    );
    assert!(!sandbox.config().join("pairing/membership.json").exists());
    assert!(
        sandbox.cred_agent_pid().is_some(),
        "the runtime's cred agent"
    );
}

/// A rerun never makes fresh keys: a verified pairing with no key files at
/// all (an old store, no home recorded) is refused before anything moves,
/// with the reset steps; Astation gets no `verifyCommit`.
#[test]
fn pair_verify_never_reruns_with_fresh_keys() {
    let sandbox = Sandbox::new();
    paired(&sandbox.config());
    verified_before_lists(&sandbox.config(), "MN3H-A74N-FJE4", None, false);
    let (url, seen) = fake_astation();
    let mut cli = sandbox.spawn(&["pair", "verify"], &sandbox.home, &[("ASTATION_WS", &url)]);
    assert!(!cli.exits(), "refused");
    let written = cli.written();
    assert!(written.contains(RERUN_NOTE_START), "{written}");
    assert!(written.contains("no key files on disk"), "{written}");
    assert!(
        written.contains("then run `atem unpair` and `atem pair`"),
        "{written}"
    );
    assert!(!written.contains("Continue?"), "{written}");
    assert!(
        !seen.try_iter().any(|(kind, _)| kind == "verifyCommit"),
        "no verifyCommit"
    );
    assert!(!sandbox.config().join("cred/device_keys.sealed").exists());
}

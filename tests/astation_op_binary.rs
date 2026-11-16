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
                            "genesis_hash": "ab".repeat(32), "account_id": "acct-bin"}})),
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
    // host-work-v1 §11.5: and the host's new encryption key, vouched for
    // by it for the account and genesis `verifyKeys` named.
    let genesis = atem_client::encoding::Hash32::from_hex(&"ab".repeat(32)).unwrap();
    let host_id = commit["device_id"].as_str().unwrap();
    support::r9log::reveal_host_enc_key(&reveal, "acct-bin", &genesis, host_id, 2)
        .unwrap_or_else(|e| panic!("Astation refuses the reveal: {e}"));
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

/// The next message of type `kind` Atem sent the fake Astation (within
/// `WAIT`), with the link it came on.
#[track_caller]
fn astation_saw(astation: &support::astation::FakeAstation, kind: &str) -> (u64, Value) {
    use support::astation::Event;
    let deadline = std::time::Instant::now() + WAIT;
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match astation.events.recv_timeout(left) {
            Ok(Event::Message(link, value)) if value["type"] == kind => return (link, value),
            Ok(_) => {}
            Err(_) => panic!("Astation never got {kind}"),
        }
    }
}

/// Every message Atem sent the fake Astation up to the first of type
/// `kind` (within `WAIT`): their types, then that message and its link.
#[track_caller]
fn astation_until(
    astation: &support::astation::FakeAstation,
    kind: &str,
) -> (Vec<String>, u64, Value) {
    use support::astation::Event;
    let deadline = std::time::Instant::now() + WAIT;
    let mut before = Vec::new();
    loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match astation.events.recv_timeout(left) {
            Ok(Event::Message(link, value)) if value["type"] == kind => {
                return (before, link, value);
            }
            Ok(Event::Message(_, value)) => {
                before.push(value["type"].as_str().unwrap_or_default().to_owned())
            }
            Ok(_) => {}
            Err(_) => panic!("Astation never got {kind} (got {before:?})"),
        }
    }
}

/// host-work-v1 §11.5, through the real binary: the record of the new
/// key's id comes before the reveal. With the record's path blocked (a
/// directory there), the ceremony aborts right after `verifyKeys` with
/// "couldn't record", no `verifyReveal` is ever sent, and nothing is
/// pinned or kept.
#[test]
fn a_key_whose_id_cant_be_recorded_is_never_revealed() {
    let sandbox = Sandbox::new();
    let config = sandbox.config();
    support::profile::write_pairing(&config, support::astation::ASTATION, 1);
    let pairing = support::profile::ProfilePaths::in_dir(&config).pairing;
    std::fs::create_dir_all(pairing.host_enc_generated.join("in-the-way")).unwrap();
    let astation = support::astation::FakeAstation::start();
    let mut ceremony = support::astation::Ceremony::new("acct-bin");
    let mut cli = sandbox.spawn(
        &["pair", "verify"],
        &sandbox.home,
        &[("ASTATION_WS", &astation.url)],
    );
    let (link, commit) = astation_saw(&astation, "verifyCommit");
    astation.send(link, ceremony.verify_keys(&commit["data"]).to_string());
    let (before, _, abort) = astation_until(&astation, "verifyAbort");
    assert!(!before.iter().any(|k| k == "verifyReveal"), "{before:?}");
    assert_eq!(
        abort["data"]["reason"],
        "atem couldn't record its host encryption key; nothing was revealed"
    );
    assert!(!cli.exits(), "the verification failed");
    assert!(
        cli.written()
            .contains("Couldn't record this host's new encryption key"),
        "{}",
        cli.written()
    );
    assert!(!pairing.membership.exists() && !pairing.host_enc_key.exists());
}

/// host-work-v1 §11.5, through the real binary: a `deviceVerified` whose
/// certificate names another account than `verifyKeys` did is refused,
/// with that refusal alone (the genesis, the list ending at the `add_host`
/// and the certificate are genuine for the account Astation signs for).
/// Nothing is pinned or kept; the record of the revealed key's id stays.
#[test]
fn a_certificate_for_another_account_than_verify_keys_named_is_refused() {
    let sandbox = Sandbox::new();
    let config = sandbox.config();
    support::profile::write_pairing(&config, support::astation::ASTATION, 1);
    let astation = support::astation::FakeAstation::start();
    let mut ceremony = support::astation::Ceremony::new("acct-bin");
    ceremony.keys_account = Some("acct-other".into());
    let mut cli = sandbox.spawn(
        &["pair", "verify"],
        &sandbox.home,
        &[("ASTATION_WS", &astation.url)],
    );
    let (link, commit) = astation_saw(&astation, "verifyCommit");
    astation.send(link, ceremony.verify_keys(&commit["data"]).to_string());
    let (_, reveal) = astation_saw(&astation, "verifyReveal");
    let (certificate, _) = ceremony
        .device_verified(&reveal["data"], false)
        .unwrap_or_else(|e| panic!("the reveal: {e}"));
    cli.shows("Does the code on your Mac match? Type y or n:");
    cli.send(b"y\r");
    astation.send(link, certificate.to_string());
    let (_, abort) = astation_saw(&astation, "verifyAbort");
    let reason = abort["data"]["reason"].as_str().unwrap();
    assert!(
        reason.contains("names another account (acct-bin) than its keys did (acct-other)"),
        "{reason}"
    );
    assert!(!cli.exits(), "the verification failed");
    let pairing = support::profile::ProfilePaths::in_dir(&config).pairing;
    assert!(!pairing.membership.exists(), "nothing pinned");
    assert!(!pairing.host_enc_key.exists(), "no key kept");
    assert!(pairing.host_enc_generated.exists(), "the id it handed out");
}

/// host-work-v1 §11.5, through the real binary: a full `atem pair verify`
/// with an Astation that signs the host's encryption key in the ceremony.
/// The runtime reads `verifyKeys.account_id`, records its new key's id
/// before the reveal, reveals `host_enc_key` (checked as Astation checks
/// it), and on the signed `deviceVerified`, whose entries end at that key's
/// `host_enc_key` right after the host's `add_host`, pins the device list
/// and keeps the revealed key as `pairing/host_enc_key`. Then (gate
/// closed) the same with entries ending at the `add_host`: the key is kept
/// all the same.
#[test]
fn pair_verify_keeps_the_encryption_key_it_revealed() {
    for key_entry in [true, false] {
        let sandbox = Sandbox::new();
        let config = sandbox.config();
        support::profile::write_pairing(&config, support::astation::ASTATION, 1);
        let astation = support::astation::FakeAstation::start();
        let mut ceremony = support::astation::Ceremony::new("acct-bin");
        let mut cli = sandbox.spawn(
            &["pair", "verify"],
            &sandbox.home,
            &[("ASTATION_WS", &astation.url)],
        );
        let (link, commit) = astation_saw(&astation, "verifyCommit");
        astation.send(link, ceremony.verify_keys(&commit["data"]).to_string());
        let (_, reveal) = astation_saw(&astation, "verifyReveal");
        let pairing = support::profile::ProfilePaths::in_dir(&config).pairing;
        let read = |path: &std::path::Path| -> Option<Value> {
            std::fs::read(path)
                .ok()
                .map(|bytes| serde_json::from_slice(&bytes).unwrap())
        };
        // Its id is on disk as the reveal arrives (the order:
        // `a_key_whose_id_cant_be_recorded_is_never_revealed`); no key file
        // yet.
        let recorded = read(&pairing.host_enc_generated).expect("recorded before the reveal");
        assert!(!pairing.host_enc_key.exists(), "{key_entry}");
        let (certificate, enc_pub) = ceremony
            .device_verified(&reveal["data"], key_entry)
            .unwrap_or_else(|e| panic!("Astation refuses the reveal: {e}"));
        let kid = {
            let key = atem_client::PublicKey::new(atem_client::Alg::X25519, &enc_pub).unwrap();
            atem_client::keys::enc_kid(&key).unwrap()
        };
        assert_eq!(
            recorded,
            json!({"v": 1, "host_trust_gen": 2, "kids": [kid]}),
            "{key_entry}"
        );
        cli.shows("Does the code on your Mac match? Type y or n:");
        cli.send(b"y\r");
        astation.send(link, certificate.to_string());
        // The first escrow: refused (the storage key stays on the device).
        astation_saw(&astation, "storageKeyRotate");
        astation.send(
            link,
            json!({"type": "storageKeyRejected", "data": {"reason": "not now"}}).to_string(),
        );
        assert!(cli.exits(), "{key_entry}: {}", cli.written());
        assert!(
            cli.written().contains("Device verified"),
            "{}",
            cli.written()
        );
        // Pinned, with the revealed key kept for generation 2.
        let list = read(&pairing.membership).expect("the device list is pinned");
        let entries = list["entries"].as_array().unwrap();
        let last = &entries.last().unwrap()["body"];
        if key_entry {
            assert_eq!(last["action"], "host_enc_key", "{list}");
            assert_eq!(
                last["enc_key"]["pub"],
                atem_client::encoding::b64u(&enc_pub)
            );
        } else {
            assert_eq!(last["action"], "add_host", "{list}");
        }
        let key = read(&pairing.host_enc_key).expect("the key is kept");
        assert_eq!(key["host_trust_gen"], 2);
        assert_eq!(key["pub"], atem_client::encoding::b64u(&enc_pub));
        assert_eq!(read(&pairing.host_enc_generated), Some(recorded));
        // The cred agent the escrow started stops (it holds this sandbox's
        // keys).
        let (_, _, locked) = sandbox.atem(&["cred", "lock"]);
        assert!(locked, "{key_entry}");
    }
}

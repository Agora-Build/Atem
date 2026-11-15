//! The host encryption key on the host (delegated host-work design II.4.1;
//! `host_enc`): made with the pin and at a start, kept, replaced at a new
//! trust generation, deleted by `atem unpair`; its record of key ids; and
//! the recipient helper.
use super::host_enc::{self, HostEncKey};
use crate::paths::PairingPaths;
use crate::profile::Sources;
use crate::session_protocol::membership::pairing::pin_at_pairing_locked;
use crate::session_protocol::membership::r9log::{TestLog, secret};
use crate::session_protocol::membership::store::{DlFile, Injected, Step, Store};
use crate::session_protocol::membership::{HostPin, MembershipHost, journal_of};
use atem_client::encoding::{b64u_decode, hex};
use atem_client::keys::enc_kid;
use atem_client::{Alg, KeyProvider, PublicKey};
use serde_json::{Value, json};
use std::os::unix::fs::PermissionsExt;

const ACCOUNT: &str = "acct-enc";
const HOST: &str = "host-enc";
const ASTATION: &str = "astation-enc";

/// An empty profile.
fn profile() -> (tempfile::TempDir, Sources) {
    let dir = tempfile::tempdir().unwrap();
    let src = Sources::in_dir(dir.path());
    (dir, src)
}

/// A device list whose host `HOST` was added at `generation` with the
/// channel key seeded by `seed`.
fn log_at(generation: u64, seed: &str) -> TestLog {
    let mut log = TestLog::genesis(ACCOUNT, &secret("enc astation"));
    log.add_host(HOST, generation, &secret(seed));
    log
}

/// The list pinned for `HOST` at `generation`, as a host paired before the
/// key existed (no key made with the pin).
fn pinned(pairing: &PairingPaths, generation: u64) -> TestLog {
    let log = log_at(generation, "enc host");
    let pin = HostPin {
        host_id: HOST.into(),
        host_trust_gen: generation,
    };
    MembershipHost::pin(
        pairing,
        &journal_of(pairing),
        &pin,
        &log.log,
        &secret("enc host"),
    )
    .unwrap();
    log
}

fn read_json(path: &std::path::Path) -> Option<Value> {
    std::fs::read(path)
        .ok()
        .map(|b| serde_json::from_slice(&b).unwrap())
}

/// The key file's generation and public half (b64u), checked against its
/// secret, and its mode.
fn key_of(pairing: &PairingPaths) -> Option<(u64, String)> {
    let file = read_json(&pairing.host_enc_key)?;
    let mode = std::fs::metadata(&pairing.host_enc_key)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "plain, 0600");
    assert_eq!(
        file.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["host_trust_gen", "pub", "secret", "v"],
        "{file}"
    );
    assert_eq!(file["v"], 1);
    let secret: [u8; 32] = b64u_decode(file["secret"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret));
    assert_eq!(
        atem_client::encoding::b64u(public.as_bytes()),
        file["pub"].as_str().unwrap(),
        "the public half is the secret's"
    );
    Some((
        file["host_trust_gen"].as_u64().unwrap(),
        file["pub"].as_str().unwrap().to_owned(),
    ))
}

/// R9.9's `enc_kid` of a public half (b64u).
fn kid_of(public: &str) -> String {
    let key = PublicKey::new(Alg::X25519, &b64u_decode(public).unwrap()).unwrap();
    enc_kid(&key).unwrap()
}

fn record(pairing: &PairingPaths) -> Option<Value> {
    read_json(&pairing.host_enc_generated)
}

fn record_of(generation: u64, kids: &[&str]) -> Value {
    json!({"v": 1, "host_trust_gen": generation, "kids": kids})
}

/// Made with the pin when a pairing is verified (its trust generation),
/// its id recorded; `atem pair verify` pins the next generation with a new
/// `host_channel_key`, and with it a new key, the record now of that
/// generation only.
#[test]
fn made_with_the_pin_and_anew_at_each_trust_generation() {
    let (_dir, src) = profile();
    let p = &src.paths.pairing;
    let mut log = log_at(1, "enc host 1");
    pin_at_pairing_locked(p, &log.log, HOST, 1, &secret("enc host 1"), true).unwrap();
    let (generation, first) = key_of(p).expect("made with the pin");
    assert_eq!(generation, 1);
    assert_eq!(record(p), Some(record_of(1, &[&kid_of(&first)])));
    // `atem pair verify`: the next generation's add_host, a new channel key.
    log.add_host(HOST, 2, &secret("enc host 2"));
    pin_at_pairing_locked(p, &log.log, HOST, 2, &secret("enc host 2"), true).unwrap();
    let (generation, second) = key_of(p).expect("made with the new pin");
    assert_eq!(generation, 2);
    assert_ne!(second, first, "a new key at a new trust generation");
    assert_eq!(record(p), Some(record_of(2, &[&kid_of(&second)])));
}

/// With the hook off a pin makes no key (as on main), and a pin removes
/// the key and record an earlier one left (a device-list leftover).
#[test]
fn the_hook_off_makes_none_and_a_new_pin_removes_an_earlier_key() {
    let (_dir, src) = profile();
    let p = &src.paths.pairing;
    let mut log = log_at(1, "enc host 1");
    pin_at_pairing_locked(p, &log.log, HOST, 1, &secret("enc host 1"), false).unwrap();
    assert!(!p.host_enc_key.exists() && !p.host_enc_generated.exists());
    pin_at_pairing_locked(p, &log.log, HOST, 1, &secret("enc host 1"), true).unwrap();
    assert!(key_of(p).is_some());
    log.add_host(HOST, 2, &secret("enc host 2"));
    pin_at_pairing_locked(p, &log.log, HOST, 2, &secret("enc host 2"), false).unwrap();
    assert!(
        !p.host_enc_key.exists(),
        "the earlier generation's key went"
    );
    assert!(!p.host_enc_generated.exists(), "with its record");
}

/// A pin whose key can't be written still pins (the key is the hook's;
/// the next start makes it), and leaves the id it recorded.
#[test]
fn a_pin_whose_key_write_fails_still_pins() {
    let (_dir, src) = profile();
    let p = &src.paths.pairing;
    let log = log_at(1, "enc host 1");
    host_enc::PIN_FAULT.with(|f| {
        f.set(Some(Injected {
            file: DlFile::HostEncKey,
            step: Step::TempWrite,
        }))
    });
    pin_at_pairing_locked(p, &log.log, HOST, 1, &secret("enc host 1"), true).unwrap();
    assert!(p.membership.exists(), "pinned");
    assert!(!p.host_enc_key.exists());
    let kids = record(p).unwrap()["kids"].as_array().unwrap().len();
    assert_eq!(kids, 1, "the id went first");
    let lines = host_enc::ensure(p, &journal_of(p), 1);
    let (_, made) = key_of(p).expect("made at the next start");
    assert_eq!(lines.len(), 1, "{lines:?}");
    let ids = record(p).unwrap()["kids"].clone();
    assert_eq!(ids.as_array().unwrap().len(), 2, "{ids}");
    assert_eq!(ids[1], kid_of(&made));
}

/// `atem unpair` deletes the key and its record with `host_channel_key`.
#[test]
fn unpair_deletes_the_key_and_its_record() {
    let dir = tempfile::tempdir().unwrap();
    let captured = crate::pairing::tests::bound_profile(dir.path(), ASTATION);
    let src = captured.sources().clone();
    let p = &src.paths.pairing;
    let generation = captured.state.host_trust_gen;
    let log = log_at(generation, "enc host");
    pin_at_pairing_locked(p, &log.log, HOST, generation, &secret("enc host"), true).unwrap();
    assert!(key_of(p).is_some() && record(p).is_some());
    crate::pairing::unpair(&src).unwrap();
    assert!(!p.host_channel_key.exists());
    assert!(!p.host_enc_key.exists(), "the key went");
    assert!(!p.host_enc_generated.exists(), "its record went");
    // Never made again without a list.
    assert!(host_enc::ensure(p, &journal_of(p), generation + 1).is_empty());
    assert!(!p.host_enc_key.exists());
}

/// A key or record without the device list is a leftover: the list's start
/// fails closed, as for `host_channel_key`.
#[test]
fn a_key_without_the_list_is_a_leftover() {
    let (_dir, src) = profile();
    let p = &src.paths.pairing;
    pinned(p, 1);
    host_enc::ensure(p, &journal_of(p), 1);
    std::fs::remove_file(&p.membership).unwrap();
    std::fs::remove_file(&p.host_channel_key).unwrap();
    std::fs::remove_file(journal_of(p).join("membership_applied")).unwrap();
    struct NoFences;
    impl crate::session_protocol::membership::Fences for NoFences {
        fn fence(&mut self, _: &str, _: u64) {}
        fn fault(&mut self, _: Option<&[String]>) {}
        fn remote_principals(&self) -> Vec<String> {
            Vec::new()
        }
    }
    let opened = MembershipHost::open(
        p,
        &journal_of(p),
        2,
        &crate::session_protocol::membership::r9log::host_now(),
        &mut NoFences,
    );
    let Err(error) = opened else {
        panic!("fails closed");
    };
    assert!(error.contains("host_enc_key"), "{error}");
    assert!(error.contains("host_enc_generated"), "{error}");
}

/// At a start on a pinned host that has none (paired before the key
/// existed): made, its id recorded; at the next start kept as it is.
#[test]
fn made_at_start_when_missing_and_then_kept() {
    let (_dir, src) = profile();
    let p = &src.paths.pairing;
    pinned(p, 3);
    let lines = host_enc::ensure(p, &journal_of(p), 3);
    let (generation, public) = key_of(p).expect("made at start");
    assert_eq!(generation, 3);
    assert_eq!(
        lines,
        [format!(
            "made for trust generation 3 (enc_kid {})",
            kid_of(&public)
        )]
    );
    assert_eq!(record(p), Some(record_of(3, &[&kid_of(&public)])));
    let bytes = std::fs::read(&p.host_enc_key).unwrap();
    let recorded = std::fs::read(&p.host_enc_generated).unwrap();
    assert!(host_enc::ensure(p, &journal_of(p), 3).is_empty());
    assert_eq!(std::fs::read(&p.host_enc_key).unwrap(), bytes, "kept");
    assert_eq!(std::fs::read(&p.host_enc_generated).unwrap(), recorded);
}

/// No pinned device list: never made.
#[test]
fn never_made_on_a_host_without_a_pinned_list() {
    let (_dir, src) = profile();
    let p = &src.paths.pairing;
    assert!(host_enc::ensure(p, &journal_of(p), 1).is_empty());
    assert!(!p.host_enc_key.exists() && !p.host_enc_generated.exists());
    assert!(!p.dir().exists(), "nothing written at all");
}

/// A key of an earlier generation (left by a build that didn't know the
/// file) is replaced at a start; one that can't be read is left as it is,
/// and said so.
#[test]
fn an_earlier_generations_key_is_replaced_and_an_unreadable_one_kept() {
    let (_dir, src) = profile();
    let p = &src.paths.pairing;
    pinned(p, 2);
    host_enc::ensure(p, &journal_of(p), 1);
    let (_, old) = key_of(p).unwrap();
    let lines = host_enc::ensure(p, &journal_of(p), 2);
    let (generation, new) = key_of(p).unwrap();
    assert_eq!(generation, 2);
    assert_ne!(new, old);
    assert_eq!(
        lines,
        [format!(
            "made for trust generation 2 (enc_kid {}), replacing the key of trust generation 1",
            kid_of(&new)
        )]
    );
    assert_eq!(record(p), Some(record_of(2, &[&kid_of(&new)])));
    // A newer generation than the host's: never handed out, never replaced.
    let bytes = std::fs::read(&p.host_enc_key).unwrap();
    let lines = host_enc::ensure(p, &journal_of(p), 1);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("beyond this host's 1"), "{lines:?}");
    assert_eq!(std::fs::read(&p.host_enc_key).unwrap(), bytes);
    // Damaged.
    std::fs::write(&p.host_enc_key, b"{damaged").unwrap();
    let lines = host_enc::ensure(p, &journal_of(p), 2);
    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("is damaged"), "{lines:?}");
    assert_eq!(std::fs::read(&p.host_enc_key).unwrap(), b"{damaged");
}

/// The record lost, unreadable or of another generation is rebuilt from
/// the key the host holds, with a runtime.log line; one that lacks the
/// key's id gets it added.
#[test]
fn the_record_is_rebuilt_from_the_key_held() {
    let (_dir, src) = profile();
    let p = &src.paths.pairing;
    pinned(p, 1);
    host_enc::ensure(p, &journal_of(p), 1);
    let (_, public) = key_of(p).unwrap();
    let kid = kid_of(&public);
    let rebuilt = |was: &str| {
        vec![format!(
            "the record of keys made was {was}; rebuilt from the key held (enc_kid {kid}, trust generation 1)"
        )]
    };
    std::fs::remove_file(&p.host_enc_generated).unwrap();
    assert_eq!(host_enc::ensure(p, &journal_of(p), 1), rebuilt("missing"));
    assert_eq!(record(p), Some(record_of(1, &[&kid])));
    std::fs::write(&p.host_enc_generated, b"not json").unwrap();
    let lines = host_enc::ensure(p, &journal_of(p), 1);
    assert!(lines[0].contains("was unreadable"), "{lines:?}");
    assert_eq!(record(p), Some(record_of(1, &[&kid])));
    let other = "0123456789abcdef";
    std::fs::write(&p.host_enc_generated, record_of(7, &[other]).to_string()).unwrap();
    assert_eq!(
        host_enc::ensure(p, &journal_of(p), 1),
        rebuilt("of trust generation 7")
    );
    assert_eq!(record(p), Some(record_of(1, &[&kid])));
    std::fs::write(&p.host_enc_generated, record_of(1, &[other]).to_string()).unwrap();
    assert_eq!(
        host_enc::ensure(p, &journal_of(p), 1),
        rebuilt("without its id")
    );
    assert_eq!(record(p), Some(record_of(1, &[other, &kid])));
    // Duplicates or bad ids are unreadable.
    for bad in [
        record_of(1, &[&kid, &kid]),
        record_of(1, &["0123"]),
        record_of(1, &["0123456789ABCDEF"]),
        json!({"v": 2, "host_trust_gen": 1, "kids": []}),
        json!({"v": 1, "host_trust_gen": 1, "kids": [], "more": 1}),
    ] {
        std::fs::write(&p.host_enc_generated, bad.to_string()).unwrap();
        let lines = host_enc::ensure(p, &journal_of(p), 1);
        assert!(lines[0].contains("was unreadable"), "{bad}: {lines:?}");
        assert_eq!(record(p), Some(record_of(1, &[&kid])));
    }
}

/// The id is durable before the key: a failed record write makes nothing,
/// a failed key write leaves the id of a key never handed out.
#[test]
fn the_record_is_written_before_the_key() {
    let (_dir, src) = profile();
    let p = &src.paths.pairing;
    pinned(p, 1);
    for step in [Step::TempWrite, Step::TempFsync, Step::Rename] {
        let mut store = Store::new(p, &journal_of(p));
        store.inject(Injected {
            file: DlFile::HostEncGenerated,
            step,
        });
        let lines = host_enc::ensure_with(&mut store, p, 1);
        assert!(lines[0].starts_with("cannot make it"), "{lines:?}");
        assert!(!p.host_enc_generated.exists(), "{step:?}");
        assert!(!p.host_enc_key.exists(), "{step:?}");
    }
    let mut store = Store::new(p, &journal_of(p));
    store.inject(Injected {
        file: DlFile::HostEncKey,
        step: Step::Rename,
    });
    host_enc::ensure_with(&mut store, p, 1);
    assert!(!p.host_enc_key.exists());
    assert_eq!(record(p).unwrap()["kids"].as_array().unwrap().len(), 1);
}

/// A profile paired with `ASTATION` at `generation` and verified as `HOST`.
fn verified(dir: &std::path::Path, generation: u64) -> Sources {
    crate::pairing::tests::write_bound(
        dir,
        ASTATION,
        generation,
        "binding-1",
        ("session-1", "token-1"),
    );
    let entry = json!({
        "device_id": HOST, "data_account": ACCOUNT, "sign_gen": 1,
        "astation_sign_pub": "", "astation_enc_pub": "", "recovery_sign_pub": "",
        "device_pub": "", "device_sign_pub": "", "unlock_auth_pub": "",
        "safety_code": "", "epoch_floor": 0, "account_state": null, "account_epoch": 0,
    });
    crate::paths::write_test_file(
        &crate::paths::CredPaths::in_dir(dir).trust,
        json!({"version": 1, "astations": {ASTATION: entry}}).to_string(),
    );
    Sources::in_dir(dir)
}

/// The receiver's view of this host (for host senders' mail): its id and
/// generation from its own pairing, the generation's private key behind
/// the provider, and the record's ids.
#[test]
fn the_recipient_is_the_pairings_with_the_generations_key_and_record() {
    let dir = tempfile::tempdir().unwrap();
    let src = verified(dir.path(), 4);
    let p = &src.paths.pairing;
    pinned(p, 4);
    host_enc::ensure(p, &journal_of(p), 4);
    let (_, public) = key_of(p).unwrap();
    let kid: [u8; 8] = atem_client::encoding::hex_decode_array(&kid_of(&public)).unwrap();
    let got = host_enc::recipient(&src).unwrap();
    assert_eq!(got.recipient.host_id, HOST);
    assert_eq!(got.recipient.host_trust_gen, 4);
    assert_eq!(got.recipient.keys, [(HostEncKey::key_id(), kid)]);
    assert_eq!(got.recipient.generated, [kid]);
    assert_eq!(
        got.provider
            .public_key(&HostEncKey::key_id())
            .unwrap()
            .as_bytes(),
        &b64u_decode(&public).unwrap()[..]
    );
    // A key made then lost before it reached the record's file... the record
    // keeps every id of the generation.
    let older = "00112233445566ff";
    std::fs::write(
        &p.host_enc_generated,
        record_of(4, &[older, &hex(&kid)]).to_string(),
    )
    .unwrap();
    let got = host_enc::recipient(&src).unwrap();
    assert_eq!(
        got.recipient.generated,
        [
            atem_client::encoding::hex_decode_array::<8>(older).unwrap(),
            kid
        ]
    );
    // The pairing moved to generation 5 (`atem pair verify` rebound it) and
    // the list still pins 4: the generation is the pairing's, never the
    // list's, and the key and record of 4 are no keys of 5.
    crate::pairing::tests::write_bound(
        dir.path(),
        ASTATION,
        5,
        "binding-2",
        ("session-1", "token-1"),
    );
    let got = host_enc::recipient(&src).unwrap();
    assert_eq!(got.recipient.host_trust_gen, 5);
    assert_eq!(got.recipient.host_id, HOST);
    assert!(got.recipient.keys.is_empty());
    assert!(got.recipient.generated.is_empty());
}

/// Not paired, or not verified: no recipient.
#[test]
fn no_recipient_without_a_verified_pairing() {
    let (_dir, src) = profile();
    assert!(host_enc::recipient(&src).is_err());
    let dir = tempfile::tempdir().unwrap();
    crate::pairing::tests::write_bound(
        dir.path(),
        ASTATION,
        1,
        "binding-1",
        ("session-1", "token-1"),
    );
    assert!(host_enc::recipient(&Sources::in_dir(dir.path())).is_err());
}

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

/// The key file's generation and its current key's public half (b64u),
/// checked against its secret, and its mode (the v2 file, a current key
/// only: no rotation in these tests).
fn key_of(pairing: &PairingPaths) -> Option<(u64, String)> {
    let file = read_json(&pairing.host_enc_key)?;
    let mode = std::fs::metadata(&pairing.host_enc_key)
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o600, "plain, 0600");
    assert_eq!(
        file.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["current", "host_trust_gen", "v"],
        "{file}"
    );
    assert_eq!(file["v"], 2);
    let current = &file["current"];
    assert_eq!(
        current.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["pub", "secret"],
        "{file}"
    );
    let secret: [u8; 32] = b64u_decode(current["secret"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let public = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret));
    assert_eq!(
        atem_client::encoding::b64u(public.as_bytes()),
        current["pub"].as_str().unwrap(),
        "the public half is the secret's"
    );
    Some((
        file["host_trust_gen"].as_u64().unwrap(),
        current["pub"].as_str().unwrap().to_owned(),
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
    json!({"v": 2, "host_trust_gen": generation, "kids": kids, "retired": [], "requests": []})
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
/// the key and record an earlier one left.
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

/// A pin taken back (a verification that failed after its pin) takes the
/// key made with it and its record too.
#[test]
fn a_pin_taken_back_takes_the_key_with_it() {
    let (_dir, src) = profile();
    let p = &src.paths.pairing;
    let log = log_at(1, "enc host 1");
    pin_at_pairing_locked(p, &log.log, HOST, 1, &secret("enc host 1"), true).unwrap();
    assert!(p.host_enc_key.exists() && p.host_enc_generated.exists());
    crate::session_protocol::membership::pairing::unpin_locked(p);
    assert!(!p.membership.exists());
    assert!(!p.host_enc_key.exists(), "the key went with the pin");
    assert!(!p.host_enc_generated.exists(), "its record too");
}

/// Each of `atem unpair`'s two removals takes the key and its record on its
/// own: the list's removal (`forget_on_unpair`) and the leftovers' removal
/// after the next generation is committed (`forget_leftovers`).
#[test]
fn each_unpair_removal_takes_the_key_on_its_own() {
    use crate::session_protocol::membership::{forget_leftovers, forget_on_unpair};
    for removal in ["forget_on_unpair", "forget_leftovers"] {
        let (_dir, src) = profile();
        let p = &src.paths.pairing;
        let log = log_at(1, "enc host 1");
        pin_at_pairing_locked(p, &log.log, HOST, 1, &secret("enc host 1"), true).unwrap();
        assert!(p.host_enc_key.exists() && p.host_enc_generated.exists());
        match removal {
            "forget_on_unpair" => forget_on_unpair(p).unwrap(),
            _ => forget_leftovers(p).unwrap(),
        }
        assert!(!p.host_enc_key.exists(), "{removal}");
        assert!(!p.host_enc_generated.exists(), "{removal}");
    }
}

/// What an older build's `atem unpair` leaves (it doesn't know the two
/// files): a stray encryption key and record without the list grant
/// nothing, so they are no device-list leftover. The list opens as none
/// (r8 not refused for them), nothing counts them, and the next pin or
/// `atem unpair` removes them.
#[test]
fn stray_key_files_without_the_list_are_no_leftover_and_go_at_the_next_pin_or_unpair() {
    struct NoFences;
    impl crate::session_protocol::membership::Fences for NoFences {
        fn fence(&mut self, _: &str, _: u64) {}
        fn fault(&mut self, _: Option<&[String]>) {}
        fn remote_principals(&self) -> Vec<String> {
            Vec::new()
        }
    }
    let older_unpair = |p: &PairingPaths| {
        pinned(p, 1);
        host_enc::ensure(p, &journal_of(p), 1);
        std::fs::remove_file(&p.membership).unwrap();
        std::fs::remove_file(&p.host_channel_key).unwrap();
        std::fs::remove_file(journal_of(p).join("membership_applied")).unwrap();
        assert!(p.host_enc_key.exists() && p.host_enc_generated.exists());
    };
    let dir = tempfile::tempdir().unwrap();
    let captured = crate::pairing::tests::bound_profile(dir.path(), ASTATION);
    let src = captured.sources().clone();
    let p = &src.paths.pairing;
    older_unpair(p);
    let opened = MembershipHost::open(
        p,
        &journal_of(p),
        2,
        &crate::session_protocol::membership::r9log::host_now(),
        &mut NoFences,
    );
    assert!(matches!(opened, Ok(None)), "opens as no list");
    assert!(!crate::session_protocol::membership::has_device_list_files(
        p
    ));
    // `atem unpair` (this build) on this paired profile removes them; on an
    // unpaired one too (`pairing::tests::
    // unpair_removes_a_host_encryption_key_an_older_unpair_left`).
    crate::pairing::unpair(&src).unwrap();
    assert!(!p.host_enc_key.exists() && !p.host_enc_generated.exists());
    // So does the next pin, with the hook off.
    older_unpair(p);
    let log = log_at(2, "enc host 2");
    pin_at_pairing_locked(p, &log.log, HOST, 2, &secret("enc host 2"), false).unwrap();
    assert!(!p.host_enc_key.exists() && !p.host_enc_generated.exists());
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
            "the record of keys made was {was}; rebuilt from the keys held (enc_kid {kid}, trust generation 1)"
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
    // A v1 record (no retired ids) reads as such.
    std::fs::write(
        &p.host_enc_generated,
        json!({"v": 1, "host_trust_gen": 1, "kids": [kid]}).to_string(),
    )
    .unwrap();
    assert!(host_enc::ensure(p, &journal_of(p), 1).is_empty());
    // Duplicates or bad ids are unreadable.
    for bad in [
        record_of(1, &[&kid, &kid]),
        record_of(1, &["0123"]),
        record_of(1, &["0123456789ABCDEF"]),
        json!({"v": 2, "host_trust_gen": 1, "kids": []}),
        json!({"v": 1, "host_trust_gen": 1, "kids": [], "retired": []}),
        json!({"v": 2, "host_trust_gen": 1, "kids": [], "retired": [&kid, &kid]}),
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

/// A record that lists the key held is synced (file and directory) before
/// it counts: a rename whose directory fsync failed isn't durable yet.
#[test]
fn a_listed_record_is_synced_before_it_counts() {
    let (_dir, src) = profile();
    let p = &src.paths.pairing;
    pinned(p, 1);
    host_enc::ensure(p, &journal_of(p), 1);
    for step in [Step::TempFsync, Step::DirectoryFsync] {
        let mut store = Store::new(p, &journal_of(p));
        store.inject(Injected {
            file: DlFile::HostEncGenerated,
            step,
        });
        let lines = host_enc::ensure_with(&mut store, p, 1);
        assert_eq!(lines.len(), 1, "{step:?}: {lines:?}");
        assert!(
            lines[0].starts_with("cannot record the ids of the keys held"),
            "{lines:?}"
        );
    }
    assert!(host_enc::ensure(p, &journal_of(p), 1).is_empty());
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
/// the provider once the committed list set it (committed-list authority:
/// a key no entry set is no accepted key, only one it made), and the
/// record's ids.
#[test]
fn the_recipient_is_the_pairings_with_the_generations_key_and_record() {
    let dir = tempfile::tempdir().unwrap();
    let src = verified(dir.path(), 4);
    let p = &src.paths.pairing;
    let mut log = pinned(p, 4);
    host_enc::ensure(p, &journal_of(p), 4);
    let (_, public) = key_of(p).unwrap();
    let kid: [u8; 8] = atem_client::encoding::hex_decode_array(&kid_of(&public)).unwrap();
    let now = Some(host_enc::DNow {
        d_ms: crate::session_protocol::membership::r9log::host_now().wall_ms,
        clock_change: None,
    });
    let got = host_enc::recipient(&src, &log.log, now).unwrap();
    assert!(got.recipient.keys.is_empty(), "no entry set it yet");
    assert_eq!(got.recipient.generated, [kid], "made: its mail waits");
    let enc_pub: [u8; 32] = b64u_decode(&public).unwrap().try_into().unwrap();
    let host_key = super::HostKey::new(&secret("enc host"));
    let sig = atem_client::membership::sign_host_enc_key(
        &host_key.keys,
        &host_key.id,
        ACCOUNT,
        &log.genesis_hash(),
        HOST,
        4,
        &enc_pub,
    )
    .unwrap();
    log.append(
        crate::session_protocol::membership::r9log::MAC,
        atem_client::membership::host_enc_key(
            HOST,
            4,
            &PublicKey::new(Alg::X25519, &enc_pub).unwrap(),
            &sig,
            false,
            1,
        )
        .unwrap(),
    );
    let got = host_enc::recipient(&src, &log.log, now).unwrap();
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
    let got = host_enc::recipient(&src, &log.log, now).unwrap();
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
    let got = host_enc::recipient(&src, &log.log, now).unwrap();
    assert_eq!(got.recipient.host_trust_gen, 5);
    assert_eq!(got.recipient.host_id, HOST);
    assert!(got.recipient.keys.is_empty());
    assert!(got.recipient.generated.is_empty());
}

/// Not paired, or not verified: no recipient.
#[test]
fn no_recipient_without_a_verified_pairing() {
    let list = log_at(1, "enc host").log;
    let (_dir, src) = profile();
    assert!(host_enc::recipient(&src, &list, None).is_err());
    let dir = tempfile::tempdir().unwrap();
    crate::pairing::tests::write_bound(
        dir.path(),
        ASTATION,
        1,
        "binding-1",
        ("session-1", "token-1"),
    );
    assert!(host_enc::recipient(&Sources::in_dir(dir.path()), &list, None).is_err());
}

// ── `host_enc_key_get` over real channels (session-v1 R9.14 item 8) ──

mod op {
    use super::super::tests::{
        ACCOUNT as R9_ACCOUNT, HOST as R9_HOST, Rig, bot, browser_of, phone,
    };
    use super::*;
    use crate::session_protocol::membership::r9log;
    use atem_client::connect::{Event as CEvent, Identity};
    use atem_client::session::host_work::SENDERS_FEATURE;
    use atem_client::session::r9::HostEncKey as Answer;

    fn mac() -> Identity {
        Identity::native(r9log::MAC, r9log::auth(r9log::MAC))
    }

    /// The r9 rig with hosting and the hook's `host.delegated` and
    /// `host.senders` on, the pairing paths handed to the engine (as the
    /// runtime does), the host's key made as a start makes it, and the Mac
    /// (a manager), the phone (control, no manage) and the bot attached.
    fn rig() -> Rig {
        let mut rig = Rig::new();
        rig.engine
            .set_policy_paths(rig.pairing.clone(), rig.journal.clone());
        rig.engine.enable_host_work(true);
        rig.engine.set_delegated_features(true, false);
        rig.engine.set_senders_feature(true);
        assert_eq!(host_enc::ensure(&rig.pairing, &rig.journal, 1).len(), 1);
        rig.link_up();
        rig.connect("ch-mac", mac());
        rig.advance(1000);
        rig.connect("ch-phone", phone());
        rig.advance(1000);
        rig.connect("ch-bot", bot());
        rig
    }

    /// `handle` asks for the key through the client core: the request's id.
    fn ask(rig: &mut Rig, handle: &str) -> String {
        let mono = rig.now.host.mono_ms;
        let (id, frame) = rig.attached(handle).send_host_enc_key_get(mono).unwrap();
        rig.send_frame(handle, &frame);
        id
    }

    /// The answers and errors `handle` got since the last call.
    fn replies(rig: &mut Rig, handle: &str) -> (Vec<Answer>, Vec<(String, Option<String>)>) {
        let mut answers = Vec::new();
        let mut errors = Vec::new();
        for event in rig.events(handle) {
            match event {
                CEvent::Family(f) if f.data.as_ref().is_some_and(|d| d["op"] == "host_enc_key") => {
                    answers.push(Answer::from_data(f.data.as_ref().unwrap()).unwrap());
                }
                CEvent::Error(e) => errors.push((e.code, e.detail)),
                other => panic!("{handle}: {other:?}"),
            }
        }
        (answers, errors)
    }

    fn busy() -> (Vec<Answer>, Vec<(String, Option<String>)>) {
        (
            Vec::new(),
            vec![(
                "busy".into(),
                Some("host encryption key unavailable".into()),
            )],
        )
    }

    fn forbidden() -> (Vec<Answer>, Vec<(String, Option<String>)>) {
        (Vec::new(), vec![("forbidden".into(), None)])
    }

    /// The public half the key file holds (b64u).
    fn held(rig: &Rig) -> String {
        key_of(&rig.pairing).unwrap().1
    }

    /// A manager gets the key the host holds, bound to this channel's host
    /// and trust generation (the client core takes it), with an `enc_sig`
    /// the shared core verifies with the host's `host_key`; drafted into a
    /// `host_enc_key` entry, the device list accepts it.
    #[test]
    fn a_manager_gets_the_key_with_its_enc_sig() {
        let mut rig = rig();
        let features = rig.attached("ch-mac").welcome().features.clone();
        assert!(
            features.iter().any(|f| f == SENDERS_FEATURE),
            "{features:?}"
        );
        let id = ask(&mut rig, "ch-mac");
        let (answers, errors) = replies(&mut rig, "ch-mac");
        assert!(errors.is_empty(), "{errors:?}");
        let [answer] = answers.as_slice() else {
            panic!("one answer: {answers:?}");
        };
        assert_eq!(answer.re, id);
        assert!(answer.answers(&id, R9_HOST, 1));
        assert_eq!(answer.host_id, R9_HOST);
        assert_eq!(answer.host_trust_gen, 1);
        assert_eq!(
            atem_client::encoding::b64u(answer.enc_key.as_bytes()),
            held(&rig)
        );
        // `enc_sig` verifies with the host's `host_key` (its add_host's).
        let host_key = rig.log.log.host(R9_HOST).unwrap().host_key.clone();
        atem_client::membership::verify_host_enc_sig(
            &host_key,
            R9_ACCOUNT,
            &rig.log.log.genesis_hash(),
            R9_HOST,
            1,
            answer.enc_key.as_32().unwrap(),
            &answer.enc_sig,
        )
        .expect("enc_sig verifies");
        // A manager drafts the entry from it; the chain takes it.
        let action = answer.action(false, r9log::host_now().wall_ms).unwrap();
        rig.log.append(r9log::MAC, action);
        let current = rig
            .log
            .log
            .host_enc_key(R9_HOST)
            .expect("set")
            .current
            .clone();
        assert_eq!(current.key, answer.enc_key);
        // Its id is the record's; asked again, the same key, nothing written.
        assert_eq!(
            record(&rig.pairing),
            Some(record_of(1, &[&hex(&current.kid)]))
        );
        let recorded = std::fs::metadata(&rig.pairing.host_enc_generated)
            .unwrap()
            .modified()
            .unwrap();
        ask(&mut rig, "ch-mac");
        let (again, _) = replies(&mut rig, "ch-mac");
        assert_eq!(again[0].enc_key, answer.enc_key);
        assert_eq!(again[0].enc_sig, answer.enc_sig, "Ed25519 is deterministic");
        assert_eq!(
            std::fs::metadata(&rig.pairing.host_enc_generated)
                .unwrap()
                .modified()
                .unwrap(),
            recorded
        );
        assert!(rig.engine.take_host_work().is_empty());
        assert!(rig.relay.is_empty());
    }

    /// Only a native member holding `manage` at the head: a native without
    /// it, a service and a browser are `forbidden`, and the record and key
    /// are untouched.
    #[test]
    fn others_are_forbidden() {
        let mut rig = rig();
        rig.advance(1000);
        let browser = browser_of(&mut rig, 1);
        rig.connect("ch-browser", browser);
        std::fs::remove_file(&rig.pairing.host_enc_generated).unwrap();
        for handle in ["ch-phone", "ch-browser"] {
            ask(&mut rig, handle);
            assert_eq!(replies(&mut rig, handle), forbidden(), "{handle}");
        }
        // The client core sends it for a service too; the channel refuses.
        ask(&mut rig, "ch-bot");
        assert_eq!(replies(&mut rig, "ch-bot"), forbidden());
        assert!(!rig.pairing.host_enc_generated.exists(), "nothing written");
    }

    /// `manage` is checked when each request is handled (R9.8a): the phone
    /// made a manager gets the key; demoted, `forbidden` again.
    #[test]
    fn manage_is_checked_at_each_request() {
        let mut rig = rig();
        for (roles, served) in [
            (&["control", "manage", "view"][..], true),
            (&["control", "view"][..], false),
        ] {
            let entry = rig.log.set_native_roles("dev-phone", roles);
            let entry = atem_client::SignedObject::parse(entry.to_string().as_bytes()).unwrap();
            let mono = rig.now.host.mono_ms;
            let (_, frame) = rig
                .attached("ch-mac")
                .send_membership(&[entry], mono)
                .unwrap();
            rig.send_frame("ch-mac", &frame);
            rig.events("ch-mac");
            rig.advance(1000);
            let handle = format!("ch-phone-{served}");
            rig.connect(&handle, phone());
            ask(&mut rig, &handle);
            let (answers, errors) = replies(&mut rig, &handle);
            if served {
                assert_eq!(answers.len(), 1, "{errors:?}");
            } else {
                assert_eq!((answers, errors), forbidden());
            }
        }
    }

    /// The record is written before the reply: lost, it is rebuilt by the
    /// request (the answer's key in it); a write that fails is `busy` and
    /// hands nothing out.
    #[test]
    fn the_record_is_written_before_the_reply() {
        let mut rig = rig();
        std::fs::remove_file(&rig.pairing.host_enc_generated).unwrap();
        for step in [Step::TempWrite, Step::TempFsync, Step::Rename] {
            rig.engine.inject_enc_fault(Injected {
                file: DlFile::HostEncGenerated,
                step,
            });
            ask(&mut rig, "ch-mac");
            assert_eq!(replies(&mut rig, "ch-mac"), busy(), "{step:?}");
            assert!(!rig.pairing.host_enc_generated.exists(), "{step:?}");
        }
        ask(&mut rig, "ch-mac");
        let (answers, _) = replies(&mut rig, "ch-mac");
        let kid = enc_kid(&answers[0].enc_key).unwrap();
        assert_eq!(record(&rig.pairing), Some(record_of(1, &[&kid])));
    }

    /// A record whose rename landed but whose directory fsync failed isn't
    /// durable: the retry finds the id listed and syncs the record and its
    /// directory before the key goes; a sync that fails is `busy` again.
    #[test]
    fn a_record_not_yet_synced_is_synced_before_the_key_goes() {
        let mut rig = rig();
        std::fs::remove_file(&rig.pairing.host_enc_generated).unwrap();
        rig.engine.inject_enc_fault(Injected {
            file: DlFile::HostEncGenerated,
            step: Step::DirectoryFsync,
        });
        ask(&mut rig, "ch-mac");
        assert_eq!(replies(&mut rig, "ch-mac"), busy());
        assert!(rig.pairing.host_enc_generated.exists(), "the rename landed");
        for step in [Step::DirectoryFsync, Step::TempFsync] {
            rig.engine.inject_enc_fault(Injected {
                file: DlFile::HostEncGenerated,
                step,
            });
            ask(&mut rig, "ch-mac");
            assert_eq!(replies(&mut rig, "ch-mac"), busy(), "{step:?}");
        }
        ask(&mut rig, "ch-mac");
        assert_eq!(replies(&mut rig, "ch-mac").0.len(), 1);
    }

    /// A manager asking a host that can't answer (here: no key) gets `busy`
    /// each time, and runtime.log gets the cause within the r9 limit for
    /// input-driven lines, never a line per request.
    #[test]
    fn failures_are_logged_within_the_input_limit() {
        let mut rig = rig();
        std::fs::remove_file(&rig.pairing.host_enc_key).unwrap();
        let before = rig.engine.input_lines_written();
        for _ in 0..40 {
            ask(&mut rig, "ch-mac");
            assert_eq!(replies(&mut rig, "ch-mac"), busy());
        }
        let lines = rig.engine.input_lines_written() - before;
        assert!((1..=20).contains(&lines), "{lines}");
    }

    /// No key for the host's generation (none made, damaged, or another
    /// generation's): `busy`, nothing made for the request.
    #[test]
    fn no_key_is_busy() {
        let mut rig = rig();
        let bytes = std::fs::read(&rig.pairing.host_enc_key).unwrap();
        std::fs::remove_file(&rig.pairing.host_enc_key).unwrap();
        ask(&mut rig, "ch-mac");
        assert_eq!(replies(&mut rig, "ch-mac"), busy());
        assert!(
            !rig.pairing.host_enc_key.exists(),
            "never made for a request"
        );
        std::fs::write(&rig.pairing.host_enc_key, b"{damaged").unwrap();
        ask(&mut rig, "ch-mac");
        assert_eq!(replies(&mut rig, "ch-mac"), busy());
        let mut other: Value = serde_json::from_slice(&bytes).unwrap();
        other["host_trust_gen"] = json!(2);
        std::fs::write(&rig.pairing.host_enc_key, other.to_string()).unwrap();
        ask(&mut rig, "ch-mac");
        assert_eq!(replies(&mut rig, "ch-mac"), busy());
        std::fs::write(&rig.pairing.host_enc_key, &bytes).unwrap();
        ask(&mut rig, "ch-mac");
        assert_eq!(replies(&mut rig, "ch-mac").0.len(), 1);
    }

    /// `handle` asks for a new key through the client core: the request's id.
    fn ask_new(rig: &mut Rig, handle: &str, request_id: &str) -> String {
        let mono = rig.now.host.mono_ms;
        let (id, frame) = rig
            .attached(handle)
            .send_host_enc_key_new(request_id, mono)
            .unwrap();
        rig.send_frame(handle, &frame);
        id
    }

    const NEW_1: &str = "aaaaaaaa-0000-4000-8000-0000000000e5";
    const NEW_2: &str = "aaaaaaaa-0000-4000-8000-0000000000e6";

    /// `entry` (a list entry's wire JSON) carried to the host on the
    /// Mac's channel.
    fn carry(rig: &mut Rig, entry: Value) {
        let entry = atem_client::SignedObject::parse(entry.to_string().as_bytes()).unwrap();
        let mono = rig.now.host.mono_ms;
        let (_, frame) = rig
            .attached("ch-mac")
            .send_membership(&[entry], mono)
            .unwrap();
        rig.send_frame("ch-mac", &frame);
        rig.events("ch-mac");
        rig.advance(1000);
    }

    /// The Mac drafts the host's current key (its get answer) into a
    /// `host_enc_key` entry, signed and carried: the list sets it.
    fn set_current(rig: &mut Rig) -> atem_client::PublicKey {
        ask(rig, "ch-mac");
        let (answers, _) = replies(rig, "ch-mac");
        let action = answers[0].action(false, r9log::host_now().wall_ms).unwrap();
        let entry = rig.log.append(r9log::MAC, action);
        carry(rig, entry);
        answers[0].enc_key.clone()
    }

    /// One `host_enc_key_new` on `handle` under `request_id`: its key,
    /// the answer bound to the request and its `enc_sig` verified.
    fn new_on(rig: &mut Rig, handle: &str, request_id: &str) -> atem_client::PublicKey {
        let id = ask_new(rig, handle, request_id);
        let (answers, errors) = replies(rig, handle);
        assert!(errors.is_empty(), "{handle}: {errors:?}");
        let [answer] = answers.as_slice() else {
            panic!("one answer: {answers:?}");
        };
        assert!(answer.answers_new(&id, request_id, R9_HOST, 1), "{handle}");
        let host_key = rig.log.log.host(R9_HOST).unwrap().host_key.clone();
        atem_client::membership::verify_host_enc_sig(
            &host_key,
            R9_ACCOUNT,
            &rig.log.log.genesis_hash(),
            R9_HOST,
            1,
            answer.enc_key.as_32().unwrap(),
            &answer.enc_sig,
        )
        .expect("enc_sig verifies");
        answer.enc_key.clone()
    }

    const NEW_3: &str = "aaaaaaaa-0000-4000-8000-0000000000e7";

    /// `host_enc_key_new` (the routine rotation, agreed with Astation on
    /// 2026-11-23), over channels:
    /// - while the host's key is one no entry has set, every request gets
    ///   that key (R61 rule 2), as the get does;
    /// - once the list sets it, a request gets a new pending key, a retry
    ///   under the same `request_id` and another manager's request the same
    ///   one, each answer echoing its own request; the get still hands out
    ///   the current key.
    #[test]
    fn every_request_gets_the_one_key_no_entry_has_set() {
        let mut rig = rig();
        let current = held(&rig);
        let b64 = |k: &atem_client::PublicKey| atem_client::encoding::b64u(k.as_bytes());
        assert_eq!(b64(&new_on(&mut rig, "ch-mac", NEW_1)), current);
        assert_eq!(b64(&new_on(&mut rig, "ch-mac", NEW_1)), current);
        let set = set_current(&mut rig);
        assert_eq!(b64(&set), current);
        // The phone made a manager too.
        let entry = rig
            .log
            .set_native_roles("dev-phone", &["control", "manage", "view"]);
        carry(&mut rig, entry);
        rig.connect("ch-manager", phone());
        let pending = new_on(&mut rig, "ch-mac", NEW_3);
        assert_ne!(b64(&pending), current);
        assert_eq!(new_on(&mut rig, "ch-mac", NEW_3), pending, "a retry");
        assert_eq!(
            new_on(&mut rig, "ch-manager", NEW_2),
            pending,
            "another manager"
        );
        // The first request's retry: its own key, the current one.
        assert_eq!(b64(&new_on(&mut rig, "ch-mac", NEW_1)), current);
        // The get is a pure read: still the current key.
        ask(&mut rig, "ch-mac");
        let (answers, _) = replies(&mut rig, "ch-mac");
        assert_eq!(b64(&answers[0].enc_key), current);
        let file: Value = read_json(&rig.pairing.host_enc_key).unwrap();
        assert_eq!(file["pending"]["pub"], json!(b64(&pending)));
    }

    /// `manage` lost between a request and its retry (R62's retry is still
    /// a request): `forbidden`, nothing handed out.
    #[test]
    fn a_retry_after_manage_is_lost_is_forbidden() {
        let mut rig = rig();
        let entry = rig
            .log
            .set_native_roles("dev-phone", &["control", "manage", "view"]);
        carry(&mut rig, entry);
        rig.connect("ch-manager", phone());
        new_on(&mut rig, "ch-manager", NEW_2);
        let entry = rig.log.set_native_roles("dev-phone", &["control", "view"]);
        carry(&mut rig, entry);
        rig.connect("ch-demoted", phone());
        ask_new(&mut rig, "ch-demoted", NEW_2);
        assert_eq!(replies(&mut rig, "ch-demoted"), forbidden());
    }

    /// Only a native member holding `manage` at the head: the phone (no
    /// manage), a service and a browser are `forbidden`, nothing written.
    #[test]
    fn others_are_forbidden_a_new_key_too() {
        let mut rig = rig();
        rig.advance(1000);
        let browser = browser_of(&mut rig, 1);
        rig.connect("ch-browser", browser);
        let before = std::fs::read(&rig.pairing.host_enc_key).unwrap();
        for handle in ["ch-phone", "ch-browser", "ch-bot"] {
            ask_new(&mut rig, handle, NEW_1);
            assert_eq!(replies(&mut rig, handle), forbidden(), "{handle}");
        }
        assert_eq!(std::fs::read(&rig.pairing.host_enc_key).unwrap(), before);
    }

    /// A write that fails (the record, then the key file) is `busy` and
    /// hands nothing out; the next request makes the key.
    #[test]
    fn a_failed_write_is_busy_and_hands_out_nothing() {
        let mut rig = rig();
        set_current(&mut rig);
        for file in [DlFile::HostEncGenerated, DlFile::HostEncKey] {
            rig.engine.inject_enc_fault(Injected {
                file,
                step: Step::TempWrite,
            });
            ask_new(&mut rig, "ch-mac", NEW_1);
            assert_eq!(replies(&mut rig, "ch-mac"), busy(), "{file:?}");
            let file: Value = read_json(&rig.pairing.host_enc_key).unwrap();
            assert!(file.get("pending").is_none());
        }
        ask_new(&mut rig, "ch-mac", NEW_1);
        assert_eq!(replies(&mut rig, "ch-mac").0.len(), 1);
    }

    /// The hook's `host.senders` off (or hosting off): the welcome doesn't
    /// list it and the op is refused as on main, `unsupported_version`, with
    /// nothing read or written; the key held changes nothing.
    #[test]
    fn without_host_senders_refused_as_on_main() {
        for (delegated, senders, hosting) in [
            (false, false, true),
            (true, false, true),
            (true, true, false),
        ] {
            let mut rig = Rig::new();
            rig.engine
                .set_policy_paths(rig.pairing.clone(), rig.journal.clone());
            rig.engine.enable_host_work(hosting);
            rig.engine.set_delegated_features(delegated, false);
            rig.engine.set_senders_feature(senders);
            host_enc::ensure(&rig.pairing, &rig.journal, 1);
            std::fs::remove_file(&rig.pairing.host_enc_generated).unwrap();
            rig.link_up();
            rig.connect("ch-mac", mac());
            let features = rig.attached("ch-mac").welcome().features.clone();
            assert!(!features.iter().any(|f| f == SENDERS_FEATURE));
            // The client core refuses to send it to such a host.
            let mono = rig.now.host.mono_ms;
            assert!(rig.attached("ch-mac").send_host_enc_key_get(mono).is_err());
            // Handed to the host anyway (a newer or misbehaving client).
            assert!(
                rig.attached("ch-mac")
                    .send_host_enc_key_new(NEW_1, mono)
                    .is_err()
            );
            for plain in [
                atem_client::session::r9::host_enc_key_get("aaaaaaaa-0000-4000-8000-0000000000e2"),
                atem_client::session::r9::host_enc_key_new(
                    "aaaaaaaa-0000-4000-8000-0000000000e3",
                    NEW_1,
                ),
            ] {
                let plain = plain.to_string().into_bytes();
                let (att, authority) = match &rig.engine.chans["ch-mac"].phase {
                    super::super::Phase::Open(a) => (a.attachment.clone(), a.authority.clone()),
                    _ => panic!("ch-mac is open"),
                };
                rig.run(|e, p| ((), e.on_record(&att, &authority, &plain, p)));
                rig.pump();
                assert_eq!(
                    replies(&mut rig, "ch-mac"),
                    (
                        Vec::new(),
                        vec![(
                            "unsupported_version".into(),
                            Some("host.senders is not advertised".into())
                        )]
                    )
                );
            }
            assert!(!rig.pairing.host_enc_generated.exists());
            let file: Value = read_json(&rig.pairing.host_enc_key).unwrap();
            assert!(file.get("pending").is_none(), "nothing made");
        }
    }
}

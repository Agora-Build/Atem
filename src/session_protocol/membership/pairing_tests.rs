//! The pairing pin (§R9.2 "Pairing"): what a ceremony's device list must
//! hold, and what pinning writes and clears.
use super::pairing::{PairingInputs, pin_at_pairing_locked, unpin_locked, verify_pairing_log};
use super::r9log::{TestLog, secret};
use super::store::{DlFile, Store};
use super::*;
use crate::paths::ProfilePaths;
use crate::session_protocol::r9::host_enc::{CeremonyKey, Vouch, make_for_ceremony_locked};

const HOST: &str = "host-x";

struct Case {
    dir: tempfile::TempDir,
    pairing: PairingPaths,
    log: TestLog,
    mac_secret: [u8; 32],
    host_seed: [u8; 32],
    /// The host encryption key this ceremony made and revealed
    /// (host-work-v1 §11.5).
    enc: CeremonyKey,
}

/// A ceremony's encryption key for `HOST` at generation 2 on `log`'s
/// account, vouched for by `host_seed`; its id recorded in `pairing`.
fn ceremony_key(pairing: &PairingPaths, log: &TestLog, host_seed: &[u8; 32]) -> CeremonyKey {
    make_for_ceremony_locked(
        pairing,
        &Vouch {
            account_id: "acct-p",
            genesis_hash: &log.genesis_hash(),
            host_id: HOST,
            host_trust_gen: 2,
            host_seed,
        },
    )
    .unwrap()
}

fn mac_pub(secret: &[u8; 32]) -> Vec<u8> {
    p256::ecdsa::SigningKey::from_bytes(secret.into())
        .unwrap()
        .verifying_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec()
}

fn host_pub(seed: &[u8; 32]) -> [u8; 32] {
    ed25519_dalek::SigningKey::from_bytes(seed)
        .verifying_key()
        .to_bytes()
}

impl Case {
    /// An account whose list ends at this host's `add_host` (gen 2).
    fn new() -> Case {
        let dir = tempfile::tempdir().unwrap();
        let pairing = ProfilePaths::in_dir(dir.path()).pairing;
        let mac_secret = secret("astation");
        let host_seed = secret("host seed");
        let mut log = TestLog::genesis("acct-p", &mac_secret);
        log.add_native("dev-phone", &["control", "view"]);
        log.add_host(HOST, 2, &host_seed);
        let enc = ceremony_key(&pairing, &log, &host_seed);
        Case {
            dir,
            pairing,
            log,
            mac_secret,
            host_seed,
            enc,
        }
    }

    /// Astation appends the ceremony's `host_enc_key` right after the
    /// `add_host` (host-work-v1 §11.5).
    fn with_key_entry(mut self) -> Case {
        let (enc_pub, enc_sig) = (*self.enc.enc_pub(), *self.enc.enc_sig());
        self.log.host_enc_key_entry(HOST, 2, &enc_pub, &enc_sig);
        self
    }

    fn verify(
        &self,
        membership: Option<&Value>,
        f: impl FnOnce(&mut PairingInputs),
    ) -> Result<Membership, String> {
        let sign_pub = mac_pub(&self.mac_secret);
        let mut inputs = PairingInputs {
            account_id: "acct-p",
            genesis_hash: self.log.genesis_hash().0,
            astation_sign_pub: &sign_pub,
            host_id: HOST,
            host_trust_gen: 2,
            host_pub: host_pub(&self.host_seed),
            enc_pub: *self.enc.enc_pub(),
            enc_sig: *self.enc.enc_sig(),
        };
        f(&mut inputs);
        let sign_pub = inputs.astation_sign_pub.to_vec();
        let inputs = PairingInputs {
            astation_sign_pub: &sign_pub,
            ..inputs
        };
        verify_pairing_log(membership, &inputs, &self.pairing, &self.log.now)
    }

    fn membership(&self) -> Value {
        json!({"entries": self.log.wire()})
    }
}

#[test]
fn the_ceremonys_list_is_verified_then_pinned_with_its_host_key() {
    let case = Case::new();
    let m = case.verify(Some(&case.membership()), |_| {}).unwrap();
    assert_eq!(m.head().seq, 3);
    let journal = journal_of(&case.pairing);
    store::private_dir(&journal).unwrap();
    store::private_dir(case.pairing.dir()).unwrap();
    // Leftovers of an earlier list, including its host key, are cleared.
    let store = Store::new(&case.pairing, &journal);
    for file in LEFTOVERS {
        std::fs::write(store.path(file), b"old").unwrap();
    }
    pin_at_pairing_locked(&case.pairing, &m, HOST, 2, &case.host_seed, &case.enc).unwrap();
    for file in [
        DlFile::Carriage,
        DlFile::Intent,
        DlFile::Freeze,
        DlFile::Fault,
    ] {
        assert!(!store.present(file), "{file:?} cleared");
    }
    let seed = host_channel_seed(&case.pairing, &m, HOST).unwrap();
    assert_eq!(*seed, case.host_seed, "the new key, not the old one");
    let (host, fenced) = MembershipHost::open(
        &case.pairing,
        &journal,
        1,
        &case.log.now,
        &mut super::tests::RecFences::default(),
    )
    .unwrap()
    .expect("a device list");
    assert!(fenced.is_empty());
    assert_eq!(host.head(), m.head());
    assert_eq!(host.applied().head, m.head());
    assert_eq!(host.pin_of().host_id, HOST);
    assert_eq!(host.pin_of().host_trust_gen, 2);
    assert!(host.held().is_none() && !host.is_frozen());
    // The ceremony's encryption key is kept with it (host-work-v1 §11.5),
    // the list ending at the add_host (the signing gate closed, or the
    // key entry's append failed): the same key is handed out later.
    assert_eq!(kept_key(&case.pairing), Some((2, *case.enc.enc_pub())));
    assert_eq!(recorded(&case.pairing), Some((2, vec![case.enc.enc_kid()])));
    // Taken back after a failed verification: nothing r9 is left but the
    // record of the key's id, which was handed out (no leftover).
    unpin_locked(&case.pairing);
    assert!(!has_device_list_files(&case.pairing));
    assert!(
        !case.pairing.host_enc_key.exists(),
        "the key goes with the pin"
    );
    assert_eq!(recorded(&case.pairing), Some((2, vec![case.enc.enc_kid()])));
    drop(case.dir);
}

/// `pairing/host_enc_key`'s generation and public half, if any.
fn kept_key(pairing: &PairingPaths) -> Option<(u64, [u8; 32])> {
    let bytes = std::fs::read(&pairing.host_enc_key).ok()?;
    let file: Value = serde_json::from_slice(&bytes).unwrap();
    let public = atem_client::encoding::b64u_decode(file["pub"].as_str().unwrap()).unwrap();
    Some((
        file["host_trust_gen"].as_u64().unwrap(),
        public.try_into().unwrap(),
    ))
}

/// `pairing/host_enc_generated`'s generation and ids, if any.
fn recorded(pairing: &PairingPaths) -> Option<(u64, Vec<String>)> {
    let bytes = std::fs::read(&pairing.host_enc_generated).ok()?;
    let file: Value = serde_json::from_slice(&bytes).unwrap();
    let kids = file["kids"].as_array().unwrap();
    Some((
        file["host_trust_gen"].as_u64().unwrap(),
        kids.iter()
            .map(|k| k.as_str().unwrap().to_owned())
            .collect(),
    ))
}

/// host-work-v1 §11.5: the ceremony's entries may also end at this host's
/// `host_enc_key` right after its `add_host`, naming the key this ceremony
/// revealed and its `enc_sig`: verified, and pinned with the key kept.
#[test]
fn the_list_may_end_at_the_ceremonys_own_host_enc_key() {
    let case = Case::new().with_key_entry();
    let m = case.verify(Some(&case.membership()), |_| {}).unwrap();
    assert_eq!(m.head().seq, 4);
    let listed = m.host_enc_key(HOST).expect("the key entry").current.clone();
    assert_eq!(listed.key.as_32(), Some(case.enc.enc_pub()));
    assert_eq!(listed.seq, 4);
    store::private_dir(&journal_of(&case.pairing)).unwrap();
    pin_at_pairing_locked(&case.pairing, &m, HOST, 2, &case.host_seed, &case.enc).unwrap();
    assert_eq!(kept_key(&case.pairing), Some((2, *case.enc.enc_pub())));
    assert_eq!(recorded(&case.pairing), Some((2, vec![case.enc.enc_kid()])));
    let (host, _) = MembershipHost::open(
        &case.pairing,
        &journal_of(&case.pairing),
        1,
        &case.log.now,
        &mut super::tests::RecFences::default(),
    )
    .unwrap()
    .expect("a device list");
    assert_eq!(host.head(), m.head());
}

/// host-work-v1 §11.5: anything else at the end fails the verification
/// (nothing is pinned): a `host_enc_key` of this host that isn't the key
/// this ceremony revealed (another key the host vouched for, valid on the
/// chain), one with `retire_previous`, another host's entry after the
/// `add_host`, or any entry after the key entry.
#[test]
fn a_list_ending_anywhere_else_is_refused() {
    let not_ours =
        "the device list's host_enc_key for this host isn't the key this ceremony revealed";
    let not_at_end =
        "the device list must end at this host's add_host or at its host_enc_key right after it";
    // Another key, vouched for by the same host channel key (chain-valid).
    let mut case = Case::new();
    let other = ceremony_key(&case.pairing, &case.log, &case.host_seed);
    case.log
        .host_enc_key_entry(HOST, 2, other.enc_pub(), other.enc_sig());
    let e = case.verify(Some(&case.membership()), |_| {}).unwrap_err();
    assert_eq!(e, not_ours);
    // The revealed key, but another enc_sig than this ceremony's (the
    // inputs say so: a key entry signed for another reveal).
    let case = Case::new().with_key_entry();
    let e = case
        .verify(Some(&case.membership()), |i| i.enc_sig = [7; 64])
        .unwrap_err();
    assert_eq!(e, not_ours);
    // The revealed key with retire_previous.
    let mut case = Case::new();
    let action = atem_client::membership::host_enc_key(
        HOST,
        2,
        &atem_client::PublicKey::new(atem_client::Alg::X25519, case.enc.enc_pub()).unwrap(),
        case.enc.enc_sig(),
        true,
        1,
    )
    .unwrap();
    case.log.append(super::r9log::MAC, action);
    let e = case.verify(Some(&case.membership()), |_| {}).unwrap_err();
    assert_eq!(e, not_ours);
    // Another host's key entry right after this host's add_host.
    let mut case = Case::new();
    let other_seed = secret("other host seed");
    let mut log = TestLog::genesis("acct-p", &case.mac_secret);
    log.add_native("dev-phone", &["control", "view"]);
    log.add_host("host-o", 1, &other_seed);
    log.add_host(HOST, 2, &case.host_seed);
    let mut keys = atem_client::SoftwareKeys::new();
    keys.insert_ed25519(atem_client::KeyId::new("o"), &other_seed);
    let other_sig = atem_client::membership::sign_host_enc_key(
        &keys,
        &atem_client::KeyId::new("o"),
        "acct-p",
        &log.genesis_hash(),
        "host-o",
        1,
        &[9; 32],
    )
    .unwrap();
    log.host_enc_key_entry("host-o", 1, &[9; 32], &other_sig);
    case.enc = ceremony_key(&case.pairing, &log, &case.host_seed);
    case.log = log;
    let e = case.verify(Some(&case.membership()), |_| {}).unwrap_err();
    assert_eq!(e, not_at_end);
    // An entry after the key entry.
    let mut case = Case::new().with_key_entry();
    case.log.add_native("dev-ipad", &["view"]);
    let e = case.verify(Some(&case.membership()), |_| {}).unwrap_err();
    assert_eq!(e, not_at_end);
    // Nothing of any of them was pinned.
    assert!(!case.pairing.membership.exists());
}

/// host-work-v1 §11.5: the key is written with the pin, before the list:
/// a key that can't be kept fails the pin (the leftovers fail closed until
/// the next pin or unpair), and the record keeps the id it handed out.
#[test]
fn a_key_that_cant_be_kept_fails_the_pin() {
    for file in [DlFile::HostEncKey, DlFile::HostEncGenerated] {
        let case = Case::new();
        let m = case.verify(Some(&case.membership()), |_| {}).unwrap();
        let journal = journal_of(&case.pairing);
        store::private_dir(&journal).unwrap();
        PIN_FAULT.with(|f| {
            f.set(Some(store::Injected {
                file,
                step: store::Step::TempFsync,
            }))
        });
        let e = pin_at_pairing_locked(&case.pairing, &m, HOST, 2, &case.host_seed, &case.enc)
            .unwrap_err();
        assert!(e.contains(file.name()), "{file:?}: {e}");
        assert!(!case.pairing.membership.exists(), "{file:?}: not pinned");
        assert!(!case.pairing.host_enc_key.exists(), "{file:?}");
        assert_eq!(
            recorded(&case.pairing),
            Some((2, vec![case.enc.enc_kid()])),
            "{file:?}"
        );
        let opened = MembershipHost::open(
            &case.pairing,
            &journal,
            1,
            &case.log.now,
            &mut super::tests::RecFences::default(),
        );
        assert!(opened.is_err(), "{file:?}: leftovers fail closed");
    }
}

#[test]
fn a_list_that_cant_be_pinned_is_refused() {
    let case = Case::new();
    let entries = case.membership();
    // No list at all (an r8 Astation).
    assert!(
        case.verify(None, |_| {})
            .unwrap_err()
            .contains("no device list")
    );
    // Another genesis than verifyKeys named.
    assert!(
        case.verify(Some(&entries), |i| i.genesis_hash = [1; 32])
            .is_err()
    );
    // Another account than the signed certificate's.
    assert!(
        case.verify(Some(&entries), |i| i.account_id = "acct-other")
            .is_err()
    );
    // Another host key (not the one this ceremony revealed).
    let e = case
        .verify(Some(&entries), |i| i.host_pub = host_pub(&[7; 32]))
        .unwrap_err();
    assert!(e.contains("host key or trust generation"), "{e}");
    // Another trust generation.
    assert!(
        case.verify(Some(&entries), |i| i.host_trust_gen = 3)
            .is_err()
    );
    // Another host.
    let e = case
        .verify(Some(&entries), |i| i.host_id = "host-y")
        .unwrap_err();
    assert!(e.contains("host not in the device list"), "{e}");
    // add_host signed by a manager that isn't the verified Astation.
    let other = mac_pub(&secret("not astation"));
    let e = case
        .verify(Some(&entries), |i| {
            i.astation_sign_pub = Box::leak(other.into_boxed_slice())
        })
        .unwrap_err();
    assert!(e.contains("not signed by the verified Astation"), "{e}");
    // A tampered entry.
    let mut tampered = entries.clone();
    tampered["entries"][1]["body"]["signed_at"] = json!(1);
    assert!(case.verify(Some(&tampered), |_| {}).is_err());
    // Not ending at this host's add_host.
    let mut longer = Case::new();
    longer.log.add_native("dev-ipad", &["view"]);
    let e = longer
        .verify(Some(&longer.membership()), |_| {})
        .unwrap_err();
    assert!(e.contains("must end at this host's add_host"), "{e}");
    // Empty, or not an object of entries.
    assert!(case.verify(Some(&json!({"entries": []})), |_| {}).is_err());
    assert!(case.verify(Some(&json!([])), |_| {}).is_err());
}

#[test]
fn a_genesis_this_host_froze_on_is_never_pinned_again() {
    let case = Case::new();
    let frozen = json!({"v": 1, "genesis": [case.log.genesis_hash().to_hex()]});
    std::fs::create_dir_all(case.pairing.dir()).unwrap();
    crate::paths::write_test_file(&case.pairing.frozen_genesis, frozen.to_string().as_bytes());
    let e = case.verify(Some(&case.membership()), |_| {}).unwrap_err();
    assert!(e.contains("frozen on this host"), "{e}");
}

#[test]
fn a_host_key_that_isnt_the_lists_fails() {
    let case = Case::new();
    let m = case.verify(Some(&case.membership()), |_| {}).unwrap();
    let journal = journal_of(&case.pairing);
    store::private_dir(&journal).unwrap();
    pin_at_pairing_locked(&case.pairing, &m, HOST, 2, &[3; 32], &case.enc).unwrap();
    let e = host_channel_seed(&case.pairing, &m, HOST).unwrap_err();
    assert!(e.contains("isn't the key the device list names"), "{e}");
    std::fs::remove_file(&case.pairing.host_channel_key).unwrap();
    let e = host_channel_seed(&case.pairing, &m, HOST).unwrap_err();
    assert!(e.contains("is missing"), "{e}");
}

/// A pin interrupted after it began leaves only leftovers, which fail
/// closed until the next pin or unpair, never an r8 host.
#[test]
fn an_interrupted_pin_fails_closed() {
    let case = Case::new();
    let m = case.verify(Some(&case.membership()), |_| {}).unwrap();
    let journal = journal_of(&case.pairing);
    store::private_dir(&journal).unwrap();
    PIN_FAULT.with(|f| {
        f.set(Some(store::Injected {
            file: DlFile::State,
            step: store::Step::TempWrite,
        }))
    });
    assert!(pin_at_pairing_locked(&case.pairing, &m, HOST, 2, &case.host_seed, &case.enc).is_err());
    let opened = MembershipHost::open(
        &case.pairing,
        &journal,
        1,
        &case.log.now,
        &mut super::tests::RecFences::default(),
    );
    assert!(opened.is_err(), "leftovers without the list fail closed");
}

/// Re-review N3: `frozen_genesis` lost while its mirror is kept is no
/// "never frozen": the mirror still refuses the frozen genesis (and the
/// other way round).
#[test]
fn a_lost_frozen_genesis_is_vouched_for_by_its_mirror() {
    let frozen = |case: &Case| json!({"v": 1, "genesis": [case.log.genesis_hash().to_hex()]});
    let case = Case::new();
    std::fs::create_dir_all(case.pairing.dir()).unwrap();
    crate::paths::write_test_file(
        &super::frozen_genesis_mirror(&case.pairing),
        frozen(&case).to_string().as_bytes(),
    );
    let e = case.verify(Some(&case.membership()), |_| {}).unwrap_err();
    assert!(e.contains("frozen on this host"), "{e}");
}

/// Re-review N3: an unreadable `frozen_genesis` (or mirror) can't tell
/// which device lists this host froze on: pairing is refused, never read
/// as an empty list.
#[test]
fn an_unreadable_frozen_genesis_refuses_pairing() {
    for damaged in [
        b"{not json".as_slice(),
        b"\xff",
        br#"{"v":1,"genesis":["zz"]}"#,
    ] {
        for mirror in [false, true] {
            let case = Case::new();
            std::fs::create_dir_all(case.pairing.dir()).unwrap();
            let path = if mirror {
                super::frozen_genesis_mirror(&case.pairing)
            } else {
                case.pairing.frozen_genesis.clone()
            };
            crate::paths::write_test_file(&path, damaged);
            let e = case.verify(Some(&case.membership()), |_| {}).unwrap_err();
            assert!(
                e.contains("can't be read") && e.contains("pairing is refused"),
                "{e}"
            );
        }
    }
}

/// Re-review F3: the mirror lives in another directory than
/// `frozen_genesis`, so losing every `frozen_genesis*` file in `pairing/`
/// still refuses the frozen genesis.
#[test]
fn the_frozen_genesis_mirror_survives_the_loss_of_pairings_copy() {
    let case = Case::new();
    let mirror = super::frozen_genesis_mirror(&case.pairing);
    assert_ne!(mirror.parent(), case.pairing.frozen_genesis.parent());
    let frozen = json!({"v": 1, "genesis": [case.log.genesis_hash().to_hex()]}).to_string();
    crate::paths::write_test_file(&case.pairing.frozen_genesis, frozen.as_bytes());
    crate::paths::write_test_file(&mirror, frozen.as_bytes());
    for e in std::fs::read_dir(case.pairing.dir())
        .unwrap()
        .filter_map(Result::ok)
    {
        if e.file_name()
            .to_string_lossy()
            .starts_with("frozen_genesis")
        {
            std::fs::remove_file(e.path()).unwrap();
        }
    }
    let e = case.verify(Some(&case.membership()), |_| {}).unwrap_err();
    assert!(e.contains("frozen on this host"), "{e}");
}

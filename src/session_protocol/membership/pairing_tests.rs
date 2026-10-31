//! The pairing pin (§R9.2 "Pairing"): what a ceremony's device list must
//! hold, and what pinning writes and clears.
use super::pairing::{PairingInputs, pin_at_pairing_locked, unpin_locked, verify_pairing_log};
use super::r9log::{TestLog, secret};
use super::store::{DlFile, Store};
use super::*;
use crate::paths::ProfilePaths;

const HOST: &str = "host-x";

struct Case {
    dir: tempfile::TempDir,
    pairing: PairingPaths,
    log: TestLog,
    mac_secret: [u8; 32],
    host_seed: [u8; 32],
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
        Case {
            dir,
            pairing,
            log,
            mac_secret,
            host_seed,
        }
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
    pin_at_pairing_locked(&case.pairing, &m, HOST, 2, &case.host_seed).unwrap();
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
    // Taken back after a failed verification: nothing r9 is left.
    unpin_locked(&case.pairing);
    assert!(!has_device_list_files(&case.pairing));
    drop(case.dir);
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
    pin_at_pairing_locked(&case.pairing, &m, HOST, 2, &[3; 32]).unwrap();
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
    assert!(pin_at_pairing_locked(&case.pairing, &m, HOST, 2, &case.host_seed).is_err());
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

//! The host encryption key in the device list (delegated host-work design
//! II.4.1, option (b)): the `host_enc_key` entry and the host's `enc_sig`,
//! through the public API the way a host and a managing device drive the
//! verifier. Each test builds its own log with its own software keys.
use atem_client::domain::SignLabel;
use atem_client::encoding::{Hash32, b64u, hex, hex_decode_array};
use atem_client::keys::enc_kid;
use atem_client::membership::{
    Action, Check, Effect, EncKey, Entry, HostEncKeys, HostNow, HostRecord, Invalid, Member,
    MemberKind, Membership, PreviousEncKey, Role, check_body, check_change, draft_on, host_enc_key,
    host_enc_sig_input, sign_entry, sign_host_enc_key, verify_host_enc_sig,
};
use atem_client::{Alg, Error, KeyId, PublicKey, SoftwareKeys};
use serde_json::{Value, json};

const ACCOUNT: &str = "acct-host-enc-key";
const ALL: [Role; 3] = [Role::Control, Role::Manage, Role::View];
const T0: u64 = 1_793_620_800_000;
const HOSTS: [&str; 3] = ["host-a", "host-b", "host-z"];

fn now(wall_ms: u64) -> HostNow {
    HostNow {
        wall_ms,
        mono_ms: wall_ms,
        boot_id: "b".into(),
    }
}

fn auth() -> KeyId {
    KeyId::new("auth")
}

/// The host key of `host_id` at `host_trust_gen` (one per `add_host`).
fn host_key_id(host_id: &str, host_trust_gen: u64) -> KeyId {
    KeyId::new(format!("host:{host_id}:{host_trust_gen}"))
}

fn invalid(reason: Invalid) -> Check {
    Check::Invalid(reason)
}

/// A log on one verifier: `dev-mac` (a native manager, Ed25519) signs
/// every entry. Hosts get their own Ed25519 `host_key` per `add_host`, held
/// in `hosts` with their X25519 encryption keys. Each committed entry is
/// replayed (`assert_replays`).
struct Log {
    m: Membership,
    mac: SoftwareKeys,
    hosts: SoftwareKeys,
    at: u64,
}

impl Log {
    fn new() -> Log {
        let mut mac = SoftwareKeys::new();
        let auth_key = mac.generate(auth(), Alg::Ed25519).unwrap();
        let enc_key = mac.generate(KeyId::new("enc"), Alg::X25519).unwrap();
        let recovery_key = mac.generate(KeyId::new("kit"), Alg::Ed25519).unwrap();
        let body = draft_on(
            ACCOUNT,
            &Hash32([0; 32]),
            1,
            &Hash32([0; 32]),
            "dev-mac",
            T0,
            &Action::Genesis {
                member: Member {
                    device_id: "dev-mac".into(),
                    auth_key,
                    kind: MemberKind::Native {
                        enc_key,
                        roles: ALL.into_iter().collect(),
                    },
                },
                recovery_key,
            },
        );
        let genesis = sign_entry(&mac, &auth(), body).unwrap();
        let m = Membership::from_genesis(ACCOUNT, &genesis.hash(), genesis).unwrap();
        Log {
            m,
            mac,
            hosts: SoftwareKeys::new(),
            at: T0,
        }
    }

    fn genesis(&self) -> Hash32 {
        self.m.genesis_hash()
    }

    /// The next entry, drafted on the head and signed by `dev-mac`.
    fn sign(&self, action: &Action) -> Result<Entry, Invalid> {
        sign_entry(&self.mac, &auth(), self.m.draft("dev-mac", self.at, action))
    }

    fn check(&self, action: &Action) -> Check {
        self.m.check_next(&self.sign(action).unwrap())
    }

    /// Signed, carried and committed as a host does; the effects.
    fn apply(&mut self, action: Action) -> Vec<Effect> {
        self.at += 1;
        let entry = self.sign(&action).unwrap();
        let eval = self
            .m
            .evaluate_objects(&[entry.object().clone()], &now(self.at));
        assert_eq!(eval.stop, None, "{action:?}");
        self.m = eval.next;
        self.assert_replays();
        eval.effects
    }

    /// An `add_host` with a new host key for this generation; its `seq`.
    fn add_host(&mut self, host_id: &str, host_trust_gen: u64) -> u64 {
        let host_key = self
            .hosts
            .generate(host_key_id(host_id, host_trust_gen), Alg::Ed25519)
            .unwrap();
        self.apply(Action::AddHost {
            host: HostRecord {
                host_id: host_id.into(),
                host_trust_gen,
                host_key,
            },
        });
        self.m.head().seq
    }

    fn remove_host(&mut self, host_id: &str) -> u64 {
        self.apply(Action::RemoveHost {
            host_id: host_id.into(),
        });
        self.m.head().seq
    }

    /// A new X25519 key the host keeps as `name`.
    fn enc_key(&mut self, name: &str) -> PublicKey {
        self.hosts
            .generate(KeyId::new(format!("enc:{name}")), Alg::X25519)
            .unwrap()
    }

    /// `enc_sig` by `signer` (a key in `hosts`) over the binding.
    fn enc_sig_by(
        &self,
        signer: &KeyId,
        host_id: &str,
        host_trust_gen: u64,
        enc_key: &PublicKey,
    ) -> Vec<u8> {
        sign_host_enc_key(
            &self.hosts,
            signer,
            ACCOUNT,
            &self.genesis(),
            host_id,
            host_trust_gen,
            enc_key.as_32().unwrap(),
        )
        .unwrap()
    }

    /// The host's own `enc_sig` (its key at that generation).
    fn enc_sig(&self, host_id: &str, host_trust_gen: u64, enc_key: &PublicKey) -> Vec<u8> {
        self.enc_sig_by(
            &host_key_id(host_id, host_trust_gen),
            host_id,
            host_trust_gen,
            enc_key,
        )
    }

    /// A `host_enc_key` the host vouched for.
    fn entry(
        &self,
        host_id: &str,
        host_trust_gen: u64,
        enc_key: &PublicKey,
        retire_previous: bool,
    ) -> Action {
        host_enc_key(
            host_id,
            host_trust_gen,
            enc_key,
            &self.enc_sig(host_id, host_trust_gen, enc_key),
            retire_previous,
            self.at,
        )
        .unwrap()
    }

    /// Commits a `host_enc_key`; its `seq`.
    fn set_key(
        &mut self,
        host_id: &str,
        host_trust_gen: u64,
        enc_key: &PublicKey,
        retire_previous: bool,
    ) -> u64 {
        let action = self.entry(host_id, host_trust_gen, enc_key, retire_previous);
        self.apply(action);
        self.m.head().seq
    }

    fn keys(&self, host_id: &str) -> Option<&HostEncKeys> {
        self.m.host_enc_key(host_id)
    }

    /// The stored form reads back as the same state, and a fresh verifier
    /// of the same entries derives the same keys (both replay them).
    fn assert_replays(&self) {
        let back = Membership::from_stored(ACCOUNT, &self.genesis(), &self.m.to_stored())
            .unwrap_or_else(|e| panic!("stored form refused: {e}"));
        assert_eq!(back, self.m);
        let fresh =
            Membership::verify_chain(ACCOUNT, &self.genesis(), self.m.entries(), &now(self.at))
                .unwrap();
        assert_eq!(fresh.deferred, None);
        for host in HOSTS {
            assert_eq!(fresh.membership.host_enc_key(host), self.keys(host));
        }
    }
}

fn enc_key_of(key: &PublicKey, seq: u64, host_trust_gen: u64) -> EncKey {
    EncKey {
        kid: hex_decode_array(&enc_kid(key).unwrap()).unwrap(),
        key: key.clone(),
        seq,
        host_trust_gen,
    }
}

/// An unsigned body after a placeholder head: the verifier's structural
/// parse only ([`check_body`]).
fn body(fields: Value) -> Value {
    let mut body = json!({
        "type": "atem-membership-entry", "v": 1, "account_id": ACCOUNT,
        "genesis_hash": "ab".repeat(32), "seq": 2, "prev_hash": "cd".repeat(32),
        "signer": "dev-mac", "signed_at": T0,
    });
    body.as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    body
}

/// Parsed as received: the wire bytes `{"body", "sig"}`.
fn parse_wire(body: Value) -> Result<Entry, Invalid> {
    let wire = json!({"body": body, "sig": b64u(&[0u8; 64])});
    Entry::parse_bytes(wire.to_string().as_bytes())
}

fn x25519_json() -> Value {
    json!({"alg": "x25519", "pub": b64u(&[9u8; 32])})
}

fn enc_key_body() -> Value {
    body(
        json!({"action": "host_enc_key", "host_id": "host-a", "host_trust_gen": 1,
                "enc_key": x25519_json(), "enc_sig": b64u(&[7u8; 64])}),
    )
}

#[test]
fn valid_entry_sets_current_key() {
    let mut log = Log::new();
    log.add_host("host-a", 1);
    log.add_host("host-b", 1);
    assert_eq!(log.keys("host-a"), None);
    let k1 = log.enc_key("a1");
    let action = log.entry("host-a", 1, &k1, false);
    assert_eq!(log.check(&action), Check::Valid);
    let effects = log.apply(action);
    let s = log.m.head();
    assert_eq!(
        effects,
        [
            Effect::Appended(s),
            Effect::HostEncKeySet {
                host_id: "host-a".into(),
                retire_previous: false,
            },
        ]
    );
    let keys = log.keys("host-a").unwrap();
    assert_eq!(
        *keys,
        HostEncKeys {
            current: enc_key_of(&k1, s.seq, 1),
            previous: None,
        }
    );
    // The kid is R9.9's `enc_kid`.
    assert_eq!(hex(&keys.current.kid), enc_kid(&k1).unwrap());
    // The binding verifies on its own, with the newest add_host's key.
    let host_key = log.m.host("host-a").unwrap().host_key.clone();
    let sig = log.enc_sig("host-a", 1, &k1);
    assert_eq!(
        verify_host_enc_sig(
            &host_key,
            ACCOUNT,
            &log.genesis(),
            "host-a",
            1,
            k1.as_32().unwrap(),
            &sig
        ),
        Ok(())
    );
    // Only the named host gets a key.
    assert_eq!(log.keys("host-b"), None);
    assert_eq!(log.keys("host-z"), None);
    // The entry changes nothing about the host itself.
    assert_eq!(log.m.host("host-a").unwrap().host_trust_gen, 1);
}

#[test]
fn enc_sig_by_another_key_refused() {
    let mut log = Log::new();
    log.add_host("host-a", 1);
    log.add_host("host-b", 1);
    let k = log.enc_key("a1");
    let refused = |log: &Log, enc_sig: Vec<u8>| {
        let action = host_enc_key("host-a", 1, &k, &enc_sig, false, log.at).unwrap();
        log.check(&action)
    };
    // Another host's key, and an unrelated Ed25519 key.
    let by_b = log.enc_sig_by(&host_key_id("host-b", 1), "host-a", 1, &k);
    assert_eq!(refused(&log, by_b), invalid(Invalid::BadEncSig));
    log.hosts
        .generate(KeyId::new("stranger"), Alg::Ed25519)
        .unwrap();
    let stranger = log.enc_sig_by(&KeyId::new("stranger"), "host-a", 1, &k);
    assert_eq!(refused(&log, stranger), invalid(Invalid::BadEncSig));
    // The manager's own key: the host vouches for its key, not the signer.
    let by_mac = sign_host_enc_key(
        &log.mac,
        &auth(),
        ACCOUNT,
        &log.genesis(),
        "host-a",
        1,
        k.as_32().unwrap(),
    )
    .unwrap();
    assert_eq!(refused(&log, by_mac), invalid(Invalid::BadEncSig));
    // The host's own key over another binding: another host id, account,
    // genesis or key.
    let a1 = host_key_id("host-a", 1);
    let other_host = log.enc_sig_by(&a1, "host-b", 1, &k);
    assert_eq!(refused(&log, other_host), invalid(Invalid::BadEncSig));
    let k2 = log.enc_key("a2");
    let other_key = log.enc_sig_by(&a1, "host-a", 1, &k2);
    assert_eq!(refused(&log, other_key), invalid(Invalid::BadEncSig));
    for (account, genesis) in [("acct-other", log.genesis()), (ACCOUNT, Hash32([5; 32]))] {
        let sig = sign_host_enc_key(
            &log.hosts,
            &a1,
            account,
            &genesis,
            "host-a",
            1,
            k.as_32().unwrap(),
        )
        .unwrap();
        assert_eq!(refused(&log, sig), invalid(Invalid::BadEncSig));
    }
    // A flipped bit.
    let mut flipped = log.enc_sig("host-a", 1, &k);
    flipped[10] ^= 1;
    assert_eq!(refused(&log, flipped), invalid(Invalid::BadEncSig));
    assert_eq!(Invalid::BadEncSig.code(), "bad_enc_sig");
    // The standalone check says the same.
    let host_key = log.m.host("host-a").unwrap().host_key.clone();
    let by_b = log.enc_sig_by(&host_key_id("host-b", 1), "host-a", 1, &k);
    assert_eq!(
        verify_host_enc_sig(
            &host_key,
            ACCOUNT,
            &log.genesis(),
            "host-a",
            1,
            k.as_32().unwrap(),
            &by_b
        ),
        Err(Error::BadSignature)
    );
    // Nothing was set, and the host's own signature is valid.
    assert_eq!(log.keys("host-a"), None);
    let good = log.enc_sig("host-a", 1, &k);
    assert_eq!(refused(&log, good), Check::Valid);
}

#[test]
fn stale_trust_gen_refused() {
    let mut log = Log::new();
    log.add_host("host-a", 1);
    // Re-verified (`atem pair verify`): the newest add_host is gen 2.
    log.add_host("host-a", 2);
    let k = log.enc_key("a");
    // Gen 1, signed by gen 1's own key: no longer the newest.
    let stale = log.entry("host-a", 1, &k, false);
    assert_eq!(log.check(&stale), invalid(Invalid::HostTrustGenNotCurrent));
    assert_eq!(
        Invalid::HostTrustGenNotCurrent.code(),
        "host_trust_gen_not_current"
    );
    // A generation beyond the newest add_host, however it is signed.
    let ahead_sig = log.enc_sig_by(&host_key_id("host-a", 2), "host-a", 3, &k);
    let ahead = host_enc_key("host-a", 3, &k, &ahead_sig, false, log.at).unwrap();
    assert_eq!(log.check(&ahead), invalid(Invalid::HostTrustGenNotCurrent));
    // Gen 2's binding signed by gen 1's (older) key.
    let old_key_sig = log.enc_sig_by(&host_key_id("host-a", 1), "host-a", 2, &k);
    let old_key = host_enc_key("host-a", 2, &k, &old_key_sig, false, log.at).unwrap();
    assert_eq!(log.check(&old_key), invalid(Invalid::BadEncSig));
    // The newest generation with its own key.
    assert_eq!(log.check(&log.entry("host-a", 2, &k, false)), Check::Valid);

    // A host that isn't current: never added, or removed.
    log.add_host("host-b", 1);
    let kb = log.enc_key("b");
    let for_b = log.entry("host-b", 1, &kb, false);
    log.remove_host("host-b");
    assert_eq!(log.check(&for_b), invalid(Invalid::NotAHost));
    let never = host_enc_key("host-z", 1, &kb, &[7u8; 64], false, log.at).unwrap();
    assert_eq!(log.check(&never), invalid(Invalid::NotAHost));
}

#[test]
fn rotation_keeps_previous() {
    let mut log = Log::new();
    log.add_host("host-a", 1);
    let k1 = log.enc_key("1");
    let k2 = log.enc_key("2");
    let k3 = log.enc_key("3");
    let s1 = log.set_key("host-a", 1, &k1, false);
    let s2 = log.set_key("host-a", 1, &k2, false);
    assert_eq!(
        *log.keys("host-a").unwrap(),
        HostEncKeys {
            current: enc_key_of(&k2, s2, 1),
            previous: Some(PreviousEncKey {
                key: enc_key_of(&k1, s1, 1),
                retired: false,
                replaced_at_seq: s2,
            }),
        }
    );
    // One previous key only: the next rotation drops the oldest.
    let s3 = log.set_key("host-a", 1, &k3, false);
    assert_eq!(
        *log.keys("host-a").unwrap(),
        HostEncKeys {
            current: enc_key_of(&k3, s3, 1),
            previous: Some(PreviousEncKey {
                key: enc_key_of(&k2, s2, 1),
                retired: false,
                replaced_at_seq: s3,
            }),
        }
    );
}

#[test]
fn retire_previous_retires_at_once() {
    let mut log = Log::new();
    log.add_host("host-a", 1);
    let k1 = log.enc_key("1");
    let k2 = log.enc_key("2");
    let k3 = log.enc_key("3");
    // Retiring with nothing before it: valid, nothing to retire.
    let s1 = log.set_key("host-a", 1, &k1, true);
    assert_eq!(log.keys("host-a").unwrap().previous, None);
    let rotation = log.entry("host-a", 1, &k2, true);
    // On the wire only when true.
    assert_eq!(
        log.m.draft("dev-mac", log.at, &rotation)["retire_previous"],
        true
    );
    let effects = log.apply(rotation);
    let s2 = log.m.head().seq;
    assert_eq!(
        effects,
        [
            Effect::Appended(log.m.head()),
            Effect::HostEncKeySet {
                host_id: "host-a".into(),
                retire_previous: true,
            },
        ]
    );
    assert_eq!(
        *log.keys("host-a").unwrap(),
        HostEncKeys {
            current: enc_key_of(&k2, s2, 1),
            previous: Some(PreviousEncKey {
                key: enc_key_of(&k1, s1, 1),
                retired: true,
                replaced_at_seq: s2,
            }),
        }
    );
    // A routine rotation after it keeps k2 (not retired); k1 is gone.
    let s3 = log.set_key("host-a", 1, &k3, false);
    assert_eq!(
        log.keys("host-a").unwrap().previous,
        Some(PreviousEncKey {
            key: enc_key_of(&k2, s2, 1),
            retired: false,
            replaced_at_seq: s3,
        })
    );
}

#[test]
fn newer_add_host_voids_keys() {
    let mut log = Log::new();
    log.add_host("host-a", 1);
    log.add_host("host-b", 1);
    let k1 = log.enc_key("1");
    let k2 = log.enc_key("2");
    let kb = log.enc_key("b");
    log.set_key("host-a", 1, &k1, false);
    log.set_key("host-a", 1, &k2, false);
    let sb = log.set_key("host-b", 1, &kb, false);
    // Re-verification voids both keys of that host only.
    let effects = {
        let host_key = log
            .hosts
            .generate(host_key_id("host-a", 2), Alg::Ed25519)
            .unwrap();
        log.apply(Action::AddHost {
            host: HostRecord {
                host_id: "host-a".into(),
                host_trust_gen: 2,
                host_key,
            },
        })
    };
    assert_eq!(
        effects,
        [
            Effect::Appended(log.m.head()),
            Effect::HostKeyChanged {
                host_id: "host-a".into()
            },
        ]
    );
    assert_eq!(log.keys("host-a"), None);
    assert_eq!(log.keys("host-b").unwrap().current, enc_key_of(&kb, sb, 1));
    // Until a new entry for the new generation: no previous key carries over.
    let k3 = log.enc_key("3");
    let s3 = log.set_key("host-a", 2, &k3, false);
    assert_eq!(
        *log.keys("host-a").unwrap(),
        HostEncKeys {
            current: enc_key_of(&k3, s3, 2),
            previous: None,
        }
    );
    // A removal voids them too, and a re-add starts with none.
    log.remove_host("host-a");
    assert_eq!(log.keys("host-a"), None);
    log.add_host("host-a", 3);
    assert_eq!(log.keys("host-a"), None);
    assert_eq!(log.keys("host-b").unwrap().current, enc_key_of(&kb, sb, 1));
}

#[test]
fn non_x25519_refused() {
    let mut log = Log::new();
    log.add_host("host-a", 1);
    let ed = log.hosts.generate(KeyId::new("ed"), Alg::Ed25519).unwrap();
    let p256 = log.hosts.generate(KeyId::new("p"), Alg::P256).unwrap();
    for key in [&ed, &p256] {
        // On the wire: the field is pinned to x25519.
        let mut b = enc_key_body();
        b["enc_key"] = key.to_json();
        assert_eq!(
            check_body(&b).map(|e| e.action),
            Err(Invalid::WrongAlg),
            "{key:?}"
        );
        // The builder refuses what the verifier refuses.
        assert_eq!(
            host_enc_key("host-a", 1, key, &[7u8; 64], false, T0),
            Err(Invalid::WrongAlg)
        );
    }
    // The host signs only with its Ed25519 host key: never with an X25519
    // or a P-256 key.
    let x = log.enc_key("x");
    for signer in [KeyId::new("enc:x"), KeyId::new("p")] {
        assert_eq!(
            sign_host_enc_key(
                &log.hosts,
                &signer,
                ACCOUNT,
                &log.genesis(),
                "host-a",
                1,
                x.as_32().unwrap()
            ),
            Err(Error::WrongAlg),
            "{signer:?}"
        );
    }
    // And verifies only with one.
    for host_key in [&x, &p256] {
        assert_eq!(
            verify_host_enc_sig(
                host_key,
                ACCOUNT,
                &log.genesis(),
                "host-a",
                1,
                x.as_32().unwrap(),
                &[7u8; 64]
            ),
            Err(Error::WrongAlg)
        );
    }
}

#[test]
fn enc_sig_length_refused() {
    for len in [0, 32, 63, 65, 128] {
        let mut b = enc_key_body();
        b["enc_sig"] = json!(b64u(&vec![7u8; len]));
        assert_eq!(
            check_body(&b).map(|e| e.action),
            Err(Invalid::Malformed("enc_sig")),
            "{len}"
        );
        let key = PublicKey::new(Alg::X25519, &[9u8; 32]).unwrap();
        assert_eq!(
            host_enc_key("host-a", 1, &key, &vec![7u8; len], false, T0),
            Err(Invalid::Malformed("enc_sig")),
            "{len}"
        );
    }
    // Not base64url without padding, or not a string.
    let padded = format!("{}=", b64u(&[7u8; 64]));
    for value in [json!(padded), json!("+".repeat(86)), json!(7), json!({})] {
        let mut b = enc_key_body();
        b["enc_sig"] = value.clone();
        assert_eq!(
            check_body(&b).map(|e| e.action),
            Err(Invalid::Malformed("enc_sig")),
            "{value}"
        );
    }
    // 64 bytes is the shape.
    assert!(check_body(&enc_key_body()).is_ok());
}

#[test]
fn signing_input_layout() {
    let genesis = Hash32([0x5a; 32]);
    let enc_pub = [0x11u8; 32];
    let input = host_enc_sig_input("acct-1", &genesis, "host-a", 3, &enc_pub);
    assert_eq!(input.label(), SignLabel::HostEncKey);
    assert_eq!(SignLabel::HostEncKey.as_str(), "atem-host-enc-key-v1");
    // Not a body type: nothing signs a body with it.
    assert_eq!(SignLabel::of_body_type("atem-host-enc-key"), None);
    // enc(["atem-host-enc-key-v1", account_id, genesis_hash (32 raw bytes),
    // host_id, u64(host_trust_gen), enc_pub]), built by hand.
    let mut expected = Vec::new();
    let mut field = |bytes: &[u8]| {
        expected.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        expected.extend_from_slice(bytes);
    };
    field(b"atem-host-enc-key-v1");
    field(b"acct-1");
    field(&[0x5a; 32]);
    field(b"host-a");
    field(&[0, 0, 0, 0, 0, 0, 0, 3]);
    field(&[0x11; 32]);
    assert_eq!(input.as_bytes(), expected.as_slice());
    assert_eq!(&expected[..4], &[0, 0, 0, 20]);

    // `enc_sig` is pure Ed25519 by `host_key` over exactly these bytes.
    let mut keys = SoftwareKeys::new();
    let host_key = keys.generate(KeyId::new("h"), Alg::Ed25519).unwrap();
    let sig = sign_host_enc_key(
        &keys,
        &KeyId::new("h"),
        "acct-1",
        &genesis,
        "host-a",
        3,
        &enc_pub,
    )
    .unwrap();
    assert_eq!(sig.len(), 64);
    assert_eq!(host_key.verify_raw(&expected, &sig), Ok(()));
    assert_eq!(
        verify_host_enc_sig(&host_key, "acct-1", &genesis, "host-a", 3, &enc_pub, &sig),
        Ok(())
    );
    // Each field counts.
    assert_eq!(
        verify_host_enc_sig(&host_key, "acct-1", &genesis, "host-a", 4, &enc_pub, &sig),
        Err(Error::BadSignature)
    );
}

#[test]
fn host_enc_key_entries_parse_strictly() {
    assert!(check_body(&enc_key_body()).is_ok());
    // Unknown fields: beside them, or another action's.
    for (field, value) in [
        ("note", json!("x")),
        ("interrupt_running", json!(false)),
        ("host", json!({})),
        ("enc_kid", json!("00".repeat(8))),
    ] {
        let mut b = enc_key_body();
        b[field] = value;
        assert_eq!(
            check_body(&b).map(|e| e.action),
            Err(Invalid::UnknownField),
            "{field}"
        );
    }
    // Every field but `retire_previous` is required, and none is `null`.
    for field in ["host_id", "host_trust_gen", "enc_key", "enc_sig"] {
        let mut missing = enc_key_body();
        missing.as_object_mut().unwrap().remove(field);
        assert_eq!(
            check_body(&missing).map(|e| e.action),
            Err(Invalid::Malformed(field)),
            "{field}"
        );
    }
    for field in [
        "host_id",
        "host_trust_gen",
        "enc_key",
        "enc_sig",
        "retire_previous",
    ] {
        let mut null = enc_key_body();
        null[field] = Value::Null;
        assert_eq!(
            parse_wire(null).map(|e| e.action),
            Err(Invalid::Malformed("null")),
            "{field}"
        );
    }
    // `retire_previous`: absent means false; present it is `true` (absent
    // fields are omitted, R9.1, so `false` has one form only).
    let parsed = check_body(&enc_key_body()).unwrap().action;
    assert!(matches!(
        parsed,
        Action::HostEncKey {
            retire_previous: false,
            ..
        }
    ));
    let mut b = enc_key_body();
    b["retire_previous"] = json!(true);
    assert!(matches!(
        check_body(&b).unwrap().action,
        Action::HostEncKey {
            retire_previous: true,
            ..
        }
    ));
    for value in [json!(false), json!("true"), json!(1), json!({})] {
        let mut b = enc_key_body();
        b["retire_previous"] = value.clone();
        assert_eq!(
            check_body(&b).map(|e| e.action),
            Err(Invalid::Malformed("retire_previous")),
            "{value}"
        );
    }
    // A generation is at least 1, an id is an id, a key a key object.
    for value in [json!(0), json!(-1), json!("1"), json!(true)] {
        let mut b = enc_key_body();
        b["host_trust_gen"] = value.clone();
        assert_eq!(
            check_body(&b).map(|e| e.action),
            Err(Invalid::Malformed("host_trust_gen")),
            "{value}"
        );
    }
    for value in [json!(7), json!(""), json!("host a"), json!("h".repeat(129))] {
        let mut b = enc_key_body();
        b["host_id"] = value.clone();
        assert_eq!(
            check_body(&b).map(|e| e.action),
            Err(Invalid::Malformed("host_id")),
            "{value}"
        );
    }
    let mut b = enc_key_body();
    b["enc_key"] = json!({"alg": "x25519", "pub": b64u(&[9u8; 31])});
    assert_eq!(check_body(&b).map(|e| e.action), Err(Invalid::BadKey));
    let mut b = enc_key_body();
    b["enc_key"] = json!({"alg": "x25519", "pub": b64u(&[9u8; 32]), "kid": "x"});
    assert!(check_body(&b).is_err());
    // The builders refuse what the verifier refuses.
    let key = PublicKey::new(Alg::X25519, &[9u8; 32]).unwrap();
    assert_eq!(
        host_enc_key("host a", 1, &key, &[7u8; 64], false, T0),
        Err(Invalid::Malformed("host_id"))
    );
    assert_eq!(
        host_enc_key("host-a", 0, &key, &[7u8; 64], false, T0),
        Err(Invalid::Malformed("host_trust_gen"))
    );
}

#[test]
fn host_enc_key_needs_a_native_manager() {
    let mut log = Log::new();
    log.add_host("host-a", 1);
    let k = log.enc_key("a");
    let action = log.entry("host-a", 1, &k, false);
    let mut phone_keys = SoftwareKeys::new();
    let phone = Member {
        device_id: "dev-phone".into(),
        auth_key: phone_keys.generate(auth(), Alg::Ed25519).unwrap(),
        kind: MemberKind::Native {
            enc_key: phone_keys.generate(KeyId::new("enc"), Alg::X25519).unwrap(),
            roles: [Role::Control, Role::View].into(),
        },
    };
    log.apply(Action::Add { member: phone });
    // A native member without `manage`.
    let body = log.m.draft("dev-phone", log.at, &action);
    let entry = sign_entry(&phone_keys, &auth(), body).unwrap();
    assert_eq!(log.m.check_next(&entry), invalid(Invalid::SignerNotManager));
    // The host itself can't sign the entry: it is no member.
    let body = log.m.draft("host-a", log.at, &action);
    let entry = sign_entry(&log.hosts, &host_key_id("host-a", 1), body).unwrap();
    assert_eq!(log.m.check_next(&entry), invalid(Invalid::SignerNotManager));
    // The recovery key signs only `recovery_add`.
    let mut by_kit = enc_key_body();
    by_kit["signer"] = json!("recovery");
    assert_eq!(
        check_body(&by_kit).map(|e| e.action),
        Err(Invalid::RecoverySignerAction)
    );
    // The manager may.
    assert_eq!(log.check(&action), Check::Valid);
}

#[test]
fn draft_round_trips_through_check_body() {
    let mut log = Log::new();
    log.add_host("host-a", 1);
    let k = log.enc_key("a");
    let sig = log.enc_sig("host-a", 1, &k);
    let action = host_enc_key("host-a", 1, &k, &sig, false, T0).unwrap();
    assert_eq!(
        action,
        Action::HostEncKey {
            host_id: "host-a".into(),
            host_trust_gen: 1,
            enc_key: k.clone(),
            enc_sig: sig.clone(),
            retire_previous: false,
        }
    );
    let body = log.m.draft("dev-mac", T0, &action);
    assert_eq!(body["action"], "host_enc_key");
    assert_eq!(body["host_id"], "host-a");
    assert_eq!(body["host_trust_gen"], 1);
    assert_eq!(body["enc_key"], k.to_json());
    assert_eq!(body["enc_sig"], b64u(&sig));
    // `retire_previous` is omitted when false.
    assert_eq!(body.get("retire_previous"), None);
    assert_eq!(body.as_object().unwrap().len(), 13);
    assert_eq!(check_body(&body).unwrap().action, action);
    let entry = log.sign(&action).unwrap();
    assert_eq!(entry.action, action);
    assert_eq!(entry.subject(), None);
    let again = Entry::parse_bytes(entry.object().to_json().to_string().as_bytes()).unwrap();
    assert_eq!(again, entry);
    let retiring = host_enc_key("host-a", 1, &k, &sig, true, T0).unwrap();
    let body = log.m.draft("dev-mac", T0, &retiring);
    assert_eq!(body["retire_previous"], true);
    assert_eq!(body.as_object().unwrap().len(), 14);
    assert_eq!(check_body(&body).unwrap().action, retiring);
    assert_eq!(action.name(), "host_enc_key");
    assert!(!action.is_pending_type());
}

#[test]
fn check_change_never_paces_host_enc_key() {
    let mut log = Log::new();
    log.add_host("host-a", 1);
    let k1 = log.enc_key("1");
    let k2 = log.enc_key("2");
    let first = log.entry("host-a", 1, &k1, false);
    assert_eq!(check_change(&log.m, &first, log.at), Ok(()));
    log.apply(first);
    // A rotation right after, routine or retiring: one entry each.
    for retire in [false, true] {
        let rotation = log.entry("host-a", 1, &k2, retire);
        assert_eq!(check_change(&log.m, &rotation, log.at), Ok(()));
    }
    // Advisory only: the verifier judges the entry itself.
    let never = host_enc_key("host-z", 1, &k2, &[7u8; 64], false, log.at).unwrap();
    assert_eq!(check_change(&log.m, &never, log.at), Ok(()));
}

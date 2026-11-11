//! The five device-list actions of delegated host work through the
//! bindings (`project_set`, `project_remove`, `host_sender_revoke`,
//! `host_sender_readmit`, `host_enc_key`): the builders return action JSON
//! the verifier takes (`draft_entry`, `check_change`), the log's queries
//! read the derived state the shared vectors' `expect` writes down, and the
//! signing purposes name what a manager is asked to confirm.
//!
//! The vectors are `designs/protocol/fixtures/r9-vectors-membership-log.json`
//! (`others`: `P*`, `EK*`, `HS*`): each has the `chain` of labels it
//! follows on log L, `expect` (valid) or `valid: false` and `reason`.
#![cfg(feature = "uniffi")]

#[path = "../../atem-client/tests/support/mod.rs"]
#[allow(unused_imports)]
mod support;

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use atem_client::KeyProvider as _;
use atem_client::provider::KeyId;
use atem_client_ffi::AtemError;
use atem_client_ffi::host_actions::{
    host_enc_key_action, host_sender_readmit_action, host_sender_revoke_action,
    project_remove_action, project_set_action, verify_host_enc_sig,
};
use atem_client_ffi::log::MembershipLog;
use atem_client_ffi::provider::{AppKeyProvider, ProviderError};
use atem_client_ffi::publish::EntryPublisher;
use atem_client_ffi::types::{
    CarriageStop, ChangeRefusalInfo, HostClock, HostSenderStateInfo, KeyAlg, MembershipEffect,
    PublicKeyData, PublishOutcome, SignRequest, SigningPurpose,
};
use serde_json::Value;
use support::*;

const WALL: u64 = 1_793_264_001_000;
const L: [&str; 6] = ["E1", "E2", "E3", "E4", "E5", "E6"];
const FIVE: [&str; 5] = [
    "project_set",
    "project_remove",
    "host_sender_revoke",
    "host_sender_readmit",
    "host_enc_key",
];

fn now() -> HostClock {
    HostClock {
        wall_ms: WALL,
        mono_ms: 1_000,
        boot_id: "boot-1".into(),
    }
}

fn wire(v: &Vectors, label: &str) -> String {
    v.object(label).to_json().to_string()
}

fn wires(v: &Vectors, labels: &[&str]) -> Vec<String> {
    labels.iter().map(|l| wire(v, l)).collect()
}

/// Log L, then the labels of a vector's `chain`.
fn log_after(v: &Vectors, chain: &[&str]) -> Arc<MembershipLog> {
    let log = MembershipLog::verify(ACCOUNT.into(), genesis_hash().to_hex(), wires(v, &L), now())
        .unwrap();
    let result = log.extend(wires(v, chain), now()).unwrap();
    assert_eq!(result.stop, None, "{chain:?}");
    log
}

fn chain_of(vector: &Value) -> Vec<String> {
    vector["chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap().to_owned())
        .collect()
}

fn strs(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap().to_owned())
        .collect()
}

fn x25519(b64u: &str) -> PublicKeyData {
    PublicKeyData {
        alg: KeyAlg::X25519,
        raw: atem_client::encoding::b64u_decode(b64u).unwrap(),
    }
}

/// The vectors of the delegated host-work families (`P*`, `EK*`, `HS*`:
/// each has a `chain`): valid ones with `expect`, refused ones with
/// `valid: false` and `reason`. Some are `add_host` / `remove_host` entries
/// that set up (or end) a host's membership.
fn delegated_vectors(v: &Vectors) -> Vec<&Value> {
    v.file["others"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|vector| vector.get("chain").is_some())
        .collect()
}

fn is_five(vector: &Value) -> bool {
    FIVE.contains(
        &vector["entry"]["body"]["action"]
            .as_str()
            .unwrap_or_default(),
    )
}

/// The builder's action JSON for a vector's body; `None` for a body the
/// builder can't write (`retire_previous: false` has one form, omitted).
fn built(body: &Value) -> Option<Result<String, AtemError>> {
    let at = body["signed_at"].as_u64().unwrap();
    Some(match body["action"].as_str().unwrap() {
        "project_set" => project_set_action(
            body["project"]["name"].as_str().unwrap().into(),
            strs(&body["project"]["hosts"]),
            strs(&body["project"]["ops"]),
            at,
        ),
        "project_remove" => project_remove_action(body["name"].as_str().unwrap().into(), at),
        "host_sender_revoke" => host_sender_revoke_action(
            body["host_id"].as_str().unwrap().into(),
            body["interrupt_running"].as_bool().unwrap(),
            at,
        ),
        "host_sender_readmit" => {
            host_sender_readmit_action(body["host_id"].as_str().unwrap().into(), at)
        }
        "host_enc_key" => {
            if body.get("retire_previous") == Some(&Value::Bool(false)) {
                return None;
            }
            host_enc_key_action(
                body["host_id"].as_str().unwrap().into(),
                body["host_trust_gen"].as_u64().unwrap(),
                x25519(body["enc_key"]["pub"].as_str().unwrap()),
                body["enc_sig"].as_str().unwrap().into(),
                body.get("retire_previous") == Some(&Value::Bool(true)),
                at,
            )
        }
        other => panic!("{other}"),
    })
}

fn detail(e: &AtemError) -> String {
    match e {
        AtemError::Membership { detail, .. } => detail.clone(),
        other => other.code(),
    }
}

/// Every vector's body, rebuilt by the builder, is what `draft_entry` makes
/// on the vector's chain (`jcs`, byte for byte); `check_change` agrees with
/// the verifier on the redundant revoke and readmit; a shape the verifier
/// refuses on its own is refused by the builder with its detail.
#[test]
fn every_builder_goes_through_draft_entry_and_check_change() {
    let v = Vectors::load();
    let mut built_ok = 0;
    for vector in delegated_vectors(&v).into_iter().filter(|x| is_five(x)) {
        let label = vector["label"].as_str().unwrap();
        let body = &vector["entry"]["body"];
        let chain = chain_of(vector);
        let chain: Vec<&str> = chain.iter().map(String::as_str).collect();
        let log = log_after(&v, &chain);
        let reason = vector.get("reason").and_then(Value::as_str);
        let Some(action) = built(body) else {
            // Not expressible by a builder: `malformed`, from the strict parse.
            assert_eq!(label, "EK8_retire_false");
            continue;
        };
        let action = match action {
            Ok(action) => action,
            Err(e) => {
                // A shape the verifier refuses by itself: the builder says so.
                assert_eq!(Some(detail(&e).as_str()), reason, "{label}: {e:?}");
                assert_eq!(e.code(), "membership_invalid", "{label}");
                assert!(
                    ["bad_project", "malformed"].contains(&detail(&e).as_str()),
                    "{label}"
                );
                continue;
            }
        };
        built_ok += 1;
        let signed_at = body["signed_at"].as_u64().unwrap();
        assert_eq!(
            log.draft_entry("dev-mac".into(), signed_at, action.clone())
                .unwrap(),
            vector["jcs"].as_str().unwrap(),
            "{label}"
        );
        let advice = log.check_change(action, signed_at).unwrap();
        let want = match reason {
            Some("already_revoked") => Some(ChangeRefusalInfo::AlreadyRevoked),
            Some("not_revoked") => Some(ChangeRefusalInfo::NotRevoked),
            _ => None,
        };
        assert_eq!(advice, want, "{label}");
    }
    // Every five-action vector reproduces through its builder, but
    // EK8_retire_false (no builder writes `retire_previous: false`) and the
    // three shapes the builder itself refuses (P9_bad_name, P9_one_host,
    // P9_unknown_op).
    assert!(built_ok >= 28, "{built_ok}");
}

/// What the vectors' `expect` writes down, read through the queries.
fn state_of(log: &MembershipLog) -> Value {
    let mut hosts = serde_json::Map::new();
    let mut senders = serde_json::Map::new();
    let mut keys = serde_json::Map::new();
    for host in ["host-a", "host-b"] {
        if let Some(h) = log.host(host.into()) {
            hosts.insert(host.into(), h.host_trust_gen.into());
        }
        if let Some(state) = log.host_sender_state(host.into()) {
            let (name, seq) = match state {
                HostSenderStateInfo::Authorized { generation } => ("authorized", generation),
                HostSenderStateInfo::Revoked { seq } => ("revoked", seq),
            };
            let mut entry = serde_json::Map::new();
            entry.insert("state".into(), name.into());
            entry.insert("seq".into(), seq.into());
            if let Some(epoch) = log.host_membership_epoch(host.into()) {
                entry.insert("membership_epoch".into(), epoch.into());
            }
            senders.insert(host.into(), Value::Object(entry));
        } else {
            assert_eq!(log.host_membership_epoch(host.into()), None);
        }
        if let Some(k) = log.host_enc_key(host.into()) {
            let key = |k: &atem_client_ffi::types::HostEncKeyInfo| {
                assert_eq!(k.key.alg, KeyAlg::X25519);
                serde_json::json!({
                    "enc_kid": k.enc_kid,
                    "pub": atem_client::encoding::b64u(&k.key.raw),
                    "seq": k.seq,
                    "host_trust_gen": k.host_trust_gen,
                })
            };
            let mut entry = serde_json::Map::new();
            entry.insert("current".into(), key(&k.current));
            if let Some(p) = &k.previous {
                let mut previous = key(&p.key);
                previous["retired"] = p.retired.into();
                previous["replaced_at_seq"] = p.replaced_at_seq.into();
                entry.insert("previous".into(), previous);
            }
            keys.insert(host.into(), Value::Object(entry));
        }
    }
    let projects: serde_json::Map<String, Value> = log
        .projects()
        .into_iter()
        .map(|p| {
            (
                p.name,
                serde_json::json!({"hosts": p.hosts, "members": p.members, "ops": p.ops}),
            )
        })
        .collect();
    serde_json::json!({
        "hosts": hosts,
        "projects": projects,
        "host_senders": senders,
        "host_enc_keys": keys,
    })
}

/// `project_ops_between` is the union of the ops of every project both hosts
/// are in effect members of, and empty for a host with itself.
fn union_between(expect: &Value, a: &str, b: &str) -> Vec<String> {
    if a == b {
        return Vec::new();
    }
    let member = |p: &Value, h: &str| strs(&p["members"]).iter().any(|m| m == h);
    let mut ops = BTreeSet::new();
    for project in expect["projects"].as_object().unwrap().values() {
        if member(project, a) && member(project, b) {
            ops.extend(strs(&project["ops"]));
        }
    }
    ops.into_iter().collect()
}

/// A valid vector applies on its chain and the queries read its `expect`;
/// a refused one stops with its `reason`.
#[test]
fn the_queries_read_the_vectors_expect_and_refusals_carry_their_reason() {
    let v = Vectors::load();
    let mut valid = 0;
    let mut refused = 0;
    for vector in delegated_vectors(&v) {
        let label = vector["label"].as_str().unwrap();
        let chain = chain_of(vector);
        let chain: Vec<&str> = chain.iter().map(String::as_str).collect();
        let log = log_after(&v, &chain);
        let entry = wire(&v, label);
        if vector.get("valid") == Some(&Value::Bool(false)) {
            refused += 1;
            let result = log.evaluate(vec![entry], now()).unwrap();
            let reason = vector["reason"].as_str().unwrap();
            assert_eq!(
                result.stop,
                Some(CarriageStop::Invalid {
                    index: 0,
                    code: reason.into()
                }),
                "{label}"
            );
            assert_eq!(result.appended, 0, "{label}");
            continue;
        }
        valid += 1;
        let result = log.extend(vec![entry], now()).unwrap();
        assert_eq!(result.stop, None, "{label}");
        assert_eq!(result.appended, 1, "{label}");
        let expect = &vector["expect"];
        assert_eq!(state_of(&log), *expect, "{label}");
        for (a, b) in [
            ("host-a", "host-b"),
            ("host-b", "host-a"),
            ("host-a", "host-a"),
        ] {
            assert_eq!(
                log.project_ops_between(a.into(), b.into()),
                union_between(expect, a, b),
                "{label}: {a} {b}"
            );
        }
        for host in ["host-a", "host-b"] {
            let projects: Vec<String> = expect["projects"]
                .as_object()
                .unwrap()
                .iter()
                .filter(|(_, p)| strs(&p["members"]).iter().any(|m| m == host))
                .map(|(name, _)| name.clone())
                .collect();
            assert_eq!(log.host_projects(host.into()), projects, "{label}: {host}");
        }
    }
    assert!(
        valid >= 28 && refused >= 17,
        "{valid} valid, {refused} refused"
    );
}

#[test]
fn the_effects_name_what_step_4_replays() {
    let v = Vectors::load();
    let effects = |label: &str| {
        let chain = chain_of(v.vector(label));
        let chain: Vec<&str> = chain.iter().map(String::as_str).collect();
        let r = log_after(&v, &chain)
            .evaluate(vec![wire(&v, label)], now())
            .unwrap();
        assert_eq!(r.stop, None, "{label}");
        r.effects
    };
    assert!(effects("P8_set").contains(&MembershipEffect::ProjectSet {
        name: "astation".into()
    }));
    assert!(
        effects("P10_remove").contains(&MembershipEffect::ProjectRemoved {
            name: "astation".into()
        })
    );
    assert!(
        effects("HS7_revoke").contains(&MembershipEffect::HostSenderRevoked {
            host_id: "host-a".into(),
            seq: 7,
            interrupt_running: false,
        })
    );
    assert!(
        effects("HS8_readmit").contains(&MembershipEffect::HostSenderReadmitted {
            host_id: "host-a".into(),
            seq: 8,
        })
    );
    assert!(
        effects("EK9_rotate_retire").contains(&MembershipEffect::HostEncKeySet {
            host_id: "host-a".into(),
            retire_previous: true,
        })
    );
}

/// The builders refuse what the verifier refuses on its own, with its detail
/// (`bad_project`, `malformed`, `wrong_alg`), and nothing is drafted.
#[test]
fn the_builders_refuse_shapes_the_verifier_refuses() {
    let ops = |o: &[&str]| o.iter().map(|s| s.to_string()).collect::<Vec<_>>();
    let two = || vec!["host-a".to_owned(), "host-b".to_owned()];
    let bad = |r: Result<String, AtemError>, want: &str| {
        let e = r.unwrap_err();
        assert_eq!(e.code(), "membership_invalid", "{e:?}");
        assert_eq!(detail(&e), want, "{e:?}");
    };
    bad(
        project_set_action("astation".into(), two(), ops(&["deploy"]), 1),
        "bad_project",
    );
    bad(
        project_set_action("astation".into(), two(), ops(&[]), 1),
        "bad_project",
    );
    bad(
        project_set_action(
            "astation".into(),
            vec!["host-a".into()],
            ops(&["message"]),
            1,
        ),
        "bad_project",
    );
    bad(
        project_set_action("Astation".into(), two(), ops(&["message"]), 1),
        "bad_project",
    );
    bad(
        project_set_action("astation".into(), two(), ops(&["notify", "prompt"]), 1),
        "bad_project",
    );
    bad(project_remove_action("Bad Name".into(), 1), "bad_project");
    bad(
        host_sender_revoke_action("Not an id".into(), false, 1),
        "malformed",
    );
    bad(host_sender_readmit_action("".into(), 1), "malformed");
    // `enc_key` is X25519; `enc_sig` is 64 bytes of strict base64url.
    let v = Vectors::load();
    let body = &v.wire("EK7_set")["body"];
    let key = x25519(body["enc_key"]["pub"].as_str().unwrap());
    let sig = body["enc_sig"].as_str().unwrap().to_owned();
    let book = Book::load();
    for wrong in [
        PublicKeyData::from(&book.public("host-a/host_key")),
        PublicKeyData::from(&book.public("dev-mac/auth")),
    ] {
        assert_eq!(
            host_enc_key_action("host-a".into(), 1, wrong, sig.clone(), false, 1)
                .map_err(|e| detail(&e))
                .unwrap_err(),
            "wrong_alg"
        );
    }
    for bad_sig in ["", "AAAA", &format!("{sig}="), &sig[1..]] {
        let e = host_enc_key_action("host-a".into(), 1, key.clone(), bad_sig.into(), false, 1)
            .unwrap_err();
        assert!(
            matches!(e.code().as_str(), "malformed" | "membership_invalid")
                || matches!(e, AtemError::Invalid { .. }),
            "{bad_sig}: {e:?}"
        );
    }
    // A time above 2^53 - 1 is outside the canonical domain.
    assert_eq!(
        host_sender_readmit_action("host-a".into(), 1 << 53)
            .unwrap_err()
            .code(),
        "not_canonical"
    );
    assert_eq!(
        host_enc_key_action("host-a".into(), 1 << 53, key, sig, false, 1)
            .unwrap_err()
            .code(),
        "not_canonical"
    );
}

/// The host's `enc_sig` is checked with the host's own key, the account, the
/// genesis, the host id, the generation and the key: any other value is
/// false, and so is a key that can't be one.
#[test]
fn verify_host_enc_sig_binds_every_field() {
    let book = Book::load();
    let v = Vectors::load();
    let host_key = |name: &str| PublicKeyData {
        alg: KeyAlg::Ed25519,
        raw: hex_to_bytes(book.keys[name]["host_key"]["pub_hex"].as_str().unwrap()),
    };
    let genesis = genesis_hash().to_hex();
    let body = &v.wire("EK7_set")["body"];
    let key = x25519(body["enc_key"]["pub"].as_str().unwrap());
    let sig = body["enc_sig"].as_str().unwrap().to_owned();
    let check = |host: &PublicKeyData,
                 account: &str,
                 genesis: &str,
                 host_id: &str,
                 gen_: u64,
                 key: &PublicKeyData,
                 sig: &str| {
        verify_host_enc_sig(
            host.clone(),
            account.into(),
            genesis.into(),
            host_id.into(),
            gen_,
            key.clone(),
            sig.into(),
        )
    };
    let a = host_key("host-a");
    assert!(check(&a, ACCOUNT, &genesis, "host-a", 1, &key, &sig));
    // Every field is bound.
    assert!(!check(
        &host_key("host-b"),
        ACCOUNT,
        &genesis,
        "host-a",
        1,
        &key,
        &sig
    ));
    assert!(!check(&a, "acct-other", &genesis, "host-a", 1, &key, &sig));
    assert!(!check(
        &a,
        ACCOUNT,
        &"0".repeat(64),
        "host-a",
        1,
        &key,
        &sig
    ));
    assert!(!check(&a, ACCOUNT, &genesis, "host-b", 1, &key, &sig));
    assert!(!check(&a, ACCOUNT, &genesis, "host-a", 2, &key, &sig));
    let other = x25519(
        v.wire("EK8_rotate")["body"]["enc_key"]["pub"]
            .as_str()
            .unwrap(),
    );
    assert!(!check(&a, ACCOUNT, &genesis, "host-a", 1, &other, &sig));
    // Another binding's signature (EK8_bad_enc_sig carries EK7_set's).
    let bad = v.wire("EK8_bad_enc_sig")["body"].clone();
    assert!(!check(
        &a,
        ACCOUNT,
        &genesis,
        "host-a",
        1,
        &x25519(bad["enc_key"]["pub"].as_str().unwrap()),
        bad["enc_sig"].as_str().unwrap()
    ));
    // Not keys, not hashes, not signatures: false, never a panic.
    let p256 = PublicKeyData {
        alg: KeyAlg::P256,
        raw: hex_to_bytes(book.keys["dev-mac"]["auth"]["pub_hex"].as_str().unwrap()),
    };
    assert!(!check(&p256, ACCOUNT, &genesis, "host-a", 1, &key, &sig));
    let ed_as_enc = PublicKeyData {
        alg: KeyAlg::Ed25519,
        raw: key.raw.clone(),
    };
    assert!(!check(&a, ACCOUNT, &genesis, "host-a", 1, &ed_as_enc, &sig));
    assert!(!check(&a, ACCOUNT, "not hex", "host-a", 1, &key, &sig));
    assert!(!check(
        &a,
        ACCOUNT,
        &genesis,
        "host-a",
        1,
        &key,
        "not base64url!"
    ));
    assert!(!check(&a, ACCOUNT, &genesis, "host-a", 1, &key, "AAAA"));
    // Every enc_sig of the vectors verifies with the host key of its generation
    // except the one that is bad.
    for vector in delegated_vectors(&v) {
        let body = &vector["entry"]["body"];
        if body["action"] != "host_enc_key" {
            continue;
        }
        let label = vector["label"].as_str().unwrap();
        let host_id = body["host_id"].as_str().unwrap();
        let gen_ = body["host_trust_gen"].as_u64().unwrap();
        let name = if gen_ == 1 {
            host_id.to_owned()
        } else {
            format!("{host_id}-gen-{gen_}")
        };
        let ok = check(
            &host_key(&name),
            ACCOUNT,
            &genesis,
            host_id,
            gen_,
            &x25519(body["enc_key"]["pub"].as_str().unwrap()),
            body["enc_sig"].as_str().unwrap(),
        );
        assert_eq!(ok, label != "EK8_bad_enc_sig", "{label}");
    }
}

fn hex_to_bytes(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

/// A provider that records every request and signs entries with the test
/// book's keys.
struct Recorder {
    book: Book,
    requests: Mutex<Vec<SignRequest>>,
}

impl AppKeyProvider for Recorder {
    fn public_key(&self, key_id: String) -> Result<PublicKeyData, ProviderError> {
        let key = self
            .book
            .provider
            .public_key(&KeyId::new(key_id))
            .map_err(|e| ProviderError::Failed {
                reason: e.to_string(),
            })?;
        Ok((&key).into())
    }

    fn sign(&self, request: SignRequest) -> Result<Vec<u8>, ProviderError> {
        self.requests.lock().unwrap().push(request.clone());
        let fields =
            atem_client::encoding::dec(&request.input).map_err(|e| ProviderError::Failed {
                reason: e.to_string(),
            })?;
        assert_eq!(fields[0], b"atem-membership-entry-v1");
        let input =
            atem_client::SigningInput::new(atem_client::SignLabel::MembershipEntry, fields[1]);
        self.book
            .provider
            .sign(&KeyId::new(request.key_id), &input)
            .map_err(|e| ProviderError::Failed {
                reason: e.to_string(),
            })
    }

    fn x25519(&self, _: String, _: Vec<u8>) -> Result<Vec<u8>, ProviderError> {
        Err(ProviderError::UnknownKey)
    }

    fn hpke_open(
        &self,
        _: String,
        _: Vec<u8>,
        _: Vec<u8>,
        _: Vec<u8>,
        _: Vec<u8>,
    ) -> Result<Vec<u8>, ProviderError> {
        Err(ProviderError::UnknownKey)
    }
}

/// A manager (dev-mac) drafts, signs and publishes each of the five actions
/// through the entry publisher: the provider is asked for a fresh
/// confirmation of the exact body under a purpose that names the action, and
/// the verifier takes the signed entry.
#[test]
fn a_manager_signs_each_action_under_its_own_purpose() {
    let v = Vectors::load();
    let book = Book::load();
    let provider = Arc::new(Recorder {
        book: Book::load(),
        requests: Mutex::new(Vec::new()),
    });
    // L plus host-b (P7_add_host_b), so a project can list two hosts.
    let log = log_after(&v, &["P7_add_host_b"]);
    let host_a_enc = atem_client::provider::KeyProvider::public_key(
        &book.provider,
        &KeyId::new("host-a-enc-1/enc"),
    )
    .unwrap();
    let enc_pub: [u8; 32] = host_a_enc.as_bytes().try_into().unwrap();
    let enc_sig = atem_client::membership::sign_host_enc_key(
        &book.provider,
        &KeyId::new("host-a/host_key"),
        ACCOUNT,
        &genesis_hash(),
        "host-a",
        1,
        &enc_pub,
    )
    .unwrap();
    let enc_key = PublicKeyData::from(&host_a_enc);
    let enc_sig = atem_client::encoding::b64u(&enc_sig);
    assert!(verify_host_enc_sig(
        PublicKeyData::from(&book.public("host-a/host_key")),
        ACCOUNT.into(),
        genesis_hash().to_hex(),
        "host-a".into(),
        1,
        enc_key.clone(),
        enc_sig.clone()
    ));
    let at = |n: u64| 1_793_620_800_000 + n * 1000;
    let actions = [
        (
            project_set_action(
                "astation".into(),
                vec!["host-b".into(), "host-a".into()],
                vec!["prompt".into(), "message".into()],
                at(8),
            )
            .unwrap(),
            SigningPurpose::Project,
            "project_set",
        ),
        (
            host_sender_revoke_action("host-b".into(), true, at(9)).unwrap(),
            SigningPurpose::HostSender,
            "host_sender_revoke",
        ),
        (
            host_sender_readmit_action("host-b".into(), at(10)).unwrap(),
            SigningPurpose::HostSender,
            "host_sender_readmit",
        ),
        (
            host_enc_key_action("host-a".into(), 1, enc_key, enc_sig, false, at(11)).unwrap(),
            SigningPurpose::HostEncKey,
            "host_enc_key",
        ),
        (
            project_remove_action("astation".into(), at(12)).unwrap(),
            SigningPurpose::Project,
            "project_remove",
        ),
    ];
    for (i, (action, purpose, name)) in actions.into_iter().enumerate() {
        assert_eq!(
            log.check_change(action.clone(), at(8 + i as u64)).unwrap(),
            None
        );
        let body = log
            .draft_entry("dev-mac".into(), at(8 + i as u64), action)
            .unwrap();
        let publisher = EntryPublisher::new();
        publisher.prepare(log.clone(), body.clone()).unwrap();
        let request = publisher
            .sign(provider.clone(), "dev-mac/auth".into(), None)
            .unwrap();
        let sent = provider.requests.lock().unwrap().last().cloned().unwrap();
        assert_eq!(sent.purpose, purpose, "{name}");
        assert!(sent.fresh_confirmation, "{name}: R9.6 rule 4");
        assert_eq!(sent.body_json.as_deref(), Some(body.as_str()), "{name}");
        assert_eq!(sent.label, "atem-membership-entry-v1");
        assert!(sent.body_json.unwrap().contains(name));
        assert!(
            matches!(
                publisher.reply_stored(log.clone(), now()).unwrap(),
                PublishOutcome::Committed { .. }
            ),
            "{name}: {request:?}"
        );
    }
    assert_eq!(log.head().seq, 12);
    // The end state: the project is gone, host-b readmitted, host-a has its key.
    assert!(log.projects().is_empty());
    assert_eq!(
        log.host_sender_state("host-b".into()),
        Some(HostSenderStateInfo::Authorized { generation: 10 })
    );
    let keys = log.host_enc_key("host-a".into()).unwrap();
    assert_eq!(keys.current.key.raw, host_a_enc.as_bytes());
    assert_eq!(
        keys.current.enc_kid,
        atem_client::keys::enc_kid(&host_a_enc).unwrap()
    );
    assert!(keys.previous.is_none());
}

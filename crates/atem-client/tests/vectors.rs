//! Runs every `designs/protocol/fixtures/r9-vectors-*.json` file
//! (`schema.md` "r9 fixtures", `kind: "vectors"`).
//!
//! Each file's runner checks every value this crate can reproduce today
//! (encodings, hashes, signatures, KDFs, HPKE, kit tags, key conversions)
//! and lists the rest as pending with the task that brings it. A runner must
//! account for every top-level field of its file: one it neither checks nor
//! lists fails the run, so nothing is skipped silently.
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use atem_client::backup::{BackupKey, KBackupEnvelope};
use atem_client::canonical::{self, Numbers, jcs};
use atem_client::domain::{SignLabel, SigningInput};
use atem_client::encoding::{Hash32, b64u, b64u_decode, enc, hex, u64_field};
use atem_client::hpke;
use atem_client::keys::{Alg, PublicKey, ed25519_public_to_x25519, enc_kid};
use atem_client::kit::{self, RecoveryKit};
use atem_client::provider::sign;
use atem_client::{Error, KeyId, KeyProvider, SignedObject, SoftwareKeys};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

const TASK2: &str = "Task 2 (membership-log verifier: chain and action rules)";
const TASK3: &str = "Task 3 (atem-ch1 transcript, key schedule, framing)";
const TASK4: &str = "Task 4 (principals, grants, push hint and seen rules)";
const RESTORE: &str = "the restore flow over the verified chain (Task 2's verifier, then a client machine; the plan names no task)";

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../designs/protocol/fixtures")
}

fn load(name: &str) -> Value {
    let bytes = std::fs::read(fixtures_dir().join(format!("{name}.json"))).unwrap();
    canonical::parse_strict(&bytes, usize::MAX, Numbers::IntegersOnly)
        .unwrap_or_else(|e| panic!("{name}: not strict JSON: {e:?}"))
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len().is_multiple_of(2), "odd hex {text}");
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
        .collect()
}

fn unhex32(text: &str) -> [u8; 32] {
    unhex(text).try_into().unwrap()
}

fn s<'a>(v: &'a Value, field: &str) -> &'a str {
    v[field]
        .as_str()
        .unwrap_or_else(|| panic!("{field} is not a string in {v}"))
}

/// Book-keeping of one vectors file: what passed, what is pending and why,
/// and which top-level fields were accounted for.
struct Run {
    name: &'static str,
    file: Value,
    covered: BTreeSet<String>,
    passed: Vec<String>,
    pending: Vec<(String, &'static str)>,
}

impl Run {
    fn new(name: &'static str) -> Self {
        let file = load(name);
        assert_eq!(file["name"], name, "named after its file");
        assert_eq!(file["kind"], "vectors");
        assert_eq!(file["requires"], "r9");
        let covered = ["name", "kind", "requires", "note"]
            .map(String::from)
            .into_iter()
            .collect();
        Run {
            name,
            file,
            covered,
            passed: Vec::new(),
            pending: Vec::new(),
        }
    }

    fn get(&mut self, field: &str) -> Value {
        assert!(
            self.file.get(field).is_some(),
            "{}: no field {field}",
            self.name
        );
        self.covered.insert(field.to_owned());
        self.file[field].clone()
    }

    fn pass(&mut self, what: impl Into<String>) {
        self.passed.push(what.into());
    }

    fn pending(&mut self, what: impl Into<String>, reason: &'static str) {
        self.pending.push((what.into(), reason));
    }

    /// Marks top-level fields that are wholly pending.
    fn pending_fields(&mut self, fields: &[&str], reason: &'static str) {
        for field in fields {
            self.get(field);
            self.pending(field.to_string(), reason);
        }
    }

    fn finish(self) {
        let fields: BTreeSet<String> = self.file.as_object().unwrap().keys().cloned().collect();
        let missed: Vec<&String> = fields.difference(&self.covered).collect();
        assert!(
            missed.is_empty(),
            "{}: fields neither checked nor listed as pending: {missed:?}",
            self.name
        );
        assert!(!self.passed.is_empty(), "{}: nothing checked", self.name);
        eprintln!(
            "{}: {} passed, {} pending",
            self.name,
            self.passed.len(),
            self.pending.len()
        );
        for (what, why) in &self.pending {
            eprintln!("  PENDING {what}: {why}");
        }
    }
}

/// The test keys of `r9-vectors-keys`, loaded into a software provider.
struct Book {
    keys: Value,
    provider: SoftwareKeys,
}

impl Book {
    fn load() -> Self {
        let keys = load("r9-vectors-keys")["keys"].clone();
        let mut provider = SoftwareKeys::new();
        for (name, entry) in keys.as_object().unwrap() {
            for (part, key) in [
                ("auth", entry.get("auth")),
                ("enc", entry.get("enc")),
                ("host_key", entry.get("host_key")),
                ("", entry.get("secret_hex").map(|_| entry)),
            ] {
                let Some(key) = key else { continue };
                let secret = unhex32(s(key, "secret_hex"));
                let id = KeyId::new(format!("{name}/{part}"));
                match key.get("alg").and_then(Value::as_str) {
                    Some("p256") => provider.insert_p256(id, &secret).unwrap(),
                    Some("ed25519") => provider.insert_ed25519(id, &secret),
                    // Member `enc` keys carry no alg: they are X25519.
                    None if part == "enc" => provider.insert_x25519(id, &secret),
                    None => {} // account keys K
                    Some(other) => panic!("unknown alg {other}"),
                }
            }
        }
        for kit in ["recovery", "recovery-2"] {
            provider.insert_ed25519(
                KeyId::new(format!("{kit}/sign")),
                &unhex32(s(&keys[kit], "sign_seed_hex")),
            );
            provider.insert_x25519(
                KeyId::new(format!("{kit}/x25519")),
                &unhex32(s(&keys[kit], "x25519_secret_hex")),
            );
        }
        Book { keys, provider }
    }

    fn public(&self, id: &str) -> PublicKey {
        self.provider.public_key(&KeyId::new(id)).unwrap()
    }

    /// A device's `auth` key, a host's `host_key`, or a kit's recovery key.
    fn signer(&self, name: &str) -> KeyId {
        let entry = &self.keys[name];
        let id = if entry.get("auth").is_some() {
            format!("{name}/auth")
        } else if entry.get("host_key").is_some() {
            format!("{name}/host_key")
        } else if entry.get("sign_seed_hex").is_some() {
            format!("{name}/sign")
        } else {
            format!("{name}/")
        };
        KeyId::new(id)
    }

    fn signer_public(&self, name: &str) -> PublicKey {
        self.provider.public_key(&self.signer(name)).unwrap()
    }
}

fn genesis_hash() -> Hash32 {
    Hash32::from_hex(s(&load("r9-vectors-membership-log"), "genesis_hash")).unwrap()
}

// ---------------------------------------------------------------- files

#[test]
fn every_vectors_file_has_a_runner() {
    let mut found: Vec<String> = std::fs::read_dir(fixtures_dir())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter(|n| n.starts_with("r9-vectors-") && n.ends_with(".json"))
        .collect();
    found.sort();
    assert_eq!(
        found,
        [
            "r9-vectors-browser-grant.json",
            "r9-vectors-channel-handshake.json",
            "r9-vectors-encoding.json",
            "r9-vectors-keys.json",
            "r9-vectors-membership-log.json",
            "r9-vectors-push-hint.json",
            "r9-vectors-recovery.json",
        ],
        "a new vectors file needs a runner below"
    );
}

#[test]
fn encoding() {
    let mut run = Run::new("r9-vectors-encoding");
    let book = Book::load();

    for (i, case) in run.get("enc").as_array().unwrap().iter().enumerate() {
        let fields: Vec<Vec<u8>> = if let Some(utf8) = case.get("fields_utf8") {
            utf8.as_array()
                .unwrap()
                .iter()
                .map(|f| f.as_str().unwrap().as_bytes().to_vec())
                .collect()
        } else {
            case["fields"]
                .as_array()
                .unwrap()
                .iter()
                .map(|f| {
                    let n = f.as_str().unwrap();
                    let n: u64 = n
                        .strip_prefix("u64(")
                        .unwrap()
                        .strip_suffix(')')
                        .unwrap()
                        .parse()
                        .unwrap();
                    u64_field(n).to_vec()
                })
                .collect()
        };
        let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
        assert_eq!(hex(&enc(&refs)), s(case, "hex"), "enc[{i}]");
        run.pass(format!("enc[{i}]"));
    }

    for (i, case) in run.get("jcs").as_array().unwrap().iter().enumerate() {
        let parsed = canonical::parse_payload(s(case, "input").as_bytes()).unwrap();
        assert_eq!(jcs(&parsed).unwrap(), s(case, "jcs"), "jcs[{i}]");
        run.pass(format!("jcs[{i}]"));
    }

    let p256 = run.get("p256_low_s");
    let key = book.signer_public(s(&p256, "key"));
    assert_eq!(key.alg(), Alg::P256);
    let message = unhex(s(&p256, "message_hex"));
    let low = unhex(s(&p256, "sig_low_s_hex"));
    let high = unhex(s(&p256, "sig_high_s_hex"));
    assert_eq!(p256["valid"], true);
    key.verify_raw(&message, &low).unwrap();
    assert_eq!(p256["high_s_valid"], false);
    assert_eq!(key.verify_raw(&message, &high), Err(Error::HighS));
    // The two are r‖s and r‖(n − s): the same r.
    assert_eq!(low[..32], high[..32]);
    run.pass("p256_low_s: low S verifies, high S refused");

    let ed = run.get("ed25519_strict");
    let key = book.signer_public(s(&ed, "key"));
    assert_eq!(key.alg(), Alg::Ed25519);
    assert_eq!(ed["valid"], true);
    key.verify_raw(&unhex(s(&ed, "message_hex")), &unhex(s(&ed, "sig_hex")))
        .unwrap();
    run.pass("ed25519_strict");
    run.finish();
}

#[test]
fn keys() {
    let mut run = Run::new("r9-vectors-keys");
    let book = Book::load();
    let keys = run.get("keys");
    // Labels of `secret = SHA-256(enc(["atem-r9-test-key", label]))`
    // (schema.md). Labels the fixtures name or that follow their pattern.
    let labels: BTreeMap<&str, &str> = [
        ("dev-evil/auth", "dev-evil auth"),
        ("dev-evil/enc", "dev-evil enc"),
        ("dev-ipad/auth", "dev-ipad auth"),
        ("dev-ipad/enc", "dev-ipad enc"),
        ("dev-mac/auth", "dev-mac auth"),
        ("dev-mac/enc", "dev-mac enc"),
        ("dev-newmac/auth", "dev-newmac auth"),
        ("dev-newmac/enc", "dev-newmac enc"),
        ("dev-phone/auth", "dev-phone auth"),
        ("dev-phone/enc", "dev-phone enc"),
        ("host-a/host_key", "host-a host_channel_key"),
        ("host-evil/host_key", "host-evil host_key"),
        ("svc-discord/auth", "svc-discord auth"),
        ("browser/", "browser key"),
        ("K-gen-3/", "K-gen-3"),
        ("K-evil/", "K-evil"),
        ("recovery-2/R", "recovery-kit-2"),
    ]
    .into_iter()
    .collect();
    let test_key = |label: &str| {
        hex(&Sha256::digest(enc(&[
            b"atem-r9-test-key",
            label.as_bytes(),
        ])))
    };

    for (name, entry) in keys.as_object().unwrap() {
        if name == "note" {
            continue;
        }
        if name == "recovery" || name == "recovery-2" {
            let r = unhex32(s(entry, "R_hex"));
            let seed = kit::sign_seed(&r);
            assert_eq!(hex(&*seed), s(entry, "sign_seed_hex"), "{name} sign_seed");
            let recovery_key = kit::recovery_key_of_seed(&seed);
            assert_eq!(hex(recovery_key.as_bytes()), s(entry, "sign_pub_hex"));
            let x_secret = kit::x25519_secret_of_seed(&seed);
            assert_eq!(hex(&*x_secret), s(entry, "x25519_secret_hex"));
            // The Montgomery form of the recovery key is the X25519 public
            // key of the derived secret.
            let x_pub = ed25519_public_to_x25519(&recovery_key).unwrap();
            assert_eq!(hex(&x_pub), s(entry, "x25519_pub_hex"));
            assert_eq!(hpke::public_of(&x_secret).unwrap(), x_pub);
            let tag = kit::kit_tag(&r, "acct-test-1", &genesis_hash());
            assert_eq!(hex(&tag), s(entry, "kit_tag_hex"), "{name} kit_tag");
            run.pass(format!(
                "{name}: sign_seed, recovery key, X25519 form, kit_tag"
            ));
            match labels.get(format!("{name}/R").as_str()) {
                Some(label) => {
                    assert_eq!(test_key(label), s(entry, "R_hex"));
                    run.pass(format!("{name}: R from its test label"));
                }
                None => run.pending(
                    format!("{name}: R from its test label"),
                    "the fixtures don't name this label (schema.md); every value derived from R is checked",
                ),
            }
            continue;
        }
        let parts: Vec<(&str, &Value)> = ["auth", "enc", "host_key"]
            .into_iter()
            .filter_map(|p| entry.get(p).map(|k| (p, k)))
            .chain(entry.get("secret_hex").map(|_| ("", entry)))
            .collect();
        assert!(!parts.is_empty(), "{name} has no key");
        for (part, key) in parts {
            let id = format!("{name}/{part}");
            let secret = s(key, "secret_hex");
            if let Some(pub_hex) = key.get("pub_hex") {
                assert_eq!(
                    hex(book.public(&id).as_bytes()),
                    pub_hex.as_str().unwrap(),
                    "{id}"
                );
                if part == "enc" {
                    assert_eq!(
                        hpke::public_of(&unhex32(secret)).unwrap().to_vec(),
                        unhex(pub_hex.as_str().unwrap())
                    );
                }
                run.pass(format!("{id}: public key from secret"));
            } else {
                // An account key K: only its secret and kid.
                assert_eq!(s(key, "kid").len(), 8);
            }
            match labels.get(id.as_str()) {
                Some(label) => {
                    assert_eq!(test_key(label), secret, "{id} label {label}");
                    run.pass(format!("{id}: secret from label {label:?}"));
                }
                None => run.pending(
                    format!("{id}: secret from its test label"),
                    "the fixtures don't name this label (schema.md); its public key is checked",
                ),
            }
        }
    }
    run.finish();
}

/// What a membership-log vector's signature should do, by label.
enum SigExpect {
    /// Verifies with this key name, and re-signing the body reproduces it
    /// (RFC 6979 P-256 normalized to low S; Ed25519 is deterministic).
    Valid(&'static str),
    /// Verifies, but the vector was signed with a hedged nonce.
    ValidHedged(&'static str),
    /// Must not verify with this key.
    Bad(&'static str),
}

fn signer_of(label: &str, signer: &str) -> SigExpect {
    match (label, signer) {
        ("X8_badsig", _) => SigExpect::Bad("dev-mac"),
        ("R7_wrong_key", _) => SigExpect::Bad("recovery"),
        ("E7_retry", _) => SigExpect::ValidHedged("dev-phone"),
        ("R8_newkit", "recovery") => SigExpect::Valid("recovery-2"),
        (_, "recovery") => SigExpect::Valid("recovery"),
        (_, "dev-mac") => SigExpect::Valid("dev-mac"),
        (_, "dev-phone") => SigExpect::Valid("dev-phone"),
        (_, "dev-ipad") => SigExpect::Valid("dev-ipad"),
        (_, "dev-newmac") => SigExpect::Valid("dev-newmac"),
        (_, "dev-evil") => SigExpect::Valid("dev-evil"),
        other => panic!("no signer for {other:?}"),
    }
}

/// Context-dependent refusals of the membership-log vectors: they need the
/// chain, the host's pending state or the action rules.
fn chain_reason(label: &str) -> Option<&'static str> {
    match label {
        "X7_ipad" => Some("invalid: signer not a manager at the head"),
        "X5_svc91d" => Some("invalid: service expiry over 90 days"),
        "R7_roles" => Some("invalid: recovery_add roles not exactly control/manage/view"),
        "R7_remove" => Some("invalid: the recovery signer may only recovery_add"),
        "A8_ipad" | "V8_ipad" => Some("invalid: signer_not_manager"),
        "R8_oldkit" | "R8_oldkit_after_lost" => Some("invalid: recovery_key_retired"),
        "A8_k_self" => Some("invalid: self_approval"),
        "KB8_stale" => Some("invalid: blob_version_not_increasing"),
        _ => None,
    }
}

#[test]
fn membership_log() {
    let mut run = Run::new("r9-vectors-membership-log");
    let book = Book::load();
    let account = run.get("account_id");
    let genesis = Hash32::from_hex(run.get("genesis_hash").as_str().unwrap()).unwrap();
    let log = run.get("log");
    let others = run.get("others");
    let head = run.get("head");

    let mut hashes: BTreeMap<String, Hash32> = BTreeMap::new();
    for vector in log
        .as_array()
        .unwrap()
        .iter()
        .chain(others.as_array().unwrap())
    {
        let label = s(vector, "label");
        let body = &vector["entry"]["body"];
        if label == "K7_current_no_kit_sig" {
            assert_eq!(s(vector, "reason"), "kit_sig_missing");
            assert_eq!(
                SignedObject::from_value(&vector["entry"]),
                Err(Error::KitSigMissing)
            );
            assert_eq!(Error::KitSigMissing.code(), "kit_sig_missing");
            run.pass(format!("{label}: refused kit_sig_missing"));
            // Its body is K7_current's: the same entry, so the same hash.
            let body_jcs = jcs(body).unwrap();
            assert_eq!(body_jcs, s(vector, "jcs"));
            assert_eq!(
                hex(SigningInput::new(SignLabel::MembershipEntry, body_jcs.as_bytes()).as_bytes()),
                s(vector, "signing_input_hex")
            );
            let hash = Hash32::of_enc(&[b"atem-membership-hash-v1", body_jcs.as_bytes()]);
            assert_eq!(hash.to_hex(), s(vector, "entry_hash"));
            run.pass(format!("{label}: jcs, signing input, entry_hash"));
            continue;
        }
        let object =
            SignedObject::from_value(&vector["entry"]).unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(object.body_type(), "atem-membership-entry");
        if let Some(expected) = vector.get("jcs") {
            assert_eq!(object.jcs(), expected.as_str().unwrap(), "{label} jcs");
        }
        if let Some(expected) = vector.get("signing_input_hex") {
            assert_eq!(
                hex(object.signing_input().as_bytes()),
                expected.as_str().unwrap(),
                "{label}"
            );
        }
        let hash = object.entry_hash().unwrap();
        assert_eq!(hash.to_hex(), s(vector, "entry_hash"), "{label} entry_hash");
        hashes.insert(label.to_owned(), hash);
        assert_eq!(object.to_json(), vector["entry"], "{label} round trip");
        run.pass(format!(
            "{label}: strict parse, arrays, jcs, signing input, entry_hash"
        ));

        match signer_of(label, s(body, "signer")) {
            SigExpect::Valid(name) => {
                let key = book.signer(name);
                object
                    .verify(&book.signer_public(name))
                    .unwrap_or_else(|e| panic!("{label}: {e}"));
                let again = SignedObject::sign(&book.provider, &key, body.clone()).unwrap();
                assert_eq!(
                    b64u(again.sig()),
                    b64u(object.sig()),
                    "{label}: deterministic signature"
                );
                run.pass(format!(
                    "{label}: signature by {name} verifies and is reproduced"
                ));
            }
            SigExpect::ValidHedged(name) => {
                object.verify(&book.signer_public(name)).unwrap();
                let again =
                    SignedObject::sign(&book.provider, &book.signer(name), body.clone()).unwrap();
                assert_ne!(again.sig(), object.sig());
                run.pass(format!("{label}: hedged signature by {name} verifies"));
            }
            SigExpect::Bad(name) => {
                assert_eq!(vector["valid"], false);
                assert_eq!(
                    object.verify(&book.signer_public(name)),
                    Err(Error::BadSignature),
                    "{label}"
                );
                run.pass(format!("{label}: signature refused under {name}"));
            }
        }

        if let Some(kit_input) = vector.get("kit_signing_input_hex") {
            let input = object.cosign_input().unwrap();
            assert_eq!(hex(input.as_bytes()), kit_input.as_str().unwrap());
            let current = book.signer_public("recovery");
            object.verify_kit_sig(&current).unwrap();
            assert_eq!(
                object.verify_kit_sig(&book.signer_public("recovery-2")),
                Err(Error::BadSignature)
            );
            let mut again =
                SignedObject::sign(&book.provider, &book.signer("dev-phone"), body.clone())
                    .unwrap();
            again
                .cosign(&book.provider, &book.signer("recovery"))
                .unwrap();
            assert_eq!(again.kit_sig(), object.kit_sig());
            run.pass(format!("{label}: kit_sig by the current recovery key"));
        }

        if let Some(reason) = chain_reason(label) {
            assert_eq!(vector["valid"], false, "{label}");
            if let Some(code) = vector.get("reason") {
                assert!(reason.ends_with(code.as_str().unwrap()), "{label}");
            }
            run.pending(format!("{label}: {reason}"), TASK2);
        } else if vector.get("valid") == Some(&Value::Bool(false)) {
            assert!(
                matches!(signer_of(label, s(body, "signer")), SigExpect::Bad(_)),
                "{label}"
            );
        }
    }

    assert_eq!(hashes["E1"], genesis);
    assert_eq!(
        hashes["E7_retry"], hashes["E7"],
        "a re-signed body is the same entry"
    );
    assert_eq!(head["seq"], 6);
    assert_eq!(hashes["E6"].to_hex(), s(&head, "hash"));
    for vector in log.as_array().unwrap() {
        assert_eq!(vector["entry"]["body"]["account_id"], account);
        // The log's members hold the test keys of their device ids.
        if let Some(member) = vector["entry"]["body"].get("member") {
            let name = s(member, "device_id");
            assert_eq!(
                PublicKey::from_json(&member["auth_key"]).unwrap(),
                book.signer_public(name)
            );
            if let Some(enc_key) = member.get("enc_key") {
                assert_eq!(
                    PublicKey::from_json_as(enc_key, Alg::X25519).unwrap(),
                    book.public(&format!("{name}/enc"))
                );
            }
        }
        if let Some(host) = vector["entry"]["body"].get("host") {
            assert_eq!(
                PublicKey::from_json_as(&host["host_key"], Alg::Ed25519).unwrap(),
                book.signer_public(s(host, "host_id"))
            );
        }
    }
    run.pass("log L: genesis_hash, head, member and host keys, E7_retry = E7");
    run.pending(
        "log L E1–E6: chain verification (seq, prev_hash, signers in effect, action rules)",
        TASK2,
    );
    run.pending(
        "alternatives in context (conflicts, deferral, pending recovery, kit replacement)",
        TASK2,
    );
    run.finish();
}

/// Checks one `atem-k-backup-v2` vector; returns its envelope.
fn check_backup(
    run: &mut Run,
    name: &str,
    vector: &Value,
    kit: &RecoveryKit,
    other_kit: &RecoveryKit,
    book: &Book,
) -> KBackupEnvelope {
    let envelope = KBackupEnvelope::from_value(&vector["wire"]).unwrap();
    assert_eq!(envelope.to_json(), vector["wire"], "{name} round trip");
    assert_eq!(
        envelope.backup_hash().to_hex(),
        s(vector, "backup_hash"),
        "{name}"
    );
    assert_eq!(envelope.recovery_key, kit.recovery_key());
    if let Some(info) = vector.get("info_hex") {
        assert_eq!(
            hex(&envelope.info().unwrap()),
            info.as_str().unwrap(),
            "{name} info"
        );
    }
    run.pass(format!("{name}: envelope, info, backup_hash"));

    let opens = vector
        .get("opens_with_kit_1")
        .is_none_or(|v| v.as_bool().unwrap());
    if !opens {
        assert_eq!(
            envelope.open_with_kit(kit).unwrap_err(),
            Error::BackupInvalid
        );
        run.pass(format!("{name}: refused backup_invalid"));
        return envelope;
    }
    let keys = envelope.open_with_kit(kit).unwrap();
    // The same through a key provider holding the kit's X25519 key.
    let kit_id = KeyId::new(if kit.recovery_key() == book.signer_public("recovery") {
        "recovery/x25519"
    } else {
        "recovery-2/x25519"
    });
    let through_provider = envelope.open(&book.provider, &kit_id).unwrap();
    assert_eq!(through_provider.len(), keys.len());
    let plain: Value = serde_json::json!({"keys": keys
        .iter()
        .map(|k| serde_json::json!({"k": b64u(&*k.k), "kid": k.kid}))
        .collect::<Vec<_>>()});
    assert_eq!(
        jcs(&plain).unwrap(),
        s(vector, "plain_jcs"),
        "{name} plaintext"
    );
    run.pass(format!(
        "{name}: opens with its kit, plaintext keys in order"
    ));

    if vector.get("opens_with_other_kit") == Some(&Value::Bool(false)) {
        assert_eq!(
            envelope.open_with_kit(other_kit).unwrap_err(),
            Error::BackupInvalid
        );
        let other_id = KeyId::new(if kit_id.0.starts_with("recovery-2") {
            "recovery/x25519"
        } else {
            "recovery-2/x25519"
        });
        assert_eq!(
            envelope.open(&book.provider, &other_id).unwrap_err(),
            Error::BackupInvalid
        );
        run.pass(format!("{name}: the other kit can't open it"));
    }

    let ikm = unhex32(s(vector, "ikmE_hex"));
    let copies: Vec<BackupKey> = keys
        .iter()
        .map(|k| BackupKey {
            kid: k.kid.clone(),
            k: Zeroizing::new(*k.k),
        })
        .collect();
    let resealed = KBackupEnvelope::seal_with_ikm(
        &envelope.account_id,
        envelope.genesis_hash,
        envelope.blob_version,
        &envelope.recovery_key,
        &copies,
        &ikm,
    )
    .unwrap();
    assert_eq!(resealed, envelope, "{name}: seal from ikmE");
    assert_eq!(resealed.jcs(), envelope.jcs());
    run.pass(format!("{name}: seal from ikmE reproduces enc and ct"));
    envelope
}

#[test]
fn recovery() {
    let mut run = Run::new("r9-vectors-recovery");
    let book = Book::load();
    let log = load("r9-vectors-membership-log");
    let entry = |label: &str| -> Value {
        log["log"]
            .as_array()
            .unwrap()
            .iter()
            .chain(log["others"].as_array().unwrap())
            .find(|v| v["label"] == label)
            .unwrap_or_else(|| panic!("no entry {label}"))
            .clone()
    };
    let genesis = genesis_hash();

    // Kit 1.
    let r = run.get("R_hex");
    assert_eq!(r, book.keys["recovery"]["R_hex"]);
    let r = unhex32(r.as_str().unwrap());
    let seed = kit::sign_seed(&r);
    assert_eq!(hex(&*seed), run.get("sign_seed_hex").as_str().unwrap());
    let recovery_key = PublicKey::from_json_as(&run.get("recovery_key"), Alg::Ed25519).unwrap();
    assert_eq!(kit::recovery_key_of_seed(&seed), recovery_key);
    assert_eq!(
        hex(&kit::kit_x25519_public(&recovery_key).unwrap()),
        run.get("recovery_key_x25519_pub_hex").as_str().unwrap()
    );
    assert_eq!(run.get("recovery_key_matches_genesis_E1"), true);
    assert_eq!(
        PublicKey::from_json(&entry("E1")["entry"]["body"]["recovery_key"]).unwrap(),
        recovery_key
    );
    run.pass("kit 1: R → sign_seed → recovery key (= E1's) → X25519 form");

    let check_kit = |run: &mut Run, name: &str, vector: &Value, r: &[u8; 32]| -> RecoveryKit {
        let account = s(vector, "account_id");
        let genesis = Hash32::from_hex(s(vector, "genesis_hash")).unwrap();
        assert_eq!(
            hex(&kit::tag_input(account, &genesis)),
            s(vector, "tag_input_hex")
        );
        assert_eq!(hex(&*kit::tag_key(r)), s(vector, "tag_key_hex"));
        let tag: [u8; 16] = unhex(s(vector, "kit_tag_hex")).try_into().unwrap();
        let kit = RecoveryKit::read(r, account, genesis, &tag).unwrap();
        assert_eq!(kit.kit_tag(), tag);
        // A kit altered without recomputing its tag is "damaged".
        assert_eq!(
            RecoveryKit::read(r, "acct-test-2", genesis, &tag).err(),
            Some(Error::KitDamaged)
        );
        assert_eq!(
            RecoveryKit::read(r, account, Hash32([0u8; 32]), &tag).err(),
            Some(Error::KitDamaged)
        );
        let mut flipped = tag;
        flipped[15] ^= 1;
        assert_eq!(
            RecoveryKit::read(r, account, genesis, &flipped).err(),
            Some(Error::KitDamaged)
        );
        run.pass(format!(
            "{name}: tag input, tag key, kit_tag; altered kits refused"
        ));
        kit
    };
    let kit_vector = run.get("kit");
    let kit1 = check_kit(&mut run, "kit", &kit_vector, &r);
    assert_eq!(kit1.genesis_hash(), genesis);

    // Kit 2.
    let kit_2 = run.get("kit_2");
    let r2 = unhex32(s(&kit_2, "R_hex"));
    assert_eq!(s(&kit_2, "R_hex"), s(&book.keys["recovery-2"], "R_hex"));
    let seed2 = kit::sign_seed(&r2);
    assert_eq!(hex(&*seed2), s(&kit_2, "sign_seed_hex"));
    let recovery_key_2 = PublicKey::from_json_as(&kit_2["recovery_key"], Alg::Ed25519).unwrap();
    assert_eq!(kit::recovery_key_of_seed(&seed2), recovery_key_2);
    assert_eq!(
        hex(&kit::kit_x25519_public(&recovery_key_2).unwrap()),
        s(&kit_2, "x25519_pub_hex")
    );
    assert_eq!(
        PublicKey::from_json(&entry("K7_current")["entry"]["body"]["recovery_key"]).unwrap(),
        recovery_key_2
    );
    run.pass("kit 2: R → sign_seed → recovery key (= K7_current's) → X25519 form");
    let kit2 = check_kit(&mut run, "kit_2.kit", &kit_2["kit"], &r2);
    assert_eq!(
        kit2.genesis_hash(),
        genesis,
        "kit 2 is bound to the same genesis"
    );

    // Backups, and the k_backup entries that name them.
    let names_backup = |label: &str, envelope: &KBackupEnvelope| {
        let record = &entry(label)["entry"]["body"]["k_backup"];
        assert_eq!(
            s(record, "backup_hash"),
            envelope.backup_hash().to_hex(),
            "{label}"
        );
        assert_eq!(record["blob_version"], envelope.blob_version);
        assert_eq!(record["kids"], Value::from(envelope.kids.clone()));
        assert_eq!(
            PublicKey::from_json(&record["recovery_key"]).unwrap(),
            envelope.recovery_key
        );
    };
    let v_env3 = run.get("k_backup");
    let env3 = check_backup(&mut run, "k_backup", &v_env3, &kit1, &kit2, &book);
    names_backup("KB7", &env3);
    let v_env4 = run.get("k_backup_rotated");
    let env4 = check_backup(&mut run, "k_backup_rotated", &v_env4, &kit1, &kit2, &book);
    names_backup("KB8", &env4);
    let k_gen_3 = env4.open_with_kit(&kit1).unwrap();
    assert_eq!(k_gen_3[0].kid, s(&book.keys["K-gen-3"], "kid"));
    assert_eq!(hex(&*k_gen_3[0].k), s(&book.keys["K-gen-3"], "secret_hex"));
    let v_bad = run.get("k_backup_bad_ct");
    let bad = check_backup(&mut run, "k_backup_bad_ct", &v_bad, &kit1, &kit2, &book);
    names_backup("KB8_badct", &bad);
    run.pass("KB7, KB8, KB8_badct name their envelopes (hash, version, kids, kit); K-gen-3 inside");
    let resealed = check_backup(
        &mut run,
        "kit_2.k_backup_resealed",
        &kit_2["k_backup_resealed"],
        &kit2,
        &kit1,
        &book,
    );
    assert_eq!(resealed.kids, env3.kids);

    // The recovery entry (R7).
    let vector = run.get("recovery_entry");
    let object = SignedObject::from_value(&vector["entry"]).unwrap();
    assert_eq!(object.jcs(), s(&vector, "jcs"));
    assert_eq!(
        hex(object.signing_input().as_bytes()),
        s(&vector, "signing_input_hex")
    );
    assert_eq!(
        object.entry_hash().unwrap().to_hex(),
        s(&vector, "entry_hash")
    );
    assert_eq!(
        s(&vector, "entry_hash"),
        run.get("recovery_entry_hash").as_str().unwrap()
    );
    object.verify(&recovery_key).unwrap();
    assert_eq!(vector["entry"], entry(s(&vector, "label"))["entry"]);
    run.pass("recovery_entry R7: jcs, signing input, entry_hash, signed by the kit");

    // The substitute chain: valid on its own, refused by the anchor.
    let sub = run.get("substitute_chain");
    let labels: Vec<&str> = sub["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(labels, ["SUB1", "SUB2", "SUB3"]);
    let sub1 = SignedObject::from_value(&entry("SUB1")["entry"]).unwrap();
    let sub_genesis = sub1.entry_hash().unwrap();
    assert_eq!(sub_genesis.to_hex(), s(&sub, "genesis_hash"));
    assert_eq!(
        PublicKey::from_json(&sub1.body()["recovery_key"]).unwrap(),
        recovery_key,
        "reuses kit 1's public key"
    );
    let refused = kit1.check_genesis(&sub_genesis, "acct-test-1").unwrap_err();
    assert_eq!(refused.code(), s(&sub, "refused"));
    kit1.check_genesis(&genesis, "acct-test-1").unwrap();
    assert_eq!(
        kit1.check_genesis(&genesis, "acct-test-2"),
        Err(Error::GenesisMismatch)
    );
    let sub_env = check_backup(
        &mut run,
        "substitute_chain.backup",
        &sub["backup"],
        &kit1,
        &kit2,
        &book,
    );
    names_backup("SUB3", &sub_env);
    let evil = sub_env.open_with_kit(&kit1).unwrap();
    assert_eq!(evil[0].kid, s(&book.keys["K-evil"], "kid"));
    assert_eq!(hex(&*evil[0].k), s(&book.keys["K-evil"], "secret_hex"));
    run.pass("substitute_chain: opens with kit 1 yet refused genesis_mismatch by the kit's anchor");
    run.pending(
        "restore flow (fetch, host-signed heads, kit_not_current, backup_hash_mismatch, publish)",
        RESTORE,
    );
    run.finish();
}

#[test]
fn channel_handshake() {
    let mut run = Run::new("r9-vectors-channel-handshake");
    let book = Book::load();
    let inputs = run.get("inputs");
    let init = run.get("init");
    let accept = run.get("accept");

    // Keys and ephemerals.
    let host_key = book.signer_public("host-a");
    assert_eq!(hex(host_key.as_bytes()), s(&inputs, "host_key_pub_hex"));
    assert_eq!(
        s(&inputs, "host_key_secret_hex"),
        s(&book.keys["host-a"]["host_key"], "secret_hex")
    );
    let client_key = book.signer_public("dev-phone");
    assert_eq!(
        hex(client_key.as_bytes()),
        s(&inputs, "client_auth_pub_hex")
    );
    assert_eq!(
        s(&inputs, "client_auth_secret_hex"),
        s(&book.keys["dev-phone"]["auth"], "secret_hex")
    );
    let mut eph = SoftwareKeys::new();
    for side in ["e_c", "e_h"] {
        eph.insert_x25519(
            KeyId::new(side),
            &unhex32(s(&inputs, &format!("{side}_secret_hex"))),
        );
        assert_eq!(
            hex(eph.public_key(&KeyId::new(side)).unwrap().as_bytes()),
            s(&inputs, &format!("{side}_hex"))
        );
    }
    assert_eq!(
        hex(&b64u_decode(s(&init, "e")).unwrap()),
        s(&inputs, "e_c_hex")
    );
    assert_eq!(
        hex(&b64u_decode(s(&init, "n")).unwrap()),
        s(&inputs, "n_c_hex")
    );
    assert_eq!(
        hex(&b64u_decode(s(&accept, "e")).unwrap()),
        s(&inputs, "e_h_hex")
    );
    assert_eq!(
        hex(&b64u_decode(s(&accept, "n")).unwrap()),
        s(&inputs, "n_h_hex")
    );
    run.pass("inputs: host and client keys, ephemerals, init/accept fields");

    // ss = X25519 both ways.
    let ss = run.get("ss_hex");
    let e_c = unhex32(s(&inputs, "e_c_hex"));
    let e_h = unhex32(s(&inputs, "e_h_hex"));
    assert_eq!(
        hex(&*eph.x25519(&KeyId::new("e_c"), &e_h).unwrap()),
        ss.as_str().unwrap()
    );
    assert_eq!(
        hex(&*eph.x25519(&KeyId::new("e_h"), &e_c).unwrap()),
        ss.as_str().unwrap()
    );
    run.pass("ss: X25519 from both sides");

    // sig_h and sig_c over their domain-separated inputs.
    let th2 = unhex(run.get("th2_hex").as_str().unwrap());
    let sig_h_input = SigningInput::new(SignLabel::ChannelHost, &th2);
    assert_eq!(
        hex(sig_h_input.as_bytes()),
        run.get("sig_h_input_hex").as_str().unwrap()
    );
    let sig_h = unhex(run.get("sig_h_hex").as_str().unwrap());
    assert_eq!(b64u(&sig_h), s(&accept, "sig"));
    host_key.verify(&sig_h_input, &sig_h).unwrap();
    assert_eq!(
        sign(&book.provider, &book.signer("host-a"), &sig_h_input).unwrap(),
        sig_h,
        "Ed25519 is deterministic"
    );
    run.pass("sig_h: input enc([atem-ch1-host-sig-v1, th2]), host key verifies, reproduced");
    let th3 = unhex(run.get("th3_hex").as_str().unwrap());
    let sig_c_input = SigningInput::new(SignLabel::ChannelClient, &th3);
    assert_eq!(
        hex(sig_c_input.as_bytes()),
        run.get("sig_c_input_hex").as_str().unwrap()
    );
    client_key
        .verify(&sig_c_input, &unhex(run.get("sig_c_hex").as_str().unwrap()))
        .unwrap();
    run.pass("sig_c: input enc([atem-ch1-client-sig-v1, th3]), dev-phone verifies");

    for case in run.get("negative").as_array().unwrap() {
        let name = s(case, "case");
        match name {
            "zero_shared_secret" => {
                assert_eq!(case["refuse"], true);
                assert_eq!(s(case, "ss_hex"), hex(&[0u8; 32]));
                let peer = unhex32(s(case, "peer_e_hex"));
                for side in ["e_c", "e_h"] {
                    assert_eq!(
                        eph.x25519(&KeyId::new(side), &peer),
                        Err(Error::ZeroSharedSecret)
                    );
                }
                run.pass("negative zero_shared_secret: refused before any HKDF");
            }
            "tampered_head" => {
                assert_eq!(case["sig_h_valid"], false);
                let input = SigningInput::new(SignLabel::ChannelHost, &unhex(s(case, "th2_hex")));
                assert_eq!(host_key.verify(&input, &sig_h), Err(Error::BadSignature));
                run.pass("negative tampered_head: sig_h fails over the rewritten th2");
                run.pending("negative tampered_head: th2 from the rewritten head", TASK3);
            }
            "replayed_finish" => {
                let input = SigningInput::new(SignLabel::ChannelHost, &unhex(s(case, "th2_hex")));
                host_key
                    .verify(&input, &unhex(s(case, "sig_h_hex")))
                    .unwrap();
                run.pass("negative replayed_finish: the second channel's sig_h verifies");
                run.pending(
                    "negative replayed_finish: th2, k_finish and the failed tag",
                    TASK3,
                );
            }
            "tampered_finish" | "replayed_record" | "direction_confusion" => {
                run.pending(format!("negative {name}"), TASK3)
            }
            other => panic!("unknown negative case {other}"),
        }
    }
    run.pending_fields(
        &[
            "hello_jcs",
            "principal_jcs",
            "hs_hex",
            "k_finish_hex",
            "finish",
            "finish_aad_hex",
            "finish_ct_hex",
            "th4_hex",
            "channel_id",
            "k_c2h_hex",
            "k_h2c_hex",
            "records",
        ],
        TASK3,
    );
    run.pending("th2 from its transcript input (th2_input_hex)", TASK3);
    run.get("th2_input_hex");
    run.finish();
}

#[test]
fn browser_grant() {
    let mut run = Run::new("r9-vectors-browser-grant");
    let book = Book::load();
    let grant = run.get("grant");
    let object = SignedObject::from_value(&grant).unwrap();
    assert_eq!(object.label(), SignLabel::BrowserGrant);
    assert_eq!(
        hex(object.signing_input().as_bytes()),
        run.get("signing_input_hex").as_str().unwrap()
    );
    assert_eq!(
        object.grant_hash().unwrap().to_hex(),
        run.get("grant_hash_hex").as_str().unwrap()
    );
    let issuer = s(&object.body().clone(), "issuer").to_owned();
    object.verify(&book.signer_public(&issuer)).unwrap();
    let again =
        SignedObject::sign(&book.provider, &book.signer(&issuer), object.body().clone()).unwrap();
    assert_eq!(again.sig(), object.sig(), "RFC 6979, low S");
    run.pass("grant: signing input, grant_hash, issuer signature (reproduced)");

    let browser_secret = unhex32(run.get("browser_key_secret_hex").as_str().unwrap());
    let mut browser = SoftwareKeys::new();
    browser
        .insert_p256(KeyId::new("b"), &browser_secret)
        .unwrap();
    let browser_key = browser.public_key(&KeyId::new("b")).unwrap();
    assert_eq!(
        PublicKey::from_json(&object.body()["browser_key"]).unwrap(),
        browser_key
    );
    assert_eq!(browser_key, book.signer_public("browser"));
    let th3 = unhex(run.get("th3_hex").as_str().unwrap());
    browser_key
        .verify(
            &SigningInput::new(SignLabel::ChannelClient, &th3),
            &unhex(run.get("sig_c_hex").as_str().unwrap()),
        )
        .unwrap();
    run.pass("browser key from its secret; sig_c over enc([atem-ch1-client-sig-v1, th3]) verifies");
    assert_eq!(
        run.get("th2_hex"),
        load("r9-vectors-channel-handshake")["th2_hex"]
    );
    run.pass("th2 is the channel vector's");

    for case in run.get("invalid").as_array().unwrap() {
        let name = s(case, "case");
        let object = SignedObject::from_value(&case["grant"]).unwrap();
        let signer = s(object.body(), "issuer").to_owned();
        object.verify(&book.signer_public(&signer)).unwrap();
        run.pass(format!(
            "invalid {name}: well-formed and signed by {signer}"
        ));
        run.pending(format!("invalid {name}: {}", s(case, "reason")), TASK4);
    }
    run.pending("th3 with grant_hash (and principal_jcs)", TASK3);
    run.get("principal_jcs");
    run.finish();
}

#[test]
fn push_hint() {
    let mut run = Run::new("r9-vectors-push-hint");
    let book = Book::load();
    let host_key = book.signer_public("host-a");
    let secrets = run.get("recipient_secrets");

    let check_open = |run: &mut Run, name: String, hint: &Value, details: &Value| {
        let object = SignedObject::from_value(hint).unwrap();
        assert_eq!(object.label(), SignLabel::PushHint);
        assert_eq!(
            hex(object.signing_input().as_bytes()),
            s(details, "signing_input_hex")
        );
        object.verify(&host_key).unwrap();
        assert_eq!(
            sign(
                &book.provider,
                &book.signer("host-a"),
                &object.signing_input()
            )
            .unwrap(),
            object.sig()
        );
        run.pass(format!(
            "{name}: signing input, host signature (reproduced)"
        ));

        let sealed = object.sealed().unwrap();
        assert_eq!(hex(&sealed.enc), s(details, "enc_hex"));
        assert_eq!(hex(&sealed.ct), s(details, "ct_hex"));
        let device = s(details, "device_id");
        let recipient = book.public(&format!("{device}/enc"));
        let kid = enc_kid(&recipient).unwrap();
        assert_eq!(kid, s(details, "enc_kid"));
        assert_eq!(kid, s(&object.body()["recipient"], "enc_kid"));
        let as_sealed = hpke::Sealed {
            enc: sealed.enc.clone().try_into().unwrap(),
            ct: sealed.ct.clone(),
        };
        assert_eq!(as_sealed.hash().to_hex(), s(details, "sealed_hash"));
        assert_eq!(as_sealed.hash().to_hex(), s(object.body(), "sealed_hash"));
        run.pass(format!("{name}: enc_kid, sealed_hash"));

        let info = unhex(s(details, "info_hex"));
        let secret = unhex32(s(&secrets, device));
        let plain = hpke::open_with_secret(&secret, &sealed.enc, &sealed.ct, &info, b"").unwrap();
        assert_eq!(
            std::str::from_utf8(&plain).unwrap(),
            s(details, "plain_jcs")
        );
        let through_provider = book
            .provider
            .hpke_open(
                &KeyId::new(format!("{device}/enc")),
                &sealed.enc,
                &sealed.ct,
                &info,
                b"",
            )
            .unwrap();
        assert_eq!(through_provider, plain);
        let resealed = hpke::seal_with_ikm(
            recipient.as_32().unwrap(),
            &info,
            b"",
            s(details, "plain_jcs").as_bytes(),
            &unhex32(s(details, "ikmE_hex")),
        )
        .unwrap();
        assert_eq!(resealed, as_sealed);
        run.pass(format!(
            "{name}: opens for {device}; seal from ikmE reproduces enc and ct"
        ));
        run.pending(format!("{name}: seal info from the hint's fields"), TASK4);
    };

    let open = run.get("open");
    let open_details = run.get("open_details");
    for (i, (hint, details)) in open
        .as_array()
        .unwrap()
        .iter()
        .zip(open_details.as_array().unwrap())
        .enumerate()
    {
        check_open(&mut run, format!("open[{i}]"), hint, details);
    }
    for name in ["open_g75", "open_g75001"] {
        let hint = run.get(name);
        let details = run.get(&format!("{name}_details"));
        check_open(&mut run, name.to_owned(), &hint, &details);
        run.pending(format!("{name}: {}", s(&details, "note")), TASK4);
    }

    let resolved = SignedObject::from_value(&run.get("resolved")).unwrap();
    resolved.verify(&host_key).unwrap();
    assert!(resolved.sealed().is_none());
    run.pass("resolved: host signature");

    let seen = SignedObject::from_value(&run.get("seen")).unwrap();
    assert_eq!(seen.label(), SignLabel::Seen);
    assert_eq!(
        hex(seen.signing_input().as_bytes()),
        run.get("seen_signing_input_hex").as_str().unwrap()
    );
    seen.verify(&host_key).unwrap();
    run.pass("seen: signing input, host signature");
    let other = run.get("seen_other_process_gen");
    let other_object = SignedObject::from_value(&serde_json::json!({
        "body": other["body"].clone(), "sig": other["sig"].clone()
    }))
    .unwrap();
    assert_eq!(
        hex(other_object.signing_input().as_bytes()),
        s(&other, "signing_input_hex")
    );
    other_object.verify(&host_key).unwrap();
    run.pass("seen_other_process_gen: signing input, host signature");
    run.pending(
        "seen_other_process_gen: identity never matches open[0]",
        TASK4,
    );

    for (i, case) in run.get("invalid").as_array().unwrap().iter().enumerate() {
        let object = SignedObject::from_value(&case["hint"]).unwrap();
        object.verify(&host_key).unwrap();
        run.pass(format!("invalid[{i}]: well-formed and host-signed"));
        run.pending(format!("invalid[{i}]: {}", s(case, "reason")), TASK4);
    }
    run.get("verifier_now");
    run.pending(
        "verifier_now: time checks against the verifier's clock",
        TASK4,
    );
    run.finish();
}

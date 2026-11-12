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
use atem_client::canonical::StrictValue;
use atem_client::canonical::{self, Numbers, jcs};
use atem_client::channel::record::{record_aad, record_nonce};
use atem_client::channel::responder::HostContext;
use atem_client::channel::transcript::{
    Schedule, channel_id, client_signing_input, th3 as th3_of, th4,
};
use atem_client::channel::wire::{self, clear_error};
use atem_client::channel::{
    ChannelError, ClearCode, ClientProof, Direction, Failure, HeadError, HeadRelation, HostAccept,
    Initiator, Principal, Responder,
};
use atem_client::control::{
    Applied as ControlApplied, ControlAbout, ControlAction, ControlBody, ControlCheck,
    ControlError, ControlFeed, ControlPrincipal, ControlRecord, ControlSigner, ControlState,
    FeedPos, HostAction, Transition, VerifiedSigner, build_control, principal_key_of,
    verify_control,
};
use atem_client::domain::{SignLabel, SigningInput};
use atem_client::encoding::{Hash32, b64u, b64u_decode, enc, hex, u64_field};
use atem_client::host_mail::{
    EnvelopePlain, EnvelopeVerdict, ExpectedResult, HostRef, MailBody, MailFields, MailKind,
    Recipient as MailRecipient, ResultPlain, ResultVerdict, accept_result, evidence_hash,
    open_envelope, seal_envelope_with_ikm, seal_info, seal_result_with_ikm,
};
use atem_client::hpke;
use atem_client::keys::{Alg, PublicKey, ed25519_public_to_x25519, enc_kid};
use atem_client::kit::{self, RecoveryKit};
use atem_client::membership::{
    Action, Check, Entry, Head, HostNow, HostRecord, HostSenderState, Invalid, Member, MemberKind,
    Membership, RECOVERY_WAIT_MS, RecoveryState, Role, Stop,
};
use atem_client::principal::{Authority, BrowserGrant, Need, Op, Refusal as PrincipalRefusal};
use atem_client::provider::sign;
use atem_client::push::{
    self, Accepted, AlertHint, AlertKey, AlertPlain, Hint, HintBook, HintPlain, HintState,
    Refusal as PushRefusal, RelayLedger, Seen, Stage, Verdict, Verifier,
};
use atem_client::restore::restore;
use atem_client::{Error, KeyId, KeyProvider, SignedObject, SoftwareKeys};
use serde_json::Value;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// A strictly parsed copy of `value` (what a host or client gets from the wire).
fn strict(value: &Value) -> StrictValue {
    StrictValue::parse(value.to_string().as_bytes(), usize::MAX).unwrap()
}

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

/// Log L (E1–E6) as a verifier holds it.
fn log_l() -> Membership {
    let file = load("r9-vectors-membership-log");
    Context::new(&file["log"], &file["others"], genesis_hash()).chain(&[])
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
            "r9-vectors-delegated-wire.json",
            "r9-vectors-encoding.json",
            "r9-vectors-host-envelope.json",
            "r9-vectors-host-route.json",
            "r9-vectors-host-work-control.json",
            "r9-vectors-keys.json",
            "r9-vectors-membership-log.json",
            "r9-vectors-pairing.json",
            "r9-vectors-push-hint.json",
            "r9-vectors-recovery.json",
            "r9-vectors-station-calls.json",
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
    let labels: BTreeMap<String, &str> = [
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
        ("recovery/R", "recovery kit R"),
        ("not-recovery/", "not the recovery key"),
    ]
    .into_iter()
    .map(|(id, label)| (id.to_owned(), label))
    // The keys the delegated-action vectors add.
    .chain(
        DELEGATED_KEYS
            .iter()
            .map(|&(name, part, label, _)| (format!("{name}/{part}"), label)),
    )
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
                    assert!(
                        s(entry, "note").contains(&format!("\"{label}\"")),
                        "{name}: the label is published in its note"
                    );
                    run.pass(format!("{name}: R from its published test label"));
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
                    if let Some(note) = entry.get("note").and_then(Value::as_str)
                        && note.contains("label")
                    {
                        assert!(note.contains(&format!("\"{label}\"")), "{id}: {note}");
                    }
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
        (_, "svc-discord") => SigExpect::Valid("svc-discord"),
        other => panic!("no signer for {other:?}"),
    }
}

/// Context-dependent refusals of the membership-log vectors: they need the
/// chain, the verifier's pending state or the action rules.
fn chain_reason(label: &str) -> Option<&'static str> {
    match label {
        "X7_ipad" => Some("invalid: signer not a manager at the head: signer_not_manager"),
        "X5_svc91d" => Some("invalid: service expiry over 90 days: service_expiry"),
        "R7_roles" => {
            Some("invalid: recovery_add roles not exactly control/manage/view: bad_roles")
        }
        "R7_remove" => {
            Some("invalid: the recovery signer may only recovery_add: recovery_signer_action")
        }
        "A8_ipad" | "V8_ipad" => Some("invalid: signer_not_manager"),
        "R8_oldkit" | "R8_oldkit_after_lost" => Some("invalid: recovery_key_retired"),
        "A8_k_self" => Some("invalid: self_approval"),
        "KB8_stale" => Some("invalid: blob_version_not_increasing"),
        // The delegated host-work actions (II.2.2, II.3.1, II.4.1).
        "P11_remove_again" => Some("invalid: no project of that name in effect: not_a_project"),
        "P9_bad_project" => Some("invalid: notify without message: bad_project"),
        "P7_not_a_host" | "EK7_not_a_host" => {
            Some("invalid: host-b isn't a current host: not_a_host")
        }
        "EK8_same_key" => Some("invalid: the host's current key set again: enc_key_reused"),
        "EK8_bad_enc_sig" => Some("invalid: enc_sig over another key's binding: bad_enc_sig"),
        "EK8_retire_false" => Some("invalid: retire_previous present as false: malformed"),
        "EK9_stale_gen" => {
            Some("invalid: generation 1 after a newer add_host: host_trust_gen_not_current")
        }
        "HS8_revoke_again" => Some("invalid: a revoke in revoked: already_revoked"),
        "HS7_readmit_authorized" | "HS7_readmit_unknown" => {
            Some("invalid: a readmit of a host that isn't revoked: not_revoked")
        }
        "HS7_revoke_unknown" => Some("invalid: no add_host names the host: unknown_host"),
        "EK9_removed_host" | "P10_set_removed_host" => {
            Some("invalid: the host was added but is removed: not_a_host")
        }
        "P9_bad_name" => Some("invalid: a name outside [a-z0-9-]: bad_project"),
        "P9_one_host" => Some("invalid: one host listed: bad_project"),
        "P9_unknown_op" => Some("invalid: an unknown op: bad_project"),
        "EK9_previous_again" => Some("invalid: the host's previous key set again: enc_key_reused"),
        "EK10_retired_again" => Some("invalid: a retired key set again: enc_key_reused"),
        "EK10_dropped_again" => Some("invalid: a key no longer kept set again: enc_key_reused"),
        "HS7_revoke_no_interrupt" => Some("invalid: a revoke without interrupt_running: malformed"),
        "HS8_readmit_interrupt" => Some("invalid: interrupt_running on a readmit: unknown_field"),
        "EK7_gen_zero" => Some("invalid: host_trust_gen 0: malformed"),
        "EK7_short_enc_sig" | "EK7_long_enc_sig" => {
            Some("invalid: an enc_sig of 63 or 65 bytes: malformed")
        }
        "EK7_ed25519_enc_key" => Some("invalid: an Ed25519 enc_key: wrong_alg"),
        "P9_unknown_field" => Some("invalid: a fourth field in project: unknown_field"),
        "P9_hosts_unsorted" | "P9_hosts_duplicate" => {
            Some("invalid: project.hosts isn't a canonical set: array_not_canonical")
        }
        "P9_empty_ops" => Some("invalid: no ops: bad_project"),
        "P9_64_hosts" => Some("invalid: 64 hosts, none added: not_a_host"),
        "P9_65_hosts" => Some("invalid: 65 hosts: bad_project"),
        "P9_remove_bad_name" => Some("invalid: a name outside [a-z0-9-]: bad_project"),
        "HS7_revoke_by_service" => Some("invalid: signed by a service: signer_not_manager"),
        "P9_set_by_recovery" => {
            Some("invalid: the recovery key signs recovery_add only: recovery_signer_action")
        }
        _ => None,
    }
}

/// The membership-log vectors as entries, and chains built from them on a
/// verifier's clock.
struct Context {
    vectors: BTreeMap<String, Value>,
    genesis: Hash32,
    now: HostNow,
}

impl Context {
    fn new(log: &Value, others: &Value, genesis: Hash32) -> Self {
        let vectors = log
            .as_array()
            .unwrap()
            .iter()
            .chain(others.as_array().unwrap())
            .map(|v| (s(v, "label").to_owned(), v.clone()))
            .collect();
        Context {
            vectors,
            genesis,
            now: HostNow {
                wall_ms: 1_793_177_601_000,
                mono_ms: 1_000,
                boot_id: "boot-1".into(),
            },
        }
    }

    fn parse(&self, label: &str) -> Result<Entry, Invalid> {
        Entry::from_strict(&strict(&self.vectors[label]["entry"]))
    }

    fn entry(&self, label: &str) -> Entry {
        self.parse(label).unwrap_or_else(|e| panic!("{label}: {e}"))
    }

    /// Log L (E1–E6) followed by `more`.
    fn chain(&self, more: &[&str]) -> Membership {
        let labels = ["E1", "E2", "E3", "E4", "E5", "E6"].iter().chain(more);
        let entries: Vec<Entry> = labels.map(|l| self.entry(l)).collect();
        let verified =
            Membership::verify_chain("acct-test-1", &self.genesis, &entries, &self.now).unwrap();
        assert!(verified.deferred.is_none());
        verified.membership
    }

    /// Checks `label` as the next entry after L + `more`.
    fn check(&self, more: &[&str], label: &str) -> Check {
        self.chain(more).check_next(&self.entry(label))
    }

    fn hash(&self, label: &str) -> Hash32 {
        self.entry(label).hash()
    }

    /// The vector's refusal in its context: the `membership_invalid` detail.
    fn refusal(&self, label: &str) -> String {
        let invalid = |check: Check| match check {
            Check::Invalid(reason) => reason.code().to_owned(),
            other => panic!("{label}: {other:?}"),
        };
        // The delegated-action vectors name their context.
        if self.vectors[label].get("chain").is_some() {
            let chain = chain_labels(&self.vectors[label]);
            return match self.parse(label) {
                Err(reason) => reason.code().to_owned(),
                Ok(entry) => invalid(self.chain(&chain).check_next(&entry)),
            };
        }
        match label {
            "X5_svc91d" | "R7_roles" | "R7_remove" => {
                self.parse(label).unwrap_err().code().to_owned()
            }
            "X7_ipad" => invalid(self.check(&[], label)),
            "A8_ipad" | "V8_ipad" => invalid(self.check(&["R7"], label)),
            "R8_oldkit" => invalid(self.check(&["K7_current"], label)),
            "R8_oldkit_after_lost" => {
                // Valid while K7_lost is pending (the old kit is still
                // current); retired once the replacement takes effect.
                let mut m = self.chain(&["K7_lost"]);
                assert_eq!(m.check_next(&self.entry(label)), Check::Valid);
                let mut later = self.now.clone();
                later.wall_ms += RECOVERY_WAIT_MS;
                later.mono_ms += RECOVERY_WAIT_MS;
                m.advance(&later);
                invalid(m.check_next(&self.entry(label)))
            }
            "A8_k_self" => invalid(self.check(&["K7_lost"], label)),
            "KB8_stale" => invalid(self.check(&["KB7"], label)),
            other => panic!("no context for {other}"),
        }
    }
}

/// Every alternative in its context (§R9.2–§R9.5): validity, deferral,
/// pending recovery and kit replacement, and the conflict rule.
fn alternatives_in_context(run: &mut Run, ctx: &Context) {
    let state = |m: &Membership, label: &str| m.record(&ctx.hash(label)).unwrap().state();
    let conflict = |base: &[&str], label: &str| {
        let m = ctx.chain(base);
        let wire = &ctx.vectors[label]["entry"];
        let eval = m.evaluate(&[strict(wire)], &ctx.now);
        match eval.stop {
            Some(Stop::Conflict { outcome, .. }) => outcome,
            other => panic!("{label}: {other:?}"),
        }
    };

    // Plain successors and a bad signature.
    assert_eq!(ctx.check(&[], "E7"), Check::Valid);
    assert_eq!(ctx.hash("E7_retry"), ctx.hash("E7"));
    assert_eq!(
        ctx.check(&["E7"], "X8_badsig"),
        Check::Invalid(Invalid::BadSignature)
    );
    let before_e6 = Membership::verify_chain(
        "acct-test-1",
        &ctx.genesis,
        &["E1", "E2", "E3", "E4", "E5"].map(|l| ctx.entry(l)),
        &ctx.now,
    )
    .unwrap()
    .membership;
    assert_eq!(before_e6.check_next(&ctx.entry("S6_phone")), Check::Valid);
    run.pass("E7 on L, X8_badsig refused bad_signature, S6_phone valid on E5");

    // Conflicts at seq 6 against L (§R9.4).
    use atem_client::membership::{Conflict, EvidenceReason};
    assert_eq!(
        conflict(&[], "C6_ipad"),
        Conflict::Ignored(EvidenceReason::SignerRemoved)
    );
    assert_eq!(conflict(&[], "C6_mac"), Conflict::Freeze);
    assert_eq!(conflict(&[], "S6_phone"), Conflict::Freeze);
    assert_eq!(conflict(&[], "R6_conflict"), Conflict::Freeze);
    run.pass("C6_ipad ignored (signer removed); C6_mac, S6_phone, R6_conflict freeze");

    // Recovery entries and decisions.
    assert_eq!(ctx.check(&[], "R7"), Check::Valid);
    assert_eq!(
        ctx.check(&[], "R7_wrong_key"),
        Check::Invalid(Invalid::BadSignature)
    );
    assert_eq!(ctx.check(&[], "R7_backdated"), Check::Valid);
    let m = ctx.chain(&["R7"]);
    assert_eq!(state(&m, "R7"), RecoveryState::Pending);
    assert_eq!(
        m.check_next(&ctx.entry("N8")),
        Check::Deferred(ctx.hash("R7"))
    );
    assert_eq!(
        state(&ctx.chain(&["R7", "A8"]), "R7"),
        RecoveryState::Active
    );
    assert_eq!(
        state(&ctx.chain(&["R7", "V8"]), "R7"),
        RecoveryState::Cancelled
    );
    let mut later = ctx.now.clone();
    later.wall_ms += RECOVERY_WAIT_MS;
    later.mono_ms += RECOVERY_WAIT_MS;
    let mut waited = ctx.chain(&["R7"]);
    waited.advance(&later);
    assert_eq!(state(&waited, "R7"), RecoveryState::Active);
    assert_eq!(waited.check_next(&ctx.entry("N8")), Check::Valid);
    run.pass("R7 pending (R7_wrong_key refused); A8 activates, V8 cancels, 24 h activates; N8 deferred, then valid");

    // Kit replacement both ways.
    let current = ctx.chain(&["K7_current"]);
    assert_ne!(*current.recovery_key(), *ctx.chain(&[]).recovery_key());
    assert_eq!(
        ctx.parse("K7_current_no_kit_sig").unwrap_err(),
        Invalid::KitSigMissing
    );
    assert_eq!(current.check_next(&ctx.entry("R8_newkit")), Check::Valid);
    let lost = ctx.chain(&["K7_lost"]);
    assert_eq!(state(&lost, "K7_lost"), RecoveryState::Pending);
    let vetoed = ctx.chain(&["K7_lost", "V8_k"]);
    assert_eq!(state(&vetoed, "K7_lost"), RecoveryState::Cancelled);
    assert_eq!(vetoed.recovery_key(), ctx.chain(&[]).recovery_key());
    run.pass("K7_current in effect at once (R8_newkit valid); K7_lost pending, V8_k cancels it");

    // K backups.
    let kb = ctx.chain(&["KB7", "KB8"]);
    assert_eq!(kb.k_backup().unwrap().blob_version, 4);
    assert_eq!(ctx.check(&["KB7"], "KB8_badct"), Check::Valid);
    run.pass("KB7 then KB8 (version 3 → 4), KB8_badct valid on KB7");

    // The substitute chain: valid under its own genesis, never under E1's.
    let sub = ["SUB1", "SUB2", "SUB3"].map(|l| ctx.entry(l));
    let own = Membership::verify_chain("acct-test-1", &sub[0].hash(), &sub, &ctx.now).unwrap();
    assert_eq!(own.membership.head().seq, 3);
    assert_eq!(
        Membership::verify_chain("acct-test-1", &ctx.genesis, &sub, &ctx.now)
            .unwrap_err()
            .reason,
        Invalid::GenesisMismatch
    );
    run.pass("SUB1–SUB3 verify on their own genesis and are refused genesis_mismatch under E1");
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
    let context = Context::new(&log, &others, genesis);

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
                SignedObject::from_strict(&strict(&vector["entry"])),
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
        if vector.get("reason") == Some(&Value::from("array_not_canonical")) {
            // Refused by the signed-object parse itself (a set out of
            // order), before the action is read: its values are checked
            // from the body as written.
            assert_eq!(
                SignedObject::from_strict(&strict(&vector["entry"])),
                Err(Error::ArrayNotCanonical),
                "{label}"
            );
            let body_jcs = jcs(body).unwrap();
            assert_eq!(body_jcs, s(vector, "jcs"), "{label}");
            let input = SigningInput::new(SignLabel::MembershipEntry, body_jcs.as_bytes());
            assert_eq!(hex(input.as_bytes()), s(vector, "signing_input_hex"));
            let hash = Hash32::of_enc(&[b"atem-membership-hash-v1", body_jcs.as_bytes()]);
            assert_eq!(hash.to_hex(), s(vector, "entry_hash"), "{label}");
            let SigExpect::Valid(name) = signer_of(label, s(body, "signer")) else {
                panic!("{label}: a valid signature expected");
            };
            let sig = b64u_decode(s(&vector["entry"], "sig")).unwrap();
            book.signer_public(name).verify(&input, &sig).unwrap();
            assert_eq!(
                sign(&book.provider, &book.signer(name), &input).unwrap(),
                sig,
                "{label}: deterministic signature"
            );
            let reason = chain_reason(label).unwrap();
            assert_eq!(context.refusal(label), "array_not_canonical", "{label}");
            assert!(reason.ends_with("array_not_canonical"), "{label}");
            run.pass(format!(
                "{label}: refused array_not_canonical by the signed-object parse; jcs, signing input, entry_hash, signature by {name}"
            ));
            continue;
        }
        let object = SignedObject::from_strict(&strict(&vector["entry"]))
            .unwrap_or_else(|e| panic!("{label}: {e}"));
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
            let detail = context.refusal(label);
            assert!(reason.ends_with(&detail), "{label}: {detail}");
            run.pass(format!("{label}: {reason} (in context)"));
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
    let l = context.chain(&[]);
    assert_eq!(l.head().seq, 6);
    assert_eq!(l.head().hash.to_hex(), s(&head, "hash"));
    assert_eq!(l.members(), ["dev-mac", "dev-phone", "svc-discord"]);
    assert!(l.host("host-a").is_some());
    run.pass("log L E1–E6: chain verification (seq, prev_hash, signers in effect, action rules)");
    alternatives_in_context(&mut run, &context);
    let file = run.file.clone();
    delegated_in_context(&mut run, &context, &book, &file);
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
    let envelope = KBackupEnvelope::from_strict(&strict(&vector["wire"])).unwrap();
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
            Some(Error::KitTagMismatch)
        );
        assert_eq!(
            RecoveryKit::read(r, account, Hash32([0u8; 32]), &tag).err(),
            Some(Error::KitTagMismatch)
        );
        let mut flipped = tag;
        flipped[15] ^= 1;
        assert_eq!(
            RecoveryKit::read(r, account, genesis, &flipped).err(),
            Some(Error::KitTagMismatch)
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
    let object = SignedObject::from_strict(&strict(&vector["entry"])).unwrap();
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
    let sub1 = SignedObject::from_strict(&strict(&entry("SUB1")["entry"])).unwrap();
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

    // The restore flow over these vectors (§R9.5 "Restore"; the scenarios
    // r9-recovery-restore-* run it step by step).
    let entries = |labels: &[&str]| -> Vec<Entry> {
        labels
            .iter()
            .map(|l| Entry::from_strict(&strict(&entry(l)["entry"])).unwrap())
            .collect()
    };
    let full = entries(&["E1", "E2", "E3", "E4", "E5", "E6", "KB7", "KB8"]);
    let kb8 = full.last().unwrap();
    // Each host's head as restore gets it: an init/accept pair signed with
    // the host key (host-a's real key, or host-evil's for the substitute).
    let accept_by = |key: &str, entry: &Entry| {
        let mut pair = HostAccept {
            e_c: [1; 32],
            n_c: [2; 32],
            genesis_hash: entries(&["E1"])[0].hash(),
            host_id: "host-a".into(),
            host_trust_gen: 1,
            e_h: [3; 32],
            n_h: [4; 32],
            head: Head {
                seq: entry.seq,
                hash: entry.hash(),
            },
            sig: Vec::new(),
        };
        if key == "host-evil" {
            pair.genesis_hash = entries(&["SUB1"])[0].hash();
        }
        pair.sig = sign(&book.provider, &book.signer(key), &pair.signing_input()).unwrap();
        pair
    };
    let host_head = |entry: &Entry| accept_by("host-a", entry);
    let now = HostNow {
        wall_ms: 1_793_264_200_000,
        mono_ms: 1,
        boot_id: "b".into(),
    };
    let env4 = v_env4["wire"].to_string();
    let env3 = v_env3["wire"].to_string();
    let restored = restore(&kit1, &full, env4.as_bytes(), &[host_head(kb8)], &now).unwrap();
    assert_eq!(restored.keys.len(), 3);
    assert_eq!(restored.keys[0].kid, s(&book.keys["K-gen-3"], "kid"));
    let fail = |kit: &RecoveryKit, log: &[Entry], blob: &str, heads: &[HostAccept]| {
        restore(kit, log, blob.as_bytes(), heads, &now)
            .err()
            .unwrap()
            .code()
    };
    assert_eq!(fail(&kit1, &full, &env4, &[]), "no_host_reachable");
    assert_eq!(
        fail(&kit1, &full[..7], &env3, &[host_head(kb8)]),
        "log_behind_host"
    );
    assert_eq!(
        fail(&kit1, &full, &env3, &[host_head(kb8)]),
        "backup_hash_mismatch"
    );
    assert_eq!(
        fail(&kit2, &full, &env4, &[host_head(kb8)]),
        "kit_not_current"
    );
    let sub = entries(&["SUB1", "SUB2", "SUB3"]);
    let sub_blob = sub_env.jcs();
    assert_eq!(
        fail(&kit1, &sub, &sub_blob, &[accept_by("host-evil", &sub[2])]),
        "genesis_mismatch"
    );
    let member = Member {
        device_id: "dev-newmac".into(),
        auth_key: book.signer_public("dev-newmac"),
        kind: MemberKind::Native {
            enc_key: book.public("dev-newmac/enc"),
            roles: [Role::Control, Role::Manage, Role::View].into(),
        },
    };
    let published = restored.recovery_add(&kit1, member, 1).unwrap();
    assert_eq!((published.seq, published.prev_hash), (9, kb8.hash()));
    assert_eq!(restored.log.check_next(&published), Check::Valid);
    run.pass("restore flow: kit anchor, host-signed head, kit_not_current, backup_hash_mismatch, K opened, recovery_add published on the confirmed head");
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

    // th2 and sig_h from the init/accept messages, verified with host-a's
    // key from log L (HostAccept, §R9.7 steps 2–3).
    let ml = load("r9-vectors-membership-log");
    let ctx = Context::new(&ml["log"], &ml["others"], genesis_hash());
    let log_l = ctx.chain(&[]);
    let pair = HostAccept::from_messages(&strict(&init), &strict(&accept)).unwrap();
    assert_eq!(pair.th2().to_hex(), run.get("th2_hex").as_str().unwrap());
    let th2_input = run.get("th2_input_hex");
    assert_eq!(Hash32::of(&unhex(th2_input.as_str().unwrap())), pair.th2());
    assert_eq!(
        hex(pair.signing_input().as_bytes()),
        run.get("sig_h_input_hex").as_str().unwrap()
    );
    let verified = pair.verify(&log_l).unwrap();
    assert_eq!(verified.head(), log_l.head());
    run.pass("th2 from its transcript input, and sig_h verified with host-a's key from log L");

    // The whole handshake through both state machines with the vector's
    // ephemerals and nonces: every message and value byte for byte.
    let e_c_secret = unhex32(s(&inputs, "e_c_secret_hex"));
    let e_h_secret = unhex32(s(&inputs, "e_h_secret_hex"));
    let n_c = unhex32(s(&inputs, "n_c_hex"));
    let n_h = unhex32(s(&inputs, "n_h_hex"));
    let host_signer = book.signer("host-a");
    let host_ctx = HostContext {
        log: &log_l,
        host_id: "host-a",
        host_trust_gen: 1,
        provider: &book.provider,
        key: &host_signer,
    };
    let (client, init_frame) = Initiator::start_with(&log_l, "host-a", e_c_secret, n_c, 0).unwrap();
    assert_eq!(
        wire::parse_frame(&init_frame).unwrap(),
        wire::parse_frame(init.to_string().as_bytes()).unwrap()
    );
    run.pass("init: the initiator's frame (host-a at trust gen 1 from log L)");
    let (host, accept_frame) =
        Responder::on_init_with(&host_ctx, &init_frame, e_h_secret, n_h, 0).unwrap();
    assert_eq!(
        wire::parse_frame(&accept_frame).unwrap(),
        wire::parse_frame(accept.to_string().as_bytes()).unwrap()
    );
    run.pass("accept: the responder's frame (head E6, sig_h reproduced)");
    let accepted = client.on_frame(&accept_frame, &log_l, 1).unwrap();
    assert_eq!(accepted.th2(), pair.th2());
    assert_eq!(accepted.relation(), HeadRelation::Same);
    assert_eq!(accepted.host_head().head(), log_l.head());
    run.pass("the initiator verifies the accept against its log: same head");

    let schedule = Schedule::new(pair.th2(), &unhex32(ss.as_str().unwrap()));
    assert_eq!(hex(schedule.hs()), run.get("hs_hex").as_str().unwrap());
    assert_eq!(
        hex(&*schedule.finish_key()),
        run.get("k_finish_hex").as_str().unwrap()
    );
    assert_eq!(
        hex(&schedule.finish_aad()),
        run.get("finish_aad_hex").as_str().unwrap()
    );
    run.pass("hs = HKDF-Extract(th2, ss); k_fin; the finish AAD");

    let principal = Principal::Native {
        device_id: "dev-phone".into(),
    };
    assert_eq!(principal.jcs(), run.get("principal_jcs").as_str().unwrap());
    assert_eq!(
        hex(th3_of(&pair.th2(), &sig_h, &principal).as_bytes()),
        s(&run.file, "th3_hex")
    );
    let signed = accepted
        .sign(principal.clone(), &book.provider, &book.signer("dev-phone"))
        .unwrap();
    assert_eq!(hex(signed.th3().as_bytes()), s(&run.file, "th3_hex"));
    assert_eq!(
        hex(signed.sig_c()),
        s(&run.file, "sig_c_hex"),
        "RFC 6979, low S"
    );
    run.pass("principal_jcs; th3; sig_c reproduced by the initiator");

    let hello = run.get("hello_jcs");
    let hello = hello.as_str().unwrap().as_bytes();
    let hello_value: Value = serde_json::from_slice(hello).unwrap();
    assert_eq!(
        hello_value["data"]["proof"]["sig"].as_str().unwrap(),
        b64u(signed.sig_c())
    );
    assert_eq!(
        hello_value["data"]["proof"]["principal"],
        principal.to_json()
    );
    // The crate's own hello builder (Task 3 review Minor 5) reproduces the
    // vector's hello byte for byte around the sig_c it made.
    let carriage = atem_client::channel::Carriage {
        head: log_l.head(),
        entries: Vec::new(),
        more: false,
        fetch_to: None,
    };
    let hello_id = hello_value["data"]["id"].as_str().unwrap();
    assert_eq!(
        atem_client::session::r9::hello_bytes(
            hello_id,
            &principal,
            signed.sig_c(),
            &carriage,
            None
        ),
        hello
    );
    let (mut client_channel, finish_frame) =
        signed.finish_hello(hello_id, &carriage, None, 2).unwrap();
    let finish = run.get("finish");
    assert_eq!(
        wire::parse_frame(&finish_frame).unwrap(),
        wire::parse_frame(finish.to_string().as_bytes()).unwrap()
    );
    let wire::Frame::Finish { ct } = wire::parse_frame(&finish_frame).unwrap() else {
        unreachable!()
    };
    assert_eq!(hex(&ct), run.get("finish_ct_hex").as_str().unwrap());
    run.pass("finish: the crate's hello (hello_jcs) sealed under k_fin, byte for byte");

    let th4_value = th4(&signed_th3(&run), &unhex(s(&run.file, "sig_c_hex")), hello);
    assert_eq!(
        hex(th4_value.as_bytes()),
        run.get("th4_hex").as_str().unwrap()
    );
    assert_eq!(
        channel_id(&th4_value),
        run.get("channel_id").as_str().unwrap()
    );
    assert_eq!(client_channel.channel_id(), s(&run.file, "channel_id"));
    let (k_c2h, k_h2c) = schedule.record_keys(&th4_value);
    assert_eq!(hex(&*k_c2h), run.get("k_c2h_hex").as_str().unwrap());
    assert_eq!(hex(&*k_h2c), run.get("k_h2c_hex").as_str().unwrap());
    run.pass("th4, channel_id, k_c2h, k_h2c");

    let opened = host.on_finish(&finish_frame, 3).unwrap();
    assert_eq!(opened.hello(), hello);
    let keyed = opened.key(&ClientProof {
        principal: principal.clone(),
        sig_c: unhex(s(&run.file, "sig_c_hex")),
    });
    assert_eq!(keyed.channel_id(), s(&run.file, "channel_id"));
    let mut host_channel = keyed.admit(&client_key, u64::MAX).unwrap();
    run.pass("the responder opens the finish, derives th4 and admits sig_c with dev-phone's key");

    let records = run.get("records");
    let records = records.as_array().unwrap();
    for (i, record) in records.iter().enumerate() {
        let dir = match s(record, "dir") {
            "c2h" => Direction::C2h,
            "h2c" => Direction::H2c,
            other => panic!("dir {other}"),
        };
        let counter = record["counter"].as_u64().unwrap();
        assert_eq!(hex(&record_aad(dir)), s(record, "aad_hex"));
        assert_eq!(hex(&record_nonce(counter)), s(record, "nonce_hex"));
        let plain = s(record, "plain_jcs").as_bytes();
        let (sender, receiver) = match dir {
            Direction::C2h => (&mut client_channel, &mut host_channel),
            Direction::H2c => (&mut host_channel, &mut client_channel),
        };
        assert_eq!(sender.counters().0, counter, "record {i}");
        let frame = sender.seal(plain, 4).unwrap();
        let wire::Frame::Rec { ct } = wire::parse_frame(&frame).unwrap() else {
            unreachable!()
        };
        assert_eq!(hex(&ct), s(record, "ct_hex"), "record {i}");
        assert_eq!(&**receiver.open(&frame, 4).unwrap(), plain);
    }
    run.pass("records: welcome h2c 0, list c2h 0 and 1, sealed and opened byte for byte");

    let rec = |ct_hex: &str| wire::Frame::Rec { ct: unhex(ct_hex) }.to_bytes();
    // A fresh host channel at the vector's keys (the same ephemerals): what
    // a host that has seen n records does with each negative case.
    let sig_c_vector = unhex(s(&run.file, "sig_c_hex"));
    let fresh_pair = || {
        let (client, init_frame) =
            Initiator::start_with(&log_l, "host-a", e_c_secret, n_c, 0).unwrap();
        let (host, accept_frame) =
            Responder::on_init_with(&host_ctx, &init_frame, e_h_secret, n_h, 0).unwrap();
        let signed = client
            .on_frame(&accept_frame, &log_l, 0)
            .unwrap()
            .sign(principal.clone(), &book.provider, &book.signer("dev-phone"))
            .unwrap();
        let (client_channel, finish_frame) = signed.finish(hello, 0).unwrap();
        let host_channel = host
            .on_finish(&finish_frame, 0)
            .unwrap()
            .key(&ClientProof {
                principal: principal.clone(),
                sig_c: sig_c_vector.clone(),
            })
            .admit(&client_key, u64::MAX)
            .unwrap();
        (client_channel, host_channel, finish_frame)
    };
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
                // The host, on an init with that ephemeral: clear
                // handshake_failed, before any key exists.
                let mut zero_init = init.clone();
                zero_init["e"] = Value::String(b64u(&peer));
                let refused = Responder::on_init_with(
                    &host_ctx,
                    zero_init.to_string().as_bytes(),
                    e_h_secret,
                    n_h,
                    0,
                )
                .err()
                .unwrap();
                assert_eq!(
                    refused.error,
                    ChannelError::HandshakeFailed(Failure::ZeroSharedSecret)
                );
                assert_eq!(
                    refused.reply.as_deref(),
                    Some(&clear_error(ClearCode::HandshakeFailed)[..])
                );
                // The client, on a correctly signed accept with it: refused,
                // nothing sent.
                let (client, init_frame) =
                    Initiator::start_with(&log_l, "host-a", e_c_secret, n_c, 0).unwrap();
                let wire::Frame::Init(sent) = wire::parse_frame(&init_frame).unwrap() else {
                    unreachable!()
                };
                let mut forged = wire::Accept {
                    e: peer,
                    n: n_h,
                    head: log_l.head(),
                    sig: Vec::new(),
                };
                forged.sig = sign(
                    &book.provider,
                    &host_signer,
                    &HostAccept::new(&sent, &forged).signing_input(),
                )
                .unwrap();
                assert_eq!(
                    client
                        .on_frame(&wire::Frame::Accept(forged).to_bytes(), &log_l, 0)
                        .err(),
                    Some(ChannelError::HandshakeFailed(Failure::ZeroSharedSecret))
                );
                run.pass(
                    "negative zero_shared_secret: refused before any HKDF, by both state machines",
                );
            }
            "tampered_head" => {
                assert_eq!(case["sig_h_valid"], false);
                let input = SigningInput::new(SignLabel::ChannelHost, &unhex(s(case, "th2_hex")));
                assert_eq!(host_key.verify(&input, &sig_h), Err(Error::BadSignature));
                let mut rewritten = accept.clone();
                rewritten["head"] = case["head"].clone();
                let forged =
                    HostAccept::from_messages(&strict(&init), &strict(&rewritten)).unwrap();
                assert_eq!(forged.th2().to_hex(), s(case, "th2_hex"));
                assert_eq!(forged.verify(&log_l), Err(HeadError::BadSignature));
                let (client, _) =
                    Initiator::start_with(&log_l, "host-a", e_c_secret, n_c, 0).unwrap();
                assert_eq!(
                    client
                        .on_frame(rewritten.to_string().as_bytes(), &log_l, 0)
                        .err(),
                    Some(ChannelError::HandshakeFailed(Failure::BadHostSignature))
                );
                run.pass("negative tampered_head: th2 from the rewritten head; sig_h refused by the initiator");
            }
            "replayed_finish" => {
                // The second channel's host values are public only: its th2,
                // sig_h and k_finish from the client's side of that channel.
                let e_h2 = unhex32(s(case, "e_h_hex"));
                let mut second = pair.clone();
                second.e_h = e_h2;
                second.n_h = unhex32(s(case, "n_h_hex"));
                assert_eq!(second.th2().to_hex(), s(case, "th2_hex"));
                host_key
                    .verify(&second.signing_input(), &unhex(s(case, "sig_h_hex")))
                    .unwrap();
                let ss2 = eph.x25519(&KeyId::new("e_c"), &e_h2).unwrap();
                let schedule2 = Schedule::new(second.th2(), &ss2);
                assert_eq!(hex(&*schedule2.finish_key()), s(case, "k_finish_hex"));
                assert_eq!(case["opens"], false);
                assert!(schedule2.open_finish(&ct).is_none());
                // And through the responder: a new channel (fresh e_h, n_h)
                // refuses the replayed finish in the clear.
                let (host2, _) = Responder::on_init(&host_ctx, &init_frame, 0).unwrap();
                let refused = host2.on_finish(&finish_frame, 0).err().unwrap();
                assert_eq!(
                    refused.error,
                    ChannelError::HandshakeFailed(Failure::FinishTag)
                );
                assert_eq!(
                    refused.reply.as_deref(),
                    Some(&clear_error(ClearCode::HandshakeFailed)[..])
                );
                run.pass("negative replayed_finish: th2, sig_h and k_finish of the second channel; the tag fails");
            }
            "tampered_finish" => {
                assert_eq!(case["opens"], false);
                let (host, _) =
                    Responder::on_init_with(&host_ctx, &init_frame, e_h_secret, n_h, 0).unwrap();
                let tampered = wire::Frame::Finish {
                    ct: unhex(s(case, "ct_hex")),
                }
                .to_bytes();
                let refused = host.on_finish(&tampered, 0).err().unwrap();
                assert_eq!(
                    refused.error,
                    ChannelError::HandshakeFailed(Failure::FinishTag)
                );
                assert_eq!(
                    refused.reply.as_deref(),
                    Some(&clear_error(ClearCode::HandshakeFailed)[..])
                );
                run.pass("negative tampered_finish: the responder refuses it in the clear");
            }
            "replayed_record" => {
                assert_eq!(case["opens"], false);
                assert_eq!(case["expected_counter"], 1);
                let (mut client, mut host, _) = fresh_pair();
                let first = client
                    .seal(s(&records[1], "plain_jcs").as_bytes(), 0)
                    .unwrap();
                host.open(&first, 0).unwrap();
                assert_eq!(
                    host.open(&rec(s(case, "ct_hex")), 0).err(),
                    Some(ChannelError::RecordRejected)
                );
                assert!(host.is_closed());
                run.pass(
                    "negative replayed_record: counter 0 again where 1 is due closes the channel",
                );
            }
            "direction_confusion" => {
                assert_eq!(case["opens"], false);
                let (mut client, _, _) = fresh_pair();
                assert_eq!(
                    client.open(&rec(s(case, "ct_hex")), 0).err(),
                    Some(ChannelError::RecordRejected)
                );
                assert!(client.is_closed());
                run.pass(
                    "negative direction_confusion: a c2h record at the h2c receiver closes it",
                );
            }
            other => panic!("unknown negative case {other}"),
        }
    }
    run.finish();
}

/// The vector's `th3` (what the host recomputes from the hello's proof).
fn signed_th3(run: &Run) -> Hash32 {
    Hash32::from_hex(s(&run.file, "th3_hex")).unwrap()
}

#[test]
fn browser_grant() {
    let mut run = Run::new("r9-vectors-browser-grant");
    let book = Book::load();
    let grant = run.get("grant");
    let object = SignedObject::from_strict(&strict(&grant)).unwrap();
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

    // The grant through §R9.6's checks at host-a (log L, generation 1):
    // a view-only browser on its target session, for the rest of its hour.
    let log = log_l();
    let grant = BrowserGrant::parse(object.clone()).unwrap();
    let now = grant.issued_at + 1_000;
    let authority = Authority::of_grant(&grant, &log, "host-a", 1, now, &|_| false).unwrap();
    assert_eq!(
        authority.name(),
        "browser:7b2d8c5a-0e3f-4a41-9c9d-3e4f5a6b7c8d"
    );
    assert_eq!(authority.key, browser_key);
    assert_eq!(authority.issuer.as_deref(), Some("dev-phone"));
    assert!(authority.allows(Need::Op(Op::View)));
    assert!(!authority.allows(Need::Lease));
    assert!(!authority.allows(Need::Control));
    assert!(authority.session_in_scope("host-a", "ses-aaaaaaaaaaaa", &|_| None));
    assert!(!authority.session_in_scope("host-a", "ses-bbbbbbbbbbbb", &|_| None));
    assert_eq!(authority.authorization_ms_left(now, 86_400_000), 3_599_000);
    assert_eq!(
        Authority::of_grant(&grant, &log, "host-a", 1, grant.expires_at, &|_| false),
        Err(PrincipalRefusal::Unauthorized("expired"))
    );
    assert_eq!(
        Authority::of_grant(&grant, &log, "host-a", 1, now, &|id| id == grant.grant_id),
        Err(PrincipalRefusal::Unauthorized("grant revoked"))
    );
    assert_eq!(
        Authority::of_grant(&grant, &log, "host-a", 2, now, &|_| false),
        Err(PrincipalRefusal::Unauthorized("invalid grant"))
    );
    run.pass("grant: a view-only browser on its session at host-a; expired, revoked, other generation refused");

    for case in run.get("invalid").as_array().unwrap() {
        let name = s(case, "case");
        let object = SignedObject::from_strict(&strict(&case["grant"])).unwrap();
        let signer = s(object.body(), "issuer").to_owned();
        object.verify(&book.signer_public(&signer)).unwrap();
        run.pass(format!(
            "invalid {name}: well-formed and signed by {signer}"
        ));
        let invalid = BrowserGrant::parse(object).unwrap();
        assert_eq!(
            Authority::of_grant(&invalid, &log, "host-a", 1, now, &|_| false),
            Err(PrincipalRefusal::Unauthorized("invalid grant")),
            "{name}"
        );
        run.pass(format!(
            "invalid {name}: refused, invalid grant ({})",
            s(case, "reason")
        ));
    }
    // th3 binds the principal and the grant hash (§R9.7 step 5).
    let principal = Principal::browser(&object).unwrap();
    assert_eq!(principal.jcs(), run.get("principal_jcs").as_str().unwrap());
    let channel = load("r9-vectors-channel-handshake");
    let th2 = Hash32::from_hex(s(&channel, "th2_hex")).unwrap();
    let browser_th3 = th3_of(&th2, &unhex(s(&channel, "sig_h_hex")), &principal);
    assert_eq!(hex(browser_th3.as_bytes()), s(&run.file, "th3_hex"));
    assert_eq!(
        hex(&sign(
            &browser,
            &KeyId::new("b"),
            &client_signing_input(&browser_th3)
        )
        .unwrap()),
        s(&run.file, "sig_c_hex"),
        "RFC 6979, low S"
    );
    run.pass("th3 with principal_jcs and grant_hash; sig_c reproduced");
    run.finish();
}

#[test]
fn push_hint() {
    let mut run = Run::new("r9-vectors-push-hint");
    let book = Book::load();
    let host_key = book.signer_public("host-a");
    let secrets = run.get("recipient_secrets");

    let check_open = |run: &mut Run, name: String, hint: &Value, details: &Value| {
        let object = SignedObject::from_strict(&strict(hint)).unwrap();
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

        // The crate's own host side and recipient side.
        let log = log_l();
        let now = run.get("verifier_now").as_u64().unwrap();
        let verified = Hint::verify(&object, &log, now, Verifier::Client).unwrap();
        verified.check_sealed().unwrap();
        let HintState::Open { .. } = &verified.state() else {
            panic!("{name} is open")
        };
        assert_eq!(
            hex(&push::seal_info(
                verified.key(),
                verified.created_at(),
                verified.expires_at(),
                device,
                &kid
            )
            .unwrap()),
            s(details, "info_hex")
        );
        let opened = verified
            .open(&book.provider, &KeyId::new(format!("{device}/enc")), device)
            .unwrap();
        assert_eq!(
            serde_json::json!({"summary": opened.summary, "tool": opened.tool}).to_string(),
            s(details, "plain_jcs")
        );
        let other = if device == "dev-phone" {
            "dev-mac"
        } else {
            "dev-phone"
        };
        assert!(
            verified
                .open(&book.provider, &KeyId::new(format!("{other}/enc")), other)
                .is_err(),
            "another device can't open it"
        );
        let rebuilt = push::open_hint_with_ikm(
            &book.provider,
            &book.signer("host-a"),
            verified.key(),
            verified.created_at(),
            verified.expires_at(),
            device,
            &recipient,
            &HintPlain {
                tool: opened.tool.clone(),
                summary: opened.summary.clone(),
            },
            &unhex32(s(details, "ikmE_hex")),
        )
        .unwrap();
        assert_eq!(rebuilt, object, "the host's hint, byte for byte");
        assert_eq!(
            Hint::verify(&object, &log, now, Verifier::Relay).unwrap(),
            verified
        );
        run.pass(format!(
            "{name}: seal info from the hint's fields; verified by client and relay; opened by {device} only; rebuilt byte for byte"
        ));
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
        // The mobile stage at created_at + 60 s against the guard.
        let object = SignedObject::from_strict(&strict(&hint)).unwrap();
        let h = Hint::verify(
            &object,
            &log_l(),
            run.get("verifier_now").as_u64().unwrap(),
            Verifier::Relay,
        )
        .unwrap();
        let mobile = push::RecipientInfo {
            class: push::DeviceClass::Mobile,
            connected: false,
            immediate_mobile: false,
        };
        let (stage, due) = push::stages(h.created_at(), mobile)
            .into_iter()
            .find(|(st, _)| *st == Stage::Mobile)
            .unwrap();
        assert_eq!(due, h.created_at() + 60_000);
        let sent = push::send_now(stage, due, due, h.expires_at(), false, false);
        let later = push::send_now(
            stage,
            due,
            h.expires_at() - 15_001,
            h.expires_at(),
            false,
            false,
        );
        match name {
            "open_g75" => {
                assert_eq!(due, push::guard(h.expires_at()));
                assert!(!sent && !later, "on the guard: never sent");
            }
            _ => {
                assert_eq!(due + 1, push::guard(h.expires_at()));
                assert!(sent, "1 ms before the guard: sent");
            }
        }
        run.pass(format!("{name}: {}", s(&details, "note")));
    }

    let resolved = SignedObject::from_strict(&strict(&run.get("resolved"))).unwrap();
    resolved.verify(&host_key).unwrap();
    assert!(resolved.sealed().is_none());
    run.pass("resolved: host signature");
    let log = log_l();
    let now = run.get("verifier_now").as_u64().unwrap();
    let open0 = SignedObject::from_strict(&strict(&run.get("open")[0])).unwrap();
    let open0 = Hint::verify(&open0, &log, now, Verifier::Client).unwrap();
    let res = Hint::verify(&resolved, &log, now, Verifier::Client).unwrap();
    let HintState::Resolved {
        reason,
        resolved_at,
    } = &res.state()
    else {
        panic!("resolved")
    };
    assert_eq!(res.key(), open0.key(), "the same approval identity");
    assert_eq!(
        push::resolved_hint(
            &book.provider,
            &book.signer("host-a"),
            res.key(),
            res.created_at(),
            res.expires_at(),
            reason,
            *resolved_at
        )
        .unwrap(),
        resolved
    );
    // A resolved dominates its opens in either order.
    let mut book_a = HintBook::new();
    assert_eq!(book_a.offer(open0.clone()), Ok(Accepted::Accepted));
    assert_eq!(book_a.offer(res.clone()), Ok(Accepted::Accepted));
    assert_eq!(
        book_a.offer(open0.clone()),
        Ok(Accepted::IgnoredAfterResolved)
    );
    let mut book_b = HintBook::new();
    assert_eq!(book_b.offer(res.clone()), Ok(Accepted::Accepted));
    assert_eq!(
        book_b.offer(open0.clone()),
        Ok(Accepted::IgnoredAfterResolved)
    );
    run.pass("resolved: verified, rebuilt byte for byte, the open's identity; dominates the open in either order");

    let seen = SignedObject::from_strict(&strict(&run.get("seen"))).unwrap();
    assert_eq!(seen.label(), SignLabel::Seen);
    assert_eq!(
        hex(seen.signing_input().as_bytes()),
        run.get("seen_signing_input_hex").as_str().unwrap()
    );
    seen.verify(&host_key).unwrap();
    run.pass("seen: signing input, host signature");
    let seen_v = Seen::verify(&seen, &log).unwrap();
    assert_eq!(seen_v.key(), open0.key());
    assert!(seen_v.in_window(open0.created_at()));
    assert_eq!(
        push::seen(
            &book.provider,
            &book.signer("host-a"),
            seen_v.key(),
            seen_v.created_at(),
            seen_v.device_id(),
            seen_v.seen_at()
        )
        .unwrap(),
        seen
    );
    run.pass("seen: verified, the open's identity and window; rebuilt byte for byte");
    let other = run.get("seen_other_process_gen");
    let other_details = run.get("seen_other_process_gen_details");
    let other_object = SignedObject::from_strict(&strict(&other)).unwrap();
    assert_eq!(
        hex(other_object.signing_input().as_bytes()),
        s(&other_details, "signing_input_hex")
    );
    other_object.verify(&host_key).unwrap();
    run.pass("seen_other_process_gen: signing input, host signature");
    let other_v = Seen::verify(&other_object, &log).unwrap();
    assert_ne!(other_v.key(), open0.key());
    assert_ne!(other_v.identity(), seen_v.identity());
    let mut ledger = RelayLedger::new();
    for o in run.get("open").as_array().unwrap() {
        let o = SignedObject::from_strict(&strict(o)).unwrap();
        assert_eq!(ledger.receive_hint(&o, &log, now).0, Verdict::Accepted);
    }
    assert_eq!(
        ledger.receive_seen(&other_object, &log, now).0,
        Verdict::Pending
    );
    assert_eq!(ledger.receive_seen(&seen, &log, now).0, Verdict::Applied);
    run.pass("seen_other_process_gen: identity never matches open[0] (pending); seen applies");

    for (i, case) in run.get("invalid").as_array().unwrap().iter().enumerate() {
        let object = SignedObject::from_strict(&strict(&case["hint"])).unwrap();
        object.verify(&host_key).unwrap();
        run.pass(format!("invalid[{i}]: well-formed and host-signed"));
        // Every rule runs on the verifier's clock (verifier_now = the good
        // hint's created_at); the time rules and the duplicate check come
        // before the sealed part, so each is refused for its stated reason
        // whatever it carries (since ec54a5c they carry the sealed envelope
        // like any open hint; their sealed part is checked below).
        let client = Hint::verify(&object, &log, now, Verifier::Client);
        let relay = Hint::verify(&object, &log, now, Verifier::Relay);
        match i {
            0 => {
                assert_eq!(client, Err(PushRefusal::Skew));
                assert_eq!(relay, Err(PushRefusal::Skew));
            }
            1 | 2 => {
                assert_eq!(client, Err(PushRefusal::InvalidTimes));
                assert_eq!(relay, Err(PushRefusal::InvalidTimes));
            }
            3 => {
                let mut book = HintBook::new();
                assert_eq!(book.offer(open0.clone()), Ok(Accepted::Accepted));
                let dup = client.unwrap();
                assert_eq!(dup.check_sealed(), Ok(()), "a well-sealed envelope");
                assert_eq!(book.offer(dup), Err(PushRefusal::Duplicate));
                assert_eq!(book.opens(open0.key())[0], &open0, "the first stays");
            }
            _ => panic!("an unexpected invalid hint"),
        }
        run.pass(format!("invalid[{i}]: refused, {}", s(case, "reason")));
    }
    run.get("verifier_now");
    run.pass("verifier_now: every time rule above ran against it");
    check_outcome_unknown(&mut run, &book);
    run.finish();
}

/// The `outcome_unknown` hints of `r9-vectors-push-hint` (delegated host-work
/// design I.4.6, session-v1 R9.9): the same checks an open approval hint
/// gets (signing input, host signature, the sealed part from `ikmE`, the
/// seal `info` from the hint's fields, both verifiers, the recipient and no
/// other opening it, the host's bytes rebuilt), the ack entries, and the
/// refusals.
fn check_outcome_unknown(run: &mut Run, book: &Book) {
    let host_key = book.signer_public("host-a");
    let secrets = run.get("recipient_secrets");
    let now = run.get("verifier_now").as_u64().unwrap();
    run.get("outcome_unknown_note");
    let hints = run.get("outcome_unknown");
    let details = run.get("outcome_unknown_details");
    let acks = run.get("outcome_unknown_acks");
    let log = log_l();
    let hints = hints.as_array().unwrap();
    assert_eq!(hints.len(), 3);
    assert_eq!(details.as_array().unwrap().len(), hints.len());
    assert_eq!(acks.as_array().unwrap().len(), hints.len());
    let mut ledger = RelayLedger::new();
    let mut first: Vec<AlertHint> = Vec::new();
    for (i, ((hint, d), ack)) in hints
        .iter()
        .zip(details.as_array().unwrap())
        .zip(acks.as_array().unwrap())
        .enumerate()
    {
        let name = format!("outcome_unknown[{i}]");
        let object = SignedObject::from_strict(&strict(hint)).unwrap();
        assert_eq!(object.label(), SignLabel::PushHint);
        assert_eq!(object.body()["kind"], "outcome_unknown");
        assert_eq!(
            hex(object.signing_input().as_bytes()),
            s(d, "signing_input_hex")
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
        assert_eq!(hex(&sealed.enc), s(d, "enc_hex"));
        assert_eq!(hex(&sealed.ct), s(d, "ct_hex"));
        let device = s(d, "device_id");
        let recipient = book.public(&format!("{device}/enc"));
        let kid = enc_kid(&recipient).unwrap();
        assert_eq!(kid, s(d, "enc_kid"));
        assert_eq!(kid, s(&object.body()["recipient"], "enc_kid"));
        let as_sealed = hpke::Sealed {
            enc: sealed.enc.clone().try_into().unwrap(),
            ct: sealed.ct.clone(),
        };
        assert_eq!(as_sealed.hash().to_hex(), s(d, "sealed_hash"));
        assert_eq!(as_sealed.hash().to_hex(), s(object.body(), "sealed_hash"));
        // The ephemeral is derived from a label anyone can recompute.
        assert_eq!(
            hex(&Sha256::digest(enc(&[
                b"atem-r9-test-ikm",
                s(d, "ikm_label").as_bytes()
            ]))),
            s(d, "ikmE_hex")
        );
        run.pass(format!("{name}: enc_kid, sealed_hash, ikmE from its label"));

        let info = unhex(s(d, "info_hex"));
        let secret = unhex32(s(&secrets, device));
        let plain = hpke::open_with_secret(&secret, &sealed.enc, &sealed.ct, &info, b"").unwrap();
        assert_eq!(std::str::from_utf8(&plain).unwrap(), s(d, "plain_jcs"));
        assert_eq!(jcs(&d["facts"]).unwrap(), s(d, "plain_jcs"));
        assert_eq!(
            book.provider
                .hpke_open(
                    &KeyId::new(format!("{device}/enc")),
                    &sealed.enc,
                    &sealed.ct,
                    &info,
                    b""
                )
                .unwrap(),
            plain
        );
        let resealed = hpke::seal_with_ikm(
            recipient.as_32().unwrap(),
            &info,
            b"",
            s(d, "plain_jcs").as_bytes(),
            &unhex32(s(d, "ikmE_hex")),
        )
        .unwrap();
        assert_eq!(resealed, as_sealed);
        run.pass(format!(
            "{name}: opens for {device}; seal from ikmE reproduces enc and ct"
        ));

        // The crate's own host side and recipient side.
        let verified = AlertHint::verify(&object, &log, now, Verifier::Client).unwrap();
        verified.check_sealed().unwrap();
        assert_eq!(
            hex(&push::alert_seal_info(
                verified.key(),
                verified.created_at(),
                verified.expires_at(),
                device,
                &kid
            )
            .unwrap()),
            s(d, "info_hex")
        );
        let facts = AlertPlain {
            task_id: s(&d["facts"], "task_id").into(),
            session_id: s(&d["facts"], "session_id").into(),
            sender: s(&d["facts"], "sender").into(),
            reason: s(&d["facts"], "reason").into(),
        };
        let key = |id: &str| KeyId::new(format!("{id}/enc"));
        assert_eq!(
            verified.open(&book.provider, &key(device), device).unwrap(),
            facts
        );
        let other = if device == "dev-phone" {
            "dev-mac"
        } else {
            "dev-phone"
        };
        assert!(
            verified.open(&book.provider, &key(other), other).is_err(),
            "another device can't open it"
        );
        assert!(
            verified.open(&book.provider, &key(other), device).is_err(),
            "another enc_key can't open it"
        );
        let rebuilt = push::alert_hint_with_ikm(
            &book.provider,
            &book.signer("host-a"),
            verified.key(),
            verified.created_at(),
            verified.expires_at(),
            device,
            &recipient,
            &facts,
            &unhex32(s(d, "ikmE_hex")),
        )
        .unwrap();
        assert_eq!(rebuilt, object, "the host's hint, byte for byte");
        assert_eq!(
            AlertHint::verify(&object, &log, now, Verifier::Relay).unwrap(),
            verified
        );
        // An approval verifier never takes it.
        assert!(matches!(
            Hint::verify(&object, &log, now, Verifier::Client),
            Err(PushRefusal::Malformed(_))
        ));
        run.pass(format!(
            "{name}: seal info from the hint's fields; verified by client and relay; opened by {device} only; rebuilt byte for byte; no approval verifier takes it"
        ));

        // Its ack entry, and what the relay does with it.
        let identity = verified.identity();
        assert_eq!(identity.to_ack(), *ack, "{name}: ack entry");
        assert_eq!(push::Identity::from_ack(ack).unwrap(), identity);
        assert_eq!(
            push::parse_push_ack(&push::push_ack(std::slice::from_ref(&identity))),
            std::slice::from_ref(&identity)
        );
        assert_eq!(
            ledger.receive_hint(&object, &log, now),
            (Verdict::Accepted, Some(identity.clone())),
            "{name}"
        );
        assert_eq!(
            ledger.receive_hint(&object, &log, now + 200_000),
            (Verdict::Idempotent, Some(identity)),
            "{name}: a late resend of the same bytes"
        );
        run.pass(format!(
            "{name}: ack entry; the relay accepts it, then idempotent"
        ));
        first.push(verified);
    }
    // One alert, two recipients: the hints share the alert's identity but
    // never each other's.
    assert_eq!(first[0].key(), first[1].key());
    assert_ne!(first[0].identity(), first[1].identity());
    assert_ne!(first[0].key(), first[2].key());
    run.pass("outcome_unknown: alert A has a hint per recipient, alert B its own identity");

    for (i, case) in run
        .get("outcome_unknown_invalid")
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let name = format!("outcome_unknown_invalid[{i}]");
        let object = SignedObject::from_strict(&strict(&case["hint"])).unwrap();
        object.verify(&host_key).unwrap();
        run.pass(format!("{name}: well-formed and host-signed"));
        let code = s(case, "code");
        let client = AlertHint::verify(&object, &log, now, Verifier::Client);
        let relay = AlertHint::verify(&object, &log, now, Verifier::Relay);
        match code {
            "malformed" | "binding" | "invalid_times" | "skew" => {
                for verdict in [&client, &relay] {
                    assert_eq!(
                        verdict.as_ref().err().map(PushRefusal::code),
                        Some(code),
                        "{name}"
                    );
                }
            }
            "duplicate" => {
                let mut book = HintBook::new();
                assert_eq!(book.offer_alert(first[0].clone()), Ok(Accepted::Accepted));
                let dup = client.unwrap();
                assert_eq!(dup.check_sealed(), Ok(()), "a well-sealed envelope");
                assert_eq!(dup.identity(), first[0].identity());
                assert_eq!(book.offer_alert(dup), Err(PushRefusal::Duplicate));
                let mut ledger = RelayLedger::new();
                ledger.receive_hint(
                    &SignedObject::from_strict(&strict(&hints[0])).unwrap(),
                    &log,
                    now,
                );
                assert_eq!(
                    ledger.receive_hint(&object, &log, now).0,
                    Verdict::Refused(PushRefusal::Duplicate)
                );
            }
            "bad_sealed" => {
                let swapped = client.unwrap();
                assert_eq!(swapped.check_sealed(), Err(PushRefusal::BadSealed));
                assert_eq!(
                    HintBook::new().offer_alert(swapped.clone()),
                    Err(PushRefusal::BadSealed)
                );
                assert!(
                    swapped
                        .open(&book.provider, &KeyId::new("dev-phone/enc"), "dev-phone")
                        .is_err()
                );
                assert_eq!(
                    RelayLedger::new().receive_hint(&object, &log, now).0,
                    Verdict::Refused(PushRefusal::BadSealed)
                );
            }
            other => panic!("{name}: an unexpected code {other}"),
        }
        run.pass(format!("{name}: refused {code}, {}", s(case, "reason")));
    }
    // Hints whose sealed facts aren't a delegated task's: both verifiers
    // take them, the relay keeps them, the sealed part is the one named,
    // and the recipient refuses each at open. A host never builds one.
    let secrets = run.get("recipient_secrets");
    for (i, case) in run
        .get("outcome_unknown_invalid_facts")
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let name = format!("outcome_unknown_invalid_facts[{i}]");
        assert_eq!(s(case, "code"), "malformed");
        let object = SignedObject::from_strict(&strict(&case["hint"])).unwrap();
        object.verify(&host_key).unwrap();
        let client = AlertHint::verify(&object, &log, now, Verifier::Client).unwrap();
        assert_eq!(
            AlertHint::verify(&object, &log, now, Verifier::Relay).unwrap(),
            client
        );
        client.check_sealed().unwrap();
        assert_eq!(
            RelayLedger::new().receive_hint(&object, &log, now).0,
            Verdict::Accepted,
            "{name}: the relay never opens it"
        );
        let device = s(case, "device_id");
        let sealed = object.sealed().unwrap();
        let plain = hpke::open_with_secret(
            &unhex32(s(&secrets, device)),
            &sealed.enc,
            &sealed.ct,
            &unhex(s(case, "info_hex")),
            b"",
        )
        .unwrap();
        assert_eq!(
            std::str::from_utf8(&plain).unwrap(),
            jcs(&case["facts"]).unwrap(),
            "{name}: only the facts are wrong"
        );
        assert!(
            matches!(
                client.open(&book.provider, &KeyId::new(format!("{device}/enc")), device),
                Err(Error::Malformed(_))
            ),
            "{name}: refused at open"
        );
        let facts = AlertPlain {
            task_id: s(&case["facts"], "task_id").into(),
            session_id: s(&case["facts"], "session_id").into(),
            sender: s(&case["facts"], "sender").into(),
            reason: s(&case["facts"], "reason").into(),
        };
        assert!(
            push::alert_hint_with_ikm(
                &book.provider,
                &book.signer("host-a"),
                client.key(),
                client.created_at(),
                client.expires_at(),
                device,
                &book.public(&format!("{device}/enc")),
                &facts,
                &[7u8; 32],
            )
            .is_err(),
            "{name}: a host never builds it"
        );
        run.pass(format!(
            "{name}: verified, kept by the relay, refused at open: {}",
            s(case, "reason")
        ));
    }
    // The key type is the one the builder makes.
    let _: &AlertKey = first[0].key();
}

/// The `outcome_unknown` entries of `r9-vectors-push-hint` (kept apart from
/// the file's other fields, whose bytes never move): hints for two alerts,
/// their `details`, ack entries and refused cases. Every value comes from the
/// crate's own builders with ephemerals derived from labels
/// (`ikmE = SHA-256(enc(["atem-r9-test-ikm", label]))`).
fn outcome_unknown_vectors(book: &Book) -> BTreeMap<&'static str, Value> {
    use serde_json::json;
    let log = log_l();
    let now = load("r9-vectors-push-hint")["verifier_now"]
        .as_u64()
        .unwrap();
    let host = book.signer("host-a");
    let ikm = |label: &str| -> [u8; 32] {
        Sha256::digest(enc(&[b"atem-r9-test-ikm", label.as_bytes()])).into()
    };
    let created_at = now + 1_000;
    // Alert A: the common case, a service's task; alert B: the bounds (a
    // host sender with a 128-byte id, a 256-byte reason). Only a delegated
    // sender's UUID v4 task raises an alert: the hints whose
    // sealed facts name another are `outcome_unknown_invalid_facts`.
    struct Alert {
        name: &'static str,
        alert_id: &'static str,
        created_at: u64,
        expires_at: u64,
        facts: Value,
    }
    let alerts = [
        Alert {
            name: "A",
            alert_id: "5e2a7c91-3b4d-4f68-a1c9-0d8e6f7a2b34",
            created_at,
            expires_at: created_at + 600_000,
            facts: json!({
                "task_id": "c4d9e8f7-1a2b-4c3d-8e5f-6a7b8c9d0e1f",
                "session_id": "ses-aaaaaaaaaaaa",
                "sender": "service:svc-discord",
                "reason": "agent exited",
            }),
        },
        Alert {
            name: "B",
            alert_id: "7b3c8d02-4e5f-4a79-b2da-1e9f708b3c45",
            created_at: created_at + 1_000,
            expires_at: created_at + 1_000 + 900_000,
            facts: json!({
                "task_id": "0f1e2d3c-4b5a-4968-8776-a5b4c3d2e1f0",
                "session_id": "ses-bbbbbbbbbbbb",
                "sender": format!("host:{}", "h".repeat(128)),
                "reason": format!("write interrupted: {}", "x".repeat(256 - 19)),
            }),
        },
    ];
    assert_eq!(alerts[1].facts["reason"].as_str().unwrap().len(), 256);
    let plain_of = |facts: &Value| AlertPlain {
        task_id: s(facts, "task_id").into(),
        session_id: s(facts, "session_id").into(),
        sender: s(facts, "sender").into(),
        reason: s(facts, "reason").into(),
    };
    let key_of = |a: &Alert| AlertKey::new(&log, "host-a", 1, a.alert_id);
    let build = |a: &Alert, device: &str, label: &str| {
        push::alert_hint_with_ikm(
            &book.provider,
            &host,
            &key_of(a),
            a.created_at,
            a.expires_at,
            device,
            &book.public(&format!("{device}/enc")),
            &plain_of(&a.facts),
            &ikm(label),
        )
        .unwrap()
    };
    let mut hints = Vec::new();
    let mut details = Vec::new();
    let mut acks = Vec::new();
    for (a, device) in [
        (&alerts[0], "dev-phone"),
        (&alerts[0], "dev-mac"),
        (&alerts[1], "dev-phone"),
    ] {
        let label = format!("alert-{}-{device}", a.name);
        let object = build(a, device, &label);
        let recipient = book.public(&format!("{device}/enc"));
        let kid = enc_kid(&recipient).unwrap();
        let sealed = object.sealed().unwrap();
        let sealed_hash = hpke::Sealed {
            enc: sealed.enc.clone().try_into().unwrap(),
            ct: sealed.ct.clone(),
        }
        .hash()
        .to_hex();
        let info =
            push::alert_seal_info(&key_of(a), a.created_at, a.expires_at, device, &kid).unwrap();
        hints.push(object.to_json());
        details.push(json!({
            "alert": a.name,
            "ct_hex": hex(&sealed.ct),
            "device_id": device,
            "enc_hex": hex(&sealed.enc),
            "enc_kid": kid,
            "facts": a.facts,
            "ikmE_hex": hex(&ikm(&label)),
            "ikm_label": label,
            "info_hex": hex(&info),
            "plain_jcs": jcs(&a.facts).unwrap(),
            "sealed_hash": sealed_hash,
            "signing_input_hex": hex(object.signing_input().as_bytes()),
        }));
        acks.push(
            push::Identity::Alert {
                key: key_of(a),
                device_id: device.into(),
            }
            .to_ack(),
        );
    }

    // The refused cases: re-signed bodies carrying the first hint's sealed
    // envelope (so only their stated reason refuses them), as the approval
    // file's `invalid` do.
    let first = SignedObject::from_strict(&strict(&hints[0])).unwrap();
    let envelope = first.sealed().unwrap().clone();
    let resigned = |edit: &dyn Fn(&mut Value)| {
        let mut body = first.body().clone();
        edit(&mut body);
        SignedObject::sign(&book.provider, &host, body)
            .unwrap()
            .with_sealed(envelope.clone())
            .to_json()
    };
    let mut invalid = Vec::new();
    let mut case = |hint: Value, code: &str, reason: &str| {
        invalid.push(json!({"code": code, "hint": hint, "reason": reason}));
    };
    case(
        resigned(&|b| b["task_id"] = json!(s(&alerts[0].facts, "task_id"))),
        "malformed",
        "the task id beside the identity: only the sealed part names the task, session, sender and reason",
    );
    case(
        resigned(&|b| b["kind"] = json!("expired")),
        "malformed",
        "kind `expired`: the one kind is `outcome_unknown`",
    );
    case(
        resigned(&|b| b["state"] = json!("open")),
        "malformed",
        "an approval's `state` beside the kind",
    );
    case(
        resigned(&|b| {
            b.as_object_mut().unwrap().remove("alert_id");
            b["approval_id"] = json!(alerts[0].alert_id);
        }),
        "malformed",
        "an approval's `approval_id` where the alert's `alert_id` belongs",
    );
    case(
        resigned(&|b| {
            b["recipient"]["enc_kid"] = json!(s(&b["recipient"], "enc_kid").to_uppercase())
        }),
        "malformed",
        "recipient.enc_kid in upper case",
    );
    case(
        resigned(&|b| b["host_trust_gen"] = json!(2)),
        "binding",
        "host_trust_gen 2: not the host's newest add_host generation",
    );
    case(
        resigned(&|b| b["expires_at"] = json!(alerts[0].created_at)),
        "invalid_times",
        "expires_at <= created_at",
    );
    case(
        resigned(&|b| b["expires_at"] = json!(alerts[0].created_at + 900_001)),
        "invalid_times",
        "a window of 900001 ms: over 15 minutes",
    );
    case(
        resigned(&|b| {
            b["created_at"] = json!(now + 600_000);
            b["expires_at"] = json!(now + 1_200_000);
        }),
        "skew",
        "created_at 600000 ms after the verifier's clock (verifier now = verifier_now): refused by a client (over 300 s) and by the relay (over 120 s)",
    );
    let again = build(&alerts[0], "dev-phone", "alert-A-dev-phone-again");
    assert_ne!(again, first);
    case(
        again.to_json(),
        "duplicate",
        "the identity of outcome_unknown[0] with other bytes (another ephemeral): the first stays",
    );
    let mut swapped = first.to_json();
    swapped["ct"] = hints[1]["ct"].clone();
    case(
        swapped,
        "bad_sealed",
        "outcome_unknown[0]'s body and signature with outcome_unknown[1]'s ct: not the sealed part sealed_hash names",
    );

    // Hints a host never builds: well signed and well sealed, but their
    // sealed facts aren't a delegated sender's UUID v4 task.
    // The relay can't tell (it never opens them); the recipient refuses each
    // at open (`malformed`). Sealed here from the raw facts, since the
    // crate's builder refuses them.
    let mut invalid_facts = Vec::new();
    for (alert_id, facts, why) in [
        (
            "8c4d9e13-5f60-4b8a-93eb-2f0a819c4d56",
            json!({
                "task_id": "6ba7b810-9dad-51d1-80b4-00c04fd430c8",
                "session_id": "ses-bbbbbbbbbbbb",
                "sender": "local",
                "reason": format!("write interrupted: {}", "x".repeat(256 - 19)),
            }),
            "a local selector's UUID v5 task, sender `local`: local tasks keep v1 (their unknown outcomes expire) and raise no alert",
        ),
        (
            "9d5eaf24-6071-4c9b-a4fc-3a1b920d5e67",
            json!({
                "task_id": "1e2f3a4b-5c6d-4e7f-8091-a2b3c4d5e6f7",
                "session_id": "ses-aaaaaaaaaaaa",
                "sender": "browser:grant-1",
                "reason": "agent exited",
            }),
            "a browser grant's task: browser grants keep v1 and raise no alert",
        ),
    ] {
        let device = "dev-phone";
        let template = Alert {
            name: "invalid",
            alert_id,
            created_at,
            expires_at: created_at + 600_000,
            facts: alerts[0].facts.clone(),
        };
        let valid = build(&template, device, "unused");
        let recipient = book.public(&format!("{device}/enc"));
        let kid = enc_kid(&recipient).unwrap();
        let info = push::alert_seal_info(
            &key_of(&template),
            template.created_at,
            template.expires_at,
            device,
            &kid,
        )
        .unwrap();
        let label = format!("alert-{alert_id}-{device}-facts");
        let sealed = hpke::seal_with_ikm(
            recipient.as_32().unwrap(),
            &info,
            b"",
            jcs(&facts).unwrap().as_bytes(),
            &ikm(&label),
        )
        .unwrap();
        let mut body = valid.body().clone();
        body["sealed_hash"] = json!(sealed.hash().to_hex());
        let hint = SignedObject::sign(&book.provider, &host, body)
            .unwrap()
            .with_sealed(atem_client::signed::SealedPart {
                enc: sealed.enc.to_vec(),
                ct: sealed.ct.clone(),
            });
        invalid_facts.push(json!({
            "code": "malformed",
            "device_id": device,
            "facts": facts,
            "hint": hint.to_json(),
            "ikm_label": label,
            "info_hex": hex(&info),
            "reason": why,
        }));
    }

    BTreeMap::from([
        ("outcome_unknown", Value::Array(hints)),
        ("outcome_unknown_acks", Value::Array(acks)),
        ("outcome_unknown_details", Value::Array(details)),
        ("outcome_unknown_invalid", Value::Array(invalid)),
        ("outcome_unknown_invalid_facts", Value::Array(invalid_facts)),
        (
            "outcome_unknown_note",
            json!(
                "Hints of kind outcome_unknown (delegated host-work I.4.6): the body's type is atem-push-hint and its label atem-push-hint-v1 like an approval hint's, told apart by `kind` (no `state`, no session_id, process_gen or approval_id; `alert_id` instead). The task, session, sender and reason are only in the sealed part, jcs of {reason, sender, session_id, task_id}. info = enc([\"atem-push-seal-v1\", account_id, genesis_hash, host_id, u64(host_trust_gen), \"outcome_unknown\", alert_id, u64(created_at), u64(expires_at), device_id, enc_kid]) (11 fields; an approval's has 12). ikmE_hex = SHA-256(enc([\"atem-r9-test-ikm\", ikm_label])). Entries 0 and 1 are one alert for two recipients; entry 2 is another alert at the bounds. Only a delegated sender's (member:, service: or host:) UUID v4 task raises an alert. outcome_unknown_acks are the push_ack entries, one per hint. Each outcome_unknown_invalid carries the first hint's sealed envelope (except bad_sealed's, which is the point) so only its code refuses it; the runner checks the code with both verifiers. Each outcome_unknown_invalid_facts is well signed and well sealed (both verifiers take it, and its sealed_hash names its sealed part), but its sealed facts aren't a delegated task's: the recipient refuses it at open (malformed)."
            ),
        ),
    ])
}

/// Adds the `outcome_unknown` entries to `r9-vectors-push-hint`: text
/// insertion between `open_g75_details` and `recipient_secrets`, so every
/// other byte of the file stays (it isn't serde's own pretty form: the
/// refused hints keep `enc` before `ct`). A file that already has them is
/// rewritten from the old fields.
#[test]
#[ignore = "writes the outcome_unknown push hint vectors"]
fn write_outcome_unknown_vectors() {
    let path = fixtures_dir().join("r9-vectors-push-hint.json");
    let mut text = std::fs::read_to_string(&path).unwrap();
    let anchor = "  \"recipient_secrets\": {\n";
    if let Some(start) = text.find("  \"outcome_unknown\": [") {
        let end = text.find(anchor).unwrap();
        text.replace_range(start..end, "");
    }
    let fields = outcome_unknown_vectors(&Book::load());
    let pretty = serde_json::to_string_pretty(&serde_json::Map::from_iter(
        fields.iter().map(|(k, v)| ((*k).to_owned(), v.clone())),
    ))
    .unwrap();
    let lines: Vec<&str> = pretty.lines().collect();
    let mut block = lines[1..lines.len() - 1].join("\n");
    block.push_str(",\n");
    let at = text.find(anchor).unwrap();
    text.insert_str(at, &block);
    // Valid JSON, the new fields as built, the old ones untouched.
    let parsed: Value = serde_json::from_str(&text).unwrap();
    for (key, value) in &fields {
        assert_eq!(parsed[key], *value, "{key}");
    }
    std::fs::write(path, text).unwrap();
}

/// `r9-vectors-pairing`: every valid `verifyCommit` gives its
/// `host_trust_gen`, every invalid one is refused.
#[test]
fn pairing() {
    use atem_client::ceremony::verify_commit_host_trust_gen;
    let file = load("r9-vectors-pairing");
    let mut checked = 0;
    for case in file["verify_commit"]["valid"].as_array().unwrap() {
        let raw = case["raw"].as_str().unwrap();
        assert_eq!(
            verify_commit_host_trust_gen(raw.as_bytes()),
            Ok(case["host_trust_gen"].as_u64().unwrap()),
            "{}",
            case["case"]
        );
        checked += 1;
    }
    for case in file["verify_commit"]["invalid"].as_array().unwrap() {
        let raw = case["raw"].as_str().unwrap();
        assert!(
            verify_commit_host_trust_gen(raw.as_bytes()).is_err(),
            "{} was accepted",
            case["case"]
        );
        checked += 1;
    }
    assert_eq!(checked, 12);
}

#[test]
fn host_route() {
    use atem_client::host_route::{
        HostChallenge, HostRouteBody, verify_host_route, verify_host_route_message,
    };
    let mut run = Run::new("r9-vectors-host-route");
    let book = Book::load();
    let file = load("r9-vectors-membership-log");
    let ctx = Context::new(&file["log"], &file["others"], genesis_hash());
    let extra: BTreeMap<String, Entry> = run
        .get("entries")
        .as_array()
        .unwrap()
        .iter()
        .map(|v| {
            let entry = Entry::from_strict(&strict(&v["entry"])).unwrap();
            assert_eq!(entry.hash().to_hex(), s(v, "entry_hash"));
            (s(v, "label").to_owned(), entry)
        })
        .collect();
    let chain = |more: &Value| -> Membership {
        let mut log = ctx.chain(&[]);
        for label in more.as_array().unwrap() {
            let entry = &extra[label.as_str().unwrap()];
            assert_eq!(log.check_next(entry), Check::Valid);
            let entries: Vec<Entry> = log
                .entries()
                .iter()
                .cloned()
                .chain([entry.clone()])
                .collect();
            log = Membership::verify_chain("acct-test-1", &genesis_hash(), &entries, &ctx.now)
                .unwrap()
                .membership;
        }
        log
    };
    run.pass("entries: H7_* chain on L (dev-mac), entry_hash");

    let challenge = run.get("challenge");
    let parsed = HostChallenge::parse(challenge["message"].to_string().as_bytes()).unwrap();
    assert_eq!(hex(&parsed.nonce), s(&challenge, "nonce_hex"));
    assert_eq!(parsed.room, s(&challenge, "room"));
    assert_eq!(parsed.to_json(), challenge["message"]);
    let nonce = parsed.nonce;
    let room = s(&challenge, "room").to_owned();
    let atem_id = s(&challenge, "atem_id").to_owned();
    run.pass("challenge: parsed exactly, rebuilt");

    for case in run.get("valid").as_array().unwrap() {
        let label = s(case, "label");
        let log = chain(&case["chain"]);
        let message = case["message"].to_string();
        let route = verify_host_route_message(&log, message.as_bytes(), &nonce, &room, &atem_id)
            .unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(route.host_id, s(&case["expect"], "host_id"), "{label}");
        assert_eq!(route.head.to_json(), case["expect"]["head"], "{label}");
        let proof = case["message"]["proof"].to_string();
        assert_eq!(
            verify_host_route(&log, proof.as_bytes(), &nonce, &room, &atem_id),
            Ok(route)
        );
        let object = SignedObject::from_strict(&strict(&case["message"]["proof"])).unwrap();
        assert_eq!(object.label(), SignLabel::HostRoute);
        assert_eq!(object.jcs(), s(case, "jcs"));
        assert_eq!(
            hex(object.signing_input().as_bytes()),
            s(case, "signing_input_hex")
        );
        // Ed25519 is deterministic: the host's own builder reproduces it.
        let host = s(&case["expect"], "host_id");
        let key = log.host(host).unwrap().host_key.clone();
        let signer = ["host-a", "host-evil"]
            .into_iter()
            .find(|k| book.signer_public(k) == key)
            .unwrap();
        let body = HostRouteBody {
            head: Head::from_json(&object.body()["head"]).unwrap(),
            ..HostRouteBody::at(&log, host, &atem_id, &parsed)
        };
        let resigned =
            atem_client::host_route::sign_host_route(&book.provider, &book.signer(signer), &body)
                .unwrap();
        assert_eq!(resigned, object, "{label}");
        run.pass(format!(
            "{label}: verifies; signing input and signature reproduced"
        ));
    }

    for case in run.get("invalid").as_array().unwrap() {
        let label = s(case, "label");
        let log = chain(&case["chain"]);
        let message = case["message"].to_string();
        let refusal = verify_host_route_message(&log, message.as_bytes(), &nonce, &room, &atem_id)
            .expect_err(label);
        assert_eq!(refusal.code(), s(case, "code"), "{label}: {refusal}");
        run.pass(format!("{label}: refused {}", s(case, "code")));
    }
    for case in run.get("invalid_text").as_array().unwrap() {
        let label = s(case, "label");
        let refusal = verify_host_route_message(
            &ctx.chain(&[]),
            s(case, "text").as_bytes(),
            &nonce,
            &room,
            &atem_id,
        )
        .expect_err(label);
        assert_eq!(refusal.code(), s(case, "code"), "{label}");
        run.pass(format!("{label}: refused {}", s(case, "code")));
    }
    let replies = run.get("relay_replies");
    for case in replies["valid"].as_array().unwrap() {
        use atem_client::host_route::RelayReply;
        let label = s(case, "label");
        let reply = RelayReply::parse(case["message"].to_string().as_bytes())
            .expect(label)
            .unwrap_or_else(|e| panic!("{label}: {e}"));
        assert_eq!(reply.to_json(), case["message"], "{label}");
        match &reply {
            RelayReply::Ok { host_id, head } => {
                assert_eq!(host_id, s(&case["expect"], "host_id"));
                assert_eq!(head.to_json(), case["expect"]["head"]);
            }
            RelayReply::Refused { code } => assert_eq!(code, s(&case["expect"], "code")),
        }
        run.pass(format!("relay reply {label}: parsed, rebuilt"));
    }
    for case in replies["invalid"].as_array().unwrap() {
        let label = s(case, "label");
        let parsed = atem_client::host_route::RelayReply::parse(s(case, "text").as_bytes());
        assert!(
            matches!(parsed, Some(Err(ref e)) if e.code() == "malformed")
                || (label == "refused_duplicate_key" && !matches!(parsed, Some(Ok(_)))),
            "{label}: {parsed:?}"
        );
        run.pass(format!("relay reply {label}: refused"));
    }
    run.finish();
}

// ------------------------------------- delegated host-work: device-list actions

// The five actions the delegated host-work design adds to the device list
// (II.2.2 projects, II.3.1 host-sender revoke and readmit, II.4.1 the host
// encryption key), as `others` of `r9-vectors-membership-log`: every one
// chains on log L and the entries its `chain` names, and every valid one
// carries `expect`, the state a verifier derives after it. They are made by
// `write_delegated_vectors` (ignored; run it to regenerate) from the test
// keys it adds to `r9-vectors-keys`, and `membership_log` checks each of them
// against the verifier and against what `delegated_vectors` makes now.

/// `signed_at` of the delegated-action vectors: this plus `seq` seconds.
const DELEGATED_T0: u64 = 1_793_620_800_000;

/// The test keys the delegated-action vectors add to `r9-vectors-keys`:
/// `(name, part, label, note)`, secret = SHA-256(enc(["atem-r9-test-key",
/// label])). `enc` parts are X25519, `host_key` parts Ed25519.
const DELEGATED_KEYS: [(&str, &str, &str, &str); 9] = [
    (
        "host-a-enc-1",
        "enc",
        "host-a host_enc_key 1",
        "host-a's first host encryption key (label \"host-a host_enc_key 1\"), installed by host_enc_key entries (delegated host-work II.4.1)",
    ),
    (
        "host-a-enc-2",
        "enc",
        "host-a host_enc_key 2",
        "host-a's second host encryption key (label \"host-a host_enc_key 2\")",
    ),
    (
        "host-a-enc-3",
        "enc",
        "host-a host_enc_key 3",
        "host-a's third host encryption key (label \"host-a host_enc_key 3\")",
    ),
    (
        "host-a-gen-2",
        "host_key",
        "host-a host_channel_key gen 2",
        "host-a's host_channel_key at host_trust_gen 2, after a re-verification (label \"host-a host_channel_key gen 2\")",
    ),
    (
        "host-a-gen-3",
        "host_key",
        "host-a host_channel_key gen 3",
        "host-a's host_channel_key at host_trust_gen 3, added again after its remove_host (label \"host-a host_channel_key gen 3\")",
    ),
    (
        "host-b",
        "host_key",
        "host-b host_channel_key",
        "the second host of the project vectors, host_trust_gen 1 (label \"host-b host_channel_key\")",
    ),
    (
        "host-b-enc-1",
        "enc",
        "host-b host_enc_key 1",
        "host-b's host encryption key (label \"host-b host_enc_key 1\")",
    ),
    (
        "host-b-enc-2",
        "enc",
        "host-b host_enc_key 2",
        "host-b's second host encryption key (label \"host-b host_enc_key 2\"): the host-envelope vectors' rotation of host-b",
    ),
    (
        "host-b-gen-2",
        "host_key",
        "host-b host_channel_key gen 2",
        "host-b's host_channel_key at host_trust_gen 2, added again after its remove_host (label \"host-b host_channel_key gen 2\")",
    ),
];

/// SHA-256(enc(["atem-r9-test-key", label])) (`schema.md`).
fn test_key_secret(label: &str) -> [u8; 32] {
    Sha256::digest(enc(&[b"atem-r9-test-key", label.as_bytes()])).into()
}

/// The `r9-vectors-keys` name of `host_id`'s host key at a generation:
/// generation 1 under the host's own name.
fn host_key_name(host_id: &str, host_trust_gen: u64) -> String {
    if host_trust_gen == 1 {
        host_id.to_owned()
    } else {
        format!("{host_id}-gen-{host_trust_gen}")
    }
}

/// The `keys` entries of `DELEGATED_KEYS`, as `r9-vectors-keys` holds them.
fn delegated_key_entries() -> Vec<(&'static str, Value)> {
    DELEGATED_KEYS
        .iter()
        .map(|&(name, part, label, note)| {
            let secret = test_key_secret(label);
            let key = if part == "enc" {
                serde_json::json!({
                    "pub_hex": hex(&hpke::public_of(&secret).unwrap()),
                    "secret_hex": hex(&secret),
                })
            } else {
                let mut provider = SoftwareKeys::new();
                provider.insert_ed25519(KeyId::new("k"), &secret);
                let public = provider.public_key(&KeyId::new("k")).unwrap();
                serde_json::json!({
                    "alg": "ed25519",
                    "pub_hex": hex(public.as_bytes()),
                    "secret_hex": hex(&secret),
                })
            };
            (name, serde_json::json!({ part: key, "note": note }))
        })
        .collect()
}

/// The parts of `expect` for one host's sending state.
fn sender(state: &str, seq: u64, epoch: Option<u64>) -> Value {
    let mut v = serde_json::json!({"state": state, "seq": seq});
    if let Some(epoch) = epoch {
        v["membership_epoch"] = epoch.into();
    }
    v
}

/// A project in `expect`: as signed (`hosts`), its members in effect and
/// its ops.
fn project_state(hosts: &[&str], members: &[&str], ops: &[&str]) -> Value {
    serde_json::json!({"hosts": hosts, "members": members, "ops": ops})
}

/// What a verifier derives after a vector: current hosts and their
/// generation, projects in effect, host-sender states and host encryption
/// keys (hosts never added, or without keys, are left out).
fn expect(hosts: Value, projects: Value, host_senders: Value, host_enc_keys: Value) -> Value {
    serde_json::json!({
        "hosts": hosts,
        "projects": projects,
        "host_senders": host_senders,
        "host_enc_keys": host_enc_keys,
    })
}

/// Builds the delegated-action vectors on log L with the test keys.
struct Delegated<'a> {
    book: &'a Book,
    genesis: Hash32,
    now: HostNow,
    entries: BTreeMap<String, Entry>,
    vectors: Vec<Value>,
}

impl<'a> Delegated<'a> {
    fn new(book: &'a Book, file: &Value) -> Self {
        let entries = file["log"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| {
                let entry = Entry::from_strict(&strict(&v["entry"])).unwrap();
                (s(v, "label").to_owned(), entry)
            })
            .collect();
        Delegated {
            book,
            genesis: Hash32::from_hex(s(file, "genesis_hash")).unwrap(),
            now: HostNow {
                wall_ms: 1_793_177_601_000,
                mono_ms: 1_000,
                boot_id: "boot-1".into(),
            },
            entries,
            vectors: Vec::new(),
        }
    }

    /// Log L followed by `chain`.
    fn chain(&self, chain: &[&str]) -> Membership {
        let entries: Vec<Entry> = ["E1", "E2", "E3", "E4", "E5", "E6"]
            .iter()
            .chain(chain)
            .map(|l| self.entries[*l].clone())
            .collect();
        Membership::verify_chain("acct-test-1", &self.genesis, &entries, &self.now)
            .unwrap()
            .membership
    }

    fn host_key(&self, host_id: &str, host_trust_gen: u64) -> PublicKey {
        self.book.public(&format!(
            "{}/host_key",
            host_key_name(host_id, host_trust_gen)
        ))
    }

    fn enc_key(&self, name: &str) -> PublicKey {
        self.book.public(&format!("{name}/enc"))
    }

    fn add_host(&self, host_id: &str, host_trust_gen: u64) -> Action {
        Action::AddHost {
            host: HostRecord {
                host_id: host_id.into(),
                host_trust_gen,
                host_key: self.host_key(host_id, host_trust_gen),
            },
        }
    }

    /// The host's `enc_sig` (its key at `host_trust_gen`) over its binding
    /// of the key `enc_name`.
    fn enc_sig(&self, host_id: &str, host_trust_gen: u64, enc_name: &str) -> Vec<u8> {
        use atem_client::membership::sign_host_enc_key;
        let signer = KeyId::new(format!(
            "{}/host_key",
            host_key_name(host_id, host_trust_gen)
        ));
        sign_host_enc_key(
            &self.book.provider,
            &signer,
            "acct-test-1",
            &self.genesis,
            host_id,
            host_trust_gen,
            self.enc_key(enc_name).as_32().unwrap(),
        )
        .unwrap()
    }

    /// A `host_enc_key` of `enc_name`, the host vouching with `enc_sig`.
    fn enc_entry(
        &self,
        host_id: &str,
        host_trust_gen: u64,
        enc_name: &str,
        enc_sig: &[u8],
        retire_previous: bool,
    ) -> Action {
        atem_client::membership::host_enc_key(
            host_id,
            host_trust_gen,
            &self.enc_key(enc_name),
            enc_sig,
            retire_previous,
            DELEGATED_T0,
        )
        .unwrap()
    }

    /// The `expect` key info of `enc_name` set at `seq`.
    fn key_info(&self, enc_name: &str, seq: u64, host_trust_gen: u64) -> Value {
        let key = self.enc_key(enc_name);
        serde_json::json!({
            "enc_kid": enc_kid(&key).unwrap(),
            "pub": b64u(key.as_bytes()),
            "seq": seq,
            "host_trust_gen": host_trust_gen,
        })
    }

    /// A previous key in `expect`.
    fn previous(
        &self,
        enc_name: &str,
        seq: u64,
        host_trust_gen: u64,
        retired: bool,
        replaced_at_seq: u64,
    ) -> Value {
        let mut v = self.key_info(enc_name, seq, host_trust_gen);
        v["retired"] = retired.into();
        v["replaced_at_seq"] = replaced_at_seq.into();
        v
    }

    /// Signs `action` by dev-mac as the next entry after L + `chain`
    /// (`edit` changes the drafted body first), and records the vector:
    /// valid with `expect`, or refused for `reason`.
    fn push(
        &mut self,
        label: &str,
        chain: &[&str],
        note: &str,
        action: &Action,
        edit: impl FnOnce(&mut Value),
        outcome: Result<Value, &str>,
    ) {
        self.push_by("dev-mac", label, chain, note, action, edit, outcome);
    }

    /// `push`, drafted for and signed by `signer` (a member's `auth` key,
    /// or `recovery`, the kit's key). A body the signed-object parse
    /// refuses (a set out of order) is signed over its `jcs` as it stands,
    /// so the vector shows exactly that refusal.
    #[allow(clippy::too_many_arguments)]
    fn push_by(
        &mut self,
        signer: &str,
        label: &str,
        chain: &[&str],
        note: &str,
        action: &Action,
        edit: impl FnOnce(&mut Value),
        outcome: Result<Value, &str>,
    ) {
        let m = self.chain(chain);
        let seq = m.head().seq + 1;
        let mut body = m.draft(signer, DELEGATED_T0 + seq * 1000, action);
        edit(&mut body);
        let key = self.book.signer(signer);
        let (wire, text, input, hash, object) =
            match SignedObject::sign(&self.book.provider, &key, body.clone()) {
                Ok(object) => (
                    object.to_json(),
                    object.jcs().to_owned(),
                    object.signing_input(),
                    object.entry_hash().unwrap(),
                    Some(object),
                ),
                Err(Error::ArrayNotCanonical) => {
                    let text = jcs(&body).unwrap();
                    let input = SigningInput::new(SignLabel::MembershipEntry, text.as_bytes());
                    let sig = sign(&self.book.provider, &key, &input).unwrap();
                    let hash = Hash32::of_enc(&[b"atem-membership-hash-v1", text.as_bytes()]);
                    let wire = serde_json::json!({"body": body, "sig": b64u(&sig)});
                    (wire, text, input, hash, None)
                }
                Err(e) => panic!("{label}: {e}"),
            };
        let mut v = serde_json::json!({
            "label": label,
            "note": note,
            "chain": chain,
            "entry": wire,
            "jcs": text,
            "signing_input_hex": hex(input.as_bytes()),
            "entry_hash": hash.to_hex(),
        });
        if let Some(input) = self.binding_input(&body) {
            v["enc_sig_input_hex"] = hex(input.as_bytes()).into();
        }
        match outcome {
            Ok(expect) => v["expect"] = expect,
            Err(reason) => {
                v["valid"] = false.into();
                v["reason"] = reason.into();
            }
        }
        if let Some(Ok(entry)) = object.map(Entry::parse) {
            self.entries.insert(label.to_owned(), entry);
        }
        self.vectors.push(v);
    }

    /// The host's `enc_sig` signing input of a `host_enc_key` body, from
    /// its fields as written: only when the binding's own fields parse (a
    /// generation of at least 1, an X25519 key, a 64-byte `enc_sig`).
    fn binding_input(&self, body: &Value) -> Option<SigningInput> {
        if body["action"] != "host_enc_key" {
            return None;
        }
        let host_trust_gen = body["host_trust_gen"].as_u64().filter(|g| *g >= 1)?;
        let enc_key = PublicKey::from_json_as(&body["enc_key"], Alg::X25519).ok()?;
        let enc_sig = b64u_decode(body["enc_sig"].as_str()?).ok()?;
        (enc_sig.len() == 64).then(|| {
            atem_client::membership::host_enc_sig_input(
                "acct-test-1",
                &self.genesis,
                body["host_id"].as_str().unwrap(),
                host_trust_gen,
                enc_key.as_32().unwrap(),
            )
        })
    }
}

/// The delegated-action vectors, in file order. Each `expect` is written
/// out by hand here; `membership_log` compares it with the verifier.
fn delegated_vectors(book: &Book, file: &Value) -> Vec<Value> {
    use atem_client::membership::{
        Project, ProjectOp, host_sender_readmit, host_sender_revoke, project_remove, project_set,
    };
    let mut g = Delegated::new(book, file);
    let no_edit = |_: &mut Value| {};
    let all = ["launch", "message", "notify", "prompt"];
    let all_ops = ProjectOp::ALL;
    let none = serde_json::json!({});
    let a1 = serde_json::json!({"host-a": 1});
    let ab = serde_json::json!({"host-a": 1, "host-b": 1});
    let a_l = sender("authorized", 2, Some(2));
    let senders_l = serde_json::json!({"host-a": a_l});
    let senders_ab = serde_json::json!({"host-a": a_l, "host-b": sender("authorized", 7, Some(7))});
    let astation = |members: &[&str], ops: &[&str]| serde_json::json!({"astation": project_state(&["host-a", "host-b"], members, ops)});
    let set_ab = |ops: &[ProjectOp]| {
        project_set(
            "astation",
            ["host-a", "host-b"],
            ops.iter().copied(),
            DELEGATED_T0,
        )
        .unwrap()
    };
    let remove = |host_id: &str| Action::RemoveHost {
        host_id: host_id.into(),
    };

    // ---- projects (II.2.2)
    let p7 = ["P7_add_host_b"];
    let p8 = ["P7_add_host_b", "P8_set"];
    let p9_rb = ["P7_add_host_b", "P8_set", "P9_remove_host_b"];
    g.push(
        "P7_add_host_b",
        &[],
        "add_host host-b (host_trust_gen 1, key \"host-b host_channel_key\") on E6, signed by dev-mac: the second host the project vectors need (a project lists at least two); host-b is authorized(7), membership epoch 7",
        &g.add_host("host-b", 1),
        no_edit,
        Ok(expect(ab.clone(), none.clone(), senders_ab.clone(), none.clone())),
    );
    g.push(
        "P8_set",
        &p7,
        "project_set \"astation\" on P7_add_host_b: hosts host-a and host-b, ops launch, message, notify, prompt; each host may send the other those ops, and a host itself gets none",
        &set_ab(&all_ops),
        no_edit,
        Ok(expect(ab.clone(), astation(&["host-a", "host-b"], &all), senders_ab.clone(), none.clone())),
    );
    g.push(
        "P9_narrow",
        &p8,
        "project_set \"astation\" on P8_set with ops [message] only: the body is the project's whole new state and replaces P8_set's (a narrowing)",
        &set_ab(&[ProjectOp::Message]),
        no_edit,
        Ok(expect(ab.clone(), astation(&["host-a", "host-b"], &["message"]), senders_ab.clone(), none.clone())),
    );
    g.push(
        "P10_remove",
        &["P7_add_host_b", "P8_set", "P9_narrow"],
        "project_remove \"astation\" on P9_narrow: no project is in effect",
        &project_remove("astation", DELEGATED_T0).unwrap(),
        no_edit,
        Ok(expect(
            ab.clone(),
            none.clone(),
            senders_ab.clone(),
            none.clone(),
        )),
    );
    g.push(
        "P11_remove_again",
        &["P7_add_host_b", "P8_set", "P9_narrow", "P10_remove"],
        "project_remove \"astation\" on P10_remove: invalid (no project of that name in effect): not_a_project",
        &project_remove("astation", DELEGATED_T0).unwrap(),
        no_edit,
        Err("not_a_project"),
    );
    g.push(
        "P9_bad_project",
        &p8,
        "project_set \"astation\" on P8_set with ops [notify, prompt]: invalid (notify needs message and prompt): bad_project",
        &Action::ProjectSet {
            project: Project {
                name: "astation".into(),
                hosts: vec!["host-a".into(), "host-b".into()],
                ops: vec![ProjectOp::Notify, ProjectOp::Prompt],
            },
        },
        no_edit,
        Err("bad_project"),
    );
    g.push(
        "P7_not_a_host",
        &[],
        "project_set \"astation\" listing host-a and host-b on E6, where host-b was never added: invalid (every listed host must be current): not_a_host",
        &set_ab(&[ProjectOp::Message]),
        no_edit,
        Err("not_a_host"),
    );
    g.push(
        "P9_remove_host_b",
        &p8,
        "remove_host host-b on P8_set: host-b leaves every project at once; \"astation\" stays in effect (as signed it still lists host-b) with host-a its only member, so it grants nothing between host-a and host-b; host-b stays authorized(7) with no membership epoch",
        &remove("host-b"),
        no_edit,
        Ok(expect(
            a1.clone(),
            astation(&["host-a"], &all),
            serde_json::json!({"host-a": a_l, "host-b": sender("authorized", 7, None)}),
            none.clone(),
        )),
    );
    g.push(
        "P10_readd_host_b",
        &p9_rb,
        "add_host host-b again (host_trust_gen 2, key \"host-b host_channel_key gen 2\") on P9_remove_host_b: a current host again, membership epoch 10, but in no project until a new project_set lists it",
        &g.add_host("host-b", 2),
        no_edit,
        Ok(expect(
            serde_json::json!({"host-a": 1, "host-b": 2}),
            astation(&["host-a"], &all),
            serde_json::json!({"host-a": a_l, "host-b": sender("authorized", 7, Some(10))}),
            none.clone(),
        )),
    );
    g.push(
        "P11_set_again",
        &["P7_add_host_b", "P8_set", "P9_remove_host_b", "P10_readd_host_b"],
        "project_set \"astation\" on P10_readd_host_b with the same project state as P8_set: valid as a new entry; host-b is a member again",
        &set_ab(&all_ops),
        no_edit,
        Ok(expect(
            serde_json::json!({"host-a": 1, "host-b": 2}),
            astation(&["host-a", "host-b"], &all),
            serde_json::json!({"host-a": a_l, "host-b": sender("authorized", 7, Some(10))}),
            none.clone(),
        )),
    );
    let gone = serde_json::json!({
        "host-a": sender("authorized", 2, None),
        "host-b": sender("authorized", 7, None),
    });
    g.push(
        "P10_remove_host_a",
        &p9_rb,
        "remove_host host-a on P9_remove_host_b: no member of \"astation\" is left, yet the project stays in effect (set and not removed)",
        &remove("host-a"),
        no_edit,
        Ok(expect(none.clone(), astation(&[], &all), gone.clone(), none.clone())),
    );
    g.push(
        "P11_remove_emptied",
        &["P7_add_host_b", "P8_set", "P9_remove_host_b", "P10_remove_host_a"],
        "project_remove \"astation\" on P10_remove_host_a: valid (a project whose members all left through remove_host is in effect until removed)",
        &project_remove("astation", DELEGATED_T0).unwrap(),
        no_edit,
        Ok(expect(none.clone(), none.clone(), gone.clone(), none.clone())),
    );
    g.push(
        "P9_reverify_a",
        &p8,
        "add_host host-a at host_trust_gen 2 (a re-verification, key \"host-a host_channel_key gen 2\") on P8_set, with no remove_host: host-a stays in \"astation\" and keeps membership epoch 2",
        &g.add_host("host-a", 2),
        no_edit,
        Ok(expect(
            serde_json::json!({"host-a": 2, "host-b": 1}),
            astation(&["host-a", "host-b"], &all),
            senders_ab.clone(),
            none.clone(),
        )),
    );

    // ---- the host encryption key (II.4.1)
    let ek7 = ["EK7_set"];
    let ek8_rv = ["EK7_set", "EK8_reverify_a"];
    let sig_a1_1 = g.enc_sig("host-a", 1, "host-a-enc-1");
    let sig_a1_2 = g.enc_sig("host-a", 1, "host-a-enc-2");
    let sig_a1_3 = g.enc_sig("host-a", 1, "host-a-enc-3");
    let keys_of = |current: Value, previous: Option<Value>| {
        let mut keys = serde_json::json!({"current": current});
        if let Some(previous) = previous {
            keys["previous"] = previous;
        }
        serde_json::json!({"host-a": keys})
    };
    g.push(
        "EK7_set",
        &[],
        "host_enc_key host-a (host_trust_gen 1) on E6: enc_key \"host-a host_enc_key 1\", enc_sig by host-a's host_key over enc_sig_input_hex, no retire_previous: host-a's current key",
        &g.enc_entry("host-a", 1, "host-a-enc-1", &sig_a1_1, false),
        no_edit,
        Ok(expect(a1.clone(), none.clone(), senders_l.clone(), keys_of(g.key_info("host-a-enc-1", 7, 1), None))),
    );
    g.push(
        "EK8_rotate",
        &ek7,
        "a routine rotation on EK7_set: \"host-a host_enc_key 2\" current; host_enc_key 1 kept as the previous key, not retired (the host still opens mail with it for 24 h on its own clock)",
        &g.enc_entry("host-a", 1, "host-a-enc-2", &sig_a1_2, false),
        no_edit,
        Ok(expect(
            a1.clone(),
            none.clone(),
            senders_l.clone(),
            keys_of(
                g.key_info("host-a-enc-2", 8, 1),
                Some(g.previous("host-a-enc-1", 7, 1, false, 8)),
            ),
        )),
    );
    g.push(
        "EK9_rotate_retire",
        &["EK7_set", "EK8_rotate"],
        "a rotation with retire_previous: true on EK8_rotate (a suspected compromise): host_enc_key 3 current, host_enc_key 2 the previous key and retired at once; host_enc_key 1 is no longer kept (one previous key only)",
        &g.enc_entry("host-a", 1, "host-a-enc-3", &sig_a1_3, true),
        no_edit,
        Ok(expect(
            a1.clone(),
            none.clone(),
            senders_l.clone(),
            keys_of(
                g.key_info("host-a-enc-3", 9, 1),
                Some(g.previous("host-a-enc-2", 8, 1, true, 9)),
            ),
        )),
    );
    g.push(
        "EK7_retire_first",
        &[],
        "host_enc_key host-a with retire_previous: true and no previous key, on E6: valid; host_enc_key 1 current, nothing to retire",
        &g.enc_entry("host-a", 1, "host-a-enc-1", &sig_a1_1, true),
        no_edit,
        Ok(expect(a1.clone(), none.clone(), senders_l.clone(), keys_of(g.key_info("host-a-enc-1", 7, 1), None))),
    );
    g.push(
        "EK8_same_key",
        &ek7,
        "host-a's current key (host_enc_key 1) set again with retire_previous: true on EK7_set: invalid (a key set for the host since its newest add_host never comes back; here the previous key would be the live one, same kid, and retired): enc_key_reused",
        &g.enc_entry("host-a", 1, "host-a-enc-1", &sig_a1_1, true),
        no_edit,
        Err("enc_key_reused"),
    );
    g.push(
        "EK8_bad_enc_sig",
        &ek7,
        "host_enc_key 2 on EK7_set carrying the enc_sig of host_enc_key 1's binding: invalid (enc_sig doesn't verify over enc_sig_input_hex with host-a's host_key): bad_enc_sig",
        &g.enc_entry("host-a", 1, "host-a-enc-2", &sig_a1_1, false),
        no_edit,
        Err("bad_enc_sig"),
    );
    g.push(
        "EK8_retire_false",
        &ek7,
        "host_enc_key 2 on EK7_set with retire_previous: false: invalid (the field is present only as true; false is omitted, one form per meaning): malformed",
        &g.enc_entry("host-a", 1, "host-a-enc-2", &sig_a1_2, false),
        |body: &mut Value| body["retire_previous"] = false.into(),
        Err("malformed"),
    );
    g.push(
        "EK8_reverify_a",
        &ek7,
        "add_host host-a at host_trust_gen 2 (atem pair verify, key \"host-a host_channel_key gen 2\") on EK7_set: voids host-a's encryption keys until an entry for generation 2",
        &g.add_host("host-a", 2),
        no_edit,
        Ok(expect(serde_json::json!({"host-a": 2}), none.clone(), senders_l.clone(), none.clone())),
    );
    g.push(
        "EK9_stale_gen",
        &ek8_rv,
        "host_enc_key for host_trust_gen 1 (host_enc_key 2, enc_sig by the generation-1 key) on EK8_reverify_a: invalid (not the newest add_host's generation): host_trust_gen_not_current",
        &g.enc_entry("host-a", 1, "host-a-enc-2", &sig_a1_2, false),
        no_edit,
        Err("host_trust_gen_not_current"),
    );
    let sig_a2_3 = g.enc_sig("host-a", 2, "host-a-enc-3");
    g.push(
        "EK9_set_gen_2",
        &ek8_rv,
        "host_enc_key for host_trust_gen 2 on EK8_reverify_a: enc_key \"host-a host_enc_key 3\", enc_sig by the generation-2 key; current, with no previous key (none carries over a newer add_host)",
        &g.enc_entry("host-a", 2, "host-a-enc-3", &sig_a2_3, false),
        no_edit,
        Ok(expect(
            serde_json::json!({"host-a": 2}),
            none.clone(),
            senders_l.clone(),
            keys_of(g.key_info("host-a-enc-3", 9, 2), None),
        )),
    );
    let sig_b1 = g.enc_sig("host-b", 1, "host-b-enc-1");
    g.push(
        "EK7_not_a_host",
        &[],
        "host_enc_key host-b on E6, where host-b was never added (enc_sig by \"host-b host_channel_key\"): invalid: not_a_host",
        &g.enc_entry("host-b", 1, "host-b-enc-1", &sig_b1, false),
        no_edit,
        Err("not_a_host"),
    );

    // ---- host-sender revoke and readmit (II.3.1)
    let hs7 = ["HS7_revoke"];
    let revoke = |host_id: &str, interrupt: bool| {
        host_sender_revoke(host_id, interrupt, DELEGATED_T0).unwrap()
    };
    let readmit = |host_id: &str| host_sender_readmit(host_id, DELEGATED_T0).unwrap();
    let a = |state: &str, seq: u64, epoch: Option<u64>| serde_json::json!({"host-a": sender(state, seq, epoch)});
    g.push(
        "HS7_revoke",
        &[],
        "host_sender_revoke host-a, interrupt_running false, on E6: host-a goes from authorized(2) (its first add_host, E2) to revoked(7)",
        &revoke("host-a", false),
        no_edit,
        Ok(expect(a1.clone(), none.clone(), a("revoked", 7, Some(2)), none.clone())),
    );
    g.push(
        "HS8_revoke_again",
        &hs7,
        "host_sender_revoke host-a on HS7_revoke (a revoke in revoked): invalid: already_revoked",
        &revoke("host-a", true),
        no_edit,
        Err("already_revoked"),
    );
    g.push(
        "HS7_readmit_authorized",
        &[],
        "host_sender_readmit host-a on E6 (a readmit in authorized): invalid: not_revoked",
        &readmit("host-a"),
        no_edit,
        Err("not_revoked"),
    );
    g.push(
        "HS7_readmit_unknown",
        &[],
        "host_sender_readmit host-b on E6, where host-b was never added: invalid (only a revoked host is readmitted): not_revoked",
        &readmit("host-b"),
        no_edit,
        Err("not_revoked"),
    );
    g.push(
        "HS7_revoke_unknown",
        &[],
        "host_sender_revoke host-b on E6, where no add_host names host-b: invalid: unknown_host",
        &revoke("host-b", false),
        no_edit,
        Err("unknown_host"),
    );
    g.push(
        "HS8_readmit",
        &hs7,
        "host_sender_readmit host-a on HS7_revoke: authorized(8), for work signed at or after seq 8 only",
        &readmit("host-a"),
        no_edit,
        Ok(expect(a1.clone(), none.clone(), a("authorized", 8, Some(2)), none.clone())),
    );
    g.push(
        "HS8_reverify_a",
        &hs7,
        "add_host host-a at host_trust_gen 2 (a re-verification, no removal) on HS7_revoke: host-a stays revoked(7) and keeps membership epoch 2",
        &g.add_host("host-a", 2),
        no_edit,
        Ok(expect(serde_json::json!({"host-a": 2}), none.clone(), a("revoked", 7, Some(2)), none.clone())),
    );
    g.push(
        "HS9_remove_host_a",
        &["HS7_revoke", "HS8_reverify_a"],
        "remove_host host-a on HS8_reverify_a: still revoked(7); no membership epoch while removed",
        &remove("host-a"),
        no_edit,
        Ok(expect(
            none.clone(),
            none.clone(),
            a("revoked", 7, None),
            none.clone(),
        )),
    );
    g.push(
        "HS10_readd_host_a",
        &["HS7_revoke", "HS8_reverify_a", "HS9_remove_host_a"],
        "add_host host-a again at host_trust_gen 3 (key \"host-a host_channel_key gen 3\") on HS9_remove_host_a: still revoked(7); membership epoch 10",
        &g.add_host("host-a", 3),
        no_edit,
        Ok(expect(serde_json::json!({"host-a": 3}), none.clone(), a("revoked", 7, Some(10)), none.clone())),
    );
    let hs10 = [
        "HS7_revoke",
        "HS8_reverify_a",
        "HS9_remove_host_a",
        "HS10_readd_host_a",
    ];
    g.push(
        "HS11_readmit",
        &hs10,
        "host_sender_readmit host-a on HS10_readd_host_a: only a native manager's readmit admits it again: authorized(11)",
        &readmit("host-a"),
        no_edit,
        Ok(expect(serde_json::json!({"host-a": 3}), none.clone(), a("authorized", 11, Some(10)), none.clone())),
    );
    let mut hs11 = hs10.to_vec();
    hs11.push("HS11_readmit");
    g.push(
        "HS12_revoke_interrupt",
        &hs11,
        "host_sender_revoke host-a, interrupt_running true, on HS11_readmit: revoked(12); its running turns are interrupted too",
        &revoke("host-a", true),
        no_edit,
        Ok(expect(serde_json::json!({"host-a": 3}), none.clone(), a("revoked", 12, Some(10)), none.clone())),
    );
    g.push(
        "HS7_remove_host_a",
        &[],
        "remove_host host-a on E6: host-a can't send (not a current host), its sending state stays authorized(2), no membership epoch",
        &remove("host-a"),
        no_edit,
        Ok(expect(none.clone(), none.clone(), a("authorized", 2, None), none.clone())),
    );
    g.push(
        "HS8_revoke_removed",
        &["HS7_remove_host_a"],
        "host_sender_revoke host-a on HS7_remove_host_a: valid (an add_host names host-a, current or removed): revoked(8)",
        &revoke("host-a", false),
        no_edit,
        Ok(expect(none.clone(), none.clone(), a("revoked", 8, None), none.clone())),
    );

    // ---- removal: keys voided, and "current" (no later remove_host)
    // rather than "ever added" (review fix: appended, so earlier vectors
    // keep their place in the file)
    let ek8_rm = ["EK7_set", "EK8_remove_host_a"];
    g.push(
        "EK8_remove_host_a",
        &ek7,
        "remove_host host-a on EK7_set: host-a is no longer current and its encryption keys are voided (no current or previous key); its sending state stays authorized(2), no membership epoch",
        &remove("host-a"),
        no_edit,
        Ok(expect(none.clone(), none.clone(), a("authorized", 2, None), none.clone())),
    );
    g.push(
        "EK9_removed_host",
        &ek8_rm,
        "host_enc_key host-a (host_trust_gen 1, host_enc_key 2, enc_sig by host-a's generation-1 key, which verifies) on EK8_remove_host_a: invalid (host-a was added but is removed, not current): not_a_host",
        &g.enc_entry("host-a", 1, "host-a-enc-2", &sig_a1_2, false),
        no_edit,
        Err("not_a_host"),
    );
    g.push(
        "EK9_readd_a",
        &ek8_rm,
        "add_host host-a again at host_trust_gen 2 (key \"host-a host_channel_key gen 2\") on EK8_remove_host_a: current again, membership epoch 9, still authorized(2), and no encryption key carried over",
        &g.add_host("host-a", 2),
        no_edit,
        Ok(expect(
            serde_json::json!({"host-a": 2}),
            none.clone(),
            a("authorized", 2, Some(9)),
            none.clone(),
        )),
    );
    let sig_a2_1 = g.enc_sig("host-a", 2, "host-a-enc-1");
    g.push(
        "EK10_set_after_readd",
        &["EK7_set", "EK8_remove_host_a", "EK9_readd_a"],
        "host_enc_key for host_trust_gen 2 on EK9_readd_a with \"host-a host_enc_key 1\", the key the removal voided: a new key here (not the current one, none is), current with no previous key",
        &g.enc_entry("host-a", 2, "host-a-enc-1", &sig_a2_1, false),
        no_edit,
        Ok(expect(
            serde_json::json!({"host-a": 2}),
            none.clone(),
            a("authorized", 2, Some(9)),
            keys_of(g.key_info("host-a-enc-1", 10, 2), None),
        )),
    );
    g.push(
        "P10_set_removed_host",
        &p9_rb,
        "project_set \"astation\" listing host-a and host-b on P9_remove_host_b: invalid (host-b was added but is removed, not current): not_a_host",
        &set_ab(&[ProjectOp::Message]),
        no_edit,
        Err("not_a_host"),
    );
    let bad_project = |name: &str, hosts: &[&str]| Action::ProjectSet {
        project: Project {
            name: name.into(),
            hosts: hosts.iter().map(|h| h.to_string()).collect(),
            ops: vec![ProjectOp::Message],
        },
    };
    g.push(
        "P9_bad_name",
        &p8,
        "project_set named \"Astation\" on P8_set: invalid (a name is 1 to 32 characters of [a-z0-9-]): bad_project",
        &bad_project("Astation", &["host-a", "host-b"]),
        no_edit,
        Err("bad_project"),
    );
    g.push(
        "P9_one_host",
        &p8,
        "project_set \"astation\" listing host-a only, on P8_set: invalid (a project lists 2 to 64 hosts): bad_project",
        &bad_project("astation", &["host-a"]),
        no_edit,
        Err("bad_project"),
    );
    g.push(
        "P9_unknown_op",
        &p8,
        "project_set \"astation\" with ops [deploy, message] on P8_set: invalid (an op outside launch, message, notify, prompt): bad_project",
        &set_ab(&[ProjectOp::Message]),
        |body: &mut Value| body["project"]["ops"] = serde_json::json!(["deploy", "message"]),
        Err("bad_project"),
    );

    // ---- PR 2 review: a key set in a generation never comes back
    // (`enc_key_reused`), and the readings a verifier written from the
    // text could get wrong (appended, so earlier vectors keep their place)
    let ek9_rr = ["EK7_set", "EK8_rotate", "EK9_rotate_retire"];
    g.push(
        "EK9_previous_again",
        &["EK7_set", "EK8_rotate"],
        "host_enc_key 1 on EK8_rotate, where it is host-a's previous key (not retired), set again with its own enc_sig (EK7_set's): invalid (a key set for the host since its newest add_host never comes back): enc_key_reused",
        &g.enc_entry("host-a", 1, "host-a-enc-1", &sig_a1_1, false),
        no_edit,
        Err("enc_key_reused"),
    );
    g.push(
        "EK10_retired_again",
        &ek9_rr,
        "host_enc_key 2 on EK9_rotate_retire, which retired it (retire_previous), set again with its own enc_sig (EK8_rotate's): invalid (a retired key stays retired): enc_key_reused",
        &g.enc_entry("host-a", 1, "host-a-enc-2", &sig_a1_2, false),
        no_edit,
        Err("enc_key_reused"),
    );
    g.push(
        "EK10_dropped_again",
        &ek9_rr,
        "host_enc_key 1 on EK9_rotate_retire, no longer kept (one previous key only), set again with its own enc_sig (EK7_set's): invalid: enc_key_reused",
        &g.enc_entry("host-a", 1, "host-a-enc-1", &sig_a1_1, false),
        no_edit,
        Err("enc_key_reused"),
    );
    g.push(
        "HS9_readmit_removed",
        &["HS7_remove_host_a", "HS8_revoke_removed"],
        "host_sender_readmit host-a on HS8_revoke_removed, where host-a is removed and revoked: valid (a readmit needs revoked, not a current host): authorized(9), no membership epoch, and it sends nothing until an add_host makes it current",
        &readmit("host-a"),
        no_edit,
        Ok(expect(none.clone(), none.clone(), a("authorized", 9, None), none.clone())),
    );
    let revoked_ab = serde_json::json!({
        "host-a": sender("revoked", 8, Some(2)),
        "host-b": sender("authorized", 7, Some(7)),
    });
    g.push(
        "P8_revoke_a",
        &p7,
        "host_sender_revoke host-a, interrupt_running false, on P7_add_host_b: host-a revoked(8), host-b still authorized(7)",
        &revoke("host-a", false),
        no_edit,
        Ok(expect(ab.clone(), none.clone(), revoked_ab.clone(), none.clone())),
    );
    g.push(
        "P9_set_revoked",
        &["P7_add_host_b", "P8_revoke_a"],
        "project_set \"astation\" listing host-a and host-b on P8_revoke_a, where host-a is revoked: valid (a listed host must be current; its sending state is apart): both are members, and host-a stays revoked(8), so it sends nothing until readmitted",
        &set_ab(&all_ops),
        no_edit,
        Ok(expect(ab.clone(), astation(&["host-a", "host-b"], &all), revoked_ab.clone(), none.clone())),
    );
    g.push(
        "HS8_enc_key_revoked",
        &hs7,
        "host_enc_key host-a (host_enc_key 1) on HS7_revoke, where host-a is revoked: valid (its keys are apart from its sending state): host-a's current key, and host-a stays revoked(7)",
        &g.enc_entry("host-a", 1, "host-a-enc-1", &sig_a1_1, false),
        no_edit,
        Ok(expect(
            a1.clone(),
            none.clone(),
            a("revoked", 7, Some(2)),
            keys_of(g.key_info("host-a-enc-1", 8, 1), None),
        )),
    );
    g.push(
        "P11_set_after_remove",
        &["P7_add_host_b", "P8_set", "P9_narrow", "P10_remove"],
        "project_set \"astation\" with ops [launch] on P10_remove: valid (unlike a device id, a project name may be set again after its project_remove): a new project of that name",
        &set_ab(&[ProjectOp::Launch]),
        no_edit,
        Ok(expect(ab.clone(), astation(&["host-a", "host-b"], &["launch"]), senders_ab.clone(), none.clone())),
    );
    let two = ["host-a", "host-b"];
    g.push(
        "P10_second_project",
        &["P7_add_host_b", "P8_set", "P9_narrow"],
        "project_set \"chisel\" listing host-a and host-b with ops [launch] on P9_narrow (\"astation\": [message]): two projects over the same hosts; between host-a and host-b the grant is the union, launch and message, and each host is a member of both",
        &project_set("chisel", two, [ProjectOp::Launch], DELEGATED_T0).unwrap(),
        no_edit,
        Ok(expect(
            ab.clone(),
            serde_json::json!({
                "astation": project_state(&two, &two, &["message"]),
                "chisel": project_state(&two, &two, &["launch"]),
            }),
            senders_ab.clone(),
            none.clone(),
        )),
    );
    g.push(
        "HS7_revoke_no_interrupt",
        &[],
        "host_sender_revoke host-a on E6 without interrupt_running: invalid (a required boolean, written as false too): malformed",
        &revoke("host-a", false),
        |body: &mut Value| {
            body.as_object_mut().unwrap().remove("interrupt_running");
        },
        Err("malformed"),
    );
    g.push(
        "HS8_readmit_interrupt",
        &hs7,
        "host_sender_readmit host-a on HS7_revoke carrying interrupt_running: false: invalid (a readmit has host_id only): unknown_field",
        &readmit("host-a"),
        |body: &mut Value| body["interrupt_running"] = false.into(),
        Err("unknown_field"),
    );
    g.push(
        "EK7_gen_zero",
        &[],
        "host_enc_key host-a on E6 with host_trust_gen 0 (EK7_set's key and enc_sig otherwise): invalid (a generation is at least 1): malformed",
        &g.enc_entry("host-a", 1, "host-a-enc-1", &sig_a1_1, false),
        |body: &mut Value| body["host_trust_gen"] = 0.into(),
        Err("malformed"),
    );
    let short = b64u(&sig_a1_1[..63]);
    g.push(
        "EK7_short_enc_sig",
        &[],
        "host_enc_key host-a on E6 whose enc_sig is 63 bytes (EK7_set's without its last byte): invalid (exactly 64 bytes): malformed",
        &g.enc_entry("host-a", 1, "host-a-enc-1", &sig_a1_1, false),
        move |body: &mut Value| body["enc_sig"] = short.into(),
        Err("malformed"),
    );
    let long = b64u(&[&sig_a1_1[..], &[0]].concat());
    g.push(
        "EK7_long_enc_sig",
        &[],
        "host_enc_key host-a on E6 whose enc_sig is 65 bytes (EK7_set's and a zero byte): invalid (exactly 64 bytes): malformed",
        &g.enc_entry("host-a", 1, "host-a-enc-1", &sig_a1_1, false),
        move |body: &mut Value| body["enc_sig"] = long.into(),
        Err("malformed"),
    );
    let host_a_key = g.host_key("host-a", 1).to_json();
    g.push(
        "EK7_ed25519_enc_key",
        &[],
        "host_enc_key host-a on E6 whose enc_key is host-a's own Ed25519 host_key (alg ed25519): invalid (an encryption key is x25519 only): wrong_alg",
        &g.enc_entry("host-a", 1, "host-a-enc-1", &sig_a1_1, false),
        move |body: &mut Value| body["enc_key"] = host_a_key,
        Err("wrong_alg"),
    );
    g.push(
        "P9_unknown_field",
        &p8,
        "project_set \"astation\" on P8_set whose project carries a fourth field, note: invalid (exactly name, hosts and ops): unknown_field",
        &set_ab(&[ProjectOp::Message]),
        |body: &mut Value| body["project"]["note"] = "x".into(),
        Err("unknown_field"),
    );
    g.push(
        "P9_hosts_unsorted",
        &p8,
        "project_set \"astation\" on P8_set listing [host-b, host-a]: invalid (project.hosts is a set, sorted by bytes with no duplicates, refused by the signed-object parse before the action's own rules): array_not_canonical",
        &set_ab(&[ProjectOp::Message]),
        |body: &mut Value| body["project"]["hosts"] = serde_json::json!(["host-b", "host-a"]),
        Err("array_not_canonical"),
    );
    g.push(
        "P9_hosts_duplicate",
        &p8,
        "project_set \"astation\" on P8_set listing [host-a, host-a, host-b]: invalid (a set has no duplicates): array_not_canonical",
        &set_ab(&[ProjectOp::Message]),
        |body: &mut Value| {
            body["project"]["hosts"] = serde_json::json!(["host-a", "host-a", "host-b"])
        },
        Err("array_not_canonical"),
    );
    g.push(
        "P9_empty_ops",
        &p8,
        "project_set \"astation\" on P8_set with ops []: invalid (an empty array is a canonical set, and the project's rule wants a non-empty one): bad_project",
        &set_ab(&[ProjectOp::Message]),
        |body: &mut Value| body["project"]["ops"] = serde_json::json!([]),
        Err("bad_project"),
    );
    let hosts = |n: usize| (0..n).map(|i| format!("h-{i:02}")).collect::<Vec<_>>();
    g.push(
        "P9_64_hosts",
        &p8,
        "project_set \"astation\" on P8_set listing the 64 hosts h-00 to h-63, none of them added: within the bound of 2 to 64, so judged against the chain: not_a_host",
        &project_set("astation", hosts(64), [ProjectOp::Message], DELEGATED_T0).unwrap(),
        no_edit,
        Err("not_a_host"),
    );
    let sixty_five = hosts(65);
    g.push(
        "P9_65_hosts",
        &p8,
        "project_set \"astation\" on P8_set listing the 65 hosts h-00 to h-64: invalid (2 to 64 hosts, judged at parse, before whether they are current): bad_project",
        &set_ab(&[ProjectOp::Message]),
        move |body: &mut Value| body["project"]["hosts"] = serde_json::json!(sixty_five),
        Err("bad_project"),
    );
    g.push(
        "P9_remove_bad_name",
        &p8,
        "project_remove \"Astation\" on P8_set (\"astation\" is in effect): invalid (a name outside [a-z0-9-], refused at parse before whether a project of that name is in effect): bad_project",
        &project_remove("astation", DELEGATED_T0).unwrap(),
        |body: &mut Value| body["name"] = "Astation".into(),
        Err("bad_project"),
    );
    g.push_by(
        "svc-discord",
        "HS7_revoke_by_service",
        &[],
        "host_sender_revoke host-a on E6 signed by svc-discord, a service member in effect: invalid (only a native manager signs these actions): signer_not_manager",
        &revoke("host-a", false),
        no_edit,
        Err("signer_not_manager"),
    );
    g.push_by(
        "recovery",
        "P9_set_by_recovery",
        &p8,
        "project_set \"astation\" on P8_set signed by the recovery key (kit 1): invalid (the recovery key signs recovery_add only): recovery_signer_action",
        &set_ab(&[ProjectOp::Message]),
        no_edit,
        Err("recovery_signer_action"),
    );
    g.vectors
}

/// The labels of a vector's `chain`.
fn chain_labels(vector: &Value) -> Vec<&str> {
    vector["chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|l| l.as_str().unwrap())
        .collect()
}

/// The state `expect` describes, read from a verifier (the two hosts the
/// vectors use).
fn derived_state(m: &Membership) -> Value {
    let mut hosts = serde_json::Map::new();
    let mut senders = serde_json::Map::new();
    let mut keys = serde_json::Map::new();
    for host_id in ["host-a", "host-b"] {
        if let Some(record) = m.host(host_id) {
            hosts.insert(host_id.into(), record.host_trust_gen.into());
        }
        if let Some(state) = m.host_sender_state(host_id) {
            let (name, seq) = match state {
                HostSenderState::Authorized { generation } => ("authorized", generation),
                HostSenderState::Revoked { seq } => ("revoked", seq),
            };
            senders.insert(
                host_id.into(),
                sender(name, seq, m.host_membership_epoch(host_id)),
            );
        } else {
            assert_eq!(m.host_membership_epoch(host_id), None, "{host_id}");
        }
        if let Some(k) = m.host_enc_key(host_id) {
            let info = |key: &atem_client::membership::EncKey| {
                assert_eq!(hex(&key.kid), enc_kid(&key.key).unwrap());
                serde_json::json!({
                    "enc_kid": hex(&key.kid),
                    "pub": b64u(key.key.as_bytes()),
                    "seq": key.seq,
                    "host_trust_gen": key.host_trust_gen,
                })
            };
            let mut v = serde_json::json!({"current": info(&k.current)});
            if let Some(p) = &k.previous {
                let mut previous = info(&p.key);
                previous["retired"] = p.retired.into();
                previous["replaced_at_seq"] = p.replaced_at_seq.into();
                v["previous"] = previous;
            }
            keys.insert(host_id.into(), v);
        }
    }
    let projects: serde_json::Map<String, Value> = m
        .projects()
        .map(|p| {
            let ops: Vec<&str> = p.ops.iter().map(|op| op.as_str()).collect();
            (
                p.name.clone(),
                project_state(
                    &p.hosts.iter().map(String::as_str).collect::<Vec<_>>(),
                    &m.project_hosts(&p.name),
                    &ops,
                ),
            )
        })
        .collect();
    expect(
        Value::Object(hosts),
        Value::Object(projects),
        Value::Object(senders),
        Value::Object(keys),
    )
}

/// The delegated-action vectors in context: each as the generator makes it,
/// every valid one valid on its chain with the stated `expect`, every
/// refused one refused for its `reason`, every `enc_sig`, and the conflict
/// rule (§R9.4) judging these actions against `C[..seq-1]`.
fn delegated_in_context(run: &mut Run, ctx: &Context, book: &Book, file: &Value) {
    use atem_client::membership::{
        Conflict, Effect, EvidenceReason, ProjectOp, host_enc_sig_input, verify_host_enc_sig,
    };
    let generated = delegated_vectors(book, file);
    let in_file: Vec<&Value> = file["others"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|v| v.get("chain").is_some())
        .collect();
    assert_eq!(in_file.len(), generated.len(), "the delegated vectors");
    for (vector, made) in in_file.iter().zip(&generated) {
        let label = s(vector, "label");
        assert_eq!(*vector, made, "{label}: as delegated_vectors makes it");
        let chain = chain_labels(vector);
        let entry = ctx.parse(label);
        if let Some(expected) = vector.get("expect") {
            assert_eq!(vector.get("valid"), None, "{label}");
            assert_eq!(ctx.check(&chain, label), Check::Valid, "{label}");
            let mut after = chain.clone();
            after.push(label);
            let m = ctx.chain(&after);
            assert_eq!(derived_state(&m), *expected, "{label}: expect");
            // Project grants between the two hosts are the union of the
            // ops of every project listing both as members; none to itself.
            for (x, y) in [
                ("host-a", "host-b"),
                ("host-b", "host-a"),
                ("host-a", "host-a"),
            ] {
                let want: BTreeSet<&str> = expected["projects"]
                    .as_object()
                    .unwrap()
                    .values()
                    .filter(|p| {
                        x != y
                            && [x, y]
                                .iter()
                                .all(|h| p["members"].as_array().unwrap().iter().any(|m| m == h))
                    })
                    .flat_map(|p| {
                        p["ops"]
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|o| o.as_str().unwrap())
                    })
                    .collect();
                let got: BTreeSet<&str> = m
                    .project_ops_between(x, y)
                    .into_iter()
                    .map(ProjectOp::as_str)
                    .collect();
                assert_eq!(got, want, "{label}: ops {x} → {y}");
            }
            // The projects each host's membership of is in effect.
            for h in ["host-a", "host-b"] {
                let mut want: Vec<&str> = expected["projects"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .filter(|(_, p)| p["members"].as_array().unwrap().iter().any(|m| m == h))
                    .map(|(name, _)| name.as_str())
                    .collect();
                want.sort_unstable();
                assert_eq!(m.host_projects(h), want, "{label}: projects of {h}");
            }
            run.pass(format!("{label}: valid on L + {chain:?}, expect matches"));
        } else {
            assert_eq!(vector["valid"], false, "{label}");
            let reason = s(vector, "reason");
            let detail = match entry {
                Err(e) => e.code().to_owned(),
                Ok(_) => match ctx.check(&chain, label) {
                    Check::Invalid(e) => e.code().to_owned(),
                    other => panic!("{label}: {other:?}"),
                },
            };
            assert_eq!(detail, reason, "{label}");
            assert!(chain_reason(label).unwrap().ends_with(reason), "{label}");
            run.pass(format!("{label}: refused {reason} on L + {chain:?}"));
        }
        // The host's enc_sig: its input from the body, and the signature by
        // the host key of the generation it names (bad only where refused so).
        if let Some(input_hex) = vector.get("enc_sig_input_hex") {
            let body = &vector["entry"]["body"];
            let host_id = s(body, "host_id");
            let host_trust_gen = body["host_trust_gen"].as_u64().unwrap();
            let enc_pub = PublicKey::from_json_as(&body["enc_key"], Alg::X25519).unwrap();
            let input = host_enc_sig_input(
                "acct-test-1",
                &ctx.genesis,
                host_id,
                host_trust_gen,
                enc_pub.as_32().unwrap(),
            );
            assert_eq!(
                hex(input.as_bytes()),
                input_hex.as_str().unwrap(),
                "{label}"
            );
            let host_key = book.signer_public(&host_key_name(host_id, host_trust_gen));
            let sig = b64u_decode(s(body, "enc_sig")).unwrap();
            let verified = verify_host_enc_sig(
                &host_key,
                "acct-test-1",
                &ctx.genesis,
                host_id,
                host_trust_gen,
                enc_pub.as_32().unwrap(),
                &sig,
            );
            if vector.get("reason") == Some(&Value::from("bad_enc_sig")) {
                assert_eq!(verified, Err(Error::BadSignature), "{label}");
            } else {
                verified.unwrap_or_else(|e| panic!("{label}: {e}"));
            }
            run.pass(format!("{label}: enc_sig input and signature"));
        } else if vector["entry"]["body"]["action"] == "host_enc_key" {
            // No binding input: the binding's own fields don't parse (a
            // generation of 0, a key that isn't X25519, an enc_sig that
            // isn't 64 bytes), and the entry is refused at parse for it.
            let reason = vector.get("reason").and_then(Value::as_str);
            assert!(matches!(reason, Some("malformed" | "wrong_alg")), "{label}");
            assert!(ctx.parse(label).is_err(), "{label}");
            run.pass(format!("{label}: no binding input, refused at parse"));
        }
    }

    // The effects of a commit name what step 4 replays (II.3.1).
    let effects = |chain: &[&str], label: &str| {
        let eval = ctx
            .chain(chain)
            .evaluate(&[strict(&ctx.vectors[label]["entry"])], &ctx.now);
        assert_eq!(eval.stop, None, "{label}");
        eval.effects
    };
    assert!(
        effects(&[], "HS7_revoke").contains(&Effect::HostSenderRevoked {
            host_id: "host-a".into(),
            seq: 7,
            interrupt_running: false,
        })
    );
    let hs11 = [
        "HS7_revoke",
        "HS8_reverify_a",
        "HS9_remove_host_a",
        "HS10_readd_host_a",
        "HS11_readmit",
    ];
    assert!(
        effects(&hs11, "HS12_revoke_interrupt").contains(&Effect::HostSenderRevoked {
            host_id: "host-a".into(),
            seq: 12,
            interrupt_running: true,
        })
    );
    assert!(
        effects(&hs11[..4], "HS11_readmit").contains(&Effect::HostSenderReadmitted {
            host_id: "host-a".into(),
            seq: 11,
        })
    );
    assert!(
        effects(&["P7_add_host_b"], "P8_set").contains(&Effect::ProjectSet {
            name: "astation".into()
        })
    );
    assert!(
        effects(&["P7_add_host_b", "P8_set", "P9_narrow"], "P10_remove").contains(
            &Effect::ProjectRemoved {
                name: "astation".into()
            }
        )
    );
    assert!(
        effects(&["EK7_set", "EK8_rotate"], "EK9_rotate_retire").contains(&Effect::HostEncKeySet {
            host_id: "host-a".into(),
            retire_previous: true,
        })
    );
    run.pass("effects: HostSenderRevoked/Readmitted name seq and interrupt_running, ProjectSet/Removed, HostEncKeySet");

    // L: host-a authorized at its first add_host (E2), epoch 2.
    let l = ctx.chain(&[]);
    assert_eq!(
        l.host_sender_state("host-a"),
        Some(HostSenderState::Authorized { generation: 2 })
    );
    assert_eq!(l.host_membership_epoch("host-a"), Some(2));
    assert_eq!(l.host_sender_state("host-b"), None);
    let m = ctx.chain(&hs11);
    for seq in 1..=11 {
        let label = match seq {
            1..=6 => format!("E{seq}"),
            _ => hs11[seq as usize - 7].to_owned(),
        };
        assert_eq!(m.entry_hash_at(seq), Some(ctx.hash(&label)), "{label}");
    }
    assert_eq!(m.entry_hash_at(12), None);
    run.pass("log L: host-a authorized(2), epoch 2; entry_hash_at names each entry");

    // A removal voids the keys and a re-add carries none over; "current"
    // means no later remove_host, not "ever added" (`EK9_removed_host`,
    // `P10_set_removed_host` name hosts an add_host added).
    let keyed = ctx.chain(&["EK7_set"]);
    assert_eq!(keyed.host_enc_key("host-a").map(|k| k.current.seq), Some(7));
    let removed = ctx.chain(&["EK7_set", "EK8_remove_host_a"]);
    assert_eq!(removed.host("host-a"), None);
    assert_eq!(removed.host_enc_key("host-a"), None);
    let readded = ctx.chain(&["EK7_set", "EK8_remove_host_a", "EK9_readd_a"]);
    assert_eq!(readded.host_enc_key("host-a"), None);
    for (base, label) in [
        (&["EK7_set", "EK8_remove_host_a"][..], "EK9_removed_host"),
        (
            &["P7_add_host_b", "P8_set", "P9_remove_host_b"][..],
            "P10_set_removed_host",
        ),
    ] {
        let m = ctx.chain(base);
        let entry = ctx.entry(label);
        let host = match &entry.action {
            Action::HostEncKey { host_id, .. } => host_id.clone(),
            Action::ProjectSet { .. } => "host-b".to_owned(),
            other => panic!("{label}: {other:?}"),
        };
        assert!(
            m.host_sender_state(&host).is_some(),
            "{label}: {host} was added"
        );
        assert_eq!(m.host(&host), None, "{label}: {host} isn't current");
        assert_eq!(
            m.check_next(&entry),
            Check::Invalid(Invalid::NotAHost),
            "{label}"
        );
    }
    run.pass("remove_host voids keys, a re-add carries none; not_a_host for removed (added) hosts");

    // §R9.4 with these actions: an alternative at `seq` is judged against
    // C[..seq-1], replayed with the host-sender state, projects and keys.
    let conflict = |base: &[&str], label: &str| {
        let m = ctx.chain(base);
        let eval = m.evaluate(&[strict(&ctx.vectors[label]["entry"])], &ctx.now);
        match eval.stop {
            Some(Stop::Conflict { outcome, .. }) => outcome,
            other => panic!("{label}: {other:?}"),
        }
    };
    let invalid = Conflict::Ignored(EvidenceReason::Invalid);
    // Against HS7_revoke at seq 7: invalid at seq 6 (host-a authorized,
    // host-b unknown) is ignored; a valid entry by a current manager freezes.
    assert_eq!(conflict(&["HS7_revoke"], "HS7_readmit_authorized"), invalid);
    assert_eq!(conflict(&["HS7_revoke"], "HS7_revoke_unknown"), invalid);
    assert_eq!(conflict(&["HS7_revoke"], "EK7_set"), Conflict::Freeze);
    assert_eq!(
        conflict(&["HS7_revoke"], "HS7_remove_host_a"),
        Conflict::Freeze
    );
    // Against HS8_reverify_a at seq 8: host-a revoked at seq 7, so another
    // revoke is invalid there, and a readmit valid (freeze).
    let base = ["HS7_revoke", "HS8_reverify_a"];
    assert_eq!(conflict(&base, "HS8_revoke_again"), invalid);
    assert_eq!(conflict(&base, "HS8_readmit"), Conflict::Freeze);
    // Projects and keys the same way: a removal on another branch is valid
    // at seq 9 (freeze); setting EK7_set's key again, or a binding that
    // doesn't verify, is invalid at seq 8 (ignored).
    let base = ["P7_add_host_b", "P8_set", "P9_narrow"];
    assert_eq!(conflict(&base, "P9_remove_host_b"), Conflict::Freeze);
    assert_eq!(
        conflict(&["EK7_set", "EK8_rotate"], "EK8_same_key"),
        invalid
    );
    assert_eq!(
        conflict(&["EK7_set", "EK8_rotate"], "EK8_bad_enc_sig"),
        invalid
    );
    run.pass("conflicts (§R9.4): host-sender, project and key entries judged against C[..seq-1]");
}

/// Writes the delegated-action keys into `r9-vectors-keys` (between host-a
/// and host-evil, existing bytes unchanged) and the vectors into
/// `r9-vectors-membership-log` (appended to `others`, replacing earlier
/// copies of the same labels).
#[test]
#[ignore = "writes the delegated-action vectors and keys"]
fn write_delegated_vectors() {
    // The keys file: text insertion, so nothing else in it moves.
    let path = fixtures_dir().join("r9-vectors-keys.json");
    let mut text = std::fs::read_to_string(&path).unwrap();
    let anchor = "    \"host-evil\": {\n";
    let first = format!("    \"{}\": {{\n", DELEGATED_KEYS[0].0);
    if let Some(start) = text.find(&first) {
        let end = text.find(anchor).unwrap();
        text.replace_range(start..end, "");
    }
    let mut block = String::new();
    for (name, entry) in delegated_key_entries() {
        let pretty = serde_json::to_string_pretty(&serde_json::json!({ name: entry })).unwrap();
        let lines: Vec<&str> = pretty.lines().collect();
        for line in &lines[1..lines.len() - 1] {
            block.push_str("  ");
            block.push_str(line);
            block.push('\n');
        }
        // Every entry is followed by another (host-evil at the end).
        block.pop();
        block.push_str(",\n");
    }
    let at = text.find(anchor).unwrap();
    text.insert_str(at, &block);
    let parsed: Value = serde_json::from_str(&text).unwrap();
    for (name, entry) in delegated_key_entries() {
        assert_eq!(parsed["keys"][name], entry);
    }
    std::fs::write(&path, text).unwrap();

    // The membership-log file: its own pretty form, so a round trip keeps
    // every existing byte.
    let book = Book::load();
    let path = fixtures_dir().join("r9-vectors-membership-log.json");
    let mut file: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let generated = delegated_vectors(&book, &file);
    let labels: BTreeSet<String> = generated.iter().map(|v| s(v, "label").to_owned()).collect();
    let others = file["others"].as_array_mut().unwrap();
    others.retain(|v| !labels.contains(s(v, "label")));
    others.extend(generated);
    let mut text = serde_json::to_string_pretty(&file).unwrap();
    text.push('\n');
    std::fs::write(path, text).unwrap();
}

// ----------------------------------------- control records (I.5.3 to I.5.5)

/// A Station's control feed: its origin and `feed_id` (I.5.2).
type Feed = (&'static str, &'static str);
/// The Station `station-dev`'s feed.
const FEED_A: Feed = (
    "https://station-dev.agora.build",
    "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b",
);
/// The same Station's feed after a reset: a new `feed_id` (I.5.2).
const FEED_A2: Feed = (
    "https://station-dev.agora.build",
    "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d",
);
/// Another Station's feed.
const FEED_B: Feed = (
    "https://station-b.example.com",
    "1d2c3b4a-5f6e-4d7c-b8a9-0f1e2d3c4b5a",
);
/// Control records are issued after every entry of the chains they name.
const CONTROL_T0: u64 = 1_793_620_900_000;
/// Auth's client id of the integration whose service key is svc-discord's.
const CONTROL_INTEGRATION: &str = "i-01jc5zq9x8w7v6t5s4r3q2p1n0";
const SVC: &str = "service:svc-discord";
const HOST_A: &str = "host:host-a";
/// host-a revoked at seq 7 (membership-log labels after L).
const HS7: &[&str] = &["HS7_revoke"];
/// host-a revoked at 7, re-verified, removed, added again, readmitted, and
/// revoked again at 12 with `interrupt_running: true`.
const HS12: &[&str] = &[
    "HS7_revoke",
    "HS8_reverify_a",
    "HS9_remove_host_a",
    "HS10_readd_host_a",
    "HS11_readmit",
    "HS12_revoke_interrupt",
];
/// dev-newmac's `recovery_add`, still waiting; then approved by dev-mac.
const R7: &[&str] = &["R7"];
const R7_A8: &[&str] = &["R7", "A8"];
/// svc-discord removed (by dev-phone).
const E7_REMOVED: &[&str] = &["E7"];

/// The record `n`'s id: a UUID v4.
fn control_rid(n: u64) -> String {
    format!("00000000-0000-4000-8000-{n:012x}")
}

/// When the record `n` is issued: in the order of `n`.
fn control_issued(n: u64) -> u64 {
    CONTROL_T0 + n * 1000
}

/// What `verify_control` says of a record against L + a chain.
enum ControlVerdict {
    /// Signed by an allowed key: the verified signer (`service:<id>` or
    /// `member:<id>`) and, for a service's own key, the `seq` of the entry
    /// that enrolled it.
    Valid(&'static str, Option<u64>),
    Pending(&'static str),
    Refused(&'static str),
}

fn verdict_json(chain: &[&str], verdict: ControlVerdict) -> Value {
    match verdict {
        ControlVerdict::Valid(signer, key_seq) => {
            let mut v = serde_json::json!({"chain": chain, "verdict": "valid", "signer": signer});
            if let Some(seq) = key_seq {
                v["key_seq"] = seq.into();
            }
            v
        }
        ControlVerdict::Pending(reason) => {
            serde_json::json!({"chain": chain, "verdict": "pending", "reason": reason})
        }
        ControlVerdict::Refused(reason) => {
            serde_json::json!({"chain": chain, "verdict": "refused", "reason": reason})
        }
    }
}

/// One application's expected result (`ControlState::apply`).
fn applied(result: &str, effects: &[(&str, &str)], actions: Vec<Value>, evidence: bool) -> Value {
    let effects: Vec<Value> = effects
        .iter()
        .map(|(effect, result)| serde_json::json!({"effect": effect, "result": result}))
        .collect();
    serde_json::json!({
        "result": result,
        "effects": effects,
        "actions": actions,
        "evidence": evidence,
    })
}

/// A host action as the vectors write it: `{"type", …}`.
fn act(kind: &str, principal: &str) -> Value {
    serde_json::json!({"type": kind, "principal": principal})
}

fn act_cover(feed: Feed) -> Value {
    serde_json::json!({"type": "cover", "principal": SVC, "origin": feed.0, "feed_id": feed.1})
}

fn act_interrupt(principal: &str, revocation: &str) -> Value {
    serde_json::json!({"type": "interrupt", "principal": principal, "revocation": revocation})
}

/// One step of a sequence: the record (by label), the device list the
/// transaction holds (L + `chain`), where it was read (`None` over a
/// channel), host-work's applied device-list `seq`, and the result.
fn control_step(
    record: &str,
    chain: &[&str],
    pos: Option<(Feed, u64)>,
    host_applied_seq: u64,
    expect: Value,
) -> Value {
    let mut v = serde_json::json!({
        "record": record,
        "chain": chain,
        "host_applied_seq": host_applied_seq,
        "expect": expect,
    });
    if let Some((feed, feed_seq)) = pos {
        v["pos"] = serde_json::json!({"origin": feed.0, "feed_id": feed.1, "feed_seq": feed_seq});
    }
    v
}

/// Builds the control-record vectors on log L with the test keys.
struct ControlGen<'a> {
    book: &'a Book,
    ctx: Context,
    records: Vec<Value>,
}

impl<'a> ControlGen<'a> {
    fn new(book: &'a Book) -> Self {
        let mlog = load("r9-vectors-membership-log");
        ControlGen {
            book,
            ctx: Context::new(&mlog["log"], &mlog["others"], genesis_hash()),
            records: Vec::new(),
        }
    }

    /// The `r9Svc` of a member's `auth` test key.
    fn r9_svc(&self, name: &str) -> Hash32 {
        principal_key_of(&self.book.signer_public(name)).unwrap()
    }

    /// The record `n` about svc-discord in `feed`, its signer the service
    /// itself or `member:<device_id>`.
    fn svc(
        &self,
        n: u64,
        signer: &str,
        action: ControlAction,
        feed: Feed,
        by: &str,
    ) -> ControlBody {
        ControlBody {
            account_id: "acct-test-1".into(),
            genesis_hash: genesis_hash(),
            feed: Some(ControlFeed {
                origin: feed.0.into(),
                feed_id: feed.1.into(),
            }),
            principal: ControlPrincipal::Service("svc-discord".into()),
            principal_key: Some(self.r9_svc("svc-discord")),
            signer: match signer.strip_prefix("member:") {
                Some(id) => ControlSigner::Member(id.into()),
                None => ControlSigner::Principal,
            },
            action,
            record_id: control_rid(n),
            issued_at: control_issued(n),
            about: ControlAbout {
                integration_id: Some(CONTROL_INTEGRATION.into()),
                by: by.into(),
            },
        }
    }

    /// The record `n`: `member:dev-mac`'s `interrupt_running` of `host_id`
    /// after the device-list revoke at `revoke_seq`.
    fn host(&self, n: u64, host_id: &str, revoke_seq: u64) -> ControlBody {
        ControlBody {
            account_id: "acct-test-1".into(),
            genesis_hash: genesis_hash(),
            feed: None,
            principal: ControlPrincipal::Host(host_id.into()),
            principal_key: None,
            signer: ControlSigner::Member("dev-mac".into()),
            action: ControlAction::InterruptRunning {
                revoke_seq: Some(revoke_seq),
            },
            record_id: control_rid(n),
            issued_at: control_issued(n),
            about: ControlAbout {
                integration_id: None,
                by: "owner".into(),
            },
        }
    }

    /// `body` signed with the test key `signed_with`, and its verdicts.
    fn push(
        &mut self,
        label: &str,
        note: &str,
        signed_with: &str,
        body: &ControlBody,
        checks: Vec<(&[&str], ControlVerdict)>,
    ) {
        let object = build_control(&self.book.provider, &self.book.signer(signed_with), body)
            .unwrap_or_else(|e| panic!("{label}: {e}"));
        let checks = checks
            .into_iter()
            .map(|(chain, verdict)| verdict_json(chain, verdict))
            .collect();
        self.push_object(label, note, signed_with, &object, Ok(checks));
    }

    /// A body the record's parse refuses for `code`, signed as it stands
    /// (the signed-object layer takes it).
    fn push_refused(
        &mut self,
        label: &str,
        note: &str,
        signed_with: &str,
        body: Value,
        code: &str,
    ) {
        let object =
            SignedObject::sign(&self.book.provider, &self.book.signer(signed_with), body).unwrap();
        self.push_object(label, note, signed_with, &object, Err(code));
    }

    fn push_object(
        &mut self,
        label: &str,
        note: &str,
        signed_with: &str,
        object: &SignedObject,
        outcome: Result<Vec<Value>, &str>,
    ) {
        let mut v = serde_json::json!({
            "label": label,
            "note": note,
            "signed_with": signed_with,
            "record": object.to_json(),
            "jcs": object.jcs(),
            "signing_input_hex": hex(object.signing_input().as_bytes()),
        });
        if object.body()["principal"] == SVC {
            v["r9_svc"] = self.r9_svc("svc-discord").to_hex().into();
        }
        match outcome {
            Ok(checks) => v["checks"] = Value::Array(checks),
            Err(code) => v["parse_error"] = code.into(),
        }
        self.records.push(v);
    }

    /// The wire record `label`.
    fn record(&self, label: &str) -> ControlRecord {
        let v = self
            .records
            .iter()
            .find(|v| v["label"] == label)
            .unwrap_or_else(|| panic!("no record {label}"));
        ControlRecord::parse(v["record"].to_string().as_bytes()).unwrap()
    }

    /// A sequence: its steps applied to a new state of L, and the state
    /// they leave (`ControlState::to_json`, the form a host persists).
    fn sequence(&self, label: &str, note: &str, steps: Vec<Value>) -> Value {
        let mut state = ControlState::new(&self.ctx.chain(&[]));
        for step in &steps {
            let chain = chain_labels(step);
            state = state
                .apply(
                    &self.record(s(step, "record")),
                    &self.ctx.chain(&chain),
                    feed_pos(step),
                    step["host_applied_seq"].as_u64().unwrap(),
                )
                .next;
        }
        serde_json::json!({"label": label, "note": note, "steps": steps, "state": state.to_json()})
    }
}

/// A step's feed position.
fn feed_pos(step: &Value) -> Option<FeedPos> {
    step.get("pos").map(|pos| FeedPos {
        origin: s(pos, "origin").into(),
        feed_id: s(pos, "feed_id").into(),
        feed_seq: pos["feed_seq"].as_u64().unwrap(),
    })
}

/// The control-record vectors (`r9-vectors-host-work-control`). Every
/// verdict and every step's result is written out by hand here;
/// `host_work_control` compares them with the verifier and the state.
fn control_vectors(book: &Book) -> Value {
    use ControlAction as C;
    use ControlVerdict::{Pending, Refused, Valid};
    let mut g = ControlGen::new(book);
    let l: &[&str] = &[];
    let own_ = || Valid(SVC, Some(5));
    let mac = || Valid("member:dev-mac", None);
    let revoke = |interrupt_running| C::Revoke { interrupt_running };
    let interrupt = C::InterruptRunning { revoke_seq: None };

    // ---- svc-discord's own key (Ed25519, E5), on station-dev's feed
    let body = g.svc(1, SVC, C::Cover, FEED_A, "station");
    g.push(
        "S1_cover",
        "station-dev covers svc-discord (signed with the integration's service key)",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );
    let body = g.svc(2, SVC, C::Hold, FEED_A, "owner");
    g.push(
        "S2_hold",
        "a pause",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );
    let body = g.svc(3, SVC, C::Release, FEED_A, "owner");
    g.push(
        "S3_release",
        "a resume",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );
    let body = g.svc(4, SVC, revoke(false), FEED_A, "owner");
    g.push(
        "S4_revoke",
        "the revocation; still valid after svc-discord's removal (E7): the principal's own key from the history signs every action",
        "svc-discord",
        &body,
        vec![(l, own_()), (E7_REMOVED, own_())],
    );
    let body = g.svc(5, SVC, revoke(true), FEED_A, "owner");
    g.push(
        "S5_revoke_interrupt",
        "a revoke that adds interrupt_running: true",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );
    let body = g.svc(6, SVC, interrupt, FEED_A, "owner");
    g.push(
        "S6_interrupt",
        "a later interrupt_running",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );
    let body = g.svc(7, SVC, C::Hold, FEED_A, "agora_build");
    g.push(
        "S7_hold_after_revoke",
        "a pause issued after the revoke",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );
    let body = g.svc(8, SVC, revoke(false), FEED_A, "future_reason");
    g.push(
        "S8_revoke_unknown_by",
        "about.by names a reason no host knows yet: display only, the record applies",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );

    // ---- another Station's feed, and station-dev's feed after a reset
    let mut body = g.svc(9, SVC, C::Cover, FEED_B, "station");
    body.issued_at = control_issued(1) - 60_000;
    g.push(
        "B1_cover_stale",
        "station-b's cover, issued a minute before S1_cover",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );
    let body = g.svc(10, SVC, C::Release, FEED_B, "owner");
    g.push(
        "B2_release",
        "station-b's release, read before its cover",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );
    let body = g.svc(11, SVC, C::Cover, FEED_B, "station");
    g.push(
        "B3_cover",
        "station-b's cover, newer than S1_cover: the integration moved",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );
    let body = g.svc(12, SVC, C::Hold, FEED_B, "owner");
    g.push(
        "B4_hold",
        "station-b's pause",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );
    let body = g.svc(13, SVC, C::Release, FEED_B, "owner");
    g.push(
        "B5_release",
        "station-b's resume",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );
    let body = g.svc(14, SVC, C::Cover, FEED_A2, "station");
    g.push(
        "A2_cover",
        "station-dev's reset snapshot: its cover signed anew (newer) on the new feed",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );
    let body = g.svc(15, SVC, C::Hold, FEED_A2, "owner");
    g.push(
        "A2_hold",
        "the snapshot's pause, signed anew after its cover",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );
    let body = g.svc(16, SVC, C::Release, FEED_A2, "owner");
    g.push(
        "A2_release",
        "a resume on the new feed",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );

    // ---- native managers (P-256): revoke and interrupt_running only
    let body = g.svc(20, "member:dev-mac", revoke(false), FEED_A, "owner");
    g.push(
        "M1_revoke",
        "a native manager's revoke of svc-discord (Astation)",
        "dev-mac",
        &body,
        vec![(l, mac())],
    );
    let body = g.svc(21, "member:dev-mac", interrupt, FEED_A, "owner");
    g.push(
        "M2_interrupt",
        "a native manager's interrupt_running",
        "dev-mac",
        &body,
        vec![(l, mac())],
    );
    let mut body = g.svc(22, "member:dev-ipad", revoke(true), FEED_A, "owner");
    body.issued_at = 1_792_400_004_500;
    g.push(
        "M3_revoke_by_removed_manager",
        "signed by dev-ipad while it was a manager, before E6 removed it; the host receives it after E6: refused and kept as evidence",
        "dev-ipad",
        &body,
        vec![(l, Refused("removed_manager"))],
    );
    let mut body = g.svc(23, "member:dev-mac", revoke(true), FEED_A, "owner");
    body.issued_at = 1_792_400_004_500;
    g.push(
        "M4_revoke_resigned",
        "M3's stop signed again by dev-mac, a current manager: the same body, a new record_id",
        "dev-mac",
        &body,
        vec![(l, mac())],
    );
    let body = g.svc(24, "member:dev-newmac", revoke(false), FEED_A, "owner");
    g.push(
        "M5_revoke_by_pending_member",
        "signed by dev-newmac: not in L, then the subject of a recovery_add still waiting (R7), then a manager once A8 approves it",
        "dev-newmac",
        &body,
        vec![
            (l, Pending("signer_unknown")),
            (R7, Pending("signer_unknown")),
            (R7_A8, Valid("member:dev-newmac", None)),
        ],
    );
    let body = g.svc(25, "member:dev-mac", C::Hold, FEED_A, "owner");
    g.push(
        "M6_hold_by_manager",
        "a native manager never signs cover, hold or release",
        "dev-mac",
        &body,
        vec![(l, Refused("signer_not_allowed"))],
    );

    // ---- a host principal: a native manager's interrupt_running only
    let body = g.host(30, "host-a", 7);
    g.push(
        "H1_interrupt_7",
        "interrupt host-a's tasks admitted before its revoke at seq 7 (HS7_revoke): pending until the list holds that revoke",
        "dev-mac",
        &body,
        vec![(l, Pending("revoke_not_in_list")), (HS7, mac())],
    );
    let body = g.host(31, "host-a", 7);
    g.push(
        "H2_interrupt_7_again",
        "another record for the same revoke_seq",
        "dev-mac",
        &body,
        vec![(HS7, mac())],
    );
    let body = g.host(32, "host-a", 12);
    g.push(
        "H3_interrupt_12",
        "for HS12_revoke_interrupt, a revoke that carried interrupt_running: true",
        "dev-mac",
        &body,
        vec![(HS12, mac())],
    );
    let body = g.host(33, "host-a", 2);
    g.push(
        "H4_interrupt_not_a_revoke",
        "revoke_seq 2 names E2 (host-a's add_host), not a revoke of host-a",
        "dev-mac",
        &body,
        vec![(l, Refused("not_a_revoke")), (HS7, Refused("not_a_revoke"))],
    );
    let body = g.host(34, "host-b", 99);
    g.push(
        "H5_interrupt_unknown_host",
        "host-b has no add_host in the list yet",
        "dev-mac",
        &body,
        vec![
            (l, Pending("principal_unknown")),
            (HS7, Pending("principal_unknown")),
        ],
    );
    let mut body = g.host(35, "host-a", 7);
    body.signer = ControlSigner::Principal;
    g.push(
        "H6_host_key_signed",
        "signed by host-a's own host_key: a host's key signs no control record",
        "host-a",
        &body,
        vec![
            (l, Refused("host_key_signed")),
            (HS7, Refused("host_key_signed")),
        ],
    );

    // ---- refused or pending by verification
    let mut body = g.svc(40, SVC, C::Cover, FEED_A, "station");
    body.account_id = "acct-other".into();
    g.push(
        "V1_wrong_account",
        "another account_id",
        "svc-discord",
        &body,
        vec![(l, Refused("wrong_account"))],
    );
    let body = g.svc(41, SVC, C::Cover, FEED_A, "station");
    let mut object = build_control(&book.provider, &book.signer("svc-discord"), &body).unwrap();
    let mut wire = object.to_json();
    let mut sig = b64u_decode(s(&wire, "sig")).unwrap();
    sig[0] ^= 1;
    wire["sig"] = b64u(&sig).into();
    object = SignedObject::parse(wire.to_string().as_bytes()).unwrap();
    g.push_object(
        "V2_bad_signature",
        "svc-discord's signature with its first byte flipped",
        "svc-discord",
        &object,
        Ok(vec![verdict_json(l, Refused("bad_signature"))]),
    );
    let mut body = g.svc(42, SVC, C::Release, FEED_A, "owner");
    body.principal_key = Some(g.r9_svc("dev-mac"));
    g.push(
        "V3_key_mismatch",
        "principal_key names dev-mac's key, not svc-discord's (r9_svc beside it is svc-discord's)",
        "svc-discord",
        &body,
        vec![(l, Refused("key_mismatch"))],
    );
    let mut body = g.svc(43, "member:dev-mac", revoke(false), FEED_A, "owner");
    body.principal = ControlPrincipal::Service("dev-phone".into());
    body.principal_key = Some(g.r9_svc("dev-phone"));
    g.push(
        "V4_not_a_service",
        "service:dev-phone names a native member",
        "dev-mac",
        &body,
        vec![(l, Refused("not_a_service"))],
    );
    let mut body = g.svc(44, "member:dev-mac", revoke(false), FEED_A, "owner");
    body.principal = ControlPrincipal::Service("svc-new".into());
    body.principal_key = Some(Hash32::of(b"svc-new"));
    g.push(
        "V5_principal_unknown",
        "service:svc-new isn't in the list yet (its principal_key names a key the list doesn't hold)",
        "dev-mac",
        &body,
        vec![(l, Pending("principal_unknown"))],
    );
    let mut body = g.svc(1, SVC, C::Cover, FEED_A, "owner");
    body.issued_at = control_issued(45);
    g.push(
        "V6_conflicting_id",
        "S1_cover's record_id with another body: valid by itself; a host that counted S1_cover refuses it and keeps it as evidence",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );

    // ---- refused by the record's parse (kept as evidence in a feed)
    let host_base = || g.host(50, "host-a", 7).to_json();
    let svc_base = || g.svc(51, SVC, C::Cover, FEED_A, "station").to_json();
    let mut v = host_base();
    v["action"] = "release".into();
    v.as_object_mut().unwrap().remove("revoke_seq");
    v["record_id"] = control_rid(50).into();
    let host_release = v;
    let mut v = g.svc(52, SVC, revoke(false), FEED_A, "owner").to_json();
    v["revoke_seq"] = 7.into();
    let revoke_seq = v;
    let mut v = g.host(53, "host-a", 7).to_json();
    v["origin"] = FEED_A.0.into();
    v["feed_id"] = FEED_A.1.into();
    let host_feed = v;
    let mut v = svc_base();
    v["record_id"] = control_rid(54).into();
    v["note"] = "x".into();
    let extra = v;
    let mut v = svc_base();
    v["record_id"] = control_rid(55).into();
    v["about"]["by"] = "Owner".into();
    let by = v;
    let mut v = svc_base();
    v["record_id"] = control_rid(56).into();
    v["about"].as_object_mut().unwrap().remove("integration_id");
    let no_integration = v;
    let mut v = g.svc(57, SVC, C::Hold, FEED_A, "owner").to_json();
    v["interrupt_running"] = false.into();
    let hold_interrupt = v;
    for (label, note, signed_with, body, code) in [
        (
            "P1_host_release",
            "a host principal's release: refused at parse",
            "dev-mac",
            host_release,
            "not_for_host_principal",
        ),
        (
            "P2_service_revoke_seq",
            "revoke_seq on a service's record",
            "svc-discord",
            revoke_seq,
            "field_not_allowed",
        ),
        (
            "P3_host_feed",
            "origin and feed_id on a host principal's record (bound to no feed)",
            "dev-mac",
            host_feed,
            "field_not_allowed",
        ),
        (
            "P4_unknown_field",
            "a field the body doesn't have",
            "svc-discord",
            extra,
            "unknown_field",
        ),
        (
            "P5_by_not_a_label",
            "about.by outside [a-z_]",
            "svc-discord",
            by,
            "malformed",
        ),
        (
            "P6_no_integration_id",
            "a service's record without about.integration_id",
            "svc-discord",
            no_integration,
            "malformed",
        ),
        (
            "P7_hold_interrupt_running",
            "interrupt_running beside an action other than revoke",
            "svc-discord",
            hold_interrupt,
            "field_not_allowed",
        ),
    ] {
        g.push_refused(label, note, signed_with, body, code);
    }

    // ---- a stop always wins, record ids per principal, an issued_at tie
    let mut body = g.svc(60, SVC, C::Cover, FEED_A2, "station");
    body.issued_at = control_issued(1) - 1000;
    g.push(
        "A2_cover_not_newer",
        "station-dev's reset snapshot cover, signed with a clock behind S1_cover's: not newer, so the coverage stays on the old feed",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );
    let body = g.svc(61, SVC, C::Hold, FEED_A, "owner");
    g.push(
        "S9_hold",
        "a pause applied out of feed order (say it waited)",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );
    let body = g.svc(62, SVC, C::Release, FEED_A, "owner");
    g.push(
        "S10_release",
        "a resume at a position before the feed's last hold or release",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );
    let body = g.svc(63, SVC, C::Release, FEED_A, "owner");
    g.push(
        "S11_release",
        "a resume after the feed's last hold or release",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );
    let tie = control_issued(66);
    let mut body = g.svc(64, SVC, C::Cover, FEED_A, "station");
    body.issued_at = tie;
    g.push(
        "T1_cover_tie_lower_id",
        "station-dev's cover issued at the same time as T2_cover_tie, with a lower record_id",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );
    let mut body = g.svc(65, SVC, C::Cover, FEED_B, "station");
    body.issued_at = tie;
    g.push(
        "T2_cover_tie",
        "station-b's cover",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );
    let body = g.svc(66, SVC, C::Cover, FEED_A, "station");
    g.push(
        "T3_cover_tie_higher_id",
        "station-dev's cover issued at the same time as T2_cover_tie, with a higher record_id: newer",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );
    let mut body = g.svc(67, SVC, C::Cover, FEED_B, "station");
    body.record_id = control_rid(30);
    g.push(
        "X1_cover_under_h1_id",
        "svc-discord's own cover under the record_id of H1_interrupt_7 (host-a's): a record of another principal never blocks it",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );
    let mut body = g.svc(68, SVC, C::Hold, FEED_A, "owner");
    body.record_id = control_rid(3);
    g.push(
        "X2_hold_under_s3_id",
        "a pause under S3_release's record_id: a stop, it applies, and the reused id is evidence",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );
    let mut body = g.svc(69, SVC, C::Release, FEED_A, "owner");
    body.record_id = control_rid(2);
    g.push(
        "X3_release_under_s2_id",
        "a resume under S2_hold's record_id: refused, and the reused id is evidence",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );
    let mut body = g.svc(70, SVC, revoke(true), FEED_A, "owner");
    body.record_id = control_rid(1);
    g.push(
        "X4_revoke_under_s1_id",
        "a revoke with interrupt_running under S1_cover's record_id: a stop, it applies, and the reused id is evidence",
        "svc-discord",
        &body,
        vec![(l, own_())],
    );

    // ---- sequences: one host's control state, step by step
    let a = |n| Some((FEED_A, n));
    let b = |n| Some((FEED_B, n));
    let a2 = |n| Some((FEED_A2, n));
    let none: Vec<Value> = Vec::new();
    let step = |record, pos, expect| control_step(record, &[], pos, 6, expect);
    let sequences = vec![
        g.sequence(
            "Q1_service_on_one_feed",
            "cover, hold, release, then the revocation from the Station and from a native manager, its interrupt added later, and a pause after it",
            vec![
                step("S1_cover", a(1), applied("applied", &[("cover", "applied")], vec![act_cover(FEED_A)], false)),
                step("S2_hold", a(2), applied("applied", &[("hold", "applied")], vec![act("hold", SVC)], false)),
                step("S2_hold", a(2), applied("duplicate", &[("hold", "duplicate")], none.clone(), false)),
                step("S3_release", a(3), applied("applied", &[("release", "applied")], vec![act("release", SVC)], false)),
                step("S4_revoke", a(4), applied("applied", &[("revocation", "applied")], vec![act("revoke", SVC)], false)),
                step("M1_revoke", a(5), applied("duplicate", &[("revocation", "duplicate")], none.clone(), false)),
                step(
                    "S5_revoke_interrupt",
                    a(6),
                    applied(
                        "applied",
                        &[("revocation", "duplicate"), ("interrupt", "applied")],
                        vec![act_interrupt(SVC, &control_rid(4))],
                        false,
                    ),
                ),
                step("M2_interrupt", a(7), applied("duplicate", &[("interrupt", "duplicate")], none.clone(), false)),
                step("S6_interrupt", a(8), applied("duplicate", &[("interrupt", "duplicate")], none.clone(), false)),
                step("S7_hold_after_revoke", a(9), applied("refused", &[("hold", "refused")], none.clone(), false)),
            ],
        ),
        g.sequence(
            "Q2_removed_manager_then_resigned",
            "a stop signed by a manager removed before the host received it is refused (evidence); its re-signed copy applies",
            vec![
                step(
                    "M3_revoke_by_removed_manager",
                    a(1),
                    applied("refused", &[("revocation", "refused"), ("interrupt", "refused")], none.clone(), true),
                ),
                step(
                    "M4_revoke_resigned",
                    a(2),
                    applied(
                        "applied",
                        &[("revocation", "applied"), ("interrupt", "applied")],
                        vec![act("revoke", SVC), act_interrupt(SVC, &control_rid(23))],
                        false,
                    ),
                ),
                step(
                    "M3_revoke_by_removed_manager",
                    a(1),
                    applied("refused", &[("revocation", "refused"), ("interrupt", "refused")], none.clone(), true),
                ),
            ],
        ),
        g.sequence(
            "Q3_pending_signer",
            "a record whose native signer the list doesn't hold yet waits, and applies once its recovery took effect",
            vec![
                control_step("M5_revoke_by_pending_member", &[], a(1), 6, applied("pending", &[("revocation", "pending")], none.clone(), false)),
                control_step("M5_revoke_by_pending_member", R7, a(1), 7, applied("pending", &[("revocation", "pending")], none.clone(), false)),
                control_step(
                    "M5_revoke_by_pending_member",
                    R7_A8,
                    a(1),
                    8,
                    applied("applied", &[("revocation", "applied")], vec![act("revoke", SVC)], false),
                ),
            ],
        ),
        g.sequence(
            "Q4_cover_from_another_station",
            "covers are ordered by (issued_at, record_id): a stale cover from another Station neither takes coverage nor releases; a newer one takes coverage and the hold persists until the new feed releases",
            vec![
                step("S1_cover", a(1), applied("applied", &[("cover", "applied")], vec![act_cover(FEED_A)], false)),
                step("S2_hold", a(2), applied("applied", &[("hold", "applied")], vec![act("hold", SVC)], false)),
                step("B1_cover_stale", b(1), applied("refused", &[("cover", "refused")], none.clone(), false)),
                step("B2_release", b(2), applied("refused", &[("release", "refused")], none.clone(), false)),
                step("B3_cover", b(3), applied("applied", &[("cover", "applied")], vec![act_cover(FEED_B)], false)),
                step("B4_hold", b(4), applied("duplicate", &[("hold", "duplicate")], none.clone(), false)),
                step("S3_release", a(3), applied("refused", &[("release", "refused")], none.clone(), false)),
                step("B5_release", b(5), applied("applied", &[("release", "applied")], vec![act("release", SVC)], false)),
            ],
        ),
        g.sequence(
            "Q5_feed_reset",
            "a reset's newer cover (a duplicate) moves the ordering to the new feed; the old feed's release no longer applies",
            vec![
                step("S1_cover", a(1), applied("applied", &[("cover", "applied")], vec![act_cover(FEED_A)], false)),
                step("S2_hold", a(2), applied("applied", &[("hold", "applied")], vec![act("hold", SVC)], false)),
                step("A2_cover", a2(1), applied("duplicate", &[("cover", "duplicate")], vec![act_cover(FEED_A2)], false)),
                step("A2_hold", a2(2), applied("duplicate", &[("hold", "duplicate")], none.clone(), false)),
                step("S3_release", a(3), applied("refused", &[("release", "refused")], none.clone(), false)),
                step("A2_release", a2(3), applied("applied", &[("release", "applied")], vec![act("release", SVC)], false)),
            ],
        ),
        g.sequence(
            "Q6_feed_reset_on_a_new_host",
            "a host that never saw the old feed applies the snapshot: no stop is lost; the old feed's older cover is a duplicate that moves nothing back",
            vec![
                step("A2_cover", a2(1), applied("applied", &[("cover", "applied")], vec![act_cover(FEED_A2)], false)),
                step("A2_hold", a2(2), applied("applied", &[("hold", "applied")], vec![act("hold", SVC)], false)),
                step("S1_cover", a(1), applied("duplicate", &[("cover", "duplicate")], none.clone(), false)),
                step("S3_release", a(3), applied("refused", &[("release", "refused")], none.clone(), false)),
            ],
        ),
        g.sequence(
            "Q7_host_interrupt",
            "revoke_seq names that host's own revoke: pending until the list holds it and host-work applied it (host_applied_seq); one interrupt per revoke_seq; a revoke entry with interrupt_running: true already interrupted",
            vec![
                control_step("H1_interrupt_7", &[], None, 6, applied("pending", &[("interrupt", "pending")], none.clone(), false)),
                control_step("H1_interrupt_7", HS7, None, 6, applied("pending", &[("interrupt", "pending")], none.clone(), false)),
                control_step(
                    "H1_interrupt_7",
                    HS7,
                    None,
                    7,
                    applied("applied", &[("interrupt", "applied")], vec![act_interrupt(HOST_A, "7")], false),
                ),
                control_step("H2_interrupt_7_again", HS7, a(1), 7, applied("duplicate", &[("interrupt", "duplicate")], none.clone(), false)),
                control_step("H1_interrupt_7", HS7, None, 7, applied("duplicate", &[("interrupt", "duplicate")], none.clone(), false)),
                control_step("H4_interrupt_not_a_revoke", HS7, None, 7, applied("refused", &[("interrupt", "refused")], none.clone(), true)),
                control_step("H6_host_key_signed", HS7, None, 7, applied("refused", &[("interrupt", "refused")], none.clone(), true)),
                control_step("H3_interrupt_12", HS12, None, 12, applied("duplicate", &[("interrupt", "duplicate")], none.clone(), false)),
            ],
        ),
        g.sequence(
            "Q8_refused_and_kept_as_evidence",
            "verification refusals and a reused record_id are evidence; a pending record is not",
            vec![
                step("S1_cover", a(1), applied("applied", &[("cover", "applied")], vec![act_cover(FEED_A)], false)),
                step("V6_conflicting_id", a(2), applied("refused", &[("cover", "refused")], none.clone(), true)),
                step("V2_bad_signature", a(3), applied("refused", &[("cover", "refused")], none.clone(), true)),
                step("V1_wrong_account", a(4), applied("refused", &[("cover", "refused")], none.clone(), true)),
                step("V3_key_mismatch", a(5), applied("refused", &[("release", "refused")], none.clone(), true)),
                step("M6_hold_by_manager", a(6), applied("refused", &[("hold", "refused")], none.clone(), true)),
                step("V4_not_a_service", a(7), applied("refused", &[("revocation", "refused")], none.clone(), true)),
                step("V5_principal_unknown", a(8), applied("pending", &[("revocation", "pending")], none.clone(), false)),
            ],
        ),
        g.sequence(
            "Q9_unknown_by_applies",
            "an about.by no host knows applies: about decides nothing",
            vec![step("S8_revoke_unknown_by", a(1), applied("applied", &[("revocation", "applied")], vec![act("revoke", SVC)], false))],
        ),
        g.sequence(
            "Q10_hold_from_a_station_that_lost_the_takeover",
            "a stop always wins: the hold of a Station whose cover wasn't newer applies; its release is refused, the covering feed's release lifts the hold, and the hold replayed is a duplicate",
            vec![
                step("S1_cover", a(1), applied("applied", &[("cover", "applied")], vec![act_cover(FEED_A)], false)),
                step("B1_cover_stale", b(1), applied("refused", &[("cover", "refused")], none.clone(), false)),
                step("B4_hold", b(2), applied("applied", &[("hold", "applied")], vec![act("hold", SVC)], false)),
                step("B5_release", b(3), applied("refused", &[("release", "refused")], none.clone(), false)),
                step("S3_release", a(2), applied("applied", &[("release", "applied")], vec![act("release", SVC)], false)),
                step("B4_hold", b(2), applied("duplicate", &[("hold", "duplicate")], none.clone(), false)),
            ],
        ),
        g.sequence(
            "Q11_reset_cover_not_newer",
            "a reset whose snapshot cover isn't newer leaves the coverage on the old feed: the new feed's hold applies, its release is refused, and the old feed's release lifts the hold",
            vec![
                step("S1_cover", a(1), applied("applied", &[("cover", "applied")], vec![act_cover(FEED_A)], false)),
                step("A2_cover_not_newer", a2(1), applied("duplicate", &[("cover", "duplicate")], none.clone(), false)),
                step("A2_hold", a2(2), applied("applied", &[("hold", "applied")], vec![act("hold", SVC)], false)),
                step("A2_release", a2(3), applied("refused", &[("release", "refused")], none.clone(), false)),
                step("S3_release", a(2), applied("applied", &[("release", "applied")], vec![act("release", SVC)], false)),
            ],
        ),
        g.sequence(
            "Q12_service_interrupt_waits",
            "a service's interrupt_running waits for the service's revocation on this host, then applies once",
            vec![
                step("S6_interrupt", a(1), applied("pending", &[("interrupt", "pending")], none.clone(), false)),
                step("S4_revoke", a(2), applied("applied", &[("revocation", "applied")], vec![act("revoke", SVC)], false)),
                step(
                    "S6_interrupt",
                    a(1),
                    applied("applied", &[("interrupt", "applied")], vec![act_interrupt(SVC, &control_rid(4))], false),
                ),
                step("S6_interrupt", a(1), applied("duplicate", &[("interrupt", "duplicate")], none.clone(), false)),
            ],
        ),
        g.sequence(
            "Q13_out_of_order_in_one_feed",
            "within the covering feed a hold applied out of feed order still applies; a release must come after the feed's last hold or release",
            vec![
                step("S1_cover", a(1), applied("applied", &[("cover", "applied")], vec![act_cover(FEED_A)], false)),
                step("S2_hold", a(2), applied("applied", &[("hold", "applied")], vec![act("hold", SVC)], false)),
                step("S3_release", a(5), applied("applied", &[("release", "applied")], vec![act("release", SVC)], false)),
                step("S9_hold", a(3), applied("applied", &[("hold", "applied")], vec![act("hold", SVC)], false)),
                step("S10_release", a(4), applied("refused", &[("release", "refused")], none.clone(), false)),
                step("S11_release", a(6), applied("applied", &[("release", "applied")], vec![act("release", SVC)], false)),
            ],
        ),
        g.sequence(
            "Q14_hold_with_no_coverage",
            "a hold applies with no coverage at all; a release needs the covering feed, after its cover",
            vec![
                step("B4_hold", b(1), applied("applied", &[("hold", "applied")], vec![act("hold", SVC)], false)),
                step("B2_release", b(2), applied("refused", &[("release", "refused")], none.clone(), false)),
                step("B3_cover", b(3), applied("applied", &[("cover", "applied")], vec![act_cover(FEED_B)], false)),
                step("B5_release", b(4), applied("applied", &[("release", "applied")], vec![act("release", SVC)], false)),
            ],
        ),
        g.sequence(
            "Q15_old_cover_replayed_after_a_move",
            "the old Station's cover replayed after the coverage moved is a duplicate that moves nothing back: the old feed's hold still applies, its release doesn't",
            vec![
                step("S1_cover", a(1), applied("applied", &[("cover", "applied")], vec![act_cover(FEED_A)], false)),
                step("B3_cover", b(1), applied("applied", &[("cover", "applied")], vec![act_cover(FEED_B)], false)),
                step("S1_cover", a(1), applied("duplicate", &[("cover", "duplicate")], none.clone(), false)),
                step("S2_hold", a(2), applied("applied", &[("hold", "applied")], vec![act("hold", SVC)], false)),
                step("S3_release", a(3), applied("refused", &[("release", "refused")], none.clone(), false)),
                step("B5_release", b(2), applied("applied", &[("release", "applied")], vec![act("release", SVC)], false)),
            ],
        ),
        g.sequence(
            "Q16_issued_at_tie",
            "covers issued at the same time are ordered by record_id: the lower one doesn't take coverage, the higher one does",
            vec![
                step("T2_cover_tie", b(1), applied("applied", &[("cover", "applied")], vec![act_cover(FEED_B)], false)),
                step("T1_cover_tie_lower_id", a(1), applied("refused", &[("cover", "refused")], none.clone(), false)),
                step("T3_cover_tie_higher_id", a(2), applied("applied", &[("cover", "applied")], vec![act_cover(FEED_A)], false)),
            ],
        ),
        g.sequence(
            "Q17_record_ids_per_principal",
            "a record of one principal under another principal's record_id blocks nothing: idempotency is by principal and record_id",
            vec![
                control_step(
                    "X1_cover_under_h1_id",
                    HS7,
                    b(1),
                    7,
                    applied("applied", &[("cover", "applied")], vec![act_cover(FEED_B)], false),
                ),
                control_step(
                    "H1_interrupt_7",
                    HS7,
                    None,
                    7,
                    applied("applied", &[("interrupt", "applied")], vec![act_interrupt(HOST_A, "7")], false),
                ),
                control_step("X1_cover_under_h1_id", HS7, b(1), 7, applied("duplicate", &[("cover", "duplicate")], none.clone(), false)),
                control_step("H1_interrupt_7", HS7, None, 7, applied("duplicate", &[("interrupt", "duplicate")], none.clone(), false)),
            ],
        ),
        g.sequence(
            "Q18_colliding_record_ids",
            "another body under a record_id the same principal's record counted with is evidence, and the first body keeps the id: a stop (hold, revoke) still applies, a release or cover is refused",
            vec![
                step("S1_cover", a(1), applied("applied", &[("cover", "applied")], vec![act_cover(FEED_A)], false)),
                step("S2_hold", a(2), applied("applied", &[("hold", "applied")], vec![act("hold", SVC)], false)),
                step("S3_release", a(3), applied("applied", &[("release", "applied")], vec![act("release", SVC)], false)),
                step("X2_hold_under_s3_id", a(4), applied("applied", &[("hold", "applied")], vec![act("hold", SVC)], true)),
                step("X3_release_under_s2_id", a(5), applied("refused", &[("release", "refused")], none.clone(), true)),
                step("V6_conflicting_id", a(6), applied("refused", &[("cover", "refused")], none.clone(), true)),
                step(
                    "X4_revoke_under_s1_id",
                    a(7),
                    applied(
                        "applied",
                        &[("revocation", "applied"), ("interrupt", "applied")],
                        vec![act("revoke", SVC), act_interrupt(SVC, &control_rid(1))],
                        true,
                    ),
                ),
                step(
                    "X4_revoke_under_s1_id",
                    a(7),
                    applied("duplicate", &[("revocation", "duplicate"), ("interrupt", "duplicate")], none.clone(), true),
                ),
                step("S1_cover", a(1), applied("duplicate", &[("cover", "duplicate")], none.clone(), false)),
            ],
        ),
    ];

    let svc_key = book.signer_public("svc-discord");
    serde_json::json!({
        "name": "r9-vectors-host-work-control",
        "kind": "vectors",
        "requires": "r9",
        "note": "Control records (delegated host-work I.5.3 to I.5.5, II.3.1; host-work-v1 §11.1; planned: host.senders, not advertised). Wire {\"body\":{…},\"sig\"}; signing input enc([\"atem-host-work-control-v1\", jcs(body)]) (R9.1). The device list is r9-vectors-membership-log's log L followed by `chain` (labels of its others); signers' keys are r9-vectors-keys' (`signed_with`). A service record's principal_key is the r9_svc of the principal's auth_key (SHA-256 of its raw bytes, decision 8), written beside it. `checks`: verify_control's verdict on each chain (valid with the verified signer and, for the principal's own key, the seq that enrolled it; pending or refused with its reason); `parse_error`: the record's parse refuses it (in a feed, refused per record and kept as evidence; over a channel the whole control_records message is invalid_request). `sequences`: ControlState::apply on one host, step by step (the record, the list of the transaction, its feed position or none over a channel, host-work's applied device-list seq) with the record's result, each effect's result, the host's actions and whether the record is kept as evidence; each step applies to the state the step before it left; `state` is ControlState::to_json after the last step (the records that counted kept by principal, then record_id). A step's position is {origin, feed_id, feed_seq}: a record counts as read at its own feed's position only when origin and feed_id are its body's. Record ids are UUID v4 numbered by record (the X* records and V6_conflicting_id reuse another record's id on purpose). Atem's proposals, for Astation's and Auth/Portal's agreement: covers are ordered by (issued_at, record_id); a hold applies from any feed, a release only from the covering feed after its cover and after that feed's last hold or release; record ids are per principal, and another body under an id the same principal's record counted with is evidence (a stop still applies, a cover or release is refused).",
        "account_id": "acct-test-1",
        "genesis_hash": genesis_hash().to_hex(),
        "stations": {
            "A": {"origin": FEED_A.0, "feed_id": FEED_A.1},
            "A2": {"origin": FEED_A2.0, "feed_id": FEED_A2.1},
            "B": {"origin": FEED_B.0, "feed_id": FEED_B.1},
        },
        "services": {
            "svc-discord": {
                "auth_key": svc_key.to_json(),
                "r9_svc": g.r9_svc("svc-discord").to_hex(),
                "seq": 5,
            },
        },
        "records": g.records,
        "sequences": sequences,
    })
}

/// A step's result as the vectors write it.
fn applied_of(a: &ControlApplied) -> Value {
    let actions: Vec<Value> = a
        .actions
        .iter()
        .map(|action| match action {
            HostAction::Revoke(p) => act("revoke", p),
            HostAction::Hold(p) => act("hold", p),
            HostAction::Release(p) => act("release", p),
            HostAction::Interrupt {
                principal,
                revocation,
            } => act_interrupt(principal, revocation),
            HostAction::Cover {
                principal,
                origin,
                feed_id,
            } => serde_json::json!({"type": "cover", "principal": principal, "origin": origin, "feed_id": feed_id}),
        })
        .collect();
    let effects: Vec<(&str, &str)> = a
        .effects
        .iter()
        .map(|e| (e.effect.code(), e.result.code()))
        .collect();
    applied(a.record_result.code(), &effects, actions, a.evidence)
}

/// A verdict as the vectors write it.
fn verdict_of(chain: &[&str], check: &ControlCheck, rec: &ControlRecord) -> Value {
    let verdict = match check {
        ControlCheck::Valid(valid) => match &valid.signer {
            VerifiedSigner::Principal { key_seq } => {
                ControlVerdict::Valid(leak(rec.principal().name()), Some(*key_seq))
            }
            VerifiedSigner::Manager { device_id } => {
                ControlVerdict::Valid(leak(format!("member:{device_id}")), None)
            }
        },
        ControlCheck::Pending(reason) => ControlVerdict::Pending(reason.code()),
        ControlCheck::Refused(reason) => ControlVerdict::Refused(reason.code()),
    };
    verdict_json(chain, verdict)
}

/// A name for the life of the test (a verdict's signer).
fn leak(text: String) -> &'static str {
    Box::leak(text.into_boxed_str())
}

/// The control-record vectors: as `control_vectors` makes them, every
/// record's parse, encodings and `r9Svc`, every verdict on its chains
/// (`verify_control`), and every sequence step by step (`ControlState`),
/// its state persisted and read back.
#[test]
fn host_work_control() {
    let mut run = Run::new("r9-vectors-host-work-control");
    let book = Book::load();
    let made = control_vectors(&book);
    let mlog = load("r9-vectors-membership-log");
    let ctx = Context::new(&mlog["log"], &mlog["others"], genesis_hash());
    for field in ["account_id", "genesis_hash", "stations", "services"] {
        assert_eq!(run.get(field), made[field], "{field}");
    }
    assert_eq!(made["note"], run.file["note"]);
    assert_eq!(run.file["genesis_hash"], genesis_hash().to_hex());
    let svc_key = book.signer_public("svc-discord");
    assert_eq!(
        run.file["services"]["svc-discord"]["r9_svc"],
        atem_client::membership::service_key_fingerprint(&svc_key).unwrap()
    );
    let l = ctx.chain(&[]);
    assert_eq!(
        l.member("svc-discord").unwrap().member.auth_key,
        svc_key,
        "E5 enrolled svc-discord's key"
    );
    run.pass("services: svc-discord's r9_svc is its E5 auth_key's service_key_fingerprint");

    // ---- records
    let records = run.get("records");
    assert_eq!(
        records, made["records"],
        "records: as control_vectors makes them"
    );
    let mut by_label = BTreeMap::new();
    let mut verdicts = BTreeSet::new();
    for v in records.as_array().unwrap() {
        let label = s(v, "label");
        let wire = v["record"].to_string();
        let object = SignedObject::parse(wire.as_bytes()).unwrap();
        assert_eq!(object.jcs(), s(v, "jcs"), "{label}");
        assert_eq!(
            hex(object.signing_input().as_bytes()),
            s(v, "signing_input_hex"),
            "{label}"
        );
        assert_eq!(object.label(), SignLabel::HostWorkControl, "{label}");
        let parsed = ControlRecord::parse(wire.as_bytes());
        if let Some(code) = v.get("parse_error") {
            let e: ControlError = parsed.unwrap_err();
            assert_eq!(e.code(), code.as_str().unwrap(), "{label}");
            assert!(v.get("checks").is_none(), "{label}");
            verdicts.insert(format!("parse:{}", e.code()));
            run.pass(format!("{label}: refused at parse, {}", e.code()));
            continue;
        }
        let rec = parsed.unwrap_or_else(|e| panic!("{label}: {e}"));
        // The signature by the key named, but where the vector says it is corrupted.
        let bad = v["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c.get("reason") == Some(&Value::from("bad_signature")));
        let signed = rec
            .object()
            .verify(&book.signer_public(s(v, "signed_with")));
        assert_eq!(
            signed.is_err(),
            bad,
            "{label}: signed with {}",
            s(v, "signed_with")
        );
        // A service record's principal_key beside its key's r9Svc.
        if rec.principal().name() == SVC {
            let r9_svc = principal_key_of(&svc_key).unwrap();
            assert_eq!(s(v, "r9_svc"), r9_svc.to_hex(), "{label}");
            let mismatch = v["checks"][0]["reason"] == "key_mismatch";
            assert_eq!(rec.principal_key() == Some(r9_svc), !mismatch, "{label}");
        } else {
            assert!(v.get("r9_svc").is_none(), "{label}");
        }
        for c in v["checks"].as_array().unwrap() {
            let chain = chain_labels(c);
            let list = ctx.chain(&chain);
            let check = verify_control(&rec, &list);
            assert_eq!(
                verdict_of(&chain, &check, &rec),
                *c,
                "{label} on L + {chain:?}"
            );
            if let ControlCheck::Valid(valid) = &check {
                assert_eq!(valid.head, list.head(), "{label}");
            }
            verdicts.insert(format!(
                "{}:{}",
                s(c, "verdict"),
                c.get("reason").and_then(Value::as_str).unwrap_or("")
            ));
        }
        run.pass(format!(
            "{label}: parse, jcs, signing input, signature, verdicts"
        ));
        by_label.insert(label.to_owned(), rec);
    }
    // Every reason a verifier or the parse gives is pinned by a vector.
    let want: BTreeSet<String> = [
        "valid:",
        "pending:principal_unknown",
        "pending:signer_unknown",
        "pending:revoke_not_in_list",
        "refused:wrong_account",
        "refused:bad_signature",
        "refused:key_mismatch",
        "refused:signer_not_allowed",
        "refused:removed_manager",
        "refused:host_key_signed",
        "refused:not_a_service",
        "refused:not_a_revoke",
        "parse:not_for_host_principal",
        "parse:field_not_allowed",
        "parse:unknown_field",
        "parse:malformed",
    ]
    .map(String::from)
    .into_iter()
    .collect();
    assert_eq!(verdicts, want);
    // Service records for each action, and a host principal's interrupt.
    let actions: BTreeSet<&str> = by_label
        .values()
        .filter(|r| r.principal().name() == SVC)
        .map(|r| r.action().name())
        .collect();
    assert_eq!(actions.len(), 5);
    assert!(by_label.values().any(|r| r.principal().is_host()));
    // Unknown `about.by` is display only.
    assert!(!by_label["S8_revoke_unknown_by"].about().is_known_by());
    run.pass("every verification reason and parse code; service records of each action; a host principal's interrupt_running");

    // ---- sequences
    let sequences = run.get("sequences");
    assert_eq!(
        sequences, made["sequences"],
        "sequences: as control_vectors makes them"
    );
    for q in sequences.as_array().unwrap() {
        let label = s(q, "label");
        let mut state = ControlState::new(&l);
        for (i, step) in q["steps"].as_array().unwrap().iter().enumerate() {
            let chain = chain_labels(step);
            let Transition { applied, next } = state.apply(
                &by_label[s(step, "record")],
                &ctx.chain(&chain),
                feed_pos(step),
                step["host_applied_seq"].as_u64().unwrap(),
            );
            assert_eq!(
                applied_of(&applied),
                step["expect"],
                "{label} step {}",
                i + 1
            );
            state = next;
        }
        assert_eq!(state.to_json(), q["state"], "{label}: state");
        let text = jcs(&q["state"]).unwrap();
        let back = ControlState::from_json(&strict(&q["state"]).into_value()).unwrap();
        assert_eq!(back, state, "{label}: from_json");
        assert_eq!(
            jcs(&back.to_json()).unwrap(),
            text,
            "{label}: to_json(from_json) is the same text"
        );
        run.pass(format!(
            "{label}: every step's results, the state and its round trip"
        ));
    }
    run.finish();
}

/// Writes `r9-vectors-host-work-control` from `control_vectors`.
#[test]
#[ignore = "writes the control-record vectors"]
fn write_control_vectors() {
    let book = Book::load();
    let mut text = serde_json::to_string_pretty(&control_vectors(&book)).unwrap();
    text.push('\n');
    std::fs::write(
        fixtures_dir().join("r9-vectors-host-work-control.json"),
        text,
    )
    .unwrap();
}

// ------------------------------------------------- the delegated wire shapes
//
// `r9-vectors-delegated-wire` (session-v1 R9.14, planned): the shapes of
// `host_enc_key_get` and its `host_enc_key` answer, and of receipts with and
// without provenance (`task_id`, `sender`), valid and refused. Every value
// comes from the crate's own builders; the valid answer's `enc_key` and
// `enc_sig` are `r9-vectors-membership-log`'s first `host_enc_key` pair, so
// its binding verifies against log L.

const WIRE_ID: &str = "c1c2c3c4-0000-4000-8000-000000000001";
const WIRE_RE: &str = "c1c2c3c4-0000-4000-8000-000000000002";

fn delegated_wire_vectors(book: &Book) -> Value {
    use atem_client::membership::{host_enc_sig_input, sign_host_enc_key};
    use atem_client::session::r9::{HostEncKey, host_enc_key_get};
    use atem_client::session::wire::{
        Envelope, Op, Receipt, ReceiptKind, ReceiptState, SessionMessage, Target,
    };
    use serde_json::json;
    let log = log_l();
    let case = |name: &str, valid: bool, message: Value| json!({"name": name, "valid": valid, "message": message});

    // host_enc_key_get: exactly v, op and a UUID v4 id.
    let get = host_enc_key_get(WIRE_ID);
    let edit = |f: &dyn Fn(&mut Value)| {
        let mut m = get.clone();
        f(&mut m);
        m
    };
    let mut gets = vec![case("host_enc_key_get", true, get.clone())];
    for (name, m) in [
        (
            "host_enc_key_get_unknown_field",
            edit(&|m| m["data"]["extra"] = json!(1)),
        ),
        (
            "host_enc_key_get_version",
            edit(&|m| m["data"]["v"] = json!(2)),
        ),
        (
            "host_enc_key_get_id_is_uuid_v4",
            edit(&|m| m["data"]["id"] = json!("6ba7b810-9dad-51d1-80b4-00c04fd430c8")),
        ),
        (
            "host_enc_key_get_id_not_null",
            edit(&|m| m["data"]["id"] = Value::Null),
        ),
        (
            "host_enc_key_get_needs_an_id",
            edit(&|m| {
                m["data"].as_object_mut().unwrap().remove("id");
            }),
        ),
        (
            "host_enc_key_get_is_a_session_message",
            edit(&|m| m["type"] = json!("terminal")),
        ),
    ] {
        gets.push(case(name, false, m));
    }
    gets.push(json!({
        "name": "host_enc_key_get_duplicate_key",
        "valid": false,
        "raw": format!(r#"{{"type":"session","data":{{"v":1,"op":"host_enc_key_get","id":"{WIRE_ID}","id":"{WIRE_RE}"}}}}"#),
    }));

    // host_enc_key: the host-a key of log L, bound by host-a's host_key.
    let enc_pub: [u8; 32] = b64u_decode("VmHgPdR1YmbgM0OShrmG5X-fQKiFf8UbteuY4GN9miA")
        .unwrap()
        .try_into()
        .unwrap();
    let genesis = log.genesis_hash();
    let enc_sig = sign_host_enc_key(
        &book.provider,
        &book.signer("host-a"),
        log.account_id(),
        &genesis,
        "host-a",
        1,
        &enc_pub,
    )
    .unwrap();
    let answer = HostEncKey {
        id: WIRE_RE.into(),
        re: WIRE_ID.into(),
        host_id: "host-a".into(),
        host_trust_gen: 1,
        enc_key: PublicKey::new(Alg::X25519, &enc_pub).unwrap(),
        enc_sig: enc_sig.clone(),
    }
    .to_json();
    let edit = |f: &dyn Fn(&mut Value)| {
        let mut m = answer.clone();
        f(&mut m);
        m
    };
    let mut keys = vec![case("host_enc_key", true, answer.clone())];
    for (name, m) in [
        (
            "host_enc_key_unknown_field",
            edit(&|m| m["data"]["extra"] = json!(1)),
        ),
        (
            "host_enc_key_needs_re",
            edit(&|m| {
                m["data"].as_object_mut().unwrap().remove("re");
            }),
        ),
        (
            "host_enc_key_re_not_null",
            edit(&|m| m["data"]["re"] = Value::Null),
        ),
        (
            "host_enc_key_host_id_grammar",
            edit(&|m| m["data"]["host_id"] = json!("host a")),
        ),
        (
            "host_enc_key_host_trust_gen_from_one",
            edit(&|m| m["data"]["host_trust_gen"] = json!(0)),
        ),
        (
            "host_enc_key_is_x25519",
            edit(&|m| m["data"]["enc_key"]["alg"] = json!("ed25519")),
        ),
        (
            "host_enc_key_32_bytes",
            edit(&|m| m["data"]["enc_key"]["pub"] = json!(b64u(&enc_pub[..31]))),
        ),
        (
            "host_enc_key_key_object",
            edit(&|m| m["data"]["enc_key"]["extra"] = json!(1)),
        ),
        (
            "host_enc_key_sig_64_bytes",
            edit(&|m| m["data"]["enc_sig"] = json!(b64u(&enc_sig[..63]))),
        ),
        (
            "host_enc_key_sig_base64url",
            edit(&|m| m["data"]["enc_sig"] = json!("not base64url!")),
        ),
    ] {
        keys.push(case(name, false, m));
    }

    // Receipts: provenance on a prompt receipt only, both or neither.
    let target = Target {
        account_id: "acct-test-1".into(),
        atem_device_id: "host-a".into(),
        host_trust_gen: 1,
        session_id: "ses-aaaaaaaaaaaa".into(),
        process_gen: "22222222-2222-4222-8222-222222222222".into(),
    };
    let receipt = |kind, state, task_id: Option<&str>, sender: Option<&str>| {
        atem_client::session::wire::to_value(&Envelope::Session(SessionMessage {
            id: WIRE_ID.into(),
            re: None,
            op: Op::Receipt(Receipt {
                request_id: "44444444-4444-4444-8444-000000000001".into(),
                target: target.clone(),
                kind,
                state,
                detail: None,
                updated_at: 1_793_620_800_000,
                lease: None,
                result: None,
                task_id: task_id.map(str::to_owned),
                sender: sender.map(str::to_owned),
            }),
        }))
    };
    const TASK: &str = "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b";
    let with = |sender: &str| {
        receipt(
            ReceiptKind::Prompt,
            ReceiptState::Executing,
            Some(TASK),
            Some(sender),
        )
    };
    let edit = |f: &dyn Fn(&mut Value)| {
        let mut m = with("service:svc-1");
        f(&mut m);
        m
    };
    let mut receipts = vec![
        case(
            "receipt_without_provenance",
            true,
            receipt(ReceiptKind::Prompt, ReceiptState::Accepted, None, None),
        ),
        case(
            "receipt_of_a_stop_without_provenance",
            true,
            receipt(ReceiptKind::Stop, ReceiptState::Completed, None, None),
        ),
        case("receipt_provenance_service", true, with("service:svc-1")),
        case("receipt_provenance_member", true, with("member:dev-phone")),
        case("receipt_provenance_host", true, with("host:host-b")),
        case(
            "receipt_provenance_128_byte_id",
            true,
            with(&format!("service:{}", "s".repeat(128))),
        ),
    ];
    for (name, m) in [
        (
            "receipt_provenance_needs_sender",
            edit(&|m| {
                m["data"].as_object_mut().unwrap().remove("sender");
            }),
        ),
        (
            "receipt_provenance_needs_task_id",
            edit(&|m| {
                m["data"].as_object_mut().unwrap().remove("task_id");
            }),
        ),
        (
            "receipt_provenance_sender_not_null",
            edit(&|m| m["data"]["sender"] = Value::Null),
        ),
        (
            "receipt_provenance_task_id_not_null",
            edit(&|m| m["data"]["task_id"] = Value::Null),
        ),
        (
            "receipt_provenance_task_id_is_uuid_v4",
            edit(&|m| m["data"]["task_id"] = json!("6ba7b810-9dad-51d1-80b4-00c04fd430c8")),
        ),
        (
            "receipt_provenance_sender_not_local",
            edit(&|m| m["data"]["sender"] = json!("local")),
        ),
        (
            "receipt_provenance_sender_not_a_browser_grant",
            edit(&|m| m["data"]["sender"] = json!("browser:g-1")),
        ),
        (
            "receipt_provenance_sender_not_host_work",
            edit(&|m| m["data"]["sender"] = json!("host-work")),
        ),
        (
            "receipt_provenance_sender_has_an_id",
            edit(&|m| m["data"]["sender"] = json!("service:")),
        ),
        (
            "receipt_provenance_sender_id_at_most_128_bytes",
            edit(&|m| m["data"]["sender"] = json!(format!("service:{}", "s".repeat(129)))),
        ),
        (
            "receipt_provenance_only_on_a_prompt",
            edit(&|m| m["data"]["kind"] = json!("interrupt")),
        ),
    ] {
        receipts.push(case(name, false, m));
    }

    json!({
        "name": "r9-vectors-delegated-wire",
        "kind": "vectors",
        "requires": "r9",
        "note": "Delegated host work's session-v1 shapes (R9.14, planned; not advertised): host_enc_key_get (exactly v, op and a UUID v4 id), its answer host_enc_key (exactly v, op, id, re, host_id, host_trust_gen, enc_key {alg: x25519, pub: 32 bytes}, enc_sig: 64 bytes), and receipts with provenance (task_id a UUID v4 and sender member:/service:/host: with a 1-128 byte id, both or neither, on a prompt receipt only; absent, never null) and without. Each case is valid or refused as a whole; a `raw` case is read as its exact text. The valid answer's enc_key and enc_sig are r9-vectors-membership-log's first host_enc_key pair: enc_sig verifies with host-a's host_key of log L over enc_sig_input_hex.",
        "host_enc_key_binding": {
            "account_id": log.account_id(),
            "genesis_hash": genesis.to_hex(),
            "host_id": "host-a",
            "host_trust_gen": 1,
            "enc_sig_input_hex": hex(host_enc_sig_input(log.account_id(), &genesis, "host-a", 1, &enc_pub).as_bytes()),
        },
        "host_enc_key_get": gets,
        "host_enc_key": keys,
        "receipt": receipts,
    })
}

#[test]
#[ignore = "writes the delegated wire shape vectors"]
fn write_delegated_wire_vectors() {
    let value = delegated_wire_vectors(&Book::load());
    let mut text = serde_json::to_string_pretty(&value).unwrap();
    text.push('\n');
    std::fs::write(fixtures_dir().join("r9-vectors-delegated-wire.json"), text).unwrap();
}

/// `r9-vectors-delegated-wire`: each case read as the shared core reads it
/// (valid or refused as a whole), the valid ones written back byte for
/// byte, and the answer's binding verified against log L.
#[test]
fn delegated_wire() {
    use atem_client::membership::{host_enc_sig_input, verify_host_enc_sig};
    use atem_client::session::r9::{HostEncKeyGet, Incoming, host_enc_key_get};
    use atem_client::session::wire::{self as swire, Envelope};
    let mut run = Run::new("r9-vectors-delegated-wire");
    let book = Book::load();
    let bytes = |case: &Value| -> Vec<u8> {
        match case.get("raw") {
            Some(raw) => raw.as_str().unwrap().as_bytes().to_vec(),
            None => case["message"].to_string().into_bytes(),
        }
    };
    for case in run.get("host_enc_key_get").as_array().unwrap() {
        let name = s(case, "name");
        let read = HostEncKeyGet::decode(&bytes(case));
        assert_eq!(read.is_ok(), case["valid"] == true, "{name}");
        if let Ok(read) = read {
            assert_eq!(host_enc_key_get(&read.id), case["message"], "{name}");
        }
        run.pass(format!(
            "{name}: {}",
            if case["valid"] == true {
                "read"
            } else {
                "refused"
            }
        ));
    }
    let binding = run.get("host_enc_key_binding");
    let log = log_l();
    assert_eq!(s(&binding, "account_id"), log.account_id());
    assert_eq!(s(&binding, "genesis_hash"), log.genesis_hash().to_hex());
    for case in run.get("host_enc_key").as_array().unwrap() {
        let name = s(case, "name");
        let read = match Incoming::parse(&bytes(case)) {
            Ok(Incoming::HostEncKey(answer)) => Some(answer),
            _ => None,
        };
        assert_eq!(read.is_some(), case["valid"] == true, "{name}");
        if let Some(answer) = read {
            assert_eq!(answer.to_json(), case["message"], "{name}");
            let enc_pub = answer.enc_key.as_32().unwrap();
            assert_eq!(
                hex(host_enc_sig_input(
                    log.account_id(),
                    &log.genesis_hash(),
                    &answer.host_id,
                    answer.host_trust_gen,
                    enc_pub
                )
                .as_bytes()),
                s(&binding, "enc_sig_input_hex"),
                "{name}"
            );
            verify_host_enc_sig(
                &book.signer_public("host-a"),
                log.account_id(),
                &log.genesis_hash(),
                &answer.host_id,
                answer.host_trust_gen,
                enc_pub,
                &answer.enc_sig,
            )
            .unwrap();
            assert!(answer.action(false, 1).is_ok(), "{name}: drafts the entry");
        }
        run.pass(format!(
            "{name}: {}",
            if case["valid"] == true {
                "read, binding verified"
            } else {
                "refused"
            }
        ));
    }
    for case in run.get("receipt").as_array().unwrap() {
        let name = s(case, "name");
        let read = swire::decode(&bytes(case));
        assert_eq!(read.is_ok(), case["valid"] == true, "{name}");
        if let Ok(Envelope::Session(message)) = read {
            assert_eq!(
                swire::to_value(&Envelope::Session(message)),
                case["message"],
                "{name}"
            );
        }
        run.pass(format!(
            "{name}: {}",
            if case["valid"] == true {
                "read and written back"
            } else {
                "refused"
            }
        ));
    }
    // The fixture is the crate's own output.
    assert_eq!(
        delegated_wire_vectors(&book),
        run.file.clone(),
        "regenerate with write_delegated_wire_vectors"
    );
}

// ------------------------------------------- the Station calls' byte goldens
//
// `r9-vectors-station-calls` (delegated host-work design I.5.8; host-work-v1
// §11.4): the six Station calls and the three refusals as the shared core's
// own builders write them, each as its exact text, with its decoded fields,
// and the invalid variants a reader refuses, each with its code. Custom
// Stations and Astation's `:8080` proxy read these as the known answers.
// `write_station_calls_vectors` (ignored) writes the file from
// `station_call_vectors`; `station_calls_build_byte_for_byte` checks the
// builders reproduce every `wire` from its `fields` (and that the file is
// what the generator makes now), `station_calls_decode_to_their_fields` that
// the readers give those fields back and judge every page record as the file
// says, and `station_calls_refuse_the_invalid_variants` that each invalid
// text is refused with its code. `scripts/check-r9-vectors.py` checks the
// texts independently: strict I-JSON, the compact form in RFC 8785 key
// order, and a reader written from the spec for every case.

use atem_client::control::{
    AckResult, ApplicationResult, CallRefused, ControlAck, ControlSync, ControlSyncResult,
    EffectKind, EffectResult, EntryRef, FeedEntry, FeedHead, Heads, MembershipFetch,
    MembershipFetchResult, RefusalCode, RefusedCall, RelayError, ToHost, ToStation,
};

const STATION_CALLS: &str = "r9-vectors-station-calls";

/// R9.9's bound for every relay message, in bytes as sent.
const RELAY_MAX_BYTES: usize = 256 * 1024;

/// The file, with its name, kind and requirement checked.
fn station_calls_file() -> Run {
    Run::new(STATION_CALLS)
}

/// A case's text: `wire` as written, or built from its `wire_fill` recipe
/// (`prefix`, `count` times `fill`, `suffix`).
fn call_wire(case: &Value) -> String {
    if let Some(text) = case.get("wire") {
        return text.as_str().unwrap().to_owned();
    }
    let fill = &case["wire_fill"];
    let count = fill["count"].as_u64().unwrap() as usize;
    format!(
        "{}{}{}",
        s(fill, "prefix"),
        s(fill, "fill").repeat(count),
        s(fill, "suffix")
    )
}

fn call_head(value: &Value) -> Head {
    Head {
        seq: value["seq"].as_u64().unwrap(),
        hash: Hash32::from_hex(s(value, "hash")).unwrap(),
    }
}

fn call_effects(value: &Value) -> Vec<EffectResult> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|e| EffectResult {
            effect: EffectKind::from_code(s(e, "effect")).unwrap(),
            result: ApplicationResult::from_code(s(e, "result")).unwrap(),
        })
        .collect()
}

fn call_ack(f: &Value) -> ControlAck {
    ControlAck {
        account_id: s(f, "account_id").into(),
        genesis_hash: Hash32::from_hex(s(f, "genesis_hash")).unwrap(),
        host_id: s(f, "host_id").into(),
        host_trust_gen: f["host_trust_gen"].as_u64().unwrap(),
        origin: s(f, "origin").into(),
        feed_id: s(f, "feed_id").into(),
        cursor: f["cursor"].as_u64().unwrap(),
        results: f["results"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| match r.get("entry") {
                Some(entry) => AckResult::Entry {
                    entry: EntryRef {
                        seq: entry["seq"].as_u64().unwrap(),
                        entry_hash: Hash32::from_hex(s(entry, "entry_hash")).unwrap(),
                    },
                    applied_seq: r["applied_seq"].as_u64().unwrap(),
                    effects: call_effects(&r["effects"]),
                },
                None => AckResult::Record {
                    record_id: s(r, "record_id").into(),
                    effects: call_effects(&r["effects"]),
                },
            })
            .collect(),
    }
}

/// A case's message as the core's builders write it, from its `fields`
/// alone. A page record the control parser refuses can't be given to
/// `FeedEntry::new` (a Station serves only what it stored): its slot is
/// built with a record that parses and the record the case names is put in
/// its place, as a Station's fault would.
fn build_call(case: &Value) -> String {
    let f = &case["fields"];
    let message = match s(case, "op") {
        "control_sync" => ControlSync {
            origin: s(f, "origin").into(),
            feed_id: f.get("feed_id").map(|v| v.as_str().unwrap().to_owned()),
            after: f["after"].as_u64().unwrap(),
        }
        .to_json(),
        "control_sync_result" => {
            let control = load("r9-vectors-host-work-control");
            let stand_in =
                ControlRecord::parse(control["records"][0]["record"].to_string().as_bytes())
                    .unwrap();
            let records = f["records"].as_array().unwrap();
            let page = ControlSyncResult {
                origin: s(f, "origin").into(),
                feed_id: s(f, "feed_id").into(),
                head: f["head"].as_u64().unwrap(),
                station_time: f["station_time"].as_u64().unwrap(),
                records: records
                    .iter()
                    .map(|r| {
                        let record = ControlRecord::parse(r["record"].to_string().as_bytes())
                            .unwrap_or_else(|_| stand_in.clone());
                        FeedEntry::new(r["feed_seq"].as_u64().unwrap(), &record)
                    })
                    .collect(),
            };
            page.to_json().map(|mut value| {
                for (slot, r) in records.iter().enumerate() {
                    if ControlRecord::parse(r["record"].to_string().as_bytes()).is_err() {
                        value["records"][slot]["record"] = r["record"].clone();
                    }
                }
                value
            })
        }
        "heads" => Heads {
            feeds: f["feeds"]
                .as_array()
                .unwrap()
                .iter()
                .map(|feed| FeedHead {
                    origin: s(feed, "origin").into(),
                    feed_id: s(feed, "feed_id").into(),
                    head: feed["head"].as_u64().unwrap(),
                    station_time: feed["station_time"].as_u64().unwrap(),
                })
                .collect(),
            membership: call_head(&f["membership"]),
        }
        .to_json(),
        "control_ack" => call_ack(f).to_json(),
        "membership_fetch" => MembershipFetch {
            after: f["after"].as_u64().unwrap(),
        }
        .to_json(),
        "membership_fetch_result" => MembershipFetchResult {
            head: call_head(&f["head"]),
            entries: f["entries"]
                .as_array()
                .unwrap()
                .iter()
                .map(|e| SignedObject::from_strict(&strict(e)).unwrap())
                .collect(),
        }
        .to_json(),
        op => {
            let call = [
                RefusedCall::ControlSync,
                RefusedCall::MembershipFetch,
                RefusedCall::ControlAck,
            ]
            .into_iter()
            .find(|c| c.op() == op)
            .unwrap_or_else(|| panic!("no builder for {op}"));
            CallRefused {
                call,
                code: RefusalCode::from_code(s(f, "code")).unwrap(),
            }
            .to_json()
        }
    };
    message.unwrap().to_string()
}

fn describe_effects(effects: &[EffectResult]) -> Value {
    Value::Array(
        effects
            .iter()
            .map(|e| serde_json::json!({"effect": e.effect.code(), "result": e.result.code()}))
            .collect(),
    )
}

/// What a host's call decodes to, as the file's `fields` write it.
fn describe_to_station(message: &ToStation) -> Value {
    use serde_json::json;
    match message {
        ToStation::ControlSync(sync) => {
            let mut f = json!({"origin": sync.origin, "after": sync.after});
            if let Some(feed_id) = &sync.feed_id {
                f["feed_id"] = json!(feed_id);
            }
            f
        }
        ToStation::ControlAck(ack) => json!({
            "account_id": ack.account_id,
            "genesis_hash": ack.genesis_hash.to_hex(),
            "host_id": ack.host_id,
            "host_trust_gen": ack.host_trust_gen,
            "origin": ack.origin,
            "feed_id": ack.feed_id,
            "cursor": ack.cursor,
            "results": ack.results.iter().map(|r| match r {
                AckResult::Record { record_id, effects } =>
                    json!({"record_id": record_id, "effects": describe_effects(effects)}),
                AckResult::Entry { entry, applied_seq, effects } => json!({
                    "entry": {"seq": entry.seq, "entry_hash": entry.entry_hash.to_hex()},
                    "applied_seq": applied_seq,
                    "effects": describe_effects(effects),
                }),
            }).collect::<Vec<_>>(),
        }),
        ToStation::MembershipFetch(fetch) => json!({"after": fetch.after}),
    }
}

/// What a Station's message decodes to, as the file's `fields` write it.
fn describe_to_host(message: &ToHost) -> Value {
    use serde_json::json;
    match message {
        ToHost::ControlSyncResult(page) => json!({
            "origin": page.origin,
            "feed_id": page.feed_id,
            "head": page.head,
            "station_time": page.station_time,
            "records": page.records.iter()
                .map(|e| json!({"feed_seq": e.feed_seq, "record": e.raw()}))
                .collect::<Vec<_>>(),
        }),
        ToHost::Heads(heads) => json!({
            "feeds": heads.feeds.iter().map(|f| json!({
                "origin": f.origin, "feed_id": f.feed_id, "head": f.head,
                "station_time": f.station_time,
            })).collect::<Vec<_>>(),
            "membership": heads.membership.to_json(),
        }),
        ToHost::MembershipFetchResult(result) => json!({
            "head": result.head.to_json(),
            "entries": result.entries.iter().map(SignedObject::to_json).collect::<Vec<_>>(),
        }),
        ToHost::ControlSyncRefused(code)
        | ToHost::MembershipFetchRefused(code)
        | ToHost::ControlAckRefused(code) => json!({"code": code.code()}),
    }
}

/// The control parser's verdict on each record of a page, parallel to its
/// records (`judged` in the file): `parses` with the `record_id`, or not
/// with the parse's code.
fn judged_records(page: &ControlSyncResult) -> Value {
    use serde_json::json;
    Value::Array(
        page.records
            .iter()
            .map(|entry| match entry.parse_record() {
                Ok(record) => json!({"feed_seq": entry.feed_seq, "parses": true,
                    "record_id": record.body().record_id}),
                Err(e) => json!({"feed_seq": entry.feed_seq, "parses": false, "error": e.code()}),
            })
            .collect(),
    )
}

/// The reader `direction` names: `to_station` reads a host's calls,
/// `to_host` a Station's messages.
fn read_call(direction: &str, bytes: &[u8]) -> Result<(Value, Option<Value>), RelayError> {
    match direction {
        "to_station" => ToStation::decode(bytes).map(|m| (describe_to_station(&m), None)),
        "to_host" => ToHost::decode(bytes).map(|m| {
            let judged = match &m {
                ToHost::ControlSyncResult(page) => Some(judged_records(page)),
                _ => None,
            };
            (describe_to_host(&m), judged)
        }),
        other => panic!("no reader {other}"),
    }
}

/// The message's own type's reader, for an `op` it reads.
fn read_typed(op: &str, bytes: &[u8]) -> Result<(), RelayError> {
    match op {
        "control_sync" => ControlSync::decode(bytes).map(drop),
        "control_sync_result" => ControlSyncResult::decode(bytes).map(drop),
        "heads" => Heads::decode(bytes).map(drop),
        "control_ack" => ControlAck::decode(bytes).map(drop),
        "membership_fetch" => MembershipFetch::decode(bytes).map(drop),
        "membership_fetch_result" => MembershipFetchResult::decode(bytes).map(drop),
        refused => CallRefused::decode(bytes).map(|r| assert_eq!(r.call.op(), refused)),
    }
}

const STATION_CALL_OPS: [&str; 9] = [
    "control_sync",
    "control_sync_result",
    "heads",
    "control_ack",
    "membership_fetch",
    "membership_fetch_result",
    "control_sync_refused",
    "membership_fetch_refused",
    "control_ack_refused",
];

/// Every valid message, byte for byte from its fields.
#[test]
fn station_calls_build_byte_for_byte() {
    let mut run = station_calls_file();
    assert_eq!(run.get("max_message_bytes"), RELAY_MAX_BYTES);
    run.get("invalid");
    let calls = run.get("calls");
    let mut ops = BTreeSet::new();
    for case in calls.as_array().unwrap() {
        let name = s(case, "name");
        let wire = s(case, "wire");
        assert_eq!(build_call(case), wire, "{name}");
        assert!(wire.len() <= RELAY_MAX_BYTES, "{name}: within the bound");
        ops.insert(s(case, "op").to_owned());
        run.pass(format!("{name}: built byte for byte"));
    }
    assert_eq!(
        ops,
        STATION_CALL_OPS.iter().map(|op| op.to_string()).collect(),
        "every call and every refusal has a golden"
    );
    // The fixture is the crate's own output.
    assert_eq!(
        station_call_vectors(),
        run.file.clone(),
        "regenerate with write_station_calls_vectors"
    );
    run.finish();
}

/// Every valid message, read by its side's reader, gives back its fields
/// (and the control parser's verdict on each page record); the other side's
/// reader refuses it as another message.
#[test]
fn station_calls_decode_to_their_fields() {
    let mut run = station_calls_file();
    run.get("max_message_bytes");
    run.get("invalid");
    let calls = run.get("calls");
    for case in calls.as_array().unwrap() {
        let name = s(case, "name");
        let wire = s(case, "wire");
        let direction = s(case, "direction");
        let (fields, judged) = read_call(direction, wire.as_bytes()).unwrap();
        assert_eq!(fields, case["fields"], "{name}: decoded fields");
        assert_eq!(
            judged.as_ref(),
            case.get("judged"),
            "{name}: judged records"
        );
        read_typed(s(case, "op"), wire.as_bytes()).unwrap();
        // The compact text in key order: parsed and written again, the same.
        let parsed: Value = serde_json::from_str(wire).unwrap();
        assert_eq!(parsed.to_string(), wire, "{name}: compact, keys in order");
        // The other side's reader doesn't read it.
        let other = match direction {
            "to_station" => "to_host",
            _ => "to_station",
        };
        assert_eq!(
            read_call(other, wire.as_bytes()).unwrap_err().code(),
            "wrong_message",
            "{name}: read by the other side"
        );
        run.pass(format!("{name}: decoded"));
    }
    run.finish();
}

/// Every invalid variant is refused, with its code, by its side's reader and
/// by the message's own type's.
#[test]
fn station_calls_refuse_the_invalid_variants() {
    let mut run = station_calls_file();
    run.get("max_message_bytes");
    run.get("calls");
    let invalid = run.get("invalid");
    let mut codes = BTreeSet::new();
    for case in invalid.as_array().unwrap() {
        let name = s(case, "name");
        let wire = call_wire(case);
        if let Some(fill) = case.get("wire_fill") {
            assert_eq!(wire.len() as u64, fill["bytes"].as_u64().unwrap(), "{name}");
        }
        let code = s(case, "code");
        let error = read_call(s(case, "reader"), wire.as_bytes()).unwrap_err();
        assert_eq!(error.code(), code, "{name}");
        if code != "wrong_message" {
            let typed = read_typed(s(case, "op"), wire.as_bytes()).unwrap_err();
            assert_eq!(typed.code(), code, "{name}: the message's own reader");
        }
        codes.insert(code.to_owned());
        run.pass(format!("{name}: refused {code}"));
    }
    assert_eq!(
        codes,
        [
            "malformed",
            "not_strict",
            "too_large",
            "unknown_field",
            "wrong_message"
        ]
        .iter()
        .map(|c| c.to_string())
        .collect(),
        "every refusal code the readers give"
    );
    run.finish();
}

/// The golden file's calls and invalid variants as they are written.
struct CallBook {
    calls: Vec<Value>,
    invalid: Vec<Value>,
    wires: BTreeMap<String, String>,
}

impl CallBook {
    /// A message the builders wrote, with its decoded fields.
    fn valid(
        &mut self,
        name: &str,
        op: &str,
        direction: &str,
        note: &str,
        fields: Value,
        message: Value,
    ) {
        let wire = message.to_string();
        self.wires.insert(name.to_owned(), wire.clone());
        self.calls.push(serde_json::json!({
            "name": name, "op": op, "direction": direction, "note": note,
            "fields": fields, "wire": wire,
        }));
    }

    /// The text of a valid message, parsed, for an invalid variant to change.
    fn parsed(&self, name: &str) -> Value {
        serde_json::from_str(&self.wires[name]).unwrap()
    }

    /// A text a reader refuses, with the code it refuses it with.
    fn bad(&mut self, name: &str, op: &str, reader: &str, code: &str, wire: impl Into<String>) {
        self.invalid.push(serde_json::json!({
            "name": name, "op": op, "reader": reader, "code": code, "wire": wire.into(),
        }));
    }

    /// `valid`'s message with `edit` applied, refused.
    fn bad_edit(&mut self, name: &str, from: &str, code: &str, edit: impl FnOnce(&mut Value)) {
        let mut message = self.parsed(from);
        edit(&mut message);
        let op = message["op"].as_str().unwrap().to_owned();
        let reader = if ["control_sync", "control_ack", "membership_fetch"].contains(&op.as_str()) {
            "to_station"
        } else {
            "to_host"
        };
        self.bad(name, &op, reader, code, message.to_string());
    }
}

/// `r9-vectors-station-calls`, as the shared core's builders make it now.
fn station_call_vectors() -> Value {
    use serde_json::json;
    const STATION_TIME: u64 = 1_793_620_940_000;
    let control = load("r9-vectors-host-work-control");
    let mlog = load("r9-vectors-membership-log");
    let station = |name: &str| {
        let st = &control["stations"][name];
        (s(st, "origin").to_owned(), s(st, "feed_id").to_owned())
    };
    let (origin, feed) = station("A");
    let (origin_b, feed_b) = station("B");
    let (_, feed_a2) = station("A2");
    let account = s(&control, "account_id").to_owned();
    let genesis = Hash32::from_hex(s(&control, "genesis_hash")).unwrap();
    let control_record = |label: &str| -> Value {
        control["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["label"] == label)
            .unwrap_or_else(|| panic!("no control record {label}"))["record"]
            .clone()
    };
    let record_id = |label: &str| s(&control_record(label)["body"], "record_id").to_owned();
    let entry = |label: &str| -> Value {
        mlog["log"]
            .as_array()
            .unwrap()
            .iter()
            .chain(mlog["others"].as_array().unwrap())
            .find(|e| e["label"] == label)
            .unwrap_or_else(|| panic!("no entry {label}"))
            .clone()
    };
    let feed_entry = |seq: u64, label: &str| {
        let record = ControlRecord::parse(control_record(label).to_string().as_bytes()).unwrap();
        FeedEntry::new(seq, &record)
    };
    let log_head = Head {
        seq: mlog["head"]["seq"].as_u64().unwrap(),
        hash: Hash32::from_hex(s(&mlog["head"], "hash")).unwrap(),
    };
    let mut g = CallBook {
        calls: Vec::new(),
        invalid: Vec::new(),
        wires: BTreeMap::new(),
    };

    // ------------------------------------------------------- control_sync
    let sync = |feed_id: Option<&str>, after: u64| {
        ControlSync {
            origin: origin.clone(),
            feed_id: feed_id.map(str::to_owned),
            after,
        }
        .to_json()
        .unwrap()
    };
    g.valid(
        "control_sync_with_feed_id",
        "control_sync",
        "to_station",
        "the host knows the feed: read it after position 2, the last it read",
        json!({"origin": origin, "feed_id": feed, "after": 2}),
        sync(Some(&feed), 2),
    );
    g.valid(
        "control_sync_without_feed_id",
        "control_sync",
        "to_station",
        "the host doesn't know the feed yet: no feed_id, and a cursor belongs to a feed, so after is 0",
        json!({"origin": origin, "after": 0}),
        sync(None, 0),
    );
    g.valid(
        "control_sync_at_the_largest_position",
        "control_sync",
        "to_station",
        "after at 2^53 - 1, the largest integer",
        json!({"origin": origin, "feed_id": feed, "after": 9_007_199_254_740_991u64}),
        sync(Some(&feed), 9_007_199_254_740_991),
    );

    // ------------------------------------------------ control_sync_result
    let page = |feed_id: &str, head: u64, records: Vec<FeedEntry>| {
        ControlSyncResult {
            origin: origin.clone(),
            feed_id: feed_id.to_owned(),
            head,
            station_time: STATION_TIME,
            records,
        }
        .to_json()
        .unwrap()
    };
    let wire_record =
        |seq: u64, label: &str| json!({"feed_seq": seq, "record": control_record(label)});
    g.valid(
        "control_sync_result_empty_feed",
        "control_sync_result",
        "to_host",
        "a feed with no record: head 0, no records",
        json!({"origin": origin, "feed_id": feed_a2, "head": 0, "station_time": STATION_TIME, "records": []}),
        page(&feed_a2, 0, vec![]),
    );
    g.valid(
        "control_sync_result_with_records",
        "control_sync_result",
        "to_host",
        "three records of the control vectors, ascending, the last at the head",
        json!({"origin": origin, "feed_id": feed, "head": 3, "station_time": STATION_TIME,
            "records": [wire_record(1, "S1_cover"), wire_record(2, "S4_revoke"), wire_record(3, "M1_revoke")]}),
        page(
            &feed,
            3,
            vec![
                feed_entry(1, "S1_cover"),
                feed_entry(2, "S4_revoke"),
                feed_entry(3, "M1_revoke"),
            ],
        ),
    );
    // A page whose records the control parser judges one at a time: a record
    // with an unknown field, a string, a null (a record may be any JSON
    // value) and a gap in the positions. The builder can't write a record it
    // doesn't parse (a Station serves only what it stored): their slots are
    // built with a record that parses and the value is put in its place.
    {
        let stand_in =
            ControlRecord::parse(control_record("S1_cover").to_string().as_bytes()).unwrap();
        let slots: Vec<(u64, Value)> = vec![
            (4, control_record("S5_revoke_interrupt")),
            (5, control_record("P4_unknown_field")),
            (6, json!("not a record")),
            (7, Value::Null),
            (9, control_record("S6_interrupt")),
        ];
        let entries = slots
            .iter()
            .map(
                |(seq, record)| match ControlRecord::parse(record.to_string().as_bytes()) {
                    Ok(record) => FeedEntry::new(*seq, &record),
                    Err(_) => FeedEntry::new(*seq, &stand_in),
                },
            )
            .collect();
        let mut message = page(&feed, 9, entries);
        for (slot, (_, record)) in slots.iter().enumerate() {
            if ControlRecord::parse(record.to_string().as_bytes()).is_err() {
                message["records"][slot]["record"] = record.clone();
            }
        }
        let fields = json!({"origin": origin, "feed_id": feed, "head": 9, "station_time": STATION_TIME,
            "records": slots.iter().map(|(seq, record)| json!({"feed_seq": seq, "record": record})).collect::<Vec<_>>()});
        g.valid(
            "control_sync_result_with_records_that_do_not_parse",
            "control_sync_result",
            "to_host",
            "a page is read whole and each record judged on its own: one with an unknown field, a string and a null don't parse, and the page, the feed's position and the records after them stand (gaps in the positions are allowed)",
            fields,
            message,
        );
    }
    // `judged` on every page: the control parser's verdict on each record.
    for case in g
        .calls
        .iter_mut()
        .filter(|c| c["op"] == "control_sync_result")
    {
        let page = ControlSyncResult::decode(s(case, "wire").as_bytes()).unwrap();
        case["judged"] = judged_records(&page);
    }

    // -------------------------------------------------------------- heads
    let feed_head = |origin: &str, feed_id: &str, head: u64, station_time: u64| FeedHead {
        origin: origin.to_owned(),
        feed_id: feed_id.to_owned(),
        head,
        station_time,
    };
    let feed_json = |origin: &str, feed_id: &str, head: u64, station_time: u64| json!({"origin": origin, "feed_id": feed_id, "head": head, "station_time": station_time});
    g.valid(
        "heads_two_stations",
        "heads",
        "to_host",
        "two feeds, each of another Station, and the device list's head (log L's)",
        json!({"feeds": [feed_json(&origin, &feed, 3, STATION_TIME), feed_json(&origin_b, &feed_b, 12, STATION_TIME - 500)],
            "membership": log_head.to_json()}),
        Heads {
            feeds: vec![
                feed_head(&origin, &feed, 3, STATION_TIME),
                feed_head(&origin_b, &feed_b, 12, STATION_TIME - 500),
            ],
            membership: log_head,
        }
        .to_json()
        .unwrap(),
    );
    g.valid(
        "heads_without_feeds",
        "heads",
        "to_host",
        "no feed covers a principal with work on this host: only the device list's head",
        json!({"feeds": [], "membership": log_head.to_json()}),
        Heads {
            feeds: vec![],
            membership: log_head,
        }
        .to_json()
        .unwrap(),
    );
    let many = |n: u64| -> Vec<(String, u64)> {
        (1..=n)
            .map(|i| (format!("00000000-0000-4000-8000-{i:012x}"), i))
            .collect()
    };
    g.valid(
        "heads_64_feeds",
        "heads",
        "to_host",
        "the most feeds one heads announces: 64, each once",
        json!({"feeds": many(64).iter().map(|(f, i)| feed_json(&origin, f, *i, STATION_TIME)).collect::<Vec<_>>(),
            "membership": log_head.to_json()}),
        Heads {
            feeds: many(64).iter().map(|(f, i)| feed_head(&origin, f, *i, STATION_TIME)).collect(),
            membership: log_head,
        }
        .to_json()
        .unwrap(),
    );

    // -------------------------------------------------------- control_ack
    let effects = |codes: &[(&str, &str)]| -> Vec<EffectResult> {
        codes
            .iter()
            .map(|(e, r)| EffectResult {
                effect: EffectKind::from_code(e).unwrap(),
                result: ApplicationResult::from_code(r).unwrap(),
            })
            .collect()
    };
    let effects_json = |codes: &[(&str, &str)]| -> Value {
        Value::Array(
            codes
                .iter()
                .map(|(e, r)| json!({"effect": e, "result": r}))
                .collect(),
        )
    };
    let record_result = |id: &str, codes: &[(&str, &str)]| {
        (
            AckResult::Record {
                record_id: id.to_owned(),
                effects: effects(codes),
            },
            json!({"record_id": id, "effects": effects_json(codes)}),
        )
    };
    let entry_result = |label: &str, applied_seq: u64, codes: &[(&str, &str)]| {
        let e = entry(label);
        let seq = e["entry"]["body"]["seq"].as_u64().unwrap();
        let hash = s(&e, "entry_hash").to_owned();
        (
            AckResult::Entry {
                entry: EntryRef {
                    seq,
                    entry_hash: Hash32::from_hex(&hash).unwrap(),
                },
                applied_seq,
                effects: effects(codes),
            },
            json!({"entry": {"seq": seq, "entry_hash": hash}, "applied_seq": applied_seq,
                "effects": effects_json(codes)}),
        )
    };
    let ack = |name: &str,
               note: &str,
               feed_id: &str,
               cursor: u64,
               results: Vec<(AckResult, Value)>,
               g: &mut CallBook| {
        let (typed, shown): (Vec<_>, Vec<_>) = results.into_iter().unzip();
        let message = ControlAck {
            account_id: account.clone(),
            genesis_hash: genesis,
            host_id: "host-b".into(),
            host_trust_gen: 1,
            origin: origin.clone(),
            feed_id: feed_id.to_owned(),
            cursor,
            results: typed,
        }
        .to_json()
        .unwrap();
        g.valid(
            name,
            "control_ack",
            "to_station",
            note,
            json!({"account_id": account, "genesis_hash": genesis.to_hex(), "host_id": "host-b",
                "host_trust_gen": 1, "origin": origin, "feed_id": feed_id, "cursor": cursor,
                "results": shown}),
            message,
        );
    };
    ack(
        "control_ack_cursor_only",
        "the host read the feed to position 5 and has applied nothing to report: the cursor says only how far it read",
        &feed,
        5,
        vec![],
        &mut g,
    );
    ack(
        "control_ack_record_results",
        "results of the reset feed's snapshot, by record_id, each with the effect its record carries: a cover applied, a hold pending, a release refused",
        &feed_a2,
        3,
        vec![
            record_result(&record_id("A2_cover"), &[("cover", "applied")]),
            record_result(&record_id("A2_hold"), &[("hold", "pending")]),
            record_result(&record_id("A2_release"), &[("release", "refused")]),
        ],
        &mut g,
    );
    ack(
        "control_ack_revoke_results",
        "a revoke (its revocation), a revoke with interrupt_running (revocation already in force, interrupt applied) and a later interrupt_running (its interrupt)",
        &feed,
        6,
        vec![
            record_result(&record_id("S4_revoke"), &[("revocation", "applied")]),
            record_result(
                &record_id("S5_revoke_interrupt"),
                &[("revocation", "duplicate"), ("interrupt", "applied")],
            ),
            record_result(&record_id("S6_interrupt"), &[("interrupt", "applied")]),
        ],
        &mut g,
    );
    ack(
        "control_ack_entry_result",
        "the result of a host sender's device-list revoke, by {seq, entry_hash}: applied once applied_seq has reached its seq",
        &feed,
        5,
        vec![entry_result("HS7_revoke", 7, &[("revocation", "applied")])],
        &mut g,
    );
    ack(
        "control_ack_entry_pending",
        "the same entry while the host's applied device-list seq is behind it: only pending or refused may be said",
        &feed,
        5,
        vec![entry_result("HS7_revoke", 6, &[("revocation", "pending")])],
        &mut g,
    );
    ack(
        "control_ack_both_result_forms",
        "both result forms in one ack: a record's and an entry's (a host sender's revoke that asked for an interrupt: revocation and interrupt)",
        &feed,
        5,
        vec![
            record_result(
                &record_id("S5_revoke_interrupt"),
                &[("revocation", "duplicate"), ("interrupt", "applied")],
            ),
            entry_result(
                "HS12_revoke_interrupt",
                12,
                &[("revocation", "applied"), ("interrupt", "applied")],
            ),
        ],
        &mut g,
    );
    ack(
        "control_ack_64_results",
        "the most results one ack carries: 64, each record once (ids of no vectors record)",
        &feed,
        64,
        many(64)
            .iter()
            .map(|(id, _)| {
                record_result(
                    &id.replace("00000000-0000-4000-8000", "11111111-1111-4111-8111"),
                    &[("cover", "applied")],
                )
            })
            .collect(),
        &mut g,
    );

    // ------------------------------------------------ the device-list fetch
    g.valid(
        "membership_fetch",
        "membership_fetch",
        "to_station",
        "the host holds the device list to seq 2",
        json!({"after": 2}),
        MembershipFetch { after: 2 }.to_json().unwrap(),
    );
    let labels = ["E3", "E4", "E5", "E6"];
    let entries: Vec<Value> = labels.iter().map(|l| entry(l)["entry"].clone()).collect();
    g.valid(
        "membership_fetch_result",
        "membership_fetch_result",
        "to_host",
        "the entries after seq 2 (log L's E3 to E6, an R9.3 carriage) and the Station's head; no echo of after, no more",
        json!({"head": log_head.to_json(), "entries": entries}),
        MembershipFetchResult {
            head: log_head,
            entries: entries.iter().map(|e| SignedObject::from_strict(&strict(e)).unwrap()).collect(),
        }
        .to_json()
        .unwrap(),
    );
    g.valid(
        "membership_fetch_result_no_entries",
        "membership_fetch_result",
        "to_host",
        "the host is current: the head and no entries",
        json!({"head": log_head.to_json(), "entries": []}),
        MembershipFetchResult {
            head: log_head,
            entries: vec![],
        }
        .to_json()
        .unwrap(),
    );

    // ---------------------------------------------------------- refusals
    for call in [
        RefusedCall::ControlSync,
        RefusedCall::MembershipFetch,
        RefusedCall::ControlAck,
    ] {
        g.valid(
            call.op(),
            call.op(),
            "to_host",
            "the Station refuses the call on this link (agreed with Astation, 2026-11-11): exactly this, naming nothing",
            json!({"code": "forbidden"}),
            CallRefused { call, code: RefusalCode::Forbidden }.to_json().unwrap(),
        );
    }

    // ============================================================ invalid
    let sync_wire = |after: &str| {
        format!(
            r#"{{"after":{after},"feed_id":"{feed}","op":"control_sync","origin":"{origin}","type":"relay"}}"#
        )
    };
    g.bad_edit(
        "control_sync_unknown_field",
        "control_sync_with_feed_id",
        "unknown_field",
        |v| v["mailbox"] = json!(1),
    );
    g.bad_edit(
        "control_sync_feed_id_null",
        "control_sync_with_feed_id",
        "malformed",
        |v| v["feed_id"] = Value::Null,
    );
    g.bad(
        "control_sync_duplicate_key",
        "control_sync",
        "to_station",
        "not_strict",
        format!(
            r#"{{"after":2,"after":3,"feed_id":"{feed}","op":"control_sync","origin":"{origin}","type":"relay"}}"#
        ),
    );
    g.bad_edit(
        "control_sync_after_without_a_feed_id",
        "control_sync_without_feed_id",
        "malformed",
        |v| v["after"] = json!(5),
    );
    g.bad_edit(
        "control_sync_origin_with_a_path",
        "control_sync_with_feed_id",
        "malformed",
        |v| v["origin"] = json!(format!("{origin}/")),
    );
    g.bad_edit(
        "control_sync_origin_not_lowercase",
        "control_sync_with_feed_id",
        "malformed",
        |v| v["origin"] = json!("https://Station-dev.agora.build"),
    );
    g.bad_edit(
        "control_sync_origin_plain_http",
        "control_sync_with_feed_id",
        "malformed",
        |v| v["origin"] = json!("http://station-dev.agora.build"),
    );
    g.bad_edit(
        "control_sync_feed_id_not_uuid_v4",
        "control_sync_with_feed_id",
        "malformed",
        |v| v["feed_id"] = json!("6f1c2b3a-4d5e-5f60-8a7b-9c0d1e2f3a4b"),
    );
    g.bad_edit(
        "control_sync_feed_id_not_lowercase",
        "control_sync_with_feed_id",
        "malformed",
        |v| v["feed_id"] = json!(feed.to_uppercase()),
    );
    g.bad(
        "control_sync_after_a_fraction",
        "control_sync",
        "to_station",
        "not_strict",
        sync_wire("1.5"),
    );
    g.bad(
        "control_sync_after_an_unsafe_integer",
        "control_sync",
        "to_station",
        "not_strict",
        sync_wire("9007199254740992"),
    );
    g.bad(
        "control_sync_after_negative",
        "control_sync",
        "to_station",
        "malformed",
        sync_wire("-1"),
    );
    g.bad_edit(
        "control_sync_after_missing",
        "control_sync_with_feed_id",
        "malformed",
        |v| {
            v.as_object_mut().unwrap().remove("after");
        },
    );
    g.bad_edit(
        "control_sync_after_as_text",
        "control_sync_with_feed_id",
        "malformed",
        |v| v["after"] = json!("2"),
    );
    g.bad_edit(
        "control_sync_not_a_relay_message",
        "control_sync_with_feed_id",
        "wrong_message",
        |v| v["type"] = json!("session"),
    );
    let wire = g.wires["control_sync_with_feed_id"].clone();
    g.bad(
        "a_call_read_as_a_stations_message",
        "control_sync",
        "to_host",
        "wrong_message",
        wire,
    );
    let wire = g.wires["heads_two_stations"].clone();
    g.bad(
        "a_stations_message_read_as_a_call",
        "heads",
        "to_station",
        "wrong_message",
        wire,
    );
    g.bad(
        "a_json_array",
        "control_sync",
        "to_station",
        "wrong_message",
        "[]",
    );
    g.bad("not_json", "control_sync", "to_station", "not_strict", "{");
    let push = r#"{"hints":[],"op":"push_hint","type":"relay"}"#;
    g.bad(
        "another_relay_message_to_a_station",
        "control_sync",
        "to_station",
        "wrong_message",
        push,
    );
    g.bad(
        "another_relay_message_to_a_host",
        "heads",
        "to_host",
        "wrong_message",
        push,
    );

    // control_sync_result
    let result_wire = |head: u64, records: &str| {
        format!(
            r#"{{"feed_id":"{feed}","head":{head},"op":"control_sync_result","origin":"{origin}","records":{records},"station_time":{STATION_TIME},"type":"relay"}}"#
        )
    };
    // A page of one record that is no record (any JSON value is read), for the
    // variants of a page's structure to change.
    let base = "control_sync_result_empty_feed";
    let one = |v: &mut Value| {
        v["head"] = json!(1);
        v["records"] = json!([{"feed_seq": 1, "record": 0}]);
    };
    g.bad_edit(
        "control_sync_result_unknown_field",
        base,
        "unknown_field",
        |v| v["more"] = json!(true),
    );
    g.bad_edit(
        "control_sync_result_item_unknown_field",
        base,
        "unknown_field",
        |v| {
            one(v);
            v["records"][0]["extra"] = json!(1)
        },
    );
    g.bad_edit(
        "control_sync_result_item_without_a_record",
        base,
        "malformed",
        |v| {
            one(v);
            v["records"][0].as_object_mut().unwrap().remove("record");
        },
    );
    g.bad_edit("control_sync_result_65_records", base, "too_large", |v| {
        v["head"] = json!(65);
        v["records"] = Value::Array(
            (1..=65)
                .map(|i| json!({"feed_seq": i, "record": 0}))
                .collect(),
        );
    });
    g.bad_edit(
        "control_sync_result_feed_seq_above_the_head",
        base,
        "malformed",
        |v| {
            one(v);
            v["records"][0]["feed_seq"] = json!(2)
        },
    );
    g.bad_edit(
        "control_sync_result_feed_seq_not_ascending",
        base,
        "malformed",
        |v| {
            v["head"] = json!(2);
            v["records"] = json!([{"feed_seq": 2, "record": 0}, {"feed_seq": 1, "record": 0}]);
        },
    );
    g.bad_edit(
        "control_sync_result_feed_seq_twice",
        base,
        "malformed",
        |v| {
            v["head"] = json!(2);
            v["records"] = json!([{"feed_seq": 1, "record": 0}, {"feed_seq": 1, "record": 0}]);
        },
    );
    g.bad_edit(
        "control_sync_result_feed_seq_zero",
        base,
        "malformed",
        |v| {
            one(v);
            v["records"][0]["feed_seq"] = json!(0)
        },
    );
    g.bad_edit("control_sync_result_head_as_text", base, "malformed", |v| {
        v["head"] = json!("0")
    });
    g.bad_edit(
        "control_sync_result_origin_with_a_path",
        base,
        "malformed",
        |v| v["origin"] = json!(format!("{origin}/")),
    );
    g.bad_edit(
        "control_sync_result_feed_id_not_uuid_v4",
        base,
        "malformed",
        |v| v["feed_id"] = json!("not-a-feed"),
    );
    g.bad_edit(
        "control_sync_result_station_time_missing",
        base,
        "malformed",
        |v| {
            v.as_object_mut().unwrap().remove("station_time");
        },
    );
    g.bad_edit(
        "control_sync_result_records_not_an_array",
        base,
        "malformed",
        |v| v["records"] = json!({}),
    );
    g.bad(
        "control_sync_result_duplicate_key_inside_a_record",
        "control_sync_result",
        "to_host",
        "not_strict",
        result_wire(1, r#"[{"feed_seq":1,"record":{"a":1,"a":2}}]"#),
    );
    g.bad(
        "control_sync_result_fraction_inside_a_record",
        "control_sync_result",
        "to_host",
        "not_strict",
        result_wire(1, r#"[{"feed_seq":1,"record":{"a":1.5}}]"#),
    );
    g.bad(
        "control_sync_result_unsafe_integer_inside_a_record",
        "control_sync_result",
        "to_host",
        "not_strict",
        result_wire(1, r#"[{"feed_seq":1,"record":{"a":9007199254740992}}]"#),
    );
    g.bad(
        "control_sync_result_lone_surrogate_inside_a_record",
        "control_sync_result",
        "to_host",
        "not_strict",
        result_wire(1, r#"[{"feed_seq":1,"record":"\ud800"}]"#),
    );
    g.bad(
        "control_sync_result_record_nested_past_the_depth_bound",
        "control_sync_result",
        "to_host",
        "not_strict",
        result_wire(
            1,
            &format!(
                r#"[{{"feed_seq":1,"record":{}{}}}]"#,
                "[".repeat(200),
                "]".repeat(200)
            ),
        ),
    );
    // Over the bound by one byte: a record that is one long string.
    {
        let prefix = format!(
            r#"{{"feed_id":"{feed}","head":1,"op":"control_sync_result","origin":"{origin}","records":[{{"feed_seq":1,"record":""#
        );
        let suffix = format!(r#""}}],"station_time":{STATION_TIME},"type":"relay"}}"#);
        let bytes = RELAY_MAX_BYTES + 1;
        g.invalid.push(json!({
            "name": "control_sync_result_over_262144_bytes",
            "op": "control_sync_result", "reader": "to_host", "code": "too_large",
            "wire_fill": {"prefix": prefix, "fill": "x", "count": bytes - prefix.len() - suffix.len(),
                "suffix": suffix, "bytes": bytes},
        }));
    }

    // heads
    let h = "heads_two_stations";
    g.bad_edit("heads_unknown_mailbox_field", h, "unknown_field", |v| {
        v["mailbox"] = json!({"head": 1, "mailbox_id": feed})
    });
    g.bad_edit("heads_a_feed_twice", h, "malformed", |v| {
        v["feeds"][1] = v["feeds"][0].clone()
    });
    g.bad_edit("heads_65_feeds", h, "too_large", |v| {
        v["feeds"] = Value::Array((0..65).map(|_| json!(0)).collect())
    });
    g.bad_edit("heads_membership_seq_zero", h, "malformed", |v| {
        v["membership"]["seq"] = json!(0)
    });
    g.bad_edit("heads_membership_hash_not_lowercase", h, "malformed", |v| {
        v["membership"]["hash"] = json!(log_head.hash.to_hex().to_uppercase())
    });
    g.bad_edit("heads_membership_unknown_field", h, "unknown_field", |v| {
        v["membership"]["extra"] = json!(1)
    });
    g.bad_edit("heads_membership_missing", h, "malformed", |v| {
        v.as_object_mut().unwrap().remove("membership");
    });
    g.bad_edit("heads_feeds_missing", h, "malformed", |v| {
        v.as_object_mut().unwrap().remove("feeds");
    });
    g.bad_edit("heads_feed_unknown_field", h, "unknown_field", |v| {
        v["feeds"][0]["extra"] = json!(1)
    });

    // control_ack
    let a = "control_ack_both_result_forms";
    g.bad_edit("control_ack_unknown_field", a, "unknown_field", |v| {
        v["extra"] = json!(1)
    });
    g.bad_edit("control_ack_65_results", a, "too_large", |v| {
        v["results"] = Value::Array((0..65).map(|_| json!(0)).collect())
    });
    g.bad_edit("control_ack_a_record_twice", a, "malformed", |v| {
        v["results"] = json!([v["results"][0].clone(), v["results"][0].clone()])
    });
    g.bad_edit("control_ack_an_entry_twice", a, "malformed", |v| {
        v["results"] = json!([v["results"][1].clone(), v["results"][1].clone()])
    });
    g.bad_edit("control_ack_effects_out_of_order", a, "malformed", |v| {
        v["results"][0]["effects"] = json!([
            {"effect": "interrupt", "result": "applied"},
            {"effect": "revocation", "result": "duplicate"}
        ])
    });
    g.bad_edit(
        "control_ack_effects_no_record_carries",
        a,
        "malformed",
        |v| {
            v["results"][0]["effects"] = json!([
                {"effect": "cover", "result": "applied"},
                {"effect": "revocation", "result": "applied"}
            ])
        },
    );
    g.bad_edit("control_ack_effects_empty", a, "malformed", |v| {
        v["results"][0]["effects"] = json!([])
    });
    g.bad_edit("control_ack_effects_three", a, "malformed", |v| {
        v["results"][0]["effects"] = json!([
            {"effect": "revocation", "result": "applied"},
            {"effect": "interrupt", "result": "applied"},
            {"effect": "hold", "result": "applied"}
        ])
    });
    g.bad_edit("control_ack_a_result_of_both_forms", a, "malformed", |v| {
        v["results"][0]["entry"] = v["results"][1]["entry"].clone()
    });
    g.bad_edit(
        "control_ack_a_result_of_neither_form",
        a,
        "malformed",
        |v| {
            v["results"][0].as_object_mut().unwrap().remove("record_id");
        },
    );
    g.bad_edit("control_ack_an_unknown_result", a, "malformed", |v| {
        v["results"][0]["effects"][0]["result"] = json!("maybe")
    });
    g.bad_edit("control_ack_host_trust_gen_zero", a, "malformed", |v| {
        v["host_trust_gen"] = json!(0)
    });
    g.bad_edit(
        "control_ack_entry_applied_behind_applied_seq",
        a,
        "malformed",
        |v| v["results"][1]["applied_seq"] = json!(11),
    );
    g.bad_edit(
        "control_ack_genesis_hash_not_lowercase",
        a,
        "malformed",
        |v| v["genesis_hash"] = json!(genesis.to_hex().to_uppercase()),
    );
    g.bad_edit("control_ack_cursor_missing", a, "malformed", |v| {
        v.as_object_mut().unwrap().remove("cursor");
    });
    g.bad_edit(
        "control_ack_result_unknown_field",
        a,
        "unknown_field",
        |v| v["results"][0]["extra"] = json!(1),
    );
    g.bad_edit("control_ack_account_id_empty", a, "malformed", |v| {
        v["account_id"] = json!("")
    });
    g.bad_edit("control_ack_feed_id_missing", a, "malformed", |v| {
        v.as_object_mut().unwrap().remove("feed_id");
    });

    // membership_fetch
    let f = "membership_fetch";
    g.bad_edit("membership_fetch_unknown_field", f, "unknown_field", |v| {
        v["feed_id"] = json!(feed)
    });
    g.bad_edit("membership_fetch_after_null", f, "malformed", |v| {
        v["after"] = Value::Null
    });
    g.bad_edit("membership_fetch_after_missing", f, "malformed", |v| {
        v.as_object_mut().unwrap().remove("after");
    });

    // membership_fetch_result
    let r = "membership_fetch_result_no_entries";
    g.bad_edit("membership_fetch_result_65_entries", r, "too_large", |v| {
        v["entries"] = Value::Array((0..65).map(|_| json!(0)).collect())
    });
    g.bad_edit(
        "membership_fetch_result_an_entry_that_is_not_an_object",
        r,
        "malformed",
        |v| v["entries"] = json!([0]),
    );
    g.bad_edit(
        "membership_fetch_result_head_seq_zero",
        r,
        "malformed",
        |v| v["head"]["seq"] = json!(0),
    );
    g.bad_edit(
        "membership_fetch_result_head_hash_not_hex",
        r,
        "malformed",
        |v| v["head"]["hash"] = json!("beb1"),
    );
    g.bad_edit(
        "membership_fetch_result_echoes_after",
        r,
        "unknown_field",
        |v| v["after"] = json!(2),
    );
    g.bad_edit(
        "membership_fetch_result_carries_more",
        r,
        "unknown_field",
        |v| v["more"] = json!(false),
    );
    g.bad_edit(
        "membership_fetch_result_entries_missing",
        r,
        "malformed",
        |v| {
            v.as_object_mut().unwrap().remove("entries");
        },
    );

    // the three refusals
    for call in [
        RefusedCall::ControlSync,
        RefusedCall::MembershipFetch,
        RefusedCall::ControlAck,
    ] {
        let op = call.op();
        let name = |what: &str| format!("{op}_{what}");
        g.bad_edit(&name("unknown_code"), op, "malformed", |v| {
            v["code"] = json!("not_found")
        });
        g.bad_edit(&name("code_null"), op, "malformed", |v| {
            v["code"] = Value::Null
        });
        g.bad_edit(&name("code_missing"), op, "malformed", |v| {
            v.as_object_mut().unwrap().remove("code");
        });
        g.bad_edit(&name("code_not_lowercase"), op, "malformed", |v| {
            v["code"] = json!("Forbidden")
        });
        g.bad_edit(&name("names_a_feed"), op, "unknown_field", |v| {
            v["feed_id"] = json!(feed)
        });
        g.bad(
            &name("duplicate_key"),
            op,
            "to_host",
            "not_strict",
            format!(r#"{{"code":"forbidden","code":"forbidden","op":"{op}","type":"relay"}}"#),
        );
        let wire = g.wires[op].clone();
        g.bad(
            &name("read_as_a_call"),
            op,
            "to_station",
            "wrong_message",
            wire,
        );
    }

    json!({
        "name": STATION_CALLS,
        "kind": "vectors",
        "requires": "r9",
        "note": "The six Station calls (control_sync, control_sync_result, heads, control_ack, membership_fetch, membership_fetch_result) and the three refusals (control_sync_refused, membership_fetch_refused, control_ack_refused) of host-work-v1 §11.4, as the shared core's own builders write them (planned; nothing advertises them). `calls`: each valid message `{name, op, direction, note, fields, wire, judged?}`. `wire` is the exact text: compact, keys in RFC 8785 order (the builders' order), no whitespace; `direction` says who reads it (`to_station`: a host's call, `to_host`: a Station's message; the other reader refuses it as another message); `fields` are what it decodes to (an absent optional field is absent; every value as sent, a page's record as a value). `judged`, for a page: the control parser's verdict on each record, parallel to the records (`parses` with the `record_id`, or not with its parse `error`): a record the parser refuses never costs the page, the feed's position or the records after it. A Station builder can't write such a record (a Station serves only what it stored), so that page's text is a builder's page with the records put in their slots. `invalid`: texts a reader refuses `{name, op, reader, code, wire}` with the code it gives (`too_large`, `not_strict`, `wrong_message`, `unknown_field` or `malformed`); each has one fault (a text with two is refused by whichever the reader reaches first: the size bound, the strict parse, the message and its op, unknown fields, then the fields' values); `wire_fill` stands for a text of `bytes` bytes written as `prefix`, `count` times `fill`, then `suffix`. `max_message_bytes` is R9.9's bound for every relay message, in bytes as sent, checked before any parse. Every valid text is strict I-JSON; `scripts/check-r9-vectors.py` reads every text, valid and invalid, with a reader written from the spec.",
        "max_message_bytes": RELAY_MAX_BYTES,
        "calls": g.calls,
        "invalid": g.invalid,
    })
}

/// Writes `r9-vectors-station-calls` from `station_call_vectors`.
#[test]
#[ignore = "writes the Station call goldens"]
fn write_station_calls_vectors() {
    let mut text = serde_json::to_string_pretty(&station_call_vectors()).unwrap();
    text.push('\n');
    std::fs::write(fixtures_dir().join("r9-vectors-station-calls.json"), text).unwrap();
}

// ------------------------- delegated host work: envelopes and results (mail)

// `r9-vectors-host-envelope` (delegated host-work design II.4.2, II.4.4,
// III.1; host-work-v1 §11.5): `atem-envelope` and `atem-result` objects
// between three hosts of log L's account, and the verdict the receiver's
// checks give each against a device list and a receiver. The lists are log L
// followed by the file's `entries` (signed by dev-mac); every object is
// sealed by the shared core's own `seal_envelope_with_ikm` or
// `seal_result_with_ikm` (`built`), by the same HPKE seal over raw bytes no
// sender's builder writes (a plaintext with `null`, one too large, one not
// canonical, a dropped reply), or is another object's bytes changed after
// signing. `write_host_envelope_vectors` (ignored) writes the file from
// `host_envelope_vectors`; `host_envelope` checks the file is exactly what
// it makes now, every value from its parts, and every check's verdict
// through `open_envelope` or `accept_result`.

/// `created_at` of the objects (but those whose times are the point).
const MAIL_T0: u64 = 1_793_620_800_000;
/// Their `expires_at`: an hour later.
const MAIL_EXPIRES: u64 = MAIL_T0 + 3_600_000;
/// The receiver's clock, unless a check names another.
const MAIL_NOW: u64 = MAIL_T0 + 1_000;
/// `signed_at` of the file's entries: this plus `seq` seconds (display only).
const MAIL_ENTRY_T0: u64 = MAIL_T0 - 3_600_000;
/// The list every object is signed at: log L and four entries (head 10).
const MAIL_B: [&str; 4] = ["M7_add_host_b", "M8_enc_a", "M9_enc_b", "M10_add_host_evil"];

/// A test id: the first 16 bytes of SHA-256(enc(["atem-r9-test-id", label]))
/// as a UUID of `version` (4; 5 for a reply's `result_id`).
fn mail_uuid(label: &str, version: u8) -> String {
    let mut b: [u8; 32] = Sha256::digest(enc(&[b"atem-r9-test-id", label.as_bytes()])).into();
    b[6] = (b[6] & 0x0f) | (version << 4);
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex(&b[..16]);
    format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    )
}

/// A UUID v4 of the host-envelope vectors.
fn mail_id(label: &str) -> String {
    mail_uuid(&format!("host-envelope {label}"), 4)
}

/// The ephemeral's ikmE: SHA-256(enc(["atem-r9-test-ikm", label])).
fn mail_ikm(label: &str) -> [u8; 32] {
    Sha256::digest(enc(&[b"atem-r9-test-ikm", label.as_bytes()])).into()
}

/// A host at a trust generation.
#[derive(Clone, Copy)]
struct MailHost(&'static str, u64);

const MAIL_A1: MailHost = MailHost("host-a", 1);
const MAIL_A2: MailHost = MailHost("host-a", 2);
const MAIL_B1: MailHost = MailHost("host-b", 1);
const MAIL_B2: MailHost = MailHost("host-b", 2);
const MAIL_EVIL: MailHost = MailHost("host-evil", 1);

impl MailHost {
    fn host_ref(self) -> HostRef {
        HostRef {
            host_id: self.0.into(),
            host_trust_gen: self.1,
        }
    }

    /// Its host key in the book (`r9-vectors-keys`).
    fn key(self) -> KeyId {
        KeyId::new(format!("{}/host_key", host_key_name(self.0, self.1)))
    }
}

/// The plaintext one of the builders seals.
enum MailPlain {
    Envelope(EnvelopePlain),
    Result(ResultPlain),
}

/// Builds the host-envelope vectors on log L with the test keys.
struct MailVectors<'a> {
    book: &'a Book,
    genesis: Hash32,
    now: HostNow,
    log_l: Vec<Entry>,
    entries: BTreeMap<String, Entry>,
    entry_vectors: Vec<Value>,
    objects: BTreeMap<String, SignedObject>,
    object_vectors: Vec<Value>,
    checks: Vec<Value>,
}

impl<'a> MailVectors<'a> {
    fn new(book: &'a Book) -> Self {
        let file = load("r9-vectors-membership-log");
        let log_l = file["log"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| Entry::from_strict(&strict(&v["entry"])).unwrap())
            .collect();
        MailVectors {
            book,
            genesis: genesis_hash(),
            now: HostNow {
                wall_ms: MAIL_NOW,
                mono_ms: 1_000,
                boot_id: "boot-1".into(),
            },
            log_l,
            entries: BTreeMap::new(),
            entry_vectors: Vec::new(),
            objects: BTreeMap::new(),
            object_vectors: Vec::new(),
            checks: Vec::new(),
        }
    }

    /// Log L followed by the file's entries `chain`.
    fn list(&self, chain: &[&str]) -> Membership {
        let entries: Vec<Entry> = self
            .log_l
            .iter()
            .cloned()
            .chain(chain.iter().map(|l| self.entries[*l].clone()))
            .collect();
        let verified =
            Membership::verify_chain("acct-test-1", &self.genesis, &entries, &self.now).unwrap();
        assert!(verified.deferred.is_none());
        verified.membership
    }

    fn enc_pub(&self, name: &str) -> PublicKey {
        self.book.public(&format!("{name}/enc"))
    }

    fn add_host(&self, host: MailHost) -> Action {
        Action::AddHost {
            host: HostRecord {
                host_id: host.0.into(),
                host_trust_gen: host.1,
                host_key: self.book.provider.public_key(&host.key()).unwrap(),
            },
        }
    }

    /// A `host_enc_key` of the key `enc_name`, the host vouching for it with
    /// its key of that generation.
    fn enc_key(&self, host: MailHost, enc_name: &str, retire_previous: bool) -> Action {
        use atem_client::membership::{host_enc_key, sign_host_enc_key};
        let key = self.enc_pub(enc_name);
        let sig = sign_host_enc_key(
            &self.book.provider,
            &host.key(),
            "acct-test-1",
            &self.genesis,
            host.0,
            host.1,
            key.as_32().unwrap(),
        )
        .unwrap();
        host_enc_key(host.0, host.1, &key, &sig, retire_previous, MAIL_ENTRY_T0).unwrap()
    }

    /// `action`, signed by dev-mac as the entry after L + `chain`.
    fn entry(&mut self, label: &str, chain: &[&str], note: &str, action: Action) {
        let m = self.list(chain);
        let seq = m.head().seq + 1;
        let body = m.draft("dev-mac", MAIL_ENTRY_T0 + seq * 1000, &action);
        let object =
            SignedObject::sign(&self.book.provider, &self.book.signer("dev-mac"), body).unwrap();
        let entry = Entry::parse(object.clone()).unwrap();
        assert_eq!(m.check_next(&entry), Check::Valid, "{label}");
        self.entry_vectors.push(serde_json::json!({
            "label": label,
            "note": note,
            "chain": chain,
            "entry": object.to_json(),
            "entry_hash": entry.hash().to_hex(),
        }));
        self.entries.insert(label.to_owned(), entry);
    }

    /// The body before the seal: `sender` to `recipient`, sealed to its key
    /// `enc_name`, the id of `id_label`, signed at the head of L + `head`.
    fn fields(
        &self,
        id_label: &str,
        sender: MailHost,
        recipient: MailHost,
        enc_name: &str,
        head: &[&str],
    ) -> MailFields {
        MailFields {
            account_id: "acct-test-1".into(),
            genesis_hash: self.genesis,
            sender: sender.host_ref(),
            recipient: recipient.host_ref(),
            enc_kid: enc_kid(&self.enc_pub(enc_name)).unwrap(),
            id: mail_id(id_label),
            created_at: MAIL_T0,
            expires_at: MAIL_EXPIRES,
            signed_at_head: self.list(head).head(),
        }
    }

    /// Records an object and what makes it: `extra` names its signer, the
    /// seal and where its bytes came from.
    fn record(&mut self, label: &str, note: &str, object: SignedObject, extra: Value) {
        let kind = match object.label() {
            SignLabel::Envelope => "envelope",
            SignLabel::Result => "result",
            other => panic!("{label}: {other:?}"),
        };
        let mut v = serde_json::json!({
            "label": label,
            "note": note,
            "kind": kind,
            "object": object.to_json(),
            "jcs": object.jcs(),
            "signing_input_hex": hex(object.signing_input().as_bytes()),
        });
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        self.objects.insert(label.to_owned(), object);
        self.object_vectors.push(v);
    }

    /// The seal's inputs and outputs (`sealed`): the key sealed to, `info`,
    /// `sealed_hash`, the ephemeral and the plaintext (its length and
    /// SHA-256 instead when it is over 4 KiB).
    fn sealed(
        &self,
        kind: MailKind,
        fields: &MailFields,
        object: &SignedObject,
        plaintext: &[u8],
        enc_name: &str,
        ikm_label: &str,
    ) -> Value {
        let part = object.sealed().unwrap();
        let mut v = serde_json::json!({
            "to": enc_name,
            "info_hex": hex(&seal_info(kind, fields)),
            "sealed_hash": Hash32::of_enc(&[&part.enc, &part.ct]).to_hex(),
            "ikm_label": ikm_label,
            "ikmE_hex": hex(&mail_ikm(ikm_label)),
        });
        if plaintext.len() > 4096 {
            v["plaintext_bytes"] = plaintext.len().into();
            v["plaintext_sha256"] = hex(&Sha256::digest(plaintext)).into();
        } else {
            v["plaintext"] = std::str::from_utf8(plaintext).unwrap().into();
        }
        v
    }

    /// `plain` sealed by the shared core's builder to `enc_name` and signed by
    /// the sender's host key of its generation.
    fn seal(
        &mut self,
        label: &str,
        note: &str,
        fields: MailFields,
        plain: MailPlain,
        enc_name: &str,
    ) {
        let ikm_label = format!("host-envelope {label}");
        let ikm = mail_ikm(&ikm_label);
        let to = self.enc_pub(enc_name);
        let signer = host_key_name(&fields.sender.host_id, fields.sender.host_trust_gen);
        let key = KeyId::new(format!("{signer}/host_key"));
        let provider = &self.book.provider;
        let (kind, object, plaintext) = match plain {
            MailPlain::Envelope(p) => (
                MailKind::Envelope,
                seal_envelope_with_ikm(provider, &key, &fields, &p, &to, &ikm).unwrap(),
                p.to_bytes().unwrap().to_vec(),
            ),
            MailPlain::Result(p) => (
                MailKind::Result,
                seal_result_with_ikm(provider, &key, &fields, &p, &to, &ikm).unwrap(),
                p.to_bytes().unwrap().to_vec(),
            ),
        };
        let sealed = self.sealed(kind, &fields, &object, &plaintext, enc_name, &ikm_label);
        let extra = serde_json::json!({
            "signed_with": signer,
            "built": true,
            "sealed": sealed,
        });
        self.record(label, note, object, extra);
    }

    /// Raw `plaintext` (one no sender's builder writes) under the same seal
    /// and signature.
    fn seal_raw(
        &mut self,
        label: &str,
        note: &str,
        kind: MailKind,
        fields: MailFields,
        plaintext: &[u8],
        enc_name: &str,
    ) {
        use atem_client::signed::SealedPart;
        let ikm_label = format!("host-envelope {label}");
        let to = self.enc_pub(enc_name);
        let sealed = hpke::seal_with_ikm(
            to.as_32().unwrap(),
            &seal_info(kind, &fields),
            b"",
            plaintext,
            &mail_ikm(&ikm_label),
        )
        .unwrap();
        let signer = host_key_name(&fields.sender.host_id, fields.sender.host_trust_gen);
        let key = KeyId::new(format!("{signer}/host_key"));
        let body = MailBody::from_fields(fields.clone(), sealed.hash()).to_value(kind);
        let object = SignedObject::sign(&self.book.provider, &key, body)
            .unwrap()
            .with_sealed(SealedPart {
                enc: sealed.enc.to_vec(),
                ct: sealed.ct,
            });
        let details = self.sealed(kind, &fields, &object, plaintext, enc_name, &ikm_label);
        let extra = serde_json::json!({
            "signed_with": signer,
            "built": false,
            "sealed": details,
        });
        self.record(label, note, object, extra);
    }

    /// `from`'s body with `edit` applied, re-signed by `by`, its sealed part
    /// kept (`sealed_from`).
    fn resign(
        &mut self,
        label: &str,
        note: &str,
        from: &str,
        by: MailHost,
        edit: impl FnOnce(&mut MailFields),
    ) {
        let source = self.objects[from].clone();
        let (kind, body) = MailBody::from_object(&source).unwrap();
        let mut fields = body.fields();
        edit(&mut fields);
        let body = MailBody::from_fields(fields, body.sealed_hash).to_value(kind);
        let object = SignedObject::sign(&self.book.provider, &by.key(), body)
            .unwrap()
            .with_sealed(source.sealed().unwrap().clone());
        let extra = serde_json::json!({
            "signed_with": host_key_name(by.0, by.1),
            "built": false,
            "sealed_from": from,
        });
        self.record(label, note, object, extra);
    }

    /// `from`'s wire object with `edit` applied after signing (`edited_from`).
    fn edit(&mut self, label: &str, note: &str, from: &str, edit: impl FnOnce(&mut Value)) {
        let mut wire = self.objects[from].to_json();
        edit(&mut wire);
        let object = SignedObject::from_strict(&strict(&wire)).unwrap();
        let extra = serde_json::json!({"built": false, "edited_from": from});
        self.record(label, note, object, extra);
    }

    /// A check of `object`: the verdict `expect` of `open_envelope` (no
    /// `outbox`) or `accept_result`, on L + `chain`, by the receiver
    /// `(host, its keys)`, at `now`.
    #[allow(clippy::too_many_arguments)]
    fn check(
        &mut self,
        label: &str,
        note: &str,
        object: &str,
        chain: &[&str],
        receiver: (MailHost, &[&str]),
        now: u64,
        outbox: Option<Value>,
        expect: Value,
    ) {
        assert!(self.objects.contains_key(object), "{label}: {object}");
        let mut v = serde_json::json!({
            "label": label,
            "note": note,
            "object": object,
            "call": if outbox.is_some() { "accept_result" } else { "open_envelope" },
            "chain": chain,
            "receiver": {
                "host_id": receiver.0.0,
                "host_trust_gen": receiver.0.1,
                "keys": receiver.1,
            },
            "now": now,
            "expect": expect,
        });
        if let Some(outbox) = outbox {
            v["outbox"] = outbox;
        }
        self.checks.push(v);
    }

    fn refused(&self, object: &str, reason: &str) -> Value {
        serde_json::json!({
            "verdict": "refused",
            "reason": reason,
            "evidence": evidence_hash(&self.objects[object]).to_hex(),
        })
    }

    fn refused_authenticated(&self, object: &str, reason: &str) -> Value {
        serde_json::json!({
            "verdict": "refused_authenticated",
            "object_id": s(self.objects[object].body(), "id"),
            "reason": reason,
        })
    }
}

fn mail_open(sender: &str) -> Value {
    serde_json::json!({"verdict": "open", "sender": format!("host:{sender}")})
}

fn mail_pending(host: MailHost) -> Value {
    serde_json::json!({"verdict": "pending", "host_id": host.0, "host_trust_gen": host.1})
}

/// The request Message of a host sender (`Message::valid_from_host`): from
/// `fields`' sender, with its id and times, a notice for the recipient host.
fn mail_message(fields: &MailFields) -> atem_client::session::messages::Message {
    use atem_client::host_principal::host_principal;
    use atem_client::session::host_work::HostTarget;
    use atem_client::session::messages::{Destination, Message, MessageKind, Recipient};
    Message {
        message_id: fields.id.clone(),
        workflow_id: mail_id("workflow"),
        sender: host_principal(&fields.sender.host_id),
        kind: MessageKind::Request,
        reply_to: None,
        from_session: None,
        created_at: fields.created_at,
        expires_at: fields.expires_at,
        recipients: vec![Recipient {
            recipient_id: mail_id("request recipient"),
            host: HostTarget {
                account_id: fields.account_id.clone(),
                atem_device_id: fields.recipient.host_id.clone(),
                host_trust_gen: fields.recipient.host_trust_gen,
            },
            destination: Destination::Host,
        }],
        text: "Review the contract".into(),
        context: vec![],
        mark: None,
    }
}

/// A Memory snapshot of `text`.
fn mail_snapshot(id: &str, text: String) -> atem_client::session::host_work::ContextSnapshot {
    use atem_client::session::host_work::{ContextKind, ContextSnapshot, digest};
    ContextSnapshot {
        kind: ContextKind::Memory,
        id: id.into(),
        version: 1,
        digest: digest(text.as_bytes()),
        text,
    }
}

/// `mail_message(fields)` with three snapshots, the last sized so the
/// Message serializes to exactly `target` bytes.
fn mail_message_of_size(
    fields: &MailFields,
    target: usize,
) -> atem_client::session::messages::Message {
    let build = |last: usize| {
        let mut m = mail_message(fields);
        m.context = vec![
            mail_snapshot("ctx-0", "a".repeat(80 * 1024)),
            mail_snapshot("ctx-1", "b".repeat(80 * 1024)),
            mail_snapshot("ctx-2", "c".repeat(last)),
        ];
        m
    };
    let len = |m: &atem_client::session::messages::Message| serde_json::to_vec(m).unwrap().len();
    let probe = 80 * 1024;
    let m = build(probe + target - len(&build(probe)));
    assert_eq!(len(&m), target);
    m
}

/// A submitted reply (`dropped`: the host no longer keeps its text).
fn mail_reply(dropped: bool) -> atem_client::session::host_work::ResultReply {
    use atem_client::session::host_work::{ReplyState, ResultReply, digest};
    let text = "Done: the contract reads well.";
    ResultReply {
        result_id: mail_uuid("host-envelope reply", 5),
        state: ReplyState::Submitted,
        digest: digest(text.as_bytes()),
        text: if dropped { String::new() } else { text.into() },
        context: vec![],
        submitted_at: Some(MAIL_T0 + 60_000),
        dropped,
    }
}

/// The host-envelope vectors file, as `write_host_envelope_vectors` writes it.
fn host_envelope_vectors(book: &Book) -> Value {
    use atem_client::membership::{host_sender_readmit, host_sender_revoke};
    use atem_client::session::messages::{Delivery, RecipientReceipt};
    let mut g = MailVectors::new(book);
    let b = MAIL_B;
    let on_b =
        |more: &[&'static str]| -> Vec<&'static str> { b.iter().chain(more).copied().collect() };

    // The device list: log L, host-b, both hosts' encryption keys and a
    // third host (B, head 10), then one change at a time on B.
    let add_b = g.add_host(MAIL_B1);
    g.entry(
        "M7_add_host_b",
        &[],
        "add_host host-b at generation 1",
        add_b,
    );
    let enc_a = g.enc_key(MAIL_A1, "host-a-enc-1", false);
    g.entry(
        "M8_enc_a",
        &b[..1],
        "host_enc_key: host-a's key host-a-enc-1",
        enc_a,
    );
    let enc_b = g.enc_key(MAIL_B1, "host-b-enc-1", false);
    g.entry(
        "M9_enc_b",
        &b[..2],
        "host_enc_key: host-b's key host-b-enc-1",
        enc_b,
    );
    let add_evil = g.add_host(MAIL_EVIL);
    g.entry(
        "M10_add_host_evil",
        &b[..3],
        "add_host host-evil (the test key host-evil, a third host of the account, with no encryption key): list B, head 10",
        add_evil,
    );
    let reverify_a = g.add_host(MAIL_A2);
    g.entry(
        "M11_reverify_a",
        &b,
        "host-a re-verified on B: add_host at generation 2 (its key host-a-gen-2)",
        reverify_a,
    );
    g.entry(
        "M11_revoke_a",
        &b,
        "host_sender_revoke host-a on B",
        host_sender_revoke("host-a", false, MAIL_ENTRY_T0).unwrap(),
    );
    g.entry(
        "M12_readmit_a",
        &on_b(&["M11_revoke_a"]),
        "host_sender_readmit host-a: authorized(12)",
        host_sender_readmit("host-a", MAIL_ENTRY_T0).unwrap(),
    );
    g.entry(
        "M11_remove_a",
        &b,
        "remove_host host-a on B",
        Action::RemoveHost {
            host_id: "host-a".into(),
        },
    );
    let rotate = g.enc_key(MAIL_A1, "host-a-enc-2", false);
    g.entry(
        "M11_rotate_a",
        &b,
        "host_enc_key: host-a rotates to host-a-enc-2 (the previous key opens mail for its 24 h window)",
        rotate,
    );
    let rotate_retire = g.enc_key(MAIL_A1, "host-a-enc-2", true);
    g.entry(
        "M11_rotate_a_retire",
        &b,
        "host_enc_key: host-a rotates to host-a-enc-2 with retire_previous",
        rotate_retire,
    );
    let reverify_b = g.add_host(MAIL_B2);
    g.entry(
        "M11_reverify_b",
        &b,
        "host-b re-verified on B: add_host at generation 2 (its key host-b-gen-2)",
        reverify_b,
    );
    g.entry(
        "M11_revoke_b",
        &b,
        "host_sender_revoke host-b on B",
        host_sender_revoke("host-b", false, MAIL_ENTRY_T0).unwrap(),
    );
    g.entry(
        "M11_remove_b",
        &b,
        "remove_host host-b on B",
        Action::RemoveHost {
            host_id: "host-b".into(),
        },
    );
    let rotate_b = g.enc_key(MAIL_B1, "host-b-enc-2", false);
    g.entry(
        "M11_rotate_b",
        &b,
        "host_enc_key: host-b rotates to host-b-enc-2 (a key it handed out)",
        rotate_b,
    );

    // Envelopes from host-a to host-b, sealed to host-b-enc-1, signed at B's
    // head (but where the point is another).
    let ab = |g: &MailVectors, label: &str| g.fields(label, MAIL_A1, MAIL_B1, "host-b-enc-1", &b);
    let task = mail_id("task");
    let cancel = |task: &str| EnvelopePlain::Cancel {
        task_id: task.into(),
    };
    let f = ab(&g, "request");
    let request = MailPlain::Envelope(EnvelopePlain::Request {
        message: mail_message(&f),
    });
    g.seal(
        "request",
        "a request: a host-work-v1 §5 Message from host:host-a, a notice for host-b",
        f,
        request,
        "host-b-enc-1",
    );
    let f = ab(&g, "cancel");
    g.seal(
        "cancel",
        "a cancel of the request's task",
        f,
        MailPlain::Envelope(cancel(&task)),
        "host-b-enc-1",
    );
    let f = ab(&g, "complete");
    let complete = EnvelopePlain::Complete {
        task_id: task.clone(),
        result: mail_snapshot("ctx-result", "The contract reads well.".into()),
    };
    g.seal(
        "complete",
        "a complete of the request's task with a result snapshot",
        f,
        MailPlain::Envelope(complete),
        "host-b-enc-1",
    );
    let f = ab(&g, "request_max");
    let message = mail_message_of_size(&f, 240 * 1024);
    g.seal(
        "request_max",
        "a request whose Message is 245,760 bytes, host-work v1's bound: its plaintext is 29 bytes more, 245,789, and the sealed object fits a 512 KiB mailbox call",
        f,
        MailPlain::Envelope(EnvelopePlain::Request { message }),
        "host-b-enc-1",
    );
    let f = ab(&g, "request_over");
    let message = mail_message_of_size(&f, 240 * 1024 + 1);
    let plaintext = jcs(&serde_json::json!({
        "kind": "request",
        "message": serde_json::to_value(&message).unwrap(),
    }))
    .unwrap();
    assert_eq!(plaintext.len(), 240 * 1024 + 30);
    g.seal_raw(
        "request_over",
        "a request whose Message is one byte over host-work v1's bound (plaintext 245,790 bytes); no builder seals it",
        MailKind::Envelope,
        f,
        plaintext.as_bytes(),
        "host-b-enc-1",
    );
    let mut f = ab(&g, "pin_mismatch");
    f.account_id = "acct-other".into();
    g.seal(
        "pin_mismatch",
        "a cancel naming another account",
        f,
        MailPlain::Envelope(cancel(&task)),
        "host-b-enc-1",
    );
    let f = g.fields("gen2_before_add_host", MAIL_A2, MAIL_B1, "host-b-enc-1", &b);
    g.seal(
        "gen2_before_add_host",
        "a cancel by host-a claiming generation 2 (signed with host-a-gen-2) at B's head, where host-a's newest add_host is generation 1",
        f,
        MailPlain::Envelope(cancel(&task)),
        "host-b-enc-1",
    );
    let f = g.fields(
        "gen2",
        MAIL_A2,
        MAIL_B1,
        "host-b-enc-1",
        &on_b(&["M11_reverify_a"]),
    );
    g.seal(
        "gen2",
        "a cancel by host-a at generation 2, signed at the head of B + M11_reverify_a (seq 11)",
        f,
        MailPlain::Envelope(cancel(&task)),
        "host-b-enc-1",
    );
    let mut f = ab(&g, "wrong_hash");
    f.signed_at_head.hash = g.entries["M9_enc_b"].hash();
    g.seal(
        "wrong_hash",
        "a cancel whose signed_at_head is seq 10 with the hash of the entry at seq 9",
        f,
        MailPlain::Envelope(cancel(&task)),
        "host-b-enc-1",
    );
    let f = g.fields(
        "head_ahead",
        MAIL_A1,
        MAIL_B1,
        "host-b-enc-1",
        &on_b(&["M11_rotate_a"]),
    );
    g.seal(
        "head_ahead",
        "a cancel by host-a at generation 1, signed at the head of B + M11_rotate_a (seq 11)",
        f,
        MailPlain::Envelope(cancel(&task)),
        "host-b-enc-1",
    );
    let f = ab(&g, "ids_mismatch");
    let mut message = mail_message(&f);
    message.message_id = mail_id("another message");
    g.seal(
        "ids_mismatch",
        "a request whose Message's message_id isn't the body's id",
        f,
        MailPlain::Envelope(EnvelopePlain::Request { message }),
        "host-b-enc-1",
    );
    let f = ab(&g, "attachments");
    let mut message = mail_message(&f);
    message.mark = Some(atem_client::session::mark::MarkTask {
        mark_id: "mark_123".into(),
        url: "http://localhost:3000".into(),
        title: "Page".into(),
        screenshot: atem_client::session::attachments::Attachment {
            attachment_id: mail_id("screenshot"),
            digest: atem_client::session::host_work::digest(b"png"),
            size: 68,
            media_type: "image/png".into(),
        },
        annotations: vec![],
    });
    g.seal(
        "attachments",
        "a request whose Message carries a mark (an attachment): none in this version",
        f,
        MailPlain::Envelope(EnvelopePlain::Request { message }),
        "host-b-enc-1",
    );
    let f = ab(&g, "from_session");
    let mut message = mail_message(&f);
    message.from_session = Some("ses-abcdefghijkl".into());
    g.seal(
        "from_session",
        "a request whose Message carries from_session (local only): not a host sender's Message",
        f,
        MailPlain::Envelope(EnvelopePlain::Request { message }),
        "host-b-enc-1",
    );
    let f = ab(&g, "plaintext_null");
    let text = format!(r#"{{"kind":"cancel","note":null,"task_id":"{task}"}}"#);
    g.seal_raw(
        "plaintext_null",
        "a cancel plaintext holding a null member; no builder seals it",
        MailKind::Envelope,
        f,
        text.as_bytes(),
        "host-b-enc-1",
    );
    let f = ab(&g, "plaintext_not_canonical");
    let text = format!(r#"{{"task_id":"{task}","kind":"cancel"}}"#);
    g.seal_raw(
        "plaintext_not_canonical",
        "a cancel plaintext whose members aren't in canonical order; the builder seals only the canonical form",
        MailKind::Envelope,
        f,
        text.as_bytes(),
        "host-b-enc-1",
    );
    let mut f = ab(&g, "bad_times");
    f.expires_at = f.created_at;
    g.seal(
        "bad_times",
        "a cancel whose expires_at equals its created_at",
        f,
        MailPlain::Envelope(cancel(&task)),
        "host-b-enc-1",
    );
    let mut f = ab(&g, "lifetime_too_long");
    f.expires_at = f.created_at + 86_400_001;
    g.seal(
        "lifetime_too_long",
        "a cancel that expires 24 h and 1 ms after its created_at",
        f,
        MailPlain::Envelope(cancel(&task)),
        "host-b-enc-1",
    );
    let f = g.fields(
        "cancel_to_new_key",
        MAIL_A1,
        MAIL_B1,
        "host-b-enc-2",
        &on_b(&["M11_rotate_b"]),
    );
    g.seal(
        "cancel_to_new_key",
        "a cancel sealed to host-b's new key host-b-enc-2, signed at the head of B + M11_rotate_b (seq 11), where host-a's list has the rotation",
        f,
        MailPlain::Envelope(cancel(&task)),
        "host-b-enc-2",
    );
    let f = g.fields("cancel_to_a", MAIL_B1, MAIL_A1, "host-a-enc-1", &b);
    g.seal(
        "cancel_to_a",
        "a cancel from host-b to host-a, sealed to host-a-enc-1",
        f,
        MailPlain::Envelope(cancel(&task)),
        "host-a-enc-1",
    );
    let f = g.fields("evil_cancel", MAIL_EVIL, MAIL_B1, "host-b-enc-1", &b);
    g.seal(
        "evil_cancel",
        "a cancel from host-evil to host-b at B's head (seq 10, host-evil's add_host)",
        f,
        MailPlain::Envelope(cancel(&task)),
        "host-b-enc-1",
    );
    let f = g.fields(
        "evil_at_head_9",
        MAIL_EVIL,
        MAIL_B1,
        "host-b-enc-1",
        &b[..3],
    );
    g.seal(
        "evil_at_head_9",
        "a cancel from host-evil to host-b signed at seq 9, before host-evil's add_host",
        f,
        MailPlain::Envelope(cancel(&task)),
        "host-b-enc-1",
    );
    let at_12 = on_b(&["M11_revoke_a", "M12_readmit_a"]);
    let f = g.fields(
        "removed_head_ahead",
        MAIL_A1,
        MAIL_B1,
        "host-b-enc-1",
        &at_12,
    );
    g.seal(
        "removed_head_ahead",
        "a cancel by host-a at generation 1, signed at the head of B + M11_revoke_a + M12_readmit_a (seq 12)",
        f,
        MailPlain::Envelope(cancel(&task)),
        "host-b-enc-1",
    );
    g.resign(
        "resigned",
        "host-evil strips the request and re-signs it as its own (sender host-evil): its signature verifies, but the seal's info binds host-a. Its verdict claims (host-evil, id), never host-a's (host-a, id): host-a's own request, judged after it, still opens (request_opens)",
        "request",
        MAIL_EVIL,
        |f| f.sender = MAIL_EVIL.host_ref(),
    );
    g.resign(
        "resigned_keeping_sender",
        "host-evil re-signs the request's body as it is (sender host-a)",
        "request",
        MAIL_EVIL,
        |_| {},
    );
    g.resign(
        "head_ahead_bad_signature",
        "head_ahead's body signed by host-b's key: host-a's at generation 1 is known, so the signature is checked before waiting",
        "head_ahead",
        MAIL_B1,
        |_| {},
    );
    let to_a = enc_kid(&g.enc_pub("host-a-enc-1")).unwrap();
    g.edit(
        "redirected_edited",
        "the request with its recipient changed to host-a (and host-a's enc_kid) after signing",
        "request",
        |v| {
            v["body"]["recipient"] =
                serde_json::json!({"host_id": "host-a", "host_trust_gen": 1, "enc_kid": to_a})
        },
    );
    let other_hash = s(g.objects["cancel"].body(), "sealed_hash").to_owned();
    g.edit(
        "tampered_sealed_hash",
        "the request with its body's sealed_hash changed (to the cancel's) after signing",
        "request",
        |v| v["body"]["sealed_hash"] = other_hash.into(),
    );
    g.edit(
        "tampered_ct",
        "the request with a byte of its ciphertext changed after signing: not the sender's copy",
        "request",
        |v| {
            let mut ct = b64u_decode(v["ct"].as_str().unwrap()).unwrap();
            ct[3] ^= 1;
            v["ct"] = b64u(&ct).into();
        },
    );
    g.edit(
        "head_ahead_tampered_ct",
        "head_ahead with a byte of its ciphertext changed after signing: a variant of a known sender's waiting object",
        "head_ahead",
        |v| {
            let mut ct = b64u_decode(v["ct"].as_str().unwrap()).unwrap();
            ct[3] ^= 1;
            v["ct"] = b64u(&ct).into();
        },
    );
    g.edit(
        "bare",
        "the request without its sealed part",
        "request",
        |v| {
            let o = v.as_object_mut().unwrap();
            o.remove("enc");
            o.remove("ct");
        },
    );

    // Results from host-b (which ran the request) to host-a, sealed to
    // host-a-enc-1.
    let ba = |g: &MailVectors, label: &str| g.fields(label, MAIL_B1, MAIL_A1, "host-a-enc-1", &b);
    let request_id = mail_id("request");
    let status = || ResultPlain::Status {
        message_id: mail_id("request"),
        recipients: vec![RecipientReceipt {
            recipient_id: mail_id("request recipient"),
            delivery: Delivery::Stored,
        }],
    };
    let f = ba(&g, "status");
    g.seal(
        "status",
        "host-b's receipt for the request: stored",
        f,
        MailPlain::Result(status()),
        "host-a-enc-1",
    );
    let f = ba(&g, "refusal");
    let refusal = ResultPlain::Refusal {
        object_id: mail_id("cancel"),
        refused: "invalid_request".into(),
    };
    g.seal(
        "refusal",
        "host-b refused the cancel envelope at check 5 or 6",
        f,
        MailPlain::Result(refusal),
        "host-a-enc-1",
    );
    let f = ba(&g, "result");
    let result = ResultPlain::Result {
        task_id: task.clone(),
        reply: mail_reply(false),
    };
    g.seal(
        "result",
        "the agent's reply to the request's task, as reply_query returns it once submitted",
        f,
        MailPlain::Result(result),
        "host-a-enc-1",
    );
    let f = g.fields("evil_status", MAIL_EVIL, MAIL_A1, "host-a-enc-1", &b);
    g.seal(
        "evil_status",
        "a status for the request from host-evil, a host of the account the outbox row didn't go to",
        f,
        MailPlain::Result(status()),
        "host-a-enc-1",
    );
    let f = g.fields(
        "status_head_ahead",
        MAIL_B1,
        MAIL_A1,
        "host-a-enc-1",
        &on_b(&["M11_revoke_a", "M12_readmit_a"]),
    );
    g.seal(
        "status_head_ahead",
        "host-b's status for the request, signed at the head of B + M11_revoke_a + M12_readmit_a (seq 12)",
        f,
        MailPlain::Result(status()),
        "host-a-enc-1",
    );
    let f = ba(&g, "dropped_reply");
    let text = jcs(&serde_json::json!({
        "kind": "result",
        "task_id": &task,
        "reply": serde_json::to_value(mail_reply(true)).unwrap(),
    }))
    .unwrap();
    g.seal_raw(
        "dropped_reply",
        "a result whose reply the host dropped (no text left); no builder seals it",
        MailKind::Result,
        f,
        text.as_bytes(),
        "host-a-enc-1",
    );

    // The verdicts. Envelopes: host-b at generation 1 with its key.
    let to_b: (MailHost, &[&str]) = (MAIL_B1, &["host-b-enc-1"]);
    let at =
        |g: &mut MailVectors,
         label: &str,
         object: &str,
         chain: &[&str],
         expect: Value,
         note: &str| { g.check(label, note, object, chain, to_b, MAIL_NOW, None, expect) };
    for (label, object) in [
        ("request_opens", "request"),
        ("cancel_opens", "cancel"),
        ("complete_opens", "complete"),
        ("request_max_opens", "request_max"),
    ] {
        at(
            &mut g,
            label,
            object,
            &b,
            mail_open("host-a"),
            "checks 1 to 6 pass",
        );
    }
    let e = g.refused_authenticated("request_over", "plaintext_too_large");
    at(
        &mut g,
        "request_over_too_large",
        "request_over",
        &b,
        e,
        "the plaintext is over the request's bound",
    );
    let e = g.refused("pin_mismatch", "pin_mismatch");
    at(
        &mut g,
        "pin_mismatch",
        "pin_mismatch",
        &b,
        e,
        "check 1: another account",
    );
    let e = g.refused_authenticated("resigned", "open_failed");
    at(
        &mut g,
        "resigned",
        "resigned",
        &b,
        e,
        "a re-signed copy: host-evil is authenticated, the seal doesn't open",
    );
    let e = g.refused("resigned_keeping_sender", "bad_signature");
    at(
        &mut g,
        "resigned_keeping_sender",
        "resigned_keeping_sender",
        &b,
        e,
        "host-evil's signature isn't host-a's",
    );
    let e = g.refused("request", "not_for_this_host");
    g.check(
        "redirected",
        "a redirected copy: host-b's request handed to host-evil",
        "request",
        &b,
        (MAIL_EVIL, &[]),
        MAIL_NOW,
        None,
        e,
    );
    let e = g.refused("redirected_edited", "bad_signature");
    g.check(
        "redirected_edited",
        "a redirected copy whose recipient was changed: the signature breaks",
        "redirected_edited",
        &b,
        (MAIL_A1, &["host-a-enc-1"]),
        MAIL_NOW,
        None,
        e,
    );
    let e = g.refused("request", "recipient_generation_not_current");
    g.check(
        "recipient_generation_not_current",
        "host-b re-verified (generation 2): mail to its generation 1 never opens",
        "request",
        &on_b(&["M11_reverify_b"]),
        (MAIL_B2, &[]),
        MAIL_NOW,
        None,
        e,
    );
    let e = g.refused("request", "stale_sender_generation");
    at(
        &mut g,
        "stale_generation",
        "request",
        &on_b(&["M11_reverify_a"]),
        e,
        "a stale generation: host-a re-verified after signing",
    );
    at(
        &mut g,
        "newer_generation_pending",
        "gen2",
        &b,
        mail_pending(MAIL_A2),
        "a newer generation, signed at a head beyond B: pending",
    );
    at(
        &mut g,
        "newer_generation_opens",
        "gen2",
        &on_b(&["M11_reverify_a"]),
        mail_open("host-a"),
        "the same object once the list has host-a's generation 2",
    );
    let e = g.refused("gen2_before_add_host", "generation_ahead");
    at(
        &mut g,
        "generation_ahead",
        "gen2_before_add_host",
        &b,
        e,
        "a generation the list doesn't hold, at a head it holds",
    );
    let e = g.refused("gen2_before_add_host", "generation_ahead");
    at(
        &mut g,
        "generation_ahead_add_host_after_head",
        "gen2_before_add_host",
        &on_b(&["M11_reverify_a"]),
        e,
        "the claimed generation's add_host (seq 11) comes after signed_at_head (seq 10)",
    );
    let e = g.refused("tampered_sealed_hash", "bad_signature");
    at(
        &mut g,
        "tampered_sealed_hash",
        "tampered_sealed_hash",
        &b,
        e,
        "a tampered sealed_hash breaks the signature",
    );
    let e = g.refused("tampered_ct", "sealed_hash_mismatch");
    at(
        &mut g,
        "tampered_ct",
        "tampered_ct",
        &b,
        e,
        "the signed sealed_hash names other bytes than the sealed part: the signature never covered them, so the copy isn't the sender's (refused unauthenticated, claiming no id; the sender's own copy still opens)",
    );
    let e = g.refused("tampered_ct", "sealed_hash_mismatch");
    g.check(
        "tampered_ct_expired",
        "the same copy at its expires_at: intact before any authenticated verdict, so still sealed_hash_mismatch, never expired",
        "tampered_ct",
        &b,
        to_b,
        MAIL_EXPIRES,
        None,
        e,
    );
    let e = g.refused("request", "signed_at_head_before_generation");
    at(
        &mut g,
        "signed_at_head_before_generation",
        "request",
        &on_b(&["M11_revoke_a", "M12_readmit_a"]),
        e,
        "signed at seq 10, before host-a's readmit (authorized(12)): refused for good",
    );
    let e = g.refused("evil_at_head_9", "signed_at_head_before_generation");
    at(
        &mut g,
        "signed_at_head_before_first_add_host",
        "evil_at_head_9",
        &b,
        e,
        "signed at seq 9, before host-evil's authorized(10)",
    );
    let e = g.refused("wrong_hash", "signed_at_head_wrong_hash");
    at(
        &mut g,
        "signed_at_head_wrong_hash",
        "wrong_hash",
        &b,
        e,
        "signed_at_head names a wrong hash",
    );
    let e = g.refused("request", "revoked_sender");
    at(
        &mut g,
        "revoked_sender",
        "request",
        &on_b(&["M11_revoke_a"]),
        e,
        "the request that opened at B, once host-a is revoked",
    );
    let e = g.refused("request", "removed_sender");
    at(
        &mut g,
        "removed_sender",
        "request",
        &on_b(&["M11_remove_a"]),
        e,
        "the request that opened at B, once host-a is removed",
    );
    let e = g.refused("removed_head_ahead", "removed_sender");
    at(
        &mut g,
        "removed_sender_head_ahead",
        "removed_head_ahead",
        &on_b(&["M11_remove_a"]),
        e,
        "a removed host at the generation it last held, signed beyond the receiver's head: refused at any head (that generation never returns)",
    );
    let e = g.refused("removed_head_ahead", "expired");
    g.check(
        "removed_sender_head_ahead_times_first",
        "the same, at its expires_at: the body's times come first",
        "removed_head_ahead",
        &on_b(&["M11_remove_a"]),
        to_b,
        MAIL_EXPIRES,
        None,
        e,
    );
    at(
        &mut g,
        "revoked_sender_head_ahead_pending",
        "removed_head_ahead",
        &on_b(&["M11_revoke_a"]),
        mail_pending(MAIL_A1),
        "a revoked host's envelope signed beyond the receiver's head waits: a readmit may be among the entries it lacks",
    );
    at(
        &mut g,
        "readmitted_sender_opens",
        "removed_head_ahead",
        &on_b(&["M11_revoke_a", "M12_readmit_a"]),
        mail_open("host-a"),
        "the same object once the list has the readmit it was signed after",
    );
    at(
        &mut g,
        "new_key_head_ahead_pending",
        "cancel_to_new_key",
        &b,
        mail_pending(MAIL_A1),
        "sealed to a key host-b handed out but hasn't applied (its host_enc_key is beyond its head): it waits",
    );
    g.check(
        "new_key_opens",
        "once host-b applies the rotation and lists the key, it opens",
        "cancel_to_new_key",
        &on_b(&["M11_rotate_b"]),
        (MAIL_B1, &["host-b-enc-2", "host-b-enc-1"]),
        MAIL_NOW,
        None,
        mail_open("host-a"),
    );
    let e = g.refused("cancel_to_new_key", "enc_key_not_accepted");
    at(
        &mut g,
        "new_key_not_listed",
        "cancel_to_new_key",
        &on_b(&["M11_rotate_b"]),
        e,
        "the rotation applied but the key not listed: this head settles it",
    );
    let e = g.refused("evil_at_head_9", "unknown_sender");
    at(
        &mut g,
        "unknown_sender",
        "evil_at_head_9",
        &b[..3],
        e,
        "no add_host names host-evil up to the receiver's head (9)",
    );
    at(
        &mut g,
        "unknown_sender_head_ahead_pending",
        "evil_cancel",
        &b[..3],
        mail_pending(MAIL_EVIL),
        "an unknown sender signed at a head beyond the receiver's: pending",
    );
    at(
        &mut g,
        "evil_cancel_opens",
        "evil_cancel",
        &b,
        mail_open("host-evil"),
        "the same object once the list has host-evil",
    );
    at(
        &mut g,
        "head_ahead_pending",
        "head_ahead",
        &b,
        mail_pending(MAIL_A1),
        "signed at a head beyond B, the signature verified first: pending",
    );
    at(
        &mut g,
        "head_ahead_opens",
        "head_ahead",
        &on_b(&["M11_rotate_a"]),
        mail_open("host-a"),
        "the same object once the list reaches its head",
    );
    let e = g.refused("head_ahead_bad_signature", "bad_signature");
    at(
        &mut g,
        "head_ahead_bad_signature",
        "head_ahead_bad_signature",
        &b,
        e,
        "beyond B, from a known generation: the signature is checked before waiting",
    );
    let e = g.refused("head_ahead_tampered_ct", "sealed_hash_mismatch");
    at(
        &mut g,
        "head_ahead_tampered_ct",
        "head_ahead_tampered_ct",
        &b,
        e,
        "beyond B, from a known generation: verified means signed and intact, so a ciphertext variant is refused, never held",
    );
    let e = g.refused_authenticated("request", "expired");
    g.check(
        "expired",
        "the request at its expires_at",
        "request",
        &b,
        to_b,
        MAIL_EXPIRES,
        None,
        e,
    );
    let e = g.refused_authenticated("request", "created_too_far_ahead");
    g.check(
        "created_too_far_ahead",
        "the request on a clock 60,001 ms behind its created_at",
        "request",
        &b,
        to_b,
        MAIL_T0 - 60_001,
        None,
        e,
    );
    let e = g.refused_authenticated("bad_times", "bad_times");
    at(
        &mut g,
        "bad_times",
        "bad_times",
        &b,
        e,
        "expires_at isn't after created_at",
    );
    let e = g.refused_authenticated("lifetime_too_long", "lifetime_too_long");
    at(
        &mut g,
        "lifetime_too_long",
        "lifetime_too_long",
        &b,
        e,
        "more than 24 h between created_at and expires_at",
    );
    let e = g.refused_authenticated("ids_mismatch", "plaintext_mismatch");
    at(
        &mut g,
        "plaintext_ids_mismatch",
        "ids_mismatch",
        &b,
        e,
        "the plaintext's ids don't match the body's",
    );
    let e = g.refused_authenticated("attachments", "attachments_not_allowed");
    at(
        &mut g,
        "attachments",
        "attachments",
        &b,
        e,
        "a host sender's Message carries no attachments",
    );
    let e = g.refused_authenticated("from_session", "invalid_message");
    at(
        &mut g,
        "invalid_message",
        "from_session",
        &b,
        e,
        "not a Message a host sender may send",
    );
    let e = g.refused_authenticated("plaintext_null", "plaintext_null");
    at(
        &mut g,
        "plaintext_null",
        "plaintext_null",
        &b,
        e,
        "a null in the plaintext",
    );
    let e = g.refused_authenticated("plaintext_not_canonical", "plaintext_malformed");
    at(
        &mut g,
        "plaintext_not_canonical",
        "plaintext_not_canonical",
        &b,
        e,
        "a plaintext that isn't its canonical form",
    );
    let e = g.refused("bare", "malformed");
    at(
        &mut g,
        "malformed",
        "bare",
        &b,
        e,
        "check 1: an envelope carries enc and ct",
    );
    let e = g.refused("status", "wrong_kind");
    g.check(
        "wrong_kind",
        "a result given to open_envelope",
        "status",
        &b,
        (MAIL_A1, &["host-a-enc-1"]),
        MAIL_NOW,
        None,
        e,
    );
    // host-a's keys: the previous one opens mail only inside its window and
    // never after a rotation with retire_previous.
    for (label, chain, keys, expect, note) in [
        (
            "cancel_to_a_opens",
            b.to_vec(),
            &["host-a-enc-1"][..],
            mail_open("host-b"),
            "sealed to host-a's current key",
        ),
        (
            "previous_key_in_window",
            on_b(&["M11_rotate_a"]),
            &["host-a-enc-2", "host-a-enc-1"][..],
            mail_open("host-b"),
            "host-a rotated; its previous key's window is open",
        ),
        (
            "previous_key_after_window",
            on_b(&["M11_rotate_a"]),
            &["host-a-enc-2"][..],
            g.refused("cancel_to_a", "enc_key_not_accepted"),
            "host-a rotated; its previous key's window has closed",
        ),
        (
            "retired_previous_key",
            on_b(&["M11_rotate_a_retire"]),
            &["host-a-enc-2"][..],
            g.refused("cancel_to_a", "enc_key_not_accepted"),
            "a retired previous key: refused at once",
        ),
    ] {
        g.check(
            label,
            note,
            "cancel_to_a",
            &chain,
            (MAIL_A1, keys),
            MAIL_NOW,
            None,
            expect,
        );
    }

    // Results: host-a's outbox row for the request went to host-b.
    let outbox = |message_id: &str| {
        serde_json::json!({
            "recipient": {"host_id": "host-b", "host_trust_gen": 1},
            "message_id": message_id,
            "cancel_complete_ids": [mail_id("cancel"), mail_id("complete")],
            "task_ids": [&task],
        })
    };
    let to_a: (MailHost, &[&str]) = (MAIL_A1, &["host-a-enc-1"]);
    let accepted = serde_json::json!({"verdict": "accepted", "sender": "host:host-b"});
    for (label, object) in [
        ("status_accepted", "status"),
        ("refusal_accepted", "refusal"),
        ("result_accepted", "result"),
    ] {
        g.check(
            label,
            "checks 1 to 6 pass and it answers the row",
            object,
            &b,
            to_a,
            MAIL_NOW,
            Some(outbox(&request_id)),
            accepted.clone(),
        );
    }
    let e = g.refused("evil_status", "not_the_recipient");
    g.check(
        "result_from_non_recipient",
        "a result from a host the row didn't go to",
        "evil_status",
        &b,
        to_a,
        MAIL_NOW,
        Some(outbox(&request_id)),
        e,
    );
    g.check(
        "removed_result_head_ahead_pending",
        "a removed host's result signed beyond the receiver's head waits (its signature checked first), to be kept as data",
        "status_head_ahead",
        &on_b(&["M11_remove_b"]),
        to_a,
        MAIL_NOW,
        Some(outbox(&request_id)),
        mail_pending(MAIL_B1),
    );
    for (label, chain, detail, note) in [
        (
            "result_sender_revoked",
            on_b(&["M11_revoke_b"]),
            "result not delivered: sender revoked",
            "host-b revoked: verified with its key, kept as data",
        ),
        (
            "result_sender_removed",
            on_b(&["M11_remove_b"]),
            "result not delivered: sender removed",
            "host-b removed: verified with its last key, kept as data",
        ),
    ] {
        let e = serde_json::json!({"verdict": "not_delivered", "sender": "host:host-b", "reason": detail});
        g.check(
            label,
            note,
            "status",
            &chain,
            to_a,
            MAIL_NOW,
            Some(outbox(&request_id)),
            e,
        );
    }
    let e = g.refused_authenticated("dropped_reply", "plaintext_malformed");
    g.check(
        "dropped_reply",
        "a dropped reply isn't a result",
        "dropped_reply",
        &b,
        to_a,
        MAIL_NOW,
        Some(outbox(&request_id)),
        e,
    );
    let e = g.refused_authenticated("status", "does_not_answer_outbox_row");
    g.check(
        "does_not_answer_outbox_row",
        "a status for another message than the row's",
        "status",
        &b,
        to_a,
        MAIL_NOW,
        Some(outbox(&mail_id("another message"))),
        e,
    );
    let e = g.refused("request", "wrong_kind");
    g.check(
        "result_wrong_kind",
        "an envelope given to accept_result",
        "request",
        &b,
        to_a,
        MAIL_NOW,
        Some(outbox(&request_id)),
        e,
    );

    serde_json::json!({
        "name": "r9-vectors-host-envelope",
        "kind": "vectors",
        "requires": "r9",
        "note": "Envelopes and results between hosts (delegated host-work II.4.2, II.4.4; host-work-v1 §11.5). Each object is {body, sig, enc, ct}: the body signed by the sender's host_key (Ed25519) over enc([\"atem-envelope-v1\" or \"atem-result-v1\", jcs(body)]); the plaintext sealed with RFC 9180 base mode, DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305, empty AAD, to the recipient's host encryption key, info = enc([\"atem-envelope-seal-v1\" or \"atem-result-seal-v1\", account_id, genesis_hash (32 bytes), sender.host_id, u64(sender.host_trust_gen), recipient.host_id, u64(recipient.host_trust_gen), enc_kid, id, u64(created_at), u64(expires_at)]); sealed_hash = SHA-256(enc([enc, ct])). The sender's ephemeral is DeriveKeyPair(ikmE), ikmE = SHA-256(enc([\"atem-r9-test-ikm\", ikm_label])). Device lists: log L of r9-vectors-membership-log followed by `chain`, labels of `entries` (signed by dev-mac); the objects are signed at B = L + M7..M10 (head 10) unless their signed_at_head says otherwise. Objects: `signed_with` names the r9-vectors-keys host key whose signature `sig` is; `built` objects are what seal_envelope / seal_result make from the body's fields, `sealed.plaintext` and ikmE; `sealed` gives the seal's inputs and outputs (`plaintext`, or `plaintext_bytes` and `plaintext_sha256` over 4 KiB); `sealed_from` names the object whose sealed part it carries, `edited_from` the object it is after a change made after signing. Checks: `call` (open_envelope, or accept_result with `outbox`, the sending host's row) on L + `chain`, by `receiver` (its host_id, current host_trust_gen and the keys it accepts, r9-vectors-keys names), at `now`; `expect` is the verdict: open or accepted (with `sender`; the plaintext is the object's), not_delivered (with `sender` and the return grant's detail as `reason`), pending (the claimed host_id and host_trust_gen), refused (before the copy is shown to be the sender's, signed and intact (step 4): `reason` and `evidence` = SHA-256(enc([jcs(body), sig, enc, ct])), enc and ct empty when absent; it claims no id) or refused_authenticated (after it: the object's id and `reason`; it claims the id for its authenticated sender, (sender.host_id, id)).",
        "account_id": "acct-test-1",
        "genesis_hash": g.genesis.to_hex(),
        "now": MAIL_NOW,
        "entries": g.entry_vectors,
        "objects": g.object_vectors,
        "checks": g.checks,
    })
}

/// A verdict as a check's `expect` writes it, and the plaintext it opened.
fn mail_verdict(verdict: EnvelopeVerdict) -> (Value, Option<Vec<u8>>) {
    match verdict {
        EnvelopeVerdict::Open { plain, sender } => (
            serde_json::json!({"verdict": "open", "sender": sender}),
            Some(plain.to_bytes().unwrap().to_vec()),
        ),
        EnvelopeVerdict::Pending {
            host_id,
            host_trust_gen,
        } => (
            serde_json::json!({"verdict": "pending", "host_id": host_id, "host_trust_gen": host_trust_gen}),
            None,
        ),
        EnvelopeVerdict::Refused { reason, evidence } => (
            serde_json::json!({"verdict": "refused", "reason": reason, "evidence": evidence.to_hex()}),
            None,
        ),
        EnvelopeVerdict::RefusedAuthenticated { object_id, reason } => (
            serde_json::json!({"verdict": "refused_authenticated", "object_id": object_id, "reason": reason}),
            None,
        ),
        EnvelopeVerdict::Unavailable { error } => panic!("unavailable: {error}"),
    }
}

/// [`mail_verdict`] for a result.
fn mail_result_verdict(verdict: ResultVerdict) -> (Value, Option<Vec<u8>>) {
    match verdict {
        ResultVerdict::Accepted { plain, sender } => (
            serde_json::json!({"verdict": "accepted", "sender": sender}),
            Some(plain.to_bytes().unwrap().to_vec()),
        ),
        ResultVerdict::NotDelivered {
            plain,
            sender,
            reason,
        } => (
            serde_json::json!({"verdict": "not_delivered", "sender": sender, "reason": reason}),
            Some(plain.to_bytes().unwrap().to_vec()),
        ),
        ResultVerdict::Pending {
            host_id,
            host_trust_gen,
        } => mail_verdict(EnvelopeVerdict::Pending {
            host_id,
            host_trust_gen,
        }),
        ResultVerdict::Refused { reason, evidence } => {
            mail_verdict(EnvelopeVerdict::Refused { reason, evidence })
        }
        ResultVerdict::RefusedAuthenticated { object_id, reason } => {
            mail_verdict(EnvelopeVerdict::RefusedAuthenticated { object_id, reason })
        }
        ResultVerdict::Unavailable { error } => panic!("unavailable: {error}"),
    }
}

#[test]
fn host_envelope() {
    let mut run = Run::new("r9-vectors-host-envelope");
    let book = Book::load();
    let made = host_envelope_vectors(&book);
    for (field, value) in made.as_object().unwrap() {
        assert_eq!(
            run.get(field),
            *value,
            "{field}: as host_envelope_vectors makes it"
        );
    }
    run.pass("the file is exactly what the shared core's builders make now");
    let file = run.file.clone();

    // The entries: each the valid next entry on L + its chain.
    let mut g = MailVectors::new(&book);
    for v in file["entries"].as_array().unwrap() {
        let label = s(v, "label");
        let entry = Entry::from_strict(&strict(&v["entry"])).unwrap();
        assert_eq!(entry.hash().to_hex(), s(v, "entry_hash"), "{label}");
        let chain: Vec<&str> = chain_labels(v);
        assert_eq!(g.list(&chain).check_next(&entry), Check::Valid, "{label}");
        g.entries.insert(label.to_owned(), entry);
    }
    run.pass("entries: each valid on L + its chain (dev-mac), entry_hash");

    // The objects: signature, seal, plaintext and bounds from their parts.
    let mut plaintexts: BTreeMap<String, Value> = BTreeMap::new();
    let objects: BTreeMap<String, &Value> = file["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| (s(v, "label").to_owned(), v))
        .collect();
    for (label, v) in &objects {
        let wire = v["object"].to_string();
        assert!(
            wire.len() <= atem_client::host_mail::MAX_MAIL_OBJECT_BYTES,
            "{label}"
        );
        let object = SignedObject::from_strict(&strict(&v["object"])).unwrap();
        assert_eq!(object.jcs(), s(v, "jcs"), "{label}");
        assert!(object.jcs().len() <= 4096, "{label}");
        assert_eq!(
            hex(object.signing_input().as_bytes()),
            s(v, "signing_input_hex")
        );
        let kind = match s(v, "kind") {
            "envelope" => MailKind::Envelope,
            _ => MailKind::Result,
        };
        assert_eq!(object.label(), kind.sign_label(), "{label}");
        if let Some(name) = v.get("signed_with").and_then(Value::as_str) {
            object.verify(&book.signer_public(name)).unwrap();
        }
        if let Some(from) = v.get("edited_from").and_then(Value::as_str) {
            assert_eq!(
                object.sig(),
                b64u_decode(s(&objects[from]["object"], "sig")).unwrap()
            );
        }
        if let Some(from) = v.get("sealed_from").and_then(Value::as_str) {
            assert_eq!(
                v["object"]["enc"], objects[from]["object"]["enc"],
                "{label}"
            );
            assert_eq!(v["object"]["ct"], objects[from]["object"]["ct"], "{label}");
        }
        let Some(sealed) = v.get("sealed") else {
            continue;
        };
        let (_, body) = MailBody::from_object(&object).unwrap();
        let fields = body.fields();
        let info = seal_info(kind, &fields);
        assert_eq!(hex(&info), s(sealed, "info_hex"), "{label}");
        let part = object.sealed().unwrap();
        assert_eq!(
            body.sealed_hash.to_hex(),
            s(sealed, "sealed_hash"),
            "{label}"
        );
        assert!(body.names(part), "{label}");
        let to = s(sealed, "to");
        assert_eq!(
            enc_kid(&book.public(&format!("{to}/enc"))).unwrap(),
            fields.enc_kid
        );
        let secret = unhex32(s(&book.keys[to]["enc"], "secret_hex"));
        let plain = hpke::open_with_secret(&secret, &part.enc, &part.ct, &info, b"").unwrap();
        match sealed.get("plaintext") {
            Some(text) => assert_eq!(&plain[..], text.as_str().unwrap().as_bytes(), "{label}"),
            None => {
                assert_eq!(
                    plain.len() as u64,
                    sealed["plaintext_bytes"].as_u64().unwrap()
                );
                assert_eq!(
                    hex(&Sha256::digest(&plain[..])),
                    s(sealed, "plaintext_sha256")
                );
            }
        }
        let ikm = mail_ikm(s(sealed, "ikm_label"));
        assert_eq!(hex(&ikm), s(sealed, "ikmE_hex"));
        let resealed = hpke::seal_with_ikm(
            book.public(&format!("{to}/enc")).as_32().unwrap(),
            &info,
            b"",
            &plain,
            &ikm,
        )
        .unwrap();
        assert_eq!(
            (resealed.enc.to_vec(), resealed.ct),
            (part.enc.clone(), part.ct.clone())
        );
        if v["built"] == true {
            // The builder makes it from its parts, byte for byte.
            let signer = KeyId::new(format!("{}/host_key", s(v, "signed_with")));
            let to = book.public(&format!("{to}/enc"));
            let rebuilt = match kind {
                MailKind::Envelope => seal_envelope_with_ikm(
                    &book.provider,
                    &signer,
                    &fields,
                    &EnvelopePlain::parse(&plain).unwrap(),
                    &to,
                    &ikm,
                ),
                MailKind::Result => seal_result_with_ikm(
                    &book.provider,
                    &signer,
                    &fields,
                    &ResultPlain::parse(&plain).unwrap(),
                    &to,
                    &ikm,
                ),
            }
            .unwrap();
            assert_eq!(rebuilt, object, "{label}");
        }
        plaintexts.insert(label.clone(), Value::from(hex(&plain)));
    }
    run.pass(format!(
        "objects ({}): jcs, signing input, signatures, info, sealed_hash, open, the seal from ikmE, builders reproduce the built ones",
        objects.len()
    ));

    // Every check, through the receiver's checks.
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for c in file["checks"].as_array().unwrap() {
        let label = s(c, "label");
        let list = g.list(&chain_labels(c));
        let receiver = &c["receiver"];
        let me = MailRecipient {
            host_id: s(receiver, "host_id").into(),
            host_trust_gen: receiver["host_trust_gen"].as_u64().unwrap(),
            keys: receiver["keys"]
                .as_array()
                .unwrap()
                .iter()
                .map(|k| {
                    let name = k.as_str().unwrap();
                    let key = book.public(&format!("{name}/enc"));
                    (
                        KeyId::new(format!("{name}/enc")),
                        atem_client::keys::enc_kid_bytes(&key).unwrap(),
                    )
                })
                .collect(),
        };
        let object_label = s(c, "object");
        let object = SignedObject::from_strict(&strict(&objects[object_label]["object"])).unwrap();
        let now = c["now"].as_u64().unwrap();
        let (got, plain) = match s(c, "call") {
            "open_envelope" => {
                mail_verdict(open_envelope(&object, &list, &me, &book.provider, now))
            }
            "accept_result" => {
                let o = &c["outbox"];
                let strs = |k: &str| -> Vec<String> {
                    o[k].as_array()
                        .unwrap()
                        .iter()
                        .map(|x| x.as_str().unwrap().to_owned())
                        .collect()
                };
                let outbox = ExpectedResult {
                    recipient: HostRef {
                        host_id: s(&o["recipient"], "host_id").into(),
                        host_trust_gen: o["recipient"]["host_trust_gen"].as_u64().unwrap(),
                    },
                    message_id: s(o, "message_id").into(),
                    cancel_complete_ids: strs("cancel_complete_ids"),
                    task_ids: strs("task_ids"),
                };
                mail_result_verdict(accept_result(
                    &object,
                    &list,
                    &me,
                    &outbox,
                    &book.provider,
                    now,
                ))
            }
            other => panic!("{other}"),
        };
        assert_eq!(got, c["expect"], "{label}");
        if let Some(plain) = plain {
            assert_eq!(
                Value::from(hex(&plain)),
                plaintexts[object_label],
                "{label}"
            );
        }
        *counts
            .entry(s(&c["expect"], "verdict").to_owned())
            .or_default() += 1;
    }
    run.pass(format!(
        "checks: every verdict as open_envelope / accept_result give it ({counts:?})"
    ));

    // Every reason the receiver's checks name has a check.
    let reasons: BTreeSet<&str> = file["checks"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["expect"].get("reason").and_then(Value::as_str))
        .collect();
    for reason in atem_client::host_mail::receive::reason::ALL {
        assert!(reasons.contains(reason), "no check refuses for {reason}");
    }
    run.pass("every reason of host_mail::receive has a check");
    run.finish();
}

/// Writes `r9-vectors-host-envelope` from `host_envelope_vectors`.
#[test]
#[ignore = "writes the host-envelope vectors"]
fn write_host_envelope_vectors() {
    let book = Book::load();
    let mut text = serde_json::to_string_pretty(&host_envelope_vectors(&book)).unwrap();
    text.push('\n');
    std::fs::write(fixtures_dir().join("r9-vectors-host-envelope.json"), text).unwrap();
}

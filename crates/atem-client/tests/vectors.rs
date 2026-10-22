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
use atem_client::domain::{SignLabel, SigningInput};
use atem_client::encoding::{Hash32, b64u, b64u_decode, enc, hex, u64_field};
use atem_client::hpke;
use atem_client::keys::{Alg, PublicKey, ed25519_public_to_x25519, enc_kid};
use atem_client::kit::{self, RecoveryKit};
use atem_client::membership::{
    Check, Entry, Head, HostNow, Invalid, Member, MemberKind, Membership, RECOVERY_WAIT_MS,
    RecoveryState, Role, Stop,
};
use atem_client::principal::{Authority, BrowserGrant, Need, Op, Refusal as PrincipalRefusal};
use atem_client::provider::sign;
use atem_client::push::{
    self, Accepted, Hint, HintBook, HintPlain, HintState, Refusal as PushRefusal, RelayLedger,
    Seen, Stage, Verdict, Verifier,
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
            "r9-vectors-encoding.json",
            "r9-vectors-host-route.json",
            "r9-vectors-keys.json",
            "r9-vectors-membership-log.json",
            "r9-vectors-pairing.json",
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
        ("recovery/R", "recovery kit R"),
        ("not-recovery/", "not the recovery key"),
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
    run.finish();
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
    run.finish();
}

//! `designs/protocol/fixtures/r9-vectors-verifier-report.json`: a member's
//! signed verifier report (`atem_client::member_report`; session-v1 R9.2
//! "How a verifier reports itself", agreed for implementation on Astation
//! #101): challenges read strictly, reports verified against log L of
//! `r9-vectors-membership-log` and this file's `entries`, the builder's
//! outcomes and the immutable request's signatures.
//!
//! `write_verifier_report_vectors` (ignored) writes the file from
//! `verifier_report_vectors`, which builds every case and checks each
//! outcome written here by hand against the shared core, and adds the
//! Ed25519 native's key (`dev-desk`) to `r9-vectors-keys`. The other
//! tests read the file: that it is what the generator makes now, and that
//! every case comes out as it says. `scripts/check-r9-vectors.py` checks
//! the same file independently; the FFI's `tests/verifier_report.rs` and
//! the Swift, Kotlin and WASM suites run it through the bindings.
mod support;

use std::collections::BTreeSet;

use atem_client::canonical::{self, jcs};
use atem_client::domain::{SignLabel, SigningInput};
use atem_client::encoding::{Hash32, b64u, enc, hex};
use atem_client::member_report::{
    ReportChallenge, SignerKind, process_generation, sign_verifier_report, verifier_report_body,
    verify_verifier_report,
};
use atem_client::membership::{
    Action, HostNow, HostRecord, Member, MemberKind, Membership, Role, VerifierInventory,
    sign_entry,
};
use atem_client::provider::sign;
use atem_client::{KeyId, KeyProvider, PublicKey, SignedObject, SoftwareKeys};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use support::{Book, Vectors, fixtures_dir, load, strict};

const FILE: &str = "r9-vectors-verifier-report";

const NOTE: &str = "A member's signed verifier report (session-v1 R9.2 \"How a verifier reports itself\"; agreed for implementation on Astation #101, comment 7082464613): wire {\"body\":{…},\"sig\"}, the body {type: atem-verifier-report, v: 1, account_id, genesis_hash, head{seq, hash}, signer, slot, process, challenge{origin, connection, nonce, issued_at, expires_at}, verifier{version, actions}} signed by the signer's own key over enc([\"atem-verifier-report-v1\", jcs(body)]) (R9.1): a current native member's auth_key (signer member:<device_id>) or a current, unexpired service's own key (service:<device_id>), under the alg the device list pins. A challenge is what the minter issues and stores, {signer, slot, origin, connection, nonce, issued_at, expires_at}: signer member:<id> or service:<id>, slot and ids 1-128 bytes of [A-Za-z0-9._:-], origin exact as station_route::normalize_relay writes it, connection 1 to 2^53-1, nonce 32 bytes and process 16 bytes (base64url, no padding), 0 < expires_at - issued_at <= 30000 ms; a challenge text is at most 4,096 bytes; the body's jcs at most 4,096 bytes and the object at most 16 KiB; no null, no kit_sig, no field beyond these at any level, no duplicate key (escaped ones included). Device lists: log L of r9-vectors-membership-log followed by `chain` (labels of `entries`, signed by dev-mac), then the carriage `freeze` (a label of r9-vectors-membership-log's others) when a case names one, which freezes it; each list verified at the case's now_ms. Keys are r9-vectors-keys' (`signed_with` names <name>/<part>: auth, host_key, or recovery/sign for the kit's recovery key); dev-desk is the Ed25519 native the chain adds. `challenges`: texts read by ReportChallenge::parse (bindings parse_verifier_report_challenge): `fields` when read, else `code`. `valid` and `invalid`: verify_verifier_report(list, report, the stored challenge `challenge`, now_ms): `expect` is the VerifiedReport (kind native or service, process base64url, at_head true at the list's head, false at an ancestor), or `code`, the first failure in the order malformed, frozen, wrong_account, unknown_signer, signer_expired, bad_signature, stale_log, fork, signer_mismatch, slot_mismatch, challenge_mismatch, expired (bindings: Report{code}). A report's process is the fixed bytes \"vectors-process!\"; a builder draws its own once per loaded core (process_generation). `builder`: verifier_report_body(list, challenge, signer, slot, station, now_ms): `body_but_process` (the body it builds, but its process, which is the loaded core's), or `code` (origin_mismatch when the challenge's origin isn't station normalized). `request`: the immutable request (bindings VerifierReportRequest): built as a builder case, its sign_request (`purpose`, `fresh_confirmation`, `label`; input = enc([label, jcs(body)]), body_json = jcs(body)), then each `finishes` entry signs with `signed_with` the input of the held body (`over: held`) or of a request for the same challenge with another `slot` (`over: {slot}`), and finish gives the report, byte-equal to {\"body\":<held body>,\"sig\":<the signature, low S>}, or `code`.";

const STATION: &str = "https://station-dev.agora.build";
const SLOT: &str = "astation-ios";
const SVC_SLOT: &str = "discord-bot";
const PHONE: &str = "member:dev-phone";
const MAC: &str = "member:dev-mac";
const DESK: &str = "member:dev-desk";
const SVC: &str = "service:svc-discord";
/// Every case's clock but the expiries': after L and its chain.
const NOW: u64 = 1_793_264_001_000;
const ISSUED: u64 = 1_793_264_000_000;
/// A full lease: 30 s.
const EXPIRES: u64 = ISSUED + 30_000;
/// svc-discord's `expires_at` (E5).
const SVC_EXPIRES: u64 = 1_794_992_004_000;
/// Every report's process generation in the vectors.
const PROCESS: &[u8; 16] = b"vectors-process!";
/// The dev-desk keys' labels (`schema.md`'s test keys).
const DESK_AUTH: &str = "dev-desk auth";
const DESK_ENC: &str = "dev-desk enc";

/// SHA-256(enc(["atem-r9-test-key", label])) (`schema.md`).
fn test_key(label: &str) -> [u8; 32] {
    Sha256::digest(enc(&[b"atem-r9-test-key", label.as_bytes()])).into()
}

fn nonce(first: u8) -> [u8; 32] {
    std::array::from_fn(|i| first + i as u8)
}

/// What the generator builds with: the book, dev-desk's keys, log L and
/// the chain's entries.
struct Gen {
    v: Vectors,
    keys: SoftwareKeys,
    /// The chain after L: (label, note, entry object).
    entries: Vec<(&'static str, &'static str, SignedObject)>,
}

impl Gen {
    fn new() -> Gen {
        let v = Vectors::load();
        let mut keys = Book::load().provider;
        keys.insert_ed25519(KeyId::new("dev-desk/auth"), &test_key(DESK_AUTH));
        keys.insert_x25519(KeyId::new("dev-desk/enc"), &test_key(DESK_ENC));
        let mut made = Gen {
            v,
            keys,
            entries: Vec::new(),
        };
        let desk = Action::Add {
            member: Member {
                device_id: "dev-desk".into(),
                auth_key: made.public("dev-desk/auth"),
                kind: MemberKind::Native {
                    enc_key: made.public("dev-desk/enc"),
                    roles: [Role::Control, Role::View].into_iter().collect(),
                },
            },
        };
        made.push(
            "VR7_add_desk",
            "add dev-desk, a native member with an Ed25519 auth_key, on E6, by dev-mac",
            1_792_400_006_000,
            desk,
        );
        let host_b = Action::AddHost {
            host: HostRecord {
                host_id: "host-b".into(),
                host_trust_gen: 1,
                host_key: made.public("host-b/host_key"),
            },
        };
        made.push(
            "VR8_add_host_b",
            "add_host host-b on VR7_add_desk, by dev-mac: a head after VR7_add_desk",
            1_792_400_007_000,
            host_b,
        );
        made
    }

    fn public(&self, id: &str) -> PublicKey {
        self.keys.public_key(&KeyId::new(id)).unwrap()
    }

    fn push(&mut self, label: &'static str, note: &'static str, at: u64, action: Action) {
        let labels: Vec<&str> = self.entries.iter().map(|(l, _, _)| *l).collect();
        let log = self.log(&labels, None, NOW);
        let body = log.draft("dev-mac", at, &action);
        let entry = sign_entry(&self.keys, &KeyId::new("dev-mac/auth"), body).unwrap();
        self.entries.push((label, note, entry.object().clone()));
    }

    /// L, then `chain`, then the carriage `freeze`, verified at `now_ms`.
    fn log(&self, chain: &[&str], freeze: Option<&str>, now_ms: u64) -> Membership {
        log_of(&self.v, &self.entry_objects(chain), freeze, now_ms)
    }

    fn entry_objects(&self, chain: &[&str]) -> Vec<SignedObject> {
        chain
            .iter()
            .map(|label| {
                self.entries
                    .iter()
                    .find(|(l, _, _)| l == label)
                    .unwrap_or_else(|| panic!("no entry {label}"))
                    .2
                    .clone()
            })
            .collect()
    }

    fn entries_json(&self) -> Vec<Value> {
        self.entries
            .iter()
            .map(|(label, note, object)| {
                json!({
                    "label": label,
                    "note": note,
                    "entry": object.to_json(),
                    "entry_hash": object.entry_hash().unwrap().to_hex(),
                })
            })
            .collect()
    }
}

fn host_now(now_ms: u64) -> HostNow {
    HostNow {
        wall_ms: now_ms,
        mono_ms: 1_000,
        boot_id: "boot-1".into(),
    }
}

/// L of `v`, then `chain`, then the carriage `freeze` (a label of the
/// membership-log vectors), verified at `now_ms`.
fn log_of(v: &Vectors, chain: &[SignedObject], freeze: Option<&str>, now_ms: u64) -> Membership {
    let now = host_now(now_ms);
    let l = v.entries(&["E1", "E2", "E3", "E4", "E5", "E6"]);
    let mut log = Membership::verify_chain(support::ACCOUNT, &v.hash("E1"), &l, &now)
        .unwrap()
        .membership;
    if !chain.is_empty() {
        let eval = log.evaluate_objects(chain, &now);
        assert!(eval.stop.is_none(), "the chain applies: {:?}", eval.stop);
        log = eval.next;
    }
    if let Some(label) = freeze {
        log = log.evaluate(&[strict(v.wire(label))], &now).next;
        assert!(log.frozen().is_some(), "{label} freezes the list");
    }
    log
}

/// The challenge a minter stores, as an object.
fn challenge(signer: &str, slot: &str, connection: u64, nonce: [u8; 32]) -> Value {
    json!({"signer": signer, "slot": slot, "origin": STATION, "connection": connection,
           "nonce": b64u(&nonce), "issued_at": ISSUED, "expires_at": EXPIRES})
}

fn with(mut value: Value, field: &str, to: Value) -> Value {
    value[field] = to;
    value
}

fn read_challenge(value: &Value) -> ReportChallenge {
    ReportChallenge::parse(value.to_string().as_bytes()).unwrap()
}

/// The body a reporter at `log`'s head signs for `challenge`, with the
/// vectors' process and `verifier`.
fn body_of(log: &Membership, challenge: &Value, verifier: Value) -> Value {
    json!({
        "type": "atem-verifier-report",
        "v": 1,
        "account_id": log.account_id(),
        "genesis_hash": log.genesis_hash().to_hex(),
        "head": log.head().to_json(),
        "signer": challenge["signer"],
        "slot": challenge["slot"],
        "process": b64u(PROCESS),
        "challenge": {
            "origin": challenge["origin"],
            "connection": challenge["connection"],
            "nonce": challenge["nonce"],
            "issued_at": challenge["issued_at"],
            "expires_at": challenge["expires_at"],
        },
        "verifier": verifier,
    })
}

fn ours() -> Value {
    VerifierInventory::ours().to_json()
}

/// `{"body":<jcs(body)>,"sig":…}` signed by `key` under `label` (the
/// report's own, or another to show it never verifies): no check of the
/// body, so a malformed one is signed too.
fn signed_as(keys: &SoftwareKeys, key: &str, label: SignLabel, body: &Value) -> String {
    let text = jcs(body).unwrap();
    let sig = sign(
        keys,
        &KeyId::new(key),
        &SigningInput::new(label, text.as_bytes()),
    )
    .unwrap();
    format!(r#"{{"body":{text},"sig":"{}"}}"#, b64u(&sig))
}

fn signed(keys: &SoftwareKeys, key: &str, body: &Value) -> String {
    signed_as(keys, key, SignLabel::VerifierReport, body)
}

/// `body` changed by `edit`.
fn edit(body: &Value, f: impl FnOnce(&mut Value)) -> Value {
    let mut body = body.clone();
    f(&mut body);
    body
}

/// What a case expects of the core.
#[derive(Debug, Clone)]
enum Want {
    /// A verified report: its kind and whether at the list's head.
    Verified { kind: SignerKind, at_head: bool },
    /// A refusal's code.
    Code(&'static str),
}

struct Report {
    label: &'static str,
    note: &'static str,
    chain: &'static [&'static str],
    freeze: Option<&'static str>,
    challenge: Value,
    now_ms: u64,
    text: String,
    /// The key that signed it, for a valid case.
    signed_with: Option<&'static str>,
    want: Want,
}

const NO_CHAIN: &[&str] = &[];
const VR7: &[&str] = &["VR7_add_desk"];
const VR8: &[&str] = &["VR7_add_desk", "VR8_add_host_b"];

impl Gen {
    fn report(
        &self,
        label: &'static str,
        note: &'static str,
        chain: &'static [&'static str],
        challenge: Value,
        text: String,
        want: Want,
    ) -> Report {
        Report {
            label,
            note,
            chain,
            freeze: None,
            challenge,
            now_ms: NOW,
            text,
            signed_with: None,
            want,
        }
    }

    /// The valid reports.
    fn valid(&self) -> Vec<Report> {
        let l = self.log(NO_CHAIN, None, NOW);
        let l7 = self.log(VR7, None, NOW);
        let phone = challenge(PHONE, SLOT, 3, nonce(0));
        let phone_text = signed(&self.keys, "dev-phone/auth", &body_of(&l, &phone, ours()));
        let desk = challenge(DESK, SLOT, 2, nonce(0));
        let desk_text = signed(&self.keys, "dev-desk/auth", &body_of(&l7, &desk, ours()));
        let svc = challenge(SVC, SVC_SLOT, 1, nonce(0));
        let later = {
            let mut actions: Vec<String> = VerifierInventory::ours().actions().to_vec();
            actions.push("zz_later_action".into());
            json!({"version": 3, "actions": actions})
        };
        let short = with(phone.clone(), "expires_at", json!(ISSUED + 1));
        let native = |at_head| Want::Verified {
            kind: SignerKind::Native,
            at_head,
        };
        let mut out = vec![
            self.report(
                "native_p256_at_head",
                "dev-phone (P-256) at L's head",
                NO_CHAIN,
                phone.clone(),
                phone_text.clone(),
                native(true),
            ),
            self.report(
                "native_p256_at_ancestor",
                "the same report, verified at L + VR7_add_desk: signed at an ancestor",
                VR7,
                phone.clone(),
                phone_text,
                native(false),
            ),
            self.report(
                "native_ed25519_at_head",
                "dev-desk (Ed25519) at L + VR7_add_desk's head",
                VR7,
                desk.clone(),
                desk_text.clone(),
                native(true),
            ),
            self.report(
                "native_ed25519_at_ancestor",
                "the same report, verified at L + VR7_add_desk + VR8_add_host_b",
                VR8,
                desk,
                desk_text,
                native(false),
            ),
            self.report(
                "service_at_head",
                "svc-discord (a service, Ed25519) with its own key, before its expires_at",
                NO_CHAIN,
                svc.clone(),
                signed(&self.keys, "svc-discord/auth", &body_of(&l, &svc, ours())),
                Want::Verified {
                    kind: SignerKind::Service,
                    at_head: true,
                },
            ),
            self.report(
                "inventory_names_a_later_action",
                "a verifier of version 3 that knows an action this release doesn't: read for its shape only, kept",
                NO_CHAIN,
                phone.clone(),
                signed(&self.keys, "dev-phone/auth", &body_of(&l, &phone, later)),
                native(true),
            ),
            self.report(
                "lease_of_one_millisecond",
                "issued_at + 1 = expires_at, verified at issued_at",
                NO_CHAIN,
                short.clone(),
                signed(&self.keys, "dev-phone/auth", &body_of(&l, &short, ours())),
                native(true),
            ),
        ];
        let signers = [
            "dev-phone/auth",
            "dev-phone/auth",
            "dev-desk/auth",
            "dev-desk/auth",
            "svc-discord/auth",
            "dev-phone/auth",
            "dev-phone/auth",
        ];
        for (case, key) in out.iter_mut().zip(signers) {
            case.signed_with = Some(key);
        }
        out[6].now_ms = ISSUED;
        out
    }

    /// The reports refused, malformed ones first.
    fn invalid(&self) -> Vec<Report> {
        let keys = &self.keys;
        let l = self.log(NO_CHAIN, None, NOW);
        let l7 = self.log(VR7, None, NOW);
        let phone = challenge(PHONE, SLOT, 3, nonce(0));
        let good = body_of(&l, &phone, ours());
        let good_text = signed(keys, "dev-phone/auth", &good);
        let resign = |f: &dyn Fn(&mut Value)| signed(keys, "dev-phone/auth", &edit(&good, f));
        let m = |label, note, text: String| {
            self.report(
                label,
                note,
                NO_CHAIN,
                phone.clone(),
                text,
                Want::Code("malformed"),
            )
        };
        let in_body = |from: &str, to: &str| good_text.replacen(from, to, 1);
        let mut out = vec![
            m(
                "duplicate_key_beside_body",
                "sig twice",
                good_text.replacen(r#","sig":"#, r#","sig":"AA","sig":"#, 1),
            ),
            m(
                "duplicate_key_in_body",
                "slot twice, the first another's",
                in_body(r#""slot":"#, r#""slot":"astation-mac","slot":"#),
            ),
            m(
                "duplicate_key_escaped",
                "slot twice, the first spelled with an escape",
                in_body(r#""slot":"#, r#""\u0073lot":"astation-mac","slot":"#),
            ),
            m(
                "duplicate_key_in_challenge",
                "nonce twice in the body's challenge",
                in_body(r#""nonce":"#, r#""nonce":"AA","nonce":"#),
            ),
            m(
                "unknown_field_beside_body",
                "a third field beside body and sig",
                good_text.replacen(r#"{"body":"#, r#"{"note":"x","body":"#, 1),
            ),
            m(
                "unknown_field_in_body",
                "the body with a field beyond its ten, signed",
                resign(&|b| b["note"] = json!("x")),
            ),
            m(
                "unknown_field_in_head",
                "head with a field beyond seq and hash, signed",
                resign(&|b| b["head"]["note"] = json!("x")),
            ),
            m(
                "unknown_field_in_challenge",
                "the body's challenge with a field beyond its five (signer and slot sit at the top, not in it), signed",
                resign(&|b| b["challenge"]["signer"] = json!(PHONE)),
            ),
            m(
                "unknown_field_in_verifier",
                "verifier with a field beyond version and actions, signed",
                resign(&|b| b["verifier"]["note"] = json!("x")),
            ),
            m(
                "null_slot",
                "slot null, signed",
                resign(&|b| b["slot"] = Value::Null),
            ),
            m(
                "null_in_challenge",
                "the challenge's nonce null, signed",
                resign(&|b| b["challenge"]["nonce"] = Value::Null),
            ),
            m(
                "missing_process",
                "no process, signed",
                resign(&|b| {
                    b.as_object_mut().unwrap().remove("process");
                }),
            ),
            m(
                "missing_challenge_field",
                "the challenge without connection, signed",
                resign(&|b| {
                    b["challenge"].as_object_mut().unwrap().remove("connection");
                }),
            ),
            m(
                "missing_sig",
                "the body alone",
                format!(r#"{{"body":{}}}"#, jcs(&good).unwrap()),
            ),
            m(
                "kit_sig_beside_body",
                "a kit_sig beside a report",
                good_text.replacen(r#"{"body":"#, r#"{"kit_sig":"AA","body":"#, 1),
            ),
        ];
        for (label, origin) in [
            ("origin_upper_case", "https://Station-dev.agora.build"),
            ("origin_trailing_slash", "https://station-dev.agora.build/"),
            ("origin_default_port", "https://station-dev.agora.build:443"),
            ("origin_path", "https://station-dev.agora.build/v1"),
            ("origin_userinfo", "https://user@station-dev.agora.build"),
            ("origin_http", "http://station-dev.agora.build"),
        ] {
            out.push(m(
                label,
                "a non-canonical origin, signed (the expected challenge is the canonical one)",
                resign(&|b| b["challenge"]["origin"] = json!(origin)),
            ));
        }
        let mut long_actions: Vec<String> = (0..64)
            .map(|i| format!("a{i:02}{}", "x".repeat(29)))
            .collect();
        long_actions.sort();
        let fields: [(&'static str, &'static str, Value); 30] = [
            ("nonce_31_bytes", "challenge.nonce", json!(b64u(&[0u8; 31]))),
            ("nonce_33_bytes", "challenge.nonce", json!(b64u(&[0u8; 33]))),
            (
                "nonce_padded",
                "challenge.nonce",
                json!(format!("{}=", b64u(&nonce(0)))),
            ),
            (
                "nonce_standard_base64",
                "challenge.nonce",
                json!("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh+/"),
            ),
            ("slot_empty", "slot", json!("")),
            ("slot_129_bytes", "slot", json!("s".repeat(129))),
            ("slot_space", "slot", json!("astation ios")),
            ("process_15_bytes", "process", json!(b64u(&[1u8; 15]))),
            ("process_17_bytes", "process", json!(b64u(&[1u8; 17]))),
            (
                "process_not_base64url",
                "process",
                json!("vectors process!"),
            ),
            ("lease_zero", "challenge.expires_at", json!(ISSUED)),
            ("lease_negative", "challenge.expires_at", json!(ISSUED - 1)),
            (
                "lease_over_30_seconds",
                "challenge.expires_at",
                json!(ISSUED + 30_001),
            ),
            ("connection_zero", "challenge.connection", json!(0)),
            ("connection_negative", "challenge.connection", json!(-1)),
            ("connection_text", "challenge.connection", json!("3")),
            ("connection_true", "challenge.connection", json!(true)),
            ("issued_at_negative", "challenge.issued_at", json!(-1)),
            ("inventory_version_zero", "verifier.version", json!(0)),
            (
                "inventory_version_over_u32",
                "verifier.version",
                json!(1u64 << 32),
            ),
            (
                "inventory_bad_action_name",
                "verifier.actions",
                json!(["Add", "remove"]),
            ),
            ("inventory_no_actions", "verifier.actions", json!([])),
            (
                "inventory_65_actions",
                "verifier.actions",
                json!((0..65).map(|i| format!("a{i:02}")).collect::<Vec<_>>()),
            ),
            ("signer_without_prefix", "signer", json!("dev-phone")),
            ("signer_unknown_prefix", "signer", json!("device:dev-phone")),
            ("signer_empty_id", "signer", json!("member:")),
            ("head_seq_zero", "head.seq", json!(0)),
            (
                "head_hash_upper_case",
                "head.hash",
                json!(l.head().hash.to_hex().to_uppercase()),
            ),
            (
                "genesis_hash_upper_case",
                "genesis_hash",
                json!(l.genesis_hash().to_hex().to_uppercase()),
            ),
            ("account_id_129_bytes", "account_id", json!("a".repeat(129))),
        ];
        for (label, path, value) in fields {
            let text = resign(&|b| {
                let mut at = &mut *b;
                for part in path.split('.') {
                    at = &mut at[part];
                }
                *at = value.clone();
            });
            out.push(m(label, "one field outside its grammar, signed", text));
        }
        out.extend([
            m(
                "inventory_unsorted",
                "actions out of byte order (signed)",
                resign(&|b| b["verifier"]["actions"] = json!(["remove", "add"])),
            ),
            m(
                "inventory_duplicate_action",
                "an action twice (signed)",
                resign(&|b| b["verifier"]["actions"] = json!(["add", "add"])),
            ),
            m(
                "array_elsewhere",
                "slot as an array (signed)",
                resign(&|b| b["slot"] = json!([SLOT])),
            ),
            m(
                "fraction",
                "connection 3.5 (strict I-JSON: integers only)",
                in_body(r#""connection":3"#, r#""connection":3.5"#),
            ),
            m(
                "unsafe_integer",
                "connection 2^53, beyond the safe integers",
                in_body(r#""connection":3"#, r#""connection":9007199254740992"#),
            ),
            m("v_2", "v 2 (signed)", resign(&|b| b["v"] = json!(2))),
            m(
                "type_of_another_kind",
                "the body typed atem-host-route and signed under its label",
                signed_as(
                    keys,
                    "dev-phone/auth",
                    SignLabel::HostRoute,
                    &edit(&good, |b| b["type"] = json!("atem-host-route")),
                ),
            ),
            m(
                "unknown_type",
                "the body typed atem-verifier-report-2",
                resign(&|b| b["type"] = json!("atem-verifier-report-2")),
            ),
            m("not_an_object", "an array", format!("[{good_text}]")),
            m(
                "sig_not_base64url",
                "sig with a character outside base64url",
                good_text.replacen(r#""sig":""#, r#""sig":"*"#, 1),
            ),
            m(
                "object_over_16_kib",
                "whitespace after the body: the object as received over 16 KiB",
                good_text.replacen(
                    r#","sig":"#,
                    &format!("{},\"sig\":", " ".repeat(16 * 1024)),
                    1,
                ),
            ),
        ]);
        // Over 4,096 bytes of jcs with every field in its grammar: the
        // longest account_id, slot, signer and origin and 64 actions of 32
        // bytes each. The same body with fewer actions reads (its account
        // isn't L's: wrong_account), so the size is all that's wrong.
        let host: Vec<String> = (0..15)
            .map(|_| "h".repeat(63))
            .chain(["h".repeat(55)])
            .collect();
        let long_origin = format!("https://{}", host.join("."));
        assert_eq!(long_origin.len(), 1023);
        let long = |actions: &[String]| {
            edit(&good, |b| {
                b["account_id"] = json!("a".repeat(128));
                b["slot"] = json!("s".repeat(128));
                b["signer"] = json!(format!("service:{}", "d".repeat(128)));
                b["challenge"]["origin"] = json!(long_origin);
                b["verifier"]["actions"] = json!(actions);
            })
        };
        let big = long(&long_actions);
        assert!(
            jcs(&big).unwrap().len() > 4096,
            "{}",
            jcs(&big).unwrap().len()
        );
        let small = long(&long_actions[..40]);
        assert!(jcs(&small).unwrap().len() <= 4096);
        assert_eq!(
            verify_verifier_report(
                &l,
                signed(keys, "dev-phone/auth", &small).as_bytes(),
                &read_challenge(&phone),
                NOW
            )
            .map(|_| ()),
            Err(atem_client::member_report::ReportRefusal::WrongAccount)
        );
        out.push(m(
            "body_over_4096_bytes",
            "every field in its grammar (the longest account_id, slot, signer and origin, 64 actions of 32 bytes): its jcs over 4,096 bytes",
            signed(keys, "dev-phone/auth", &big),
        ));

        // Refused after reading, in the verifier's order.
        let r = |label, note, text: String, code| {
            self.report(label, note, NO_CHAIN, phone.clone(), text, Want::Code(code))
        };
        let as_signer = |signer: &str, key: &str| {
            signed(keys, key, &edit(&good, |b| b["signer"] = json!(signer)))
        };
        let mut frozen = r(
            "frozen",
            "a valid report, the list frozen by C6_mac",
            good_text.clone(),
            "frozen",
        );
        frozen.freeze = Some("C6_mac");
        let mut frozen_other = r(
            "frozen_before_wrong_account",
            "another account's report against a frozen list: frozen first",
            resign(&|b| b["account_id"] = json!("acct-other")),
            "frozen",
        );
        frozen_other.freeze = Some("C6_mac");
        out.extend([
            frozen,
            frozen_other,
            r(
                "wrong_account",
                "account_id acct-other, signed",
                resign(&|b| b["account_id"] = json!("acct-other")),
                "wrong_account",
            ),
            r(
                "wrong_genesis",
                "another genesis_hash (SUB1's), signed",
                resign(&|b| b["genesis_hash"] = json!(self.v.hash("SUB1").to_hex())),
                "wrong_account",
            ),
            r(
                "unknown_member",
                "member:dev-evil, never a member, with its own key",
                as_signer("member:dev-evil", "dev-evil/auth"),
                "unknown_signer",
            ),
            r(
                "removed_member",
                "member:dev-ipad, removed by E6, with its own key",
                as_signer("member:dev-ipad", "dev-ipad/auth"),
                "unknown_signer",
            ),
            r(
                "recovery",
                "member:recovery, with the current kit's recovery key",
                as_signer("member:recovery", "recovery/sign"),
                "unknown_signer",
            ),
            r(
                "host",
                "host:host-a, with its host_channel_key",
                as_signer("host:host-a", "host-a/host_key"),
                "unknown_signer",
            ),
            r(
                "browser_grant",
                "browser:grant-1, with the browser's key",
                as_signer("browser:grant-1", "browser/auth"),
                "unknown_signer",
            ),
            r(
                "service_as_member",
                "member:svc-discord: a service named as a native member, with its key",
                as_signer("member:svc-discord", "svc-discord/auth"),
                "unknown_signer",
            ),
            r(
                "native_as_service",
                "service:dev-phone: a native named as a service, with its key",
                as_signer("service:dev-phone", "dev-phone/auth"),
                "unknown_signer",
            ),
            r(
                "another_members_key",
                "dev-phone's report signed by dev-mac's key",
                signed(keys, "dev-mac/auth", &good),
                "bad_signature",
            ),
            r(
                "tampered_after_signing",
                "the slot changed after signing (the expected challenge names the new slot)",
                good_text.replacen(r#""slot":"astation-ios""#, r#""slot":"astation-mac""#, 1),
                "bad_signature",
            ),
        ]);
        let tampered = out.last_mut().unwrap();
        tampered.challenge = with(phone.clone(), "slot", json!("astation-mac"));
        for (label, other) in [
            ("signed_under_route_label", SignLabel::HostRoute),
            ("signed_under_proxy_route_label", SignLabel::HostRouteProxy),
            ("signed_under_sig_c_label", SignLabel::ChannelClient),
            ("signed_under_control_label", SignLabel::HostWorkControl),
            ("signed_under_entry_label", SignLabel::MembershipEntry),
        ] {
            out.push(r(
                label,
                "the report's body signed by dev-phone under another label",
                signed_as(keys, "dev-phone/auth", other, &good),
                "bad_signature",
            ));
        }
        let mut expired_svc = self.report(
            "service_expired",
            "svc-discord's report verified at its expires_at",
            NO_CHAIN,
            with(
                with(
                    challenge(SVC, SVC_SLOT, 1, nonce(0)),
                    "issued_at",
                    json!(SVC_EXPIRES - 1_000),
                ),
                "expires_at",
                json!(SVC_EXPIRES + 20_000),
            ),
            String::new(),
            Want::Code("signer_expired"),
        );
        expired_svc.text = signed(
            keys,
            "svc-discord/auth",
            &body_of(&l, &expired_svc.challenge, ours()),
        );
        expired_svc.now_ms = SVC_EXPIRES;
        out.push(expired_svc);
        // Heads: beyond the verifier's, and on its chain at another hash.
        out.push(r(
            "stale_log",
            "dev-phone at L + VR7_add_desk's head, verified at L",
            signed(keys, "dev-phone/auth", &body_of(&l7, &phone, ours())),
            "stale_log",
        ));
        out.push(r(
            "fork",
            "head seq 6 at C6_ipad's hash (a sibling of E6)",
            resign(&|b| b["head"]["hash"] = json!(self.v.hash("C6_ipad").to_hex())),
            "fork",
        ));
        out.push(r(
            "fork_earlier_seq",
            "head seq 5 at E6's hash",
            resign(&|b| b["head"] = json!({"seq": 5, "hash": self.v.hash("E6").to_hex()})),
            "fork",
        ));
        // Substitution: a valid report by B against A's expectation, and for
        // slot X against slot Y.
        let mac = challenge(MAC, SLOT, 3, nonce(0));
        let by_mac = signed(keys, "dev-mac/auth", &body_of(&l, &mac, ours()));
        out.push(r(
            "signer_mismatch",
            "a valid report by dev-mac, against the expectation for dev-phone",
            by_mac,
            "signer_mismatch",
        ));
        let slot_x = with(phone.clone(), "slot", json!("astation-mac"));
        out.push(r(
            "slot_mismatch",
            "a valid report of dev-phone for slot astation-mac, against the expectation for astation-ios",
            signed(keys, "dev-phone/auth", &body_of(&l, &slot_x, ours())),
            "slot_mismatch",
        ));
        for (label, field, value) in [
            (
                "origin_mismatch",
                "origin",
                json!("https://station.agora.build"),
            ),
            ("connection_mismatch", "connection", json!(4)),
            ("nonce_mismatch", "nonce", json!(b64u(&nonce(32)))),
            ("issued_at_mismatch", "issued_at", json!(ISSUED + 1)),
            ("expires_at_mismatch", "expires_at", json!(EXPIRES - 1)),
        ] {
            let mut case = r(
                label,
                "a valid report against a stored challenge one field of which differs",
                good_text.clone(),
                "challenge_mismatch",
            );
            case.challenge = with(phone.clone(), field, value);
            out.push(case);
        }
        let mut at_expiry = r(
            "expired_at_expires_at",
            "a valid report verified at its expires_at exactly",
            good_text.clone(),
            "expired",
        );
        at_expiry.now_ms = EXPIRES;
        out.push(at_expiry);
        let mut after = r(
            "expired_after",
            "a valid report verified after its expires_at",
            good_text,
            "expired",
        );
        after.now_ms = EXPIRES + 1;
        out.push(after);
        out
    }
}

/// A challenge text and what the reader makes of it.
struct ChallengeCase {
    label: &'static str,
    text: String,
    read: bool,
}

fn challenge_cases() -> Vec<ChallengeCase> {
    let good = challenge(PHONE, SLOT, 3, nonce(0));
    let text = |v: &Value| v.to_string();
    let ok = |label, value: Value| ChallengeCase {
        label,
        text: text(&value),
        read: true,
    };
    let bad = |label, value: String| ChallengeCase {
        label,
        text: value,
        read: false,
    };
    let compact = text(&good);
    let mut out = vec![
        ok("member", good.clone()),
        ok("service", challenge(SVC, SVC_SLOT, 1, nonce(0))),
        ok(
            "lease_one_millisecond",
            with(good.clone(), "expires_at", json!(ISSUED + 1)),
        ),
        ok(
            "largest_connection",
            with(
                good.clone(),
                "connection",
                json!(canonical::MAX_SAFE_INTEGER),
            ),
        ),
        ok(
            "loopback_http_origin",
            with(good.clone(), "origin", json!("http://127.0.0.1:8080")),
        ),
        ok(
            "slot_128_bytes",
            with(good.clone(), "slot", json!("s".repeat(128))),
        ),
        bad(
            "duplicate_key",
            compact.replacen('{', r#"{"slot":"astation-mac","#, 1),
        ),
        bad(
            "duplicate_key_escaped",
            compact.replacen('{', r#"{"\u0073lot":"astation-mac","#, 1),
        ),
        bad(
            "unknown_field",
            text(&with(good.clone(), "note", json!("x"))),
        ),
        bad("null", text(&with(good.clone(), "slot", Value::Null))),
        bad("not_an_object", format!("[{compact}]")),
        bad(
            "over_4096_bytes",
            compact.replacen(',', &format!("{},", " ".repeat(4096)), 1),
        ),
    ];
    for field in [
        "signer",
        "slot",
        "origin",
        "connection",
        "nonce",
        "issued_at",
        "expires_at",
    ] {
        let mut missing = good.clone();
        missing.as_object_mut().unwrap().remove(field);
        out.push(ChallengeCase {
            label: Box::leak(format!("missing_{field}").into_boxed_str()),
            text: text(&missing),
            read: false,
        });
    }
    for (label, field, value) in [
        ("signer_host", "signer", json!("host:host-a")),
        ("signer_browser", "signer", json!("browser:grant-1")),
        ("signer_without_prefix", "signer", json!("dev-phone")),
        ("slot_empty", "slot", json!("")),
        ("slot_129_bytes", "slot", json!("s".repeat(129))),
        (
            "origin_upper_case",
            "origin",
            json!("https://Station-dev.agora.build"),
        ),
        (
            "origin_trailing_slash",
            "origin",
            json!("https://station-dev.agora.build/"),
        ),
        (
            "origin_default_port",
            "origin",
            json!("https://station-dev.agora.build:443"),
        ),
        (
            "origin_path",
            "origin",
            json!("https://station-dev.agora.build/v1"),
        ),
        (
            "origin_userinfo",
            "origin",
            json!("https://user@station-dev.agora.build"),
        ),
        (
            "origin_http",
            "origin",
            json!("http://station-dev.agora.build"),
        ),
        ("connection_zero", "connection", json!(0)),
        ("nonce_31_bytes", "nonce", json!(b64u(&[0u8; 31]))),
        ("lease_zero", "expires_at", json!(ISSUED)),
        ("lease_negative", "expires_at", json!(ISSUED - 1)),
        (
            "lease_over_30_seconds",
            "expires_at",
            json!(ISSUED + 30_001),
        ),
        ("issued_at_text", "issued_at", json!("1793264000000")),
    ] {
        out.push(bad(label, text(&with(good.clone(), field, value))));
    }
    out.push(bad(
        "unsafe_connection",
        compact.replacen(r#""connection":3"#, r#""connection":9007199254740992"#, 1),
    ));
    out.push(bad(
        "fraction",
        compact.replacen(r#""connection":3"#, r#""connection":3.0"#, 1),
    ));
    out
}

/// A builder case: its inputs and the refusal's code, if refused.
struct BuildCase {
    label: &'static str,
    note: &'static str,
    chain: &'static [&'static str],
    freeze: Option<&'static str>,
    challenge: Value,
    signer: &'static str,
    slot: &'static str,
    station: &'static str,
    now_ms: u64,
    code: Option<&'static str>,
}

fn build_cases() -> Vec<BuildCase> {
    let phone = challenge(PHONE, SLOT, 3, nonce(0));
    let case = |label, note, signer, slot, station, code| BuildCase {
        label,
        note,
        chain: NO_CHAIN,
        freeze: None,
        challenge: phone.clone(),
        signer,
        slot,
        station,
        now_ms: NOW,
        code,
    };
    let mut out = vec![
        case(
            "native",
            "dev-phone answers its challenge",
            PHONE,
            SLOT,
            STATION,
            None,
        ),
        case(
            "station_normalized",
            "the configured Station as written, normalized to the challenge's origin",
            PHONE,
            SLOT,
            "https://Station-Dev.agora.build/",
            None,
        ),
        case(
            "another_station",
            "a challenge minted for another Station than the configured one",
            PHONE,
            SLOT,
            "https://station.agora.build",
            Some("origin_mismatch"),
        ),
        case(
            "another_port",
            "the configured Station on another port",
            PHONE,
            SLOT,
            "https://station-dev.agora.build:8443",
            Some("origin_mismatch"),
        ),
        case(
            "station_not_an_origin",
            "a configured Station normalize_relay refuses",
            PHONE,
            SLOT,
            "ftp://station-dev.agora.build",
            Some("malformed"),
        ),
        case(
            "another_signer",
            "the challenge names dev-mac; the reporter is dev-phone",
            PHONE,
            SLOT,
            STATION,
            Some("signer_mismatch"),
        ),
        case(
            "another_slot",
            "the challenge names astation-ios; the reporter's slot is astation-mac",
            PHONE,
            "astation-mac",
            STATION,
            Some("slot_mismatch"),
        ),
        case(
            "signer_host",
            "a host never reports",
            "host:host-a",
            SLOT,
            STATION,
            Some("malformed"),
        ),
        case(
            "slot_empty",
            "an empty slot",
            PHONE,
            "",
            STATION,
            Some("malformed"),
        ),
    ];
    out[5].challenge = challenge(MAC, SLOT, 3, nonce(0));
    let mut frozen = case(
        "frozen",
        "the reporter's list frozen by C6_mac",
        PHONE,
        SLOT,
        STATION,
        Some("frozen"),
    );
    frozen.freeze = Some("C6_mac");
    out.push(frozen);
    let mut removed = case(
        "removed_member",
        "dev-ipad, removed by E6, answers a challenge for itself",
        "member:dev-ipad",
        SLOT,
        STATION,
        Some("unknown_signer"),
    );
    removed.challenge = challenge("member:dev-ipad", SLOT, 3, nonce(0));
    out.push(removed);
    let mut svc = case(
        "service",
        "svc-discord with its own key",
        SVC,
        SVC_SLOT,
        STATION,
        None,
    );
    svc.challenge = challenge(SVC, SVC_SLOT, 1, nonce(0));
    out.push(svc);
    let mut desk = case(
        "native_ed25519",
        "dev-desk at L + VR7_add_desk",
        DESK,
        SLOT,
        STATION,
        None,
    );
    desk.chain = VR7;
    desk.challenge = challenge(DESK, SLOT, 2, nonce(0));
    out.push(desk);
    let mut expired_svc = case(
        "service_expired",
        "svc-discord at its expires_at",
        SVC,
        SVC_SLOT,
        STATION,
        Some("signer_expired"),
    );
    expired_svc.challenge = with(
        with(
            challenge(SVC, SVC_SLOT, 1, nonce(0)),
            "issued_at",
            json!(SVC_EXPIRES - 1_000),
        ),
        "expires_at",
        json!(SVC_EXPIRES + 20_000),
    );
    expired_svc.now_ms = SVC_EXPIRES;
    out.push(expired_svc);
    let mut expired = case(
        "challenge_expired",
        "the challenge at its expires_at on the reporter's clock",
        PHONE,
        SLOT,
        STATION,
        Some("expired"),
    );
    expired.now_ms = EXPIRES;
    out.push(expired);
    out
}

/// The immutable request: a builder case and its finishes
/// `(label, signed_with, other slot (None: the held body), code)`.
struct RequestCase {
    build: BuildCase,
    key: &'static str,
    finishes: Vec<(
        &'static str,
        &'static str,
        Option<&'static str>,
        Option<&'static str>,
    )>,
}

fn request_cases() -> Vec<RequestCase> {
    let builds = build_cases();
    let take = |label: &str| {
        builds
            .iter()
            .find(|c| c.label == label)
            .map(|c| BuildCase {
                label: c.label,
                note: c.note,
                chain: c.chain,
                freeze: c.freeze,
                challenge: c.challenge.clone(),
                signer: c.signer,
                slot: c.slot,
                station: c.station,
                now_ms: c.now_ms,
                code: c.code,
            })
            .unwrap()
    };
    vec![
        RequestCase {
            build: take("native"),
            key: "dev-phone/auth",
            finishes: vec![
                ("held_by_its_signer", "dev-phone/auth", None, None),
                (
                    "another_body",
                    "dev-phone/auth",
                    Some("astation-mac"),
                    Some("bad_signature"),
                ),
                (
                    "another_member",
                    "dev-mac/auth",
                    None,
                    Some("bad_signature"),
                ),
            ],
        },
        RequestCase {
            build: take("native_ed25519"),
            key: "dev-desk/auth",
            finishes: vec![
                ("held_by_its_signer", "dev-desk/auth", None, None),
                (
                    "another_body",
                    "dev-desk/auth",
                    Some("astation-mac"),
                    Some("bad_signature"),
                ),
                (
                    "another_member",
                    "dev-phone/auth",
                    None,
                    Some("bad_signature"),
                ),
            ],
        },
        RequestCase {
            build: take("service"),
            key: "svc-discord/auth",
            finishes: vec![
                ("held_by_its_signer", "svc-discord/auth", None, None),
                (
                    "another_body",
                    "svc-discord/auth",
                    Some("discord-bot-2"),
                    Some("bad_signature"),
                ),
                (
                    "another_member",
                    "dev-phone/auth",
                    None,
                    Some("bad_signature"),
                ),
            ],
        },
    ]
}

/// A builder's body as JSON, but its process.
fn but_process(body: &Value) -> Value {
    let mut body = body.clone();
    body.as_object_mut().unwrap().remove("process");
    body
}

fn verified_json(v: &atem_client::member_report::VerifiedReport) -> Value {
    json!({
        "signer": v.signer,
        "kind": match v.kind {
            SignerKind::Native => "native",
            SignerKind::Service => "service",
        },
        "slot": v.slot,
        "process": b64u(&v.process),
        "connection": v.connection,
        "head": v.head.to_json(),
        "at_head": v.at_head,
        "inventory": v.inventory.to_json(),
        "expires_at": v.expires_at,
    })
}

fn opt(map: &mut Map<String, Value>, key: &str, value: Option<Value>) {
    if let Some(value) = value {
        map.insert(key.into(), value);
    }
}

/// The file: every case's outcome checked against the shared core.
fn verifier_report_vectors() -> Value {
    let made = Gen::new();
    let challenges: Vec<Value> = challenge_cases()
        .into_iter()
        .map(|case| {
            let read = ReportChallenge::parse(case.text.as_bytes());
            match (&read, case.read) {
                (Ok(c), true) => {
                    json!({"label": case.label, "text": case.text, "fields": c.to_json()})
                }
                (Err(e), false) => {
                    json!({"label": case.label, "text": case.text, "code": e.code()})
                }
                _ => panic!("{}: {read:?}", case.label),
            }
        })
        .collect();
    let report = |case: Report| {
        let log = made.log(case.chain, case.freeze, case.now_ms);
        let got = verify_verifier_report(
            &log,
            case.text.as_bytes(),
            &read_challenge(&case.challenge),
            case.now_ms,
        );
        let mut out = Map::new();
        out.insert("label".into(), json!(case.label));
        out.insert("note".into(), json!(case.note));
        out.insert("chain".into(), json!(case.chain));
        opt(&mut out, "freeze", case.freeze.map(|f| json!(f)));
        out.insert("challenge".into(), case.challenge.clone());
        out.insert("now_ms".into(), json!(case.now_ms));
        out.insert("report".into(), json!(case.text));
        match (case.want, got) {
            (Want::Verified { kind, at_head }, Ok(v)) => {
                assert_eq!((v.kind, v.at_head), (kind, at_head), "{}", case.label);
                assert_eq!(v.process, *PROCESS);
                let object = SignedObject::parse(case.text.as_bytes()).unwrap();
                out.insert("jcs".into(), json!(object.jcs()));
                out.insert(
                    "signing_input_hex".into(),
                    json!(hex(object.signing_input().as_bytes())),
                );
                opt(&mut out, "signed_with", case.signed_with.map(|k| json!(k)));
                out.insert("expect".into(), verified_json(&v));
            }
            (Want::Code(code), Err(e)) => {
                assert_eq!(e.code(), code, "{}: {e}", case.label);
                out.insert("code".into(), json!(code));
            }
            (want, got) => panic!("{}: {want:?} written here, {got:?} given", case.label),
        }
        Value::Object(out)
    };
    let valid: Vec<Value> = made.valid().into_iter().map(report).collect();
    let invalid: Vec<Value> = made.invalid().into_iter().map(report).collect();
    let build = |case: &BuildCase| {
        let log = made.log(case.chain, case.freeze, case.now_ms);
        let got = verifier_report_body(
            &log,
            &read_challenge(&case.challenge),
            case.signer,
            case.slot,
            case.station,
            case.now_ms,
        );
        let mut out = Map::new();
        out.insert("label".into(), json!(case.label));
        out.insert("note".into(), json!(case.note));
        out.insert("chain".into(), json!(case.chain));
        opt(&mut out, "freeze", case.freeze.map(|f| json!(f)));
        out.insert("challenge".into(), case.challenge.clone());
        out.insert("signer".into(), json!(case.signer));
        out.insert("slot".into(), json!(case.slot));
        out.insert("station".into(), json!(case.station));
        out.insert("now_ms".into(), json!(case.now_ms));
        match (case.code, got) {
            (None, Ok(body)) => {
                let json = body.to_json();
                assert_eq!(json["process"], json!(b64u(&process_generation())));
                assert_eq!(
                    but_process(&json),
                    but_process(&body_of(&log, &case.challenge, ours())),
                    "{}",
                    case.label
                );
                out.insert("body_but_process".into(), but_process(&json));
                (Value::Object(out), Some(body))
            }
            (Some(code), Err(e)) => {
                assert_eq!(e.code(), code, "{}: {e}", case.label);
                out.insert("code".into(), json!(code));
                (Value::Object(out), None)
            }
            (want, got) => panic!("{}: {want:?} written here, {got:?} given", case.label),
        }
    };
    let builder: Vec<Value> = build_cases().iter().map(|c| build(c).0).collect();
    let request: Vec<Value> = request_cases()
        .into_iter()
        .map(|case| {
            let (mut out, body) = build(&case.build);
            let body = body.unwrap();
            let held = sign_verifier_report(&made.keys, &KeyId::new(case.key), &body).unwrap();
            assert_eq!(held.jcs(), body.jcs());
            let finishes: Vec<Value> = case
                .finishes
                .iter()
                .map(|(label, key, other_slot, code)| {
                    let input = match other_slot {
                        None => body.signing_input(),
                        Some(slot) => {
                            let log = made.log(case.build.chain, None, case.build.now_ms);
                            let other = with(case.build.challenge.clone(), "slot", json!(slot));
                            verifier_report_body(
                                &log,
                                &read_challenge(&other),
                                case.build.signer,
                                slot,
                                case.build.station,
                                case.build.now_ms,
                            )
                            .unwrap()
                            .signing_input()
                        }
                    };
                    let sig = sign(&made.keys, &KeyId::new(*key), &input).unwrap();
                    match (code, body.with_signature(&sig)) {
                        (None, Ok(report)) => {
                            let text = jcs(&report.to_json()).unwrap();
                            assert_eq!(
                                text,
                                format!(r#"{{"body":{},"sig":"{}"}}"#, body.jcs(), b64u(&sig))
                            );
                        }
                        (Some(code), Err(e)) => assert_eq!(e.code(), *code, "{label}"),
                        (want, got) => panic!("{label}: {want:?} written here, {got:?} given"),
                    }
                    let mut f = Map::new();
                    f.insert("label".into(), json!(label));
                    f.insert("signed_with".into(), json!(key));
                    f.insert(
                        "over".into(),
                        other_slot.map_or(json!("held"), |slot| json!({"slot": slot})),
                    );
                    opt(&mut f, "code", code.map(|c| json!(c)));
                    Value::Object(f)
                })
                .collect();
            out["key"] = json!(case.key);
            out["sign_request"] = json!({
                "purpose": "verifier_report",
                "fresh_confirmation": false,
                "label": "atem-verifier-report-v1",
            });
            out["finishes"] = json!(finishes);
            out
        })
        .collect();
    json!({
        "name": FILE,
        "kind": "vectors",
        "requires": "r9",
        "note": NOTE,
        "entries": made.entries_json(),
        "challenges": challenges,
        "valid": valid,
        "invalid": invalid,
        "builder": builder,
        "request": request,
    })
}

/// dev-desk's entry in `r9-vectors-keys`.
fn desk_key_entry() -> Value {
    let mut keys = SoftwareKeys::new();
    keys.insert_ed25519(KeyId::new("auth"), &test_key(DESK_AUTH));
    keys.insert_x25519(KeyId::new("enc"), &test_key(DESK_ENC));
    let public = |id: &str| hex(keys.public_key(&KeyId::new(id)).unwrap().as_bytes());
    json!({
        "auth": {"alg": "ed25519", "pub_hex": public("auth"), "secret_hex": hex(&test_key(DESK_AUTH))},
        "enc": {"pub_hex": public("enc"), "secret_hex": hex(&test_key(DESK_ENC))},
        "note": format!("a native member with an Ed25519 auth_key, which r9-vectors-verifier-report's chain adds (labels \"{DESK_AUTH}\" and \"{DESK_ENC}\")"),
    })
}

/// Writes the file from `verifier_report_vectors`, and dev-desk's keys
/// into `r9-vectors-keys` (text insertion before host-a, so nothing else in
/// it moves).
#[test]
#[ignore = "writes the verifier-report vectors"]
fn write_verifier_report_vectors() {
    let path = fixtures_dir().join("r9-vectors-keys.json");
    let mut text = std::fs::read_to_string(&path).unwrap();
    let anchor = "    \"host-a\": {\n";
    let start = "    \"dev-desk\": {\n";
    if let Some(at) = text.find(start) {
        let end = text.find(anchor).unwrap();
        text.replace_range(at..end, "");
    }
    let pretty = serde_json::to_string_pretty(&json!({"dev-desk": desk_key_entry()})).unwrap();
    let lines: Vec<&str> = pretty.lines().collect();
    let mut block = String::new();
    for line in &lines[1..lines.len() - 1] {
        block.push_str("  ");
        block.push_str(line);
        block.push('\n');
    }
    block.pop();
    block.push_str(",\n");
    let at = text.find(anchor).unwrap();
    text.insert_str(at, &block);
    let parsed: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(parsed["keys"]["dev-desk"], desk_key_entry());
    std::fs::write(&path, text).unwrap();

    let mut text = serde_json::to_string_pretty(&verifier_report_vectors()).unwrap();
    text.push('\n');
    std::fs::write(fixtures_dir().join(format!("{FILE}.json")), text).unwrap();
}

#[test]
fn verifier_report_file_is_what_the_generator_makes() {
    let file = load(FILE);
    assert_eq!(
        file.as_object().unwrap().keys().collect::<Vec<_>>(),
        [
            "builder",
            "challenges",
            "entries",
            "invalid",
            "kind",
            "name",
            "note",
            "request",
            "requires",
            "valid"
        ]
    );
    assert_eq!(
        load("r9-vectors-keys")["keys"]["dev-desk"],
        desk_key_entry()
    );
    assert_eq!(
        file,
        verifier_report_vectors(),
        "regenerate with write_verifier_report_vectors"
    );
}

/// L, then the file's `chain` entries, then `freeze`, at `now_ms`.
fn case_log(v: &Vectors, file: &Value, case: &Value) -> Membership {
    let chain: Vec<SignedObject> = case["chain"]
        .as_array()
        .unwrap()
        .iter()
        .map(|label| {
            let entry = file["entries"]
                .as_array()
                .unwrap()
                .iter()
                .find(|e| e["label"] == *label)
                .unwrap();
            SignedObject::from_strict(&strict(&entry["entry"])).unwrap()
        })
        .collect();
    log_of(
        v,
        &chain,
        case.get("freeze").and_then(Value::as_str),
        case["now_ms"].as_u64().unwrap(),
    )
}

/// Every case as the file says, read from the file: the challenges, the
/// reports' verdicts, the builder's bodies and refusals, and the request's
/// finishes. The cases cover every verifier code and the builder's.
#[test]
fn verifier_report_vectors_run_through_the_shared_core() {
    let (file, v, book) = (load(FILE), Vectors::load(), Book::load());
    for case in file["challenges"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let read = ReportChallenge::parse(case["text"].as_str().unwrap().as_bytes());
        match case.get("fields") {
            Some(fields) => assert_eq!(&read.unwrap().to_json(), fields, "{label}"),
            None => assert_eq!(
                read.map(|_| ()).map_err(|e| e.code()),
                Err("malformed"),
                "{label}"
            ),
        }
    }
    let mut codes = BTreeSet::new();
    for case in file["valid"]
        .as_array()
        .unwrap()
        .iter()
        .chain(file["invalid"].as_array().unwrap())
    {
        let label = case["label"].as_str().unwrap();
        let log = case_log(&v, &file, case);
        let got = verify_verifier_report(
            &log,
            case["report"].as_str().unwrap().as_bytes(),
            &read_challenge(&case["challenge"]),
            case["now_ms"].as_u64().unwrap(),
        );
        match case.get("expect") {
            Some(expect) => {
                assert_eq!(&verified_json(&got.unwrap()), expect, "{label}");
                let object =
                    SignedObject::parse(case["report"].as_str().unwrap().as_bytes()).unwrap();
                assert_eq!(object.jcs(), case["jcs"].as_str().unwrap());
                assert_eq!(
                    hex(object.signing_input().as_bytes()),
                    case["signing_input_hex"].as_str().unwrap()
                );
                let key = book.public(case["signed_with"].as_str().unwrap());
                object.verify(&key).unwrap();
            }
            None => {
                let code = case["code"].as_str().unwrap();
                assert_eq!(got.map(|_| ()).map_err(|e| e.code()), Err(code), "{label}");
                codes.insert(code.to_owned());
            }
        }
    }
    assert_eq!(
        codes,
        atem_client::member_report::VERIFY_ORDER
            .iter()
            .map(|c| c.to_string())
            .collect(),
        "every verifier code has a vector"
    );
    let mut build_codes = BTreeSet::new();
    for case in file["builder"]
        .as_array()
        .unwrap()
        .iter()
        .chain(file["request"].as_array().unwrap())
    {
        let label = case["label"].as_str().unwrap();
        let log = case_log(&v, &file, case);
        let got = verifier_report_body(
            &log,
            &read_challenge(&case["challenge"]),
            case["signer"].as_str().unwrap(),
            case["slot"].as_str().unwrap(),
            case["station"].as_str().unwrap(),
            case["now_ms"].as_u64().unwrap(),
        );
        match case.get("body_but_process") {
            Some(want) => {
                let body = got.unwrap();
                assert_eq!(&but_process(&body.to_json()), want, "{label}");
                assert_eq!(body.process(), process_generation());
            }
            None => {
                let code = case["code"].as_str().unwrap();
                assert_eq!(got.map(|_| ()).map_err(|e| e.code()), Err(code), "{label}");
                build_codes.insert(code.to_owned());
            }
        }
    }
    for code in [
        "frozen",
        "origin_mismatch",
        "signer_mismatch",
        "slot_mismatch",
        "unknown_signer",
        "signer_expired",
        "expired",
        "malformed",
    ] {
        assert!(build_codes.contains(code), "the builder's {code}");
    }
}

/// The request's finishes, read from the file: the held body takes only
/// its signer's signature over itself, and the report is that body with
/// the signature, byte for byte.
#[test]
fn the_immutable_request_takes_only_a_signature_over_its_held_body() {
    let (file, v) = (load(FILE), Vectors::load());
    let mut keys = Book::load().provider;
    // dev-desk, from the keys file as the bindings load it.
    let desk = &load("r9-vectors-keys")["keys"]["dev-desk"]["auth"];
    keys.insert_ed25519(
        KeyId::new("dev-desk/auth"),
        &Hash32::from_hex(desk["secret_hex"].as_str().unwrap())
            .unwrap()
            .0,
    );
    for case in file["request"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        assert_eq!(
            case["sign_request"]["label"],
            SignLabel::VerifierReport.as_str()
        );
        let log = case_log(&v, &file, case);
        let build = |challenge: &Value, slot: &str| {
            verifier_report_body(
                &log,
                &read_challenge(challenge),
                case["signer"].as_str().unwrap(),
                slot,
                case["station"].as_str().unwrap(),
                case["now_ms"].as_u64().unwrap(),
            )
            .unwrap()
        };
        let held = build(&case["challenge"], case["slot"].as_str().unwrap());
        let mut finished = 0;
        for f in case["finishes"].as_array().unwrap() {
            let input = match f["over"].as_str() {
                Some("held") => held.signing_input(),
                _ => {
                    let slot = f["over"]["slot"].as_str().unwrap();
                    build(&with(case["challenge"].clone(), "slot", json!(slot)), slot)
                        .signing_input()
                }
            };
            let key = KeyId::new(f["signed_with"].as_str().unwrap());
            let sig = sign(&keys, &key, &input).unwrap();
            match f.get("code") {
                None => {
                    let report = held.with_signature(&sig).unwrap();
                    assert_eq!(
                        jcs(&report.to_json()).unwrap(),
                        format!(r#"{{"body":{},"sig":"{}"}}"#, held.jcs(), b64u(&sig))
                    );
                    finished += 1;
                }
                Some(code) => assert_eq!(
                    held.with_signature(&sig).map(|_| ()).map_err(|e| e.code()),
                    Err(code.as_str().unwrap()),
                    "{label}: {}",
                    f["label"]
                ),
            }
        }
        assert_eq!(finished, 1, "{label}");
    }
}

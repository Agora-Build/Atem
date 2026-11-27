//! `r9-vectors-station-binding` through the production exports (a native
//! manager's Station binding proof, delegated host-work III.5 (b)):
//! Astation's examples through the encoding exports, the challenge reader
//! and minter, `verify_station_binding` with `Report{code}`, the immutable
//! `StationBindingRequest` (its body, sign request and finishes) and the
//! synchronous `sign_station_binding` through an app provider. The core's
//! runner is `crates/atem-client/tests/station_binding.rs`.
// The provider-taking calls are the UniFFI layer's (default feature).
#![cfg(feature = "uniffi")]

#[path = "../../atem-client/tests/support/mod.rs"]
#[allow(unused_imports)]
mod support;

use std::sync::{Arc, Mutex};

use atem_client::KeyProvider as _;
use atem_client::encoding::{b64u, b64u_decode, enc};
use atem_client::provider::KeyId;
use atem_client_ffi::AtemError;
use atem_client_ffi::encoding::{canonical_json, signing_input, verify_signature};
use atem_client_ffi::log::MembershipLog;
use atem_client_ffi::provider::{AppKeyProvider, ProviderError};
use atem_client_ffi::station_binding::{
    StationBindingRequest, parse_station_binding_challenge, sign_station_binding,
    station_binding_challenge, verify_station_binding,
};
use atem_client_ffi::types::{
    AuthClaims, BindingAction, ExpectedBinding, HostClock, KeyAlg, LogHead, PublicKeyData,
    SignLabelKind, SignRequest, SigningPurpose, StationBindingChallenge, VerifiedStationBinding,
};
use serde_json::{Value, json};
use support::*;

fn file() -> Value {
    serde_json::from_str(include_str!(
        "../../../designs/protocol/fixtures/r9-vectors-station-binding.json"
    ))
    .unwrap()
}

fn clock(now_ms: u64) -> HostClock {
    HostClock {
        wall_ms: now_ms,
        mono_ms: 1_000,
        boot_id: "boot-1".into(),
    }
}

/// L, the case's chain (the file's entries), then its `freeze` carriage,
/// as an app builds its log.
fn log_of(file: &Value, case: &Value) -> Arc<MembershipLog> {
    let v = Vectors::load();
    let now = clock(case["now_ms"].as_u64().unwrap());
    let mut entries: Vec<String> = ["E1", "E2", "E3", "E4", "E5", "E6"]
        .iter()
        .map(|l| v.object(l).to_json().to_string())
        .collect();
    for label in case["chain"].as_array().unwrap() {
        let entry = file["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["label"] == *label)
            .unwrap();
        entries.push(entry["entry"].to_string());
    }
    let log =
        MembershipLog::verify(ACCOUNT.into(), v.hash("E1").to_hex(), entries, now.clone()).unwrap();
    if let Some(label) = case.get("freeze").and_then(Value::as_str) {
        log.extend(vec![v.wire(label).to_string()], now).unwrap();
        assert!(log.frozen().is_some());
    }
    log
}

fn report_code(code: &str) -> impl Fn(&AtemError) -> bool + '_ {
    move |e| matches!(e, AtemError::Report { code: c, .. } if c == code)
}

fn action_name(a: BindingAction) -> &'static str {
    match a {
        BindingAction::Bind => "bind",
        BindingAction::Transfer => "transfer",
        BindingAction::Unbind => "unbind",
    }
}

fn expected_json(e: &ExpectedBinding) -> Value {
    let record = |state: &str, binding_id: &str, version: u64, owner: &str| json!({"state": state, "binding_id": binding_id, "version": version, "owner": owner});
    match e {
        ExpectedBinding::NeverBound => json!({"state": "never_bound"}),
        ExpectedBinding::Bound {
            binding_id,
            version,
            owner,
        } => record("bound", binding_id, *version, owner),
        ExpectedBinding::Unbound {
            binding_id,
            version,
            owner,
        } => record("unbound", binding_id, *version, owner),
        ExpectedBinding::Released {
            binding_id,
            version,
            owner,
        } => record("released", binding_id, *version, owner),
    }
}

fn challenge_json(c: &StationBindingChallenge) -> Value {
    json!({
        "type": "atem-station-binding",
        "v": 1,
        "action": action_name(c.action),
        "origin": c.origin,
        "issuer": c.issuer,
        "subject": c.subject,
        "auth_time": c.auth_time,
        "account_id": c.account_id,
        "genesis_hash": c.genesis_hash,
        "head": {"seq": c.head.seq, "hash": c.head.hash},
        "signer": c.signer,
        "expected_binding": expected_json(&c.expected_binding),
        "nonce": c.nonce,
        "issued_at": c.issued_at,
        "expires_at": c.expires_at,
    })
}

fn verified_json(v: &VerifiedStationBinding) -> Value {
    json!({
        "action": action_name(v.action),
        "signer": v.signer,
        "head": {"seq": v.head.seq, "hash": v.head.hash},
        "at_head": v.at_head,
        "account_id": v.account_id,
        "genesis_hash": v.genesis_hash,
        "issuer": v.issuer,
        "subject": v.subject,
        "auth_time": v.auth_time,
        "expected_binding": expected_json(&v.expected_binding),
        "nonce": v.nonce,
        "expires_at": v.expires_at,
    })
}

fn claims(value: &Value) -> AuthClaims {
    AuthClaims {
        issuer: value["issuer"].as_str().unwrap().into(),
        subject: value["subject"].as_str().unwrap().into(),
        auth_time: value["auth_time"].as_u64().unwrap(),
    }
}

/// The test book's keys as an app provider that records every request;
/// `cancel` declines every signature, as an owner who cancels the prompt.
struct Keys {
    book: Book,
    requests: Mutex<Vec<SignRequest>>,
    cancel: bool,
}

impl Keys {
    fn new(cancel: bool) -> Arc<Self> {
        Arc::new(Keys {
            book: Book::load(),
            requests: Mutex::new(Vec::new()),
            cancel,
        })
    }

    /// A signature by `key` over `input` (a binding's signing input).
    fn sign_input(&self, key: &str, input: &[u8]) -> Vec<u8> {
        let fields = atem_client::encoding::dec(input).unwrap();
        assert_eq!(fields[0], b"atem-station-binding-v1");
        let input =
            atem_client::SigningInput::new(atem_client::SignLabel::StationBinding, fields[1]);
        atem_client::provider::sign(&self.book.provider, &KeyId::new(key), &input).unwrap()
    }
}

impl AppKeyProvider for Keys {
    fn public_key(&self, key_id: String) -> Result<PublicKeyData, ProviderError> {
        let key = self
            .book
            .provider
            .public_key(&KeyId::new(key_id))
            .map_err(|_| ProviderError::UnknownKey)?;
        Ok((&key).into())
    }

    fn sign(&self, request: SignRequest) -> Result<Vec<u8>, ProviderError> {
        self.requests.lock().unwrap().push(request.clone());
        if self.cancel {
            return Err(ProviderError::Cancelled {
                reason: "the owner cancelled".into(),
            });
        }
        Ok(self.sign_input(&request.key_id, &request.input))
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

fn text(v: &Value) -> String {
    v.to_string()
}

/// Astation's posted examples, as a binding consumer checks them: each
/// challenge reads, its canonical JSON's signing input has the posted
/// digest, and both posted signatures verify under the posted keys.
#[test]
fn astations_examples_through_the_encoding_exports() {
    let external = &file()["external"];
    for case in external["cases"].as_array().unwrap() {
        let challenge = text(&case["challenge"]);
        let read = parse_station_binding_challenge(challenge.clone()).unwrap();
        assert_eq!(challenge_json(&read), case["challenge"]);
        let body = canonical_json(challenge).unwrap();
        let input = signing_input(SignLabelKind::StationBinding, body.clone().into_bytes());
        assert_eq!(
            atem_client::encoding::Hash32::of(&input).to_hex(),
            case["signing_input_sha256"].as_str().unwrap()
        );
        for key in external["public_keys"].as_array().unwrap() {
            let alg = key["alg"].as_str().unwrap();
            let key = PublicKeyData {
                alg: if alg == "ed25519" {
                    KeyAlg::Ed25519
                } else {
                    KeyAlg::P256
                },
                raw: b64u_decode(key["pub"].as_str().unwrap()).unwrap(),
            };
            let sig = b64u_decode(case[format!("{alg}_sig")].as_str().unwrap()).unwrap();
            verify_signature(
                key.clone(),
                SignLabelKind::StationBinding,
                body.clone().into_bytes(),
                sig.clone(),
            )
            .unwrap();
            assert!(
                verify_signature(
                    key,
                    SignLabelKind::SignerReport,
                    body.clone().into_bytes(),
                    sig
                )
                .is_err()
            );
        }
    }
}

#[test]
fn challenges_through_the_production_binding() {
    let file = file();
    for case in file["challenges"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let read = parse_station_binding_challenge(case["text"].as_str().unwrap().into());
        match case.get("fields") {
            Some(fields) => {
                let c = read.unwrap_or_else(|e| panic!("{label}: {e}"));
                assert_eq!(challenge_json(&c), *fields, "{label}");
            }
            None => assert!(read.is_err_and(|e| report_code("malformed")(&e)), "{label}"),
        }
    }
    // A Station's fresh challenge: its own nonce, read back as written.
    let good = &file["valid"][0]["challenge"];
    let new = |origin: &str, expires_at: u64, expected: ExpectedBinding, action| {
        station_binding_challenge(
            action,
            origin.into(),
            claims(good),
            good["account_id"].as_str().unwrap().into(),
            good["genesis_hash"].as_str().unwrap().into(),
            LogHead {
                seq: good["head"]["seq"].as_u64().unwrap(),
                hash: good["head"]["hash"].as_str().unwrap().into(),
            },
            good["signer"].as_str().unwrap().into(),
            expected,
            good["issued_at"].as_u64().unwrap(),
            expires_at,
        )
    };
    let expires = good["expires_at"].as_u64().unwrap();
    let one = new(
        "https://Station-Dev.agora.build/",
        expires,
        ExpectedBinding::NeverBound,
        BindingAction::Bind,
    )
    .unwrap();
    let two = new(
        "https://station-dev.agora.build",
        expires,
        ExpectedBinding::NeverBound,
        BindingAction::Bind,
    )
    .unwrap();
    let (a, b) = (
        parse_station_binding_challenge(one.clone()).unwrap(),
        parse_station_binding_challenge(two).unwrap(),
    );
    assert_eq!(a.origin, "https://station-dev.agora.build");
    assert_ne!(a.nonce, b.nonce);
    assert_eq!(canonical_json(one.clone()).unwrap(), one, "canonical JSON");
    let mut same = challenge_json(&a);
    same["nonce"] = good["nonce"].clone();
    assert_eq!(
        &same, good,
        "the same fields as the vectors' bind but its nonce"
    );
    // A lease over 30 s, a transfer naming never_bound, an unbind by
    // another account.
    for (expires_at, expected, action) in [
        (
            expires + 1,
            ExpectedBinding::NeverBound,
            BindingAction::Bind,
        ),
        (
            expires,
            ExpectedBinding::NeverBound,
            BindingAction::Transfer,
        ),
        (
            expires,
            ExpectedBinding::Bound {
                binding_id: "bind-0001".into(),
                version: 1,
                owner: "ab00000000000000000000000009".into(),
            },
            BindingAction::Unbind,
        ),
    ] {
        assert!(
            new(
                "https://station-dev.agora.build",
                expires_at,
                expected,
                action
            )
            .is_err_and(|e| report_code("malformed")(&e))
        );
    }
}

#[test]
fn proofs_through_the_production_binding() {
    let file = file();
    for case in file["valid"]
        .as_array()
        .unwrap()
        .iter()
        .chain(file["invalid"].as_array().unwrap())
    {
        let label = case["label"].as_str().unwrap();
        let got = verify_station_binding(
            log_of(&file, case),
            case["proof"].as_str().unwrap().into(),
            text(&case["challenge"]),
            case["now_ms"].as_u64().unwrap(),
        );
        match case.get("expect") {
            Some(expect) => assert_eq!(&verified_json(&got.unwrap()), expect, "{label}"),
            None => {
                let code = case["code"].as_str().unwrap();
                assert!(
                    got.as_ref().is_err_and(report_code(code)),
                    "{label}: {got:?}"
                );
            }
        }
    }
    // An expected challenge that doesn't read is the caller's input.
    let case = &file["valid"][0];
    assert!(matches!(
        verify_station_binding(
            log_of(&file, case),
            case["proof"].as_str().unwrap().into(),
            "{}".into(),
            case["now_ms"].as_u64().unwrap(),
        ),
        Err(AtemError::Invalid { .. })
    ));
}

/// The builder's cases as requests: the body the request holds, or its
/// refusal.
#[test]
fn requests_hold_the_challenge_as_their_body() {
    let file = file();
    for case in file["builder"]
        .as_array()
        .unwrap()
        .iter()
        .chain(file["request"].as_array().unwrap())
    {
        let label = case["label"].as_str().unwrap();
        let got = StationBindingRequest::new(
            log_of(&file, case),
            text(&case["challenge"]),
            case["signer"].as_str().unwrap().into(),
            case["station"].as_str().unwrap().into(),
            claims(&case["expected"]),
            "key".into(),
            case["now_ms"].as_u64().unwrap(),
        );
        match case.get("body_json") {
            Some(want) => {
                let request = got.unwrap_or_else(|e| panic!("{label}: {e}"));
                assert_eq!(request.body_json(), want.as_str().unwrap(), "{label}");
                assert_eq!(challenge_json(&request.challenge()), case["challenge"]);
            }
            None => {
                let code = case["code"].as_str().unwrap();
                assert!(got.as_ref().is_err_and(report_code(code)), "{label}");
            }
        }
    }
    // A challenge that doesn't read is the request's malformed input.
    let case = &file["request"][0];
    assert!(
        StationBindingRequest::new(
            log_of(&file, case),
            "{}".into(),
            case["signer"].as_str().unwrap().into(),
            case["station"].as_str().unwrap().into(),
            claims(&case["expected"]),
            "key".into(),
            case["now_ms"].as_u64().unwrap(),
        )
        .is_err_and(|e| report_code("malformed")(&e))
    );
}

/// The immutable request: its sign request is built inside the core from
/// the held body (a fresh confirmation), and `finish` takes only a
/// signature over that body by its signer, giving the held body with the
/// signature byte for byte.
#[test]
fn a_request_finishes_only_with_its_signers_signature_over_its_body() {
    let (file, keys) = (file(), Keys::new(false));
    for case in file["request"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let log = log_of(&file, case);
        let new = |challenge: &Value| {
            StationBindingRequest::new(
                log.clone(),
                text(challenge),
                case["signer"].as_str().unwrap().into(),
                case["station"].as_str().unwrap().into(),
                claims(&case["expected"]),
                case["key"].as_str().unwrap().into(),
                case["now_ms"].as_u64().unwrap(),
            )
            .unwrap()
        };
        let request = new(&case["challenge"]);
        let held = request.body_json();
        let sign = request.sign_request();
        assert_eq!(sign.purpose, SigningPurpose::StationBinding, "{label}");
        assert!(sign.fresh_confirmation);
        assert_eq!(sign.label, case["sign_request"]["label"].as_str().unwrap());
        assert_eq!(sign.key_id, case["key"].as_str().unwrap());
        assert_eq!(sign.body_json.as_deref(), Some(held.as_str()));
        assert_eq!(
            sign.input,
            enc(&[b"atem-station-binding-v1", held.as_bytes()])
        );
        for f in case["finishes"].as_array().unwrap() {
            let input = match f["over"].as_str() {
                Some("held") => sign.input.clone(),
                _ => {
                    let mut other = case["challenge"].clone();
                    other["nonce"] = f["over"]["nonce"].clone();
                    new(&other).sign_request().input
                }
            };
            let sig = keys.sign_input(f["signed_with"].as_str().unwrap(), &input);
            let got = request.finish(sig.clone());
            match f.get("code") {
                None => assert_eq!(
                    got.unwrap(),
                    format!(r#"{{"body":{held},"sig":"{}"}}"#, b64u(&sig)),
                    "{label}"
                ),
                Some(code) => assert!(
                    got.as_ref().is_err_and(report_code(code.as_str().unwrap())),
                    "{label} {}: {got:?}",
                    f["label"]
                ),
            }
        }
        assert_eq!(request.body_json(), held);
    }
}

/// The synchronous helper signs through the app's provider under the
/// purpose that asks a fresh confirmation; a provider that declines leaves
/// nothing (`signing_failed`), and another member's key is
/// `bad_signature`.
#[test]
fn the_synchronous_helper_signs_through_the_apps_provider() {
    let file = file();
    let case = &file["request"][0];
    let log = log_of(&file, case);
    let sign = |keys: Arc<Keys>, key: &str| {
        sign_station_binding(
            keys,
            log.clone(),
            text(&case["challenge"]),
            case["signer"].as_str().unwrap().into(),
            case["station"].as_str().unwrap().into(),
            claims(&case["expected"]),
            key.into(),
            case["now_ms"].as_u64().unwrap(),
        )
    };
    let keys = Keys::new(false);
    let proof = sign(keys.clone(), case["key"].as_str().unwrap()).unwrap();
    let verified = verify_station_binding(
        log.clone(),
        proof,
        text(&case["challenge"]),
        case["now_ms"].as_u64().unwrap(),
    )
    .unwrap();
    assert!(verified.at_head);
    let requests = keys.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].purpose, SigningPurpose::StationBinding);
    assert!(requests[0].fresh_confirmation);
    assert!(
        sign(Keys::new(true), case["key"].as_str().unwrap())
            .is_err_and(|e| report_code("signing_failed")(&e))
    );
    assert!(sign(keys, "dev-mac/auth").is_err_and(|e| report_code("bad_signature")(&e)));
}

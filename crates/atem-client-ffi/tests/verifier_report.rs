//! `r9-vectors-verifier-report` through the production exports (a
//! member's signed verifier report, session-v1 R9.2; Astation #101): the
//! challenge reader, `verify_verifier_report` with `Report{code}`, the
//! immutable `VerifierReportRequest` (its body, sign request and finishes)
//! and the synchronous `sign_verifier_report` through an app provider. The
//! core's runner is `crates/atem-client/tests/verifier_report.rs`.
// The provider-taking calls are the UniFFI layer's (default feature).
#![cfg(feature = "uniffi")]

#[path = "../../atem-client/tests/support/mod.rs"]
#[allow(unused_imports)]
mod support;

use std::sync::{Arc, Mutex};

use atem_client::KeyProvider as _;
use atem_client::encoding::{b64u, enc};
use atem_client::provider::KeyId;
use atem_client_ffi::AtemError;
use atem_client_ffi::log::MembershipLog;
use atem_client_ffi::member_report::{
    VerifierReportRequest, parse_verifier_report_challenge, sign_verifier_report,
    verifier_report_challenge, verifier_report_process, verify_verifier_report,
};
use atem_client_ffi::provider::{AppKeyProvider, ProviderError};
use atem_client_ffi::types::{
    HostClock, PublicKeyData, ReportSignerKind, SignRequest, SigningPurpose, VerifiedReport,
};
use serde_json::{Value, json};
use support::*;

fn file() -> Value {
    serde_json::from_str(include_str!(
        "../../../designs/protocol/fixtures/r9-vectors-verifier-report.json"
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

fn verified_json(v: &VerifiedReport) -> Value {
    json!({
        "signer": v.signer,
        "kind": match v.kind {
            ReportSignerKind::Native => "native",
            ReportSignerKind::Service => "service",
        },
        "slot": v.slot,
        "process": v.process,
        "connection": v.connection,
        "head": {"seq": v.head.seq, "hash": v.head.hash},
        "at_head": v.at_head,
        "inventory": {"version": v.inventory.version, "actions": v.inventory.actions},
        "expires_at": v.expires_at,
    })
}

/// The test book's keys (dev-desk's from the keys file too) as an app
/// provider that records every request; `cancel` declines every signature,
/// as a key that needs interaction does for this purpose.
struct Keys {
    book: Book,
    requests: Mutex<Vec<SignRequest>>,
    cancel: bool,
}

impl Keys {
    fn new(cancel: bool) -> Arc<Self> {
        let mut book = Book::load();
        let desk = &book.keys["dev-desk"]["auth"]["secret_hex"];
        let seed = unhex32(desk.as_str().unwrap());
        book.provider
            .insert_ed25519(KeyId::new("dev-desk/auth"), &seed);
        Arc::new(Keys {
            book,
            requests: Mutex::new(Vec::new()),
            cancel,
        })
    }

    /// A signature by `key` over `input` (a signing input's exact bytes),
    /// P-256 normalized to low S as a report carries it.
    fn sign_input(&self, key: &str, input: &[u8]) -> Vec<u8> {
        let fields = atem_client::encoding::dec(input).unwrap();
        assert_eq!(fields[0], b"atem-verifier-report-v1");
        let input =
            atem_client::SigningInput::new(atem_client::SignLabel::VerifierReport, fields[1]);
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
                reason: "the key needs an interaction".into(),
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

#[test]
fn challenges_through_the_production_binding() {
    for case in file()["challenges"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let read = parse_verifier_report_challenge(case["text"].as_str().unwrap().into());
        match case.get("fields") {
            Some(fields) => {
                let c = read.unwrap_or_else(|e| panic!("{label}: {e}"));
                assert_eq!(
                    json!({"signer": c.signer, "slot": c.slot, "origin": c.origin,
                           "connection": c.connection, "nonce": c.nonce,
                           "issued_at": c.issued_at, "expires_at": c.expires_at}),
                    *fields,
                    "{label}"
                );
            }
            None => assert!(read.is_err_and(|e| report_code("malformed")(&e)), "{label}"),
        }
    }
    // A minter's fresh challenge: its own nonce, read back as written.
    let one = verifier_report_challenge(
        "member:dev-phone".into(),
        "astation-ios".into(),
        "https://Station-Dev.agora.build/".into(),
        3,
        1_793_264_000_000,
        1_793_264_030_000,
    )
    .unwrap();
    let two = verifier_report_challenge(
        "member:dev-phone".into(),
        "astation-ios".into(),
        "https://station-dev.agora.build".into(),
        3,
        1_793_264_000_000,
        1_793_264_030_000,
    )
    .unwrap();
    let (a, b) = (
        parse_verifier_report_challenge(one.clone()).unwrap(),
        parse_verifier_report_challenge(two).unwrap(),
    );
    assert_eq!(a.origin, "https://station-dev.agora.build");
    assert_ne!(a.nonce, b.nonce);
    assert_eq!(
        atem_client::canonical::jcs(&serde_json::from_str::<Value>(&one).unwrap()).unwrap(),
        one,
        "canonical JSON"
    );
    assert!(
        verifier_report_challenge(
            "member:dev-phone".into(),
            "astation-ios".into(),
            "https://station-dev.agora.build".into(),
            3,
            1_793_264_000_000,
            1_793_264_030_001,
        )
        .is_err_and(|e| report_code("malformed")(&e))
    );
}

#[test]
fn reports_through_the_production_binding() {
    let file = file();
    for case in file["valid"]
        .as_array()
        .unwrap()
        .iter()
        .chain(file["invalid"].as_array().unwrap())
    {
        let label = case["label"].as_str().unwrap();
        let got = verify_verifier_report(
            log_of(&file, case),
            case["report"].as_str().unwrap().into(),
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
    // Among them: a native whose roles changed, a recovery still waiting,
    // and a high-S P-256 signature.
    let cases: Vec<&Value> = file["valid"]
        .as_array()
        .unwrap()
        .iter()
        .chain(file["invalid"].as_array().unwrap())
        .collect();
    let by_label = |label: &str| *cases.iter().find(|c| c["label"] == label).unwrap();
    assert_eq!(
        by_label("native_after_set_roles")["expect"]["at_head"],
        false
    );
    assert_eq!(
        by_label("pending_recovery_subject")["code"],
        "unknown_signer"
    );
    assert_eq!(by_label("high_s_signature")["code"], "bad_signature");
    // An expected challenge that doesn't read is the caller's input.
    let case = &file["valid"][0];
    assert!(matches!(
        verify_verifier_report(
            log_of(&file, case),
            case["report"].as_str().unwrap().into(),
            "{}".into(),
            case["now_ms"].as_u64().unwrap(),
        ),
        Err(AtemError::Invalid { .. })
    ));
}

/// The builder's cases as requests: the body the request holds, or its
/// refusal; the process is this loaded core's.
#[test]
fn requests_hold_the_body_the_core_builds() {
    let file = file();
    let process = verifier_report_process();
    assert_eq!(
        process,
        b64u(&atem_client::member_report::process_generation())
    );
    for case in file["builder"]
        .as_array()
        .unwrap()
        .iter()
        .chain(file["request"].as_array().unwrap())
    {
        let label = case["label"].as_str().unwrap();
        let got = VerifierReportRequest::new(
            log_of(&file, case),
            text(&case["challenge"]),
            case["signer"].as_str().unwrap().into(),
            case["slot"].as_str().unwrap().into(),
            case["station"].as_str().unwrap().into(),
            "key".into(),
            case["now_ms"].as_u64().unwrap(),
        );
        match case.get("body_but_process") {
            Some(want) => {
                let request = got.unwrap_or_else(|e| panic!("{label}: {e}"));
                let mut body: Value = serde_json::from_str(&request.body_json()).unwrap();
                assert_eq!(body["process"], json!(process), "{label}");
                body.as_object_mut().unwrap().remove("process");
                assert_eq!(&body, want, "{label}");
            }
            None => {
                let code = case["code"].as_str().unwrap();
                assert!(got.as_ref().is_err_and(report_code(code)), "{label}");
            }
        }
    }
}

/// The immutable request: its sign request is built inside the core from
/// the held body, and `finish` takes only a signature over that body by
/// its signer, giving the held body with the signature byte for byte.
#[test]
fn a_request_finishes_only_with_its_signers_signature_over_its_body() {
    let (file, keys) = (file(), Keys::new(false));
    for case in file["request"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let log = log_of(&file, case);
        let new = |challenge: &Value, slot: &str| {
            VerifierReportRequest::new(
                log.clone(),
                text(challenge),
                case["signer"].as_str().unwrap().into(),
                slot.into(),
                case["station"].as_str().unwrap().into(),
                case["key"].as_str().unwrap().into(),
                case["now_ms"].as_u64().unwrap(),
            )
            .unwrap()
        };
        let request = new(&case["challenge"], case["slot"].as_str().unwrap());
        let held = request.body_json();
        let sign = request.sign_request();
        assert_eq!(sign.purpose, SigningPurpose::VerifierReport, "{label}");
        assert!(!sign.fresh_confirmation);
        assert_eq!(sign.label, case["sign_request"]["label"].as_str().unwrap());
        assert_eq!(sign.key_id, case["key"].as_str().unwrap());
        assert_eq!(sign.body_json.as_deref(), Some(held.as_str()));
        assert_eq!(
            sign.input,
            enc(&[b"atem-verifier-report-v1", held.as_bytes()])
        );
        for f in case["finishes"].as_array().unwrap() {
            let input = match f["over"].as_str() {
                Some("held") => sign.input.clone(),
                _ => {
                    let slot = f["over"]["slot"].as_str().unwrap();
                    let mut other = case["challenge"].clone();
                    other["slot"] = json!(slot);
                    new(&other, slot).sign_request().input
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
        // The held body never changed.
        assert_eq!(request.body_json(), held);
    }
}

/// The synchronous helper signs through the app's provider, under the
/// purpose that never prompts; a provider that declines leaves nothing
/// (`signing_failed`), and another member's key is `bad_signature`.
#[test]
fn the_synchronous_helper_signs_through_the_apps_provider() {
    let file = file();
    let case = &file["request"][0];
    let log = log_of(&file, case);
    let sign = |keys: Arc<Keys>, key: &str| {
        sign_verifier_report(
            keys,
            log.clone(),
            text(&case["challenge"]),
            case["signer"].as_str().unwrap().into(),
            case["slot"].as_str().unwrap().into(),
            case["station"].as_str().unwrap().into(),
            key.into(),
            case["now_ms"].as_u64().unwrap(),
        )
    };
    let keys = Keys::new(false);
    let report = sign(keys.clone(), case["key"].as_str().unwrap()).unwrap();
    let verified = verify_verifier_report(
        log.clone(),
        report,
        text(&case["challenge"]),
        case["now_ms"].as_u64().unwrap(),
    )
    .unwrap();
    assert_eq!(verified.process, verifier_report_process());
    let requests = keys.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].purpose, SigningPurpose::VerifierReport);
    assert!(!requests[0].fresh_confirmation);
    assert!(
        sign(Keys::new(true), case["key"].as_str().unwrap())
            .is_err_and(|e| report_code("signing_failed")(&e))
    );
    assert!(sign(keys, "dev-mac/auth").is_err_and(|e| report_code("bad_signature")(&e)));
}

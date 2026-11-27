//! `r9-vectors-signer-report` through the production exports (a native
//! manager's signed report of its control-record signing journal,
//! host-work-v1 §11.1 "The signer report"; Astation #114 item 4): the
//! challenge reader and builder, `verify_signer_report` with
//! `Report{code}`, the immutable `SignerReportRequest` (its body, sign
//! request and finishes) and the synchronous `sign_signer_report` through
//! an app provider. The core's runner is
//! `crates/atem-client/tests/signer_report.rs`.
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
use atem_client_ffi::member_report::signer::{
    SignerReportRequest, parse_signer_report_challenge, sign_signer_report,
    signer_report_challenge, signer_report_plan_record, verify_signer_report,
};
use atem_client_ffi::member_report::verifier_report_process;
use atem_client_ffi::provider::{AppKeyProvider, ProviderError};
use atem_client_ffi::types::{
    HostClock, PublicKeyData, SignRequest, SignerJournalView, SignerPlanRecord,
    SignerReportRecovery, SigningPurpose, VerifiedSignerReport,
};
use serde_json::{Value, json};
use support::*;

fn file() -> Value {
    serde_json::from_str(include_str!(
        "../../../designs/protocol/fixtures/r9-vectors-signer-report.json"
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

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t.as_str().unwrap().to_owned())
        .collect()
}

fn journal(value: &Value) -> SignerJournalView {
    SignerJournalView {
        id: value["id"].as_str().unwrap().into(),
        since: value["since"].as_u64().unwrap(),
        revision: value["revision"].as_u64().unwrap(),
        records: strings(&value["records"]),
        drafts: strings(&value["drafts"]),
    }
}

fn recovery_json(r: &SignerReportRecovery) -> Value {
    json!({"generation": r.generation, "plan_id": r.plan_id,
           "candidate_feed_id": r.candidate_feed_id, "source_hash": r.source_hash,
           "evidence_hash": r.evidence_hash})
}

fn verified_json(v: &VerifiedSignerReport) -> Value {
    json!({
        "signer": v.signer,
        "slot": v.slot,
        "process": v.process,
        "connection": v.connection,
        "head": {"seq": v.head.seq, "hash": v.head.hash},
        "at_head": v.at_head,
        "recovery": recovery_json(&v.recovery),
        "journal": {"id": v.journal.id, "since": v.journal.since,
                    "revision": v.journal.revision, "records": v.journal.records,
                    "records_hash": v.journal.records_hash, "drafts": v.journal.drafts,
                    "drafts_hash": v.journal.drafts_hash},
        "records": v.records,
    })
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

    /// A signature by `key` over `input` (a signer report's signing input),
    /// P-256 normalized to low S as a report carries it.
    fn sign_input(&self, key: &str, input: &[u8]) -> Vec<u8> {
        let fields = atem_client::encoding::dec(input).unwrap();
        assert_eq!(fields[0], b"atem-signer-report-v1");
        let input = atem_client::SigningInput::new(atem_client::SignLabel::SignerReport, fields[1]);
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

fn recovery() -> SignerReportRecovery {
    SignerReportRecovery {
        generation: "7".into(),
        plan_id: "5b7c9d1e-2f3a-4b5c-8d6e-7f8091a2b3c4".into(),
        candidate_feed_id: "7a2d3c4b-5e6f-4071-9b8c-0d1e2f3a4b5c".into(),
        source_hash: "5a".repeat(32),
        evidence_hash: "e7".repeat(32),
    }
}

#[test]
fn challenges_through_the_production_binding() {
    for case in file()["challenges"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let read = parse_signer_report_challenge(case["text"].as_str().unwrap().into());
        match case.get("fields") {
            Some(fields) => {
                let c = read.unwrap_or_else(|e| panic!("{label}: {e}"));
                assert_eq!(
                    json!({"signer": c.signer, "slot": c.slot, "origin": c.origin,
                           "connection": c.connection, "nonce": c.nonce,
                           "issued_at": c.issued_at, "expires_at": c.expires_at,
                           "recovery": recovery_json(&c.recovery)}),
                    *fields,
                    "{label}"
                );
            }
            None => assert!(read.is_err_and(|e| report_code("malformed")(&e)), "{label}"),
        }
    }
    // A minter's fresh challenge: its own nonce, read back as written.
    let new = |origin: &str, expires_at: u64, recovery: SignerReportRecovery| {
        signer_report_challenge(
            "member:dev-phone".into(),
            "astation-ios".into(),
            origin.into(),
            3,
            1_793_264_000_000,
            expires_at,
            recovery,
        )
    };
    let one = new(
        "https://Station-Dev.agora.build/",
        1_793_264_030_000,
        recovery(),
    )
    .unwrap();
    let two = new(
        "https://station-dev.agora.build",
        1_793_264_030_000,
        recovery(),
    )
    .unwrap();
    let (a, b) = (
        parse_signer_report_challenge(one.clone()).unwrap(),
        parse_signer_report_challenge(two).unwrap(),
    );
    assert_eq!(a.origin, "https://station-dev.agora.build");
    assert_eq!(a.recovery, recovery());
    assert_ne!(a.nonce, b.nonce);
    assert_eq!(
        atem_client::canonical::jcs(&serde_json::from_str::<Value>(&one).unwrap()).unwrap(),
        one,
        "canonical JSON"
    );
    // A lease over 30 s, a generation not canonical, a hash not lowercase.
    assert!(
        new(
            "https://station-dev.agora.build",
            1_793_264_030_001,
            recovery()
        )
        .is_err_and(|e| report_code("malformed")(&e))
    );
    for bad in [
        SignerReportRecovery {
            generation: "07".into(),
            ..recovery()
        },
        SignerReportRecovery {
            generation: "9223372036854775808".into(),
            ..recovery()
        },
        SignerReportRecovery {
            source_hash: "5A".repeat(32),
            ..recovery()
        },
        SignerReportRecovery {
            plan_id: "plan".into(),
            ..recovery()
        },
    ] {
        assert!(
            new(
                "https://station-dev.agora.build",
                1_793_264_030_000,
                bad.clone()
            )
            .is_err_and(|e| report_code("malformed")(&e)),
            "{bad:?}"
        );
    }
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
        let got = verify_signer_report(
            log_of(&file, case),
            case["report"].as_str().unwrap().into(),
            text(&case["challenge"]),
            strings(&case["exported"]),
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
        verify_signer_report(
            log_of(&file, case),
            case["report"].as_str().unwrap().into(),
            "{}".into(),
            strings(&case["exported"]),
            case["now_ms"].as_u64().unwrap(),
        ),
        Err(AtemError::Invalid { .. })
    ));
}

/// The plan predicate's cases through `signer_report_plan_record`: each
/// answer typed (`InPlan`, or `NotInPlan{reason}`), or `Report{code}`;
/// every reason among them.
#[test]
fn the_plan_predicate_through_the_production_binding() {
    let file = file();
    let mut reasons = std::collections::BTreeSet::new();
    for case in file["plan_predicate"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let got = signer_report_plan_record(
            log_of(&file, case),
            case["body"].as_str().unwrap().into(),
            case["member"].as_str().unwrap().into(),
            case["origin"].as_str().unwrap().into(),
        );
        match (case.get("code"), case.get("reason")) {
            (Some(code), _) => assert!(
                got.as_ref().is_err_and(report_code(code.as_str().unwrap())),
                "{label}: {got:?}"
            ),
            (None, None) => {
                assert_eq!(case["in_plan"], true, "{label}");
                assert_eq!(got.unwrap(), SignerPlanRecord::InPlan, "{label}");
            }
            (None, Some(reason)) => {
                assert_eq!(case["in_plan"], false, "{label}");
                let reason = reason.as_str().unwrap().to_owned();
                reasons.insert(reason.clone());
                assert_eq!(
                    got.unwrap(),
                    SignerPlanRecord::NotInPlan { reason },
                    "{label}"
                );
            }
        }
    }
    assert_eq!(
        reasons.into_iter().collect::<Vec<_>>(),
        [
            "another_account",
            "another_genesis",
            "another_origin",
            "another_signer"
        ]
    );
}

/// The builder's cases as requests: the body the request holds, or its
/// refusal; the process is this loaded core's.
#[test]
fn requests_hold_the_body_the_core_builds() {
    let file = file();
    let process = verifier_report_process();
    for case in file["builder"]
        .as_array()
        .unwrap()
        .iter()
        .chain(file["request"].as_array().unwrap())
    {
        let label = case["label"].as_str().unwrap();
        let got = SignerReportRequest::new(
            log_of(&file, case),
            text(&case["challenge"]),
            case["signer"].as_str().unwrap().into(),
            case["slot"].as_str().unwrap().into(),
            case["station"].as_str().unwrap().into(),
            journal(&case["journal"]),
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
    // A journal id that isn't 16 bytes of base64url is the request's
    // malformed input.
    let case = &file["request"][0];
    let mut bad = journal(&case["journal"]);
    bad.id = b64u(&[1u8; 15]);
    assert!(
        SignerReportRequest::new(
            log_of(&file, case),
            text(&case["challenge"]),
            case["signer"].as_str().unwrap().into(),
            case["slot"].as_str().unwrap().into(),
            case["station"].as_str().unwrap().into(),
            bad,
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
        let new = |challenge: &Value, slot: &str| {
            SignerReportRequest::new(
                log.clone(),
                text(challenge),
                case["signer"].as_str().unwrap().into(),
                slot.into(),
                case["station"].as_str().unwrap().into(),
                journal(&case["journal"]),
                case["key"].as_str().unwrap().into(),
                case["now_ms"].as_u64().unwrap(),
            )
            .unwrap()
        };
        let request = new(&case["challenge"], case["slot"].as_str().unwrap());
        let held = request.body_json();
        let sign = request.sign_request();
        assert_eq!(sign.purpose, SigningPurpose::SignerReport, "{label}");
        assert!(sign.fresh_confirmation);
        assert_eq!(sign.label, case["sign_request"]["label"].as_str().unwrap());
        assert_eq!(sign.key_id, case["key"].as_str().unwrap());
        assert_eq!(sign.body_json.as_deref(), Some(held.as_str()));
        assert_eq!(
            sign.input,
            enc(&[b"atem-signer-report-v1", held.as_bytes()])
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
        sign_signer_report(
            keys,
            log.clone(),
            text(&case["challenge"]),
            case["signer"].as_str().unwrap().into(),
            case["slot"].as_str().unwrap().into(),
            case["station"].as_str().unwrap().into(),
            journal(&case["journal"]),
            key.into(),
            case["now_ms"].as_u64().unwrap(),
        )
    };
    let keys = Keys::new(false);
    let report = sign(keys.clone(), case["key"].as_str().unwrap()).unwrap();
    // The records the journal holds, as its signer signed them.
    let exported: Vec<String> = file["records"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|r| {
            ["phone_revoke", "phone_interrupt", "phone_host_interrupt"]
                .contains(&r["label"].as_str().unwrap())
        })
        .map(|r| atem_client::canonical::jcs(&r["record"]).unwrap())
        .collect();
    let verified = verify_signer_report(
        log.clone(),
        report,
        text(&case["challenge"]),
        exported,
        case["now_ms"].as_u64().unwrap(),
    )
    .unwrap();
    assert_eq!(verified.process, verifier_report_process());
    assert_eq!(verified.journal.records, 3);
    let requests = keys.requests.lock().unwrap().clone();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].purpose, SigningPurpose::SignerReport);
    assert!(requests[0].fresh_confirmation);
    assert!(
        sign(Keys::new(true), case["key"].as_str().unwrap())
            .is_err_and(|e| report_code("signing_failed")(&e))
    );
    assert!(sign(keys, "dev-mac/auth").is_err_and(|e| report_code("bad_signature")(&e)));
}

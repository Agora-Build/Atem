//! `r9-vectors-resigned-copy` through the production export
//! (`check_resigned_copy`: a current manager's re-signed copy of a removed
//! or demoted manager's stop, host-work-v1 §11.1, condition (c)): each
//! case's `ResignedCopy`, or `Invalid{code, detail}` with the copy check's
//! code and detail. The core's runner is
//! `crates/atem-client/tests/resigned_copy.rs`.
#[path = "../../atem-client/tests/support/mod.rs"]
#[allow(unused_imports)]
mod support;

use std::collections::BTreeSet;
use std::sync::Arc;

use atem_client_ffi::AtemError;
use atem_client_ffi::control::{check_resigned_copy, resigned_copy_codes, verify_control_record};
use atem_client_ffi::log::MembershipLog;
use atem_client_ffi::types::{ControlCheckInfo, HostClock, ResignedCopy};
use serde_json::{Value, json};
use support::*;

fn file() -> Value {
    serde_json::from_str(include_str!(
        "../../../designs/protocol/fixtures/r9-vectors-resigned-copy.json"
    ))
    .unwrap()
}

/// L, then the case's chain (the file's entries), then its `freeze`
/// carriage, as an app builds its log.
fn log_of(file: &Value, case: &Value) -> Arc<MembershipLog> {
    let v = Vectors::load();
    let now = HostClock {
        wall_ms: case["now_ms"].as_u64().unwrap(),
        mono_ms: 1_000,
        boot_id: "boot-1".into(),
    };
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

fn copy_json(c: &ResignedCopy) -> Value {
    let mut out = json!({
        "original_record_id": c.original_record_id,
        "copy_record_id": c.copy_record_id,
        "signer": c.signer,
        "principal": c.principal,
        "action": c.action,
    });
    if let Some(feed) = &c.feed {
        out["feed"] = json!(feed);
    }
    out
}

#[test]
fn copies_through_the_production_binding() {
    let file = file();
    assert_eq!(json!(resigned_copy_codes()), file["codes"]);
    let mut codes = BTreeSet::new();
    for case in file["cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let got = check_resigned_copy(
            log_of(&file, case),
            case["original_json"].as_str().unwrap().into(),
            case["copy_json"].as_str().unwrap().into(),
            case["candidate_feed_id"].as_str().unwrap().into(),
        );
        match case.get("expect") {
            Some(expect) => assert_eq!(&copy_json(&got.unwrap()), expect, "{label}"),
            None => {
                let want = (
                    case["code"].as_str().unwrap(),
                    case.get("detail").and_then(Value::as_str).unwrap_or(""),
                );
                match got {
                    Err(AtemError::Invalid { code, detail }) => {
                        assert_eq!((code.as_str(), detail.as_str()), want, "{label}");
                        codes.insert(code);
                    }
                    other => panic!("{label}: {other:?}"),
                }
            }
        }
    }
    assert_eq!(
        codes,
        resigned_copy_codes().into_iter().collect(),
        "every code"
    );
    // The copy the snapshot checker passes is refused here too.
    for p in file["checker_passes"].as_array().unwrap() {
        let text = |label: &Value| {
            file["records"]
                .as_array()
                .unwrap()
                .iter()
                .find(|r| r["label"] == *label)
                .unwrap()["record"]
                .to_string()
        };
        let got = check_resigned_copy(
            log_of(&file, p),
            text(&p["original"]),
            text(&p["copy"]),
            p["candidate_feed_id"].as_str().unwrap().into(),
        );
        assert!(
            matches!(&got, Err(AtemError::Invalid { code, detail })
                if code == p["code"].as_str().unwrap() && detail == p["detail"].as_str().unwrap()),
            "{}: {got:?}",
            p["label"]
        );
    }
}

/// Every record of the file verifies on each of its chains as its `checks`
/// say, through the production `verify_control_record`; a record the
/// parse refuses is `Invalid` with its `parse_error`.
#[test]
fn every_record_verifies_as_its_checks_say() {
    let file = file();
    let mut verdicts = 0;
    for rec in file["records"].as_array().unwrap() {
        let label = rec["label"].as_str().unwrap();
        let wire = rec["record"].to_string();
        let Some(checks) = rec.get("checks") else {
            let code = rec["parse_error"].as_str().unwrap();
            let got = verify_control_record(
                log_of(&file, &json!({"chain": [], "now_ms": 1_793_620_850_000u64})),
                wire,
            );
            assert!(
                matches!(&got, Err(AtemError::Invalid { code: c, .. }) if c == code),
                "{label}: {got:?}"
            );
            continue;
        };
        for check in checks.as_array().unwrap() {
            let case = json!({"chain": check["chain"], "now_ms": 1_793_620_850_000u64});
            let got = match verify_control_record(log_of(&file, &case), wire.clone()).unwrap() {
                ControlCheckInfo::Valid { signer, .. } => {
                    json!({"verdict": "valid", "signer": signer})
                }
                ControlCheckInfo::Pending { reason } => {
                    json!({"verdict": "pending", "reason": reason})
                }
                ControlCheckInfo::Refused { reason } => {
                    json!({"verdict": "refused", "reason": reason})
                }
            };
            let mut want = check.clone();
            want.as_object_mut().unwrap().remove("chain");
            assert_eq!(got, want, "{label} on L + {}", check["chain"]);
            verdicts += 1;
        }
    }
    assert!(verdicts > 100, "{verdicts}");
}

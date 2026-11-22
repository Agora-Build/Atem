//! `r9-vectors-required-verifier` through the production export: each
//! case's requirement, or its refusal as `Membership{membership_invalid,
//! detail: reason}` (the core's runner is
//! `crates/atem-client/tests/required_verifier.rs`).
use atem_client_ffi::error::AtemError;
use atem_client_ffi::log::membership_required_version;
use serde_json::{Value, json};

#[test]
fn shared_signing_requirements_through_the_production_binding() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../designs/protocol/fixtures/r9-vectors-required-verifier.json"
    ))
    .unwrap();
    let cases = vectors["cases"].as_array().unwrap();
    assert!(!cases.is_empty());
    for case in cases {
        let label = case["label"].as_str().unwrap();
        let result = membership_required_version(case["body_json"].as_str().unwrap().into());
        if case["reject"] == true {
            assert_eq!(
                result,
                Err(AtemError::Membership {
                    code: "membership_invalid".into(),
                    detail: case["reason"].as_str().unwrap().into(),
                    index: None,
                }),
                "{label}"
            );
        } else {
            let actual = result
                .unwrap_or_else(|e| panic!("{label}: {e}"))
                .map(|r| json!({"action": r.action, "minimum_version": r.minimum_version}));
            assert_eq!(json!(actual), case["requirement"], "{label}");
        }
    }
}

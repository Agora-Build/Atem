use atem_client_ffi::log::membership_required_version;
use serde_json::{Value, json};

#[test]
fn shared_signing_requirements_through_the_production_binding() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../designs/protocol/fixtures/r9-vectors-required-verifier.json"
    ))
    .unwrap();
    for case in vectors["cases"].as_array().unwrap() {
        let result = membership_required_version(case["body_json"].as_str().unwrap().into());
        if case["reject"] == true {
            assert!(result.is_err(), "{}", case["label"]);
        } else {
            let actual = result
                .unwrap()
                .map(|r| json!({"action":r.action,"minimum_version":r.minimum_version}));
            assert_eq!(json!(actual), case["requirement"], "{}", case["label"]);
        }
    }
}

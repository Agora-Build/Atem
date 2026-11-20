use atem_client::membership::{known_actions, required_version};
use serde_json::{Value, json};
use std::collections::BTreeSet;

#[test]
fn signing_requirements_use_the_strict_membership_parser_and_shared_vectors() {
    let vectors: Value = serde_json::from_str(include_str!(
        "../../../designs/protocol/fixtures/r9-vectors-required-verifier.json"
    ))
    .unwrap();
    let mut actions = BTreeSet::new();
    for case in vectors["cases"].as_array().unwrap() {
        let body = case["body_json"].as_str().unwrap();
        let result = required_version(body.as_bytes());
        if case["reject"] == true {
            assert!(result.is_err(), "{}", case["label"]);
        } else {
            let actual = result
                .unwrap()
                .map(|r| json!({"action":r.action,"minimum_version":r.minimum_version}));
            assert_eq!(json!(actual), case["requirement"], "{}", case["label"]);
            let parsed: Value = serde_json::from_str(body).unwrap();
            actions.insert(parsed["action"].as_str().unwrap().to_owned());
        }
    }
    assert_eq!(
        actions,
        known_actions().iter().map(|a| (*a).to_owned()).collect()
    );
}

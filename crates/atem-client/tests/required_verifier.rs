//! `designs/protocol/fixtures/r9-vectors-required-verifier.json`: unsigned
//! membership-entry bodies and what `membership::required_version` gives
//! each (session-v1 R9.2 "How the signing gate uses it"): no requirement,
//! `{action, minimum_version}`, or a refusal with its reason (the
//! `Invalid` code).
//!
//! `write_required_verifier_vectors` (ignored) writes the file from
//! `required_verifier_vectors`, which builds every body from
//! `r9-vectors-membership-log` and checks each outcome written here by hand
//! against `required_version` (the exact `Invalid`, a `malformed`'s text
//! too, which the file doesn't carry). The other tests read the file: that
//! it is what the generator makes now, and that every case classifies as it
//! says, covering every action and every scope op the verifier knows. The
//! Swift, Kotlin and WASM suites and the FFI's own test run the same file;
//! `scripts/check-r9-vectors.py` doesn't check it (it holds no
//! cryptographic value).
mod support;

use std::collections::BTreeSet;

use atem_client::canonical;
use atem_client::membership::entry::OPS;
use atem_client::membership::{Invalid, known_actions, required_version};
use serde_json::{Value, json};
use support::{Vectors, fixtures_dir, load};

const FILE: &str = "r9-vectors-required-verifier";

const NOTE: &str = "Unsigned membership-entry bodies (body_json, the exact text passed) and what the shared core's membership::required_version gives each (session-v1 R9.2 \"How the signing gate uses it\"): requirement null (an entry every release from v0.8.0 to v0.8.5 accepts), {action, minimum_version} (the first verifier version that accepts it), or reject: true with reason, the Invalid code a verifier gives that shape (bindings: Membership{code: membership_invalid, detail: reason}). A label starting with a capital letter is that entry of r9-vectors-membership-log (its jcs); the others are E5 (svc-discord's service add) changed as the label says: add-<ops> and set_roles-<ops> with those scope ops (set_roles-*: the same member as a set_roles), the rest as the case's note says. Only each body's shape is checked: no signature, chain, membership authority or participant authentication is established.";

/// The five actions version 2 adds.
const DELEGATED: [&str; 5] = [
    "host_enc_key",
    "host_sender_readmit",
    "host_sender_revoke",
    "project_remove",
    "project_set",
];

/// What `required_version` gives a case.
#[derive(Debug)]
enum Outcome {
    /// No requirement, or the action and its minimum version.
    Needs(Option<(&'static str, u32)>),
    /// Refused: the exact `Invalid` (the file carries its code).
    Refused(Invalid),
}

struct Case {
    label: String,
    body: String,
    outcome: Outcome,
    note: Option<&'static str>,
}

fn case(label: impl Into<String>, body: String, outcome: Outcome) -> Case {
    Case {
        label: label.into(),
        body,
        outcome,
        note: None,
    }
}

fn noted(label: &str, body: String, outcome: Outcome, note: &'static str) -> Case {
    Case {
        note: Some(note),
        ..case(label, body, outcome)
    }
}

fn needs(action: &'static str, version: u32) -> Outcome {
    Outcome::Needs(Some((action, version)))
}

const NONE: Outcome = Outcome::Needs(None);

fn refused(reason: Invalid) -> Outcome {
    Outcome::Refused(reason)
}

/// A body as text: compact, keys sorted (the vectors' bodies are ASCII and
/// integers, so this is their JCS).
fn text(body: &Value) -> String {
    serde_json::to_string(body).unwrap()
}

/// `text` replacing the one `from` in it by `to`.
fn edit(text: &str, from: &str, to: &str) -> String {
    assert_eq!(text.matches(from).count(), 1, "{from}");
    text.replacen(from, to, 1)
}

/// E5, svc-discord's service `add`, as a value.
fn e5(log: &Vectors) -> Value {
    serde_json::from_str(log.vector("E5")["jcs"].as_str().unwrap()).unwrap()
}

/// E5 with the scope ops `ops`.
fn service_add(log: &Vectors, ops: &[&str]) -> Value {
    let mut body = e5(log);
    body["member"]["scope"]["ops"] = json!(ops);
    body
}

/// E5's member as a `set_roles`, with the scope ops `ops`.
fn service_set_roles(log: &Vectors, ops: &[&str]) -> Value {
    let mut body = e5(log);
    let member = body.as_object_mut().unwrap().remove("member").unwrap();
    body["action"] = json!("set_roles");
    for field in ["device_id", "expires_at", "roles", "scope"] {
        body[field] = member[field].clone();
    }
    body["scope"]["ops"] = json!(ops);
    body
}

/// E5 with ops `launch` and `view`, 44 project hashes and a longer device
/// id: a body of exactly `len` bytes.
fn sized(log: &Vectors, len: usize) -> String {
    let mut body = service_add(log, &["launch", "view"]);
    body["member"]["scope"]["projects"] = json!(
        (0..44u32)
            .map(|i| format!("h1.b982533d.{i:064x}"))
            .collect::<Vec<_>>()
    );
    let pad = len - text(&body).len();
    body["member"]["device_id"] = json!(format!("svc-discord{}", "x".repeat(pad)));
    let sized = text(&body);
    assert_eq!(sized.len(), len);
    sized
}

fn cases() -> Vec<Case> {
    let log = Vectors::load();
    let from_log = |label: &str| log.vector(label)["jcs"].as_str().unwrap().to_owned();
    let mut cases = Vec::new();

    // Every action but `add` and `set_roles` of services: no requirement
    // before the five delegated ones, version 2 for each of them.
    for label in [
        "E1",
        "E2",
        "E3",
        "E6",
        "C6_mac",
        "R7",
        "K7_current",
        "A8",
        "V8",
        "KB7",
    ] {
        cases.push(case(label, from_log(label), NONE));
    }
    for (label, action) in [
        ("P8_set", "project_set"),
        ("P10_remove", "project_remove"),
        ("EK7_set", "host_enc_key"),
        ("HS7_revoke", "host_sender_revoke"),
        ("HS8_readmit", "host_sender_readmit"),
    ] {
        cases.push(case(label, from_log(label), needs(action, 2)));
    }
    cases.push(case("P9_remove_host_b", from_log("P9_remove_host_b"), NONE));

    // A service's scope: version 1 with `launch`, `message` or `notify`,
    // none with R9.6's seven only; every op appears.
    let scopes: [(&[&str], Option<u32>); 8] = [
        (&["view"], None),
        (&["interrupt", "prompt", "view"], None),
        (
            &[
                "approval",
                "interrupt",
                "prompt",
                "rule_revoke",
                "stop",
                "terminal",
                "view",
            ],
            None,
        ),
        (&["launch", "view"], Some(1)),
        (&["message", "view"], Some(1)),
        (&["notify", "view"], Some(1)),
        (&["launch", "message", "notify", "view"], Some(1)),
        (&OPS, Some(1)),
    ];
    for (action, build) in [
        ("add", service_add as fn(&Vectors, &[&str]) -> Value),
        ("set_roles", service_set_roles),
    ] {
        for (ops, version) in scopes {
            cases.push(case(
                format!("{action}-{}", ops.join(",")),
                text(&build(&log, ops)),
                Outcome::Needs(version.map(|v| (action, v))),
            ));
        }
    }

    // Refused: never no requirement.
    let changed = |change: &dyn Fn(&mut Value)| {
        let mut body = e5(&log);
        change(&mut body);
        text(&body)
    };
    let raw = log.vector("E5")["jcs"].as_str().unwrap().to_owned();
    cases.push(case(
        "invalid-action",
        changed(&|b| b["action"] = json!("future_action")),
        refused(Invalid::Malformed("unknown action")),
    ));
    cases.push(case(
        "invalid-v",
        changed(&|b| b["v"] = json!(2)),
        refused(Invalid::Malformed("v must be 1")),
    ));
    cases.push(case(
        "invalid-type",
        changed(&|b| b["type"] = json!("atem-other")),
        refused(Invalid::Malformed("type")),
    ));
    cases.push(noted(
        "unknown-field",
        changed(&|b| b["unexpected"] = json!(1)),
        refused(Invalid::UnknownField),
        "a top-level field add doesn't have, with a value that isn't null: unknown_field",
    ));
    cases.push(noted(
        "null-field",
        changed(&|b| b["unexpected"] = Value::Null),
        refused(Invalid::Malformed("null")),
        "the same field as null: the signed-object parse refuses a null anywhere before the action's fields are read: malformed",
    ));
    cases.push(case(
        "unsorted-ops",
        text(&service_add(&log, &["view", "launch"])),
        refused(Invalid::ArrayNotCanonical),
    ));
    cases.push(case(
        "duplicate-ops",
        text(&service_add(&log, &["view", "view"])),
        refused(Invalid::ArrayNotCanonical),
    ));
    cases.push(case(
        "unknown-op",
        text(&service_add(&log, &["future", "view"])),
        refused(Invalid::BadScope),
    ));
    cases.push(case(
        "wrong-key-alg",
        changed(&|b| b["member"]["auth_key"]["alg"] = json!("x25519")),
        refused(Invalid::WrongAlg),
    ));
    cases.push(noted(
        "expired-body-still-needs-chain-validation",
        changed(&|b| b["member"]["expires_at"] = json!(1_792_400_003_999u64)),
        NONE,
        "a service add whose expires_at is before its signed_at: the shape is accepted; required_version checks no chain or clock",
    ));
    cases.push(case(
        "duplicate-action",
        edit(
            &raw,
            r#""action":"add""#,
            r#""action":"remove","action":"add""#,
        ),
        refused(Invalid::Malformed("not strict JSON")),
    ));
    cases.push(case(
        "escaped-duplicate-action",
        edit(
            &raw,
            r#""action":"add""#,
            r#""\u0061ction":"add","action":"add""#,
        ),
        refused(Invalid::Malformed("not strict JSON")),
    ));
    cases.push(case(
        "duplicate-nested-key",
        edit(
            &raw,
            r#""kind":"service""#,
            r#""kind":"native","kind":"service""#,
        ),
        refused(Invalid::Malformed("not strict JSON")),
    ));
    cases.push(case(
        "null-body",
        "null".into(),
        refused(Invalid::Malformed("body must be an object")),
    ));
    cases.push(case(
        "fractional-seq",
        edit(&raw, r#""seq":5,"#, r#""seq":5.0,"#),
        refused(Invalid::Malformed("not strict JSON")),
    ));
    cases.push(case(
        "unsafe-integer",
        edit(&raw, r#""seq":5,"#, r#""seq":9007199254740992,"#),
        refused(Invalid::Malformed("not strict JSON")),
    ));
    cases.push(noted(
        "input-over-16-kib",
        format!("{}{raw}", " ".repeat(16 * 1024 + 1)),
        refused(Invalid::Malformed("not strict JSON")),
        "16,385 spaces before E5's body, 17,020 bytes: over the strict reader's 16 KiB input bound, read as not strict JSON: malformed",
    ));
    cases.push(noted(
        "body-of-4096-bytes",
        sized(&log, 4096),
        needs("add", 1),
        "E5 with ops launch and view, 44 project hashes and a longer device id: exactly 4,096 bytes of JCS, the body bound",
    ));
    cases.push(noted(
        "body-of-4097-bytes",
        sized(&log, 4097),
        refused(Invalid::TooLarge),
        "the same with one byte more of device id: over the body bound (within the 16 KiB input bound): too_large",
    ));

    // One refused body of each delegated action: the device list's own
    // refusals of their shape, for the same reason as the chain's.
    for (label, reason) in [
        ("P9_one_host", Invalid::BadProject),
        ("P9_remove_bad_name", Invalid::BadProject),
        ("EK7_ed25519_enc_key", Invalid::WrongAlg),
        (
            "HS7_revoke_no_interrupt",
            Invalid::Malformed("interrupt_running"),
        ),
        ("HS8_readmit_interrupt", Invalid::UnknownField),
    ] {
        let vector = log.vector(label);
        assert_eq!(vector["valid"], false, "{label}");
        assert_eq!(vector["reason"], reason.code(), "{label}");
        cases.push(case(label, from_log(label), refused(reason)));
    }
    cases
}

/// The file: every case's outcome checked against `required_version`.
fn required_verifier_vectors() -> Value {
    let cases: Vec<Value> = cases()
        .into_iter()
        .map(|case| {
            let label = &case.label;
            match (&case.outcome, required_version(case.body.as_bytes())) {
                (Outcome::Needs(want), Ok(got)) => {
                    assert_eq!(got.map(|r| (r.action, r.minimum_version)), *want, "{label}");
                    let body: Value = serde_json::from_str(&case.body).unwrap();
                    assert_eq!(canonical::jcs(&body).unwrap(), case.body, "{label}: JCS");
                }
                (Outcome::Refused(want), Err(got)) => assert_eq!(&got, want, "{label}"),
                (want, got) => panic!("{label}: {want:?} written here, {got:?} given"),
            }
            let mut out = json!({"label": case.label, "body_json": case.body});
            match case.outcome {
                Outcome::Needs(requirement) => {
                    out["requirement"] = requirement.map_or(
                        Value::Null,
                        |(action, version)| json!({"action": action, "minimum_version": version}),
                    );
                }
                Outcome::Refused(reason) => {
                    out["reject"] = json!(true);
                    out["reason"] = json!(reason.code());
                }
            }
            if let Some(note) = case.note {
                out["note"] = json!(note);
            }
            out
        })
        .collect();
    json!({
        "name": FILE,
        "requires": "r9",
        "kind": "vectors",
        "note": NOTE,
        "cases": cases,
    })
}

/// Writes the file from `required_verifier_vectors`.
#[test]
#[ignore = "writes the required-verifier vectors"]
fn write_required_verifier_vectors() {
    let mut text = serde_json::to_string_pretty(&required_verifier_vectors()).unwrap();
    text.push('\n');
    std::fs::write(fixtures_dir().join(format!("{FILE}.json")), text).unwrap();
}

#[test]
fn required_verifier_file_is_what_the_generator_makes() {
    let file = load(FILE);
    assert_eq!(file["name"], FILE);
    assert_eq!(file["kind"], "vectors");
    assert_eq!(file["requires"], "r9");
    assert_eq!(
        file.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["cases", "kind", "name", "note", "requires"]
    );
    assert_eq!(
        file,
        required_verifier_vectors(),
        "regenerate with write_required_verifier_vectors"
    );
}

/// Every case as the file says: its requirement, or its refusal's reason.
/// The accepted bodies name every action and every scope op this verifier
/// knows, and each delegated action has a refused body too.
#[test]
fn signing_requirements_use_the_strict_membership_parser_and_shared_vectors() {
    let file = load(FILE);
    let mut actions = BTreeSet::new();
    let mut ops = BTreeSet::new();
    let mut refused_actions = BTreeSet::new();
    for case in file["cases"].as_array().unwrap() {
        let label = case["label"].as_str().unwrap();
        let body = case["body_json"].as_str().unwrap();
        let result = required_version(body.as_bytes());
        let parsed: Option<Value> = serde_json::from_str(body).ok();
        if case["reject"] == true {
            assert!(case.get("requirement").is_none(), "{label}");
            assert_eq!(
                result.map_err(|e| e.code()),
                Err(case["reason"].as_str().unwrap()),
                "{label}"
            );
            if let Some(action) = parsed.as_ref().and_then(|b| b["action"].as_str()) {
                refused_actions.insert(action.to_owned());
            }
        } else {
            assert!(case.get("reject").is_none() && case.get("reason").is_none());
            let actual = result
                .unwrap_or_else(|e| panic!("{label}: {e}"))
                .map(|r| json!({"action": r.action, "minimum_version": r.minimum_version}));
            assert_eq!(json!(actual), case["requirement"], "{label}");
            let parsed = parsed.unwrap();
            actions.insert(parsed["action"].as_str().unwrap().to_owned());
            for scope in [&parsed["member"]["scope"], &parsed["scope"]] {
                for op in scope["ops"].as_array().into_iter().flatten() {
                    ops.insert(op.as_str().unwrap().to_owned());
                }
            }
        }
    }
    assert_eq!(
        actions,
        known_actions().iter().map(|a| (*a).to_owned()).collect()
    );
    assert_eq!(ops, OPS.iter().map(|op| (*op).to_owned()).collect());
    for action in DELEGATED {
        assert!(refused_actions.contains(action), "{action}");
    }
}

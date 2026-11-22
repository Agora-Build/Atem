//! Host work through the bindings' exports: a task's `result_id`
//! (`host_work_result_id`, host-work-v1 §11.5, "`result_id`"), the shared
//! core's one derivation, with the known answers of
//! `designs/protocol/fixtures/host-work/requests-v1.json` (`result_ids`),
//! and an app's own check of its reply `answers` cases (a reply answers its
//! `reply_query` only with the asked task's `result_id`; no reply yet
//! always does); the core's request reader (`host_work_request_valid`) over
//! every request case, the owner's ops naming a host sender's selector task
//! (§11.2) among them; and its result correlation
//! (`host_work_result_answers`) over every `answers` case. The Swift,
//! Kotlin and JS suites run the same vectors against the same exports.
use atem_client_ffi::host_work::host_work_result_id;
use serde_json::Value;

fn vectors() -> Value {
    serde_json::from_str(include_str!(
        "../../../designs/protocol/fixtures/host-work/requests-v1.json"
    ))
    .unwrap()
}

#[test]
fn result_ids_match_the_known_answers() {
    let file = vectors();
    let known = file["result_ids"].as_array().unwrap();
    assert_eq!(known.len(), 2);
    for case in known {
        assert_eq!(
            host_work_result_id(case["task_id"].as_str().unwrap().into()),
            case["result_id"].as_str().unwrap(),
            "{}",
            case["name"]
        );
        assert_eq!(
            host_work_result_id(case["task_id"].as_str().unwrap().into()),
            atem_client::session::host_work::result_id(case["task_id"].as_str().unwrap()),
        );
    }
}

/// An app that holds a `reply_query` and its result checks the reply as
/// the core does (`Response::answers`, applied by `ClientConnection` to
/// every result it reads).
#[test]
fn an_app_checks_a_reply_against_its_task() {
    let file = vectors();
    let cases: Vec<&Value> = file["answers"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["result"]["result"]["kind"] == "reply")
        .collect();
    assert_eq!(cases.len(), 3);
    for case in cases {
        let task = case["request"]["data"]["task_id"].as_str().unwrap();
        let reply = &case["result"]["result"]["reply"];
        let answers = reply.is_null()
            || reply["result_id"].as_str() == Some(&host_work_result_id(task.into()));
        assert_eq!(
            answers,
            case["answers"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
}

/// Every request case of the vectors through the bindings' export
/// (`host_work_request_valid`): what the shared core's reader takes, so
/// what `ClientConnection::send_json` seals; the owner's three ops with a
/// host sender's selector task (its UUID v5, host-work-v1 §11.2, §11.5)
/// among the valid, their uppercase, other versions and variants refused,
/// and the other task ops keeping a UUID v4.
#[test]
fn every_request_case_reads_as_the_vectors_say() {
    use atem_client_ffi::host_work::host_work_request_valid;
    let file = vectors();
    let cases = file["cases"].as_array().unwrap();
    for case in cases {
        let text = match case.get("raw") {
            Some(raw) => raw.as_str().unwrap().to_owned(),
            None => case["message"].to_string(),
        };
        assert_eq!(
            host_work_request_valid(text),
            case["valid"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
    for name in [
        "work_query_selector_task",
        "work_interrupt_selector_task",
        "work_resolve_selector_task",
    ] {
        assert!(
            cases
                .iter()
                .any(|c| c["name"] == name && c["valid"] == true),
            "{name}"
        );
    }
    assert!(!host_work_request_valid("not json".into()));
}

/// Every `answers` case through `host_work_result_answers`: the result
/// read as the connection reads it and taken only when it answers the
/// request, a selector task's status answering what named it.
#[test]
fn every_answers_case_correlates_as_the_vectors_say() {
    use atem_client_ffi::host_work::host_work_result_answers;
    let file = vectors();
    let cases = file["answers"].as_array().unwrap();
    assert_eq!(cases.len(), 5);
    for case in cases {
        assert_eq!(
            host_work_result_answers(case["request"].to_string(), case["result"].to_string()),
            case["answers"].as_bool().unwrap(),
            "{}",
            case["name"]
        );
    }
    // A result the reader refuses answers nothing.
    let first = &cases[0];
    let mut bad = first["result"].clone();
    bad["id"] = serde_json::json!("not-a-uuid");
    assert!(!host_work_result_answers(
        first["request"].to_string(),
        bad.to_string()
    ));
}

/// `host_work_result_answers` reads a result as strictly as the connection
/// reads its record (review L1): a duplicate key, whether or not one copy
/// is escaped, anywhere in the result, is no result, so it answers nothing,
/// even when the last copy is the one that would answer.
#[test]
fn a_result_with_a_duplicate_key_answers_nothing() {
    use atem_client_ffi::host_work::host_work_result_answers;
    let file = vectors();
    let case = file["answers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == "work_status_answers_its_selector_task")
        .unwrap();
    let request = case["request"].to_string();
    let text = case["result"].to_string();
    assert!(host_work_result_answers(request.clone(), text.clone()));
    let re = case["result"]["re"].as_str().unwrap();
    let task = case["result"]["result"]["work"]["task_id"]
        .as_str()
        .unwrap();
    let other = "99999999-9999-4999-8999-999999999999";
    for (what, damaged) in [
        (
            "re twice",
            text.replacen(
                &format!(r#""re":"{re}""#),
                &format!(r#""re":"{other}","re":"{re}""#),
                1,
            ),
        ),
        (
            "re twice, one escaped",
            text.replacen(
                &format!(r#""re":"{re}""#),
                &format!(r#""\u0072e":"{other}","re":"{re}""#),
                1,
            ),
        ),
        (
            "the work's task_id twice",
            text.replacen(
                &format!(r#""task_id":"{task}""#),
                &format!(r#""task_id":"{other}","task_id":"{task}""#),
                1,
            ),
        ),
    ] {
        assert_ne!(damaged, text, "{what}");
        assert!(
            serde_json::from_str::<Value>(&damaged).is_ok(),
            "{what}: a lenient reader takes it"
        );
        assert!(
            !host_work_result_answers(request.clone(), damaged),
            "{what}"
        );
    }
}

//! Host work's `result_id` through the bindings' export
//! (`host_work_result_id`, host-work-v1 §11.5, "`result_id`"): the shared
//! core's one derivation, with the known answers of
//! `designs/protocol/fixtures/host-work/requests-v1.json` (`result_ids`),
//! and an app's own check of its `answers` cases (a reply answers its
//! `reply_query` only with the asked task's `result_id`; no reply yet
//! always does). The Swift, Kotlin and JS suites run the same vectors
//! against the same export.
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
    let cases = file["answers"].as_array().unwrap();
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

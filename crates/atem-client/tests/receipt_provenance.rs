//! Receipt provenance (delegated host-work design I.4.2, I.7 item 2;
//! session-v1 R9.14): a receipt of the `host-work` principal's request names
//! the task and the sender that asked, in two optional fields. Every other
//! receipt, the r8 fixtures' included, reads and writes exactly as before.
use std::path::PathBuf;

use atem_client::session::wire::{
    self, Envelope, HOST_WORK_PRINCIPAL, Op, Receipt, ReceiptKind, ReceiptState, SessionMessage,
    Target,
};
use serde_json::{Value, json};

const TASK: &str = "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b";
const REQUEST: &str = "44444444-4444-4444-8444-000000000001";
const MESSAGE: &str = "11111111-1111-4111-8111-000000000904";

fn target() -> Target {
    Target {
        account_id: "account-a".into(),
        atem_device_id: "host-a".into(),
        host_trust_gen: 1,
        session_id: "ses-aaaaaaaaaaaa".into(),
        process_gen: "22222222-2222-4222-8222-222222222222".into(),
    }
}

fn receipt(kind: ReceiptKind, state: ReceiptState) -> Receipt {
    Receipt {
        request_id: REQUEST.into(),
        target: target(),
        kind,
        state,
        detail: None,
        updated_at: 1_760_500_000_000,
        lease: None,
        result: None,
        task_id: None,
        sender: None,
    }
}

fn message(op: Op) -> Value {
    wire::to_value(&Envelope::Session(SessionMessage {
        id: MESSAGE.into(),
        re: None,
        op,
    }))
}

fn decoded(value: &Value) -> Result<Receipt, String> {
    match wire::decode(value.to_string().as_bytes()) {
        Ok(Envelope::Session(SessionMessage {
            op: Op::Receipt(r), ..
        })) => Ok(r),
        Ok(other) => Err(format!("not a receipt: {other:?}")),
        Err(e) => Err(format!("{e:?}")),
    }
}

/// The name is a bare word, like `local`: no principal a channel admits
/// (`member:`, `service:`, `browser:`) or a host sender (`host:`) can be it.
#[test]
fn the_host_work_principal_is_a_bare_word() {
    assert_eq!(HOST_WORK_PRINCIPAL, "host-work");
    assert!(!HOST_WORK_PRINCIPAL.contains(':'));
    assert_ne!(HOST_WORK_PRINCIPAL, "local");
}

/// Both fields travel together on a `prompt` receipt, in every state, and
/// come back as they were sent; the sender is a delegated sender's
/// principal (a native member, a service or a host).
#[test]
fn receipt_provenance_optional_round_trip() {
    for sender in ["service:svc-1", "member:dev-phone", "host:host-b"] {
        for state in [
            ReceiptState::Accepted,
            ReceiptState::Executing,
            ReceiptState::Rejected,
            ReceiptState::OutcomeUnknown,
        ] {
            let mut r = receipt(ReceiptKind::Prompt, state);
            r.task_id = Some(TASK.into());
            r.sender = Some(sender.into());
            if state == ReceiptState::Rejected {
                r.detail = Some("withdrawn by the host".into());
            }
            let sent = message(Op::Receipt(r.clone()));
            assert_eq!(sent["data"]["task_id"], TASK);
            assert_eq!(sent["data"]["sender"], sender);
            assert_eq!(decoded(&sent), Ok(r.clone()), "{sender} {state:?}");
            // Inside a `receipts` reply too.
            let list = message(Op::Receipts {
                receipts: vec![
                    r.clone(),
                    receipt(ReceiptKind::Stop, ReceiptState::Completed),
                ],
            });
            let Ok(Envelope::Session(SessionMessage {
                op: Op::Receipts { receipts },
                ..
            })) = wire::decode(list.to_string().as_bytes())
            else {
                panic!("a receipts reply: {list}");
            };
            assert_eq!(receipts[0], r);
            assert_eq!(receipts[1].task_id, None);
        }
    }
    // Without them: absent on the wire, never `null`.
    let plain = message(Op::Receipt(receipt(
        ReceiptKind::Prompt,
        ReceiptState::Accepted,
    )));
    let data = plain["data"].as_object().unwrap();
    assert!(!data.contains_key("task_id") && !data.contains_key("sender"));
    assert_eq!(decoded(&plain).unwrap().sender, None);

    let good = {
        let mut r = receipt(ReceiptKind::Prompt, ReceiptState::Executing);
        r.task_id = Some(TASK.into());
        r.sender = Some("service:svc-1".into());
        message(Op::Receipt(r))
    };
    let edit = |f: &dyn Fn(&mut serde_json::Map<String, Value>)| {
        let mut v = good.clone();
        f(v["data"].as_object_mut().unwrap());
        decoded(&v)
    };
    assert!(edit(&|_| {}).is_ok());
    // One without the other.
    assert!(edit(&|d| drop(d.remove("sender"))).is_err());
    assert!(edit(&|d| drop(d.remove("task_id"))).is_err());
    // `null` is no value.
    assert!(edit(&|d| drop(d.insert("sender".into(), Value::Null))).is_err());
    assert!(edit(&|d| drop(d.insert("task_id".into(), Value::Null))).is_err());
    // A remote task's id is a UUID v4.
    for bad in [
        "18f208d8-a1d7-5fba-8a53-7fb8f9bc5dc4",
        "not-a-uuid",
        "",
        "6F1C2B3A-4D5E-4F60-8A7B-9C0D1E2F3A4B",
    ] {
        assert!(
            edit(&|d| drop(d.insert("task_id".into(), json!(bad)))).is_err(),
            "{bad}"
        );
    }
    assert!(edit(&|d| drop(d.insert("task_id".into(), json!(7)))).is_err());
    // Only a delegated sender: never `local`, a browser, the host-work
    // principal itself, a bare id, an empty or oversized id.
    let long = format!("service:{}", "a".repeat(129));
    for bad in [
        "local",
        "browser:g-1",
        HOST_WORK_PRINCIPAL,
        "svc-1",
        "service:",
        "host:",
        "member:dev phone",
        long.as_str(),
    ] {
        assert!(
            edit(&|d| drop(d.insert("sender".into(), json!(bad)))).is_err(),
            "{bad}"
        );
    }
    let longest = format!("service:{}", "a".repeat(128));
    assert!(edit(&|d| drop(d.insert("sender".into(), json!(longest)))).is_ok());
    // Only on a `prompt` receipt: the host-work principal submits prompts.
    for kind in ["interrupt", "stop", "approval", "approval_rule_revoke"] {
        assert!(
            edit(&|d| drop(d.insert("kind".into(), json!(kind)))).is_err(),
            "{kind}"
        );
    }
}

/// Every r8 (and r9) fixture's receipt reads and writes exactly as it did:
/// neither field appears, and the message serializes back to the fixture's
/// JSON, key for key. A receipt the host builds without them has neither
/// key, in every kind and state.
#[test]
fn old_receipts_unchanged() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../designs/protocol/fixtures");
    let mut seen = 0;
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "json"))
        .collect();
    files.sort();
    fn walk(value: &Value, found: &mut Vec<Value>) {
        match value {
            Value::Object(o) => {
                let op = o
                    .get("data")
                    .and_then(|d| d.get("op"))
                    .and_then(Value::as_str);
                if o.get("type").and_then(Value::as_str) == Some("session")
                    && matches!(op, Some("receipt" | "receipts"))
                {
                    found.push(value.clone());
                }
                o.values().for_each(|v| walk(v, found));
            }
            Value::Array(a) => a.iter().for_each(|v| walk(v, found)),
            _ => {}
        }
    }
    for file in &files {
        let fixture: Value = serde_json::from_slice(&std::fs::read(file).unwrap()).unwrap();
        let mut found = Vec::new();
        walk(&fixture, &mut found);
        for original in found {
            // Only whole messages have `type` and `data` (an expectation
            // names its paths under `match`), so every one found must decode:
            // a receipt this reader no longer takes is a regression.
            let decoded = wire::decode(original.to_string().as_bytes());
            let Ok(Envelope::Session(msg)) = decoded else {
                panic!("{file:?}: a fixture receipt no longer decodes: {decoded:?}\n{original}");
            };
            let receipts = match &msg.op {
                Op::Receipt(r) => vec![r.clone()],
                Op::Receipts { receipts } => receipts.clone(),
                _ => unreachable!(),
            };
            for r in &receipts {
                assert_eq!((&r.task_id, &r.sender), (&None, &None), "{file:?}");
            }
            assert_eq!(
                wire::to_value(&Envelope::Session(msg)),
                original,
                "{file:?}: the receipt reads and writes back as it was"
            );
            seen += 1;
        }
    }
    // Pinned: a receipt that went missing from the walk would hide a
    // regression as surely as one skipped.
    assert_eq!(seen, 5, "whole receipts in the fixtures");

    let r8_keys = [
        "request_id",
        "target",
        "kind",
        "state",
        "detail",
        "updated_at",
        "lease",
        "result",
    ];
    for kind in [
        ReceiptKind::Prompt,
        ReceiptKind::Interrupt,
        ReceiptKind::Stop,
        ReceiptKind::Approval,
        ReceiptKind::ApprovalRuleRevoke,
    ] {
        for state in [
            ReceiptState::Accepted,
            ReceiptState::Executing,
            ReceiptState::Completed,
            ReceiptState::Rejected,
            ReceiptState::OutcomeUnknown,
        ] {
            let mut r = receipt(kind, state);
            r.detail = Some("done".into());
            let value = serde_json::to_value(&r).unwrap();
            for key in value.as_object().unwrap().keys() {
                assert!(
                    r8_keys.contains(&key.as_str()),
                    "{key} on {kind:?} {state:?}"
                );
            }
        }
    }
}

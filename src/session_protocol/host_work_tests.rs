//! The `host-work` principal (session-v1 R9.14, items 1 and 2): its
//! internal attachment is never fenced, its prompts carry their provenance
//! (`task_id`, `sender`) on every receipt and across restarts, and no other
//! receipt does.

use super::fake_runtime::{AUTHORIZATION_MS, FakeRuntime};
use super::file_journal::FileJournal;
use super::fixtures::{HostEvent, HostUnderTest};
use super::host::*;
use super::journal::{Journal, MemJournal, Record};
use super::wire::{self, ClientKind, HOST_WORK_PRINCIPAL, Permission, ReceiptKind, ReceiptState};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicU64, Ordering};

const S1: &str = "ses-aaaaaaaaaaaa";
const P1: &str = "22222222-2222-4222-8222-222222222222";
const C1: &str = "33333333-3333-4333-8333-333333333333";
const HW: &str = "abababab-abab-4bab-8bab-abababababab";
const HW2: &str = "cdcdcdcd-cdcd-4dcd-8dcd-cdcdcdcdcdcd";
const GEN2: &str = "99999999-9999-4999-8999-999999999999";
const TASK: &str = "5ba7b810-9dad-41d1-80b4-00c04fd430c8";
const TASK2: &str = "6ba7b811-9dad-41d1-80b4-00c04fd430c8";
const SENDER: &str = "member:phone-1";

fn id() -> String {
    static N: AtomicU64 = AtomicU64::new(1);
    format!(
        "11111111-1111-4111-8111-{:012}",
        N.fetch_add(1, Ordering::Relaxed)
    )
}

fn rid(n: u64) -> String {
    format!("44444444-4444-4444-8444-{n:012}")
}

fn setup_json() -> Value {
    let client = |name: &str, att: &str, perms: Value| json!({"name": name, "attachment_gen": att, "permissions": perms, "client_kind": "native"});
    json!({
        "host": {"account_id": "account-a", "atem_device_id": "host-a", "host_trust_gen": 1,
                 "runtime_gen": "55555555-5555-4555-8555-555555555555", "runtime_epoch": 7},
        "sessions": [{"session_id": S1, "process_gen": P1, "chat": true}],
        "clients": [client("c1", C1, json!(["view", "control"])),
                    client("v", "77777777-7777-4777-8777-777777777777", json!(["view"]))]
    })
}

fn setup() -> FakeRuntime {
    FakeRuntime::from_json(setup_json(), HostConfig::default())
}

fn setup_file(dir: &std::path::Path) -> FakeRuntime<FileJournal> {
    let journal = FileJournal::open(&dir.join("state")).unwrap();
    FakeRuntime::from_json_with(setup_json(), HostConfig::default(), journal)
}

fn target() -> Value {
    json!({"account_id": "account-a", "atem_device_id": "host-a", "host_trust_gen": 1,
           "session_id": S1, "process_gen": P1})
}

/// The runtime's internal attachment of the `host-work` principal, made
/// as the runtime makes it: connected with `view` and `control`, welcomed
/// through the internal path (never an r8 `hello`).
fn host_work<J: Journal + super::fake_runtime::FailFsync>(rt: &mut FakeRuntime<J>, att: &str) {
    rt.connect_only(
        HOST_WORK_PRINCIPAL,
        att,
        vec![Permission::View, Permission::Control],
        AUTHORIZATION_MS,
    );
    let now = rt.now();
    rt.host.welcome_r9(att, now).unwrap();
    let fx = rt.host.take_effects();
    rt.apply(fx);
}

fn provenance(task_id: &str, sender: &str) -> Provenance {
    Provenance {
        task_id: task_id.into(),
        sender: sender.into(),
    }
}

/// A session-v1 `submit` (its `data`): a prompt that acquires the lease
/// (session-v1 §F), as host-work submits it.
fn prompt_data(att: &str, n: u64) -> Value {
    json!({"v": 1, "op": "submit", "id": id(),
           "binding": {"target": target(), "attachment_gen": att},
           "request_id": rid(n), "kind": "prompt", "payload": {"text": "run the tests"},
           "acquire": true})
}

fn submit_host_work<J: Journal + super::fake_runtime::FailFsync>(
    rt: &mut FakeRuntime<J>,
    att: &str,
    data: Value,
    provenance: Provenance,
) {
    let fx = rt.host.submit_host_work(att, data, provenance);
    rt.apply(fx);
}

fn got<J: Journal + super::fake_runtime::FailFsync>(
    rt: &mut FakeRuntime<J>,
    client: &str,
) -> Vec<Value> {
    rt.take(client)
        .into_iter()
        .map(|m| m["data"].clone())
        .collect()
}

fn receipts(msgs: &[Value]) -> Vec<Value> {
    msgs.iter()
        .filter(|m| m["op"] == "receipt")
        .cloned()
        .collect()
}

/// The code of the one error among `msgs`.
fn error_code(msgs: &[Value]) -> String {
    let errors: Vec<&Value> = msgs.iter().filter(|m| m["op"] == "error").collect();
    assert_eq!(errors.len(), 1, "{msgs:#?}");
    errors[0]["code"].as_str().unwrap().to_string()
}

fn done() -> DispatchReport {
    DispatchReport::Completed {
        detail: Some("done".into()),
        turn_id: Some("turn-1".into()),
        user_message_id: Some("turn-1-u".into()),
    }
}

/// Every message a client gets decodes with the shared reader, which
/// checks a receipt's provenance rules (both or neither, a prompt only, a
/// delegated sender).
fn decodes(message: &Value) {
    let bytes = serde_json::to_vec(&json!({"type": "session", "data": message})).unwrap();
    wire::decode(&bytes).unwrap_or_else(|e| panic!("{message} does not decode: {e:?}"));
}

#[test]
fn host_work_principal_is_never_fenced_by_a_freeze_or_fault() {
    let mut rt = setup();
    host_work(&mut rt, HW);
    // Accepted work stays queued: a fence would reject it `control revoked`.
    rt.host.hold_dispatch(true);
    submit_host_work(&mut rt, HW, prompt_data(HW, 1), provenance(TASK, SENDER));
    assert_eq!(
        rt.host.receipt(&rid(1)).unwrap().state,
        ReceiptState::Accepted
    );
    assert_eq!(rt.host.lease_holder(S1), Some(HW));
    // It is no remote principal (R9.3, "every remote principal").
    let remote = rt.host.remote_principals();
    assert!(
        !remote.iter().any(|p| p == HOST_WORK_PRINCIPAL),
        "{remote:?}"
    );
    assert!(remote.iter().any(|p| p == "c1"), "{remote:?}");

    // A device-list entry naming it, and a freeze (every remote principal,
    // no entry), pass it by; the others are fenced.
    let fx = rt.host.fence_principal(HOST_WORK_PRINCIPAL, 5);
    rt.apply(fx);
    for p in remote.iter().chain([&HOST_WORK_PRINCIPAL.to_string()]) {
        let fx = rt.host.fence_principal(p, 0);
        rt.apply(fx);
    }
    assert_eq!(rt.host.control_gen(HOST_WORK_PRINCIPAL), 1);
    assert_eq!(rt.host.fence_seq(HOST_WORK_PRINCIPAL), 0);
    assert!(rt.host.control_gen("c1") > 1, "c1 was fenced");
    assert_eq!(rt.host.attachment_principal(C1), None);
    assert_eq!(rt.host.attachment_principal(HW), Some(HOST_WORK_PRINCIPAL));
    assert_eq!(rt.host.lease_holder(S1), Some(HW));
    assert_eq!(
        rt.host.receipt(&rid(1)).unwrap().state,
        ReceiptState::Accepted
    );
    // Its one durable control state: `control` at generation 1, never raised.
    let records = rt.host.journal().load().unwrap();
    let mine: Vec<&Record> = records
        .iter()
        .filter(
            |r| matches!(r, Record::Control { principal, .. } if principal == HOST_WORK_PRINCIPAL),
        )
        .collect();
    assert_eq!(
        mine,
        vec![&Record::Control {
            principal: HOST_WORK_PRINCIPAL.into(),
            control: true,
            control_gen: 1,
            fence_seq: 0,
        }]
    );

    // A device-list fault, naming it or not: the journal halts (the start
    // check stops delegated tasks then), and it keeps everything.
    let fx = rt
        .host
        .membership_fault(Some(&[HOST_WORK_PRINCIPAL.to_string()]));
    rt.apply(fx);
    let fx = rt.host.membership_fault(None);
    rt.apply(fx);
    assert!(rt.host.journal_halted());
    assert_eq!(rt.host.control_gen(HOST_WORK_PRINCIPAL), 1);
    assert_eq!(rt.host.attachment_principal(HW), Some(HOST_WORK_PRINCIPAL));
    assert_eq!(rt.host.lease_holder(S1), Some(HW));
    assert_eq!(
        rt.host.receipt(&rid(1)).unwrap().state,
        ReceiptState::Accepted
    );

    // Before the start's resolution only the durable fence is written:
    // none for it either.
    let ctx = rt.host.context().clone();
    let mut fresh = SessionHost::new(
        ctx,
        HostConfig::default(),
        MemJournal::default(),
        random_ids(),
    )
    .unwrap();
    fresh.fence_principal(HOST_WORK_PRINCIPAL, 3);
    assert_eq!(fresh.control_gen(HOST_WORK_PRINCIPAL), 1);
    assert!(fresh.journal().records().is_empty());

    // It never loses `control`: an attachment of it without `control` is
    // refused.
    let refused = fresh.connect(Attach {
        client: "atem-internal-host-work".into(),
        principal: HOST_WORK_PRINCIPAL.into(),
        attachment_gen: HW2.into(),
        permissions: vec![Permission::View],
        client_kind: ClientKind::Native,
        authorization_ms: AUTHORIZATION_MS,
    });
    assert!(refused.is_err());
    assert_eq!(fresh.attachment_principal(HW2), None);
}

#[test]
fn host_work_receipts_carry_task_id_and_sender() {
    let mut rt = setup();
    host_work(&mut rt, HW);
    submit_host_work(&mut rt, HW, prompt_data(HW, 1), provenance(TASK, SENDER));
    // Accepted (with the lease it acquired) and executing: each carries both.
    let mine = receipts(&got(&mut rt, HOST_WORK_PRINCIPAL));
    let states: Vec<&str> = mine.iter().map(|r| r["state"].as_str().unwrap()).collect();
    assert_eq!(states, ["accepted", "executing"], "{mine:#?}");
    assert!(mine[0]["lease"].is_object(), "{}", mine[0]);
    for r in &mine {
        assert_eq!(r["task_id"], TASK, "{r}");
        assert_eq!(r["sender"], SENDER, "{r}");
        decodes(r);
    }
    // A viewer that names the request sees them too.
    let query = json!({"type": "session", "data": {"v": 1, "op": "receipt_query", "id": id(),
        "binding": {"target": target(), "attachment_gen": rt.attachment("v")},
        "request_ids": [rid(1)]}});
    got(&mut rt, "v");
    rt.send("v", &query);
    let answer = got(&mut rt, "v");
    assert_eq!(answer.len(), 1, "{answer:#?}");
    assert_eq!(answer[0]["receipts"][0]["task_id"], TASK);
    assert_eq!(answer[0]["receipts"][0]["sender"], SENDER);
    decodes(&answer[0]);
    // Completed: unchanged, admission metadata never moves.
    let fx = rt.host.dispatch_report(&rid(1), done());
    rt.apply(fx);
    let r = rt.host.receipt(&rid(1)).unwrap();
    assert_eq!(r.state, ReceiptState::Completed);
    assert_eq!(
        (r.task_id.as_deref(), r.sender.as_deref()),
        (Some(TASK), Some(SENDER))
    );
    // Each delegated sender form: a service and a host sender.
    for (n, sender) in [(2, "service:svc-1"), (3, "host:host-b")] {
        submit_host_work(&mut rt, HW, prompt_data(HW, n), provenance(TASK2, sender));
        let r = rt.host.receipt(&rid(n)).unwrap();
        assert_eq!(r.sender.as_deref(), Some(sender));
        assert_eq!(r.task_id.as_deref(), Some(TASK2));
        let fx = rt.host.dispatch_report(&rid(n), done());
        rt.apply(fx);
    }
    got(&mut rt, HOST_WORK_PRINCIPAL);

    // Refused, nothing recorded: a provenance that breaks the rules (no
    // UUID v4 task, a sender that is no delegated sender) …
    let bad = [
        provenance("not-a-uuid", SENDER),
        provenance(TASK, "local"),
        provenance(TASK, "browser:g-1"),
        provenance(TASK, HOST_WORK_PRINCIPAL),
        provenance(TASK, "member:"),
        provenance(TASK, "member:a b"),
    ];
    for (i, p) in bad.into_iter().enumerate() {
        let n = 10 + i as u64;
        submit_host_work(&mut rt, HW, prompt_data(HW, n), p);
        assert!(rt.host.receipt(&rid(n)).is_none(), "case {i}");
        let msgs = got(&mut rt, HOST_WORK_PRINCIPAL);
        assert_eq!(error_code(&msgs), "invalid_request", "case {i}");
    }
    // … a kind other than a prompt …
    let mut interrupt = prompt_data(HW, 20);
    interrupt["kind"] = json!("interrupt");
    interrupt["payload"] = json!({});
    interrupt.as_object_mut().unwrap().remove("acquire");
    interrupt["binding"]["lease_epoch"] = json!(rt.host.lease_epoch(S1).unwrap());
    submit_host_work(&mut rt, HW, interrupt, provenance(TASK, SENDER));
    assert!(rt.host.receipt(&rid(20)).is_none());
    assert_eq!(
        error_code(&got(&mut rt, HOST_WORK_PRINCIPAL)),
        "invalid_request"
    );
    // … a takeover (it acquires only while nobody holds the lease) …
    let mut takeover = prompt_data(HW, 23);
    takeover["takeover"] = json!(true);
    takeover["expected_controller"] =
        json!({"controller_session": "abababab-abab-4bab-8bab-000000000001", "lease_epoch": 1});
    submit_host_work(&mut rt, HW, takeover, provenance(TASK, SENDER));
    assert!(rt.host.receipt(&rid(23)).is_none());
    assert_eq!(
        error_code(&got(&mut rt, HOST_WORK_PRINCIPAL)),
        "invalid_request"
    );
    // … a prompt of the host-work principal without provenance (the plain
    // session path) …
    let plain = json!({"type": "session", "data": prompt_data(HW, 21)});
    rt.send(HOST_WORK_PRINCIPAL, &plain);
    assert!(rt.host.receipt(&rid(21)).is_none());
    assert_eq!(
        error_code(&got(&mut rt, HOST_WORK_PRINCIPAL)),
        "invalid_request"
    );
    // … and provenance on another principal's attachment.
    got(&mut rt, "c1");
    submit_host_work(&mut rt, C1, prompt_data(C1, 22), provenance(TASK, SENDER));
    assert!(rt.host.receipt(&rid(22)).is_none());
    assert_eq!(error_code(&got(&mut rt, "c1")), "invalid_request");
}

#[test]
fn other_receipts_carry_no_provenance() {
    let dir = tempfile::tempdir().unwrap();
    let mut rt = setup_file(dir.path());
    host_work(&mut rt, HW);
    // c1's prompt and interrupt, with a host-work attachment present.
    let acquire = json!({"type": "session", "data": {"v": 1, "op": "acquire", "id": id(),
        "binding": {"target": target(), "attachment_gen": C1}, "takeover": false}});
    rt.send("c1", &acquire);
    let lease = got(&mut rt, "c1")
        .into_iter()
        .find(|m| m["op"] == "lease")
        .unwrap();
    let epoch = lease["binding"]["lease_epoch"].as_u64().unwrap();
    for (n, kind, payload) in [
        (1, "prompt", json!({"text": "run the tests"})),
        (2, "interrupt", json!({})),
    ] {
        let m = json!({"type": "session", "data": {"v": 1, "op": "submit", "id": id(),
            "binding": {"target": target(), "attachment_gen": C1, "lease_epoch": epoch},
            "request_id": rid(n), "kind": kind, "payload": payload}});
        rt.send("c1", &m);
    }
    let fx = rt.host.dispatch_report(&rid(1), done());
    rt.apply(fx);
    let mine = receipts(&got(&mut rt, "c1"));
    assert!(mine.len() >= 4, "{mine:#?}");
    for r in &mine {
        let keys: Vec<&String> = r.as_object().unwrap().keys().collect();
        assert!(
            !keys.iter().any(|k| *k == "task_id" || *k == "sender"),
            "{r}"
        );
        decodes(r);
    }
    for n in [1, 2] {
        let r = rt.host.receipt(&rid(n)).unwrap();
        assert_eq!((r.task_id, r.sender), (None, None));
    }
    // On disk: written as before, no provenance field.
    let log = std::fs::read_to_string(dir.path().join(format!("state/receipts/{S1}.log"))).unwrap();
    assert!(log.contains(&rid(1)));
    assert!(!log.contains("provenance"), "{log}");
    // Read back from the disk: none.
    let records = rt.host.journal().load().unwrap();
    assert!(records.iter().all(|r| match r {
        Record::Accepted { provenance, .. } => provenance.is_none(),
        _ => true,
    }));
}

#[test]
fn provenance_survives_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let mut rt = setup_file(dir.path());
    host_work(&mut rt, HW);
    // One that ran (its payload compacted away), one still accepted.
    submit_host_work(&mut rt, HW, prompt_data(HW, 1), provenance(TASK, SENDER));
    let fx = rt.host.dispatch_report(&rid(1), done());
    rt.apply(fx);
    rt.host.hold_dispatch(true);
    submit_host_work(
        &mut rt,
        HW,
        prompt_data(HW, 2),
        provenance(TASK2, "service:svc-1"),
    );
    let want = |n: u64| match n {
        1 => (Some(TASK.to_string()), Some(SENDER.to_string())),
        _ => (Some(TASK2.to_string()), Some("service:svc-1".to_string())),
    };
    for n in [1, 2] {
        let r = rt.host.receipt(&rid(n)).unwrap();
        assert_eq!((r.task_id, r.sender), want(n), "{n}");
    }
    let log = std::fs::read_to_string(dir.path().join(format!("state/receipts/{S1}.log"))).unwrap();
    assert!(log.contains(&format!("\"task_id\":\"{TASK}\"")), "{log}");

    // An orderly restart over the same journal.
    let now = rt.now();
    rt.event(
        &HostEvent::RestartRuntime {
            runtime_gen: GEN2.into(),
            runtime_epoch: 8,
        },
        now,
    )
    .unwrap();
    for n in [1, 2] {
        let r = rt.host.receipt(&rid(n)).unwrap();
        assert_eq!((r.task_id, r.sender), want(n), "{n} after a restart");
    }
    // A new process over the files, after a compaction of every log.
    rt.host.journal_mut().compact_all().unwrap();
    drop(rt);
    let journal = FileJournal::open(&dir.path().join("state")).unwrap();
    let ctx = HostContext {
        account_id: "account-a".into(),
        atem_device_id: "host-a".into(),
        host_trust_gen: 1,
        runtime_gen: GEN2.into(),
        runtime_epoch: 9,
    };
    let host = SessionHost::new(ctx, HostConfig::default(), journal, random_ids()).unwrap();
    for n in [1, 2] {
        let r = host.receipt(&rid(n)).unwrap();
        assert_eq!((r.task_id, r.sender), want(n), "{n} in a new process");
        assert_eq!(r.kind, ReceiptKind::Prompt);
    }
}

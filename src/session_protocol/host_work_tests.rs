//! The `host-work` principal (session-v1 R9.14): its internal attachment
//! is never fenced, its prompts carry their provenance (`task_id`,
//! `sender`) on every receipt and across restarts, and no other receipt
//! does (items 1, 2); its requests start only after the start check, in
//! the step that makes them `executing`, and it may withdraw them (items 3,
//! 4); a `request_id` recorded under another submitter is
//! `request_id_reused` when either is the host-work principal (item 7).

use super::canonical;
use super::fake_runtime::{AUTHORIZATION_MS, FailFsync, FakeRuntime};
use super::file_journal::FileJournal;
use super::fixtures::{HostEvent, HostUnderTest};
use super::host::*;
use super::journal::{Journal, MemJournal, Record};
use super::wire::{
    self, ClientKind, HOST_WORK_PRINCIPAL, Permission, ReceiptKind, ReceiptState, Target,
};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

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
/// through the internal path (never an r8 `hello`), with a start check
/// that lets every request start (R9.14 item 3: without one, none does).
fn host_work<J: Journal + super::fake_runtime::FailFsync>(rt: &mut FakeRuntime<J>, att: &str) {
    connect_host_work(rt, att);
    rt.host.set_start_check(Box::new(StartVerdict::Go));
}

/// The internal attachment alone: no start check installed.
fn connect_host_work<J: Journal + super::fake_runtime::FailFsync>(
    rt: &mut FakeRuntime<J>,
    att: &str,
) {
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

// ── The start check, withdrawal, and `request_id_reused` across submitters
//    (session-v1 R9.14 items 3, 4 and 7) ──

const V: &str = "77777777-7777-4777-8777-777777777777";
const C2: &str = "88888888-8888-4888-8888-888888888888";
const GEN3: &str = "aaaaaaaa-9999-4999-8999-999999999999";

/// What a start check was asked: the request, its session and process,
/// and its provenance.
type Asked = (String, String, String, Provenance);

/// A start check whose verdict the test sets; it records what it was
/// asked.
#[derive(Clone)]
struct Verdicts(Arc<Mutex<(StartVerdict, Vec<Asked>)>>);

impl Verdicts {
    fn new(verdict: StartVerdict) -> Self {
        Self(Arc::new(Mutex::new((verdict, Vec::new()))))
    }

    fn set(&self, verdict: StartVerdict) {
        self.0.lock().unwrap().0 = verdict;
    }

    fn asked(&self) -> Vec<Asked> {
        self.0.lock().unwrap().1.clone()
    }
}

impl StartCheck for Verdicts {
    fn check(&self, req: &StartRequest<'_>) -> StartVerdict {
        let mut state = self.0.lock().unwrap();
        state.1.push((
            req.request_id.to_string(),
            req.session_id.to_string(),
            req.process_gen.to_string(),
            req.provenance.clone(),
        ));
        state.0
    }
}

fn asked(n: u64) -> Asked {
    (
        rid(n),
        S1.to_string(),
        P1.to_string(),
        provenance(TASK, SENDER),
    )
}

fn states(receipts: &[Value]) -> Vec<String> {
    receipts
        .iter()
        .map(|r| r["state"].as_str().unwrap().to_string())
        .collect()
}

/// Whether the host ever asked the runtime to perform `request_id`.
fn dispatched<J: Journal>(rt: &FakeRuntime<J>, request_id: &str) -> bool {
    rt.effects
        .iter()
        .any(|e| matches!(e, Effect::Dispatch { request_id: r, .. } if r == request_id))
}

fn log_path(dir: &Path) -> PathBuf {
    dir.join(format!("state/receipts/{S1}.log"))
}

/// What `request_id`'s records on disk say, in order: `accepted`, then
/// each transition's state (with its detail, if any).
fn logged(log: &Path, request_id: &str) -> Vec<String> {
    let log = std::fs::read_to_string(log).unwrap_or_default();
    log.lines()
        .map(|line| line.splitn(3, ' ').nth(2).unwrap())
        .map(|json| serde_json::from_str::<Value>(json).unwrap())
        .filter(|r| r["request_id"] == request_id)
        .map(|r| match r["t"].as_str().unwrap() {
            "transition" => format!(
                "{}{}",
                r["state"].as_str().unwrap(),
                r["detail"]
                    .as_str()
                    .map(|d| format!(": {d}"))
                    .unwrap_or_default()
            ),
            t => t.to_string(),
        })
        .collect()
}

/// The immutable values (§6) of `prompt_data(_, n)`'s request, with the
/// attempt's provenance, as host-work keeps them for a withdrawal.
fn immutable() -> Immutable {
    Immutable {
        target: serde_json::from_value::<Target>(target()).unwrap(),
        payload_digest: canonical::payload_digest(&json!({"text": "run the tests"})).unwrap(),
        provenance: provenance(TASK, SENDER),
    }
}

/// `client` (attachment `att`) submits a prompt that acquires the lease,
/// as `prompt_data` writes it, on the plain session path.
fn client_prompt<J: Journal + FailFsync>(rt: &mut FakeRuntime<J>, client: &str, att: &str, n: u64) {
    rt.send(
        client,
        &json!({"type": "session", "data": prompt_data(att, n)}),
    );
}

/// The lease holder (the host-work attachment, here) releases it, as the
/// runtime does at its next pass once the turn ended.
fn release_host_work<J: Journal + FailFsync>(rt: &mut FakeRuntime<J>, att: &str) {
    let now = rt.now();
    rt.host.release(att, S1, now).unwrap();
    let fx = rt.host.take_effects();
    rt.apply(fx);
}

fn restart<J: Journal + FailFsync>(rt: &mut FakeRuntime<J>, runtime_gen: &str, runtime_epoch: u64) {
    let now = rt.now();
    rt.event(
        &HostEvent::RestartRuntime {
            runtime_gen: runtime_gen.into(),
            runtime_epoch,
        },
        now,
    )
    .unwrap();
}

fn withdraw<J: Journal + FailFsync>(rt: &mut FakeRuntime<J>, n: u64) -> Withdrawal {
    let w = rt.host.withdraw(&rid(n), &immutable());
    let fx = rt.host.take_effects();
    rt.apply(fx);
    w
}

/// A new process over the journal in `dir` (after compacting every log):
/// what the disk says.
fn reopened(dir: &Path) -> SessionHost<FileJournal> {
    let mut journal = FileJournal::open(&dir.join("state")).unwrap();
    journal.compact_all().unwrap();
    drop(journal);
    let journal = FileJournal::open(&dir.join("state")).unwrap();
    let ctx = HostContext {
        account_id: "account-a".into(),
        atem_device_id: "host-a".into(),
        host_trust_gen: 1,
        runtime_gen: GEN3.into(),
        runtime_epoch: 20,
    };
    SessionHost::new(ctx, HostConfig::default(), journal, random_ids()).unwrap()
}

#[test]
fn start_check_withdraw_rejects_withdrawn_by_the_host_before_any_effect() {
    let dir = tempfile::tempdir().unwrap();
    let mut rt = setup_file(dir.path());
    connect_host_work(&mut rt, HW);
    let check = Verdicts::new(StartVerdict::Withdraw);
    rt.host.set_start_check(Box::new(check.clone()));
    submit_host_work(&mut rt, HW, prompt_data(HW, 1), provenance(TASK, SENDER));

    // Accepted (with the lease it acquired, §F), then rejected at its
    // start: never executing.
    let mine = receipts(&got(&mut rt, HOST_WORK_PRINCIPAL));
    assert_eq!(states(&mine), ["accepted", "rejected"], "{mine:#?}");
    assert_eq!(DETAIL_WITHDRAWN_BY_HOST, "withdrawn by the host");
    assert_eq!(mine[1]["detail"], DETAIL_WITHDRAWN_BY_HOST);
    for r in &mine {
        assert_eq!(r["task_id"], TASK, "{r}");
        assert_eq!(r["sender"], SENDER, "{r}");
        decodes(r);
    }
    assert_eq!(check.asked(), vec![asked(1)]);
    // Before any effect: nothing dispatched, nothing written to the agent.
    assert!(!dispatched(&rt, &rid(1)));
    assert_eq!(rt.pty.dispatch_attempts, 0);
    assert!(
        !rt.effects
            .iter()
            .any(|e| matches!(e, Effect::PtyWrite { .. }))
    );
    // Durable: accepted, then rejected with the detail; never executing.
    assert_eq!(
        logged(&log_path(dir.path()), &rid(1)),
        ["accepted", "rejected: withdrawn by the host"]
    );

    // Another principal's work never asks it: c1's prompt runs.
    release_host_work(&mut rt, HW);
    client_prompt(&mut rt, "c1", C1, 2);
    assert_eq!(
        rt.host.receipt(&rid(2)).unwrap().state,
        ReceiptState::Executing
    );
    assert!(dispatched(&rt, &rid(2)));
    assert_eq!(check.asked().len(), 1);
}

/// Each request a check was asked about, with its records on disk then.
type Seen = Arc<Mutex<Vec<(String, Vec<String>)>>>;

/// A start check that reads the journal on disk when it is asked, so the
/// test sees where in the step it runs.
struct ReadsTheLog {
    log: PathBuf,
    verdicts: Verdicts,
    seen: Seen,
}

impl StartCheck for ReadsTheLog {
    fn check(&self, req: &StartRequest<'_>) -> StartVerdict {
        let on_disk = logged(&self.log, req.request_id);
        self.seen
            .lock()
            .unwrap()
            .push((req.request_id.to_string(), on_disk));
        self.verdicts.check(req)
    }
}

#[test]
fn start_check_runs_in_the_same_step_as_executing() {
    let dir = tempfile::tempdir().unwrap();
    let mut rt = setup_file(dir.path());
    connect_host_work(&mut rt, HW);
    let verdicts = Verdicts::new(StartVerdict::Go);
    let seen = Seen::default();
    rt.host.set_start_check(Box::new(ReadsTheLog {
        log: log_path(dir.path()),
        verdicts: verdicts.clone(),
        seen: seen.clone(),
    }));
    submit_host_work(&mut rt, HW, prompt_data(HW, 1), provenance(TASK, SENDER));
    assert_eq!(
        rt.host.receipt(&rid(1)).unwrap().state,
        ReceiptState::Executing
    );

    // Admitted behind that turn while the check would refuse it: it isn't
    // asked at admission, only at its start.
    verdicts.set(StartVerdict::Withdraw);
    submit_host_work(&mut rt, HW, prompt_data(HW, 2), provenance(TASK, SENDER));
    assert_eq!(
        rt.host.receipt(&rid(2)).unwrap().state,
        ReceiptState::Accepted
    );
    assert_eq!(verdicts.asked(), vec![asked(1)]);
    verdicts.set(StartVerdict::Go);

    // The turn ends. In that one step the check is asked while the request
    // is `accepted` on disk and not yet `executing`; then it is `executing`
    // and dispatched, in the effects of the same call.
    let fx = rt.host.dispatch_report(&rid(1), done());
    assert!(
        fx.iter()
            .any(|e| matches!(e, Effect::Dispatch { request_id, .. } if *request_id == rid(2))),
        "{fx:#?}"
    );
    rt.apply(fx);
    assert_eq!(verdicts.asked(), vec![asked(1), asked(2)]);
    assert_eq!(
        seen.lock().unwrap().last().unwrap(),
        &(rid(2), vec!["accepted".to_string()])
    );
    assert_eq!(
        logged(&log_path(dir.path()), &rid(2)),
        ["accepted", "executing"]
    );

    // Refused at the same point: rejected in that step, never executing.
    submit_host_work(&mut rt, HW, prompt_data(HW, 3), provenance(TASK, SENDER));
    verdicts.set(StartVerdict::Withdraw);
    let fx = rt.host.dispatch_report(&rid(2), done());
    assert!(
        !fx.iter()
            .any(|e| matches!(e, Effect::Dispatch { request_id, .. } if *request_id == rid(3))),
        "{fx:#?}"
    );
    rt.apply(fx);
    assert_eq!(
        seen.lock().unwrap().last().unwrap(),
        &(rid(3), vec!["accepted".to_string()])
    );
    assert_eq!(
        logged(&log_path(dir.path()), &rid(3)),
        ["accepted", "rejected: withdrawn by the host"]
    );
    assert!(!dispatched(&rt, &rid(3)));
}

/// What the runtime's views hold (Decision 16): updated at the moment what
/// they show commits, read by the start check when it is asked.
#[derive(Default)]
struct Views {
    frozen: bool,
}

struct ListCheck {
    views: Arc<Mutex<Views>>,
    /// Each request asked about, with whether the list was frozen then.
    saw: Arc<Mutex<Vec<(String, bool)>>>,
}

impl StartCheck for ListCheck {
    fn check(&self, req: &StartRequest<'_>) -> StartVerdict {
        let frozen = self.views.lock().unwrap().frozen;
        self.saw
            .lock()
            .unwrap()
            .push((req.request_id.to_string(), frozen));
        if frozen {
            StartVerdict::Withdraw
        } else {
            StartVerdict::Go
        }
    }
}

#[test]
fn a_freeze_committed_in_the_same_call_chain_is_seen_by_the_start_check() {
    let mut rt = setup();
    connect_host_work(&mut rt, HW);
    let views = Arc::new(Mutex::new(Views::default()));
    let saw = Arc::new(Mutex::new(Vec::new()));
    rt.host.set_start_check(Box::new(ListCheck {
        views: views.clone(),
        saw: saw.clone(),
    }));
    submit_host_work(&mut rt, HW, prompt_data(HW, 1), provenance(TASK, SENDER));
    submit_host_work(&mut rt, HW, prompt_data(HW, 2), provenance(TASK, SENDER));
    assert_eq!(
        rt.host.receipt(&rid(2)).unwrap().state,
        ReceiptState::Accepted
    );

    // One call chain, with no pass of host-work's in it: a device-list
    // freeze commits (R9.4), updating the views at once and fencing every
    // remote principal as `MembershipHost`'s freeze does; then the turn
    // holding the session ends, and the attempt waiting `accepted` starts.
    let commit_freeze_then_end_turn = |rt: &mut FakeRuntime| {
        views.lock().unwrap().frozen = true;
        for p in rt.host.remote_principals() {
            let fx = rt.host.fence_principal(&p, 0);
            rt.apply(fx);
        }
        let fx = rt.host.dispatch_report(&rid(1), done());
        rt.apply(fx);
    };
    commit_freeze_then_end_turn(&mut rt);

    // The check saw the freeze (condition 2a): withdrawn, never dispatched.
    assert_eq!(*saw.lock().unwrap(), vec![(rid(1), false), (rid(2), true)]);
    let r = rt.host.receipt(&rid(2)).unwrap();
    assert_eq!(r.state, ReceiptState::Rejected);
    assert_eq!(r.detail.as_deref(), Some(DETAIL_WITHDRAWN_BY_HOST));
    assert!(!dispatched(&rt, &rid(2)));
    // The check stopped it, not a fence: the host-work principal keeps
    // `control` at generation 1, the remote one was fenced.
    assert_eq!(rt.host.control_gen(HOST_WORK_PRINCIPAL), 1);
    assert!(rt.host.control_gen("c1") > 1);
}

#[test]
fn no_start_check_installed_withdraws() {
    let mut rt = setup();
    connect_host_work(&mut rt, HW);
    submit_host_work(&mut rt, HW, prompt_data(HW, 1), provenance(TASK, SENDER));
    let mine = receipts(&got(&mut rt, HOST_WORK_PRINCIPAL));
    assert_eq!(states(&mine), ["accepted", "rejected"], "{mine:#?}");
    assert_eq!(mine[1]["detail"], DETAIL_WITHDRAWN_BY_HOST);
    assert!(!dispatched(&rt, &rid(1)));
    assert_eq!(rt.pty.dispatch_attempts, 0);

    // Every other principal's work runs as before, with no check at all.
    release_host_work(&mut rt, HW);
    client_prompt(&mut rt, "c1", C1, 2);
    assert_eq!(
        rt.host.receipt(&rid(2)).unwrap().state,
        ReceiptState::Executing
    );
    assert!(dispatched(&rt, &rid(2)));
}

#[test]
fn withdraw_accepted_rejects_durably() {
    let dir = tempfile::tempdir().unwrap();
    let mut rt = setup_file(dir.path());
    host_work(&mut rt, HW);
    rt.host.hold_dispatch(true);
    submit_host_work(&mut rt, HW, prompt_data(HW, 1), provenance(TASK, SENDER));
    assert_eq!(
        rt.host.receipt(&rid(1)).unwrap().state,
        ReceiptState::Accepted
    );
    got(&mut rt, HOST_WORK_PRINCIPAL);

    assert_eq!(withdraw(&mut rt, 1), Withdrawal::Rejected);
    // Durable before it returned, and reported to its submitter.
    assert_eq!(
        logged(&log_path(dir.path()), &rid(1)),
        ["accepted", "rejected: withdrawn by the host"]
    );
    let mine = receipts(&got(&mut rt, HOST_WORK_PRINCIPAL));
    assert_eq!(states(&mine), ["rejected"], "{mine:#?}");
    assert_eq!(mine[0]["detail"], DETAIL_WITHDRAWN_BY_HOST);
    assert_eq!(mine[0]["task_id"], TASK);
    decodes(&mine[0]);

    // It never runs: the queue goes on past it.
    rt.host.hold_dispatch(false);
    submit_host_work(&mut rt, HW, prompt_data(HW, 2), provenance(TASK2, SENDER));
    assert_eq!(
        rt.host.receipt(&rid(2)).unwrap().state,
        ReceiptState::Executing
    );
    assert!(!dispatched(&rt, &rid(1)));

    // Withdrawn again: still `Rejected`, nothing written.
    let before = rt.host.journal().load().unwrap().len();
    assert_eq!(withdraw(&mut rt, 1), Withdrawal::Rejected);
    assert_eq!(rt.host.journal().load().unwrap().len(), before);

    // What the disk says, in a new process.
    drop(rt);
    let host = reopened(dir.path());
    let r = host.receipt(&rid(1)).unwrap();
    assert_eq!(r.state, ReceiptState::Rejected);
    assert_eq!(r.detail.as_deref(), Some(DETAIL_WITHDRAWN_BY_HOST));
    assert_eq!(
        (r.task_id.as_deref(), r.sender.as_deref()),
        (Some(TASK), Some(SENDER))
    );
}

#[test]
fn withdraw_absent_lists_it_and_a_late_submit_gets_the_rejected_receipt() {
    let dir = tempfile::tempdir().unwrap();
    let mut rt = setup_file(dir.path());
    host_work(&mut rt, HW);

    assert_eq!(withdraw(&mut rt, 1), Withdrawal::Listed);
    // On the refusal list: its immutable values, the detail and the
    // attempt's provenance. Nothing in the journal's log.
    let listed = rt.host.journal().refusals().unwrap();
    assert_eq!(listed.len(), 1, "{listed:#?}");
    let entry = &listed[0];
    let imm = immutable();
    assert_eq!(entry.request_id, rid(1));
    assert_eq!(entry.target, imm.target);
    assert_eq!(entry.kind, ReceiptKind::Prompt);
    assert_eq!(entry.payload_digest, imm.payload_digest);
    assert_eq!(entry.detail.as_deref(), Some(DETAIL_WITHDRAWN_BY_HOST));
    assert_eq!(entry.provenance, Some(provenance(TASK, SENDER)));
    assert!(rt.host.receipt(&rid(1)).is_none());
    assert!(logged(&log_path(dir.path()), &rid(1)).is_empty());
    // Withdrawn again: still listed, once.
    assert_eq!(withdraw(&mut rt, 1), Withdrawal::Listed);
    assert_eq!(rt.host.journal().refusals().unwrap().len(), 1);

    // A late submit of it gets that rejected receipt instead of running:
    // no lease, nothing dispatched, nothing recorded.
    submit_host_work(&mut rt, HW, prompt_data(HW, 1), provenance(TASK, SENDER));
    let mine = receipts(&got(&mut rt, HOST_WORK_PRINCIPAL));
    assert_eq!(states(&mine), ["rejected"], "{mine:#?}");
    assert_eq!(mine[0]["detail"], DETAIL_WITHDRAWN_BY_HOST);
    assert_eq!(mine[0]["task_id"], TASK);
    assert_eq!(mine[0]["sender"], SENDER);
    assert!(mine[0].get("lease").is_none(), "{}", mine[0]);
    decodes(&mine[0]);
    assert_eq!(rt.host.lease_holder(S1), None);
    assert!(!dispatched(&rt, &rid(1)));
    assert!(logged(&log_path(dir.path()), &rid(1)).is_empty());
    // With another payload: `request_id_reused`.
    let mut other = prompt_data(HW, 1);
    other["payload"]["text"] = json!("something else");
    submit_host_work(&mut rt, HW, other, provenance(TASK, SENDER));
    assert_eq!(
        error_code(&got(&mut rt, HOST_WORK_PRINCIPAL)),
        "request_id_reused"
    );
    // From another submitter, every value equal: `request_id_reused`
    // (item 7), and no lease.
    got(&mut rt, "c1");
    client_prompt(&mut rt, "c1", C1, 1);
    assert_eq!(error_code(&got(&mut rt, "c1")), "request_id_reused");
    assert_eq!(rt.host.lease_holder(S1), None);

    // A restart records it, with the same detail and provenance.
    restart(&mut rt, GEN2, 8);
    let r = rt.host.receipt(&rid(1)).unwrap();
    assert_eq!(r.state, ReceiptState::Rejected);
    assert_eq!(r.detail.as_deref(), Some(DETAIL_WITHDRAWN_BY_HOST));
    assert_eq!(
        (r.task_id.as_deref(), r.sender.as_deref()),
        (Some(TASK), Some(SENDER))
    );
    assert!(rt.host.journal().refusals().unwrap().is_empty());
    // A late submit after it: the recorded receipt.
    host_work(&mut rt, HW2);
    submit_host_work(&mut rt, HW2, prompt_data(HW2, 1), provenance(TASK, SENDER));
    let mine = receipts(&got(&mut rt, HOST_WORK_PRINCIPAL));
    assert_eq!(states(&mine), ["rejected"], "{mine:#?}");
    assert_eq!(mine[0]["detail"], DETAIL_WITHDRAWN_BY_HOST);
    assert!(!dispatched(&rt, &rid(1)));
}

#[test]
fn withdraw_executing_reports_started() {
    let mut rt = setup();
    host_work(&mut rt, HW);
    submit_host_work(&mut rt, HW, prompt_data(HW, 1), provenance(TASK, SENDER));
    assert_eq!(
        rt.host.receipt(&rid(1)).unwrap().state,
        ReceiptState::Executing
    );
    got(&mut rt, HOST_WORK_PRINCIPAL);
    let before = rt.host.journal().records().len();
    assert_eq!(withdraw(&mut rt, 1), Withdrawal::Started);
    assert_eq!(
        rt.host.receipt(&rid(1)).unwrap().state,
        ReceiptState::Executing
    );
    assert_eq!(rt.host.journal().records().len(), before);
    assert!(got(&mut rt, HOST_WORK_PRINCIPAL).is_empty());
    // Past `executing`, the same.
    let fx = rt.host.dispatch_report(&rid(1), done());
    rt.apply(fx);
    assert_eq!(withdraw(&mut rt, 1), Withdrawal::Started);
    assert_eq!(
        rt.host.receipt(&rid(1)).unwrap().state,
        ReceiptState::Completed
    );
}

#[test]
fn a_failed_withdrawal_write_halts_the_journal() {
    // Still `accepted`, and its rejection can't be written.
    let dir = tempfile::tempdir().unwrap();
    let mut rt = setup_file(dir.path());
    host_work(&mut rt, HW);
    rt.host.hold_dispatch(true);
    submit_host_work(&mut rt, HW, prompt_data(HW, 1), provenance(TASK, SENDER));
    got(&mut rt, HOST_WORK_PRINCIPAL);
    rt.host.journal_mut().fail_next_fsync();
    assert_eq!(withdraw(&mut rt, 1), Withdrawal::Halted);
    assert!(rt.host.journal_halted());
    assert_eq!(
        rt.host.receipt(&rid(1)).unwrap().state,
        ReceiptState::Accepted
    );
    // Nothing becomes `executing` until the restart, and nothing is
    // admitted.
    rt.host.hold_dispatch(false);
    submit_host_work(&mut rt, HW, prompt_data(HW, 2), provenance(TASK, SENDER));
    assert_eq!(error_code(&got(&mut rt, HOST_WORK_PRINCIPAL)), "busy");
    assert!(!dispatched(&rt, &rid(1)));
    // The restart settles it: rejected, withdrawn by the host.
    restart(&mut rt, GEN2, 8);
    let r = rt.host.receipt(&rid(1)).unwrap();
    assert_eq!(r.state, ReceiptState::Rejected);
    assert_eq!(r.detail.as_deref(), Some(DETAIL_WITHDRAWN_BY_HOST));
    assert_eq!(r.task_id.as_deref(), Some(TASK));
    assert!(!dispatched(&rt, &rid(1)));

    // Not in the journal yet, and the refusal list can't be written.
    let mut rt = setup();
    host_work(&mut rt, HW);
    rt.host.journal_mut().fail_next_refusal();
    assert_eq!(withdraw(&mut rt, 3), Withdrawal::Halted);
    assert!(rt.host.journal_halted());
    submit_host_work(&mut rt, HW, prompt_data(HW, 3), provenance(TASK, SENDER));
    assert_eq!(error_code(&got(&mut rt, HOST_WORK_PRINCIPAL)), "busy");
    assert!(rt.host.receipt(&rid(3)).is_none());
    assert!(!dispatched(&rt, &rid(3)));
}

#[test]
fn request_id_recorded_under_another_submitter_is_reused_both_ways() {
    let mut rt = setup();
    host_work(&mut rt, HW);
    // Recorded under c1, a remote native: the host-work principal's submit
    // with every immutable value equal is `request_id_reused`, and changes
    // nothing.
    client_prompt(&mut rt, "c1", C1, 1);
    assert_eq!(
        rt.host.receipt(&rid(1)).unwrap().state,
        ReceiptState::Executing
    );
    got(&mut rt, "c1");
    submit_host_work(&mut rt, HW, prompt_data(HW, 1), provenance(TASK, SENDER));
    let msgs = got(&mut rt, HOST_WORK_PRINCIPAL);
    assert_eq!(error_code(&msgs), "request_id_reused");
    assert!(receipts(&msgs).is_empty(), "{msgs:#?}");
    let r = rt.host.receipt(&rid(1)).unwrap();
    assert_eq!((r.state, r.task_id), (ReceiptState::Executing, None));
    assert_eq!(rt.host.lease_holder(S1), Some(C1));
    // c1's turn ends and it releases the lease.
    let fx = rt.host.dispatch_report(&rid(1), done());
    rt.apply(fx);
    let epoch = rt.host.lease_epoch(S1).unwrap();
    rt.send(
        "c1",
        &json!({"type": "session", "data": {"v": 1, "op": "release", "id": id(),
            "binding": {"target": target(), "attachment_gen": C1, "lease_epoch": epoch}}}),
    );
    assert_eq!(rt.host.lease_holder(S1), None);

    // Recorded under the host-work principal: c1's submit with every value
    // equal is `request_id_reused`, not its receipt; a viewer's too.
    submit_host_work(&mut rt, HW, prompt_data(HW, 2), provenance(TASK, SENDER));
    assert_eq!(
        rt.host.receipt(&rid(2)).unwrap().state,
        ReceiptState::Executing
    );
    got(&mut rt, "c1");
    client_prompt(&mut rt, "c1", C1, 2);
    let msgs = got(&mut rt, "c1");
    assert_eq!(error_code(&msgs), "request_id_reused");
    assert!(receipts(&msgs).is_empty(), "{msgs:#?}");
    got(&mut rt, "v");
    client_prompt(&mut rt, "v", V, 2);
    assert_eq!(error_code(&got(&mut rt, "v")), "request_id_reused");
    assert_eq!(rt.host.lease_holder(S1), Some(HW));

    // Between other principals nothing changes (§6): a viewer's duplicate
    // of c1's request gets its receipt.
    client_prompt(&mut rt, "v", V, 1);
    let mine = receipts(&got(&mut rt, "v"));
    assert_eq!(states(&mine), ["completed"], "{mine:#?}");
    assert_eq!(mine[0]["request_id"], rid(1));
}

#[test]
fn refusal_entries_keep_their_detail_across_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let mut rt = setup_file(dir.path());
    host_work(&mut rt, HW);
    // A withdrawal of a request not in the journal, then c1's admission
    // write fails (§I.2): two entries, one with the withdrawal's detail.
    assert_eq!(withdraw(&mut rt, 1), Withdrawal::Listed);
    got(&mut rt, "c1");
    rt.host.journal_mut().fail_next_fsync();
    client_prompt(&mut rt, "c1", C1, 2);
    let msgs = got(&mut rt, "c1");
    assert_eq!(error_code(&msgs), "busy");
    assert!(rt.host.journal_halted());
    let listed = rt.host.journal().refusals().unwrap();
    let details: Vec<(String, Option<String>)> = listed
        .iter()
        .map(|r| (r.request_id.clone(), r.detail.clone()))
        .collect();
    assert_eq!(
        details,
        [
            (rid(1), Some(DETAIL_WITHDRAWN_BY_HOST.to_string())),
            (rid(2), None)
        ]
    );
    // On disk, a failed admission write's entry is written as before:
    // neither a detail nor a provenance.
    let file = std::fs::read_to_string(dir.path().join("state/refused")).unwrap();
    assert_eq!(file.matches("\"detail\"").count(), 1, "{file}");
    assert_eq!(file.matches("\"provenance\"").count(), 1, "{file}");

    // The restart resolves each with its own detail.
    restart(&mut rt, GEN2, 8);
    let want = |host: &SessionHost<FileJournal>| {
        let r = host.receipt(&rid(1)).unwrap();
        assert_eq!(r.state, ReceiptState::Rejected);
        assert_eq!(r.detail.as_deref(), Some(DETAIL_WITHDRAWN_BY_HOST));
        assert_eq!(
            (r.task_id.as_deref(), r.sender.as_deref()),
            (Some(TASK), Some(SENDER))
        );
        let r = host.receipt(&rid(2)).unwrap();
        assert_eq!(r.state, ReceiptState::Rejected);
        assert_eq!(r.detail.as_deref(), Some("acceptance not confirmed"));
        assert_eq!((r.task_id, r.sender), (None, None));
    };
    want(&rt.host);
    assert!(rt.host.journal().refusals().unwrap().is_empty());
    // Each submitter's late submit: its own recorded receipt; the other
    // one's is `request_id_reused`.
    host_work(&mut rt, HW2);
    submit_host_work(&mut rt, HW2, prompt_data(HW2, 1), provenance(TASK, SENDER));
    let mine = receipts(&got(&mut rt, HOST_WORK_PRINCIPAL));
    assert_eq!(states(&mine), ["rejected"], "{mine:#?}");
    assert_eq!(mine[0]["detail"], DETAIL_WITHDRAWN_BY_HOST);
    decodes(&mine[0]);
    rt.attach("c1", C2).unwrap();
    client_prompt(&mut rt, "c1", C2, 1);
    assert_eq!(error_code(&got(&mut rt, "c1")), "request_id_reused");
    client_prompt(&mut rt, "c1", C2, 2);
    let theirs = receipts(&got(&mut rt, "c1"));
    assert_eq!(states(&theirs), ["rejected"], "{theirs:#?}");
    assert_eq!(theirs[0]["detail"], "acceptance not confirmed");

    // In a new process, after compaction: the same.
    drop(rt);
    want(&reopened(dir.path()));
}

/// Task 13's review (M2): a `host-work` submit whose admission write fails
/// keeps its provenance on the refusal list, and the receipt the restart
/// resolves carries it.
#[test]
fn a_refused_host_work_admission_keeps_its_provenance_across_a_restart() {
    let dir = tempfile::tempdir().unwrap();
    let mut rt = setup_file(dir.path());
    host_work(&mut rt, HW);
    rt.host.journal_mut().fail_next_fsync();
    submit_host_work(&mut rt, HW, prompt_data(HW, 1), provenance(TASK, SENDER));
    assert_eq!(error_code(&got(&mut rt, HOST_WORK_PRINCIPAL)), "busy");
    let listed = rt.host.journal().refusals().unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].provenance, Some(provenance(TASK, SENDER)));
    assert_eq!(listed[0].detail, None);

    restart(&mut rt, GEN2, 8);
    let want = |host: &SessionHost<FileJournal>| {
        let r = host.receipt(&rid(1)).unwrap();
        assert_eq!(r.state, ReceiptState::Rejected);
        assert_eq!(r.detail.as_deref(), Some("acceptance not confirmed"));
        assert_eq!(
            (r.task_id.as_deref(), r.sender.as_deref()),
            (Some(TASK), Some(SENDER))
        );
        decodes(
            &wire::to_value(&wire::Envelope::Session(wire::SessionMessage {
                id: id(),
                re: None,
                op: wire::Op::Receipt(r),
            }))["data"],
        );
    };
    want(&rt.host);
    drop(rt);
    want(&reopened(dir.path()));
}

// ── Task 14 review fixes (ruling T14a): a bounded refusal list (M1), the
//    `Reused` withdrawal (M3), the start check's unwritten refusal (M4) ──

/// The refusal list's bound in these tests (bytes of JSON, written and
/// read alike): a few entries.
const REFUSAL_LIMIT: usize = 2_000;

/// The JSON length a framed file names (`<len> <crc32> <json>\n`).
fn framed_len(bytes: &[u8]) -> usize {
    let text = std::str::from_utf8(bytes).unwrap();
    text.split(' ').next().unwrap().parse().unwrap()
}

#[test]
fn a_full_refusal_list_fails_the_withdrawn_request_closed_and_a_start_still_works() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("state/refused");
    let mut rt = setup_file(dir.path());
    rt.host.journal_mut().set_refusal_limit(REFUSAL_LIMIT);
    host_work(&mut rt, HW);

    // Withdrawals of requests not in the journal fill the list.
    let mut listed = Vec::new();
    let mut n = 1;
    let full = loop {
        match withdraw(&mut rt, n) {
            // A few fit (bounded, so a list that never fills fails here).
            Withdrawal::Listed if n < 100 => {
                listed.push(rid(n));
                n += 1;
            }
            other => break other,
        }
    };
    assert_eq!(full, Withdrawal::ListFull);
    assert!(listed.len() >= 2, "{listed:?}");
    // The list is within the bound and read back whole: nothing of the one
    // that didn't fit.
    let bytes = std::fs::read(&path).unwrap();
    assert!(framed_len(&bytes) <= REFUSAL_LIMIT);
    let on_list: Vec<String> = rt
        .host
        .journal()
        .refusals()
        .unwrap()
        .into_iter()
        .map(|r| r.request_id)
        .collect();
    assert_eq!(on_list, listed);

    // Closed for that request only, and the journal doesn't halt. Again:
    // still `ListFull`, nothing written.
    assert!(!rt.host.journal_halted());
    assert_eq!(withdraw(&mut rt, n), Withdrawal::ListFull);
    assert_eq!(std::fs::read(&path).unwrap(), bytes);
    // Its submit, by anyone, is `busy` (`refusal list full`): never
    // admitted, nothing recorded, no lease.
    submit_host_work(&mut rt, HW, prompt_data(HW, n), provenance(TASK, SENDER));
    let msgs = got(&mut rt, HOST_WORK_PRINCIPAL);
    assert_eq!(error_code(&msgs), "busy");
    let error = msgs.iter().find(|m| m["op"] == "error").unwrap();
    assert_eq!(error["detail"], DETAIL_REFUSAL_LIST_FULL);
    assert_eq!(DETAIL_REFUSAL_LIST_FULL, "refusal list full");
    got(&mut rt, "c1");
    client_prompt(&mut rt, "c1", C1, n);
    assert_eq!(error_code(&got(&mut rt, "c1")), "busy");
    assert!(rt.host.receipt(&rid(n)).is_none());
    assert_eq!(rt.host.lease_holder(S1), None);
    assert!(!dispatched(&rt, &rid(n)));
    // Other work goes on.
    submit_host_work(&mut rt, HW, prompt_data(HW, 100), provenance(TASK2, SENDER));
    assert_eq!(
        rt.host.receipt(&rid(100)).unwrap().state,
        ReceiptState::Executing
    );

    // A start after reaching the bound works: each listed request is
    // recorded `rejected` with its detail, the list is emptied, and the one
    // that didn't fit is simply absent (never admitted).
    restart(&mut rt, GEN2, 8);
    assert_eq!(rt.host.start_error(), None);
    assert!(!rt.host.journal_halted());
    for id in &listed {
        let r = rt.host.receipt(id).unwrap();
        assert_eq!(r.state, ReceiptState::Rejected, "{id}");
        assert_eq!(r.detail.as_deref(), Some(DETAIL_WITHDRAWN_BY_HOST));
        assert_eq!(r.task_id.as_deref(), Some(TASK));
    }
    assert!(rt.host.receipt(&rid(n)).is_none());
    assert!(rt.host.journal().refusals().unwrap().is_empty());
    // And the list takes entries again.
    host_work(&mut rt, HW2);
    assert_eq!(withdraw(&mut rt, n + 1), Withdrawal::Listed);
}

#[test]
fn withdraw_of_an_id_recorded_under_another_submitter_is_reused() {
    let mut rt = setup();
    host_work(&mut rt, HW);
    client_prompt(&mut rt, "c1", C1, 1);
    assert_eq!(
        rt.host.receipt(&rid(1)).unwrap().state,
        ReceiptState::Executing
    );
    got(&mut rt, "c1");
    let records = rt.host.journal().records().len();

    // Not host-work's request: nothing written or changed.
    assert_eq!(withdraw(&mut rt, 1), Withdrawal::Reused);
    assert!(rt.host.journal().refusals().unwrap().is_empty());
    assert_eq!(rt.host.journal().records().len(), records);
    let r = rt.host.receipt(&rid(1)).unwrap();
    assert_eq!((r.state, r.task_id), (ReceiptState::Executing, None));
    assert!(got(&mut rt, "c1").is_empty());
    // The attempt's own submit is `request_id_reused`: never admitted.
    submit_host_work(&mut rt, HW, prompt_data(HW, 1), provenance(TASK, SENDER));
    assert_eq!(
        error_code(&got(&mut rt, HOST_WORK_PRINCIPAL)),
        "request_id_reused"
    );
    // c1's duplicate still gets its receipt.
    client_prompt(&mut rt, "c1", C1, 1);
    let mine = receipts(&got(&mut rt, "c1"));
    assert_eq!(states(&mine), ["executing"], "{mine:#?}");
}

#[test]
fn withdraw_of_a_request_rejected_for_another_reason_is_rejected() {
    let mut rt = setup();
    host_work(&mut rt, HW);
    rt.host.hold_dispatch(true);
    submit_host_work(&mut rt, HW, prompt_data(HW, 1), provenance(TASK, SENDER));
    let fx = rt.host.process_exited(S1, None);
    rt.apply(fx);
    let r = rt.host.receipt(&rid(1)).unwrap();
    assert_eq!(r.state, ReceiptState::Rejected);
    assert_eq!(r.detail.as_deref(), Some("session closed"));
    let records = rt.host.journal().records().len();
    assert_eq!(withdraw(&mut rt, 1), Withdrawal::Rejected);
    assert_eq!(rt.host.journal().records().len(), records);
    assert!(rt.host.journal().refusals().unwrap().is_empty());
    let r = rt.host.receipt(&rid(1)).unwrap();
    assert_eq!(r.detail.as_deref(), Some("session closed"));
}

#[test]
fn a_start_check_refusal_whose_write_fails_is_listed() {
    let dir = tempfile::tempdir().unwrap();
    let mut rt = setup_file(dir.path());
    connect_host_work(&mut rt, HW);
    let verdicts = Verdicts::new(StartVerdict::Go);
    rt.host.set_start_check(Box::new(verdicts.clone()));
    submit_host_work(&mut rt, HW, prompt_data(HW, 1), provenance(TASK, SENDER));
    submit_host_work(&mut rt, HW, prompt_data(HW, 2), provenance(TASK, SENDER));
    verdicts.set(StartVerdict::Withdraw);

    // The turn's end is written; the start check's refusal of the next
    // request isn't: the journal halts, and it stays `accepted`.
    rt.host.journal_mut().fail_fsync_of(2, false);
    let fx = rt.host.dispatch_report(&rid(1), done());
    rt.apply(fx);
    assert_eq!(
        rt.host.receipt(&rid(1)).unwrap().state,
        ReceiptState::Completed
    );
    assert_eq!(
        rt.host.receipt(&rid(2)).unwrap().state,
        ReceiptState::Accepted
    );
    assert!(rt.host.journal_halted());
    assert!(!dispatched(&rt, &rid(2)));
    // On the refusal list, as `withdraw`'s unwritten rejection is.
    let listed = rt.host.journal().refusals().unwrap();
    assert_eq!(listed.len(), 1, "{listed:#?}");
    assert_eq!(listed[0].request_id, rid(2));
    assert_eq!(listed[0].detail.as_deref(), Some(DETAIL_WITHDRAWN_BY_HOST));
    assert_eq!(listed[0].provenance, Some(provenance(TASK, SENDER)));

    // The restart rejects it so, before anything runs.
    restart(&mut rt, GEN2, 8);
    let r = rt.host.receipt(&rid(2)).unwrap();
    assert_eq!(r.state, ReceiptState::Rejected);
    assert_eq!(r.detail.as_deref(), Some(DETAIL_WITHDRAWN_BY_HOST));
    assert_eq!(r.task_id.as_deref(), Some(TASK));
    assert!(!dispatched(&rt, &rid(2)));
}

/// Memory stays bounded too: past `MAX_UNLISTED` requests held closed after
/// the list filled, the next withdrawal halts the journal (nothing is
/// admitted until the restart), and the start after it works.
#[test]
fn past_the_bound_in_memory_a_full_list_halts_the_journal() {
    let dir = tempfile::tempdir().unwrap();
    let mut rt = setup_file(dir.path());
    // No entry fits.
    rt.host.journal_mut().set_refusal_limit(100);
    host_work(&mut rt, HW);
    for n in 1..=MAX_UNLISTED as u64 {
        assert_eq!(withdraw(&mut rt, n), Withdrawal::ListFull, "{n}");
    }
    assert!(!rt.host.journal_halted());
    let next = MAX_UNLISTED as u64 + 1;
    assert_eq!(withdraw(&mut rt, next), Withdrawal::Halted);
    assert!(rt.host.journal_halted());
    submit_host_work(&mut rt, HW, prompt_data(HW, next), provenance(TASK, SENDER));
    assert_eq!(error_code(&got(&mut rt, HOST_WORK_PRINCIPAL)), "busy");
    assert!(rt.host.journal().refusals().unwrap().is_empty());

    restart(&mut rt, GEN2, 8);
    assert_eq!(rt.host.start_error(), None);
    assert!(!rt.host.journal_halted());
    assert!(rt.host.receipt(&rid(next)).is_none());
}

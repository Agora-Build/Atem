//! r8 §H/§I conformance obligations beyond the shared fixtures: the halted
//! journal at the PTY write boundary, a refusal that can't be recorded, the
//! refusal list replayed or damaged, the clean-close record around crashes,
//! the fence on disk after a failed rollback, and §F's acquire while the
//! feature is off.

use super::fake_runtime::{FailFsync, FakeRuntime, harness_config};
use super::file_journal::FileJournal;
use super::fixtures::{HostEvent, HostUnderTest};
use super::host::*;
use super::journal::{self, ControlState, Journal, MemJournal, Refusal};
use super::wire::{ClientKind, Permission, ReceiptKind, ReceiptState, Target};
use serde_json::{Value, json};
use std::sync::atomic::{AtomicU64, Ordering};

const S1: &str = "ses-aaaaaaaaaaaa";
const P1: &str = "22222222-2222-4222-8222-222222222222";
const C1: &str = "33333333-3333-4333-8333-333333333333";
const C1B: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const GEN2: &str = "99999999-9999-4999-8999-999999999999";
const GEN3: &str = "12121212-1212-4212-8212-121212121212";

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
    json!({
        "host": {"account_id": "account-a", "atem_device_id": "host-a", "host_trust_gen": 1,
                 "runtime_gen": "55555555-5555-4555-8555-555555555555", "runtime_epoch": 7},
        "sessions": [{"session_id": S1, "process_gen": P1, "chat": true}],
        "clients": [{"name": "c1", "attachment_gen": C1, "permissions": ["view", "control"],
                     "client_kind": "native"}]
    })
}

fn mem() -> FakeRuntime {
    FakeRuntime::from_json(setup_json(), harness_config())
}

fn file(dir: &std::path::Path) -> FakeRuntime<FileJournal> {
    let journal = FileJournal::open(&dir.join("state")).unwrap();
    FakeRuntime::from_json_with(setup_json(), harness_config(), journal)
}

fn target() -> Value {
    json!({"account_id": "account-a", "atem_device_id": "host-a", "host_trust_gen": 1,
           "session_id": S1, "process_gen": P1})
}

fn binding<J: Journal + FailFsync>(rt: &FakeRuntime<J>, epoch: Option<u64>) -> Value {
    let mut b = json!({"target": target(), "attachment_gen": rt.attachment("c1")});
    if let Some(e) = epoch {
        b["lease_epoch"] = json!(e);
    }
    b
}

fn session(op: &str, fields: Value) -> Value {
    let mut data = json!({"v": 1, "op": op, "id": id()});
    data.as_object_mut()
        .unwrap()
        .extend(fields.as_object().unwrap().clone());
    json!({"type": "session", "data": data})
}

fn got<J: Journal + FailFsync>(rt: &mut FakeRuntime<J>) -> Vec<Value> {
    rt.take("c1")
        .into_iter()
        .map(|m| m["data"].clone())
        .collect()
}

/// `c1` acquires the session; the lease epoch.
fn hold<J: Journal + FailFsync>(rt: &mut FakeRuntime<J>) -> u64 {
    let m = session(
        "acquire",
        json!({"binding": binding(rt, None), "takeover": false}),
    );
    rt.send("c1", &m);
    let lease = got(rt).into_iter().find(|m| m["op"] == "lease").unwrap();
    lease["binding"]["lease_epoch"].as_u64().unwrap()
}

fn prompt<J: Journal + FailFsync>(rt: &FakeRuntime<J>, epoch: u64, n: u64) -> Value {
    session(
        "submit",
        json!({"binding": binding(rt, Some(epoch)), "request_id": rid(n), "kind": "prompt",
               "payload": {"text": "run the tests"}}),
    )
}

fn event<J: Journal + FailFsync>(rt: &mut FakeRuntime<J>, e: HostEvent) {
    let now = rt.now();
    rt.event(&e, now).unwrap();
}

fn crash<J: Journal + FailFsync>(rt: &mut FakeRuntime<J>, runtime_gen: &str, epoch: u64) {
    event(
        rt,
        HostEvent::CrashRuntime {
            runtime_gen: runtime_gen.into(),
            runtime_epoch: epoch,
        },
    );
}

fn restart<J: Journal + FailFsync>(rt: &mut FakeRuntime<J>, runtime_gen: &str, epoch: u64) {
    event(
        rt,
        HostEvent::RestartRuntime {
            runtime_gen: runtime_gen.into(),
            runtime_epoch: epoch,
        },
    );
}

fn state_of<J: Journal>(rt: &FakeRuntime<J>, n: u64) -> Option<(ReceiptState, Option<String>)> {
    rt.host.receipt(&rid(n)).map(|r| (r.state, r.detail))
}

fn rejected(detail: &str) -> Option<(ReceiptState, Option<String>)> {
    Some((ReceiptState::Rejected, Some(detail.to_string())))
}

/// §H conformance: a halted journal also blocks remote terminal bytes
/// already queued at the PTY writer (they never go through `accepted` →
/// `executing`).
#[test]
fn a_halted_journal_drops_queued_remote_terminal_bytes() {
    let mut rt = mem();
    let e = hold(&mut rt);
    let subscribe = json!({"type": "terminal", "data": {"v": 1, "op": "subscribe",
        "terminal_id": S1, "generation": P1, "binding": binding(&rt, None)}});
    rt.send("c1", &subscribe);
    let stream = got(&mut rt)
        .into_iter()
        .find(|m| m["op"] == "attached")
        .unwrap()["stream_id"]
        .as_str()
        .unwrap()
        .to_string();
    rt.hold_writes = true;
    let input = json!({"type": "terminal", "data": {"v": 1, "op": "input", "terminal_id": S1,
        "generation": P1, "binding": binding(&rt, Some(e)), "stream_id": stream,
        "sequence": 0, "bytes": "aGkN"}});
    rt.send("c1", &input);
    // A failed admission write halts the journal.
    rt.host.journal_mut().fail_next_fsync();
    let m = prompt(&rt, e, 1);
    rt.send("c1", &m);
    assert!(rt.host.journal_halted());
    let epoch = rt.host.input_epoch(S1).unwrap();
    assert!(!rt.host.admit_write(S1, epoch, rt.now()), "nothing passes");
    rt.flush_writes();
    assert_eq!(rt.pty.writes_remote, 0);
    assert_eq!(rt.pty.dropped_remote, 1);
    // More input is refused outright.
    got(&mut rt);
    rt.send("c1", &input);
    let refused = got(&mut rt);
    assert_eq!(refused[0]["op"], "error");
    assert_eq!(refused[0]["code"], "busy");
}

/// §I.4: when the refusal list can't be written either, the link is closed
/// with no reply and the journal stays halted; after the restart the
/// journal decides: nothing (rollback done) or the accepted record, which
/// recovery rejects (no clean close).
#[test]
fn an_unrecordable_refusal_closes_the_link() {
    unrecordable_refusal(mem, false);
    unrecordable_refusal(mem, true);
    for undo_fails in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        unrecordable_refusal(|| file(dir.path()), undo_fails);
    }
}

fn unrecordable_refusal<J: Journal + FailFsync + RefusalFault>(
    setup: impl FnOnce() -> FakeRuntime<J>,
    undo_fails: bool,
) {
    let mut rt = setup();
    let e = hold(&mut rt);
    rt.host.journal_mut().fail_fsync_of(1, undo_fails);
    rt.host.journal_mut().fail_next_refusal();
    let m = prompt(&rt, e, 1);
    rt.send("c1", &m);
    assert!(got(&mut rt).is_empty(), "no reply");
    assert!(
        rt.effects
            .iter()
            .any(|f| matches!(f, Effect::Close { attachment } if attachment == C1))
    );
    assert_eq!(rt.host.welcomed_attachments(), 0);
    assert!(rt.host.journal_halted());
    assert!(rt.host.journal().refusals().unwrap().is_empty());
    restart(&mut rt, GEN2, 8);
    assert!(
        !rt.host.previous_run_clean(),
        "a halted run never closes cleanly"
    );
    let expected =
        undo_fails.then(|| (ReceiptState::Rejected, Some(DETAIL_HISTORY_UNKNOWN.into())));
    assert_eq!(state_of(&rt, 1), expected, "undo_fails {undo_fails}");
    assert_eq!(rt.pty.dispatch_attempts, 0);
}

/// §I.3 conformance: resolving the refusal list is idempotent. A restart
/// that finds the list again (a crash after the rejection was durable,
/// before the list was cleared) changes nothing and never runs the
/// request, whether its `accepted` record reached the disk or not.
#[test]
fn replaying_the_refusal_list_never_runs_a_refused_request() {
    for undo_fails in [false, true] {
        replay_refusals(mem(), undo_fails);
        let dir = tempfile::tempdir().unwrap();
        replay_refusals(file(dir.path()), undo_fails);
    }
}

fn replay_refusals<J: Journal + FailFsync>(mut rt: FakeRuntime<J>, undo_fails: bool) {
    let e = hold(&mut rt);
    rt.host.journal_mut().fail_fsync_of(1, undo_fails);
    let m = prompt(&rt, e, 1);
    rt.send("c1", &m);
    let busy = got(&mut rt);
    assert_eq!(busy[0]["detail"], DETAIL_ACCEPTANCE_NOT_RECORDED);
    let listed = rt.host.journal().refusals().unwrap();
    assert_eq!(listed.len(), 1);
    restart(&mut rt, GEN2, 8);
    assert_eq!(state_of(&rt, 1), rejected(DETAIL_ACCEPTANCE_NOT_CONFIRMED));
    assert!(rt.host.journal().refusals().unwrap().is_empty(), "cleared");
    // The list again, as if the clear never became durable.
    rt.host
        .journal_mut()
        .record_refusal(listed[0].clone())
        .unwrap();
    crash(&mut rt, GEN3, 9);
    assert_eq!(state_of(&rt, 1), rejected(DETAIL_ACCEPTANCE_NOT_CONFIRMED));
    assert!(rt.host.start_error().is_none());
    // The same id returns its receipt (no lease) and isn't re-admitted.
    rt.event_reconnect_c1();
    let e = hold(&mut rt);
    let m = prompt(&rt, e, 1);
    rt.send("c1", &m);
    let r = got(&mut rt);
    assert_eq!(r[0]["op"], "receipt");
    assert_eq!(r[0]["state"], "rejected");
    assert!(r[0].get("lease").is_none());
    assert_eq!(rt.pty.dispatch_attempts, 0, "undo_fails {undo_fails}");
}

/// A refusal list that can't be read: the host starts with remote
/// sessions disabled, resolves and dispatches nothing, every request is
/// `busy`, and it never closes cleanly.
#[test]
fn a_damaged_refusal_list_disables_remote_sessions() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    {
        let mut rt = file(dir.path());
        let e = hold(&mut rt);
        let m = prompt(&rt, e, 1);
        rt.send("c1", &m);
        let m = prompt(&rt, e, 2);
        rt.send("c1", &m);
        assert_eq!(state_of(&rt, 2).unwrap().0, ReceiptState::Accepted);
    }
    std::fs::write(state.join("refused"), b"not a framed record").unwrap();
    let journal = FileJournal::open(&state).unwrap();
    let mut host =
        SessionHost::open(ctx(), harness_config(), journal, random_ids(), Some(7)).unwrap();
    host.restore_session(spec()).unwrap();
    let fx = host.recover();
    assert!(fx.is_empty(), "nothing reconciled or dispatched: {fx:?}");
    assert!(host.start_error().is_some());
    assert!(host.journal_halted());
    assert_eq!(host.receipt(&rid(2)).unwrap().state, ReceiptState::Accepted);
    assert!(!host.close_cleanly());
}

/// The refusal list is replaced atomically: a temp file left by a crash
/// before the rename is ignored, and the next write replaces both.
#[test]
fn the_refusal_list_survives_a_crash_around_its_rename() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let mut j = FileJournal::open(&state).unwrap();
    let refusal = |n| Refusal {
        request_id: rid(n),
        target: serde_json::from_value::<Target>(target()).unwrap(),
        kind: ReceiptKind::Prompt,
        payload_digest: "0".repeat(64),
        updated_at: 1,
    };
    j.record_refusal(refusal(1)).unwrap();
    std::fs::write(state.join("refused.tmp"), b"half a file").unwrap();
    assert_eq!(j.refusals().unwrap(), vec![refusal(1)]);
    j.record_refusal(refusal(2)).unwrap();
    assert!(!state.join("refused.tmp").exists());
    drop(j);
    let mut j = FileJournal::open(&state).unwrap();
    assert_eq!(j.refusals().unwrap(), vec![refusal(1), refusal(2)]);
    j.clear_refusals().unwrap();
    j.clear_refusals().unwrap();
    assert!(j.refusals().unwrap().is_empty());
}

/// §H conformance: the clean-close record around crashes. Only an orderly
/// stop with a healthy journal writes it; a crash before its rename leaves
/// none; a stale or damaged one vouches for nothing; it is removed at the
/// start, and a removal that didn't happen can't vouch for a later crash
/// (the next start names a newer epoch).
#[test]
fn the_clean_close_record_vouches_only_for_the_run_that_wrote_it() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state");
    let open = |previous: u64| {
        let journal = FileJournal::open(&state).unwrap();
        SessionHost::open(
            ctx(),
            harness_config(),
            journal,
            random_ids(),
            Some(previous),
        )
        .unwrap()
    };
    let mut host = open(6);
    assert!(!host.previous_run_clean());
    assert!(host.close_cleanly());
    let text = std::fs::read_to_string(state.join("clean_close")).unwrap();
    assert_eq!(
        serde_json::from_str::<Value>(&text).unwrap(),
        json!({"runtime_epoch": 9})
    );
    drop(host);
    let host = open(9);
    assert!(host.previous_run_clean());
    assert!(!state.join("clean_close").exists(), "removed at the start");
    drop(host);
    // A crash of the next run: nothing vouches for it.
    let host = open(9);
    assert!(!host.previous_run_clean());
    drop(host);
    // A crash during the write (before the rename): only the temp file.
    std::fs::write(state.join("clean_close.tmp"), br#"{"runtime_epoch":9}"#).unwrap();
    let host = open(9);
    assert!(!host.previous_run_clean());
    assert!(!state.join("clean_close.tmp").exists());
    drop(host);
    // A removal that failed: the next start names a newer epoch.
    std::fs::write(state.join("clean_close"), br#"{"runtime_epoch":9}"#).unwrap();
    let host = open(10);
    assert!(!host.previous_run_clean(), "stale");
    drop(host);
    std::fs::write(state.join("clean_close"), b"garbage").unwrap();
    let host = open(9);
    assert!(!host.previous_run_clean(), "damaged");
    assert!(!state.join("clean_close").exists());
    drop(host);
    // A halted journal writes none.
    let mut rt = file(dir.path().join("halted").as_path());
    let e = hold(&mut rt);
    rt.host.journal_mut().fail_next_fsync();
    let m = prompt(&rt, e, 1);
    rt.send("c1", &m);
    assert!(!rt.host.close_cleanly());
    assert!(!dir.path().join("halted/state/clean_close").exists());
}

/// §H conformance: the fence write with both rollback outcomes, on disk.
/// A failed fence whose rollback worked leaves the old control state; one
/// whose rollback failed leaves the raised generation. Either way the run
/// halts and the restart rejects the queued work the same way.
#[test]
fn a_failed_fence_write_leaves_either_state_and_the_same_outcome() {
    for undo_fails in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let mut rt = file(dir.path());
        let e = hold(&mut rt);
        for n in [1, 2] {
            let m = prompt(&rt, e, n);
            rt.send("c1", &m);
        }
        rt.host.journal_mut().fail_fsync_of(1, undo_fails);
        event(
            &mut rt,
            HostEvent::SetPermissions {
                client: "c1".into(),
                permissions: vec![Permission::View],
                attachment_gen: C1B.into(),
            },
        );
        assert!(rt.host.journal_halted());
        assert_eq!(rt.host.lease_holder(S1), None);
        assert_eq!(
            state_of(&rt, 2),
            rejected(DETAIL_CONTROL_REVOKED),
            "in memory"
        );
        let records = rt.host.journal().load().unwrap();
        let control = journal::replay(records)
            .unwrap()
            .principals
            .get("c1")
            .copied();
        let expected = if undo_fails {
            ControlState {
                control: false,
                control_gen: 2,
            }
        } else {
            ControlState {
                control: true,
                control_gen: 1,
            }
        };
        assert_eq!(control, Some(expected), "undo_fails {undo_fails}");
        restart(&mut rt, GEN2, 8);
        assert_eq!(state_of(&rt, 2), rejected(DETAIL_HISTORY_UNKNOWN));
        assert_eq!(rt.pty.dispatch_attempts, 1);
    }
}

/// §F stays off until it is advertised: an acquiring submit is an op of an
/// unadvertised feature, nothing recorded.
#[test]
fn an_acquiring_submit_is_refused_while_the_feature_is_off() {
    let mut rt = FakeRuntime::from_json(setup_json(), HostConfig::default());
    let m = session(
        "submit",
        json!({"binding": binding(&rt, None), "request_id": rid(1), "kind": "prompt",
               "payload": {"text": "run the tests"}, "acquire": true}),
    );
    rt.send("c1", &m);
    let r = got(&mut rt);
    assert_eq!(r[0]["code"], "unsupported_version");
    assert!(rt.host.receipt(&rid(1)).is_none());
    assert_eq!(rt.host.lease_holder(S1), None);
}

/// A principal must be an opaque id; it is never taken from messages.
#[test]
fn a_principal_is_an_opaque_id() {
    let mut rt = mem();
    let attach = |principal: &str| Attach {
        client: "c9".into(),
        principal: principal.into(),
        attachment_gen: "dddddddd-dddd-4ddd-8ddd-dddddddddddd".into(),
        permissions: vec![Permission::View],
        client_kind: ClientKind::Native,
        authorization_ms: 1000,
    };
    assert!(rt.host.connect(attach("")).is_err());
    assert!(rt.host.connect(attach("no spaces")).is_err());
    assert!(rt.host.connect(attach("astation:account-a:a1")).is_ok());
}

fn ctx() -> HostContext {
    HostContext {
        account_id: "account-a".into(),
        atem_device_id: "host-a".into(),
        host_trust_gen: 1,
        runtime_gen: GEN2.into(),
        runtime_epoch: 9,
    }
}

fn spec() -> SessionSpec {
    SessionSpec {
        session_id: S1.into(),
        process_gen: P1.into(),
        provider: "claude".into(),
        cwd_label: "Atem".into(),
        chat: true,
        rows: 24,
        cols: 80,
    }
}

/// The refusal-list fault of both journals.
trait RefusalFault {
    fn fail_next_refusal(&mut self);
}

impl RefusalFault for MemJournal {
    fn fail_next_refusal(&mut self) {
        MemJournal::fail_next_refusal(self);
    }
}

impl RefusalFault for FileJournal {
    fn fail_next_refusal(&mut self) {
        FileJournal::fail_next_refusal(self);
    }
}

impl<J: Journal + FailFsync> FakeRuntime<J> {
    fn event_reconnect_c1(&mut self) {
        self.attach("c1", "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb")
            .unwrap();
    }
}

/// A rollback that keeps failing survives `reopen`: the restart is refused
/// and the host stays halted, so nothing is written that the pending
/// rollback could later cut away. The records written before the failure
/// are all there when a new process opens the journal.
#[test]
fn a_pending_rollback_survives_reopen_and_loses_no_records() {
    let dir = tempfile::tempdir().unwrap();
    let mut rt = file(dir.path());
    let e = hold(&mut rt);
    let m = prompt(&rt, e, 1);
    rt.send("c1", &m);
    assert_eq!(state_of(&rt, 1).unwrap().0, ReceiptState::Executing);
    rt.host.journal_mut().set_undo_stuck(true);
    rt.host
        .journal_mut()
        .inject(super::file_journal::Fault::FsyncAndUndo);
    let m = prompt(&rt, e, 2);
    rt.send("c1", &m);
    assert_eq!(
        got(&mut rt).last().unwrap()["detail"],
        DETAIL_ACCEPTANCE_NOT_RECORDED
    );
    let now = rt.now();
    assert!(rt.host.restart_at(GEN2, 8, now, true).is_err());
    assert!(rt.host.journal_halted());
    assert!(rt.host.journal().failed().is_some());
    assert!(!rt.host.close_cleanly());
    let m = prompt(&rt, e, 3);
    rt.send("c1", &m);
    assert!(rt.host.receipt(&rid(3)).is_none());
    let record = journal::Record::Transition {
        request_id: rid(1),
        state: ReceiptState::OutcomeUnknown,
        detail: None,
        updated_at: 1,
    };
    assert!(rt.host.journal_mut().append(record).is_err());
    // The rollback finally works when the process goes away.
    rt.host.journal_mut().set_undo_stuck(false);
    drop(rt);
    let journal = FileJournal::open(&dir.path().join("state")).unwrap();
    let host = SessionHost::new(ctx(), harness_config(), journal, random_ids()).unwrap();
    assert_eq!(
        host.receipt(&rid(1)).map(|r| r.state),
        Some(ReceiptState::Executing)
    );
    assert!(host.receipt(&rid(2)).is_none(), "rolled back");
    assert_eq!(host.journal().refusals().unwrap().len(), 1);
}

/// A reload that fails leaves the journal failed and the host halted,
/// never a wiped journal that takes writes.
#[test]
fn a_failed_reload_leaves_the_journal_failed_and_the_host_halted() {
    let dir = tempfile::tempdir().unwrap();
    let mut rt = file(dir.path());
    let e = hold(&mut rt);
    let m = prompt(&rt, e, 1);
    rt.send("c1", &m);
    std::fs::write(dir.path().join("state/floors"), b"damaged").unwrap();
    let now = rt.now();
    assert!(rt.host.restart_at(GEN2, 8, now, true).is_err());
    assert!(rt.host.journal_halted());
    assert!(rt.host.journal().failed().is_some());
    let record = journal::Record::LeaseEpochs {
        session_id: S1.into(),
        reserved: 1000,
    };
    assert!(rt.host.journal_mut().append(record).is_err());
    assert_eq!(
        std::fs::read(dir.path().join("state/floors")).unwrap(),
        b"damaged",
        "never rewritten from a wiped state"
    );
}

/// A link that connects without `control` before the start's resolution
/// (workers still being adopted) doesn't change what recovered work is
/// resolved as: rule 2's detail, not "control revoked".
#[test]
fn recovered_work_is_resolved_before_a_connect_changes_control() {
    let mut j = MemJournal::default();
    j.append(journal::Record::Control {
        principal: "c1".into(),
        control: true,
        control_gen: 1,
    })
    .unwrap();
    j.append(journal::Record::Accepted {
        request_id: rid(1),
        target: serde_json::from_value(target()).unwrap(),
        kind: ReceiptKind::Prompt,
        payload_digest: "0".repeat(64),
        payload: json!({"text": "run the tests"}),
        updated_at: 1,
        principal: "c1".into(),
        control_gen: 1,
    })
    .unwrap();
    let mut host = SessionHost::open(ctx(), harness_config(), j, random_ids(), Some(8)).unwrap();
    host.connect(Attach {
        client: "c1".into(),
        principal: "c1".into(),
        attachment_gen: C1.into(),
        permissions: vec![Permission::View],
        client_kind: ClientKind::Native,
        authorization_ms: 1000,
    })
    .unwrap();
    host.restore_session(spec()).unwrap();
    host.recover();
    let r = host.receipt(&rid(1)).unwrap();
    assert_eq!(r.state, ReceiptState::Rejected);
    assert_eq!(r.detail.as_deref(), Some(DETAIL_HISTORY_UNKNOWN));
}

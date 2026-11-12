// The delegated dispatch in the bridge (design I.4.2, I.4.3, I.6.4;
// host-work-v1 §11.6): the rig's host with a pinned device list, a phone
// (a native member) as the delegated sender, the fake agent, and the
// delegated clock on a manual OS. Included into the host-work bridge's
// local tests (`include!`), beside the rig they share.

use crate::runtime::delegated::SenderStanding;
use crate::runtime::delegated::attempts::MAX_ATTEMPTS;
use crate::runtime::delegated::start::Event;
use crate::runtime::host_clock::os::{OsReading, Synced};
use crate::runtime::test_hooks::HostFeatures;
use crate::session_protocol::membership::r9log::{MAC, TestLog, auth};
use crate::session_protocol::r9::envelope::{self, Event as Envelope9, Transport};
use atem_client::connect::{Connector, Identity};
use std::sync::Mutex;

const ORIGIN: &str = "https://station-dev.agora.build";
const PHONE: &str = "member:dev-phone";

/// The OS the delegated clock reads: synchronized, one boot, the wall
/// clock and boot-time counter as the test sets them.
#[derive(Clone)]
struct ManualOs(Arc<Mutex<OsReading>>);

impl ManualOs {
    fn at(wall_ms: u64) -> ManualOs {
        ManualOs(Arc::new(Mutex::new(OsReading {
            wall_ms,
            boot_ns: 1_000_000_000_000,
            boot_id: "boot-manual".into(),
            machine: [7; 16],
            timens_boot_ns: 0,
            synced: Synced::Yes,
        })))
    }

    /// Time passes on it: the wall clock and the boot-time counter.
    fn pass(&self, ms: u64) {
        let mut r = self.0.lock().unwrap();
        r.wall_ms += ms;
        r.boot_ns += ms * 1_000_000;
    }
}

/// The delegated clock on `os`'s readings, beside the rig's store.
fn manual_clock(rig: &mut LocalRig, os: &ManualOs) {
    let reading = os.0.clone();
    let store = rig.bridge.work.store.as_ref().unwrap();
    rig.bridge.work.clock = Some(crate::runtime::host_clock::HostClock::with_readings(
        store,
        move || Some(reading.lock().unwrap().clone()),
    ));
}

/// The rig as a delegated host: `host.delegated` on, the phone pinned with
/// route `rm`, the delegated clock on `os`, and with `gate` the host's own
/// Station's gate open (what the feeds will make it, PR 10: this version's
/// are closed, so otherwise only the phone's own caught-up channel opens
/// it). The phone's authority, and the list.
fn delegated(rig: &mut LocalRig, root: &Path, os: &ManualOs, gate: bool) -> (Authority, TestLog) {
    // On before the list opens: its deferral is kept on disk then.
    rig.bridge.features = HostFeatures::parse("host.delegated").unwrap();
    let (log, phone) = pin_phone_log(rig, root);
    manual_clock(rig, os);
    if gate {
        rig.bridge.start_view().gates.open_own_station(ORIGIN);
    }
    (phone, log)
}

/// The phone enqueues `prompt`: the task's id.
fn enqueue(rig: &mut LocalRig, phone: &Authority, prompt: &str) -> String {
    let req = phone_enqueue(rig, prompt);
    as_phone(rig, phone, &req).unwrap();
    enqueued(&req)
}

/// What the fake agent was given, in order.
fn input(rig: &LocalRig) -> String {
    std::fs::read_to_string(rig.fake.join("input")).unwrap_or_default()
}

/// `n` scheduling passes (no wall-time margin: each forces one).
fn passes(rig: &mut LocalRig, n: usize) {
    for _ in 0..n {
        for s in rig.sessions.values_mut() {
            s.pump();
        }
        rig.bridge.work.scheduled = Instant::now();
        rig.bridge.tick(&mut rig.app, &mut rig.sessions, false);
    }
}

/// The task's attempts: (id, end, counted), in order.
fn attempts(rig: &LocalRig, task_id: &str) -> Vec<(String, Option<String>, bool)> {
    let db = &rig.bridge.work.store.as_ref().unwrap().db;
    let mut q = db
        .prepare(r#"SELECT attempt_id,"end",counted FROM attempts WHERE task_id=?1 ORDER BY n"#)
        .unwrap();
    q.query_map([task_id], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// The turn the fake agent runs ends.
async fn complete(rig: &mut LocalRig, task: &str) {
    std::fs::write(rig.fake.join("complete"), "").unwrap();
    rig.until(|r| stored_record(r, task).status.state == WorkState::AwaitingResult)
        .await;
}

/// A local task (stage 1) on the rig's session, run to its turn's end, and
/// the lease it took given back (local input wins, so the next task finds
/// the session free).
async fn local_task_runs(rig: &mut LocalRig, text: &str) {
    let mut message = rig.message();
    message.text = text.into();
    rig.publish(&message);
    rig.until(|r| input(r).contains(text)).await;
    std::fs::write(rig.fake.join("complete"), "").unwrap();
    rig.until(|r| r.work(&message).status.state == WorkState::AwaitingResult)
        .await;
    rig.bridge
        .local_input(
            &rig.sid,
            vec![],
            &rig.app.astation_client,
            &mut rig.sessions,
        )
        .unwrap();
}

/// Design I.4.2, session-v1 R9.14 items 1 to 3: a delegated task is
/// submitted under the session host's `host-work` principal, on its
/// internal attachment (which takes the lease with the prompt), as a fresh
/// attempt whose id is the task's `receipt_id` now; the receipt carries the
/// task and the sender; the chat's acceptance journals the turn (the normal
/// dispatch), and the task follows the receipt to `awaiting_result`. The
/// attempt ended `started`: never submitted again.
#[test]
fn delegated_task_dispatches_under_host_work_with_provenance() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let req = phone_enqueue(&rig, "DELEGATED_TASK_PROMPT");
        let task = enqueued(&req);
        let ResultBody::Work { work } = as_phone(&mut rig, &phone, &req).unwrap() else {
            panic!("a work result");
        };
        rig.until(|r| input(r).contains("DELEGATED_TASK_PROMPT"))
            .await;
        let record = stored_record(&rig, &task);
        let attempt = record.status.receipt_id.clone();
        assert_ne!(attempt, work.receipt_id, "an attempt's own id");
        assert!(wire::is_uuid_v4(&attempt));
        let receipt = rig
            .bridge
            .host
            .attempt_receipt(&attempt, &task)
            .expect("host-work's receipt of the attempt");
        assert_eq!(receipt.task_id.as_deref(), Some(task.as_str()));
        assert_eq!(receipt.sender.as_deref(), Some(PHONE));
        assert_eq!(receipt.kind, wire::ReceiptKind::Prompt);
        let host_work = rig.bridge.host_work_attachment().unwrap().to_string();
        assert_eq!(
            rig.bridge.host.lease_holder(rig.sid.as_str()),
            Some(host_work.as_str()),
            "host-work holds the lease for the turn"
        );
        rig.until(|r| r.bridge.host.recorded_turn(&attempt).is_some())
            .await;
        // Framed: Atem's lines carry a tag this prompt drew.
        assert!(input(&rig).contains("[atem "), "{}", input(&rig));
        complete(&mut rig, &task).await;
        assert_eq!(
            rig.bridge
                .host
                .attempt_receipt(&attempt, &task)
                .unwrap()
                .state,
            wire::ReceiptState::Completed
        );
        assert_eq!(
            attempts(&rig, &task),
            [(attempt.clone(), Some("started".into()), true)]
        );
        passes(&mut rig, 3);
        assert_eq!(input(&rig).matches("DELEGATED_TASK_PROMPT").count(), 1);
        assert_eq!(attempts(&rig, &task).len(), 1);
        // The lease goes once the turn ended.
        assert_eq!(rig.bridge.host.lease_holder(rig.sid.as_str()), None);
    });
}

/// Design I.4.3 ("The sender's channel and online status are not
/// conditions"), VII.A test 1: the phone has no channel at all (never had
/// one in this run); its first task runs, ends, and its next one then
/// starts and ends too.
#[test]
fn sender_offline_task_runs() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        assert!(rig.bridge.r9.attachments().is_empty(), "no channel");
        let first = enqueue(&mut rig, &phone, "OFFLINE_FIRST");
        let second = enqueue(&mut rig, &phone, "OFFLINE_SECOND");
        rig.until(|r| input(r).contains("OFFLINE_FIRST")).await;
        assert_eq!(
            stored_record(&rig, &second).status.detail,
            "waiting for an earlier task on this session"
        );
        complete(&mut rig, &first).await;
        rig.until(|r| input(r).contains("OFFLINE_SECOND")).await;
        complete(&mut rig, &second).await;
        let text = input(&rig);
        assert!(text.find("OFFLINE_FIRST") < text.find("OFFLINE_SECOND"));
    });
}

/// Condition 2a (design I.4.3): a halted session journal alone (the
/// device list usable) leaves a delegated task `blocked` until the
/// restart, `journal halted; restart Atem`; it is never failed, and no
/// attempt is made.
#[test]
fn a_halted_journal_alone_blocks() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        rig.bridge.host.journal_mut().fail_append_of(1, false);
        let effects = rig.bridge.host.fence_principal("service:other", 0);
        rig.bridge.exec(
            effects,
            &mut Cx {
                client: &rig.app.astation_client,
                sessions: &mut rig.sessions,
            },
        );
        assert!(rig.bridge.host.journal_halted());
        let task = enqueue(&mut rig, &phone, "HALTED_PROMPT");
        passes(&mut rig, 5);
        let record = stored_record(&rig, &task);
        assert_eq!(
            record.status.state,
            WorkState::Blocked,
            "{}",
            record.status.detail
        );
        assert_eq!(record.status.detail, details::JOURNAL_HALTED);
        assert!(attempts(&rig, &task).is_empty());
        assert!(!input(&rig).contains("HALTED_PROMPT"));
    });
}

/// §11.6 ("Waiting doesn't hold the session"), VII.A test 5: a delegated
/// task blocked for a closed gate, a hold or a deferred device-list entry
/// lets later tasks of other senders, a local one here, run on its session;
/// once nothing stops it, it runs.
#[test]
fn paused_gate_and_deferred_blocked_tasks_dont_hold_the_session() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let (phone, _) = delegated(&mut rig, root, &os, false);
        let task = enqueue(&mut rig, &phone, "WAITING_DELEGATED");
        let blocked = |rig: &LocalRig, detail: &str| {
            let r = stored_record(rig, &task);
            r.status.state == WorkState::Blocked && r.status.detail == detail
        };
        // The gate closed (no feed, no channel of the phone).
        rig.until(|r| blocked(r, details::REVOCATIONS_NOT_YET_CHECKED))
            .await;
        local_task_runs(&mut rig, "LOCAL_PAST_THE_GATE").await;
        // Held (a `hold` record, as the feeds will apply one).
        rig.bridge.start_view().gates.open_own_station(ORIGIN);
        rig.bridge.start_view().standings.insert(
            PHONE.into(),
            SenderStanding {
                held: true,
                ..SenderStanding::default()
            },
        );
        rig.until(|r| blocked(r, details::PAUSED)).await;
        local_task_runs(&mut rig, "LOCAL_PAST_THE_HOLD").await;
        // A deferred device-list entry (its own test carries a real one).
        rig.bridge.start_view().standings.clear();
        rig.bridge.start_view().list.as_mut().unwrap().deferred =
            Some(crate::session_protocol::membership::DeferredStop {
                seq: 99,
                until_ms: u64::MAX,
                on: None,
            });
        rig.until(|r| blocked(r, details::DEVICE_LIST_UPDATE_PENDING))
            .await;
        local_task_runs(&mut rig, "LOCAL_PAST_THE_DEFERRAL").await;
        assert!(attempts(&rig, &task).is_empty(), "never attempted");
        // Nothing stops it: it runs.
        rig.bridge.start_view().list.as_mut().unwrap().deferred = None;
        rig.until(|r| input(r).contains("WAITING_DELEGATED")).await;
        complete(&mut rig, &task).await;
    });
}

/// §11.6 ("One sender's tasks keep their order"): while the phone's first
/// task waits without holding the session (its gate closed), the phone's
/// later task waits behind it with the same detail and a local task passes
/// both; once the gate opens, the first runs, then the second.
#[test]
fn one_senders_tasks_keep_their_order() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let (phone, _) = delegated(&mut rig, root, &os, false);
        let first = enqueue(&mut rig, &phone, "ORDER_FIRST");
        let second = enqueue(&mut rig, &phone, "ORDER_SECOND");
        rig.until(|r| {
            [&first, &second]
                .iter()
                .all(|t| stored_record(r, t).status.detail == details::REVOCATIONS_NOT_YET_CHECKED)
        })
        .await;
        local_task_runs(&mut rig, "LOCAL_PAST_BOTH").await;
        rig.bridge.start_view().gates.open_own_station(ORIGIN);
        rig.until(|r| input(r).contains("ORDER_FIRST")).await;
        assert!(!input(&rig).contains("ORDER_SECOND"));
        assert_eq!(
            stored_record(&rig, &second).status.detail,
            "waiting for an earlier task on this session"
        );
        complete(&mut rig, &first).await;
        rig.until(|r| input(r).contains("ORDER_SECOND")).await;
        let text = input(&rig);
        assert!(text.find("LOCAL_PAST_BOTH") < text.find("ORDER_FIRST"));
        assert!(text.find("ORDER_FIRST") < text.find("ORDER_SECOND"));
        complete(&mut rig, &second).await;
    });
}

// ── The phone's own r9 channel, through the bridge's engine ──

/// The rig's link up for r9 as a routed relay link would be (no Astation
/// session on it), so the bridge's engine admits channels.
fn r9_link_up(rig: &mut LocalRig) {
    rig.app.astation_routed = true;
    rig.app.astation_link_gen = 7;
    passes(rig, 1);
    assert_eq!(rig.bridge.r9_link, Some(7));
}

/// An envelope from the router (the relay) to the bridge's engine.
fn envelope_in(rig: &mut LocalRig, text: &str) {
    let text = text.to_string();
    let effects = rig.bridge.r9_call(|r9, parts| r9.on_envelope(&text, parts));
    rig.bridge.r9_exec(
        effects,
        &mut Cx {
            client: &rig.app.astation_client,
            sessions: &mut rig.sessions,
        },
    );
}

/// The engine's frames for `handle` since the last call (the link takes
/// nothing on its own here: there is no socket).
fn frames_for(rig: &mut LocalRig, handle: &str) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    rig.bridge.r9.flush(&mut |text, _| {
        out.push(text);
        true
    });
    out.into_iter()
        .filter_map(|text| match envelope::parse(&text).unwrap() {
            Envelope9::Frame { channel, frame } if channel == handle => Some(frame),
            _ => None,
        })
        .collect()
}

/// `device`'s channel `handle`, its `hello` carrying `log`'s suffix (the
/// shared client core on its side): the attached client.
fn channel(
    rig: &mut LocalRig,
    log: &TestLog,
    handle: &str,
    device: &str,
) -> atem_client::connect::Attached {
    rig.bridge.r9.reset_init_limiter();
    envelope_in(rig, &envelope::open(handle, Transport::Relay));
    let identity = Identity::native(device, auth(device));
    let (connecting, init) = Connector::new("host").start(&log.log, 1).unwrap();
    envelope_in(rig, &envelope::frame(handle, &init));
    let accept = frames_for(rig, handle).remove(0);
    let (welcoming, finish) = connecting
        .on_accept(&accept, &log.log, &log.keys, &identity, 1)
        .unwrap();
    envelope_in(rig, &envelope::frame(handle, &finish));
    let welcome = frames_for(rig, handle).remove(0);
    welcoming.on_frame(&welcome, &log.log, 1).unwrap()
}

/// VII.A test 20, design I.5.8 ("Native senders"): with no Station gate
/// open (this version's: no feeds), the phone's task runs once the phone
/// holds a channel whose `hello` carriage brought the host up to its own
/// head; with that channel closed, its next task waits (`revocations not
/// yet checked`, the session free), and runs again once it reconnects.
#[test]
fn native_passes_the_gate_with_a_caught_up_channel() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let (phone, log) = delegated(&mut rig, root, &os, false);
        r9_link_up(&mut rig);
        let first = enqueue(&mut rig, &phone, "CAUGHT_UP_FIRST");
        rig.until(|r| {
            stored_record(r, &first).status.detail == details::REVOCATIONS_NOT_YET_CHECKED
        })
        .await;
        let _channel = channel(&mut rig, &log, "ph-1", "dev-phone");
        assert!(
            rig.bridge.r9.native_caught_up(
                PHONE,
                log.log
                    .member("dev-phone")
                    .unwrap()
                    .member
                    .auth_key
                    .as_bytes()
            )
        );
        rig.until(|r| input(r).contains("CAUGHT_UP_FIRST")).await;
        complete(&mut rig, &first).await;
        // The channel closes: the gate with it.
        envelope_in(&mut rig, &envelope::close("ph-1", None));
        let second = enqueue(&mut rig, &phone, "CAUGHT_UP_SECOND");
        rig.until(|r| {
            stored_record(r, &second).status.detail == details::REVOCATIONS_NOT_YET_CHECKED
        })
        .await;
        local_task_runs(&mut rig, "LOCAL_WHILE_THE_GATE_IS_CLOSED").await;
        assert!(attempts(&rig, &second).is_empty());
        let _again = channel(&mut rig, &log, "ph-2", "dev-phone");
        rig.until(|r| input(r).contains("CAUGHT_UP_SECOND")).await;
        complete(&mut rig, &second).await;
    });
}

/// VII.A test 15, design I.4.3 ("Deferred entries"): the phone's channel
/// carries a pending `recovery_add` and an entry its subject signed, which
/// this host defers: every unstarted delegated remote task waits (`device
/// list update pending`) without holding its session, and a local task
/// runs. Another manager's approval, carried the same way, ends the wait,
/// and the delegated task runs.
#[test]
fn a_deferred_carriage_blocks_every_delegated_remote_task_not_local() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let (phone, mut log) = delegated(&mut rig, root, &os, false);
        r9_link_up(&mut rig);
        let mut ch = channel(&mut rig, &log, "ph-1", "dev-phone");
        let carry =
            |rig: &mut LocalRig, ch: &mut atem_client::connect::Attached, entries: Vec<Value>| {
                let message = json!({"type": "session", "data": {"v": 1, "op": "membership",
                "id": uuid::Uuid::new_v4().to_string(), "entries": entries}});
                let frame = ch.send(&message, 2).unwrap();
                envelope_in(rig, &envelope::frame("ph-1", &frame));
            };
        let recovery = log.recovery_add("dev-new");
        let recovery_hash = log.entries.last().unwrap().hash();
        let body = log.log.draft(
            "dev-new",
            host_now().wall_ms,
            &atem_client::membership::entry::Action::Remove {
                device_id: "dev-phone".into(),
            },
        );
        let deferred = atem_client::membership::sign_entry(&log.keys, &auth("dev-new"), body)
            .unwrap()
            .object()
            .to_json();
        let task = enqueue(&mut rig, &phone, "DEFERRED_DELEGATED");
        carry(&mut rig, &mut ch, vec![recovery, deferred]);
        let stop = rig.bridge.membership.as_ref().unwrap().deferred_stop();
        assert!(stop.is_some(), "the carriage stopped at the deferred entry");
        assert_eq!(
            rig.bridge.start_view().list.as_ref().unwrap().deferred,
            stop
        );
        rig.until(|r| stored_record(r, &task).status.detail == details::DEVICE_LIST_UPDATE_PENDING)
            .await;
        // Kept on disk with the hook on, beside `membership_applied`.
        assert!(root.join("runtime/journal/membership_deferred").is_file());
        local_task_runs(&mut rig, "LOCAL_DURING_THE_DEFERRAL").await;
        assert!(attempts(&rig, &task).is_empty());
        // The Mac approves: the wait ends.
        let approve = log.append(
            MAC,
            atem_client::membership::entry::Action::RecoveryApprove {
                target: recovery_hash,
            },
        );
        carry(&mut rig, &mut ch, vec![approve]);
        assert_eq!(
            rig.bridge.membership.as_ref().unwrap().deferred_stop(),
            None
        );
        rig.until(|r| input(r).contains("DEFERRED_DELEGATED")).await;
        complete(&mut rig, &task).await;
    });
}

/// §11.6 ("Deadline comparisons"): a delegated task's deadline is compared
/// with the delegated clock's `D` only, never with the wall clock v1 uses:
/// with `D` an hour behind the wall clock, a deadline the wall clock passed
/// long ago doesn't expire the task until `D` reaches it; with `D` ahead of
/// the wall clock, a deadline still ahead on the wall clock has passed.
#[test]
fn deadlines_use_the_delegated_clock() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        // The manual OS an hour behind the host's wall clock.
        let os = ManualOs::at(host_now().wall_ms - 3_600_000);
        let (phone, _) = delegated(&mut rig, root, &os, false);
        let task = enqueue(&mut rig, &phone, "DEADLINE_PROMPT");
        rig.until(|r| {
            stored_record(r, &task).status.detail == details::REVOCATIONS_NOT_YET_CHECKED
        })
        .await;
        // Its deadline 10 s ahead on `D`, long past on the wall clock.
        let deadline = os.0.lock().unwrap().wall_ms + 10_000;
        assert!(host_now().wall_ms > deadline);
        let mut record = stored_record(&rig, &task);
        record.task.expires_at = deadline;
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .save_work(&record)
            .unwrap();
        passes(&mut rig, 3);
        assert_eq!(stored_record(&rig, &task).status.state, WorkState::Blocked);
        // `D` reaches it.
        os.pass(10_000);
        rig.until(|r| stored_record(r, &task).status.state == WorkState::Expired)
            .await;
        assert_eq!(
            stored_record(&rig, &task).status.detail,
            "expired before submission"
        );
        assert!(attempts(&rig, &task).is_empty());
        // `D` two hours on, an hour ahead of the wall clock: a task whose
        // deadline is a minute ahead on the wall clock expires at once.
        os.pass(2 * 3_600_000);
        let ahead = enqueue(&mut rig, &phone, "DEADLINE_AHEAD");
        let expires_at = stored_record(&rig, &ahead).task.expires_at;
        assert!(expires_at > host_now().wall_ms);
        rig.until(|r| stored_record(r, &ahead).status.state == WorkState::Expired)
            .await;
        // The start check reads the same reading (the pass's `D`).
        assert!(
            rig.bridge
                .start_view()
                .now_d_ms
                .is_some_and(|d| d >= expires_at)
        );
    });
}

/// Step 4's Decision 10, ruling T18a: a task accepted while
/// `host.delegated` was on, not started, after a restart without the hook
/// stays `blocked`, `host.delegated is off`, never dispatched and not
/// holding its session (a local task runs), and expires at its deadline on
/// the delegated clock, which the bridge builds because the store holds a
/// delegated task.
#[test]
fn hook_off_after_acceptance_blocks_and_expires_on_the_delegated_clock() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        // Accepted with the hook on, before any pass dispatched it.
        let task = enqueue(&mut rig, &phone, "HOOK_OFF_PROMPT");
        // The hook is gone (the runtime restarted without it): the store
        // holds a delegated task, so the delegated clock is built anyway.
        rig.bridge.features = HostFeatures::default();
        rig.bridge.work.clock = None;
        rig.bridge.work.clock_checked = false;
        rig.bridge.ensure_clock();
        assert!(
            rig.bridge.work.clock.is_some(),
            "built for the delegated task"
        );
        manual_clock(&mut rig, &os);
        rig.until(|r| stored_record(r, &task).status.detail == details::HOST_DELEGATED_IS_OFF)
            .await;
        assert_eq!(stored_record(&rig, &task).status.state, WorkState::Blocked);
        local_task_runs(&mut rig, "LOCAL_WITH_THE_HOOK_OFF").await;
        assert!(attempts(&rig, &task).is_empty());
        assert!(!input(&rig).contains("HOOK_OFF_PROMPT"));
        // Its deadline, on `D`.
        let deadline = stored_record(&rig, &task).task.expires_at;
        let wall = os.0.lock().unwrap().wall_ms;
        os.pass(deadline - wall);
        rig.until(|r| stored_record(r, &task).status.state == WorkState::Expired)
            .await;
        assert_eq!(
            stored_record(&rig, &task).status.detail,
            "expired before submission"
        );
        assert!(attempts(&rig, &task).is_empty());
    });
}

/// Design I.6.4, I.4.3: an attempt the start check withdraws for a hold
/// isn't counted, one withdrawn for another event is; the task takes the
/// event's state, which beats `too many attempts` (here a revocation's
/// `cancelled` on the eighth counted end). The attempts are made and
/// submitted as the dispatch makes them, the view changing in between, as
/// a record applied there would.
#[test]
fn withdrawals_at_the_start_settle_from_the_event() {
    use crate::runtime::delegated::attempts::AttemptEnd;
    use crate::runtime::delegated::start::StartTask;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let held = enqueue(&mut rig, &phone, "HELD_PROMPT");
        let revoked = enqueue(&mut rig, &phone, "REVOKED_PROMPT");
        rig.bridge.sync_host_work(&mut Cx {
            client: &rig.app.astation_client,
            sessions: &mut rig.sessions,
        });
        let att = rig.bridge.host_work_attachment().unwrap().to_string();
        // The view as a pass leaves it (its routes, the clock's reading).
        rig.bridge.refresh_start_view();
        let attempt = |rig: &LocalRig, task: &str| {
            let store = rig.bridge.work.store.as_ref().unwrap();
            let tx = store.immediate().unwrap();
            let a = store.new_attempt(&tx, task).unwrap();
            tx.commit().unwrap();
            a
        };
        let submit =
            |rig: &mut LocalRig, task: &str, a: &crate::runtime::delegated::attempts::Attempt| {
                let record = stored_record(rig, task);
                rig.bridge
                    .start_view()
                    .register(&a.attempt_id, StartTask::of(&record).unwrap());
                let (binding, _) = rig
                    .bridge
                    .host
                    .binding_for_work(&att, &record.task.target)
                    .unwrap();
                let data = json!({"v": 1, "op": "submit", "id": uuid::Uuid::new_v4().to_string(),
                "binding": binding, "request_id": a.attempt_id, "kind": "prompt",
                "payload": {"text": "x"}, "acquire": true});
                let effects = rig.bridge.host.submit_host_work(
                    &att,
                    data,
                    crate::session_protocol::host::Provenance {
                        task_id: task.to_string(),
                        sender: PHONE.into(),
                    },
                );
                rig.bridge.exec(
                    effects,
                    &mut Cx {
                        client: &rig.app.astation_client,
                        sessions: &mut rig.sessions,
                    },
                );
            };
        // A hold between the dispatch and the start.
        rig.bridge.start_view().standings.insert(
            PHONE.into(),
            SenderStanding {
                held: true,
                ..SenderStanding::default()
            },
        );
        let h = attempt(&rig, &held);
        submit(&mut rig, &held, &h);
        assert_eq!(
            rig.bridge.start_view().refused(&h.attempt_id),
            Some(Event::Held)
        );
        // Seven counted no-effect ends of the other task, then a revocation
        // between the dispatch of its eighth and the start.
        for _ in 0..MAX_ATTEMPTS - 1 {
            let a = attempt(&rig, &revoked);
            let store = rig.bridge.work.store.as_ref().unwrap();
            let tx = store.immediate().unwrap();
            store
                .end_attempt(&tx, &revoked, &a.attempt_id, AttemptEnd::NotAdmitted)
                .unwrap();
            tx.commit().unwrap();
        }
        rig.bridge.start_view().standings.insert(
            PHONE.into(),
            SenderStanding {
                revoked: Some("rec-1".into()),
                ..SenderStanding::default()
            },
        );
        // The lease the held attempt took is given back, as the pass does
        // once host-work has no request open there.
        rig.bridge.renew_host_work_leases();
        let last = attempt(&rig, &revoked);
        submit(&mut rig, &revoked, &last);
        assert_eq!(
            rig.bridge.start_view().refused(&last.attempt_id),
            Some(Event::Revoked)
        );
        rig.until(|r| stored_record(r, &revoked).status.state == WorkState::Cancelled)
            .await;
        assert_eq!(
            stored_record(&rig, &revoked).status.detail,
            details::SENDER_REVOKED
        );
        let ends = attempts(&rig, &revoked);
        assert_eq!(ends.len(), MAX_ATTEMPTS as usize);
        assert_eq!(
            ends.last().unwrap(),
            &(last.attempt_id.clone(), Some("withdrawn".into()), true)
        );
        // The hold's withdrawal: not counted (that task is cancelled now
        // too, by the revocation, before any other attempt).
        assert_eq!(
            attempts(&rig, &held),
            [(h.attempt_id.clone(), Some("withdrawn".into()), false)]
        );
        assert_eq!(
            stored_record(&rig, &held).status.state,
            WorkState::Cancelled
        );
        let text = input(&rig);
        assert!(!text.contains("HELD_PROMPT") && !text.contains("REVOKED_PROMPT"));
    });
}

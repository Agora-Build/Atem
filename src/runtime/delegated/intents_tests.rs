// Interrupt intents and the deadline interrupt in the bridge (design I.4.4,
// I.5.7, I.6.2 step 3; session-v1 R9.14 item 5; host-work-v1 §11.6): the
// rig's host with a pinned device list, the phone's delegated tasks on the
// fake agent, the delegated clock on a manual OS (deadlines move only with
// it, never with real time). Included beside the dispatch's, the
// lifecycle's and the recovery's tests, whose helpers and imports it
// shares.

use crate::runtime::delegated::intents::{Intent, IntentReason};

/// The interrupt keys the agent was given: bare Esc bytes (a bracketed
/// paste's `ESC [` doesn't count).
fn escs(rig: &LocalRig) -> usize {
    let text = input(rig);
    text.matches('\x1b').count() - text.matches("\x1b[").count()
}

/// Waits, without a pass, until the fake agent has appended `n` Escs: it
/// appends what it read on its own poll, ordered after neither the
/// worker's answer nor the pass that records the delivery (the bound only
/// limits a failure). The exact count is asserted after.
async fn escs_reach(rig: &LocalRig, n: usize) {
    let deadline = Instant::now() + Duration::from_secs(60);
    while escs(rig) < n {
        assert!(Instant::now() < deadline, "the agent got {n} Esc");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// The worker gets what was written and answers it (the passes alone never
/// yield to it): a write no pass should have made shows as an Esc too.
async fn settle(rig: &mut LocalRig) {
    rig.until(|r| r.bridge.pending.is_empty()).await;
}

/// `task`'s intents, oldest first.
fn intents(rig: &LocalRig, task: &str) -> Vec<Intent> {
    rig.bridge
        .work
        .store
        .as_ref()
        .unwrap()
        .intents_of(task)
        .unwrap()
}

/// The intent of `task` for `reason`, committed as the pass commits one (a
/// crash may come before anything acts on it).
fn commit_intent(rig: &LocalRig, task: &str, reason: IntentReason) {
    let store = rig.bridge.work.store.as_ref().unwrap();
    let attempt = store.work(task).unwrap().unwrap().status.receipt_id;
    let tx = store.immediate().unwrap();
    assert!(store.write_intent(&tx, task, &attempt, reason).unwrap());
    tx.commit().unwrap();
}

/// The session host's receipt of `task`'s current attempt.
fn attempt_receipt(rig: &LocalRig, task: &str) -> wire::Receipt {
    let attempt = stored_record(rig, task).status.receipt_id;
    rig.bridge
        .host
        .attempt_receipt(&attempt, task)
        .expect("the attempt's receipt")
}

/// The agent ends its turn interrupted, as after an Esc (its
/// "[Request interrupted by user]" entry); the attempt's receipt completes
/// `interrupted` (host-work's scheduling may be held meanwhile).
async fn turn_interrupted(rig: &mut LocalRig, task: &str) {
    std::fs::write(rig.fake.join("interrupt"), "").unwrap();
    rig.until(|r| attempt_receipt(r, task).state == wire::ReceiptState::Completed)
        .await;
    assert_eq!(
        attempt_receipt(rig, task).detail.as_deref(),
        Some("interrupted")
    );
}

/// The write of the host interrupt for `attempt` on the rig's session that
/// waits for the worker's answer: its sequence.
fn pending_write(rig: &LocalRig, attempt: &str) -> Option<u64> {
    rig.bridge
        .pending
        .iter()
        .find_map(|((sid, seq), p)| match p {
            super::Pending::HostInterrupt(rid) if sid == rig.sid.as_str() && rid == attempt => {
                Some(*seq)
            }
            _ => None,
        })
}

/// A native member's attachment (`view`, `control`), welcomed as r9
/// admission welcomes one (on no link: what is sent to it goes nowhere).
fn native_controller(rig: &mut LocalRig) -> String {
    use crate::session_protocol::host::Attach;
    use crate::session_protocol::wire::{ClientKind, Permission};
    let att = uuid::Uuid::new_v4().to_string();
    rig.bridge
        .host
        .connect(Attach {
            client: "mac".into(),
            principal: "mac".into(),
            attachment_gen: att.clone(),
            permissions: vec![Permission::View, Permission::Control],
            client_kind: ClientKind::Native,
            authorization_ms: 24 * HOUR,
        })
        .unwrap();
    let now = rig.bridge.clock.now();
    rig.bridge.host.welcome_r9(&att, now).unwrap();
    let _ = rig.bridge.host.take_effects();
    att
}

/// The native `att` takes the rig's session's lease over (an explicit
/// `takeover`), and the bridge performs what it causes.
fn take_over(rig: &mut LocalRig, att: &str) {
    let ctx = rig.bridge.host.context().clone();
    let binding = json!({"target": {"account_id": ctx.account_id,
        "atem_device_id": ctx.atem_device_id, "host_trust_gen": ctx.host_trust_gen,
        "session_id": rig.sid.to_string(),
        "process_gen": rig.sessions[&rig.sid].process_gen},
        "attachment_gen": att});
    let message = json!({"type": "session", "data": {"v": 1, "op": "acquire",
        "id": uuid::Uuid::new_v4().to_string(), "binding": binding, "takeover": true}});
    let now = rig.bridge.clock.now();
    let effects = rig
        .bridge
        .host
        .receive(att, message.to_string().as_bytes(), now);
    rig.bridge.exec(
        effects,
        &mut Cx {
            client: &rig.app.astation_client,
            sessions: &mut rig.sessions,
        },
    );
    assert_eq!(rig.bridge.host.lease_holder(rig.sid.as_str()), Some(att));
}

/// The phone's task of `prompt`, due 10 minutes after `start`, whose turn
/// runs (its prompt written, its turn journaled: the chat shows it running).
async fn running_until_deadline(
    rig: &mut LocalRig,
    phone: &Authority,
    prompt: &str,
    start: u64,
) -> String {
    let task = phone_task(rig, phone, prompt, start + 10 * MIN);
    turn_journaled(rig, &task, prompt).await;
    task
}

/// Design I.4.4, I.5.7: a delegated turn still running when the delegated
/// clock reaches its task's deadline gets an interrupt intent, reason
/// `deadline`, for its attempt, committed in the pass that saw the
/// deadline, which then carries it out: the Esc is written once, on the
/// host's authority, and the turn it reached is recorded once the worker
/// reported it written. One intent per attempt; nothing before the
/// deadline; no second Esc while the turn goes on (the fake agent ignores
/// it).
#[test]
fn deadline_writes_an_intent_for_a_running_turn() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let task = running_until_deadline(&mut rig, &phone, "DEADLINE_RUNNING", start).await;
        let attempt = stored_record(&rig, &task).status.receipt_id;
        os.pass(10 * MIN - 1);
        passes(&mut rig, 3);
        assert!(intents(&rig, &task).is_empty(), "not before the deadline");
        assert_eq!(escs(&rig), 0);
        os.pass(1);
        passes(&mut rig, 1);
        let written = intents(&rig, &task);
        assert_eq!(written.len(), 1, "{written:?}");
        assert_eq!(
            (written[0].attempt_id.as_str(), &written[0].reason),
            (attempt.as_str(), &IntentReason::Deadline)
        );
        assert_eq!(written[0].done_ms, None, "pending while the turn runs");
        assert!(pending_write(&rig, &attempt).is_some(), "written this pass");
        rig.until(|r| intents(r, &task)[0].delivered_turn.is_some())
            .await;
        escs_reach(&rig, 1).await;
        assert_eq!(escs(&rig), 1);
        for _ in 0..10 {
            passes(&mut rig, 1);
            assert_eq!(pending_write(&rig, &attempt), None, "once per turn");
        }
        settle(&mut rig).await;
        assert_eq!(escs(&rig), 1, "once per turn");
        assert_eq!(intents(&rig, &task).len(), 1, "one per attempt");
        assert_eq!(intents(&rig, &task)[0].done_ms, None);
        assert_eq!(settled(&rig, &task).0, WorkState::Submitted);
        assert_eq!(input(&rig).matches("DEADLINE_RUNNING").count(), 1);
    });
}

/// Design I.5.7 ("Attempt not yet `executing`: it is withdrawn, and the
/// task … expired"), PR 6 review n1: an attempt waiting `accepted` behind
/// another turn is withdrawn once the delegated clock reaches its task's
/// deadline, before its turn comes: the task is `expired` (`expired before
/// submission`), its attempt ends `withdrawn`, its receipt is `rejected`
/// (`withdrawn by the host`), the intent is done, and nothing is written:
/// no Esc, the running turn of the other task goes on, and the withdrawn
/// prompt never reaches the agent.
#[test]
fn an_intent_withdraws_an_unstarted_attempt_and_the_task_expires() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let running = phone_task(&mut rig, &phone, "WITHDRAW_RUNNING", start + 3 * HOUR);
        turn_journaled(&mut rig, &running, "WITHDRAW_RUNNING").await;
        let waiting = phone_task(&mut rig, &phone, "WITHDRAW_WAITING", start + 10 * MIN);
        blocked(
            &mut rig,
            &waiting,
            "waiting for an earlier task on this session",
        )
        .await;
        let attempt = attempt_behind_the_turn(&mut rig, &waiting, "WITHDRAW_WAITING");
        passes(&mut rig, 3);
        assert_eq!(
            attempts(&rig, &waiting),
            [(attempt.clone(), None, true)],
            "waits accepted before its deadline"
        );
        os.pass(10 * MIN);
        passes(&mut rig, 1);
        let receipt = rig.bridge.host.attempt_receipt(&attempt, &waiting).unwrap();
        assert_eq!(
            (receipt.state, receipt.detail.as_deref()),
            (
                wire::ReceiptState::Rejected,
                Some(details::WITHDRAWN_BY_THE_HOST)
            )
        );
        assert_eq!(
            attempts(&rig, &waiting),
            [(attempt.clone(), Some("withdrawn".into()), true)]
        );
        assert_eq!(
            settled(&rig, &waiting),
            (WorkState::Expired, "expired before submission".into())
        );
        let done = intents(&rig, &waiting);
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].attempt_id, attempt);
        assert!(done[0].done_ms.is_some(), "done: its attempt was withdrawn");
        assert_eq!(done[0].delivered_turn, None);
        assert_eq!(escs(&rig), 0, "nothing interrupted");
        assert_eq!(settled(&rig, &running).0, WorkState::Submitted);
        complete(&mut rig, &running).await;
        passes(&mut rig, 5);
        assert!(!input(&rig).contains("WITHDRAW_WAITING"));
        assert_eq!(attempts(&rig, &waiting).len(), 1);
    });
}

/// Task 26 re-review N2, PR 8 review n2: withdrawing an attempt still
/// waiting `accepted` at its task's deadline is a stop, so it is done while
/// hosting is paused too (`runtime.toml` stopped loading), and its task is
/// `expired` (`expired before submission`) at once: the one record change
/// of a pause. Nothing is written, and the other task's turn goes on.
#[test]
fn a_paused_host_withdraws_an_accepted_attempt_and_the_task_expires() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let running = phone_task(&mut rig, &phone, "PAUSED_W_RUNNING", start + 3 * HOUR);
        turn_journaled(&mut rig, &running, "PAUSED_W_RUNNING").await;
        let waiting = phone_task(&mut rig, &phone, "PAUSED_W_WAITING", start + 10 * MIN);
        blocked(
            &mut rig,
            &waiting,
            "waiting for an earlier task on this session",
        )
        .await;
        let attempt = attempt_behind_the_turn(&mut rig, &waiting, "PAUSED_W_WAITING");
        passes(&mut rig, 3);
        assert_eq!(attempts(&rig, &waiting), [(attempt.clone(), None, true)]);
        // `runtime.toml` stops loading, then the deadline passes.
        rig.bridge.work.config = Config::default();
        rig.bridge.work.config_problem = Some("expected a table".into());
        assert!(!rig.bridge.hosting_enabled());
        os.pass(10 * MIN);
        passes(&mut rig, 1);
        let receipt = rig.bridge.host.attempt_receipt(&attempt, &waiting).unwrap();
        assert_eq!(
            (receipt.state, receipt.detail.as_deref()),
            (
                wire::ReceiptState::Rejected,
                Some(details::WITHDRAWN_BY_THE_HOST)
            )
        );
        assert_eq!(
            attempts(&rig, &waiting),
            [(attempt.clone(), Some("withdrawn".into()), true)]
        );
        assert_eq!(
            settled(&rig, &waiting),
            (WorkState::Expired, "expired before submission".into())
        );
        assert!(intents(&rig, &waiting)[0].done_ms.is_some());
        assert_eq!(escs(&rig), 0, "nothing interrupted");
        assert_eq!(settled(&rig, &running).0, WorkState::Submitted);
        assert!(!input(&rig).contains("PAUSED_W_WAITING"));
    });
}

/// Design I.4.4: the turn interrupted at its deadline ends `interrupted`
/// (the attempt's prompt receipt completes so, R9.14 item 5): the task goes
/// to `awaiting_result`, detail `interrupted at deadline` (§11.6), then
/// expires as today (`expired awaiting a result`) at the next pass. The
/// intent is done once the turn ended. One Esc in all.
#[test]
fn interrupted_at_deadline_then_expired() {
    use crate::runtime::host_work::EXPIRED_AWAITING;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let task = running_until_deadline(&mut rig, &phone, "DEADLINE_INTERRUPTED", start).await;
        os.pass(10 * MIN);
        passes(&mut rig, 1);
        rig.until(|r| intents(r, &task)[0].delivered_turn.is_some())
            .await;
        // Host-work's scheduling held while the turn ends, so each pass
        // after it is seen.
        hold_host_work(&mut rig);
        turn_interrupted(&mut rig, &task).await;
        assert_eq!(settled(&rig, &task).0, WorkState::Submitted);
        passes(&mut rig, 1);
        assert_eq!(
            settled(&rig, &task),
            (
                WorkState::AwaitingResult,
                details::INTERRUPTED_AT_DEADLINE.into()
            )
        );
        assert!(intents(&rig, &task)[0].done_ms.is_some(), "the turn ended");
        passes(&mut rig, 1);
        assert_eq!(
            settled(&rig, &task),
            (WorkState::Expired, EXPIRED_AWAITING.into())
        );
        passes(&mut rig, 3);
        escs_reach(&rig, 1).await;
        assert_eq!(escs(&rig), 1);
        assert_eq!(input(&rig).matches("DEADLINE_INTERRUPTED").count(), 1);
    });
}

/// Design I.5.7 ("Pending intents are carried out again after a restart"),
/// I.6.2 step 3; session-v1 R9.14 item 5's restart bullet: an intent
/// committed just before a crash, nothing acted on it, is carried out at
/// the start's recovery, step 3, once the start's reconciliation rebound
/// the running turn (while the adopted worker's chat hasn't arrived, it
/// stays pending and nothing is written). A second crash after the Esc was
/// delivered, the turn still running: the next run delivers it once more
/// (delivery is per run). Its turn then ends interrupted, and the task
/// awaits its result, `interrupted at deadline`, then expires.
#[test]
fn an_intent_survives_a_restart_and_is_carried_out() {
    use crate::runtime::host_work::EXPIRED_AWAITING;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let task = running_until_deadline(&mut rig, &phone, "RESTART_RUNNING", start).await;
        hold_host_work(&mut rig);
        os.pass(10 * MIN);
        commit_intent(&rig, &task, IntentReason::Deadline);
        assert_eq!(escs(&rig), 0);
        // The adopted worker's chat hasn't reached the new broker yet.
        rig.sessions.get_mut(&rig.sid).unwrap().chat_synced = false;
        let steps = restart(&mut rig, root, &os, false, true);
        assert_eq!(steps[2], RecoveryStep::PendingIntents(vec![task.clone()]));
        let attempt = stored_record(&rig, &task).status.receipt_id;
        assert!(rig.bridge.host_work_reconciling(&attempt));
        passes(&mut rig, 3);
        assert_eq!(escs(&rig), 0, "pending while the turn isn't known");
        assert_eq!(intents(&rig, &task)[0].done_ms, None);
        // The chat arrives: the turn is rebound, and the intent delivers.
        rig.sessions.get_mut(&rig.sid).unwrap().chat_synced = true;
        rig.until(|r| intents(r, &task)[0].delivered_turn.is_some())
            .await;
        assert!(!rig.bridge.host_work_reconciling(&attempt));
        escs_reach(&rig, 1).await;
        assert_eq!(escs(&rig), 1);
        for _ in 0..5 {
            passes(&mut rig, 1);
            assert_eq!(pending_write(&rig, &attempt), None, "once per turn");
        }
        settle(&mut rig).await;
        assert_eq!(escs(&rig), 1);

        // A crash after the delivery: the next run delivers once more,
        // at the recovery (the adopted chat already there).
        let steps = restart(&mut rig, root, &os, false, true);
        assert_eq!(steps[2], RecoveryStep::PendingIntents(vec![task.clone()]));
        rig.until(|r| intents(r, &task)[0].delivered_turn.is_some() && escs(r) == 2)
            .await;
        for _ in 0..5 {
            passes(&mut rig, 1);
            assert_eq!(pending_write(&rig, &attempt), None, "once in this run");
        }
        settle(&mut rig).await;
        assert_eq!(escs(&rig), 2, "once in this run");
        hold_host_work(&mut rig);
        turn_interrupted(&mut rig, &task).await;
        passes(&mut rig, 1);
        assert_eq!(
            settled(&rig, &task),
            (
                WorkState::AwaitingResult,
                details::INTERRUPTED_AT_DEADLINE.into()
            )
        );
        passes(&mut rig, 1);
        assert_eq!(
            settled(&rig, &task),
            (WorkState::Expired, EXPIRED_AWAITING.into())
        );
        let all = intents(&rig, &task);
        assert_eq!(all.len(), 1, "{all:?}");
        assert!(all[0].done_ms.is_some());
        assert_eq!(input(&rig).matches("RESTART_RUNNING").count(), 1);
    });
}

/// Design I.5.7 ("interrupting a turn that has already ended does
/// nothing"): an intent committed just before a crash whose turn then ended
/// on its own while no broker ran (its receipt reconciled `completed` at
/// the start) is done at the recovery's step 3 with nothing written: no
/// Esc, no delivery recorded. The task follows its receipt
/// (`awaiting_result`, not `interrupted at deadline`) and expires at step 6.
#[test]
fn an_ended_turn_makes_the_intent_do_nothing() {
    use crate::runtime::host_work::EXPIRED_AWAITING;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let task = running_until_deadline(&mut rig, &phone, "ENDED_RUNNING", start).await;
        hold_host_work(&mut rig);
        os.pass(10 * MIN);
        commit_intent(&rig, &task, IntentReason::Deadline);
        // The turn ends before the crash (the receipt completes `done`;
        // host-work's pass never ran again).
        std::fs::write(rig.fake.join("complete"), "").unwrap();
        rig.until(|r| attempt_receipt(r, &task).state == wire::ReceiptState::Completed)
            .await;
        assert_eq!(settled(&rig, &task).0, WorkState::Submitted);
        let steps = restart(&mut rig, root, &os, false, true);
        assert_eq!(steps[2], RecoveryStep::PendingIntents(vec![task.clone()]));
        let all = intents(&rig, &task);
        assert!(all[0].done_ms.is_some(), "done at step 3: {all:?}");
        assert_eq!(all[0].delivered_turn, None);
        assert_eq!(expired(&steps), std::slice::from_ref(&task));
        assert_eq!(
            settled(&rig, &task),
            (WorkState::Expired, EXPIRED_AWAITING.into())
        );
        passes(&mut rig, 5);
        settle(&mut rig).await;
        assert_eq!(escs(&rig), 0);
    });
}

/// Session-v1 R9.14 item 5: an Esc the worker reports `consumed` (as on
/// Codex, when it only handed a waiting approval to Codex's own dialog)
/// wrote nothing: the intent's next pass writes it again, and that one,
/// reported written, is the turn's delivery; no third. (The worker's
/// answer to the first write is replaced by a `consumed` one before the
/// bridge reads it: the fake Claude agent has no approval dialog.)
#[test]
fn a_consumed_esc_is_written_again_next_pass() {
    use crate::runtime::broker::WriteOutcome;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let task = running_until_deadline(&mut rig, &phone, "CONSUMED_RUNNING", start).await;
        let attempt = stored_record(&rig, &task).status.receipt_id;
        os.pass(10 * MIN);
        passes(&mut rig, 1);
        let seq = pending_write(&rig, &attempt).expect("written, its answer awaited");
        // The worker's answer to it, taken before the bridge sees it.
        let deadline = Instant::now() + Duration::from_secs(60);
        let mut others = Vec::new();
        loop {
            let session = rig.sessions.get_mut(&rig.sid).unwrap();
            session.pump();
            let results = session.take_results();
            let found = results.iter().any(|r| r.seq == seq);
            others.extend(results.into_iter().filter(|r| r.seq != seq));
            if found {
                break;
            }
            assert!(Instant::now() < deadline, "the worker answers the write");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        escs_reach(&rig, 1).await;
        assert_eq!(escs(&rig), 1, "the worker wrote it");
        // Told `consumed` (nothing written) instead.
        let sid = rig.sid.to_string();
        let consumed = WriteOutcome {
            seq,
            ok: false,
            dropped: false,
            no_effect: true,
            consumed: true,
            error: None,
        };
        let mut cx = Cx {
            client: &rig.app.astation_client,
            sessions: &mut rig.sessions,
        };
        for result in others.into_iter().chain([consumed]) {
            rig.bridge.write_result(&sid, result, &mut cx);
        }
        assert!(pending_write(&rig, &attempt).is_none());
        assert_eq!(intents(&rig, &task)[0].delivered_turn, None);
        passes(&mut rig, 1);
        assert!(
            pending_write(&rig, &attempt).is_some(),
            "written again on the next pass"
        );
        assert_eq!(intents(&rig, &task)[0].delivered_turn, None);
        rig.until(|r| intents(r, &task)[0].delivered_turn.is_some())
            .await;
        for _ in 0..10 {
            passes(&mut rig, 1);
            assert_eq!(pending_write(&rig, &attempt), None, "no third");
        }
        settle(&mut rig).await;
        escs_reach(&rig, 2).await;
        assert_eq!(escs(&rig), 2, "the consumed write and the delivered one");
    });
}

/// Design I.5.7 ("A native takeover therefore can't silently defeat the
/// owner's choice"), R9.14 item 5 ("only the lease revocation repeats"):
/// after the deadline's interrupt was delivered, a native controller takes
/// the session's lease over; the intent's next pass revokes it again, and
/// again after a second takeover, writing nothing. Once the turn ended the
/// intent is done, and a takeover keeps its lease.
#[test]
fn an_intent_revokes_a_native_takeover_again() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let task = running_until_deadline(&mut rig, &phone, "TAKEOVER_RUNNING", start).await;
        let attempt = stored_record(&rig, &task).status.receipt_id;
        os.pass(10 * MIN);
        passes(&mut rig, 1);
        rig.until(|r| intents(r, &task)[0].delivered_turn.is_some())
            .await;
        let mac = native_controller(&mut rig);
        for _ in 0..2 {
            take_over(&mut rig, &mac);
            let epoch = rig.bridge.host.input_epoch(rig.sid.as_str());
            passes(&mut rig, 1);
            assert_eq!(pending_write(&rig, &attempt), None, "nothing written");
            assert_eq!(
                rig.bridge.host.lease_holder(rig.sid.as_str()),
                None,
                "revoked again"
            );
            assert!(rig.bridge.host.input_epoch(rig.sid.as_str()) > epoch);
        }
        settle(&mut rig).await;
        assert_eq!(escs(&rig), 1, "nothing written by a revocation");
        hold_host_work(&mut rig);
        turn_interrupted(&mut rig, &task).await;
        passes(&mut rig, 2);
        assert!(intents(&rig, &task)[0].done_ms.is_some());
        take_over(&mut rig, &mac);
        passes(&mut rig, 3);
        assert_eq!(
            rig.bridge.host.lease_holder(rig.sid.as_str()),
            Some(mac.as_str()),
            "the intent is done: the takeover stands"
        );
        escs_reach(&rig, 1).await;
        assert_eq!(escs(&rig), 1);
    });
}

/// Hosting is paused (`runtime.toml` stopped loading: hosting off, as
/// `work_config` leaves it) while a delegated turn runs, and the delegated
/// clock reaches its deadline. Design I.4.4 still holds (ruling T26a): the
/// deadline's intent is written and the Esc delivered once, while paused.
/// Host-work dispatches nothing during the pause: the next task of the
/// session gets no attempt, even once the interrupted turn ended. When the file loads
/// again, the task awaits its result, `interrupted at deadline`, then
/// expires, and the next task runs.
#[test]
fn a_paused_host_still_interrupts_a_turn_at_its_deadline() {
    use crate::runtime::host_work::EXPIRED_AWAITING;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let task = running_until_deadline(&mut rig, &phone, "PAUSED_RUNNING", start).await;
        let attempt = stored_record(&rig, &task).status.receipt_id;
        let next = phone_task(&mut rig, &phone, "PAUSED_NEXT", start + 3 * HOUR);
        blocked(
            &mut rig,
            &next,
            "waiting for an earlier task on this session",
        )
        .await;
        // `runtime.toml` stops loading.
        let config = std::mem::take(&mut rig.bridge.work.config);
        rig.bridge.work.config_problem = Some("expected a table".into());
        assert!(!rig.bridge.hosting_enabled());
        os.pass(10 * MIN);
        passes(&mut rig, 1);
        let written = intents(&rig, &task);
        assert_eq!(written.len(), 1, "{written:?}");
        assert_eq!(written[0].reason, IntentReason::Deadline);
        assert!(
            pending_write(&rig, &attempt).is_some(),
            "written while paused"
        );
        rig.until(|r| intents(r, &task)[0].delivered_turn.is_some())
            .await;
        for _ in 0..5 {
            passes(&mut rig, 1);
            assert_eq!(pending_write(&rig, &attempt), None, "once per turn");
        }
        settle(&mut rig).await;
        escs_reach(&rig, 1).await;
        assert_eq!(escs(&rig), 1);
        // The turn ends interrupted; host-work dispatches nothing while
        // paused.
        turn_interrupted(&mut rig, &task).await;
        passes(&mut rig, 5);
        settle(&mut rig).await;
        assert!(intents(&rig, &task)[0].done_ms.is_some(), "its turn ended");
        assert!(attempts(&rig, &next).is_empty(), "no attempt while paused");
        assert!(!input(&rig).contains("PAUSED_NEXT"));
        assert_eq!(settled(&rig, &task).0, WorkState::Submitted, "untouched");
        // The file loads again.
        rig.bridge.work.config = config;
        rig.bridge.work.config_problem = None;
        passes(&mut rig, 1);
        assert_eq!(
            settled(&rig, &task),
            (
                WorkState::AwaitingResult,
                details::INTERRUPTED_AT_DEADLINE.into()
            )
        );
        passes(&mut rig, 1);
        assert_eq!(
            settled(&rig, &task),
            (WorkState::Expired, EXPIRED_AWAITING.into())
        );
        rig.until(|r| input(r).contains("PAUSED_NEXT")).await;
        complete(&mut rig, &next).await;
        assert_eq!(escs(&rig), 1);
    });
}

/// Hosting switched off (`enabled = false`, a deliberate stop) while a
/// delegated turn runs past its deadline: the deadline's interrupt is
/// still delivered, once (ruling T26a).
#[test]
fn hosting_switched_off_still_interrupts_a_turn_at_its_deadline() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let task = running_until_deadline(&mut rig, &phone, "OFF_RUNNING", start).await;
        let attempt = stored_record(&rig, &task).status.receipt_id;
        rig.bridge.work.config.enabled = false;
        assert!(!rig.bridge.hosting_enabled());
        os.pass(10 * MIN);
        passes(&mut rig, 1);
        assert!(pending_write(&rig, &attempt).is_some(), "written while off");
        rig.until(|r| intents(r, &task)[0].delivered_turn.is_some())
            .await;
        for _ in 0..5 {
            passes(&mut rig, 1);
            assert_eq!(pending_write(&rig, &attempt), None, "once per turn");
        }
        settle(&mut rig).await;
        escs_reach(&rig, 1).await;
        assert_eq!(escs(&rig), 1);
        assert_eq!(settled(&rig, &task).0, WorkState::Submitted);
    });
}

/// Task 26 review M1: a turn that ended interrupted for another reason (an
/// Esc at the terminal, before the deadline) reads `turn interrupted`, not
/// `interrupted at deadline`, though the pass that reconciles it after the
/// deadline writes the deadline's intent too: only a turn the deadline's
/// interrupt reached is the deadline's. The intent is done, with nothing
/// written.
#[test]
fn a_turn_interrupted_otherwise_reads_turn_interrupted() {
    use crate::runtime::host_work::EXPIRED_AWAITING;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let task = running_until_deadline(&mut rig, &phone, "OTHER_RUNNING", start).await;
        hold_host_work(&mut rig);
        turn_interrupted(&mut rig, &task).await;
        os.pass(10 * MIN);
        passes(&mut rig, 1);
        assert_eq!(
            settled(&rig, &task),
            (WorkState::AwaitingResult, TURN_INTERRUPTED.into())
        );
        let all = intents(&rig, &task);
        assert_eq!(all.len(), 1, "{all:?}");
        assert!(all[0].done_ms.is_some());
        assert_eq!(all[0].delivered_turn, None);
        passes(&mut rig, 1);
        assert_eq!(
            settled(&rig, &task),
            (WorkState::Expired, EXPIRED_AWAITING.into())
        );
        settle(&mut rig).await;
        assert_eq!(escs(&rig), 0);
    });
}

/// Task 26 review M1, the timing: the worker's report of the deadline's
/// Esc and the turn's interrupted end reach the same scheduling pass (here
/// both arrive while host-work's scheduling is held). The report is taken
/// before that pass reconciles the receipt, so the turn reads
/// `interrupted at deadline`.
#[test]
fn a_delivery_reported_with_the_turns_end_reads_interrupted_at_deadline() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let task = running_until_deadline(&mut rig, &phone, "SAME_PASS_RUNNING", start).await;
        let attempt = stored_record(&rig, &task).status.receipt_id;
        os.pass(10 * MIN);
        passes(&mut rig, 1);
        assert!(pending_write(&rig, &attempt).is_some());
        hold_host_work(&mut rig);
        turn_interrupted(&mut rig, &task).await;
        rig.until(|r| pending_write(r, &attempt).is_none()).await;
        assert_eq!(
            intents(&rig, &task)[0].delivered_turn,
            None,
            "not taken yet"
        );
        passes(&mut rig, 1);
        assert!(intents(&rig, &task)[0].delivered_turn.is_some());
        assert_eq!(
            settled(&rig, &task),
            (
                WorkState::AwaitingResult,
                details::INTERRUPTED_AT_DEADLINE.into()
            )
        );
    });
}

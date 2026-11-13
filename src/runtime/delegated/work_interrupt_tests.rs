// `work_interrupt` in the bridge (feature `host.delegated`; design I.4.5;
// host-work-v1 §11.2; session-v1 R9.14 item 5; step 4's Decision 15): the
// rig's host with a pinned device list, the phone's and the bot's delegated
// tasks on the fake agent (which ignores an Esc: the tests end its turns),
// and the delegated clock on a manual OS. Included beside the dispatch's,
// the lifecycle's, the recovery's and the intents' tests, whose helpers and
// imports it shares.

/// The bot's ops with `interrupt`.
const BOT_OPS_INTERRUPT: [&str; 6] = ["interrupt", "message", "notify", "prompt", "stop", "view"];

/// `who`'s `work_interrupt` of `task` answers `not running`: the task's
/// status as stored, that detail in this one result only. Nothing is
/// stored (the record, and what `work_query` reads, keep their detail).
fn not_running(rig: &mut LocalRig, who: &Authority, task: &str) {
    let before = stored_record(rig, task).status;
    let got = status(ask(rig, who, Q::Interrupt(task)));
    assert_eq!(got.detail, details::NOT_RUNNING);
    assert_eq!(
        WorkStatus {
            detail: before.detail.clone(),
            ..got
        },
        before,
        "the status as it is"
    );
    assert_eq!(stored_record(rig, task).status, before, "nothing stored");
    assert_eq!(status(ask(rig, who, Q::Query(task))), before);
}

/// Design I.4.5, host-work-v1 §11.2: the task's sender, holding `interrupt`
/// in its current grant (a bot whose scope lists it), interrupts its task's
/// running turn. The result is a `work` result with the task's status, and
/// the Esc is written at once on the host's authority, once (it is no
/// submission: no receipt of its own, and no intent: a one-shot request).
/// The turn ends interrupted and the task awaits its result.
#[test]
fn work_interrupt_by_the_sender_with_interrupt() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot_ops(&mut rig, root, &os, start + 3 * HOUR, &BOT_OPS_INTERRUPT);
        let task = bot_task(&mut rig, &s, "SENDER_INTERRUPT", start + HOUR);
        turn_journaled(&mut rig, &task, "SENDER_INTERRUPT").await;
        let attempt = stored_record(&rig, &task).status.receipt_id;
        let before = stored_record(&rig, &task).status;
        assert_eq!(status(ask(&mut rig, &s.bot, Q::Interrupt(&task))), before);
        assert!(pending_write(&rig, &attempt).is_some(), "written at once");
        settle(&mut rig).await;
        assert_eq!(escs(&rig), 1);
        passes(&mut rig, 5);
        settle(&mut rig).await;
        assert_eq!(escs(&rig), 1, "one-shot: nothing repeats it");
        assert!(intents(&rig, &task).is_empty(), "no intent");
        turn_interrupted(&mut rig, &task).await;
        rig.until(|r| stored_record(r, &task).status.state == WorkState::AwaitingResult)
            .await;
        assert_eq!(
            settled(&rig, &task),
            (WorkState::AwaitingResult, TURN_INTERRUPTED.into())
        );
        assert_eq!(escs(&rig), 1);
        assert_eq!(input(&rig).matches("SENDER_INTERRUPT").count(), 1);
    });
}

/// Decision 15, design I.4.5: the owner (a native member holding `control`
/// at the head: the Mac) interrupts any delegated task's running turn,
/// here the bot's, whose grant has no `interrupt`. A second owner's request
/// while the first's write waits for the worker's answer writes nothing
/// (one write in flight per attempt) and still answers the status. A viewer
/// (`view` only) is `forbidden`. A v1 task (admitted with the hook off) is
/// `forbidden` to the owner and to its own sender: only a delegated task is
/// interrupted on the host's authority.
#[test]
fn work_interrupt_by_the_owner() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        let task = bot_task(&mut rig, &s, "OWNER_INTERRUPT", start + HOUR);
        turn_journaled(&mut rig, &task, "OWNER_INTERRUPT").await;
        // The phone's v1 task (the hook off): no admission.
        rig.bridge.features = HostFeatures::default();
        let v1 = phone_task(&mut rig, &s.phone, "OWNER_V1", start + HOUR);
        rig.bridge.features = HostFeatures::parse("host.delegated").unwrap();
        assert_eq!(stored_record(&rig, &v1).delegated, None);
        assert_eq!(ask(&mut rig, &s.mac, Q::Interrupt(&v1)), forbidden());
        assert_eq!(ask(&mut rig, &s.phone, Q::Interrupt(&v1)), forbidden());
        let attempt = stored_record(&rig, &task).status.receipt_id;
        let before = stored_record(&rig, &task).status;
        assert_eq!(ask(&mut rig, &s.viewer, Q::Interrupt(&task)), forbidden());
        assert_eq!(pending_write(&rig, &attempt), None);
        assert_eq!(status(ask(&mut rig, &s.mac, Q::Interrupt(&task))), before);
        let seq = pending_write(&rig, &attempt).expect("written at once");
        // The phone holds `control` too: another owner.
        assert_eq!(status(ask(&mut rig, &s.phone, Q::Interrupt(&task))), before);
        assert_eq!(pending_write(&rig, &attempt), Some(seq), "no second write");
        settle(&mut rig).await;
        assert_eq!(escs(&rig), 1);
        turn_interrupted(&mut rig, &task).await;
        rig.until(|r| stored_record(r, &task).status.state == WorkState::AwaitingResult)
            .await;
        assert_eq!(
            settled(&rig, &task),
            (WorkState::AwaitingResult, TURN_INTERRUPTED.into())
        );
        assert_eq!(escs(&rig), 1);
    });
}

/// Host-work-v1 §11.2: when the task's turn isn't the session's current
/// turn, nothing happens, and the result is the task's status as it is
/// with `detail` `not running`, in that one result only: the record keeps
/// its detail, and `work_query` reads it. Nothing is written, withdrawn or
/// recorded. So for a task queued behind another's turn; its attempt
/// waiting `accepted` there (not executing); a turn the start's
/// reconciliation hasn't rebound yet after a restart (its adopted chat not
/// arrived: still reconciling, which says nothing of the turn); and a task
/// whose turn ended.
#[test]
fn not_running_detail_is_not_stored() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let running = phone_task(&mut rig, &phone, "NOT_RUNNING_TURN", start + 3 * HOUR);
        turn_journaled(&mut rig, &running, "NOT_RUNNING_TURN").await;
        let waiting = phone_task(&mut rig, &phone, "NOT_RUNNING_WAITING", start + 3 * HOUR);
        blocked(
            &mut rig,
            &waiting,
            "waiting for an earlier task on this session",
        )
        .await;
        not_running(&mut rig, &phone, &waiting);
        // Its attempt waits `accepted` behind the turn: not executing.
        let attempt = attempt_behind_the_turn(&mut rig, &waiting, "NOT_RUNNING_WAITING");
        not_running(&mut rig, &phone, &waiting);
        assert_eq!(
            rig.bridge
                .host
                .attempt_receipt(&attempt, &waiting)
                .unwrap()
                .state,
            wire::ReceiptState::Accepted,
            "not withdrawn"
        );
        assert_eq!(attempts(&rig, &waiting), [(attempt.clone(), None, true)]);
        // A restart; the adopted worker's chat hasn't reached the new
        // broker yet: the running turn is still being reconciled.
        rig.sessions.get_mut(&rig.sid).unwrap().chat_synced = false;
        restart(&mut rig, root, &os, false, true);
        let turn = stored_record(&rig, &running).status.receipt_id;
        assert!(rig.bridge.host_work_reconciling(&turn));
        not_running(&mut rig, &phone, &running);
        settle(&mut rig).await;
        assert_eq!(escs(&rig), 0, "never a blind Esc");
        // The chat arrives and the turn is rebound: now it is interrupted.
        rig.sessions.get_mut(&rig.sid).unwrap().chat_synced = true;
        rig.until(|r| !r.bridge.host_work_reconciling(&turn)).await;
        let before = stored_record(&rig, &running).status;
        assert_eq!(
            status(ask(&mut rig, &phone, Q::Interrupt(&running))),
            before
        );
        settle(&mut rig).await;
        assert_eq!(escs(&rig), 1);
        // Its turn ended: not running.
        complete(&mut rig, &running).await;
        not_running(&mut rig, &phone, &running);
        settle(&mut rig).await;
        assert_eq!(escs(&rig), 1);
        assert!(intents(&rig, &running).is_empty());
        assert!(intents(&rig, &waiting).is_empty());
    });
}

/// Host-work-v1 §11.2: the result is the task's status as it stood when
/// the interrupt was accepted, before the interrupt is written (`submitted`,
/// in the agent's turn, its current attempt's `receipt_id`); the turn's end
/// shows in later queries (`awaiting_result`, `turn interrupted`), and the
/// same request then answers that status, `not running`.
#[test]
fn the_result_is_the_status_before_the_interrupt() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let task = phone_task(&mut rig, &phone, "BEFORE_INTERRUPT", start + HOUR);
        turn_journaled(&mut rig, &task, "BEFORE_INTERRUPT").await;
        rig.until(|r| {
            let s = stored_record(r, &task).status;
            s.state == WorkState::Submitted && s.detail == collab_bridge::IN_TURN
        })
        .await;
        let before = stored_record(&rig, &task).status;
        let got = status(ask(&mut rig, &phone, Q::Interrupt(&task)));
        assert_eq!(got, before);
        assert_eq!(
            (got.state, got.detail.as_str()),
            (WorkState::Submitted, collab_bridge::IN_TURN)
        );
        assert_eq!(
            got.receipt_id,
            attempts(&rig, &task)[0].0,
            "its current attempt"
        );
        turn_interrupted(&mut rig, &task).await;
        rig.until(|r| stored_record(r, &task).status.state == WorkState::AwaitingResult)
            .await;
        let after = status(ask(&mut rig, &phone, Q::Query(&task)));
        assert_eq!(
            (after.state, after.detail.as_str()),
            (WorkState::AwaitingResult, TURN_INTERRUPTED)
        );
        let again = status(ask(&mut rig, &phone, Q::Interrupt(&task)));
        assert_eq!(
            (again.state, again.detail.as_str()),
            (WorkState::AwaitingResult, details::NOT_RUNNING)
        );
        assert_eq!(settled(&rig, &task).1, TURN_INTERRUPTED);
        settle(&mut rig).await;
        assert_eq!(escs(&rig), 1);
    });
}

/// Host-work-v1 §11.2 "Authority": the channel took the bot's request (it
/// holds `notify`), and the host refuses it: the bot is the task's sender
/// with current authority, but its grant has no `interrupt`. `forbidden`,
/// nothing written, and the bot still reads its task. The owner's
/// interrupt of the same turn goes through.
#[test]
fn a_sender_without_interrupt_is_forbidden() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        let task = bot_task(&mut rig, &s, "NO_INTERRUPT", start + HOUR);
        turn_journaled(&mut rig, &task, "NO_INTERRUPT").await;
        let attempt = stored_record(&rig, &task).status.receipt_id;
        assert_eq!(ask(&mut rig, &s.bot, Q::Interrupt(&task)), forbidden());
        assert_eq!(pending_write(&rig, &attempt), None);
        settle(&mut rig).await;
        assert_eq!(escs(&rig), 0);
        assert_eq!(
            status(ask(&mut rig, &s.bot, Q::Query(&task))).task_id,
            task,
            "its sender still"
        );
        assert_eq!(
            status(ask(&mut rig, &s.mac, Q::Interrupt(&task))).state,
            WorkState::Submitted
        );
        settle(&mut rig).await;
        assert_eq!(escs(&rig), 1);
    });
}

/// Task 26 review, notes for Task 27: `work_interrupt` and a pending
/// deadline intent of the same attempt share this run's record of the
/// turn's interrupt, so a turn gets one Esc, whichever comes first.
/// - **The request first**, the intent pending and not carried out yet:
///   while the request's write waits for the worker's answer the intent's
///   passes only revoke, and once it is reported written the intent counts
///   it as delivered.
/// - **The intent's delivery first** (the next task's turn, at its own
///   deadline): the request writes nothing, and its result is still the
///   task's status (the turn is the session's current turn).
#[test]
fn a_pending_intent_and_work_interrupt_give_one_esc() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let first = running_until_deadline(&mut rig, &phone, "ONE_ESC_FIRST", start).await;
        let next = phone_task(&mut rig, &phone, "ONE_ESC_NEXT", start + 20 * MIN);
        let attempt = stored_record(&rig, &first).status.receipt_id;
        hold_host_work(&mut rig);
        os.pass(10 * MIN);
        commit_intent(&rig, &first, IntentReason::Deadline);
        assert_eq!(
            status(ask(&mut rig, &phone, Q::Interrupt(&first))).state,
            WorkState::Submitted
        );
        assert!(pending_write(&rig, &attempt).is_some());
        for _ in 0..10 {
            passes(&mut rig, 1);
        }
        settle(&mut rig).await;
        assert_eq!(escs(&rig), 1);
        for _ in 0..5 {
            passes(&mut rig, 1);
            assert_eq!(pending_write(&rig, &attempt), None, "one Esc per turn");
        }
        settle(&mut rig).await;
        assert_eq!(escs(&rig), 1, "one Esc per turn");
        let pending = intents(&rig, &first);
        assert_eq!(pending.len(), 1, "{pending:?}");
        assert_eq!(pending[0].done_ms, None, "pending while the turn runs");
        // The first turn ends; the next task's turn runs.
        turn_interrupted(&mut rig, &first).await;
        rig.until(|r| intents(r, &first)[0].done_ms.is_some()).await;
        turn_journaled(&mut rig, &next, "ONE_ESC_NEXT").await;
        let next_attempt = stored_record(&rig, &next).status.receipt_id;
        os.pass(10 * MIN);
        passes(&mut rig, 1);
        rig.until(|r| {
            intents(r, &next)
                .first()
                .is_some_and(|i| i.delivered_turn.is_some())
        })
        .await;
        assert_eq!(escs(&rig), 2);
        assert_eq!(
            status(ask(&mut rig, &phone, Q::Interrupt(&next))).state,
            WorkState::Submitted
        );
        assert_eq!(pending_write(&rig, &next_attempt), None, "nothing written");
        for _ in 0..5 {
            passes(&mut rig, 1);
            assert_eq!(pending_write(&rig, &next_attempt), None);
        }
        settle(&mut rig).await;
        assert_eq!(escs(&rig), 2, "one Esc per turn");
        hold_host_work(&mut rig);
        turn_interrupted(&mut rig, &next).await;
        passes(&mut rig, 1);
        assert_eq!(
            settled(&rig, &next),
            (
                WorkState::AwaitingResult,
                details::INTERRUPTED_AT_DEADLINE.into()
            ),
            "the deadline's Esc ended it"
        );
    });
}

/// Task 26 review M1, notes for Task 27: a turn that `work_interrupt`'s Esc
/// ended reads `turn interrupted`, never `interrupted at deadline`, even
/// with the deadline's intent pending for it (the request's write counted
/// as that intent's delivery, so no second Esc, but the turn isn't the
/// deadline's). The task then expires at its deadline as any other.
#[test]
fn a_turn_ended_by_work_interrupt_reads_turn_interrupted() {
    use crate::runtime::host_work::EXPIRED_AWAITING;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let task = running_until_deadline(&mut rig, &phone, "REQUEST_ENDED", start).await;
        hold_host_work(&mut rig);
        os.pass(10 * MIN);
        commit_intent(&rig, &task, IntentReason::Deadline);
        status(ask(&mut rig, &phone, Q::Interrupt(&task)));
        // Reported written while host-work's scheduling is held; the turn
        // ends interrupted.
        settle(&mut rig).await;
        turn_interrupted(&mut rig, &task).await;
        passes(&mut rig, 1);
        assert_eq!(
            settled(&rig, &task),
            (WorkState::AwaitingResult, TURN_INTERRUPTED.into())
        );
        let all = intents(&rig, &task);
        assert!(all[0].done_ms.is_some(), "the turn ended: {all:?}");
        assert_eq!(all[0].delivered_turn, None, "not the deadline's Esc");
        passes(&mut rig, 1);
        assert_eq!(
            settled(&rig, &task),
            (WorkState::Expired, EXPIRED_AWAITING.into())
        );
        settle(&mut rig).await;
        assert_eq!(escs(&rig), 1);
    });
}

/// With the session journal halted the turn can't be interrupted (nothing
/// passes the write boundary until the restart, which settles the attempt):
/// `busy`, never `not running` (the turn may well be the current one), and
/// nothing written.
#[test]
fn a_halted_journal_is_busy() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let task = phone_task(&mut rig, &phone, "HALTED_TURN", start + HOUR);
        turn_journaled(&mut rig, &task, "HALTED_TURN").await;
        let attempt = stored_record(&rig, &task).status.receipt_id;
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
        let before = stored_record(&rig, &task).status;
        assert_eq!(ask(&mut rig, &phone, Q::Interrupt(&task)), busy());
        assert_eq!(pending_write(&rig, &attempt), None);
        assert_eq!(stored_record(&rig, &task).status, before);
        settle(&mut rig).await;
        assert_eq!(escs(&rig), 0);
    });
}

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
        rig.until(|r| escs(r) == 1).await;
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
        rig.until(|r| escs(r) == 1).await;
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
        rig.until(|r| escs(r) == 1).await;
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
        rig.until(|r| escs(r) == 1).await;
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
        rig.until(|r| escs(r) == 1).await;
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
        rig.until(|r| escs(r) == 1).await;
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
        rig.until(|r| escs(r) == 2).await;
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
/// as that intent's delivery, so no second Esc, and stored on it as the
/// request's, ruling T27a: the turn isn't the deadline's). The task then
/// expires at its deadline as any other.
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
        // Ruling T27a: stored on the intent, as the request's delivery.
        assert!(all[0].delivered_turn.is_some(), "{all:?}");
        assert!(all[0].delivered_by_request, "not the deadline's Esc");
        passes(&mut rig, 1);
        assert_eq!(
            settled(&rig, &task),
            (WorkState::Expired, EXPIRED_AWAITING.into())
        );
        settle(&mut rig).await;
        rig.until(|r| escs(r) == 1).await;
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

/// Task 27 re-review N2 (§11.2, "Still `busy`"): after a receipt-database
/// fault `work_interrupt` is `busy` whoever asks and whatever the turn,
/// with nothing written, also when the request reaches the bridge in the
/// batch the fault happened in: this run's record of the turn's Esc may
/// have lost a report then, so a write could be a second Esc.
#[test]
fn a_receipt_database_fault_makes_work_interrupt_busy() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let task = phone_task(&mut rig, &phone, "FAULT_TURN", start + HOUR);
        turn_journaled(&mut rig, &task, "FAULT_TURN").await;
        let attempt = stored_record(&rig, &task).status.receipt_id;
        rig.bridge.work_fail();
        assert_eq!(ask(&mut rig, &phone, Q::Interrupt(&task)), busy());
        assert_eq!(pending_write(&rig, &attempt), None);
        settle(&mut rig).await;
        assert_eq!(escs(&rig), 0);
    });
}

/// Ruling T27a, case 1: `work_interrupt`'s Esc reaches the turn before any
/// intent exists; the deadline then comes while the same turn still runs
/// (the agent hasn't stopped), and its intent writes nothing: the turn had
/// its interrupt (this run's record, kept with no intent). One Esc. The
/// turn the request ended reads `turn interrupted`, then expires.
#[test]
fn a_request_then_the_deadline_in_one_turn_give_one_esc() {
    use crate::runtime::host_work::EXPIRED_AWAITING;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let task = running_until_deadline(&mut rig, &phone, "REQUEST_THEN_DEADLINE", start).await;
        let attempt = stored_record(&rig, &task).status.receipt_id;
        assert_eq!(
            status(ask(&mut rig, &phone, Q::Interrupt(&task))).state,
            WorkState::Submitted
        );
        assert!(intents(&rig, &task).is_empty(), "no intent yet");
        // Reported written, and taken in by a pass.
        settle(&mut rig).await;
        passes(&mut rig, 2);
        rig.until(|r| escs(r) == 1).await;
        os.pass(10 * MIN);
        for _ in 0..10 {
            passes(&mut rig, 1);
            assert_eq!(pending_write(&rig, &attempt), None, "one Esc per turn");
        }
        settle(&mut rig).await;
        assert_eq!(escs(&rig), 1, "one Esc per turn");
        let pending = intents(&rig, &task);
        assert_eq!(pending.len(), 1, "the deadline's: {pending:?}");
        assert_eq!(pending[0].done_ms, None, "pending while the turn runs");
        hold_host_work(&mut rig);
        turn_interrupted(&mut rig, &task).await;
        passes(&mut rig, 1);
        assert_eq!(
            settled(&rig, &task),
            (WorkState::AwaitingResult, TURN_INTERRUPTED.into())
        );
        passes(&mut rig, 1);
        assert_eq!(
            settled(&rig, &task),
            (WorkState::Expired, EXPIRED_AWAITING.into())
        );
        assert_eq!(escs(&rig), 1);
    });
}

/// Ruling T27a, case 2: repeated `work_interrupt`s of one turn, with no
/// intent, write one Esc. Every later request, while the first's write is
/// in flight and after it was reported written, writes nothing and
/// answers the task's status as it is (its own detail, not `not running`:
/// the turn is current). The record goes with the attempt's turn: the
/// session's next task's turn gets its own Esc.
#[test]
fn repeated_work_interrupts_of_one_turn_give_one_esc() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let task = phone_task(&mut rig, &phone, "REPEATED_INTERRUPT", start + HOUR);
        let next = phone_task(&mut rig, &phone, "REPEATED_NEXT", start + HOUR);
        turn_journaled(&mut rig, &task, "REPEATED_INTERRUPT").await;
        let attempt = stored_record(&rig, &task).status.receipt_id;
        let before = stored_record(&rig, &task).status;
        assert_eq!(status(ask(&mut rig, &phone, Q::Interrupt(&task))), before);
        let seq = pending_write(&rig, &attempt).expect("written");
        assert_eq!(status(ask(&mut rig, &phone, Q::Interrupt(&task))), before);
        assert_eq!(pending_write(&rig, &attempt), Some(seq), "in flight");
        settle(&mut rig).await;
        passes(&mut rig, 2);
        for _ in 0..3 {
            let now = stored_record(&rig, &task).status;
            assert_eq!(
                status(ask(&mut rig, &phone, Q::Interrupt(&task))),
                now,
                "the status as it is"
            );
            assert_ne!(now.detail, details::NOT_RUNNING);
            assert_eq!(pending_write(&rig, &attempt), None, "nothing written");
            passes(&mut rig, 1);
        }
        settle(&mut rig).await;
        rig.until(|r| escs(r) == 1).await;
        assert!(intents(&rig, &task).is_empty());
        // The turn ends; the next task's turn is another.
        turn_interrupted(&mut rig, &task).await;
        turn_journaled(&mut rig, &next, "REPEATED_NEXT").await;
        assert_eq!(
            status(ask(&mut rig, &phone, Q::Interrupt(&next))).state,
            WorkState::Submitted
        );
        settle(&mut rig).await;
        rig.until(|r| escs(r) == 2).await;
        assert!(
            !rig.bridge.work.intents.knows(&attempt),
            "the ended turn's record went"
        );
    });
}

/// Ruling T27a (2): a stop is served while hosting is paused when it can
/// be: `host.delegated` on, the store recovered, no receipt-database fault,
/// a paired host. Otherwise, as before, `busy`.
#[test]
fn stops_are_served_while_paused_only_when_they_can_be() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        delegated(&mut rig, root, &os, true);
        passes(&mut rig, 1);
        let identity = rig.bridge.work_host();
        // `runtime.toml` stops loading (hosting off, as `work_config`
        // leaves it).
        drop(std::mem::take(&mut rig.bridge.work.config));
        rig.bridge.work.config_problem = Some("expected a table".into());
        assert!(!rig.bridge.hosting_enabled());
        assert!(rig.bridge.stops_while_paused(&identity));
        rig.bridge.work.error = true;
        assert!(
            !rig.bridge.stops_while_paused(&identity),
            "a receipt-database fault"
        );
        rig.bridge.work.error = false;
        rig.bridge.work.recovered = false;
        assert!(!rig.bridge.stops_while_paused(&identity), "not recovered");
        rig.bridge.work.recovered = true;
        rig.bridge.features = HostFeatures::default();
        assert!(!rig.bridge.stops_while_paused(&identity), "the hook off");
    });
}

/// `client` (an attached r9 client of channel `handle`) sends the session
/// request `data` (`v` and a fresh `id` added) to the rig's engine, which
/// queues a host-work request for the next work pass: its id.
fn send_on(
    rig: &mut LocalRig,
    client: &mut atem_client::connect::Attached,
    handle: &str,
    mut data: Value,
) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    data["v"] = json!(1);
    data["id"] = json!(id);
    // The client's clock as `channel` started it (1 ms), a moment on.
    let frame = client
        .send(&json!({"type": "session", "data": data}), 2)
        .unwrap();
    envelope_in(rig, &envelope::frame(handle, &frame));
    id
}

/// What `client` got on `handle` since the last call: each reply's data
/// (a result, or an error's) by the request id it answers.
fn replies_on(
    rig: &mut LocalRig,
    client: &mut atem_client::connect::Attached,
    handle: &str,
) -> BTreeMap<String, Value> {
    use atem_client::connect::Event;
    let mut out = BTreeMap::new();
    for frame in frames_for(rig, handle) {
        for event in client.on_frame(&frame, 3).unwrap() {
            let data = match event {
                Event::Family(f) => f.data,
                Event::Error(e) => {
                    Some(serde_json::from_slice::<Value>(&e.to_bytes()).unwrap()["data"].clone())
                }
                _ => None,
            };
            if let Some(data) = data
                && let Some(re) = data["re"].as_str()
            {
                out.insert(re.to_string(), data);
            }
        }
    }
    out
}

/// Task 27 review m1 (ruling T27a): requests queued while hosting was on
/// reach the work pass where the pause begins. There only `work_interrupt`
/// is served (a stop); every other host-work request is `busy`, as before.
/// Through the phone's real r9 channel: a `work_query` and a
/// `work_interrupt` queued, `runtime.toml` stops loading, one pass.
#[test]
fn the_paused_pass_serves_only_work_interrupt() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, log) = delegated(&mut rig, root, &os, true);
        let task = phone_task(&mut rig, &phone, "PAUSED_PASS", start + HOUR);
        turn_journaled(&mut rig, &task, "PAUSED_PASS").await;
        let attempt = stored_record(&rig, &task).status.receipt_id;
        // The engine lists host work and `host.delegated` (hosting on).
        rig.bridge.r9.set_delegated_features(true, false);
        rig.bridge.r9.enable_host_work(true);
        r9_link_up(&mut rig);
        let mut client = channel(&mut rig, &log, "ph-paused", "dev-phone");
        let host = serde_json::to_value(rig.bridge.work_host()).unwrap();
        let query = send_on(
            &mut rig,
            &mut client,
            "ph-paused",
            json!({"op": "work_query", "host": host, "task_id": task}),
        );
        let interrupt = send_on(
            &mut rig,
            &mut client,
            "ph-paused",
            json!({"op": "work_interrupt", "host": host, "task_id": task}),
        );
        // `runtime.toml` stops loading before the pass takes them.
        drop(std::mem::take(&mut rig.bridge.work.config));
        rig.bridge.work.config_problem = Some("expected a table".into());
        passes(&mut rig, 1);
        let replies = replies_on(&mut rig, &mut client, "ph-paused");
        assert_eq!(replies[&query]["code"], "busy", "{replies:?}");
        assert_eq!(
            replies[&interrupt]["result"]["work"]["state"], "submitted",
            "{replies:?}"
        );
        assert!(pending_write(&rig, &attempt).is_some(), "the Esc written");
        rig.until(|r| escs(r) == 1).await;
    });
}

/// Task 27 review m3: a write the worker reported as having written nothing
/// (`consumed`, as on Codex when the Esc only handed a waiting approval to
/// its dialog) frees the turn at once: a retry before any pass took that
/// report in is written, not lost as a revoke-only answer.
#[test]
fn a_retry_after_a_write_that_wrote_nothing_is_written() {
    use crate::runtime::broker::WriteOutcome;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let task = phone_task(&mut rig, &phone, "RETRY_CONSUMED", start + HOUR);
        turn_journaled(&mut rig, &task, "RETRY_CONSUMED").await;
        let attempt = stored_record(&rig, &task).status.receipt_id;
        status(ask(&mut rig, &phone, Q::Interrupt(&task)));
        let seq = pending_write(&rig, &attempt).expect("written");
        // The worker's answer, replaced by `consumed` (no pass runs).
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
        assert_eq!(
            status(ask(&mut rig, &phone, Q::Interrupt(&task))).state,
            WorkState::Submitted
        );
        assert!(
            pending_write(&rig, &attempt).is_some(),
            "the retry is written"
        );
    });
}

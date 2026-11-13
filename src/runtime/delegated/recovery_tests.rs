// The recovery of delegated tasks at a start (design I.6.2, I.6.3;
// host-work-v1 §11.6 "Restart"; session-v1 R9.14 item 6), in the bridge: the
// rig's broker goes with no clean close (a crash) and the next one opens
// over the same journal, store, device list and `runtime.toml`, adopting
// the rig's session as its worker runs (or finding it gone). Included
// beside the dispatch's and the lifecycle's tests, whose helpers and
// imports it shares.

use super::delegated_recovery::{Recovered, RecoveryStep};

const MIN: u64 = 60_000;

/// The broker goes with no clean close (nothing of it is written: a crash)
/// and the next one opens over the same journal, store, device list and
/// `runtime.toml`, with the same features and the delegated clock on `os`;
/// its start view is new. The rig's session is adopted as its worker runs,
/// or, with `gone`, its worker is gone. With `gate`, the host's own
/// Station's gate is open in the new view before anything runs (as if a
/// gate could outlive the run: the recovery closes every one). Its first
/// pass runs the start's recovery: the recovery's steps.
fn restart(
    rig: &mut LocalRig,
    root: &Path,
    os: &ManualOs,
    gone: bool,
    gate: bool,
) -> Vec<RecoveryStep> {
    let config = rig.bridge.work.config.clone();
    let features = rig.bridge.features;
    // The journal is the old broker's until it goes.
    let scratch = HostBridge::open(
        &root.join("scratch/runtime/journal"),
        None,
        Clock::default(),
    )
    .unwrap();
    drop(std::mem::replace(&mut rig.bridge, scratch));
    let mut bridge =
        HostBridge::open(&root.join("runtime/journal"), None, Clock::default()).unwrap();
    bridge.host.set_refuse_r8(true);
    bridge.features = features;
    bridge.work.config = config;
    bridge.work.store = Some(Store::open(&root.join("runtime")).unwrap());
    rig.bridge = bridge;
    if gone {
        let session = rig.sessions.remove(&rig.sid).unwrap();
        let _ = session.stop();
    }
    let mut cx = Cx {
        client: &rig.app.astation_client,
        sessions: &mut rig.sessions,
    };
    assert!(rig.bridge.adopt_identity(
        &crate::runtime::host_bridge::Identity {
            account_id: "acct".into(),
            atem_device_id: "host".into(),
            host_trust_gen: 1
        },
        &mut cx
    ));
    // The list pinned before, opened as the runtime opens its pin.
    let pairing = crate::profile::Sources::in_dir(&root.join("profile"))
        .paths
        .pairing;
    rig.bridge.pairing = Some(pairing);
    rig.bridge.reopen_list_if_changed(&mut cx);
    rig.bridge.pairing = None;
    assert!(rig.bridge.membership.is_some());
    manual_clock(rig, os);
    if gate {
        rig.bridge.start_view().gates.open_own_station(ORIGIN);
    }
    assert!(rig.bridge.work.recovery.is_empty());
    rig.bridge.tick(&mut rig.app, &mut rig.sessions, false);
    std::mem::take(&mut rig.bridge.work.recovery)
}

/// The steps' names, in order.
fn kinds(steps: &[RecoveryStep]) -> Vec<&'static str> {
    steps
        .iter()
        .map(|s| match s {
            RecoveryStep::Identity(_) => "identity",
            RecoveryStep::SessionJournal { .. } => "session journal",
            RecoveryStep::PendingIntents(_) => "pending intents",
            RecoveryStep::Reconcile(_) => "reconcile",
            RecoveryStep::Routes(_) => "routes",
            RecoveryStep::Deadlines(_) => "deadlines",
            RecoveryStep::GatesClosed => "gates closed",
        })
        .collect()
}

/// What the reconcile step left `task` as, if it looked at it.
fn reconciled(steps: &[RecoveryStep], task: &str) -> Option<(WorkState, String)> {
    steps.iter().find_map(|s| match s {
        RecoveryStep::Reconcile(tasks) => tasks
            .iter()
            .find(|t| t.task_id == task)
            .map(|t: &Recovered| (t.state, t.detail.clone())),
        _ => None,
    })
}

/// The tasks the routes step failed.
fn routed_out(steps: &[RecoveryStep]) -> Vec<String> {
    steps
        .iter()
        .find_map(|s| match s {
            RecoveryStep::Routes(tasks) => Some(tasks.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

/// The tasks the deadlines step expired.
fn expired(steps: &[RecoveryStep]) -> Vec<String> {
    steps
        .iter()
        .find_map(|s| match s {
            RecoveryStep::Deadlines(tasks) => Some(tasks.clone()),
            _ => None,
        })
        .unwrap_or_default()
}

/// The phone enqueues `prompt` through `route`, its deadline `expires_at`.
fn phone_task_on(
    rig: &mut LocalRig,
    phone: &Authority,
    route: &str,
    prompt: &str,
    expires_at: u64,
) -> String {
    let mut req = phone_enqueue(rig, prompt);
    if let hw::Request::Enqueue { route_id, task, .. } = &mut req {
        *route_id = route.into();
        task.expires_at = expires_at;
    }
    as_phone(rig, phone, &req).unwrap();
    enqueued(&req)
}

/// A new attempt of `task`, committed (`submitting`) and registered as the
/// dispatch makes one, and not submitted: a crash between the commit and
/// the submit leaves it so. Its id.
fn committed_attempt(rig: &mut LocalRig, task: &str) -> String {
    let store = rig.bridge.work.store.as_ref().unwrap();
    let tx = store.immediate().unwrap();
    let attempt = store.new_attempt(&tx, task).unwrap();
    let mut record = store.work(task).unwrap().unwrap();
    record.status.state = WorkState::Submitting;
    record.status.detail = "dispatch intent persisted".into();
    store.save_work(&record).unwrap();
    tx.commit().unwrap();
    rig.bridge.start_view().register(
        &attempt.attempt_id,
        crate::runtime::delegated::start::StartTask::of(&record).unwrap(),
    );
    attempt.attempt_id
}

/// [`committed_attempt`], then submitted under host-work as the dispatch
/// submits it (`acquire`, with its provenance): on a ready session it
/// starts at once (the start check passes). Its id.
fn submitted_attempt(rig: &mut LocalRig, task: &str, prompt: &str) -> String {
    let attempt = committed_attempt(rig, task);
    let record = stored_record(rig, task);
    let att = rig.bridge.host_work_attachment().unwrap().to_string();
    let (mut binding, _) = rig
        .bridge
        .host
        .binding_for_work(&att, &record.task.target)
        .unwrap();
    binding.lease_epoch = None;
    let data = json!({"v": 1, "op": "submit", "id": uuid::Uuid::new_v4().to_string(),
        "binding": binding, "request_id": attempt, "kind": "prompt",
        "payload": {"text": prompt}, "acquire": true});
    let effects = rig.bridge.host.submit_host_work(
        &att,
        data,
        crate::session_protocol::host::Provenance {
            task_id: task.to_string(),
            sender: record.principal.clone(),
        },
    );
    rig.bridge.exec(
        effects,
        &mut Cx {
            client: &rig.app.astation_client,
            sessions: &mut rig.sessions,
        },
    );
    attempt
}

/// `task` runs: its prompt was written and its turn journaled (the chat
/// accepted it), so a restart finds the turn to reconnect (before that the
/// session host can't tell it is current: `outcome could not be
/// established`, Task 16a).
async fn turn_journaled(rig: &mut LocalRig, task: &str, prompt: &str) {
    rig.until(|r| {
        input(r).contains(prompt)
            && r.bridge
                .host
                .recorded_turn(&stored_record(r, task).status.receipt_id)
                .is_some()
    })
    .await;
}

/// Host-work's scheduling passes stop (the rest of each pass goes on): what
/// it would settle stays as it is until the crash.
fn hold_host_work(rig: &mut LocalRig) {
    rig.bridge.work.scheduled = Instant::now() + Duration::from_secs(3600);
}

/// Design I.6.2: before anything is dispatched, the recovery runs its
/// seven steps in order (identity, the session journal, the pending
/// interrupt intents, the reconciliation, the routes, the deadlines, the
/// gates), each settling what is its own: an attempt waiting `accepted` at
/// the crash is reconciled (withdrawn at recovery, so `queued`), a task of
/// a route changed while the runtime was down fails `route changed`, one
/// whose deadline passed on the delegated clock (its boot-time counter on,
/// the wall clock set an hour back) expires; every gate is closed after,
/// so the withdrawn task waits for its gate and no new attempt was made.
#[test]
fn recovery_runs_in_the_designs_order() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let mut rm2 = rig
            .bridge
            .work
            .config
            .routes
            .iter()
            .find(|r| r.id == "rm")
            .unwrap()
            .clone();
        rm2.id = "rm2".into();
        rig.bridge.work.config.routes.push(rm2);
        let running = phone_task(&mut rig, &phone, "ORDER_RUNNING", start + 3 * HOUR);
        turn_journaled(&mut rig, &running, "ORDER_RUNNING").await;
        let accepted = phone_task(&mut rig, &phone, "ORDER_ACCEPTED", start + 3 * HOUR);
        let routed = phone_task_on(&mut rig, &phone, "rm2", "ORDER_ROUTED", start + 3 * HOUR);
        let late = phone_task(&mut rig, &phone, "ORDER_LATE", start + 10 * MIN);
        for task in [&accepted, &routed, &late] {
            blocked(
                &mut rig,
                task,
                "waiting for an earlier task on this session",
            )
            .await;
        }
        let attempt = attempt_behind_the_turn(&mut rig, &accepted, "ORDER_ACCEPTED");
        // While the runtime is down: the route `rm2` gets a new revision,
        // and 20 minutes pass on the boot-time counter while the wall clock
        // is set an hour back.
        rig.bridge
            .work
            .config
            .routes
            .iter_mut()
            .find(|r| r.id == "rm2")
            .unwrap()
            .revision = 2;
        os.pass(20 * MIN);
        os.0.lock().unwrap().wall_ms -= 80 * MIN;
        let steps = restart(&mut rig, root, &os, false, true);
        assert_eq!(
            kinds(&steps),
            [
                "identity",
                "session journal",
                "pending intents",
                "reconcile",
                "routes",
                "deadlines",
                "gates closed"
            ],
            "{steps:?}"
        );
        assert_eq!(
            steps[0],
            RecoveryStep::Identity(rig.bridge.work_host()),
            "the store's identity"
        );
        assert_eq!(steps[1], RecoveryStep::SessionJournal { halted: false });
        assert_eq!(steps[2], RecoveryStep::PendingIntents(vec![]));
        assert_eq!(
            reconciled(&steps, &accepted),
            Some((WorkState::Queued, "waiting for a ready agent".into()))
        );
        assert_eq!(
            reconciled(&steps, &running).map(|(state, _)| state),
            Some(WorkState::Submitted)
        );
        assert_eq!(routed_out(&steps), std::slice::from_ref(&routed));
        assert_eq!(expired(&steps), std::slice::from_ref(&late));
        assert_eq!(
            settled(&rig, &routed),
            (WorkState::Failed, details::ROUTE_CHANGED.into())
        );
        assert_eq!(
            settled(&rig, &late),
            (WorkState::Expired, "expired before submission".into())
        );
        // The gates closed: the withdrawn task waits for its own, and its
        // first attempt is its only one.
        assert_eq!(
            settled(&rig, &accepted),
            (
                WorkState::Blocked,
                details::REVOCATIONS_NOT_YET_CHECKED.into()
            )
        );
        assert_eq!(
            attempts(&rig, &accepted),
            [(attempt.clone(), Some("withdrawn".into()), true)]
        );
        assert!(!rig.bridge.start_view().is_live(&attempt));
        // The gate opens: once the running turn ends, it runs, once.
        rig.bridge.start_view().gates.open_own_station(ORIGIN);
        complete(&mut rig, &running).await;
        rig.until(|r| input(r).contains("ORDER_ACCEPTED")).await;
        complete(&mut rig, &accepted).await;
        passes(&mut rig, 3);
        let text = input(&rig);
        assert_eq!(text.matches("ORDER_ACCEPTED").count(), 1);
        assert!(!text.contains("ORDER_ROUTED") && !text.contains("ORDER_LATE"));
    });
}

/// Design I.6.3 (`submitting` or `submitted`, by the attempt's receipt):
/// an attempt committed but never submitted (absent from the journal: a
/// crash between the commit and the submit) ends `not_admitted`, and one
/// the session host had `accepted` is withdrawn at recovery (R9.14 item 6)
/// and ends `withdrawn`: both tasks go back to `queued`, neither attempt is
/// live or sent again, and each task then runs once, on a new attempt. A
/// third attempt `accepted` at the crash is a tablet's, whose removal was
/// carried before it (I.6.3: "becomes `cancelled` (`sender revoked`) if its
/// sender has been revoked in the meantime"): its attempt ends `withdrawn`
/// and the task takes the event's state, never a second attempt.
#[test]
fn absent_or_accepted_attempt_returns_to_queued() {
    use atem_client::channel::Principal;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, mut log) = delegated(&mut rig, root, &os, true);
        // A tablet (a native member holding `control`) and its route `rt`.
        let added = log.add_native("dev-tablet", &["control", "view"]);
        carry(&mut rig, &log, added);
        rig.bridge
            .work
            .config
            .routes
            .push(crate::runtime::host_work::Route {
                id: "rt".into(),
                revision: 1,
                profile_id: "p".into(),
                principals: vec!["member:dev-tablet".into()],
                labels: vec![],
                launch: Default::default(),
                results: false,
                auto_report: Default::default(),
            });
        let tablet = resolve(
            &log,
            Principal::Native {
                device_id: "dev-tablet".into(),
            },
        );
        let running = phone_task(&mut rig, &phone, "QUEUED_RUNNING", start + 3 * HOUR);
        turn_journaled(&mut rig, &running, "QUEUED_RUNNING").await;
        let absent = phone_task(&mut rig, &phone, "QUEUED_ABSENT", start + 3 * HOUR);
        let accepted = phone_task(&mut rig, &phone, "QUEUED_ACCEPTED", start + 3 * HOUR);
        for task in [&absent, &accepted] {
            blocked(
                &mut rig,
                task,
                "waiting for an earlier task on this session",
            )
            .await;
        }
        let removed = phone_task_on(&mut rig, &tablet, "rt", "QUEUED_REMOVED", start + 3 * HOUR);
        blocked(
            &mut rig,
            &removed,
            "waiting for an earlier task on this session",
        )
        .await;
        let accepted_attempt = attempt_behind_the_turn(&mut rig, &accepted, "QUEUED_ACCEPTED");
        let removed_attempt = attempt_behind_the_turn(&mut rig, &removed, "QUEUED_REMOVED");
        let absent_attempt = committed_attempt(&mut rig, &absent);
        assert!(
            rig.bridge
                .host
                .attempt_receipt(&absent_attempt, &absent)
                .is_none()
        );
        // The tablet's removal commits; host-work's pass never sees it.
        let removal = log.remove("dev-tablet");
        carry(&mut rig, &log, removal);
        let steps = restart(&mut rig, root, &os, false, false);
        let queued = Some((WorkState::Queued, "waiting for a ready agent".to_string()));
        assert_eq!(reconciled(&steps, &absent), queued);
        assert_eq!(reconciled(&steps, &accepted), queued);
        let cancelled = Some((WorkState::Cancelled, details::SENDER_REVOKED.to_string()));
        assert_eq!(reconciled(&steps, &removed), cancelled);
        assert_eq!(
            attempts(&rig, &removed),
            [(removed_attempt.clone(), Some("withdrawn".into()), true)]
        );
        let receipt = rig
            .bridge
            .host
            .attempt_receipt(&accepted_attempt, &accepted)
            .unwrap();
        assert_eq!(
            (receipt.state, receipt.detail.as_deref()),
            (
                wire::ReceiptState::Rejected,
                Some(details::WITHDRAWN_AT_RECOVERY)
            )
        );
        assert_eq!(
            attempts(&rig, &absent),
            [(absent_attempt.clone(), Some("not_admitted".into()), true)]
        );
        assert_eq!(
            attempts(&rig, &accepted),
            [(accepted_attempt.clone(), Some("withdrawn".into()), true)]
        );
        for attempt in [&absent_attempt, &accepted_attempt, &removed_attempt] {
            assert!(!rig.bridge.start_view().is_live(attempt));
        }
        rig.bridge.start_view().gates.open_own_station(ORIGIN);
        complete(&mut rig, &running).await;
        for (task, prompt) in [(&absent, "QUEUED_ABSENT"), (&accepted, "QUEUED_ACCEPTED")] {
            rig.until(|r| input(r).contains(prompt)).await;
            complete(&mut rig, task).await;
        }
        passes(&mut rig, 3);
        let text = input(&rig);
        for prompt in ["QUEUED_ABSENT", "QUEUED_ACCEPTED"] {
            assert_eq!(text.matches(prompt).count(), 1, "{prompt}");
        }
        for (task, first) in [(&absent, &absent_attempt), (&accepted, &accepted_attempt)] {
            let all = attempts(&rig, task);
            assert_eq!(all.len(), 2, "{all:?}");
            assert_eq!(&all[0].0, first);
            assert_eq!(all[1].1.as_deref(), Some("started"));
        }
        // The removed tablet's task: no second attempt, never written.
        assert!(!text.contains("QUEUED_REMOVED"));
        assert_eq!(
            settled(&rig, &removed),
            (WorkState::Cancelled, details::SENDER_REVOKED.into())
        );
        assert_eq!(attempts(&rig, &removed).len(), 1);
    });
}

/// Design I.6.3 (`rejected` → no side effect: `failed` when the target is
/// gone): an attempt whose receipt the session host rejected `session
/// closed` before the crash (the session closed while it waited
/// `accepted`), and host-work never saw it: at the recovery the attempt
/// ends `rejected` and its task fails `session closed`, never sent again.
#[test]
fn rejected_attempt_with_its_target_gone_fails() {
    use crate::session_protocol::host::DETAIL_SESSION_CLOSED;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let running = phone_task(&mut rig, &phone, "GONE_RUNNING", start + 3 * HOUR);
        turn_journaled(&mut rig, &running, "GONE_RUNNING").await;
        let waiting = phone_task(&mut rig, &phone, "GONE_WAITING", start + 3 * HOUR);
        blocked(
            &mut rig,
            &waiting,
            "waiting for an earlier task on this session",
        )
        .await;
        let attempt = attempt_behind_the_turn(&mut rig, &waiting, "GONE_WAITING");
        let effects = rig.bridge.host.close_session(rig.sid.as_str(), false);
        rig.bridge.exec(
            effects,
            &mut Cx {
                client: &rig.app.astation_client,
                sessions: &mut rig.sessions,
            },
        );
        let receipt = rig.bridge.host.attempt_receipt(&attempt, &waiting).unwrap();
        assert_eq!(
            (receipt.state, receipt.detail.as_deref()),
            (wire::ReceiptState::Rejected, Some(DETAIL_SESSION_CLOSED))
        );
        let steps = restart(&mut rig, root, &os, false, true);
        let failed = Some((WorkState::Failed, DETAIL_SESSION_CLOSED.to_string()));
        assert_eq!(reconciled(&steps, &waiting), failed);
        assert_eq!(
            settled(&rig, &waiting),
            (WorkState::Failed, DETAIL_SESSION_CLOSED.into())
        );
        assert_eq!(
            attempts(&rig, &waiting),
            [(attempt.clone(), Some("rejected".into()), true)]
        );
        assert!(!rig.bridge.start_view().is_live(&attempt));
        complete(&mut rig, &running).await;
        passes(&mut rig, 5);
        assert!(!input(&rig).contains("GONE_WAITING"));
        assert_eq!(attempts(&rig, &waiting).len(), 1);
    });
}

/// Design I.6.3 (`executing` → `submitted`, reconnected through worker
/// adoption; the worker gone → `outcome_unknown` (`agent exited`), and the
/// task follows), consuming the session host's reconciliation of the
/// adopted chat (R9.14 item 6, Task 16a), never deciding it again: a crash
/// after an attempt's `executing` and its turn's journaling, before
/// host-work ended the attempt. With its worker adopted, the attempt ends
/// `started` and the task is `submitted`, reconnected to its turn, whose
/// end makes it `awaiting_result`, its prompt written once. With the worker
/// gone, the attempt ends `started` and the task is `outcome_unknown`, its
/// detail the receipt's `agent exited` (the reason its alert names).
#[test]
fn executing_attempt_is_reconnected_or_outcome_unknown_agent_exited() {
    use crate::session_protocol::host::DETAIL_AGENT_EXITED;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        passes(&mut rig, 2);
        let task = phone_task(&mut rig, &phone, "EXEC_RECONNECTED", start + 3 * HOUR);
        hold_host_work(&mut rig);
        let attempt = submitted_attempt(&mut rig, &task, "EXEC_RECONNECTED");
        rig.until(|r| r.bridge.host.recorded_turn(&attempt).is_some())
            .await;
        assert_eq!(
            rig.bridge
                .host
                .attempt_receipt(&attempt, &task)
                .unwrap()
                .state,
            wire::ReceiptState::Executing
        );
        assert_eq!(
            attempts(&rig, &task),
            [(attempt.clone(), None, true)],
            "live at the crash"
        );
        let steps = restart(&mut rig, root, &os, false, true);
        assert_eq!(
            reconciled(&steps, &task).map(|(state, _)| state),
            Some(WorkState::Submitted)
        );
        assert_eq!(
            attempts(&rig, &task),
            [(attempt.clone(), Some("started".into()), true)]
        );
        assert!(!rig.bridge.start_view().is_live(&attempt));
        rig.bridge.start_view().gates.open_own_station(ORIGIN);
        complete(&mut rig, &task).await;
        passes(&mut rig, 3);
        assert_eq!(input(&rig).matches("EXEC_RECONNECTED").count(), 1);
        assert_eq!(attempts(&rig, &task).len(), 1);

        // The next one's worker is gone at the restart.
        let next = phone_task(&mut rig, &phone, "EXEC_EXITED", start + 3 * HOUR);
        hold_host_work(&mut rig);
        let attempt = submitted_attempt(&mut rig, &next, "EXEC_EXITED");
        rig.until(|r| r.bridge.host.recorded_turn(&attempt).is_some())
            .await;
        let steps = restart(&mut rig, root, &os, true, true);
        let receipt = rig.bridge.host.attempt_receipt(&attempt, &next).unwrap();
        assert_eq!(
            (receipt.state, receipt.detail.as_deref()),
            (
                wire::ReceiptState::OutcomeUnknown,
                Some(DETAIL_AGENT_EXITED)
            )
        );
        let unknown = Some((WorkState::OutcomeUnknown, DETAIL_AGENT_EXITED.to_string()));
        assert_eq!(reconciled(&steps, &next), unknown);
        assert_eq!(
            settled(&rig, &next),
            (WorkState::OutcomeUnknown, DETAIL_AGENT_EXITED.into())
        );
        assert_eq!(
            attempts(&rig, &next),
            [(attempt.clone(), Some("started".into()), true)]
        );
    });
}

/// Design I.6.2 and I.6.3 ("A task that would return to `queued` becomes
/// `cancelled` (`sender revoked`) if its sender has been revoked in the
/// meantime"; I.3.3's removal row): the phone's removal commits while its
/// task waits for its gate, and the runtime goes before host-work's pass
/// sees it: at the recovery, before any gate, the task is cancelled
/// `sender revoked`.
#[test]
fn a_queued_task_of_a_removed_sender_is_cancelled_at_recovery() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, mut log) = delegated(&mut rig, root, &os, false);
        let task = phone_task(&mut rig, &phone, "REMOVED_QUEUED", start + 3 * HOUR);
        blocked(&mut rig, &task, details::REVOCATIONS_NOT_YET_CHECKED).await;
        hold_host_work(&mut rig);
        let removal = log.remove("dev-phone");
        carry(&mut rig, &log, removal);
        assert_eq!(
            settled(&rig, &task).1,
            details::REVOCATIONS_NOT_YET_CHECKED,
            "host-work's pass never saw it"
        );
        let steps = restart(&mut rig, root, &os, false, true);
        let cancelled = Some((WorkState::Cancelled, details::SENDER_REVOKED.to_string()));
        assert_eq!(reconciled(&steps, &task), cancelled);
        assert_eq!(settled(&rig, &task), outcome(Event::Removed));
        passes(&mut rig, 3);
        assert!(!input(&rig).contains("REMOVED_QUEUED"));
        assert!(attempts(&rig, &task).is_empty());
    });
}

/// Design I.6.2 step 6, host-work-v1 §11.6 ("Deadline comparisons"): at
/// the recovery, deadlines are compared with a fresh reading of the
/// delegated clock. While the runtime was down the boot-time counter moved
/// 20 minutes and the wall clock went an hour back: a waiting task and one
/// awaiting its result, both due at 10 minutes, expire (`expired before
/// submission`, `expired awaiting a result`), though the wall clock is
/// before their deadlines; one due in three hours waits on, and the
/// running turn goes on.
#[test]
fn deadlines_settle_on_the_delegated_clock_at_recovery() {
    use crate::runtime::host_work::EXPIRED_AWAITING;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let awaiting = phone_task(&mut rig, &phone, "DUE_AWAITING", start + 10 * MIN);
        rig.until(|r| input(r).contains("DUE_AWAITING")).await;
        complete(&mut rig, &awaiting).await;
        let running = phone_task(&mut rig, &phone, "DUE_RUNNING", start + 3 * HOUR);
        turn_journaled(&mut rig, &running, "DUE_RUNNING").await;
        let waiting = phone_task(&mut rig, &phone, "DUE_WAITING", start + 10 * MIN);
        let later = phone_task(&mut rig, &phone, "DUE_LATER", start + 3 * HOUR);
        for task in [&waiting, &later] {
            blocked(
                &mut rig,
                task,
                "waiting for an earlier task on this session",
            )
            .await;
        }
        os.pass(20 * MIN);
        os.0.lock().unwrap().wall_ms -= 80 * MIN;
        assert!(os.0.lock().unwrap().wall_ms < start + 10 * MIN);
        let steps = restart(&mut rig, root, &os, false, true);
        let mut due = expired(&steps);
        due.sort();
        let mut want = vec![awaiting.clone(), waiting.clone()];
        want.sort();
        assert_eq!(due, want);
        assert_eq!(
            settled(&rig, &waiting),
            (WorkState::Expired, "expired before submission".into())
        );
        assert_eq!(
            settled(&rig, &awaiting),
            (WorkState::Expired, EXPIRED_AWAITING.into())
        );
        assert_ne!(settled(&rig, &later).0, WorkState::Expired);
        assert_eq!(settled(&rig, &running).0, WorkState::Submitted);
        rig.bridge.start_view().gates.open_own_station(ORIGIN);
        complete(&mut rig, &running).await;
        rig.until(|r| input(r).contains("DUE_LATER")).await;
        assert!(!input(&rig).contains("DUE_WAITING"));
    });
}

/// Step 4's Decision 10 at a start: the runtime comes back without
/// `host.delegated` (the hook removed) while a delegated task's attempt
/// waited `accepted`. The session journal withdraws it at recovery as
/// ever; the attempt ends `withdrawn` and the task is `blocked`,
/// `host.delegated is off`, never dispatched again, while the started one
/// follows its receipt.
#[test]
fn with_the_hook_off_a_withdrawn_attempts_task_is_blocked_never_run() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        let running = phone_task(&mut rig, &phone, "OFF_RUNNING", start + 3 * HOUR);
        turn_journaled(&mut rig, &running, "OFF_RUNNING").await;
        let waiting = phone_task(&mut rig, &phone, "OFF_WAITING", start + 3 * HOUR);
        blocked(
            &mut rig,
            &waiting,
            "waiting for an earlier task on this session",
        )
        .await;
        let attempt = attempt_behind_the_turn(&mut rig, &waiting, "OFF_WAITING");
        rig.bridge.features = HostFeatures::default();
        let steps = restart(&mut rig, root, &os, false, false);
        let off = Some((
            WorkState::Blocked,
            details::HOST_DELEGATED_IS_OFF.to_string(),
        ));
        assert_eq!(reconciled(&steps, &waiting), off);
        assert_eq!(
            attempts(&rig, &waiting),
            [(attempt.clone(), Some("withdrawn".into()), true)]
        );
        complete(&mut rig, &running).await;
        passes(&mut rig, 5);
        assert_eq!(
            settled(&rig, &waiting),
            (WorkState::Blocked, details::HOST_DELEGATED_IS_OFF.into())
        );
        assert!(!input(&rig).contains("OFF_WAITING"));
        assert_eq!(attempts(&rig, &waiting).len(), 1);
    });
}

/// PR 10 (Task 21 review m8; design I.6.2 step 4): the control state the
/// feeds committed before a crash is read into the start view before the
/// start's recovery: the bot, revoked by a record applied while its task
/// waited for its gate, has that task cancelled `sender revoked` at the
/// recovery, never back to `queued`, and it never runs.
#[test]
fn the_stored_control_state_is_read_before_the_recovery() {
    use atem_client::control::ControlAction;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        rig.bridge.start_view().gates = Gates::closed_until_feeds();
        let task = bot_task(&mut rig, &s, "REVOKED_BEFORE_THE_CRASH", start + 2 * HOUR);
        blocked(&mut rig, &task, details::REVOCATIONS_NOT_YET_CHECKED).await;
        commit_bot_records(
            &rig,
            &s.log,
            &[
                ControlAction::Cover,
                ControlAction::Revoke {
                    interrupt_running: false,
                },
            ],
        );
        let steps = restart(&mut rig, root, &os, false, true);
        let cancelled = Some((WorkState::Cancelled, details::SENDER_REVOKED.to_string()));
        assert_eq!(reconciled(&steps, &task), cancelled);
        assert!(rig.bridge.start_view().standings[BOT].revoked.is_some());
        rig.bridge.start_view().gates.open_own_station(ORIGIN);
        passes(&mut rig, 3);
        assert_eq!(settled(&rig, &task), outcome(Event::Revoked));
        assert!(!input(&rig).contains("REVOKED_BEFORE_THE_CRASH"));
    });
}

/// Bindings §9 step 3 (ruling PR2b), PR 10's ruling: a part of the current
/// list's control state that doesn't read stops every delegated task,
/// fail closed (`revocations not yet checked`, the gate open or not), never
/// an empty state in its place; once the store is repaired, the next start
/// runs it.
#[test]
fn a_control_state_that_doesnt_read_starts_no_delegated_task() {
    use crate::runtime::delegated::feeds::Feeds;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, false);
        let task = phone_task(&mut rig, &phone, "DAMAGED_CONTROLS", start + 3 * HOUR);
        blocked(&mut rig, &task, details::REVOCATIONS_NOT_YET_CHECKED).await;
        let db = |rig: &LocalRig, sql: &str| {
            rig.bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .db
                .execute(sql, [])
                .unwrap();
        };
        db(
            &rig,
            "INSERT INTO control_principals(principal,part) VALUES('service:svc-x','{damaged')",
        );
        restart(&mut rig, root, &os, false, true);
        assert!(matches!(rig.bridge.work.feeds, Feeds::Damaged));
        assert!(rig.bridge.start_view().controls_damaged);
        rig.bridge.start_view().gates.open_own_station(ORIGIN);
        passes(&mut rig, 5);
        assert_eq!(settled(&rig, &task), outcome(Event::GateClosed));
        assert!(attempts(&rig, &task).is_empty());
        assert!(!input(&rig).contains("DAMAGED_CONTROLS"));

        // Repaired (the row removed), the next start runs it.
        db(
            &rig,
            "DELETE FROM control_principals WHERE principal='service:svc-x'",
        );
        restart(&mut rig, root, &os, false, true);
        assert!(matches!(rig.bridge.work.feeds, Feeds::Loaded(_)));
        assert!(!rig.bridge.start_view().controls_damaged);
        rig.bridge.start_view().gates.open_own_station(ORIGIN);
        rig.until(|r| input(r).contains("DAMAGED_CONTROLS")).await;
    });
}

/// Ruling T32b (Task 32 review I1): a damaged control state never makes a
/// service a v1 sender. The bot, covered and since revoked by records the
/// feeds committed, is refused `busy` while a part of the state doesn't
/// read: its `work_enqueue` and its `message_publish` with an agent
/// recipient store nothing, and its query, `message_query` and completion
/// of its own work are refused while the owner still reads; a native's
/// task is still admitted, and waits `revocations not yet checked`. Once
/// the store is repaired, after a restart, the bot is delegated and
/// revoked.
#[test]
fn a_damaged_control_state_never_makes_a_service_v1() {
    use crate::runtime::delegated::feeds::Feeds;
    use atem_client::control::ControlAction;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        let task = bot_task(&mut rig, &s, "BOT_BEFORE_THE_DAMAGE", start + HOUR);
        run(&mut rig, &task, "BOT_BEFORE_THE_DAMAGE").await;
        // A message of the bot's, its task waiting at the closed gate.
        rig.bridge.start_view().gates = Gates::closed_until_feeds();
        let (earlier, _) = message_from(&rig, BOT, "rs", "BOT_EARLIER_MESSAGE", None);
        ask_req(&mut rig, &s.bot, &earlier).unwrap();
        commit_bot_records(
            &rig,
            &s.log,
            &[
                ControlAction::Cover,
                ControlAction::Revoke {
                    interrupt_running: false,
                },
            ],
        );
        let db = |rig: &LocalRig, sql: &str| {
            rig.bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .db
                .execute(sql, [])
                .unwrap();
        };
        db(
            &rig,
            "INSERT INTO control_principals(principal,part) VALUES('service:svc-x','{damaged')",
        );
        restart(&mut rig, root, &os, false, true);
        assert!(matches!(rig.bridge.work.feeds, Feeds::Damaged));
        assert_eq!(rig.bridge.sender_class(BOT), SenderClass::Unchecked);
        let stored = |rig: &LocalRig, id: &str| {
            rig.bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .work(id)
                .unwrap()
                .is_some()
        };

        // Its enqueue: `busy`, nothing stored.
        let mut req = phone_enqueue(&rig, "BOT_WHILE_DAMAGED");
        if let hw::Request::Enqueue { route_id, .. } = &mut req {
            *route_id = "rs".into();
        }
        assert_eq!(ask_req(&mut rig, &s.bot, &req), busy());
        assert!(!stored(&rig, &enqueued(&req)));
        // Its publish with an agent recipient: `busy`, nothing stored.
        let (publish, recipient) = message_from(&rig, BOT, "rs", "BOT_MESSAGE_WHILE_DAMAGED", None);
        assert_eq!(ask_req(&mut rig, &s.bot, &publish), busy());
        assert!(!stored(&rig, &recipient));
        let hw::Request::Publish { message, .. } = &publish else {
            unreachable!()
        };
        let store = rig.bridge.work.store.as_ref().unwrap();
        assert!(store.message(&message.message_id).unwrap().is_none());
        // Its own work: `busy`; the owner reads it.
        assert_eq!(ask(&mut rig, &s.bot, Q::Query(&task)), busy());
        assert_eq!(ask(&mut rig, &s.bot, Q::Reply(&task)), busy());
        assert_eq!(ask(&mut rig, &s.bot, Q::Complete(&task, "done")), busy());
        assert_eq!(ask(&mut rig, &s.bot, Q::Message(&earlier)), busy());
        assert_eq!(settled(&rig, &task).0, WorkState::AwaitingResult);
        assert_eq!(
            status(ask(&mut rig, &s.mac, Q::Query(&task))).state,
            WorkState::AwaitingResult
        );
        assert!(ask(&mut rig, &s.mac, Q::Message(&earlier)).is_ok());
        // A native's task is admitted, and waits.
        let phone = phone_task(&mut rig, &s.phone, "PHONE_WHILE_DAMAGED", start + 2 * HOUR);
        assert!(stored_record(&rig, &phone).delegated.is_some());
        rig.bridge.start_view().gates.open_own_station(ORIGIN);
        blocked(&mut rig, &phone, details::REVOCATIONS_NOT_YET_CHECKED).await;

        // Repaired, the next start: delegated, and revoked.
        db(
            &rig,
            "DELETE FROM control_principals WHERE principal='service:svc-x'",
        );
        restart(&mut rig, root, &os, false, true);
        assert!(matches!(rig.bridge.work.feeds, Feeds::Loaded(_)));
        assert!(matches!(
            rig.bridge.sender_class(BOT),
            SenderClass::Delegated(crate::runtime::delegated::DelegatedSender::Service { .. })
        ));
        assert!(rig.bridge.start_view().standings[BOT].revoked.is_some());
        assert_eq!(ask(&mut rig, &s.bot, Q::Query(&task)), forbidden());
    });
}

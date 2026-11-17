// `atem message cancel` and `complete` of a task on another host (design
// II.4.4, II.7; host-work-v1 §11.5, "On the sending host"): the task id a
// status named routes to a sealed `cancel` or `complete` envelope, its own
// delivery row, put every 10 minutes until a status shows its effect, the
// host answers it by its own id, or it expires. Shares the results tests'
// rig (`sp_host`, `rb_*`); every name here starts with `rs_`.

use crate::runtime::protocol::{RemoteStop, StopOutcome};

/// This host's send to B, B's status naming its one task in `state`
/// applied: the message, its recipient and the task.
fn rs_task(rig: &mut LocalRig, host: &mut MbHost, state: WorkState) -> (String, String, String) {
    let (m, r) = rb_send(rig);
    let task = rb_task_id(&m, &r);
    let status = rs_status(rig, host, host_now().wall_ms, (&m, &r, &task), state);
    rb_receive(rig, host, &[status]);
    (m, r, task)
}

/// A stop row: (kind, task id, state, code, detail).
type RsRow = (String, Option<String>, String, Option<String>, String);

/// What `atem message cancel` or `complete` says of a stop to B.
fn rs_said(outcome: StopOutcome) -> Option<RemoteStop> {
    Some(RemoteStop {
        host: "host-b".into(),
        outcome,
    })
}

/// The stop rows of `message`.
fn rs_rows(rig: &LocalRig, message: &str) -> Vec<RsRow> {
    crate::runtime::delegated::remote_send::rows(
        &rig.bridge.work.store.as_ref().unwrap().db,
        message,
    )
    .unwrap()
    .into_iter()
    .filter(|r| r.kind != "request")
    .map(|r| (r.kind, r.task_id, r.state, r.code, r.detail))
    .collect()
}

/// The state of `message`'s request row to B.
fn rs_request(rig: &LocalRig, message: &str) -> String {
    crate::runtime::delegated::remote_send::rows(
        &rig.bridge.work.store.as_ref().unwrap().db,
        message,
    )
    .unwrap()
    .into_iter()
    .find(|r| r.kind == "request")
    .unwrap()
    .state
}

/// The engine row of the stop `kind` of `message`: its object id, state,
/// policy and bytes.
fn rs_engine(rig: &LocalRig, message: &str, kind: &str) -> (String, String, String, Vec<u8>) {
    rig.bridge
        .work
        .store
        .as_ref()
        .unwrap()
        .db
        .query_row(
            "SELECT o.object_id, o.state, o.policy, o.bytes FROM remote_deliveries d
            JOIN mail_outbox o ON o.n=d.outbox_n WHERE d.message_id=?1 AND d.kind=?2",
            [message, kind],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .unwrap()
}

/// B's status of `message` naming `task` (its recipient `recipient`) in
/// `state`, made `at`.
fn rs_status(
    rig: &LocalRig,
    host: &MbHost,
    at: u64,
    (message, recipient, task): (&str, &str, &str),
    state: WorkState,
) -> Value {
    let mut progress = rb_progress(message, recipient, RB_SESSION, state, "on B");
    progress.task_id = task.into();
    if state == WorkState::Completed {
        progress.result = Some(atem_client::session::messages::ContextReference {
            kind: hw::ContextKind::Memory,
            id: "mem_rs".into(),
            version: 1,
            digest: hw::digest(b"done"),
        });
    }
    let status = rb_status(
        message,
        recipient,
        Delivery::Resolved {
            tasks: vec![progress],
        },
    );
    rb_from_b(rig, host, at, &status)
}

/// Item 1: a cancel of a task B queued is sealed to B as its own envelope,
/// committed (another connection reads it) before any put, with its own
/// delivery row; a second cancel sends nothing more. It is put again every
/// 10 minutes, the same bytes, until B's status shows the task cancelled:
/// its row is then `accepted` and put no more.
#[test]
fn a_cancel_is_put_until_a_status_shows_the_task_cancelled() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let t = host_now().wall_ms;
        sp_d(&rig, t);
        let (m, r, task) = rs_task(&mut rig, &mut host, WorkState::Queued);
        assert_eq!(
            rig.bridge.collab_cancel(None, &task).unwrap(),
            rs_said(StopOutcome::Sent)
        );
        let other = Store::open(&root.join("runtime")).unwrap();
        let committed: i64 = other
            .db
            .query_row(
                "SELECT count(*) FROM remote_deliveries WHERE kind='cancel' AND task_id=?1",
                [&task],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(committed, 1, "committed before any put");
        assert_eq!(
            rs_rows(&rig, &m),
            [(
                "cancel".into(),
                Some(task.clone()),
                "ready".into(),
                None,
                "waiting to be put in the host's mailbox".into()
            )]
        );
        let (id, state, policy, bytes) = rs_engine(&rig, &m, "cancel");
        assert_eq!((state.as_str(), policy.as_str()), ("queued", "repeat"));
        assert_eq!(
            sp_open(&rig, &bytes),
            atem_client::host_mail::EnvelopePlain::Cancel {
                task_id: task.clone()
            }
        );
        let object = atem_client::host_mail::parse_object(&bytes).unwrap();
        let (_, body) = atem_client::host_mail::MailBody::from_object(&object).unwrap();
        assert_eq!(body.id, id);
        assert_eq!(body.created_at, t, "made on D");
        let expires: u64 = rig
            .bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .query_row(
                "SELECT expires_at FROM mail_outbox WHERE object_id=?1",
                [&m],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(body.expires_at, expires, "alive while its message is");
        // A second cancel while the first stands: nothing more, and it says
        // so (review L4).
        assert_eq!(
            rig.bridge.collab_cancel(None, &task).unwrap(),
            rs_said(StopOutcome::Pending)
        );
        assert_eq!(rs_rows(&rig, &m).len(), 1);
        let puts = sp_out(&mut rig);
        assert_eq!(puts.len(), 1);
        assert_eq!(puts[0].object().to_json().to_string().into_bytes(), bytes);
        sp_stored(&mut rig, &puts[0]);
        assert_eq!(rs_rows(&rig, &m)[0].2, "sent");
        sp_d(&rig, t + 10 * 60_000);
        let again = sp_out(&mut rig);
        assert_eq!(again.len(), 1, "put again in 10 minutes");
        assert_eq!(again[0].object(), puts[0].object());
        sp_stored(&mut rig, &again[0]);
        // B's status shows the effect: accepted, put no more.
        let at = host_now().wall_ms + 1;
        let shown = rs_status(&rig, &host, at, (&m, &r, &task), WorkState::Cancelled);
        rb_receive(&mut rig, &mut host, &[shown]);
        let rows = rs_rows(&rig, &m);
        assert_eq!(
            (rows[0].2.as_str(), rows[0].4.as_str()),
            ("accepted", "the host's status shows the task cancelled")
        );
        assert_eq!(rs_engine(&rig, &m, "cancel").1, "done");
        // `atem message status` shows it under its task.
        let view = rig.bridge.collab_status(None, Some(&m)).unwrap();
        assert_eq!(
            view[0].remote[0].tasks[0].stops,
            [crate::runtime::collab::RemoteStopView {
                kind: "cancel".into(),
                state: "accepted".into(),
                code: None,
                detail: "the host's status shows the task cancelled".into(),
            }]
        );
        sp_d(&rig, t + 20 * 60_000);
        assert!(
            sp_out(&mut rig)
                .iter()
                .all(|p| p.mail().unwrap().1.id != id),
            "put no more"
        );
    });
}

/// B answers a stop it doesn't reach by its own id (`busy`, `forbidden`):
/// the stop's row is `refused` with that code and put no more; the
/// request's row is untouched.
#[test]
fn a_stop_the_host_refuses_by_its_own_id_is_put_no_more() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let t = host_now().wall_ms;
        sp_d(&rig, t);
        let (m, _, task) = rs_task(&mut rig, &mut host, WorkState::Blocked);
        rig.bridge.collab_cancel(None, &task).unwrap();
        let (id, ..) = rs_engine(&rig, &m, "cancel");
        let refusal = ResultPlain::Refusal {
            object_id: id.clone(),
            refused: "busy".into(),
        };
        let object = rb_from_b(&rig, &host, t, &refusal);
        rb_receive(&mut rig, &mut host, &[object]);
        assert_eq!(
            rs_rows(&rig, &m),
            [(
                "cancel".into(),
                Some(task),
                "refused".into(),
                Some("busy".into()),
                "refused by the host (busy)".into()
            )]
        );
        assert_eq!(rs_engine(&rig, &m, "cancel").1, "done");
        assert_eq!(rs_request(&rig, &m), "accepted", "the request's row");
    });
}

/// Only the task's sending session (its process for a complete), or the
/// owner outside any session, stops a remote task, as stage 1 allows; a
/// task the host's status shows started isn't cancelled, nor one that
/// ended completed; nothing is sealed for a refused stop.
#[test]
fn who_may_stop_a_remote_task_and_when() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        sp_d(&rig, host_now().wall_ms);
        let (m, _, task) = rs_task(&mut rig, &mut host, WorkState::Queued);
        let stranger = SessionId::parse("ses-zzzzzzzzzzzz").unwrap();
        assert_eq!(
            rig.bridge
                .collab_cancel(Some(&stranger), &task)
                .unwrap_err()
                .to_string(),
            format!(
                "task {task} is not one of this session's messages; only the session that sent it (or the owner, outside any session) cancels it"
            )
        );
        assert_eq!(
            rig.bridge
                .collab_complete(Some(&stranger), &task, &rig.sessions)
                .unwrap_err()
                .to_string(),
            "only the task's sending session completes it"
        );
        assert!(rs_rows(&rig, &m).is_empty());
        let sid = rig.sid.clone();
        assert!(rig.bridge.collab_cancel(Some(&sid), &task).is_ok());
        assert_eq!(rs_rows(&rig, &m).len(), 1);
        // Started at B: not cancelled, and a complete is held until B's
        // status shows the task awaiting its result (ruling R50);
        // completed there already: a complete is done, nothing kept (review
        // L4); failed, or of unknown outcome (its owner resolves it there,
        // review L3): neither.
        let unknown = "is outcome_unknown; a task of unknown outcome is resolved by that host's owner, never completed by its sender";
        for (state, cancel, complete, kept) in [
            (
                WorkState::Submitted,
                "is submitted; only a task that hasn't started can be cancelled",
                Ok(StopOutcome::Queued),
                1,
            ),
            (
                WorkState::Completed,
                "is completed; only a task that hasn't started can be cancelled",
                Ok(StopOutcome::Done),
                0,
            ),
            (
                WorkState::Failed,
                "is failed; only a task that hasn't started can be cancelled",
                Err("is failed; only a task awaiting its result can be completed"),
                0,
            ),
            (
                WorkState::OutcomeUnknown,
                "is outcome_unknown; only a task that hasn't started can be cancelled",
                Err(unknown),
                0,
            ),
        ] {
            let (m, _, task) = rs_task(&mut rig, &mut host, state);
            let refused = rig.bridge.collab_cancel(None, &task);
            assert_eq!(
                refused.unwrap_err().to_string(),
                format!("task {task} on host host-b {cancel}")
            );
            let completed = rig.bridge.collab_complete(None, &task, &rig.sessions);
            match complete {
                Err(why) => assert_eq!(
                    completed.unwrap_err().to_string(),
                    format!("task {task} on host host-b {why}")
                ),
                Ok(outcome) => assert_eq!(completed.unwrap(), rs_said(outcome), "{state:?}"),
            }
            let rows = rs_rows(&rig, &m);
            assert_eq!(rows.len(), kept, "{state:?}: {rows:?}");
            assert!(rows.iter().all(|r| r.0 == "complete"), "no cancel kept");
        }
    });
}

/// The delivered result's last line, `Complete the task with: atem message
/// complete <task>`, works for a remote task: run by the sending session,
/// it seals a `complete` whose result names the reply this host got back
/// (a `result` snapshot of the task's own `result:<result_id>`, its text
/// the reply's digest), puts it until B's status shows the task completed,
/// and ends the delivery still queued, as stage 1's completion does. A
/// task with no reply here is completed naming none.
#[test]
fn the_result_prompts_last_line_completes_a_remote_task_with_its_reply() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        rig.bridge.work.config.routes[0].results = true;
        let t = host_now().wall_ms;
        sp_d(&rig, t);
        let (m, r) = rb_send(&mut rig);
        let task = rb_task_id(&m, &r);
        let status = rb_from_b(
            &rig,
            &host,
            t,
            &rb_resolved(&m, &r, WorkState::AwaitingResult),
        );
        let result = rb_from_b(&rig, &host, t, &rb_reply(&task, "RS_REPLY"));
        rb_receive(&mut rig, &mut host, &[status, result]);
        let delivery = rb_delivery(&m, &task);
        assert_eq!(rb_deliveries(&rig).len(), 1, "queued for the session");
        // Hold the delivery so it hasn't started when the sender completes.
        let store = rig.bridge.work.store.as_ref().unwrap();
        let mut queued = store.work(&delivery).unwrap().unwrap();
        queued.status.state = WorkState::Blocked;
        store.save_work(&queued).unwrap();
        let sid = rig.sid.clone();
        assert_eq!(
            rig.bridge
                .collab_complete(Some(&sid), &task, &rig.sessions)
                .unwrap(),
            rs_said(StopOutcome::Sent)
        );
        let (_, _, policy, bytes) = rs_engine(&rig, &m, "complete");
        assert_eq!(policy, "repeat");
        let atem_client::host_mail::EnvelopePlain::Complete { task_id, result } =
            sp_open(&rig, &bytes)
        else {
            panic!("not a complete");
        };
        assert_eq!(task_id, task);
        assert!(result.names_reply_of(&task), "{result:?}");
        let reply: Value = serde_json::from_str(&result.text).unwrap();
        assert_eq!(reply["digest"], json!(hw::digest(b"RS_REPLY")));
        assert_eq!(reply["result_id"], json!(hw::result_id(&task)));
        let store = rig.bridge.work.store.as_ref().unwrap();
        let ended = store.work(&delivery).unwrap().unwrap();
        assert_eq!(
            (ended.status.state, ended.status.detail.as_str()),
            (
                WorkState::Cancelled,
                "not delivered: its task was completed by its sender"
            )
        );
        // B's status shows the task completed: accepted.
        let at = host_now().wall_ms + 1;
        let shown = rs_status(&rig, &host, at, (&m, &r, &task), WorkState::Completed);
        rb_receive(&mut rig, &mut host, &[shown]);
        let rows = rs_rows(&rig, &m);
        assert_eq!(rows[0].2, "accepted", "{rows:?}");
        // No reply here: the complete names none.
        let (m, _, task) = rs_task(&mut rig, &mut host, WorkState::AwaitingResult);
        rig.bridge
            .collab_complete(None, &task, &rig.sessions)
            .unwrap();
        let (.., bytes) = rs_engine(&rig, &m, "complete");
        let atem_client::host_mail::EnvelopePlain::Complete { result, .. } = sp_open(&rig, &bytes)
        else {
            panic!("not a complete");
        };
        assert!(result.names_reply_of(&task));
        let named: Value = serde_json::from_str(&result.text).unwrap();
        assert_eq!(named.get("digest"), None, "no reply named");
    });
}

/// A stop that can't be sealed now (B no longer a current host at its
/// generation) is refused with why, nothing kept; one past its message's
/// expiry too. With host senders off, a remote task id is no task here
/// (stage 1's answer).
#[test]
fn a_stop_that_cant_go_is_refused_with_why() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let t = host_now().wall_ms;
        sp_d(&rig, t);
        let (m, _, task) = rs_task(&mut rig, &mut host, WorkState::Queued);
        sp_d(&rig, t + 2 * HOUR);
        assert_eq!(
            rig.bridge
                .collab_cancel(None, &task)
                .unwrap_err()
                .to_string(),
            format!("task {task}'s message expired")
        );
        sp_d(&rig, t);
        sign_and_carry(
            &mut rig,
            &mut host.s,
            ListAction::RemoveHost {
                host_id: "host-b".into(),
            },
        );
        mb_tick(&mut rig, &mut host, 0);
        assert_eq!(
            rig.bridge
                .collab_cancel(None, &task)
                .unwrap_err()
                .to_string(),
            "host host-b is no longer a current host at trust generation 1"
        );
        assert!(rs_rows(&rig, &m).is_empty());
        rig.bridge.features.senders = false;
        assert_eq!(
            rig.bridge
                .collab_cancel(None, &task)
                .unwrap_err()
                .to_string(),
            "no local collaboration task"
        );
    });
}

/// On the receiving host: a host sender's `complete` naming the task's own
/// reply (the `result` snapshot its sending host makes) completes a task
/// awaiting its result with that snapshot, and the status back carries its
/// reference.
#[test]
fn a_complete_naming_the_reply_completes_the_task_on_the_host_that_ran_it() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = sp_host(&mut rig, root, &os);
        let (message, task) = rb_task(&mut rig);
        let id = task.task.task_id.clone();
        reply(&mut rig, &id, "the answer", &[]).unwrap();
        let store = rig.bridge.work.store.as_ref().unwrap();
        let row = crate::runtime::collab::results::load(&store.db, &id)
            .unwrap()
            .unwrap();
        let naming = crate::runtime::delegated::results_back::naming(&id, Some(&row.wire()));
        let stop = uuid::Uuid::new_v4().to_string();
        ad_inbox(
            &rig,
            &stop,
            message.expires_at,
            None,
            &EnvelopePlain::Complete {
                task_id: id.clone(),
                result: naming.clone(),
            },
        );
        ad_admit(&mut rig);
        let done = ad_tasks(&rig, &message).remove(0);
        assert_eq!(done.status.state, WorkState::Completed);
        assert_eq!(done.status.result, Some(naming.clone()));
        let receipts = ad_receipts(&rig, &message);
        let progress = &ad_resolved(&receipts[0])[0];
        let reference = progress.result.as_ref().unwrap();
        assert_eq!(
            (reference.kind, reference.id.as_str()),
            (hw::ContextKind::Result, naming.id.as_str())
        );
    });
}

/// Ruling R50 (review M1): a `complete` of a task B's newest status shows
/// before `awaiting_result` (its turn still runs) is held, durable with the
/// command (another connection reads it), nothing sealed or put; the
/// status showing `awaiting_result` seals it in the pass that applies it
/// (its result the reply named as at the command), and it is put until B's
/// status shows the task completed.
#[test]
fn a_complete_before_its_task_awaits_its_result_is_held_until_it_does() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        sp_d(&rig, host_now().wall_ms);
        let (m, r, task) = rs_task(&mut rig, &mut host, WorkState::Submitted);
        let reply = rb_from_b(
            &rig,
            &host,
            host_now().wall_ms,
            &rb_reply(&task, "RS_EARLY"),
        );
        rb_receive(&mut rig, &mut host, &[reply]);
        assert_eq!(
            rig.bridge
                .collab_complete(None, &task, &rig.sessions)
                .unwrap(),
            rs_said(StopOutcome::Queued)
        );
        let other = Store::open(&root.join("runtime")).unwrap();
        let held: String = other
            .db
            .query_row(
                "SELECT state FROM remote_deliveries WHERE kind='complete' AND task_id=?1",
                [&task],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(held, "held", "committed with the command");
        let held_id = rs_object(&rig, &m);
        assert_eq!(
            rows_where(&rig, "mail_outbox", &format!("object_id='{held_id}'")),
            0,
            "nothing sealed"
        );
        assert_eq!(
            rs_rows(&rig, &m)[0].4,
            "held until the host's status shows the task awaiting its result"
        );
        // A second complete while it is held: it stands.
        assert_eq!(
            rig.bridge
                .collab_complete(None, &task, &rig.sessions)
                .unwrap(),
            rs_said(StopOutcome::Pending)
        );
        // B's status shows it awaiting its result: sealed in that pass.
        let at = host_now().wall_ms + 1;
        let awaiting = rs_status(&rig, &host, at, (&m, &r, &task), WorkState::AwaitingResult);
        rb_receive(&mut rig, &mut host, &[awaiting]);
        let rows = rs_rows(&rig, &m);
        assert_eq!(rows[0].2, "ready", "{rows:?}");
        let (.., bytes) = rs_engine(&rig, &m, "complete");
        let atem_client::host_mail::EnvelopePlain::Complete { result, .. } = sp_open(&rig, &bytes)
        else {
            panic!("not a complete");
        };
        let named: Value = serde_json::from_str(&result.text).unwrap();
        assert_eq!(
            named["digest"],
            json!(hw::digest(b"RS_EARLY")),
            "the reply named"
        );
        let completed = rs_status(&rig, &host, at + 1, (&m, &r, &task), WorkState::Completed);
        rb_receive(&mut rig, &mut host, &[completed]);
        assert_eq!(rs_rows(&rig, &m)[0].2, "accepted");
    });
}

/// A held complete is dropped, with its reason, when B's status shows the
/// task ending otherwise (expired, cancelled, failed, completed, or of
/// unknown outcome), and expired with its message.
#[test]
fn a_held_complete_ends_with_its_task_or_its_message() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let t = host_now().wall_ms;
        sp_d(&rig, t);
        for state in [
            WorkState::Expired,
            WorkState::Cancelled,
            WorkState::Failed,
            WorkState::Completed,
            WorkState::OutcomeUnknown,
        ] {
            let (m, r, task) = rs_task(&mut rig, &mut host, WorkState::Blocked);
            rig.bridge
                .collab_complete(None, &task, &rig.sessions)
                .unwrap();
            let name = serde_json::to_value(state).unwrap();
            let ended = rs_status(&rig, &host, host_now().wall_ms + 1, (&m, &r, &task), state);
            rb_receive(&mut rig, &mut host, &[ended]);
            let rows = rs_rows(&rig, &m);
            assert_eq!(
                (rows[0].2.as_str(), rows[0].4.clone()),
                (
                    "dropped",
                    format!(
                        "not sent: the host's status shows the task {}",
                        name.as_str().unwrap()
                    )
                ),
                "{state:?}"
            );
            assert_eq!(
                rows_where(
                    &rig,
                    "mail_outbox",
                    &format!("object_id='{}'", rs_object(&rig, &m))
                ),
                0
            );
        }
        // Its message expires while it is held.
        let (m, _, task) = rs_task(&mut rig, &mut host, WorkState::Queued);
        rig.bridge
            .collab_complete(None, &task, &rig.sessions)
            .unwrap();
        sp_d(&rig, t + 2 * HOUR);
        rig.bridge.remote_stops_pass();
        let rows = rs_rows(&rig, &m);
        assert_eq!(
            (rows[0].2.as_str(), rows[0].4.as_str()),
            ("expired", "expired before it was sent")
        );
    });
}

/// Ruling R50: a `complete` sent while B's status showed the task awaiting
/// its result, answered `busy` by its own id (a race: the task wasn't
/// awaiting it there any more), is held again under a fresh id, never
/// ended; the next status showing `awaiting_result` seals it again. One
/// answered `busy` once the task is shown ended is dropped.
#[test]
fn a_busy_answer_holds_a_complete_again() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        sp_d(&rig, host_now().wall_ms);
        let (m, r, task) = rs_task(&mut rig, &mut host, WorkState::AwaitingResult);
        assert_eq!(
            rig.bridge
                .collab_complete(None, &task, &rig.sessions)
                .unwrap(),
            rs_said(StopOutcome::Sent)
        );
        let first = rs_object(&rig, &m);
        let busy = ResultPlain::Refusal {
            object_id: first.clone(),
            refused: "busy".into(),
        };
        let busy = rb_from_b(&rig, &host, host_now().wall_ms, &busy);
        rb_receive(&mut rig, &mut host, &[busy]);
        let rows = rs_rows(&rig, &m);
        assert_eq!(
            (rows[0].2.as_str(), rows[0].3.as_deref(), rows[0].4.as_str()),
            (
                "held",
                Some("busy"),
                "the host answered busy: the task wasn't awaiting its result there; held until its status shows it"
            )
        );
        let again = rs_object(&rig, &m);
        assert_ne!(again, first, "a fresh object");
        let state: String = rig
            .bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .query_row(
                "SELECT state FROM mail_outbox WHERE object_id=?1",
                [&first],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(state, "done", "the first is put no more");
        let at = host_now().wall_ms + 1;
        let awaiting = rs_status(&rig, &host, at, (&m, &r, &task), WorkState::AwaitingResult);
        rb_receive(&mut rig, &mut host, &[awaiting]);
        assert_eq!(rs_rows(&rig, &m)[0].2, "ready");
        assert_eq!(rs_object(&rig, &m), again, "sealed under its fresh id");
        // `busy` again, once B's status showed the task expired: dropped.
        let expired = rs_status(&rig, &host, at + 1, (&m, &r, &task), WorkState::Expired);
        rb_receive(&mut rig, &mut host, &[expired]);
        let busy = ResultPlain::Refusal {
            object_id: again,
            refused: "busy".into(),
        };
        let busy = rb_from_b(&rig, &host, host_now().wall_ms, &busy);
        rb_receive(&mut rig, &mut host, &[busy]);
        let rows = rs_rows(&rig, &m);
        assert_eq!(
            (rows[0].2.as_str(), rows[0].4.as_str()),
            (
                "dropped",
                "the host answered busy; its status shows the task expired"
            )
        );
    });
}

/// The object id of `message`'s complete row now.
fn rs_object(rig: &LocalRig, message: &str) -> String {
    rig.bridge
        .work
        .store
        .as_ref()
        .unwrap()
        .db
        .query_row(
            "SELECT object_id FROM remote_deliveries WHERE message_id=?1 AND kind='complete'",
            [message],
            |r| r.get(0),
        )
        .unwrap()
}

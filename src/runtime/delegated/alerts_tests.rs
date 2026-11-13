// Alerts, `alert_list` and the capacity limits on unknown outcomes (design
// I.4.6; host-work-v1 §11.3, §11.6 "Unknown outcomes" and "Capacity"), in
// the bridge: the rig's host with a pinned device list, `host.delegated`
// and `host.alerts` on, the phone (a native member holding `control`), and
// for the authority and limits the bot (a service a feed covers), the Mac
// and a viewer. Included beside the dispatch's and the lifecycle's tests,
// whose helpers and imports it shares.

/// `host.delegated` and `host.alerts` on, as the hook turns them on (and
/// on the r9 side with hosting on, as the runtime's `work_config` hands
/// them over: the welcome lists `host.alerts`).
fn alerts_on(rig: &mut LocalRig) {
    rig.bridge.features = HostFeatures::parse("host.delegated,host.alerts").unwrap();
    rig.bridge.r9.set_delegated_features(true, true);
    rig.bridge.r9.enable_host_work(true);
}

/// `alert_list` (after `after`), as `who`'s channel hands it to the bridge.
fn list_alerts(
    rig: &mut LocalRig,
    who: &Authority,
    after: Option<&str>,
) -> (hw::Request, Result<ResultBody, HostWorkError>) {
    let req = hw::Request::AlertList {
        v: 1,
        id: uuid::Uuid::new_v4().to_string(),
        host: rig.bridge.work_host(),
        after: after.map(str::to_owned),
    };
    let reply = ask_req(rig, who, &req);
    (req, reply)
}

/// The page an `alerts` result carries, read back by the client core's
/// strict reader as the answer to `req` (the host's order, at most 64, this
/// host's alerts, a cursor never repeated).
fn alert_page(
    req: &hw::Request,
    reply: Result<ResultBody, HostWorkError>,
) -> (Vec<atem_client::session::alerts::Alert>, bool) {
    let body = reply.expect("an alerts result");
    let json = hw::result(
        &uuid::Uuid::new_v4().to_string(),
        req.id(),
        req.host(),
        &uuid::Uuid::new_v4().to_string(),
        "channel",
        body.clone(),
    );
    let response = hw::Response::from_data(&json["data"]).expect("the reader takes it");
    assert!(response.answers(req), "it answers the request");
    match body {
        ResultBody::Alerts { alerts, more } => (alerts, more),
        other => panic!("an alerts result: {other:?}"),
    }
}

/// `who`'s page after `after`.
fn page_for(
    rig: &mut LocalRig,
    who: &Authority,
    after: Option<&str>,
) -> (Vec<atem_client::session::alerts::Alert>, bool) {
    let (req, reply) = list_alerts(rig, who, after);
    alert_page(&req, reply)
}

/// `stale_target`, `unknown alert` (§11.3, "An unknown cursor").
fn unknown_alert() -> Result<ResultBody, HostWorkError> {
    Err(HostWorkError {
        code: "stale_target",
        detail: Some(crate::runtime::delegated::alerts::UNKNOWN_ALERT),
    })
}

/// `busy`, `too many unresolved outcomes` (§11.6, "Capacity").
fn too_many() -> Result<ResultBody, HostWorkError> {
    Err(HostWorkError {
        code: "busy",
        detail: Some(details::TOO_MANY_UNRESOLVED_OUTCOMES),
    })
}

/// The stored task `task` written `outcome_unknown` with `detail`, as the
/// lifecycle writes a task whose outcome it can't establish.
fn make_unknown(rig: &LocalRig, task: &str, detail: &str) {
    let mut record = stored_record(rig, task);
    record.status.state = WorkState::OutcomeUnknown;
    record.status.detail = detail.into();
    rig.bridge
        .work
        .store
        .as_ref()
        .unwrap()
        .save_work(&record)
        .unwrap();
}

/// `n` delegated tasks of `sender` like `template` (a task the bridge
/// admitted), each stored and then written `outcome_unknown` (`agent
/// exited`), as tasks accepted earlier whose outcomes became unknown: their
/// ids, in order.
fn unknown_outcomes(rig: &LocalRig, template: &WorkRecord, sender: &str, n: usize) -> Vec<String> {
    let store = rig.bridge.work.store.as_ref().unwrap();
    (0..n)
        .map(|_| {
            let mut r = template.clone();
            let id = uuid::Uuid::new_v4().to_string();
            r.task.task_id = id.clone();
            r.status.task_id = id.clone();
            r.status.state = WorkState::Queued;
            r.principal = sender.into();
            r.delegated.as_mut().unwrap().principal = sender.into();
            assert!(store.enqueue(&r).unwrap());
            r.status.state = WorkState::OutcomeUnknown;
            r.status.detail = details::AGENT_EXITED.into();
            store.save_work(&r).unwrap();
            id
        })
        .collect()
}

/// Ends `task`'s alert (it had one unresolved), as a resolution does.
fn end_alert(rig: &LocalRig, task: &str) {
    let store = rig.bridge.work.store.as_ref().unwrap();
    assert!(store.end_alert(&store.db, task).unwrap());
}

/// Every alert row, ended ones too (what a read must leave as it was).
fn alert_rows(rig: &LocalRig) -> Vec<(String, u64, String, Option<u64>)> {
    let db = &rig.bridge.work.store.as_ref().unwrap().db;
    let mut q = db
        .prepare("SELECT alert_id,seq,task_id,ended_ms FROM alerts ORDER BY seq")
        .unwrap();
    q.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

/// Design I.4.6 ("The alert"), host-work-v1 §11.3 and §11.6 "Unknown
/// outcomes": the phone's task runs, and its agent exits mid-turn; the task
/// becomes `outcome_unknown` (`agent exited`, its receipt's reason) and the
/// host has exactly one alert for it, naming the host, the session, the
/// task, the phone and why, listed to the phone. Later passes, and the task
/// written again, raise no other. A v1 task of unknown outcome raises none.
#[test]
fn an_alert_per_unresolved_delegated_outcome() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        alerts_on(&mut rig);
        let task = phone_task(&mut rig, &phone, "ALERT_EXITED", start + HOUR);
        rig.until(|r| input(r).contains("ALERT_EXITED")).await;
        assert_eq!(page_for(&mut rig, &phone, None), (vec![], false));
        // The agent exits in the task's turn.
        std::fs::write(rig.fake.join("exit"), "").unwrap();
        rig.until(|r| settled(r, &task).0 == WorkState::OutcomeUnknown)
            .await;
        assert_eq!(settled(&rig, &task).1, details::AGENT_EXITED);
        passes(&mut rig, 3);
        let (alerts, more) = page_for(&mut rig, &phone, None);
        assert!(!more);
        assert_eq!(alerts.len(), 1, "{alerts:?}");
        let alert = &alerts[0];
        assert_eq!(
            (
                alert.seq,
                alert.kind,
                alert.host_id.as_str(),
                alert.session_id.as_str(),
                alert.task_id.as_str(),
                alert.sender.as_str(),
                alert.reason.as_str(),
            ),
            (
                1,
                atem_client::session::alerts::AlertKind::OutcomeUnknown,
                "host",
                rig.sid.as_str(),
                task.as_str(),
                PHONE,
                details::AGENT_EXITED,
            )
        );
        assert!(alert.created_at >= start && alert.created_at <= host_now().wall_ms);
        let store = rig.bridge.work.store.as_ref().unwrap();
        assert_eq!(
            store.unresolved().unwrap(),
            (1, BTreeMap::from([(PHONE.to_string(), 1)]))
        );
        // Written again (a pass rewriting it): still its one alert.
        store.save_work(&stored_record(&rig, &task)).unwrap();
        assert_eq!(alert_rows(&rig).len(), 1);
        // A v1 task (no admission record) of unknown outcome: none.
        let mut v1 = stored_record(&rig, &task);
        v1.delegated = None;
        let id = uuid::Uuid::new_v4().to_string();
        v1.task.task_id = id.clone();
        v1.status.task_id = id;
        v1.status.state = WorkState::Queued;
        let store = rig.bridge.work.store.as_ref().unwrap();
        assert!(store.enqueue(&v1).unwrap());
        v1.status.state = WorkState::OutcomeUnknown;
        store.save_work(&v1).unwrap();
        assert_eq!(alert_rows(&rig).len(), 1);
        assert_eq!(page_for(&mut rig, &phone, None).0, alerts);
    });
}

/// Host-work-v1 §11.3 ("Order and pages"): `alert_list` lists unresolved
/// alerts in the order the host made them, by `seq`, at most 64 a page,
/// `more` while others follow, the next page after the last `alert_id` read.
/// The wall clock went back between them (each later alert has an earlier
/// `created_at`): the order is still `seq`'s, and a caller following
/// `after` misses none. An alert that ended leaves a gap in `seq`.
#[test]
fn alert_list_pages_by_seq_not_created_at() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, false);
        alerts_on(&mut rig);
        let template = phone_task(&mut rig, &phone, "ALERT_TEMPLATE", start + HOUR);
        let template = stored_record(&rig, &template);
        let tasks = unknown_outcomes(&rig, &template, PHONE, 70);
        // Each later alert made with the wall clock further back.
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .execute("UPDATE alerts SET created_ms=?1-seq*1000", [start])
            .unwrap();
        let (first, more) = page_for(&mut rig, &phone, None);
        assert!(more);
        assert_eq!(
            first.iter().map(|a| a.seq).collect::<Vec<_>>(),
            (1..=64).collect::<Vec<_>>()
        );
        assert_eq!(
            first.iter().map(|a| a.task_id.clone()).collect::<Vec<_>>(),
            tasks[..64]
        );
        assert!(first.windows(2).all(|w| w[0].created_at > w[1].created_at));
        let (next, more) = page_for(&mut rig, &phone, Some(&first[63].alert_id));
        assert!(!more);
        assert_eq!(
            next.iter().map(|a| a.seq).collect::<Vec<_>>(),
            (65..=70).collect::<Vec<_>>()
        );
        // One ends: a gap in `seq`, the order kept.
        end_alert(&rig, &tasks[66]);
        let (next, more) = page_for(&mut rig, &phone, Some(&first[63].alert_id));
        assert_eq!(
            (next.iter().map(|a| a.seq).collect::<Vec<_>>(), more),
            (vec![65, 66, 68, 69, 70], false)
        );
        // After the last: an empty page, nothing more.
        let (none, more) = page_for(&mut rig, &phone, Some(&next[4].alert_id));
        assert_eq!((none.len(), more), (0, false));
        // From the start again: 64, then the rest.
        let (again, more) = page_for(&mut rig, &phone, None);
        assert_eq!((again.len(), more), (64, true));
        assert_eq!(again, first);
    });
}

/// Host-work-v1 §11.3 ("An unknown cursor"): an `after` the host has no
/// unresolved alert for, one it never had or one that ended, is
/// `stale_target`, detail `unknown alert`; the caller lists again from the
/// start. The query changes nothing and records nothing.
#[test]
fn an_unknown_after_is_stale_target_unknown_alert() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, false);
        alerts_on(&mut rig);
        let template = phone_task(&mut rig, &phone, "ALERT_TEMPLATE", start + HOUR);
        let template = stored_record(&rig, &template);
        let tasks = unknown_outcomes(&rig, &template, PHONE, 3);
        let (all, _) = page_for(&mut rig, &phone, None);
        assert_eq!(all.len(), 3);
        let before = alert_rows(&rig);
        // Never an alert of this host.
        let never = uuid::Uuid::new_v4().to_string();
        assert_eq!(
            list_alerts(&mut rig, &phone, Some(&never)).1,
            unknown_alert()
        );
        // One that ended.
        end_alert(&rig, &tasks[1]);
        let ended = alert_rows(&rig);
        assert_eq!(
            list_alerts(&mut rig, &phone, Some(&all[1].alert_id)).1,
            unknown_alert()
        );
        // A live one: the page after it.
        let (after, more) = page_for(&mut rig, &phone, Some(&all[0].alert_id));
        assert_eq!((after, more), (vec![all[2].clone()], false));
        // Reads recorded nothing: only the end changed the rows.
        assert_eq!(alert_rows(&rig), ended);
        assert_eq!(
            before
                .iter()
                .zip(&ended)
                .filter(|(b, e)| b != e)
                .map(|(b, _)| b.2.clone())
                .collect::<Vec<_>>(),
            [tasks[1].clone()]
        );
    });
}

/// Design I.4.6 ("New rule"), host-work-v1 §11.3 ("Authority"):
/// `alert_list` answers native members holding `control` (the phone, the
/// Mac), the members that get approval hints. The channel refuses everyone
/// else `forbidden` before decoding (`Need::Alerts`), and the bridge again:
/// a native member without `control` (the viewer), a service whatever its
/// ops (the bot), and `local`. Without `host.alerts` the op is `busy` as
/// before the hook.
#[test]
fn alert_list_answers_native_control_only() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        alerts_on(&mut rig);
        rig.bridge.start_view().gates = Gates::closed_until_feeds();
        let template = phone_task(&mut rig, &s.phone, "ALERT_TEMPLATE", start + HOUR);
        let template = stored_record(&rig, &template);
        let task = unknown_outcomes(&rig, &template, PHONE, 1).remove(0);
        // The channel's check, before any field is decoded.
        let need = Need::of_request(
            "session",
            &json!({"v": 1, "op": "alert_list", "id": "x", "host": {}}),
        );
        assert_eq!(need, Ok(Need::Alerts));
        for (who, allowed) in [
            (&s.phone, true),
            (&s.mac, true),
            (&s.viewer, false),
            (&s.bot, false),
        ] {
            assert_eq!(who.allows(Need::Alerts), allowed, "{}", who.name());
        }
        // The bridge answers the phone and the Mac.
        for who in [s.phone.clone(), s.mac.clone()] {
            let (alerts, more) = page_for(&mut rig, &who, None);
            assert_eq!(
                (
                    alerts.iter().map(|a| a.task_id.clone()).collect::<Vec<_>>(),
                    more
                ),
                (vec![task.clone()], false),
                "{}",
                who.name()
            );
        }
        // And no one else.
        for who in [s.viewer.clone(), s.bot.clone()] {
            assert_eq!(
                list_alerts(&mut rig, &who, None).1,
                forbidden(),
                "{}",
                who.name()
            );
        }
        let local = rig.bridge.local_attachment().to_string();
        let req = hw::Request::AlertList {
            v: 1,
            id: uuid::Uuid::new_v4().to_string(),
            host: rig.bridge.work_host(),
            after: None,
        };
        assert_eq!(
            rig.bridge.work_request(
                &local,
                &req,
                &mut Cx {
                    client: &rig.app.astation_client,
                    sessions: &mut rig.sessions,
                },
            ),
            forbidden(),
            "local"
        );
        // `host.alerts` off: `busy`, as before the hook.
        rig.bridge.features = HostFeatures::parse("host.delegated").unwrap();
        assert_eq!(list_alerts(&mut rig, &s.phone, None).1, busy());
    });
}

/// Design I.4.6 ("Ending"), host-work-v1 §11.3 ("What is listed"): the
/// phone's task runs and its outcome becomes unknown (`write
/// interrupted`); its agent then submits a reply, which proves the turn
/// ran: the task moves to `awaiting_result`, and its alert ends in the same
/// write. It is no longer listed, its id is an unknown cursor, and nothing
/// is unresolved; the row stays.
#[test]
fn an_alert_ends_when_a_reply_moves_its_task() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        alerts_on(&mut rig);
        let task = phone_task(&mut rig, &phone, "ALERT_REPLY", start + HOUR);
        turn_journaled(&mut rig, &task, "ALERT_REPLY").await;
        hold_host_work(&mut rig);
        make_unknown(&rig, &task, details::WRITE_INTERRUPTED);
        let (alerts, _) = page_for(&mut rig, &phone, None);
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].reason, details::WRITE_INTERRUPTED);
        let alert = alerts[0].alert_id.clone();
        reply(&mut rig, &task, "ALERT_REPLY_TEXT", &[]).unwrap();
        assert_eq!(settled(&rig, &task).0, WorkState::AwaitingResult);
        assert_eq!(page_for(&mut rig, &phone, None), (vec![], false));
        assert_eq!(
            list_alerts(&mut rig, &phone, Some(&alert)).1,
            unknown_alert()
        );
        let store = rig.bridge.work.store.as_ref().unwrap();
        assert_eq!(store.unresolved().unwrap(), (0, BTreeMap::new()));
        let rows = alert_rows(&rig);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            (rows[0].0.as_str(), rows[0].2.as_str()),
            (alert.as_str(), task.as_str())
        );
        assert!(rows[0].3.is_some(), "ended, kept");
        // The task still needs its result.
        assert_eq!(
            status(ask(&mut rig, &phone, Q::Query(&task))).state,
            WorkState::AwaitingResult
        );
    });
}

/// Design I.4.6 ("Capacity"), host-work-v1 §11.6: at 64 unresolved
/// outcomes from the phone, its requests that would make a new task are
/// refused `busy`, `too many unresolved outcomes`, and nothing is recorded:
/// `work_enqueue`, and `message_publish` with an agent recipient. A message
/// with no task (a notice) is accepted, a retry of a task accepted before is
/// answered with its status, and another sender (the bot) isn't refused.
/// One resolved, the phone's next task is accepted. With the hook off,
/// nothing is counted (main's behaviour).
#[test]
fn sixty_four_from_one_sender_refuse_its_new_tasks() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        alerts_on(&mut rig);
        rig.bridge.start_view().gates = Gates::closed_until_feeds();
        let template = phone_task(&mut rig, &s.phone, "CAP_TEMPLATE", start + HOUR);
        let template = stored_record(&rig, &template);
        let mut seeded = unknown_outcomes(&rig, &template, PHONE, 63);
        // 63: accepted.
        let below = phone_enqueue(&rig, "CAP_BELOW");
        assert!(matches!(
            ask_req(&mut rig, &s.phone, &below),
            Ok(ResultBody::Work { .. })
        ));
        seeded.extend(unknown_outcomes(&rig, &template, PHONE, 1));
        let store = rig.bridge.work.store.as_ref().unwrap();
        assert_eq!(store.unresolved().unwrap().1[PHONE], 64);
        // 64: a new task is refused, and nothing recorded.
        let refused = phone_enqueue(&rig, "CAP_REFUSED");
        assert_eq!(ask_req(&mut rig, &s.phone, &refused), too_many());
        let store = rig.bridge.work.store.as_ref().unwrap();
        assert!(store.work(&enqueued(&refused)).unwrap().is_none());
        let (publish, message_task) = phone_message(&rig, "CAP_MESSAGE", None);
        assert_eq!(ask_req(&mut rig, &s.phone, &publish), too_many());
        let hw::Request::Publish { message, .. } = &publish else {
            unreachable!()
        };
        let store = rig.bridge.work.store.as_ref().unwrap();
        assert!(store.message(&message.message_id).unwrap().is_none());
        assert!(store.work(&message_task).unwrap().is_none());
        // A notice makes no task: accepted.
        let (mut notice, _) = phone_message(&rig, "CAP_NOTICE", None);
        if let hw::Request::Publish { message, .. } = &mut notice {
            message.recipients[0].destination = Destination::Project {
                route_id: "rm".into(),
                route_revision: 1,
            };
        }
        let Ok(ResultBody::Message { message: receipt }) = ask_req(&mut rig, &s.phone, &notice)
        else {
            panic!("a message result");
        };
        assert!(matches!(receipt.recipients[0].delivery, Delivery::Stored));
        // A retry of the task accepted before: its status.
        assert!(matches!(
            ask_req(&mut rig, &s.phone, &below),
            Ok(ResultBody::Work { .. })
        ));
        // Another sender: not refused.
        bot_task(&mut rig, &s, "CAP_BOT", start + HOUR);
        // One resolved: the phone's next task is accepted.
        end_alert(&rig, &seeded[0]);
        let next = phone_enqueue(&rig, "CAP_NEXT");
        assert!(matches!(
            ask_req(&mut rig, &s.phone, &next),
            Ok(ResultBody::Work { .. })
        ));
        // 64 again, the hook off: v1, nothing counted.
        unknown_outcomes(&rig, &template, PHONE, 1);
        let again = phone_enqueue(&rig, "CAP_X");
        assert_eq!(ask_req(&mut rig, &s.phone, &again), too_many());
        rig.bridge.features = HostFeatures::default();
        let off = phone_enqueue(&rig, "CAP_HOOK_OFF");
        assert!(matches!(
            ask_req(&mut rig, &s.phone, &off),
            Ok(ResultBody::Work { .. })
        ));
        assert_eq!(stored_record(&rig, &enqueued(&off)).delegated, None);
    });
}

/// Design I.4.6 ("Capacity"), host-work-v1 §11.6: at 256 unresolved
/// outcomes on the host (64 each from four other senders), every remote
/// sender's new tasks are refused `busy`, `too many unresolved outcomes`:
/// the phone and the bot (delegated, none of their own unresolved), and the
/// bot again once no feed covers it (a v1 sender). Local tasks never are:
/// a local `message send` is accepted and its task queued. One resolved,
/// the phone's next task is accepted.
#[test]
fn two_fifty_six_refuse_every_remote_sender_not_local() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        alerts_on(&mut rig);
        rig.bridge.start_view().gates = Gates::closed_until_feeds();
        let template = phone_task(&mut rig, &s.phone, "CAP_TEMPLATE", start + HOUR);
        let template = stored_record(&rig, &template);
        let mut seeded = Vec::new();
        for sender in [
            "member:dev-a",
            "member:dev-b",
            "member:dev-c",
            "service:svc-d",
        ] {
            seeded.extend(unknown_outcomes(&rig, &template, sender, 64));
        }
        let store = rig.bridge.work.store.as_ref().unwrap();
        let (host, by_sender) = store.unresolved().unwrap();
        assert_eq!((host, by_sender.len()), (256, 4));
        assert!(!by_sender.contains_key(PHONE) && !by_sender.contains_key(BOT));
        // The phone: its task and its message.
        let task = phone_enqueue(&rig, "HOST_PHONE");
        assert_eq!(ask_req(&mut rig, &s.phone, &task), too_many());
        let (publish, _) = phone_message(&rig, "HOST_MESSAGE", None);
        assert_eq!(ask_req(&mut rig, &s.phone, &publish), too_many());
        // The bot, covered (delegated), then uncovered (v1).
        let mut bot = phone_enqueue(&rig, "HOST_BOT");
        if let hw::Request::Enqueue { route_id, .. } = &mut bot {
            *route_id = "rs".into();
        }
        assert_eq!(ask_req(&mut rig, &s.bot, &bot), too_many());
        rig.bridge.work.controls = Some(Box::new(NoFeeds));
        assert_eq!(ask_req(&mut rig, &s.bot, &bot), too_many());
        let store = rig.bridge.work.store.as_ref().unwrap();
        assert!(store.work(&enqueued(&bot)).unwrap().is_none());
        // Local: never refused for unresolved outcomes.
        let local = rig.message();
        rig.publish(&local);
        let task = rig.work(&local);
        assert_eq!((task.delegated, task.principal.as_str()), (None, "local"));
        assert!(matches!(
            task.status.state,
            WorkState::Queued | WorkState::Blocked | WorkState::Submitting | WorkState::Submitted
        ));
        // One resolved: 255, and the phone's next task is accepted.
        end_alert(&rig, &seeded[0]);
        let next = phone_enqueue(&rig, "HOST_NEXT");
        assert!(matches!(
            ask_req(&mut rig, &s.phone, &next),
            Ok(ResultBody::Work { .. })
        ));
    });
}

// ── The push hints of alerts (Task 24; session-v1 R9.9) ──

/// The relay link is up on the r9 side (the rig has no Astation link, so
/// nothing is flushed to one: [`relay_out`] takes what waits).
fn relay_up(rig: &mut LocalRig) {
    rig.bridge.r9_call(|r9, parts| r9.link_up(1, parts));
}

/// What the r9 side would send the relay now.
fn relay_out(rig: &mut LocalRig) -> Vec<Value> {
    let mut out = Vec::new();
    rig.bridge.r9.flush_relay(&mut |text| {
        out.push(serde_json::from_str(&text).unwrap());
        true
    });
    out
}

/// The `outcome_unknown` hints among `messages`, verified as a client does
/// against `log`, the host's device list.
fn alert_hints_in(log: &TestLog, messages: &[Value]) -> Vec<atem_client::push::AlertHint> {
    messages
        .iter()
        .filter(|m| m["op"] == "push_hint")
        .flat_map(|m| m["hints"].as_array().unwrap().clone())
        .map(|h| {
            let object = atem_client::SignedObject::parse(h.to_string().as_bytes()).unwrap();
            atem_client::push::AlertHint::verify(
                &object,
                &log.log,
                host_now().wall_ms,
                atem_client::push::Verifier::Client,
            )
            .unwrap()
        })
        .collect()
}

/// Unacknowledged hints and seens waiting for the relay.
fn hints_pending(rig: &LocalRig) -> usize {
    rig.bridge.r9.push_status(host_now().wall_ms).pending
}

/// Design I.4.6 ("Transport"), host-work-v1 §11.3 ("The push hint"),
/// session-v1 R9.9: the phone's task runs and its agent exits; the task
/// becomes `outcome_unknown`, its alert is committed, and then the host
/// sends one `outcome_unknown` hint per native member holding `control` (the
/// Mac and the phone; never the viewer or the bot), signed with the host
/// channel key, its identity the alert's, its `created_at` the alert's;
/// each device opens its own sealed part: the task, the session, the sender
/// and the alert's reason (the receipt's, `agent exited`), none of them in
/// clear on the wire. Later passes send no other hint (a resend has the same
/// bytes). A covered service's task gets its alert hinted to the same two.
/// Once an alert ends (the owner resolves its task), its hints are no
/// longer sent.
#[test]
fn outcome_unknown_raises_one_hint_per_native_control_member() {
    use crate::session_protocol::membership::r9log::enc;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        alerts_on(&mut rig);
        relay_up(&mut rig);
        let task = phone_task(&mut rig, &s.phone, "HINT_EXITED", start + HOUR);
        rig.until(|r| input(r).contains("HINT_EXITED")).await;
        passes(&mut rig, 1);
        assert!(relay_out(&mut rig).is_empty(), "nothing while it runs");
        std::fs::write(rig.fake.join("exit"), "").unwrap();
        rig.until(|r| settled(r, &task).0 == WorkState::OutcomeUnknown)
            .await;
        passes(&mut rig, 1);
        let (alerts, _) = page_for(&mut rig, &s.phone, None);
        assert_eq!(alerts.len(), 1, "{alerts:?}");
        let alert = alerts[0].clone();
        let out = relay_out(&mut rig);
        assert_eq!(out.len(), 1, "{out:?}");
        let text = out[0].to_string();
        for clear in [
            task.as_str(),
            rig.sid.as_str(),
            PHONE,
            details::AGENT_EXITED,
        ] {
            assert!(!text.contains(clear), "{clear} in clear: {text}");
        }
        let hints = alert_hints_in(&s.log, &out);
        let devices: Vec<&str> = hints.iter().map(|h| h.device_id()).collect();
        assert_eq!(devices, [MAC, "dev-phone"]);
        let key = atem_client::push::AlertKey::new(&s.log.log, "host", 1, &alert.alert_id);
        let facts = atem_client::push::AlertPlain {
            task_id: task.clone(),
            session_id: rig.sid.to_string(),
            sender: PHONE.into(),
            reason: details::AGENT_EXITED.into(),
        };
        for h in &hints {
            assert_eq!(h.key(), &key);
            assert_eq!(h.created_at(), alert.created_at);
            assert_eq!(
                h.expires_at(),
                alert.created_at + atem_client::push::MAX_HINT_LIFETIME_MS
            );
            assert_eq!(
                h.open(&s.log.keys, &enc(h.device_id()), h.device_id())
                    .unwrap(),
                facts
            );
        }
        assert_eq!(hints_pending(&rig), 2);
        // More passes and a rewrite of the task: no other hint (a resend, if
        // one fell due, has the first one's bytes).
        let store = rig.bridge.work.store.as_ref().unwrap();
        store.save_work(&stored_record(&rig, &task)).unwrap();
        passes(&mut rig, 3);
        let sent: Vec<Value> = out[0]["hints"].as_array().unwrap().clone();
        for m in relay_out(&mut rig) {
            for h in m["hints"].as_array().unwrap() {
                assert!(sent.contains(h), "a new hint: {h}");
            }
        }
        assert_eq!(hints_pending(&rig), 2);
        // A covered service's task: hinted to the Mac and the phone, never
        // to the bot.
        let template = stored_record(&rig, &task);
        let bot_task = unknown_outcomes(&rig, &template, BOT, 1).remove(0);
        passes(&mut rig, 1);
        let out = relay_out(&mut rig);
        let hints: Vec<_> = alert_hints_in(&s.log, &out)
            .into_iter()
            .filter(|h| h.key().alert_id != alert.alert_id)
            .collect();
        let devices: Vec<&str> = hints.iter().map(|h| h.device_id()).collect();
        assert_eq!(devices, [MAC, "dev-phone"]);
        let opened = hints[1]
            .open(&s.log.keys, &enc("dev-phone"), "dev-phone")
            .unwrap();
        assert_eq!((opened.sender.as_str(), opened.task_id), (BOT, bot_task));
        assert_eq!(hints_pending(&rig), 4);
        // The owner resolves the phone's task: its alert ends, and so do
        // its hints' resends; the bot's go on.
        let (req, reply) = resolve_by(&mut rig, &s.mac, &task, &failure("resolved by the owner"));
        assert_eq!(resolved_status(&req, reply).state, WorkState::Failed);
        passes(&mut rig, 1);
        assert_eq!(hints_pending(&rig), 2);
        assert!(
            rig.bridge
                .r9
                .hinted_alerts()
                .iter()
                .all(|a| *a != alert.alert_id)
        );
    });
}

/// Step 4's constraints (hook off = main; `host.alerts`, session-v1 R9.9
/// "Compatibility"): with `host.delegated` on and `host.alerts` off, a
/// delegated task's unknown outcome keeps its alert (internal state) but
/// nothing is hinted, even handed to the engine directly; with the hook off
/// entirely a task's unknown outcome raises no alert and sends nothing.
#[test]
fn no_hint_without_host_alerts() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        // `host.delegated` alone, on the r9 side too (as `work_config`
        // hands the hook's features over).
        rig.bridge.r9.set_delegated_features(true, false);
        rig.bridge.r9.enable_host_work(true);
        relay_up(&mut rig);
        let tasks = phone_unknowns(&mut rig, &s, 2, start + HOUR);
        passes(&mut rig, 2);
        assert_eq!(alert_rows(&rig).len(), 2, "the alerts are kept");
        assert!(relay_out(&mut rig).is_empty());
        assert_eq!(hints_pending(&rig), 0);
        // Handed to the engine itself: `host.alerts` is off there too.
        let store = rig.bridge.work.store.as_ref().unwrap();
        let (alerts, _) = store.alert_page(None, 64).unwrap();
        assert_eq!(alerts.len(), 2);
        rig.bridge
            .r9_call(|r9, parts| r9.alert_opened(&alerts[0], parts));
        assert!(relay_out(&mut rig).is_empty());
        assert_eq!(hints_pending(&rig), 0);
        // The hook off (main): a task of unknown outcome raises nothing and
        // sends nothing.
        rig.bridge.features = HostFeatures::default();
        let template = stored_record(&rig, &tasks[0]);
        let mut v1 = template.clone();
        v1.delegated = None;
        let id = uuid::Uuid::new_v4().to_string();
        v1.task.task_id = id.clone();
        v1.status.task_id = id;
        v1.status.state = WorkState::Queued;
        let store = rig.bridge.work.store.as_ref().unwrap();
        assert!(store.enqueue(&v1).unwrap());
        v1.status.state = WorkState::OutcomeUnknown;
        store.save_work(&v1).unwrap();
        passes(&mut rig, 2);
        assert_eq!(alert_rows(&rig).len(), 2);
        assert!(relay_out(&mut rig).is_empty());
        assert_eq!(hints_pending(&rig), 0);
    });
}

/// Host-work-v1 §11.3 ("only behind `host.alerts`"), in the bridge: with
/// the hook's features on but hosting off on the r9 side (its welcome lists
/// no `host.alerts`, as after a receipt-database fault), an unknown
/// outcome's alert is kept and listed later, but nothing is hinted, then or
/// once hosting is back; an alert raised with hosting on is hinted.
#[test]
fn an_alert_raised_while_hosting_is_off_is_never_hinted() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        alerts_on(&mut rig);
        rig.bridge.r9.enable_host_work(false);
        relay_up(&mut rig);
        let off = phone_unknowns(&mut rig, &s, 1, start + HOUR).remove(0);
        passes(&mut rig, 2);
        assert_eq!(alert_rows(&rig).len(), 1);
        assert!(relay_out(&mut rig).is_empty(), "hosting off: no hint");
        assert_eq!(hints_pending(&rig), 0);
        rig.bridge.r9.enable_host_work(true);
        passes(&mut rig, 2);
        assert!(relay_out(&mut rig).is_empty(), "never hinted later");
        let template = stored_record(&rig, &off);
        let on = unknown_outcomes(&rig, &template, PHONE, 1).remove(0);
        passes(&mut rig, 1);
        let hints = alert_hints_in(&s.log, &relay_out(&mut rig));
        assert_eq!(hints.len(), 2);
        let (alerts, _) = page_for(&mut rig, &s.phone, None);
        let on_alert = alerts.iter().find(|a| a.task_id == on).unwrap();
        assert!(alerts.iter().any(|a| a.task_id == off), "listed");
        assert!(hints.iter().all(|h| h.key().alert_id == on_alert.alert_id));
    });
}

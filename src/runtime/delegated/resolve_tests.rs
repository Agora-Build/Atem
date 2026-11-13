// Unknown outcomes stay unresolved until `work_resolve` or a reply settles
// them (design I.4.5, I.4.6; host-work-v1 §11.2, §11.6 "Unknown outcomes"
// and "Capacity"), in the bridge: the rig's host with a pinned device list,
// `host.delegated` (and for the alerts `host.alerts`) on, the phone (a
// native member holding `control`), and for the authority the bot, the Mac
// (the owner) and a viewer. Included beside the dispatch's, the lifecycle's
// and the alerts' tests, whose helpers and imports it shares.

use atem_client::session::host_work::Resolution;

/// `failed`, with `detail`.
fn failure(detail: &str) -> Resolution {
    Resolution::Failed {
        detail: detail.into(),
    }
}

/// `done`, with a vault snapshot of `text` at `version`.
fn done_with(text: &str, version: u64) -> Resolution {
    Resolution::Done {
        result: hw::ContextSnapshot {
            kind: hw::ContextKind::Vault,
            id: "v-result:1".into(),
            version,
            digest: hw::digest(text.as_bytes()),
            text: text.into(),
        },
    }
}

/// `work_resolve` of `task` as `resolution`, with a fresh exchange id.
fn resolve_req(rig: &LocalRig, task: &str, resolution: &Resolution) -> hw::Request {
    hw::Request::WorkResolve {
        v: 1,
        id: uuid::Uuid::new_v4().to_string(),
        host: rig.bridge.work_host(),
        task_id: task.into(),
        resolution: resolution.clone(),
    }
}

/// `who` resolves `task` as `resolution`, as its channel hands the request
/// to the bridge: the request and the reply.
fn resolve_by(
    rig: &mut LocalRig,
    who: &Authority,
    task: &str,
    resolution: &Resolution,
) -> (hw::Request, Result<ResultBody, HostWorkError>) {
    let req = resolve_req(rig, task, resolution);
    let reply = ask_req(rig, who, &req);
    (req, reply)
}

/// The status a `work_resolve` result carries, read back by the client
/// core's strict reader as the answer to `req` (the task as resolved,
/// settled the way it asked).
fn resolved_status(req: &hw::Request, reply: Result<ResultBody, HostWorkError>) -> WorkStatus {
    let body = reply.expect("a work result");
    let json = hw::result(
        &uuid::Uuid::new_v4().to_string(),
        req.id(),
        req.host(),
        &uuid::Uuid::new_v4().to_string(),
        "channel",
        body.clone(),
    );
    let response = hw::Response::from_data(&json["data"]).expect("the reader takes it");
    assert!(response.answers(req), "it answers the request: {body:?}");
    status(Ok(body))
}

/// The phone's tasks the bridge admitted, `n` of them, each written
/// `outcome_unknown` (`agent exited`) before any ran: the host's own
/// Station's gate closed first, so none is dispatched. Their ids.
fn phone_unknowns(rig: &mut LocalRig, s: &Senders, n: usize, expires_at: u64) -> Vec<String> {
    rig.bridge.start_view().gates = Gates::default();
    let template = phone_task(rig, &s.phone, "RESOLVE_TEMPLATE", expires_at);
    let template = stored_record(rig, &template);
    unknown_outcomes(rig, &template, PHONE, n)
}

/// Design I.4.6, host-work-v1 §11.6 ("Unknown outcomes"): a delegated task
/// of unknown outcome no longer expires at its deadline. Its agent exits in
/// its turn (`agent exited`), and the delegated clock passes its deadline,
/// then two days more: pass after pass it stays `outcome_unknown`,
/// unresolved, its detail `deadline passed; outcome unknown`, and its alert
/// stays listed with the reason it was raised with. Its sender's query
/// shows it so (the reconciliation the query runs keeps the deadline's
/// detail), and it can still be resolved.
#[test]
fn delegated_outcome_unknown_never_expires() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        alerts_on(&mut rig);
        let task = phone_task(&mut rig, &phone, "NEVER_EXPIRES", start + HOUR);
        rig.until(|r| input(r).contains("NEVER_EXPIRES")).await;
        std::fs::write(rig.fake.join("exit"), "").unwrap();
        rig.until(|r| settled(r, &task).0 == WorkState::OutcomeUnknown)
            .await;
        assert_eq!(settled(&rig, &task).1, details::AGENT_EXITED);
        let unresolved = (
            WorkState::OutcomeUnknown,
            details::DEADLINE_PASSED_OUTCOME_UNKNOWN.to_string(),
        );
        // Its deadline on the delegated clock, then two days more.
        os.pass(HOUR);
        passes(&mut rig, 3);
        assert_eq!(settled(&rig, &task), unresolved);
        os.pass(48 * HOUR);
        passes(&mut rig, 3);
        assert_eq!(settled(&rig, &task), unresolved);
        assert_eq!(stored_record(&rig, &task).status.resolved, None);
        // Its alert stays, with its reason.
        let (alerts, more) = page_for(&mut rig, &phone, None);
        assert!(!more);
        assert_eq!(
            alerts
                .iter()
                .map(|a| (a.task_id.as_str(), a.reason.as_str()))
                .collect::<Vec<_>>(),
            [(task.as_str(), details::AGENT_EXITED)]
        );
        // Its sender reads it as it stands.
        let s = status(ask(&mut rig, &phone, Q::Query(&task)));
        assert_eq!((s.state, s.detail), unresolved);
        assert_eq!(settled(&rig, &task), unresolved);
        // It can still be resolved.
        let (req, reply) = resolve_by(&mut rig, &phone, &task, &failure("given up"));
        assert_eq!(resolved_status(&req, reply).state, WorkState::Failed);
    });
}

/// Design I.4.6 ("At the deadline it stops holding its session"),
/// host-work-v1 §11.6: the phone's task runs, its outcome becomes unknown
/// (`write interrupted`) and the turn ends. Until its deadline it holds its
/// session: the phone's next task waits behind it. At its deadline on the
/// delegated clock it stops holding, its detail `deadline passed; outcome
/// unknown`, still `outcome_unknown` and unresolved with its alert, and the
/// next task runs. No later pass reads it again.
#[test]
fn at_its_deadline_it_stops_holding_with_its_detail() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        alerts_on(&mut rig);
        let first = phone_task(&mut rig, &phone, "HOLDS_FIRST", start + HOUR);
        turn_journaled(&mut rig, &first, "HOLDS_FIRST").await;
        hold_host_work(&mut rig);
        make_unknown(&rig, &first, details::WRITE_INTERRUPTED);
        let next = phone_task(&mut rig, &phone, "HOLDS_NEXT", start + 3 * HOUR);
        // The turn ends: only the unknown outcome holds the session now.
        std::fs::write(rig.fake.join("complete"), "").unwrap();
        rig.until(|r| r.sessions[&r.sid].chat.status().state == ChatState::Ready)
            .await;
        passes(&mut rig, 5);
        assert!(!input(&rig).contains("HOLDS_NEXT"), "held");
        assert_eq!(
            settled(&rig, &next),
            (
                WorkState::Blocked,
                "waiting for an earlier task on this session".into()
            )
        );
        let store = rig.bridge.work.store.as_ref().unwrap();
        assert!(store.holds_unknown_outcome(rig.sid.as_str()).unwrap());
        assert_eq!(
            settled(&rig, &first),
            (WorkState::OutcomeUnknown, details::WRITE_INTERRUPTED.into())
        );
        // Its deadline, on the delegated clock.
        os.pass(HOUR);
        rig.until(|r| input(r).contains("HOLDS_NEXT")).await;
        assert_eq!(
            settled(&rig, &first),
            (
                WorkState::OutcomeUnknown,
                details::DEADLINE_PASSED_OUTCOME_UNKNOWN.into()
            )
        );
        let store = rig.bridge.work.store.as_ref().unwrap();
        assert!(!store.holds_unknown_outcome(rig.sid.as_str()).unwrap());
        assert_eq!(stored_record(&rig, &first).status.resolved, None);
        let (alerts, _) = page_for(&mut rig, &phone, None);
        assert_eq!(
            alerts
                .iter()
                .map(|a| (a.task_id.as_str(), a.reason.as_str()))
                .collect::<Vec<_>>(),
            [(first.as_str(), details::WRITE_INTERRUPTED)]
        );
        complete(&mut rig, &next).await;
        // Nothing reads it again: it has no row among the waits.
        let waits: u32 = rig
            .bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .query_row(
                "SELECT count(*) FROM work_waits WHERE id=?1",
                [&first],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(waits, 0);
        let before = stored_record(&rig, &first);
        os.pass(HOUR);
        passes(&mut rig, 3);
        assert_eq!(
            serde_json::to_value(stored_record(&rig, &first)).unwrap(),
            serde_json::to_value(before).unwrap()
        );
    });
}

/// Design I.4.6 ("A reply ... proves its turn ran"), host-work-v1 §11.6:
/// the phone's task runs and its outcome becomes unknown; its agent's reply
/// moves it to `awaiting_result`, which isn't success. Its alert ends, it
/// can't be resolved any more (`forbidden`: it isn't `outcome_unknown`),
/// and it still needs `work_complete`, which its sender gives it.
#[test]
fn a_reply_moves_it_to_awaiting_result() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        alerts_on(&mut rig);
        let task = phone_task(&mut rig, &phone, "REPLY_MOVES", start + HOUR);
        turn_journaled(&mut rig, &task, "REPLY_MOVES").await;
        hold_host_work(&mut rig);
        make_unknown(&rig, &task, details::WRITE_INTERRUPTED);
        assert_eq!(page_for(&mut rig, &phone, None).0.len(), 1);
        reply(&mut rig, &task, "REPLY_MOVES_TEXT", &[]).unwrap();
        assert_eq!(settled(&rig, &task).0, WorkState::AwaitingResult);
        assert_eq!(stored_record(&rig, &task).status.resolved, None);
        assert_eq!(page_for(&mut rig, &phone, None), (vec![], false));
        // No longer of unknown outcome: not resolvable.
        for resolution in [failure("no"), done_with("no", 1)] {
            assert_eq!(
                resolve_by(&mut rig, &phone, &task, &resolution).1,
                forbidden()
            );
        }
        assert_eq!(settled(&rig, &task).0, WorkState::AwaitingResult);
        // Its sender completes it.
        let s = status(ask(
            &mut rig,
            &phone,
            Q::Complete(&task, "REPLY_MOVES_RESULT"),
        ));
        assert_eq!((s.state, s.resolved), (WorkState::Completed, None));
    });
}

/// Design I.4.6 ("A reply that arrives after a failed resolution is stored
/// and the task stays failed"), host-work-v1 §11.6: the phone's task runs,
/// its outcome becomes unknown, and the Mac (the owner) resolves it
/// `failed`. Its agent's reply then is stored and readable by the sender
/// and the owner; the task stays `failed`, its status as the resolution
/// left it.
#[test]
fn a_reply_after_a_failed_resolution_is_stored_task_stays_failed() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        alerts_on(&mut rig);
        let task = phone_task(&mut rig, &s.phone, "REPLY_AFTER", start + HOUR);
        turn_journaled(&mut rig, &task, "REPLY_AFTER").await;
        hold_host_work(&mut rig);
        make_unknown(&rig, &task, details::WRITE_INTERRUPTED);
        let (req, reply_to) = resolve_by(&mut rig, &s.mac, &task, &failure("the owner gave up"));
        let resolved = resolved_status(&req, reply_to);
        assert_eq!(
            (resolved.state, resolved.detail.as_str()),
            (WorkState::Failed, "the owner gave up")
        );
        assert_eq!(resolved.resolved.as_ref().unwrap().by, "member:dev-mac");
        reply(&mut rig, &task, "REPLY_AFTER_TEXT", &[]).unwrap();
        assert_eq!(stored_record(&rig, &task).status, resolved);
        for who in [&s.phone, &s.mac] {
            assert_eq!(
                reply_text(ask(&mut rig, who, Q::Reply(&task))),
                "REPLY_AFTER_TEXT"
            );
            assert_eq!(status(ask(&mut rig, who, Q::Query(&task))), resolved);
        }
        // The same reply again is the one recorded; another is refused.
        reply(&mut rig, &task, "REPLY_AFTER_TEXT", &[]).unwrap();
        assert!(reply(&mut rig, &task, "ANOTHER_REPLY", &[]).is_err());
        assert_eq!(
            reply_text(ask(&mut rig, &s.phone, Q::Reply(&task))),
            "REPLY_AFTER_TEXT"
        );
        assert_eq!(stored_record(&rig, &task).status, resolved);
    });
}

/// Host-work-v1 §11.2, design I.4.5: `work_resolve` settles a delegated
/// task of unknown outcome. The phone, its sender with current authority,
/// resolves one `failed`: it is `failed` with the detail given, and
/// `resolved{by: member:dev-phone, at}` the host's wall clock then. The Mac,
/// the owner, resolves another `done`: `completed` with exactly that result,
/// resolved by the Mac. Each result answers its request (the client core's
/// reader), and later queries show the same status. The bot (another
/// sender) and the viewer (no `control`) may not: `forbidden`, nothing
/// changed.
#[test]
fn work_resolve_failed_and_done() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        alerts_on(&mut rig);
        let tasks = phone_unknowns(&mut rig, &s, 2, start + HOUR);
        for who in [&s.bot, &s.viewer] {
            assert_eq!(
                resolve_by(&mut rig, who, &tasks[0], &failure("no")).1,
                forbidden(),
                "{}",
                who.name()
            );
        }
        assert_eq!(
            settled(&rig, &tasks[0]),
            (WorkState::OutcomeUnknown, details::AGENT_EXITED.into())
        );
        let before = host_now().wall_ms;
        let (req, reply) = resolve_by(
            &mut rig,
            &s.phone,
            &tasks[0],
            &failure("the agent crashed mid-write"),
        );
        let after = host_now().wall_ms;
        let failed = resolved_status(&req, reply);
        assert_eq!(
            (failed.state, failed.detail.as_str(), failed.result.as_ref()),
            (WorkState::Failed, "the agent crashed mid-write", None)
        );
        let by = failed.resolved.clone().unwrap();
        assert_eq!(by.by, PHONE);
        assert!(by.at >= before && by.at <= after, "{by:?}");
        assert!(failed.valid());
        assert_eq!(status(ask(&mut rig, &s.phone, Q::Query(&tasks[0]))), failed);
        let resolution = done_with("the change landed", 3);
        let (req, reply) = resolve_by(&mut rig, &s.mac, &tasks[1], &resolution);
        let completed = resolved_status(&req, reply);
        let Resolution::Done { result } = &resolution else {
            unreachable!()
        };
        assert_eq!(
            (completed.state, completed.result.as_ref()),
            (WorkState::Completed, Some(result))
        );
        assert_eq!(completed.resolved.as_ref().unwrap().by, "member:dev-mac");
        assert!(completed.valid());
        for who in [&s.phone, &s.mac] {
            assert_eq!(status(ask(&mut rig, who, Q::Query(&tasks[1]))), completed);
        }
        assert_eq!(stored_record(&rig, &tasks[0]).status, failed);
        assert_eq!(stored_record(&rig, &tasks[1]).status, completed);
    });
}

/// Host-work-v1 §11.2 ("The same resolution"): the same canonical
/// resolution again, whoever asks and whatever the exchange id, returns the
/// recorded status, with the first resolver's `resolved{by, at}`, and
/// writes nothing. The phone resolves a task `failed`, then the phone and
/// the Mac send the same; the Mac resolves another `done`, and the phone
/// sends the same snapshot.
#[test]
fn an_identical_resolution_returns_the_recorded_status() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        alerts_on(&mut rig);
        let tasks = phone_unknowns(&mut rig, &s, 2, start + HOUR);
        let record_json = |rig: &LocalRig, task: &str| -> String {
            rig.bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .db
                .query_row("SELECT record FROM work WHERE id=?1", [task], |r| r.get(0))
                .unwrap()
        };
        for (task, first, again, resolution) in [
            (
                &tasks[0],
                &s.phone,
                [&s.phone, &s.mac],
                failure("stopped mid-turn"),
            ),
            (
                &tasks[1],
                &s.mac,
                [&s.phone, &s.mac],
                done_with("the result", 2),
            ),
        ] {
            let (req, reply) = resolve_by(&mut rig, first, task, &resolution);
            let recorded = resolved_status(&req, reply);
            let stored = record_json(&rig, task);
            for who in again {
                let (req, reply) = resolve_by(&mut rig, who, task, &resolution);
                assert_eq!(resolved_status(&req, reply), recorded, "{}", who.name());
            }
            assert_eq!(record_json(&rig, task), stored, "nothing written");
            assert_eq!(recorded.resolved.unwrap().by, first.name());
        }
    });
}

/// Host-work-v1 §11.2: another resolution of a resolved task is
/// `request_id_reused`, and the task keeps the first: for a `failed` task,
/// another detail (one space more) or `done`; for a `done` task, another
/// snapshot (the same text at another version) or `failed`.
#[test]
fn another_resolution_is_request_id_reused() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        alerts_on(&mut rig);
        let tasks = phone_unknowns(&mut rig, &s, 2, start + HOUR);
        let reused = Err(HostWorkError {
            code: "request_id_reused",
            detail: None,
        });
        for (task, first, others) in [
            (
                &tasks[0],
                failure("stopped"),
                [failure("stopped "), done_with("stopped", 1)],
            ),
            (
                &tasks[1],
                done_with("the result", 1),
                [done_with("the result", 2), failure("the result")],
            ),
        ] {
            let (req, reply) = resolve_by(&mut rig, &s.phone, task, &first);
            let recorded = resolved_status(&req, reply);
            for other in &others {
                for who in [&s.phone, &s.mac] {
                    assert_eq!(
                        resolve_by(&mut rig, who, task, other).1,
                        reused,
                        "{other:?}"
                    );
                }
            }
            assert_eq!(stored_record(&rig, task).status, recorded);
        }
    });
}

/// Host-work-v1 §11.2: `work_resolve` settles only a delegated sender's
/// task of unknown outcome. A v1 task of unknown outcome (accepted with the
/// hook off: no admission) is `forbidden` to its sender and to the owner,
/// and keeps v1: it expires at `expires_at` (the wall clock). A delegated
/// task that isn't `outcome_unknown` (waiting, awaiting its result) is
/// `forbidden`, as are a task the host doesn't have and `local`.
#[test]
fn resolve_of_a_v1_task_is_forbidden() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        alerts_on(&mut rig);
        rig.bridge.start_view().gates = Gates::default();
        // The phone's v1 task: accepted with the hook off.
        rig.bridge.features = HostFeatures::default();
        let v1 = phone_task(&mut rig, &s.phone, "V1_UNKNOWN", start + HOUR);
        alerts_on(&mut rig);
        assert_eq!(stored_record(&rig, &v1).delegated, None);
        make_unknown(&rig, &v1, "submission interrupted");
        // A delegated one, waiting; another awaiting its result.
        let waiting = phone_task(&mut rig, &s.phone, "DELEGATED_WAITING", start + HOUR);
        let awaiting = unknown_outcomes(&rig, &stored_record(&rig, &waiting), PHONE, 1).remove(0);
        let mut record = stored_record(&rig, &awaiting);
        record.status.state = WorkState::AwaitingResult;
        let store = rig.bridge.work.store.as_ref().unwrap();
        store.save_work(&record).unwrap();
        let never = uuid::Uuid::new_v4().to_string();
        for task in [&v1, &waiting, &awaiting, &never] {
            for who in [&s.phone, &s.mac] {
                for resolution in [failure("no"), done_with("no", 1)] {
                    assert_eq!(
                        resolve_by(&mut rig, who, task, &resolution).1,
                        forbidden(),
                        "{task} {}",
                        who.name()
                    );
                }
            }
        }
        // `local`.
        let local = rig.bridge.local_attachment().to_string();
        let req = resolve_req(&rig, &v1, &failure("no"));
        assert_eq!(
            rig.bridge.work_request(
                &local,
                &req,
                &mut Cx {
                    client: &rig.app.astation_client,
                    sessions: &mut rig.sessions,
                },
            ),
            forbidden()
        );
        assert_eq!(
            settled(&rig, &v1),
            (WorkState::OutcomeUnknown, "submission interrupted".into())
        );
        assert_eq!(settled(&rig, &waiting).0, WorkState::Queued);
        assert_eq!(settled(&rig, &awaiting).0, WorkState::AwaitingResult);
        // The v1 one expires at its deadline, on the wall clock.
        let mut record = stored_record(&rig, &v1);
        record.task.expires_at = host_now().wall_ms - 1;
        let store = rig.bridge.work.store.as_ref().unwrap();
        store.save_work(&record).unwrap();
        passes(&mut rig, 1);
        assert_eq!(
            settled(&rig, &v1),
            (
                WorkState::Expired,
                crate::runtime::host_work::EXPIRED_UNKNOWN.into()
            )
        );
        assert_eq!(stored_record(&rig, &v1).status.resolved, None);
    });
}

/// Host-work-v1 §11.2 ("failed.detail is kept exactly as given"): the
/// detail, taken from the wire as a client sends it, is stored and shown
/// byte for byte: leading and trailing spaces, runs of them, non-ASCII
/// text, a combining mark, and a detail of the full 1024 bytes. The same
/// bytes again return the recorded status; the detail trimmed, or the same
/// text in another Unicode form, is another resolution.
#[test]
fn failed_detail_kept_byte_for_byte() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        alerts_on(&mut rig);
        let tasks = phone_unknowns(&mut rig, &s, 2, start + HOUR);
        let long = format!(" {} ", "é".repeat(511));
        assert_eq!(long.len(), hw::MAX_DETAIL_BYTES);
        let details = [
            "  wrote half of src/lib.rs;   rolled back — re\u{301}sume\u{301} ✓  ".to_string(),
            long,
        ];
        for (task, detail) in tasks.iter().zip(&details) {
            // As a client sends it.
            let wire = json!({"v": 1, "id": uuid::Uuid::new_v4().to_string(),
                "host": rig.bridge.work_host(), "op": "work_resolve", "task_id": task,
                "resolution": {"kind": "failed", "detail": detail}});
            let req = hw::Request::from_data(&wire).expect("a valid request");
            let first = resolved_status(&req, ask_req(&mut rig, &s.phone, &req));
            assert_eq!(first.detail.as_bytes(), detail.as_bytes());
            assert_eq!(stored_record(&rig, task).status.detail, *detail);
            assert_eq!(
                status(ask(&mut rig, &s.phone, Q::Query(task))).detail,
                *detail
            );
            let (req, reply) = resolve_by(&mut rig, &s.mac, task, &failure(detail));
            assert_eq!(resolved_status(&req, reply), first);
        }
        // Trimmed, or composed instead of decomposed: another resolution.
        for other in [
            details[0].trim().to_string(),
            details[0].replace("e\u{301}", "é"),
        ] {
            assert_eq!(
                resolve_by(&mut rig, &s.phone, &tasks[0], &failure(&other)).1,
                Err(HostWorkError {
                    code: "request_id_reused",
                    detail: None
                })
            );
        }
        assert_eq!(stored_record(&rig, &tasks[0]).status.detail, details[0]);
    });
}

/// Host-work-v1 §11.2 ("Compatibility"), ruling T17b: `resolved` is
/// written only behind `host.delegated`. With the hook off, `work_resolve`
/// is `busy` as before it existed, and nothing is resolved; with it on, a
/// resolution's status carries `resolved`, and so does the task's
/// `work_query`. Once the runtime runs without the hook again, the task's
/// status reaches the wire without it (a reader that doesn't know the
/// field drops the channel) while the store keeps it. `message_query`'s
/// per-recipient progress never carries it.
#[test]
fn resolved_appears_only_behind_host_delegated() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        alerts_on(&mut rig);
        let tasks = phone_unknowns(&mut rig, &s, 1, start + HOUR);
        let (publish, message_task) = phone_message(&rig, "RESOLVED_MESSAGE", None);
        ask_req(&mut rig, &s.phone, &publish).unwrap();
        make_unknown(&rig, &message_task, details::AGENT_EXITED);
        let wire = |body: &ResultBody| serde_json::to_string(body).unwrap();
        // The hook off: `busy`, nothing resolved.
        rig.bridge.features = HostFeatures::default();
        for task in [&tasks[0], &message_task] {
            assert_eq!(
                resolve_by(&mut rig, &s.phone, task, &failure("no")).1,
                busy()
            );
            assert_eq!(settled(&rig, task).0, WorkState::OutcomeUnknown);
        }
        // On: resolved, and shown resolved.
        alerts_on(&mut rig);
        for task in [&tasks[0], &message_task] {
            let (req, reply) = resolve_by(&mut rig, &s.phone, task, &failure("gave up"));
            let resolved = resolved_status(&req, reply);
            assert!(resolved.resolved.is_some());
            let body = ask(&mut rig, &s.phone, Q::Query(task)).unwrap();
            assert!(wire(&body).contains("\"resolved\":{"), "{}", wire(&body));
        }
        let progress = ask(&mut rig, &s.phone, Q::Message(&publish)).unwrap();
        assert!(matches!(progress, ResultBody::Message { .. }));
        assert!(!wire(&progress).contains("resolved"), "{}", wire(&progress));
        // Off again (a restart without the hook): the store keeps it, the
        // wire doesn't carry it.
        rig.bridge.features = HostFeatures::default();
        for task in [&tasks[0], &message_task] {
            assert!(stored_record(&rig, task).status.resolved.is_some());
            let body = ask(&mut rig, &s.phone, Q::Query(task)).unwrap();
            assert!(!wire(&body).contains("resolved"), "{}", wire(&body));
            let work = status(Ok(body));
            assert_eq!(
                (work.state, work.detail.as_str(), work.resolved),
                (WorkState::Failed, "gave up", None)
            );
            assert_eq!(
                resolve_by(&mut rig, &s.phone, task, &failure("gave up")).1,
                busy()
            );
        }
        let progress = ask(&mut rig, &s.phone, Q::Message(&publish)).unwrap();
        assert!(!wire(&progress).contains("resolved"), "{}", wire(&progress));
    });
}

/// Design I.4.6 ("Ending"), host-work-v1 §11.3: a resolution ends its
/// task's alert in the transaction that resolves it: listed before, not
/// after (its id an unknown cursor), the unresolved count down by one, its
/// row kept. A resolution whose write fails (the alert's end can't be
/// written) resolves nothing: `busy`, the task still `outcome_unknown` and
/// unresolved, its alert listed; once the write works the same request
/// resolves it. At 64 unresolved from the phone its new tasks are refused;
/// one resolved, the next is accepted.
#[test]
fn resolving_ends_the_alert() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        alerts_on(&mut rig);
        let tasks = phone_unknowns(&mut rig, &s, 64, start + HOUR);
        let (alerts, _) = page_for(&mut rig, &s.phone, None);
        let alert = alerts
            .iter()
            .find(|a| a.task_id == tasks[0])
            .unwrap()
            .alert_id
            .clone();
        let refused = phone_enqueue(&rig, "AT_SIXTY_FOUR");
        assert_eq!(ask_req(&mut rig, &s.phone, &refused), too_many());
        // Its end can't be written: nothing is resolved.
        let db = &rig.bridge.work.store.as_ref().unwrap().db;
        db.execute_batch(
            "CREATE TRIGGER no_end BEFORE UPDATE ON alerts BEGIN
                SELECT RAISE(ABORT, 'no end'); END;",
        )
        .unwrap();
        let req = resolve_req(&rig, &tasks[0], &failure("resolved by the owner"));
        assert_eq!(ask_req(&mut rig, &s.mac, &req), busy());
        assert_eq!(
            settled(&rig, &tasks[0]),
            (WorkState::OutcomeUnknown, details::AGENT_EXITED.into())
        );
        assert_eq!(stored_record(&rig, &tasks[0]).status.resolved, None);
        assert!(
            page_for(&mut rig, &s.phone, None)
                .0
                .iter()
                .any(|a| a.alert_id == alert)
        );
        let store = rig.bridge.work.store.as_ref().unwrap();
        assert_eq!(store.unresolved().unwrap().0, 64);
        store.db.execute_batch("DROP TRIGGER no_end").unwrap();
        // It works: the same request resolves it and ends its alert.
        let resolved = resolved_status(&req, ask_req(&mut rig, &s.mac, &req));
        assert_eq!(resolved.state, WorkState::Failed);
        let store = rig.bridge.work.store.as_ref().unwrap();
        assert_eq!(
            store.unresolved().unwrap(),
            (63, BTreeMap::from([(PHONE.to_string(), 63)]))
        );
        assert!(
            !page_for(&mut rig, &s.phone, None)
                .0
                .iter()
                .any(|a| a.alert_id == alert)
        );
        assert_eq!(
            list_alerts(&mut rig, &s.phone, Some(&alert)).1,
            unknown_alert()
        );
        let rows = alert_rows(&rig);
        let row = rows.iter().find(|r| r.2 == tasks[0]).unwrap();
        assert!(row.3.is_some(), "ended, kept");
        // Under 64: the phone's next task is accepted.
        let next = phone_enqueue(&rig, "UNDER_SIXTY_FOUR");
        assert!(matches!(
            ask_req(&mut rig, &s.phone, &next),
            Ok(ResultBody::Work { .. })
        ));
    });
}

/// Design I.4.6 (it "stays `outcome_unknown` until it is resolved"),
/// host-work-v1 §11.3 ("no other ending exists"): a delegated task of unknown
/// outcome past its deadline is moved by no reply, whatever its state:
/// publishing, refused or submitted, it stays `outcome_unknown` with the
/// deadline's detail (a submitted one would make it `awaiting_result`, which
/// the next pass expires, ending its alert with nobody resolving it).
#[test]
fn no_reply_moves_a_task_past_its_deadline() {
    use crate::runtime::collab::results::{Binding, Reply, ReplyState, ResultRow};
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        let task = phone_unknowns(&mut rig, &s, 1, start + HOUR).remove(0);
        os.pass(HOUR);
        passes(&mut rig, 3);
        let mut record = stored_record(&rig, &task);
        assert!(record.deadline_passed);
        let mut row = ResultRow::new(
            Reply {
                binding: Binding {
                    task_id: task.clone(),
                    session_id: rig.sid.to_string(),
                    process_gen: record.task.target.process_gen.clone(),
                    turn_id: "turn-1".into(),
                },
                text: "a reply".into(),
                references: vec![],
                context: vec![],
                dropped: false,
            },
            start,
        );
        for state in [
            ReplyState::Publishing,
            ReplyState::Refused,
            ReplyState::Submitted,
        ] {
            row.state = state;
            collab_bridge::apply_reply(&mut record, &row);
            assert_eq!(
                (record.status.state, record.status.detail.as_str()),
                (
                    WorkState::OutcomeUnknown,
                    details::DEADLINE_PASSED_OUTCOME_UNKNOWN
                ),
                "{state:?}"
            );
        }
    });
}

/// The phone's task, run, its outcome then unknown (`write interrupted`)
/// with its turn still running, and host-work's passes held: its id.
async fn unknown_in_its_turn(
    rig: &mut LocalRig,
    phone: &Authority,
    prompt: &str,
    expires_at: u64,
) -> String {
    let task = phone_task(rig, phone, prompt, expires_at);
    turn_journaled(rig, &task, prompt).await;
    hold_host_work(rig);
    make_unknown(rig, &task, details::WRITE_INTERRUPTED);
    task
}

/// Design I.4.4 ("the deadline bounds the whole task"), I.4.6, step 4's
/// clock rule (every delegated deadline is compared on `D`): the delegated
/// clock passes the deadline of the phone's task of unknown outcome while
/// the wall clock hasn't. Its agent's reply then is refused, `expired`, as
/// any reply after its task's deadline, and stores nothing: the task stays
/// `outcome_unknown`, unresolved, with the deadline's detail and its alert,
/// later passes leave it as it is, and it can still be resolved.
#[test]
fn a_reply_after_the_deadline_on_d_is_refused_and_the_task_stays_unresolved() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        alerts_on(&mut rig);
        let task = unknown_in_its_turn(&mut rig, &phone, "LATE_REPLY", start + HOUR).await;
        let unresolved = (
            WorkState::OutcomeUnknown,
            details::DEADLINE_PASSED_OUTCOME_UNKNOWN.to_string(),
        );
        // `D` reaches the deadline; the wall clock is an hour short of it.
        os.pass(HOUR);
        passes(&mut rig, 3);
        assert!(host_now().wall_ms < start + HOUR);
        assert_eq!(settled(&rig, &task), unresolved);
        let refused = reply(&mut rig, &task, "LATE_REPLY_TEXT", &[]).unwrap_err();
        assert_eq!(refused, format!("task {task} expired"));
        let store = rig.bridge.work.store.as_ref().unwrap();
        assert!(
            crate::runtime::collab::results::load(&store.db, &task)
                .unwrap()
                .is_none()
        );
        assert_eq!(settled(&rig, &task), unresolved);
        assert_eq!(stored_record(&rig, &task).status.resolved, None);
        let before = serde_json::to_value(stored_record(&rig, &task)).unwrap();
        passes(&mut rig, 3);
        assert_eq!(
            serde_json::to_value(stored_record(&rig, &task)).unwrap(),
            before
        );
        let (alerts, _) = page_for(&mut rig, &phone, None);
        assert_eq!(
            alerts
                .iter()
                .map(|a| (a.task_id.as_str(), a.reason.as_str()))
                .collect::<Vec<_>>(),
            [(task.as_str(), details::WRITE_INTERRUPTED)]
        );
        let (req, answer) = resolve_by(&mut rig, &phone, &task, &failure("too late"));
        assert_eq!(resolved_status(&req, answer).state, WorkState::Failed);
    });
}

/// PR 7 review m4 (the Task 23 re-review's Minor 1): the deadline on `D`
/// refuses a reply before any pass marks the task past it. `D` reaches the
/// deadline with no pass run (as while hosting is paused): the task isn't
/// marked yet and the wall clock is short of the deadline, yet the reply is
/// refused `expired` and nothing is stored; later passes leave the task of
/// unknown outcome. Compared on the wall clock alone, the reply would be
/// taken.
#[test]
fn a_reply_after_the_deadline_on_d_is_refused_before_any_pass_marks_it() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        alerts_on(&mut rig);
        let task = unknown_in_its_turn(&mut rig, &phone, "UNMARKED_REPLY", start + HOUR).await;
        os.pass(HOUR);
        assert!(!stored_record(&rig, &task).deadline_passed);
        assert!(host_now().wall_ms < start + HOUR);
        let refused = reply(&mut rig, &task, "UNMARKED_REPLY_TEXT", &[]).unwrap_err();
        assert_eq!(refused, format!("task {task} expired"));
        let store = rig.bridge.work.store.as_ref().unwrap();
        assert!(
            crate::runtime::collab::results::load(&store.db, &task)
                .unwrap()
                .is_none()
        );
        passes(&mut rig, 3);
        assert_eq!(settled(&rig, &task).0, WorkState::OutcomeUnknown);
    });
}

/// The same with a reply stored before the deadline that was still
/// publishing its context: its publication completes once the delegated
/// clock passed the deadline (the wall clock hasn't). The pass refuses the
/// reply, `expired before context publication`, as a reply whose task's
/// deadline passed before it was published; the reply stays stored, and the
/// task stays `outcome_unknown`, unresolved, with its alert.
#[test]
fn a_reply_publishing_past_the_deadline_on_d_is_refused_and_the_task_stays_unresolved() {
    use crate::runtime::collab::results::{self, Binding, Reply, ReplyState, ResultRow};
    use crate::runtime::collab_context::{ContextSpec, VaultRef};
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (phone, _) = delegated(&mut rig, root, &os, true);
        alerts_on(&mut rig);
        let task = unknown_in_its_turn(&mut rig, &phone, "PUBLISHING_REPLY", start + HOUR).await;
        // Stored before the deadline, publishing (as `atem message reply
        // --vault` stores one).
        let mut record = stored_record(&rig, &task);
        let row = ResultRow::new(
            Reply {
                binding: Binding {
                    task_id: task.clone(),
                    session_id: rig.sid.to_string(),
                    process_gen: record.task.target.process_gen.clone(),
                    turn_id: rig
                        .bridge
                        .collab_task_turn(&record, &rig.sessions)
                        .expect("its turn"),
                },
                text: "the reply".into(),
                references: vec![ContextSpec::Vault {
                    reference: VaultRef::parse("v-context:1@1").unwrap(),
                }],
                context: vec![],
                dropped: false,
            },
            start,
        );
        assert_eq!(row.state, ReplyState::Publishing);
        let store = rig.bridge.work.store.as_ref().unwrap();
        let tx = store.db.unchecked_transaction().unwrap();
        results::submit(&tx, &row).unwrap();
        collab_bridge::apply_reply(&mut record, &row);
        store.save_work(&record).unwrap();
        tx.commit().unwrap();
        // Its publication is done, handed over at the next pass.
        let (done, rx) = tokio::sync::oneshot::channel();
        done.send(Ok(vec![snapshot("the published context")]))
            .unwrap();
        rig.bridge
            .work
            .context_jobs
            .insert(row.result_id.clone(), rx);
        // `D` reaches the deadline; the wall clock is an hour short of it.
        os.pass(HOUR);
        passes(&mut rig, 3);
        assert!(host_now().wall_ms < start + HOUR);
        assert_eq!(
            settled(&rig, &task),
            (
                WorkState::OutcomeUnknown,
                details::DEADLINE_PASSED_OUTCOME_UNKNOWN.into()
            )
        );
        assert_eq!(stored_record(&rig, &task).status.resolved, None);
        let store = rig.bridge.work.store.as_ref().unwrap();
        let stored = results::load(&store.db, &task).unwrap().expect("stored");
        assert_eq!(
            (stored.state, stored.detail.as_str()),
            (ReplyState::Refused, results::EXPIRED)
        );
        // (Not read with `reply_query` here: its reconciliation would follow
        // the turn this rig still runs, a receipt no real unknown outcome
        // has; `reply_query` returns this row.)
        assert_eq!(stored.reply.text, "the reply");
        let (alerts, _) = page_for(&mut rig, &phone, None);
        assert_eq!(
            alerts
                .iter()
                .map(|a| a.task_id.as_str())
                .collect::<Vec<_>>(),
            [task.as_str()]
        );
        passes(&mut rig, 3);
        assert_eq!(settled(&rig, &task).0, WorkState::OutcomeUnknown);
    });
}

/// Host-work-v1 §11.2 ("checks, each time, that the caller is the task's
/// sender with current authority, or the owner"), design I.4.5 ("the
/// owner may `work_resolve` any task, including those of a revoked
/// sender"): the bot resolves one of its tasks. Once a `revoke` record
/// applies to it, the same resolution again is `forbidden` (the caller is
/// checked before the recorded status is returned), and so is resolving
/// another of its tasks, which the Mac, the owner, then resolves. With the
/// revocation gone but its grant lapsed (on the delegated clock), the bot is
/// `forbidden` again, and the phone, an owner too, resolves its last task.
#[test]
fn work_resolve_needs_current_authority_and_the_owner_resolves_a_revoked_senders_task() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        alerts_on(&mut rig);
        rig.bridge.start_view().gates = Gates::default();
        let template = bot_task(&mut rig, &s, "BOT_TEMPLATE", start + HOUR);
        let template = stored_record(&rig, &template);
        let tasks = unknown_outcomes(&rig, &template, BOT, 3);
        let stopped = failure("stopped");
        let (req, answer) = resolve_by(&mut rig, &s.bot, &tasks[0], &stopped);
        let first = resolved_status(&req, answer);
        assert_eq!(first.resolved.as_ref().unwrap().by, BOT);
        // A `revoke` record applies to the bot.
        rig.bridge
            .start_view()
            .standings
            .get_mut(BOT)
            .unwrap()
            .revoked = Some("rec-1".into());
        assert_eq!(
            resolve_by(&mut rig, &s.bot, &tasks[0], &stopped).1,
            forbidden()
        );
        assert_eq!(
            resolve_by(&mut rig, &s.bot, &tasks[1], &stopped).1,
            forbidden()
        );
        assert_eq!(settled(&rig, &tasks[1]).0, WorkState::OutcomeUnknown);
        let resolution = done_with("the owner's result", 1);
        let (req, answer) = resolve_by(&mut rig, &s.mac, &tasks[1], &resolution);
        let by_owner = resolved_status(&req, answer);
        assert_eq!(
            (
                by_owner.state,
                by_owner.resolved.as_ref().unwrap().by.as_str()
            ),
            (WorkState::Completed, "member:dev-mac")
        );
        // The revocation gone, its grant lapsed on the delegated clock.
        rig.bridge
            .start_view()
            .standings
            .get_mut(BOT)
            .unwrap()
            .revoked = None;
        os.pass(3 * HOUR + 1_000);
        passes(&mut rig, 2);
        assert_eq!(
            resolve_by(&mut rig, &s.bot, &tasks[2], &stopped).1,
            forbidden()
        );
        assert_eq!(settled(&rig, &tasks[2]).0, WorkState::OutcomeUnknown);
        let (req, answer) = resolve_by(&mut rig, &s.phone, &tasks[2], &stopped);
        let by_phone = resolved_status(&req, answer);
        assert_eq!(by_phone.resolved.as_ref().unwrap().by, PHONE);
        assert_eq!(stored_record(&rig, &tasks[0]).status, first);
    });
}

/// PR 11 (PR 7's and PR 8's requests under PR 10's ruling T20c, Task 32
/// review m1): an unresolved unknown outcome's record closes a day after
/// its deadline, alert kept, so a start doesn't register its launch
/// project. Like `work_query`, the bot's `work_interrupt` and `work_resolve`
/// of it register that project when they ask: while its hash under the
/// grant's new kid isn't made the bot is `busy`, never a `forbidden` that
/// would stand, and then answered (`not running`; resolved `failed`).
#[test]
fn a_resolve_or_interrupt_whose_tasks_project_isnt_hashed_yet_is_busy_until_it_is() {
    const KID_A: &str = "0e0f0a1a";
    const PROJECT_A: &str =
        "h1.0e0f0a1a.6666666666666666666666666666666666666666666666666666666666666666";
    const KID_B: &str = "0e0f0a1b";
    const PROJECT_B: &str =
        "h1.0e0f0a1b.7777777777777777777777777777777777777777777777777777777777777777";
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let agent = TableAgent::new(true);
        let mut s =
            with_project_bot(&mut rig, root, &os, start + 3 * HOUR, &[PROJECT], &agent).await;
        rig.bridge.start_view().gates = Gates::default();
        let template = bot_task(&mut rig, &s, "PROJECTS_UNKNOWN", start + HOUR);
        let template = stored_record(&rig, &template);
        let [unknown] = unknown_outcomes(&rig, &template, BOT, 1)
            .try_into()
            .unwrap();
        let session = rig.sessions.remove(&rig.sid).unwrap();
        let _ = session.stop();
        let bot = s.bot.clone();
        // As a start finds it once its record closed: its project not
        // registered, its session gone; the grant re-issued under a kid its
        // admission didn't see.
        let regrant = |rig: &mut LocalRig, s: &mut Senders, kid: &str, project: &str| {
            rig.bridge
                .projects
                .forget(&crate::runtime::project_scope::task_project_key(
                    RIG_PROJECT,
                ));
            agent
                .table
                .lock()
                .unwrap()
                .insert((RIG_PROJECT.into(), kid.into()), project.into());
            let change = s.log.set_service(
                "svc-bot",
                &ServiceScope::new(["host"]).projects(Some([project])).ops([
                    "interrupt",
                    "message",
                    "notify",
                    "prompt",
                    "stop",
                ]),
                start + 3 * HOUR,
            );
            carry(rig, &s.log, change);
        };
        let until_answered =
            async |rig: &mut LocalRig,
                   ask: &dyn Fn(&mut LocalRig) -> Result<ResultBody, HostWorkError>| {
                let deadline = Instant::now() + Duration::from_secs(60);
                let mut asked = ask(rig);
                assert_eq!(asked, busy(), "not yet hashed");
                while asked.is_err() && Instant::now() < deadline {
                    assert_eq!(asked, busy(), "busy until hashed, never forbidden");
                    passes(rig, 1);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    asked = ask(rig);
                }
                asked
            };
        passes(&mut rig, 3);
        regrant(&mut rig, &mut s, KID_A, PROJECT_A);
        let interrupted = until_answered(&mut rig, &|rig: &mut LocalRig| {
            ask(rig, &bot, Q::Interrupt(&unknown))
        })
        .await;
        let interrupted = status(interrupted);
        assert_eq!(
            (interrupted.state, interrupted.detail.as_str()),
            (WorkState::OutcomeUnknown, "not running")
        );
        regrant(&mut rig, &mut s, KID_B, PROJECT_B);
        let resolved = until_answered(&mut rig, &|rig: &mut LocalRig| {
            resolve_by(rig, &bot, &unknown, &failure("given up")).1
        })
        .await;
        assert_eq!(status(resolved).state, WorkState::Failed);
    });
}

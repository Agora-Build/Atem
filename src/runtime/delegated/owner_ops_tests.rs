// The owner's channel ops on a host sender's selector task (host-work-v1
// §11.2, §11.5; design I.4.5; Astation's asks, #120 comments 7028723996 and
// 7082465179, the second for `reply_query`), in the bridge: the receiving
// host of the admission tests (`sp_host`: host B with an encryption key,
// project `build` granting a task's ops, route `rh` consenting to
// `project:build`), B's `select` admitted through the mailbox into a task
// whose id is the selector's UUID v5, and the phone (a native member
// holding `control`: the owner) asking over its channel.
// Every other caller, and every v5 id that names no host sender's selector
// task, is answered exactly as a missing task is. Every name here starts
// with `oo_`.

/// B's request to this host's agents (`atem:host`, one agent), its text
/// `text`, admitted: the message and its one task's id (the selector's).
fn oo_admitted(rig: &mut LocalRig, host: &mut MbHost, text: &str) -> (Message, String) {
    let mut message = ad_message(rig, vec![ad_select(&["atem:host"], 1)]);
    message.text = text.into();
    let object = ad_request(rig, host, &message);
    ad_deliver(rig, host, &[object]);
    ad_admit(rig);
    let tasks = ad_tasks(rig, &message);
    assert_eq!(tasks.len(), 1);
    let task = tasks[0].task.task_id.clone();
    assert_eq!(
        task,
        atem_client::session::select::selector_task_id(
            &message.message_id,
            &message.recipients[0].recipient_id,
            rig.sid.as_str()
        )
    );
    assert!(atem_client::session::wire::is_uuid_v5(&task));
    (message, task)
}

/// `who` sends `req` as its channel hands it to the bridge: the bytes it
/// sends read first by the shared core's strict reader (what the r9 engine
/// decodes before queueing a host-work request).
fn oo_ask(
    rig: &mut LocalRig,
    who: &Authority,
    req: &hw::Request,
) -> Result<ResultBody, HostWorkError> {
    let read = hw::Request::decode(req.to_json().to_string().as_bytes())
        .unwrap_or_else(|code| panic!("{code}: {req:?}"));
    ask_req(rig, who, &read)
}

/// `who` asks `q`, through [`oo_ask`].
fn oo_q(rig: &mut LocalRig, who: &Authority, q: Q<'_>) -> Result<ResultBody, HostWorkError> {
    let req = q.request(rig.bridge.work_host());
    oo_ask(rig, who, &req)
}

/// `who`'s `work_resolve` of `task` as `failed{detail}`.
fn oo_resolve(
    rig: &mut LocalRig,
    who: &Authority,
    task: &str,
    detail: &str,
) -> (hw::Request, Result<ResultBody, HostWorkError>) {
    let req = hw::Request::WorkResolve {
        v: 1,
        id: uuid::Uuid::new_v4().to_string(),
        host: rig.bridge.work_host(),
        task_id: task.into(),
        resolution: hw::Resolution::Failed {
            detail: detail.into(),
        },
    };
    let reply = oo_ask(rig, who, &req);
    (req, reply)
}

/// `reply`, the answer to `req`, read back by the client core's strict
/// reader as a channel reads it: the status it carries (it answers `req`).
fn oo_read(req: &hw::Request, reply: Result<ResultBody, HostWorkError>) -> WorkStatus {
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

/// The host's list as these tests extend it: the viewer (`view` only), a
/// service on this host (a task's ops) and a browser grant of the Mac's for
/// this host, each carried to the host (the grant needs none), and the Mac.
struct OoCallers {
    mac: Authority,
    viewer: Authority,
    service: Authority,
    browser: Authority,
}

fn oo_callers(rig: &mut LocalRig, host: &mut MbHost) -> OoCallers {
    use crate::session_protocol::membership::r9log::host_now as now;
    use atem_client::channel::Principal;
    let expiry = host_now().wall_ms + 3 * HOUR;
    let entry = host.s.log.add_native("dev-viewer", &["view"]);
    carry(rig, &host.s.log, entry);
    let entry = host.s.log.add_service(
        "svc-oo",
        &["host"],
        None,
        &["message", "notify", "prompt", "view"],
        expiry,
    );
    carry(rig, &host.s.log, entry);
    let (grant, _) = host.s.log.grant(
        MAC,
        "aaaaaaaa-1111-4111-8111-0000000000aa",
        "host",
        1,
        None,
        &["notify", "prompt", "view"],
        host_now().wall_ms - 1_000,
        host_now().wall_ms + HOUR - 60_000,
    );
    let browser = Authority::resolve(
        &host.s.log.log,
        &Principal::browser(&grant).unwrap(),
        Some(&grant),
        "host",
        1,
        &now(),
        &|_| false,
    )
    .unwrap();
    let native = |id: &str| Principal::Native {
        device_id: id.into(),
    };
    OoCallers {
        mac: resolve(&host.s.log, native(MAC)),
        viewer: resolve(&host.s.log, native("dev-viewer")),
        service: resolve(
            &host.s.log,
            Principal::Service {
                device_id: "svc-oo".into(),
            },
        ),
        browser,
    }
}

/// A control state that reads (standing in for the host's feeds): no
/// sender covered or revoked.
struct OoChecked;

impl crate::runtime::delegated::ControlView for OoChecked {
    fn standing(&self, _: &str) -> SenderStanding {
        SenderStanding::default()
    }
}

/// What every owner's request naming a task (`work_query`, `reply_query`,
/// `work_interrupt`, `work_resolve`) of `who` naming `task` is answered
/// with.
fn oo_answers(
    rig: &mut LocalRig,
    who: &Authority,
    task: &str,
) -> Vec<Result<ResultBody, HostWorkError>> {
    vec![
        oo_q(rig, who, Q::Query(task)),
        oo_q(rig, who, Q::Reply(task)),
        oo_q(rig, who, Q::Interrupt(task)),
        oo_resolve(rig, who, task, "agent exited").1,
    ]
}

/// The owner (the phone, a native member holding `control`) queries a host
/// sender's selector task over its channel, and resolves it once its
/// outcome is unknown: `failed` with the detail, `resolved{by, at}` its own
/// principal, the alert ended, durable before the answer; the same
/// resolution again returns the recorded status, another is
/// `request_id_reused`; `work_query` then shows the resolver. Each answer is
/// read by the client core's strict reader as the answer to its request (a
/// UUID v5 task id). The status owed to B shows the task `failed`.
#[test]
fn the_owner_queries_and_resolves_a_host_senders_selector_task() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let (message, task) = oo_admitted(&mut rig, &mut host, "OO_RESOLVE");
        let owner = host.s.phone.clone();
        let req = Q::Query(&task).request(rig.bridge.work_host());
        let queued = oo_read(&req, oo_ask(&mut rig, &owner, &req));
        assert_eq!(queued, stored_record(&rig, &task).status);
        assert_eq!(queued.state, WorkState::Queued);
        // Not of unknown outcome: `forbidden`, as for any delegated task.
        assert_eq!(oo_resolve(&mut rig, &owner, &task, "x").1, forbidden());
        let record = stored_record(&rig, &task);
        ad_set_state(&rig, &record, WorkState::OutcomeUnknown);
        assert_eq!(
            rig.bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .unresolved()
                .unwrap()
                .0,
            1,
            "its alert"
        );
        let (req, reply) = oo_resolve(&mut rig, &owner, &task, "agent exited");
        let resolved = oo_read(&req, reply);
        assert_eq!(
            (resolved.state, resolved.detail.as_str()),
            (WorkState::Failed, "agent exited")
        );
        assert_eq!(resolved.resolved.as_ref().unwrap().by, PHONE);
        assert_eq!(stored_record(&rig, &task).status, resolved, "durable");
        assert_eq!(
            rig.bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .unresolved()
                .unwrap()
                .0,
            0,
            "its alert ended"
        );
        // The same resolution, from another owner (the Mac): the recorded
        // status, the first resolver kept; another: `request_id_reused`.
        let callers = oo_callers(&mut rig, &mut host);
        let (req, reply) = oo_resolve(&mut rig, &callers.mac, &task, "agent exited");
        assert_eq!(oo_read(&req, reply), resolved);
        assert_eq!(
            oo_resolve(&mut rig, &owner, &task, "another reason").1,
            Err("request_id_reused".into())
        );
        let req = Q::Query(&task).request(rig.bridge.work_host());
        assert_eq!(oo_read(&req, oo_ask(&mut rig, &owner, &req)), resolved);
        // B's status of the message shows the task failed.
        rig.bridge.mail_statuses();
        let receipts = ad_receipts(&rig, &message);
        let progress = &ad_resolved(&receipts[0])[0];
        assert_eq!(
            (progress.task_id.as_str(), progress.state),
            (task.as_str(), WorkState::Failed)
        );
    });
}

/// The owner interrupts a host sender's selector task's running turn over
/// its channel, as §11.2 says: before its dispatch the answer is the
/// status with `not running` (nothing written or stored); in its turn the
/// answer is the status as it stood, one Esc is written at once on the
/// host's authority (no intent), and the turn ends interrupted, the task
/// awaiting its result (`turn interrupted`).
#[test]
fn the_owner_interrupts_a_host_senders_selector_task() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let (_, task) = oo_admitted(&mut rig, &mut host, "OO_INTERRUPT");
        let owner = host.s.phone.clone();
        let before = stored_record(&rig, &task).status;
        let req = Q::Interrupt(&task).request(rig.bridge.work_host());
        let idle = oo_read(&req, oo_ask(&mut rig, &owner, &req));
        assert_eq!(idle.detail, details::NOT_RUNNING);
        assert_eq!(stored_record(&rig, &task).status, before, "nothing stored");
        // Host senders' gate open for the start (this rig's passes keep no
        // Station link).
        rig.bridge.start_view().gates.set_mailbox(true);
        turn_journaled(&mut rig, &task, "OO_INTERRUPT").await;
        let attempt = stored_record(&rig, &task).status.receipt_id;
        let running = stored_record(&rig, &task).status;
        let req = Q::Interrupt(&task).request(rig.bridge.work_host());
        assert_eq!(oo_read(&req, oo_ask(&mut rig, &owner, &req)), running);
        assert!(pending_write(&rig, &attempt).is_some(), "written at once");
        settle(&mut rig).await;
        rig.until(|r| escs(r) == 1).await;
        assert!(intents(&rig, &task).is_empty(), "no intent");
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

/// No disclosure (Astation's asks): a host sender's selector task is
/// answered to every caller but the owner exactly as a task the host
/// doesn't have (the same code, no detail, nothing read or changed), for
/// each of the owner's ops, `reply_query` included: a native member
/// without `control`, a service, a browser grant. And to the owner too, a
/// UUID v5 that names no task, one that names a task whose recorded
/// provenance isn't a host sender's selector task (the phone's own task, a
/// `local` one, or B's task under an id its message doesn't derive). A
/// UUID v4 behaves as before: B's v4 task (a `work_enqueue`'s shape) is the
/// owner's to query, read the reply of, interrupt and resolve, and nobody
/// else's.
#[test]
fn every_other_caller_and_id_is_answered_as_a_missing_task() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut host = sp_host(&mut rig, root, &os);
        let (message, task) = oo_admitted(&mut rig, &mut host, "OO_HIDDEN");
        let record = stored_record(&rig, &task);
        ad_set_state(&rig, &record, WorkState::OutcomeUnknown);
        let record = stored_record(&rig, &task);
        let callers = oo_callers(&mut rig, &mut host);
        let owner = host.s.phone.clone();
        let missing = uuid::Uuid::new_v4().to_string();
        // While this host's control state isn't read, a service is `busy`
        // whatever it names (ruling T32b): the missing task's answer too.
        // Once it reads, `forbidden`, as a missing task is.
        for checked in [false, true] {
            if checked {
                rig.bridge.work.controls = Some(Box::new(OoChecked));
            }
            for (name, who) in [
                ("viewer", &callers.viewer),
                ("service", &callers.service),
                ("browser", &callers.browser),
            ] {
                let absent = oo_answers(&mut rig, who, &missing);
                if checked || name != "service" {
                    assert!(
                        absent.iter().all(|a| *a == forbidden()),
                        "{name}: {absent:?}"
                    );
                } else {
                    assert!(absent.iter().all(|a| *a == busy()), "{absent:?}");
                }
                assert_eq!(oo_answers(&mut rig, who, &task), absent, "{name}");
            }
        }
        // The owner, naming a UUID v5 of no task.
        let nothing = atem_client::session::select::selector_task_id(
            &uuid::Uuid::new_v4().to_string(),
            &uuid::Uuid::new_v4().to_string(),
            rig.sid.as_str(),
        );
        assert_eq!(oo_answers(&mut rig, &owner, &nothing), vec![forbidden(); 4]);
        // The owner, naming a UUID v5 task whose recorded provenance isn't
        // a host sender's selector task: the phone's own v1 task (not
        // delegated), its own delegated task (queued), the runtime's
        // `local` task, and B's task under an id its message doesn't derive
        // (another recipient's), the others of unknown outcome.
        let store = rig.bridge.work.store.as_ref().unwrap();
        let mut copies = Vec::new();
        for kind in ["member", "delegated member", "local", "underived"] {
            let mut r = record.clone();
            let id = atem_client::session::select::selector_task_id(
                &message.message_id,
                &uuid::Uuid::new_v4().to_string(),
                rig.sid.as_str(),
            );
            r.task.task_id = id.clone();
            r.status.task_id = id.clone();
            r.status.state = WorkState::Queued;
            match kind {
                "member" => {
                    r.principal = PHONE.into();
                    r.delegated = None;
                }
                "delegated member" => {
                    r.principal = PHONE.into();
                    let admission = r.delegated.as_mut().unwrap();
                    admission.principal = PHONE.into();
                    admission.sender = DelegatedSender::Native {
                        device_id: "dev-phone".into(),
                    };
                    admission.host = None;
                }
                "local" => {
                    r.principal = "local".into();
                    r.delegated = None;
                    r.message = None;
                }
                _ => {}
            }
            assert!(store.enqueue(&r).unwrap());
            // Of unknown outcome, but the delegated native's: the store
            // raises no alert for a member's task under a UUID v5 (its
            // alert couldn't be read), so it stays queued.
            if kind != "delegated member" {
                r.status.state = WorkState::OutcomeUnknown;
                store.save_work(&r).unwrap();
            }
            copies.push((kind, id));
        }
        for (kind, id) in &copies {
            let before = stored_record(&rig, id).status;
            assert_eq!(
                oo_answers(&mut rig, &owner, id),
                vec![forbidden(); 4],
                "{kind}"
            );
            assert_eq!(stored_record(&rig, id).status, before, "{kind}");
        }
        // Nothing of the hidden task changed for any of them.
        assert_eq!(stored_record(&rig, &task).status, record.status);
        assert_eq!(escs(&rig), 0);

        // The v4 path as before: B's task with a UUID v4 (a `work_enqueue`
        // task's id, rewritten as B's) is the owner's, and nobody else's.
        let v4 = host_task(&mut rig, &host.s, "OO_V4", start + HOUR);
        assert!(atem_client::session::wire::is_uuid_v4(&v4));
        assert_eq!(
            status(oo_q(&mut rig, &owner, Q::Query(&v4))),
            stored_record(&rig, &v4).status
        );
        assert_eq!(
            oo_q(&mut rig, &owner, Q::Reply(&v4)),
            Ok(ResultBody::Reply { reply: None })
        );
        for who in [&callers.viewer, &callers.service, &callers.browser] {
            assert_eq!(oo_answers(&mut rig, who, &v4), vec![forbidden(); 4]);
        }
        let v4_record = stored_record(&rig, &v4);
        ad_set_state(&rig, &v4_record, WorkState::OutcomeUnknown);
        let (req, reply) = oo_resolve(&mut rig, &callers.mac, &v4, "stopped");
        let resolved = oo_read(&req, reply);
        assert_eq!(
            (resolved.state, resolved.resolved.unwrap().by.as_str()),
            (WorkState::Failed, "member:dev-mac")
        );
        // And the hidden task is still the owner's.
        let (req, reply) = oo_resolve(&mut rig, &owner, &task, "agent exited");
        assert_eq!(oo_read(&req, reply).state, WorkState::Failed);
    });
}

/// Review L2: each condition of the provenance gate (`host_selector_task`)
/// on its own. B's selector task copied under a message of its own, stored
/// as admission stores one (its id derived from that message, its recipient
/// and the session, its receipt listing it): served to the owner. Then one
/// condition broken at a time, everything else as in that copy: the
/// admission's sender kind (a native's, the principals still B's), the
/// record's principal, the stored message's sender, its receipt's sender,
/// the recipient's host (this host at another trust generation), the
/// recipient's destination (a host notice, not a `select`), and a receipt
/// that doesn't list the task. Each is answered as a missing task, for all
/// four of the owner's ops, and nothing of it changes.
#[test]
fn the_gate_checks_each_condition_of_a_host_senders_selector_task() {
    use atem_client::session::messages::{Delivery, Destination};
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let (message, task) = oo_admitted(&mut rig, &mut host, "OO_GATE");
        let record = stored_record(&rig, &task);
        let stored = rig
            .bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .message(&message.message_id)
            .unwrap()
            .unwrap();
        let owner = host.s.phone.clone();
        let sid = rig.sid.as_str().to_owned();
        // A copy of B's task under a message of its own, `broken` applied
        // to its record and message as stored: its id.
        let copy =
            |rig: &mut LocalRig,
             broken: &dyn Fn(&mut WorkRecord, &mut crate::runtime::host_work::MessageRecord)|
             -> String {
                let mut m = stored.clone();
                let message_id = uuid::Uuid::new_v4().to_string();
                m.message.message_id = message_id.clone();
                m.receipt.message_id = message_id.clone();
                let recipient = m.message.recipients[0].recipient_id.clone();
                let id =
                    atem_client::session::select::selector_task_id(&message_id, &recipient, &sid);
                let mut r = record.clone();
                r.task.task_id = id.clone();
                r.status.task_id = id.clone();
                r.status.state = WorkState::Queued;
                r.message.as_mut().unwrap().message_id = message_id.clone();
                m.receipt.recipients[0].delivery = Delivery::Resolved {
                    tasks: vec![(&r.status).into()],
                };
                broken(&mut r, &mut m);
                let store = rig.bridge.work.store.as_ref().unwrap();
                store
                    .db
                    .execute(
                        "INSERT INTO messages(id,record) VALUES(?1,?2)",
                        rusqlite::params![message_id, serde_json::to_string(&m).unwrap()],
                    )
                    .unwrap();
                assert!(store.enqueue(&r).unwrap());
                id
            };
        // The construction is right: the copy itself is the owner's.
        let whole = copy(&mut rig, &|_, _| {});
        assert_eq!(
            status(oo_q(&mut rig, &owner, Q::Query(&whole))),
            stored_record(&rig, &whole).status
        );
        assert_eq!(
            oo_q(&mut rig, &owner, Q::Reply(&whole)),
            Ok(ResultBody::Reply { reply: None })
        );
        type Break<'a> =
            Box<dyn Fn(&mut WorkRecord, &mut crate::runtime::host_work::MessageRecord) + 'a>;
        let cases: Vec<(&str, Break<'_>)> = vec![
            (
                "the admission's sender is a native's",
                Box::new(|r, _| {
                    r.delegated.as_mut().unwrap().sender = DelegatedSender::Native {
                        device_id: "dev-phone".into(),
                    }
                }),
            ),
            (
                "the record's principal is another host's",
                Box::new(|r, _| r.principal = "host:host-x".into()),
            ),
            (
                "the admission's principal is another host's",
                Box::new(|r, _| r.delegated.as_mut().unwrap().principal = "host:host-x".into()),
            ),
            (
                "the stored message's sender is another host",
                Box::new(|_, m| m.message.sender = "host:host-x".into()),
            ),
            (
                "the stored receipt's sender is another host",
                Box::new(|_, m| m.receipt.sender = "host:host-x".into()),
            ),
            (
                "the recipient is this host at another trust generation",
                Box::new(|_, m| m.message.recipients[0].host.host_trust_gen = 2),
            ),
            (
                "the recipient is a host notice, not a select",
                Box::new(|_, m| m.message.recipients[0].destination = Destination::Host),
            ),
            (
                "the receipt doesn't list the task",
                Box::new(|_, m| {
                    m.receipt.recipients[0].delivery = Delivery::Resolved {
                        tasks: vec![(&record.status).into()],
                    }
                }),
            ),
        ];
        for (what, broken) in &cases {
            let id = copy(&mut rig, broken.as_ref());
            let before = stored_record(&rig, &id).status;
            assert_eq!(
                oo_answers(&mut rig, &owner, &id),
                vec![forbidden(); 4],
                "{what}"
            );
            assert_eq!(stored_record(&rig, &id).status, before, "{what}");
        }
        assert_eq!(escs(&rig), 0);
    });
}

/// `reply`, the answer to the `reply_query` `req`, read back by the client
/// core's strict reader as a channel reads it: the reply it carries (it
/// answers `req`: no reply yet, or one with the asked task's `result_id`).
fn oo_reply_read(
    req: &hw::Request,
    reply: Result<ResultBody, HostWorkError>,
) -> Option<atem_client::session::host_work::ResultReply> {
    let body = reply.expect("a reply result");
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
    match body {
        ResultBody::Reply { reply } => reply,
        other => panic!("a reply result: {other:?}"),
    }
}

/// `who`'s `reply_query` of `task`, through [`oo_ask`], read back.
fn oo_reply(
    rig: &mut LocalRig,
    who: &Authority,
    task: &str,
) -> Option<atem_client::session::host_work::ResultReply> {
    let req = Q::Reply(task).request(rig.bridge.work_host());
    let reply = oo_ask(rig, who, &req);
    oo_reply_read(&req, reply)
}

/// Every row of every table of the host-work store, each table's rows
/// sorted: what a request that only reads leaves exactly as it was.
fn oo_store(rig: &LocalRig) -> std::collections::BTreeMap<String, Vec<String>> {
    let db = &rig.bridge.work.store.as_ref().unwrap().db;
    let tables: Vec<String> = db
        .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    tables
        .into_iter()
        .map(|table| {
            let mut q = db.prepare(&format!("SELECT * FROM \"{table}\"")).unwrap();
            let columns = q.column_count();
            let mut rows: Vec<String> = q
                .query_map([], |r| {
                    (0..columns)
                        .map(|i| r.get::<_, rusqlite::types::Value>(i))
                        .collect::<rusqlite::Result<Vec<_>>>()
                        .map(|row| format!("{row:?}"))
                })
                .unwrap()
                .map(Result::unwrap)
                .collect();
            rows.sort();
            (table, rows)
        })
        .collect()
}

/// Astation's ask (#120 comment 7082465179; host-work-v1 §11.2): the owner
/// (the phone, a native member holding `control`) reads a host sender's
/// selector task's reply over its channel with `reply_query`, naming its
/// UUID v5, in each state the reply goes through on this host: none yet
/// (`null`); `publishing` (its vault context being published: no context,
/// no time); `refused` (that publication refused); `submitted` (the agent's
/// corrected reply, through `atem message reply`'s path); and once the task
/// settled and its 30 days passed, `dropped` (no text, no context, the same
/// digest). Each answer is the reply as the store holds it (`row.wire()`),
/// its `result_id` the selector task's own, read by the client core's
/// strict reader as the answer to its request.
///
/// It is a read: after each query (twice, the owner and the Mac, both
/// owners) every row of the host-work store is as it was: the task, its
/// reply, the status and result owed to B, the outbox. And the phone's
/// `reply_query` naming a UUID v5 of no task, or B's task under an id its
/// message doesn't derive, is answered as a missing task.
#[test]
fn the_owner_reads_a_host_senders_selector_tasks_reply() {
    use crate::runtime::collab::results::{self, Binding, Reply, ResultRow};
    use atem_client::session::host_work::ReplyState;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let (message, task) = oo_admitted(&mut rig, &mut host, "OO_REPLY");
        // Its turn ended, its turn known: the agent may reply.
        let mut record = stored_record(&rig, &task);
        record.status.state = WorkState::AwaitingResult;
        record.turn_id = Some("turn-1".into());
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .save_work(&record)
            .unwrap();
        rig.bridge.mail_statuses();
        let owner = host.s.phone.clone();
        let callers = oo_callers(&mut rig, &mut host);
        // Each owner reads `expected`; the store is as it was after both.
        let reads = |rig: &mut LocalRig, expected: Option<&ResultRow>| {
            let before = oo_store(rig);
            assert!(["work", "messages"].iter().all(|t| !before[*t].is_empty()));
            assert_eq!(before["results"].is_empty(), expected.is_none());
            for who in [&owner, &callers.mac] {
                let read = oo_reply(rig, who, &task);
                assert_eq!(read, expected.map(ResultRow::wire));
                if let Some(reply) = &read {
                    assert_eq!(reply.result_id, hw::result_id(&task));
                }
            }
            assert_eq!(oo_store(rig), before, "a read changes nothing");
        };
        let row = |rig: &LocalRig| {
            results::load(&rig.bridge.work.store.as_ref().unwrap().db, &task)
                .unwrap()
                .unwrap()
        };

        // No reply yet.
        reads(&mut rig, None);
        // Publishing: a reply naming a vault entry, its context not yet
        // published.
        let publishing = ResultRow::new(
            Reply {
                binding: Binding {
                    task_id: task.clone(),
                    session_id: rig.sid.to_string(),
                    process_gen: record.task.target.process_gen.clone(),
                    turn_id: "turn-1".into(),
                },
                text: "OO_WITH_A_VAULT_ENTRY".into(),
                references: vec![crate::runtime::collab_context::ContextSpec::Vault {
                    reference: crate::runtime::collab_context::VaultRef::parse("v-oo:1@2").unwrap(),
                }],
                context: vec![],
                dropped: false,
            },
            host_now().wall_ms,
        );
        let store = rig.bridge.work.store.as_ref().unwrap();
        let tx = store.db.unchecked_transaction().unwrap();
        results::submit(&tx, &publishing).unwrap();
        tx.commit().unwrap();
        rig.bridge.mail_statuses();
        let current = row(&rig);
        assert_eq!(current.state, ReplyState::Publishing);
        reads(&mut rig, Some(&current));
        // Refused: its publication refused for good.
        let store = rig.bridge.work.store.as_ref().unwrap();
        results::refuse(
            &store.db,
            &task,
            crate::runtime::collab_context::VAULT_CREDENTIAL,
        )
        .unwrap();
        rig.bridge.mail_statuses();
        let current = row(&rig);
        assert_eq!(current.state, ReplyState::Refused);
        reads(&mut rig, Some(&current));
        // Submitted: the agent's corrected reply, and its result owed to B,
        // sealed once.
        reply(&mut rig, &task, "OO_CORRECTED", &[]).unwrap();
        rig.bridge.mail_statuses();
        let current = row(&rig);
        assert_eq!(
            (current.state, current.reply.text.as_str()),
            (ReplyState::Submitted, "OO_CORRECTED")
        );
        reads(&mut rig, Some(&current));
        // Dropped: the task settled (`failed`), past its deadline a day,
        // then 30 days on: the reply's text and context go, its digest
        // stays.
        let store = rig.bridge.work.store.as_ref().unwrap();
        let settled = stored_record(&rig, &task);
        ad_set_state(&rig, &settled, WorkState::Failed);
        let after = settled.task.expires_at + crate::runtime::host_work::PAYLOAD_RETENTION_MS + 1;
        assert_eq!(store.drop_payloads(after).unwrap().tasks, 1);
        let kept = store
            .drop_kept_replies(
                host_now().wall_ms + crate::runtime::host_work::KEPT_REPLY_MS + 1,
                crate::runtime::host_work::KEPT_REPLY_BUDGET,
            )
            .unwrap();
        assert_eq!(kept.expired, 1);
        rig.bridge.mail_statuses();
        let current = row(&rig);
        assert!(current.reply.dropped && current.reply.text.is_empty());
        let dropped = current.wire();
        assert_eq!(
            (dropped.state, dropped.digest.as_str(), dropped.dropped),
            (ReplyState::Submitted, current.digest.as_str(), true)
        );
        reads(&mut rig, Some(&current));

        // Still a missing task's answer for a UUID v5 of no task, or B's
        // task under an id its message doesn't derive.
        let nothing = atem_client::session::select::selector_task_id(
            &uuid::Uuid::new_v4().to_string(),
            &uuid::Uuid::new_v4().to_string(),
            rig.sid.as_str(),
        );
        assert_eq!(oo_q(&mut rig, &owner, Q::Reply(&nothing)), forbidden());
        let underived = atem_client::session::select::selector_task_id(
            &message.message_id,
            &uuid::Uuid::new_v4().to_string(),
            rig.sid.as_str(),
        );
        let mut copy = stored_record(&rig, &task);
        copy.task.task_id = underived.clone();
        copy.status.task_id = underived.clone();
        assert!(
            rig.bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .enqueue(&copy)
                .unwrap()
        );
        assert_eq!(oo_q(&mut rig, &owner, Q::Reply(&underived)), forbidden());
    });
}

/// Review L1 (Astation's "a read, not `work_complete`, cancellation or
/// authority to resend"): the owner's `reply_query` of a host sender's
/// selector task of unknown outcome writes nothing. The task's agent exits
/// in its turn: its receipt ends `outcome_unknown` (`agent exited`), the
/// task becomes so with its alert raised and its status owed to B (sealed
/// by the status pass). Then, in each standing such a task has, the phone
/// and the Mac (both owners) read it, and nothing is written: no row of the
/// host-work store is written at all (not even rewritten as it was: the
/// task's record is read, reconciled from its receipt and found unchanged),
/// and every row reads as before, the task's state, detail and alert, no
/// status or result owed or put to B, also after a status pass. The
/// standings: no reply; a reply whose publication was refused (as the host
/// refuses one: its row, then the task written with it); and past the
/// task's deadline on the delegated clock (`deadline passed; outcome
/// unknown`), the refused reply still there.
#[test]
fn the_owners_reply_query_of_an_unknown_outcome_writes_nothing() {
    use crate::runtime::collab::results::{self, Binding, Reply, ResultRow};
    use atem_client::session::host_work::ReplyState;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let (message, task) = oo_admitted(&mut rig, &mut host, "OO_UNKNOWN");
        rig.bridge.start_view().gates.set_mailbox(true);
        turn_journaled(&mut rig, &task, "OO_UNKNOWN").await;
        // Its agent exits in its turn.
        std::fs::write(rig.fake.join("exit"), "").unwrap();
        rig.until(|r| settled(r, &task).0 == WorkState::OutcomeUnknown)
            .await;
        passes(&mut rig, 3);
        assert_eq!(
            settled(&rig, &task),
            (WorkState::OutcomeUnknown, details::AGENT_EXITED.into())
        );
        let unresolved = |rig: &LocalRig| {
            rig.bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .unresolved()
                .unwrap()
                .0
        };
        assert_eq!(unresolved(&rig), 1, "its alert");
        let owner = host.s.phone.clone();
        let callers = oo_callers(&mut rig, &mut host);
        count_writes(&rig);
        let owed = |rig: &LocalRig, table: &str| -> i64 {
            rig.bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .db
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                .unwrap()
        };
        // Each owner reads `expected`: nothing written, nothing changed.
        let reads = |rig: &mut LocalRig, expected: Option<&ResultRow>, standing: &str| {
            rig.bridge.mail_statuses();
            assert_eq!(owed(rig, "mail_status_owed"), 0, "{standing}");
            assert_eq!(owed(rig, "mail_result_owed"), 0, "{standing}");
            let before = oo_store(rig);
            let record = stored_record(rig, &task);
            let alerts = unresolved(rig);
            let written = writes(rig, "work") + writes(rig, "results");
            for who in [&owner, &callers.mac] {
                assert_eq!(
                    oo_reply(rig, who, &task),
                    expected.map(ResultRow::wire),
                    "{standing}"
                );
            }
            assert_eq!(
                writes(rig, "work") + writes(rig, "results"),
                written,
                "{standing}: no write"
            );
            assert_eq!(oo_store(rig), before, "{standing}: every row as it was");
            let after = stored_record(rig, &task);
            assert_eq!(
                serde_json::to_string(&after).unwrap(),
                serde_json::to_string(&record).unwrap(),
                "{standing}"
            );
            assert_eq!(after.status.state, WorkState::OutcomeUnknown, "{standing}");
            assert_eq!(unresolved(rig), alerts, "{standing}: its alert");
            assert_eq!(owed(rig, "mail_status_owed"), 0, "{standing}");
            assert_eq!(owed(rig, "mail_result_owed"), 0, "{standing}");
            // Nothing owed shows after a status pass either.
            rig.bridge.mail_statuses();
            assert_eq!(oo_store(rig), before, "{standing}: after a status pass");
        };

        reads(&mut rig, None, "no reply");

        // A reply whose publication was refused, as the host records one.
        let record = stored_record(&rig, &task);
        let publishing = ResultRow::new(
            Reply {
                binding: Binding {
                    task_id: task.clone(),
                    session_id: rig.sid.to_string(),
                    process_gen: record.task.target.process_gen.clone(),
                    turn_id: record.turn_id.clone().expect("its turn"),
                },
                text: "OO_UNKNOWN_REPLY".into(),
                references: vec![crate::runtime::collab_context::ContextSpec::Vault {
                    reference: crate::runtime::collab_context::VaultRef::parse("v-oo:1@2").unwrap(),
                }],
                context: vec![],
                dropped: false,
            },
            host_now().wall_ms,
        );
        let store = rig.bridge.work.store.as_ref().unwrap();
        let tx = store.db.unchecked_transaction().unwrap();
        results::submit(&tx, &publishing).unwrap();
        results::refuse(&tx, &task, crate::runtime::collab_context::VAULT_CREDENTIAL).unwrap();
        let refused = results::load(&tx, &task).unwrap().unwrap();
        let mut record = stored_record(&rig, &task);
        collab_bridge::apply_reply(&mut record, &refused);
        store.save_work(&record).unwrap();
        tx.commit().unwrap();
        assert_eq!(refused.state, ReplyState::Refused);
        assert_eq!(
            settled(&rig, &task),
            (WorkState::OutcomeUnknown, details::AGENT_EXITED.into())
        );
        reads(&mut rig, Some(&refused), "a refused reply");

        // Past its deadline on the delegated clock.
        os.pass(2 * HOUR);
        passes(&mut rig, 3);
        assert_eq!(
            settled(&rig, &task),
            (
                WorkState::OutcomeUnknown,
                details::DEADLINE_PASSED_OUTCOME_UNKNOWN.into()
            )
        );
        assert!(stored_record(&rig, &task).deadline_passed);
        reads(&mut rig, Some(&refused), "past its deadline");
        // B was told the task's outcome is unknown, once: nothing more.
        let receipts = ad_receipts(&rig, &message);
        assert_eq!(
            ad_resolved(&receipts[0])[0].state,
            WorkState::OutcomeUnknown
        );
    });
}

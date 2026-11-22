// Results back between hosts (design II.4.4; host-work-v1 §11.5): on the
// receiving host, an agent's reply to a host sender's task sealed as a
// result for the sending host; on the sending host, every status and
// result its mailbox keeps judged with `accept_result` and applied. Shares
// the admission tests' rig (`sp_host`, `ad_*`: this host is `host`, the
// other host `host-b`); every name here starts with `rb_`.

use atem_client::session::host_work::ResultReply;

/// B's request to this host's agent admitted: its one task, in the state
/// a dispatch leaves it once its turn ended (awaiting its result, its turn
/// known), so the agent may reply.
fn rb_task(rig: &mut LocalRig) -> (Message, WorkRecord) {
    let message = ad_message(rig, vec![ad_select(&["atem:host"], 1)]);
    ad_inbox_request(rig, &message);
    ad_admit(rig);
    let mut task = ad_tasks(rig, &message).remove(0);
    task.status.state = WorkState::AwaitingResult;
    task.turn_id = Some("turn-1".into());
    rig.bridge
        .work
        .store
        .as_ref()
        .unwrap()
        .save_work(&task)
        .unwrap();
    (message, task)
}

/// The results enqueued for B, oldest first: (engine state, task id,
/// reply), opened with B's key.
fn rb_results(rig: &LocalRig) -> Vec<(String, String, ResultReply)> {
    ad_statuses(rig)
        .into_iter()
        .filter_map(|(state, plain)| match plain {
            ResultPlain::Result { task_id, reply } => Some((state, task_id, reply)),
            _ => None,
        })
        .collect()
}

/// Item 1: a host sender's task's submitted reply becomes a result for
/// its sender (`{"kind":"result","task_id","reply"}`, the reply exactly as
/// `reply_query` returns it, its `result_id` the task's), owed in the
/// reply's own commit (another connection reads the mark), sealed and
/// enqueued until stored once: no later pass, and no identical retry,
/// makes a second.
#[test]
fn a_submitted_reply_is_sealed_for_its_sender_once() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = sp_host(&mut rig, root, &os);
        let (_, task) = rb_task(&mut rig);
        let id = task.task.task_id.clone();
        let result_id = reply(&mut rig, &id, "the answer", &[]).unwrap();
        let other = Store::open(&root.join("runtime")).unwrap();
        let owed: i64 = other
            .db
            .query_row(
                "SELECT count(*) FROM mail_result_owed WHERE task_id=?1",
                [&id],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(owed, 1, "owed in the reply's commit");
        assert!(rb_results(&rig).is_empty(), "sealed by the pass");
        rig.bridge.mail_statuses();
        rig.bridge.mail_statuses();
        assert_eq!(reply(&mut rig, &id, "the answer", &[]).unwrap(), result_id);
        rig.bridge.mail_statuses();
        let results = rb_results(&rig);
        assert_eq!(results.len(), 1, "one result per task");
        let (state, task_id, wire) = &results[0];
        assert_eq!((state.as_str(), task_id.as_str()), ("queued", id.as_str()));
        assert_eq!(wire.result_id, result_id);
        assert_eq!(
            wire.result_id,
            atem_client::session::host_work::result_id(&id)
        );
        let store = rig.bridge.work.store.as_ref().unwrap();
        let row = crate::runtime::collab::results::load(&store.db, &id)
            .unwrap()
            .unwrap();
        assert_eq!(*wire, row.wire(), "as reply_query returns it");
        let policy: Vec<String> = store
            .db
            .prepare("SELECT DISTINCT policy FROM mail_outbox WHERE kind='atem-result'")
            .unwrap()
            .query_map([], |r| r.get(0))
            .unwrap()
            .map(Result::unwrap)
            .collect();
        assert_eq!(policy, ["until_stored"]);
        assert_eq!(rows(&rig, "mail_result_owed"), 0);
    });
}

/// A sender with no current key gets no result (nor a status); the owner
/// still reads the reply, which the task's detail names. Nor does one no
/// longer a current host: removed, its result is never sealed.
#[test]
fn no_result_goes_to_a_sender_with_no_key_or_no_longer_a_host() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = mb_host(&mut rig, root, &os);
        let (_, task) = rb_task(&mut rig);
        let id = task.task.task_id.clone();
        reply(&mut rig, &id, "the answer", &[]).unwrap();
        rig.bridge.mail_statuses();
        assert_eq!(rows(&rig, "mail_outbox"), 0);
        assert_eq!(rows(&rig, "mail_result_owed"), 0, "none owed");
        let store = rig.bridge.work.store.as_ref().unwrap();
        let kept = crate::runtime::collab::results::load(&store.db, &id).unwrap();
        assert_eq!(kept.unwrap().reply.text, "the answer");
        assert_eq!(
            store.work(&id).unwrap().unwrap().status.detail,
            "reply submitted"
        );
    });
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let (_, task) = rb_task(&mut rig);
        let id = task.task.task_id.clone();
        reply(&mut rig, &id, "the answer", &[]).unwrap();
        sign_and_carry(
            &mut rig,
            &mut host.s,
            ListAction::RemoveHost {
                host_id: "host-b".into(),
            },
        );
        mb_tick(&mut rig, &mut host, 0);
        rig.bridge.mail_statuses();
        assert!(rb_results(&rig).is_empty());
        assert_eq!(rows(&rig, "mail_result_owed"), 0);
    });
}

/// A reply its publication refused (a vault entry the credential redactor
/// would change) or one over the limits sends nothing; a corrected reply
/// that is submitted sends one.
#[test]
fn a_refused_reply_sends_nothing_until_a_corrected_one_is_submitted() {
    use crate::runtime::collab::results::{self, Binding, Reply, ResultRow};
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = sp_host(&mut rig, root, &os);
        let (_, task) = rb_task(&mut rig);
        let id = task.task.task_id.clone();
        let publishing = ResultRow::new(
            Reply {
                binding: Binding {
                    task_id: id.clone(),
                    session_id: rig.sid.to_string(),
                    process_gen: task.task.target.process_gen.clone(),
                    turn_id: "turn-1".into(),
                },
                text: "with a vault entry".into(),
                references: vec![crate::runtime::collab_context::ContextSpec::Vault {
                    reference: crate::runtime::collab_context::VaultRef::parse("v-rb:1@2").unwrap(),
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
        let store = rig.bridge.work.store.as_ref().unwrap();
        results::refuse(
            &store.db,
            &id,
            crate::runtime::collab_context::VAULT_CREDENTIAL,
        )
        .unwrap();
        rig.bridge.mail_statuses();
        assert!(reply(&mut rig, &id, &"x".repeat(16 * 1024 + 1), &[]).is_err());
        rig.bridge.mail_statuses();
        assert!(rb_results(&rig).is_empty(), "nothing for a refused reply");
        reply(&mut rig, &id, "corrected", &[]).unwrap();
        rig.bridge.mail_statuses();
        let results = rb_results(&rig);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].2.text, "corrected");
    });
}

// ------------------------------------------------- on the sending host

use atem_client::session::host_work::ReplyState;

/// A session of B's, as its selector task ids name it.
const RB_SESSION: &str = "ses-bbbbbbbbbbbb";

/// This host's send to B's agents: its message id, and the recipient id
/// B's statuses name.
fn rb_send(rig: &mut LocalRig) -> (String, String) {
    let id = sp_send(rig, &["atem:host-b/rh"]).unwrap();
    let recipient: String = rig
        .bridge
        .work
        .store
        .as_ref()
        .unwrap()
        .db
        .query_row(
            "SELECT recipient_id FROM remote_deliveries WHERE object_id=?1 AND host_id='host-b'",
            [&id],
            |r| r.get(0),
        )
        .unwrap();
    (id, recipient)
}

/// B's `plain` back to this host, made at `created_at` (alive an hour),
/// signed with B's key at this list's head, sealed to this host's key.
fn rb_from_b(rig: &LocalRig, host: &MbHost, created_at: u64, plain: &ResultPlain) -> Value {
    let list = rig.bridge.membership.as_ref().unwrap().membership();
    let fields = atem_client::host_mail::MailFields {
        account_id: "acct".into(),
        genesis_hash: list.genesis_hash(),
        sender: atem_client::host_mail::HostRef {
            host_id: AD_B.into(),
            host_trust_gen: 1,
        },
        recipient: atem_client::host_mail::HostRef {
            host_id: "host".into(),
            host_trust_gen: 1,
        },
        enc_kid: atem_client::keys::enc_kid(&host.enc_pub).unwrap(),
        id: uuid::Uuid::new_v4().to_string(),
        created_at,
        expires_at: created_at + HOUR,
        signed_at_head: list.head(),
    };
    atem_client::host_mail::seal_result(
        &host.sender,
        &atem_client::KeyId::new("host-b"),
        &fields,
        plain,
        &host.enc_pub,
    )
    .unwrap()
    .to_json()
}

/// B's status of `message` with its recipient's `delivery`.
fn rb_status(message: &str, recipient: &str, delivery: Delivery) -> ResultPlain {
    ResultPlain::Status {
        message_id: message.into(),
        recipients: vec![RecipientReceipt {
            recipient_id: recipient.into(),
            delivery,
        }],
    }
}

/// A task of B's resolution of `recipient` on B's session `session`.
fn rb_progress(
    message: &str,
    recipient: &str,
    session: &str,
    state: WorkState,
    detail: &str,
) -> WorkProgress {
    WorkProgress {
        task_id: atem_client::session::select::selector_task_id(message, recipient, session),
        receipt_id: uuid::Uuid::new_v4().to_string(),
        state,
        detail: detail.into(),
        result: None,
    }
}

/// B's resolution of `recipient`: one task, `state`.
fn rb_resolved(message: &str, recipient: &str, state: WorkState) -> ResultPlain {
    let task = rb_progress(message, recipient, RB_SESSION, state, "on B");
    rb_status(message, recipient, Delivery::Resolved { tasks: vec![task] })
}

/// The selector task id of B's one task for `recipient`.
fn rb_task_id(message: &str, recipient: &str) -> String {
    atem_client::session::select::selector_task_id(message, recipient, RB_SESSION)
}

/// B's result for `task_id`: the reply as B's `reply_query` returns it.
fn rb_reply(task_id: &str, text: &str) -> ResultPlain {
    rb_reply_with(task_id, text, vec![])
}

/// B's submitted reply to `task_id` with its context: the snapshots B's
/// agent published with it.
fn rb_reply_with(task_id: &str, text: &str, context: Vec<hw::ContextSnapshot>) -> ResultPlain {
    ResultPlain::Result {
        task_id: task_id.into(),
        reply: ResultReply {
            result_id: atem_client::session::host_work::result_id(task_id),
            state: ReplyState::Submitted,
            digest: hw::digest(text.as_bytes()),
            text: text.into(),
            context,
            submitted_at: Some(host_now().wall_ms),
            dropped: false,
        },
    }
}

/// The results pass: what the mailbox kept judged and applied, then the
/// replies delivered.
fn rb_pass(rig: &mut LocalRig) {
    rig.bridge.results_drain();
    rig.bridge.remote_stops_pass();
    rig.bridge.remote_deliveries(&rig.sessions);
}

/// `objects` reach this host's mailbox, then the results pass.
fn rb_receive(rig: &mut LocalRig, host: &mut MbHost, objects: &[Value]) {
    ad_deliver(rig, host, objects);
    rb_pass(rig);
}

/// What this host recorded of `message` at B: per row (recipient, task id,
/// state, detail, reply text, delivery and its detail).
type RbRemote = (
    String,
    String,
    String,
    String,
    Option<String>,
    Option<String>,
);
fn rb_remote(rig: &LocalRig, message: &str) -> Vec<RbRemote> {
    let db = &rig.bridge.work.store.as_ref().unwrap().db;
    let mut q = db
        .prepare(
            "SELECT recipient_id, task_id, state, detail, json_extract(reply, '$.text'),
                delivery || coalesce(': ' || delivery_detail, '')
            FROM remote_tasks WHERE message_id=?1 AND host_id='host-b' ORDER BY rowid",
        )
        .unwrap();
    q.query_map([message], |r| {
        Ok((
            r.get(0)?,
            r.get(1)?,
            r.get(2)?,
            r.get(3)?,
            r.get(4)?,
            r.get(5)?,
        ))
    })
    .unwrap()
    .map(Result::unwrap)
    .collect()
}

/// The delivery tasks queued here: (task id, target session, prompt).
fn rb_deliveries(rig: &LocalRig) -> Vec<(String, String, String)> {
    let db = &rig.bridge.work.store.as_ref().unwrap().db;
    let mut q = db
        .prepare("SELECT record FROM work WHERE json_extract(record,'$.principal')='local'")
        .unwrap();
    q.query_map([], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| serde_json::from_str::<WorkRecord>(&r.unwrap()).unwrap())
        .map(|r| (r.task.task_id, r.task.target.session_id, r.task.prompt))
        .collect()
}

/// Item 2, every status form: the first status naming B's resolution
/// moves the row to `accepted` (`resolved`, `work`, `no_match`, `stored`)
/// or `refused` with the code (a recipient's `refused{code}`, or the
/// object-level refusal of the request), and the resolution is recorded;
/// each object judged leaves the mailbox's results at once.
#[test]
fn each_status_form_moves_the_row_and_records_the_resolution() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let now = host_now().wall_ms;
        let accepted = || vec![("host-b".to_string(), "accepted".to_string(), None)];
        let (m, r) = rb_send(&mut rig);
        let status = rb_from_b(&rig, &host, now, &rb_resolved(&m, &r, WorkState::Queued));
        rb_receive(&mut rig, &mut host, &[status]);
        assert_eq!(sp_rows(&rig, &m), accepted());
        let task = rb_task_id(&m, &r);
        assert_eq!(
            rb_remote(&rig, &m),
            [(r.clone(), task, "queued".into(), "on B".into(), None, None)]
        );
        assert_eq!(rows(&rig, "mailbox_results"), 0, "drained at once");
        // An agent recipient's own task (`work`, its id the recipient's).
        let (m, r) = rb_send(&mut rig);
        let work = WorkProgress {
            task_id: r.clone(),
            ..rb_progress(&m, &r, RB_SESSION, WorkState::Blocked, "agent busy")
        };
        let status = rb_from_b(
            &rig,
            &host,
            now,
            &rb_status(&m, &r, Delivery::Work { work }),
        );
        rb_receive(&mut rig, &mut host, &[status]);
        assert_eq!(sp_rows(&rig, &m), accepted());
        assert_eq!(rb_remote(&rig, &m)[0].1, r);
        // `no_match` and `stored`: recorded, no task.
        for (delivery, state) in [
            (Delivery::NoMatch {}, "no_match"),
            (Delivery::Stored {}, "stored"),
        ] {
            let (m, r) = rb_send(&mut rig);
            let status = rb_from_b(&rig, &host, now, &rb_status(&m, &r, delivery));
            rb_receive(&mut rig, &mut host, &[status]);
            assert_eq!(sp_rows(&rig, &m), accepted());
            assert_eq!(
                rb_remote(&rig, &m),
                [(r, String::new(), state.into(), String::new(), None, None)]
            );
        }
        // A recipient refused, and the request refused whole.
        let (m, r) = rb_send(&mut rig);
        let refused = Delivery::Refused {
            code: "forbidden".into(),
        };
        let status = rb_from_b(&rig, &host, now, &rb_status(&m, &r, refused));
        rb_receive(&mut rig, &mut host, &[status]);
        assert_eq!(
            sp_rows(&rig, &m),
            [("host-b".into(), "refused".into(), Some("forbidden".into()))]
        );
        let (m, _) = rb_send(&mut rig);
        let refusal = ResultPlain::Refusal {
            object_id: m.clone(),
            refused: "busy".into(),
        };
        let object = rb_from_b(&rig, &host, now, &refusal);
        rb_receive(&mut rig, &mut host, &[object]);
        assert_eq!(
            sp_rows(&rig, &m),
            [("host-b".into(), "refused".into(), Some("busy".into()))]
        );
        assert_eq!(rows(&rig, "mailbox_results"), 0);
    });
}

/// Statuses arrive in any order: one applies only when it was made after
/// the one recorded, and a resolution never changes once recorded (a
/// later status's other form, or a task it adds, changes nothing).
#[test]
fn statuses_apply_newest_first_and_a_resolution_never_changes() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let now = host_now().wall_ms;
        let (m, r) = rb_send(&mut rig);
        let newer = rb_from_b(
            &rig,
            &host,
            now,
            &rb_resolved(&m, &r, WorkState::AwaitingResult),
        );
        let older = rb_from_b(
            &rig,
            &host,
            now - 10_000,
            &rb_resolved(&m, &r, WorkState::Queued),
        );
        let no_match = rb_from_b(
            &rig,
            &host,
            now + 5_000,
            &rb_status(&m, &r, Delivery::NoMatch {}),
        );
        rb_receive(&mut rig, &mut host, &[newer, older, no_match]);
        let state = |rig: &LocalRig| -> Vec<(String, String)> {
            rb_remote(rig, &m)
                .into_iter()
                .map(|row| (row.1, row.2))
                .collect()
        };
        let task = rb_task_id(&m, &r);
        assert_eq!(state(&rig), [(task.clone(), "awaiting_result".into())]);
        let mut later = rb_progress(&m, &r, RB_SESSION, WorkState::Expired, "expired");
        later.task_id = task.clone();
        let added = rb_progress(&m, &r, "ses-cccccccccccc", WorkState::Queued, "new");
        let status = rb_status(
            &m,
            &r,
            Delivery::Resolved {
                tasks: vec![later, added],
            },
        );
        let status = rb_from_b(&rig, &host, now + 10_000, &status);
        rb_receive(&mut rig, &mut host, &[status]);
        assert_eq!(state(&rig), [(task, "expired".into())]);
    });
}

/// What answers no message this host sent is dropped (never kept): a
/// status naming another message, a result naming no recorded task once
/// every row is resolved, and a result whose reply carries another task's
/// `result_id` (refused, `result_id_mismatch`). Nothing is recorded.
#[test]
fn what_answers_no_row_is_dropped_and_a_result_id_mismatch_refused() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let now = host_now().wall_ms;
        let (m, r) = rb_send(&mut rig);
        let status = rb_from_b(&rig, &host, now, &rb_resolved(&m, &r, WorkState::Queued));
        rb_receive(&mut rig, &mut host, &[status]);
        let task = rb_task_id(&m, &r);
        let never = uuid::Uuid::new_v4().to_string();
        let mut mismatched = rb_reply(&task, "forged");
        if let ResultPlain::Result { reply, .. } = &mut mismatched {
            reply.result_id = atem_client::session::host_work::result_id(&never);
        }
        let objects = [
            rb_from_b(
                &rig,
                &host,
                now,
                &rb_resolved(&never, &r, WorkState::Queued),
            ),
            rb_from_b(&rig, &host, now, &rb_reply(&never, "no such task")),
            rb_from_b(&rig, &host, now, &mismatched),
        ];
        rb_receive(&mut rig, &mut host, &objects);
        assert_eq!(rows(&rig, "mailbox_results"), 0, "dropped");
        assert!(rb_remote(&rig, &never).is_empty());
        assert_eq!(rb_remote(&rig, &m)[0].4, None, "no reply recorded");
        assert_eq!(rows(&rig, "remote_tasks"), 1);
    });
}

/// A result that arrives before the status naming its task waits in the
/// mailbox's results; once the status is recorded it is applied, and
/// nothing waits any more.
#[test]
fn a_result_waits_for_the_status_naming_its_task() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let now = host_now().wall_ms;
        let (m, r) = rb_send(&mut rig);
        let task = rb_task_id(&m, &r);
        let result = rb_from_b(&rig, &host, now, &rb_reply(&task, "early"));
        rb_receive(&mut rig, &mut host, &[result]);
        assert_eq!(rows(&rig, "mailbox_results"), 1, "waiting");
        assert!(rb_remote(&rig, &m).is_empty());
        let status = rb_from_b(
            &rig,
            &host,
            now,
            &rb_resolved(&m, &r, WorkState::AwaitingResult),
        );
        rb_receive(&mut rig, &mut host, &[status]);
        rb_pass(&mut rig);
        assert_eq!(rows(&rig, "mailbox_results"), 0);
        assert_eq!(rb_remote(&rig, &m)[0].4.as_deref(), Some("early"));
    });
}

/// The prompt the runtime delivers for another host's reply is the shared
/// vectors' (`framing-host-result-v1.json`), byte for byte: rendered by the
/// dispatch's own `render_task_prompt` from the delivery's records (its
/// frame, the reply's text and the snapshots it carries), then its tag,
/// drawn for the attempt, swapped for the vectors' on Atem's lines, and
/// the vectors' task id for the delivered task's (same length). The plain
/// reply, and the reply with its context.
#[test]
fn a_delivered_result_is_the_shared_vectors_prompt() {
    local_test(async |root| {
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("designs/protocol/fixtures/host-work/framing-host-result-v1.json");
        let file: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let tag = file["tag"].as_str().unwrap();
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        rig.bridge.work.config.routes[0].results = true;
        let now = host_now().wall_ms;
        for name in ["a plain reply", "the counted blocks with context"] {
            let case = file["prompts"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["name"].as_str().unwrap().starts_with(name))
                .unwrap();
            let input = &case["input"];
            assert_eq!(input["header"]["sender"], "host:host-b");
            let text = input["text"].as_str().unwrap();
            let context: Vec<hw::ContextSnapshot> =
                serde_json::from_value(input["context"].clone()).unwrap();
            let (m, r) = rb_send(&mut rig);
            let task = rb_task_id(&m, &r);
            let status = rb_from_b(
                &rig,
                &host,
                now,
                &rb_resolved(&m, &r, WorkState::AwaitingResult),
            );
            let result = rb_from_b(&rig, &host, now, &rb_reply_with(&task, text, context));
            rb_receive(&mut rig, &mut host, &[status, result]);
            let record = rig
                .bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .work(&rb_delivery(&m, &task))
                .unwrap()
                .unwrap();
            let (prompt, drawn) = rig
                .bridge
                .render_task_prompt(&record, &[])
                .unwrap()
                .unwrap();
            let retagged: Vec<String> = prompt
                .split('\n')
                .map(|line| match line.strip_prefix(&drawn.prefix()) {
                    Some(rest) => format!("[atem {tag}] {rest}"),
                    None => line.to_string(),
                })
                .collect();
            let vector_task = input["header"]["task_id"].as_str().unwrap();
            assert_eq!(vector_task.len(), task.len());
            let expected = case["rendered"]
                .as_str()
                .unwrap()
                .replace(vector_task, &task);
            assert_eq!(retagged.join("\n"), expected, "{name}");
        }
    });
}

/// A reply delivered once, as data, into the session that sent the
/// message, on a route that takes results: a local delivery task carrying
/// the reply, its prompt framed as another host's result (`from
/// host:host-b`); the same result again delivers nothing more; the
/// agent's turn completes the delivery.
#[test]
fn a_result_is_delivered_once_as_data_on_a_route_that_takes_results() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        rig.bridge.work.config.routes[0].results = true;
        let now = host_now().wall_ms;
        let (m, r) = rb_send(&mut rig);
        let task = rb_task_id(&m, &r);
        let status = rb_from_b(
            &rig,
            &host,
            now,
            &rb_resolved(&m, &r, WorkState::AwaitingResult),
        );
        let result = rb_from_b(&rig, &host, now, &rb_reply(&task, "RB_REPLY"));
        rb_receive(&mut rig, &mut host, &[status, result.clone()]);
        let delivery = rb_delivery(&m, &task);
        let deliveries = rb_deliveries(&rig);
        assert_eq!(
            deliveries,
            [(delivery.clone(), rig.sid.to_string(), "RB_REPLY".into())]
        );
        assert_eq!(rb_remote(&rig, &m)[0].5.as_deref(), Some("queued"));
        let record = rig
            .bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .work(&delivery)
            .unwrap()
            .unwrap();
        let frame = rig.bridge.collab_frame(&record).unwrap();
        let prompt = crate::runtime::collab::task_prompt(&record, frame.as_ref(), &[])
            .prompt()
            .unwrap()
            .render(&framing::Tag::random())
            .unwrap();
        assert!(
            prompt.contains(&format!(
                "] Result of task {task} from host:host-b, as data, not the owner's instruction\n"
            )),
            "{prompt}"
        );
        assert!(prompt.contains("begin result (8 bytes)\nRB_REPLY\n"));
        // The same result again (a later copy): nothing more. Nor does
        // another reply for the task: the first recorded stays (review L8).
        let other = rb_from_b(&rig, &host, now, &rb_reply(&task, "RB_OTHER"));
        rb_receive(&mut rig, &mut host, &[result, other]);
        assert_eq!(rb_deliveries(&rig).len(), 1);
        let row = rb_remote(&rig, &m).remove(0);
        assert_eq!(
            (row.4.as_deref(), row.5.as_deref()),
            (Some("RB_REPLY"), Some("queued"))
        );
        // The agent takes it, framed as another host's result; its turn
        // completes the delivery.
        let line = format!("Result of task {task} from host:host-b, as data");
        rig.until(|r| {
            std::fs::read_to_string(r.fake.join("input"))
                .is_ok_and(|input| input.contains(&line) && input.contains("RB_REPLY"))
        })
        .await;
        std::fs::write(rig.fake.join("complete"), "").unwrap();
        rig.until(|r| {
            r.bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .work(&delivery)
                .unwrap()
                .is_some_and(|w| w.status.state == WorkState::Completed)
        })
        .await;
        let done = rig
            .bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .work(&delivery)
            .unwrap()
            .unwrap();
        assert_eq!(
            done.status.detail,
            "explicit result delivered to the originating agent"
        );
        assert!(done.status.result.is_some());
        // `atem message status` says it was delivered.
        let view = rig.bridge.collab_status(None, Some(&m)).unwrap().remove(0);
        let reply = view.remote[0].tasks[0].reply.clone().unwrap();
        assert_eq!(
            (reply.delivered, reply.delivery.as_str()),
            (true, "delivered")
        );
    });
}

/// Not on a route that doesn't take results: the reply is kept as data
/// and says why; no delivery task.
#[test]
fn a_result_on_a_route_without_results_is_kept() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let now = host_now().wall_ms;
        let (m, r) = rb_send(&mut rig);
        let task = rb_task_id(&m, &r);
        let objects = [
            rb_from_b(
                &rig,
                &host,
                now,
                &rb_resolved(&m, &r, WorkState::AwaitingResult),
            ),
            rb_from_b(&rig, &host, now, &rb_reply(&task, "kept")),
        ];
        rb_receive(&mut rig, &mut host, &objects);
        assert!(rb_deliveries(&rig).is_empty());
        let row = rb_remote(&rig, &m).remove(0);
        assert_eq!(row.4.as_deref(), Some("kept"));
        assert_eq!(
            row.5.as_deref(),
            Some(
                format!(
                    "kept: {}",
                    crate::runtime::delegated::results_back::NO_RESULTS
                )
                .as_str()
            )
        );
        // Its text is kept a day past the message's expiry, then dropped
        // (on `D`, by the mailbox's minute prune); the row stays.
        let db = &rig.bridge.work.store.as_ref().unwrap().db;
        let expires: u64 = db
            .query_row(
                "SELECT expires_at FROM remote_tasks WHERE message_id=?1",
                [&m],
                |r| r.get(0),
            )
            .unwrap();
        let day = 24 * HOUR;
        crate::runtime::delegated::results_back::prune_replies(db, expires + day - 1).unwrap();
        assert_eq!(rb_remote(&rig, &m)[0].4.as_deref(), Some("kept"));
        crate::runtime::delegated::results_back::prune_replies(db, expires + day).unwrap();
        assert_eq!(rb_remote(&rig, &m)[0].4.as_deref(), Some(""));
    });
}

/// A result from a host this host revoked meanwhile is kept as data with
/// the return grant's detail, never delivered (its status still
/// recorded); one from a host no current project shares with this host
/// any more is kept too.
#[test]
fn a_result_from_a_revoked_or_ungranted_host_is_kept_as_data() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        rig.bridge.work.config.routes[0].results = true;
        let now = host_now().wall_ms;
        let (m, r) = rb_send(&mut rig);
        let task = rb_task_id(&m, &r);
        sign_and_carry(
            &mut rig,
            &mut host.s,
            atem_client::membership::host_sender_revoke("host-b", false, 0).unwrap(),
        );
        mb_tick(&mut rig, &mut host, 0);
        let objects = [
            rb_from_b(
                &rig,
                &host,
                now,
                &rb_resolved(&m, &r, WorkState::AwaitingResult),
            ),
            rb_from_b(&rig, &host, now, &rb_reply(&task, "from a revoked host")),
        ];
        rb_receive(&mut rig, &mut host, &objects);
        assert!(rb_deliveries(&rig).is_empty());
        let row = rb_remote(&rig, &m).remove(0);
        assert_eq!(row.2, "awaiting_result", "its status recorded");
        assert_eq!(
            row.5.as_deref(),
            Some("kept: result not delivered: sender revoked")
        );
    });
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        rig.bridge.work.config.routes[0].results = true;
        let now = host_now().wall_ms;
        let (m, r) = rb_send(&mut rig);
        let task = rb_task_id(&m, &r);
        sign_and_carry(
            &mut rig,
            &mut host.s,
            atem_client::membership::project_remove("build", 0).unwrap(),
        );
        mb_tick(&mut rig, &mut host, 0);
        let objects = [
            rb_from_b(
                &rig,
                &host,
                now,
                &rb_resolved(&m, &r, WorkState::AwaitingResult),
            ),
            rb_from_b(&rig, &host, now, &rb_reply(&task, "no project")),
        ];
        rb_receive(&mut rig, &mut host, &objects);
        assert!(rb_deliveries(&rig).is_empty());
        assert_eq!(
            rb_remote(&rig, &m)[0].5.as_deref(),
            Some("kept: result not delivered: sender no longer granted")
        );
    });
    // Revoked once its delivery is queued, before the agent took it: the
    // delivery is cancelled and the reply kept.
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        rig.bridge.work.config.routes[0].results = true;
        let now = host_now().wall_ms;
        let (m, r) = rb_send(&mut rig);
        let task = rb_task_id(&m, &r);
        let objects = [
            rb_from_b(
                &rig,
                &host,
                now,
                &rb_resolved(&m, &r, WorkState::AwaitingResult),
            ),
            rb_from_b(&rig, &host, now, &rb_reply(&task, "queued first")),
        ];
        rb_receive(&mut rig, &mut host, &objects);
        assert_eq!(rb_deliveries(&rig).len(), 1);
        sign_and_carry(
            &mut rig,
            &mut host.s,
            atem_client::membership::host_sender_revoke("host-b", false, 0).unwrap(),
        );
        mb_tick(&mut rig, &mut host, 0);
        rig.bridge.remote_deliveries(&rig.sessions);
        let delivery = rb_delivery(&m, &task);
        let record = rig
            .bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .work(&delivery)
            .unwrap()
            .unwrap();
        assert_eq!(
            (record.status.state, record.status.detail.as_str()),
            (
                WorkState::Cancelled,
                "not delivered: result not delivered: sender revoked"
            )
        );
        assert_eq!(
            rb_remote(&rig, &m)[0].5.as_deref(),
            Some("kept: result not delivered: sender revoked")
        );
    });
}

/// The runtime again over the same store (a crash): a new bridge, its
/// recovery, then the Station link as `mb_host` set it up.
fn rb_restart(rig: &mut LocalRig, root: &Path, os: &ManualOs) {
    use crate::runtime::delegated::station::{LinkKind, Station};
    restart(rig, root, os, false, true);
    let pairing = crate::profile::Sources::in_dir(&root.join("profile"))
        .paths
        .pairing;
    rig.bridge.pairing = Some(pairing);
    rig.bridge.start_view().now_d_ms = Some(host_now().wall_ms);
    let mut station = Station::with_senders(true);
    station.sync_link(Some(1), 1, || LinkKind::Routed, || Some(ORIGIN.into()));
    rig.bridge.station = Some(station);
    rig.bridge.station_identity();
    rig.bridge.mail_observe();
}

/// A send to B whose status (B's task awaiting its result) and reply
/// `text` came back and were judged (none delivered yet): the message, its
/// recipient and B's task.
fn rb_replied(rig: &mut LocalRig, host: &mut MbHost, text: &str) -> (String, String, String) {
    let now = host_now().wall_ms;
    let (m, r) = rb_send(rig);
    let task = rb_task_id(&m, &r);
    let objects = [
        rb_from_b(
            rig,
            host,
            now,
            &rb_resolved(&m, &r, WorkState::AwaitingResult),
        ),
        rb_from_b(rig, host, now, &rb_reply(&task, text)),
    ];
    ad_deliver(rig, host, &objects);
    rig.bridge.results_drain();
    (m, r, task)
}

/// Durable before visible, across a crash: the drain commits the reply
/// (another connection reads it, due) with its row gone from the
/// mailbox's results, before anything is delivered. The runtime dies
/// there and starts again over the same store: the reply is delivered
/// once.
#[test]
fn a_crash_after_the_drain_delivers_once_after_the_restart() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        rig.bridge.work.config.routes[0].results = true;
        let (m, _, task) = rb_replied(&mut rig, &mut host, "durable");
        let other = Store::open(&root.join("runtime")).unwrap();
        let (delivery, kept): (Option<String>, i64) = other
            .db
            .query_row(
                "SELECT (SELECT delivery FROM remote_tasks WHERE task_id=?1),
                    (SELECT count(*) FROM mailbox_results)",
                [&task],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!((delivery.as_deref(), kept), (Some("due"), 0));
        assert!(rb_deliveries(&rig).is_empty(), "nothing delivered yet");
        rb_restart(&mut rig, root, &os);
        rig.until(|r| !rb_deliveries(r).is_empty()).await;
        for _ in 0..3 {
            rig.bridge.remote_deliveries(&rig.sessions);
        }
        assert_eq!(rb_deliveries(&rig).len(), 1);
        assert_eq!(rb_deliveries(&rig)[0].0, rb_delivery(&m, &task));
    });
}

/// A crash between the delivery's commit and its dispatch: after the
/// restart the queued delivery reaches the agent once, and its turn
/// completes it (`delivered`).
#[test]
fn a_crash_after_the_deliverys_commit_dispatches_it_once() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        rig.bridge.work.config.routes[0].results = true;
        let (m, _, task) = rb_replied(&mut rig, &mut host, "RB_ONCE");
        rig.bridge.remote_deliveries(&rig.sessions);
        assert_eq!(rb_remote(&rig, &m)[0].5.as_deref(), Some("queued"));
        rb_restart(&mut rig, root, &os);
        rig.until(|r| {
            std::fs::read_to_string(r.fake.join("input")).is_ok_and(|i| i.contains("RB_ONCE"))
        })
        .await;
        std::fs::write(rig.fake.join("complete"), "").unwrap();
        rig.until(|r| rb_remote(r, &m)[0].5.as_deref() == Some("delivered"))
            .await;
        let input = std::fs::read_to_string(rig.fake.join("input")).unwrap();
        assert_eq!(input.matches("RB_ONCE").count(), 1);
        assert_eq!(rb_deliveries(&rig).len(), 1);
        let _ = task;
    });
}

/// Hook off = main: the results pass does nothing and makes no table.
#[test]
fn without_host_senders_no_result_is_judged() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _s = host_senders_host(&mut rig, root, &os);
        rig.bridge.features = HostFeatures::parse("host.delegated").unwrap();
        rig.bridge.mail_observe();
        rb_pass(&mut rig);
        let made: bool = rig
            .bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name GLOB 'remote_*'
                    OR name GLOB 'mail_result*')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!made);
    });
}

/// The hook turned off over a store that has the tables (a debug runtime
/// started again without it): no kept result is judged, and a delivery
/// queued meanwhile is never dispatched (review L4): it waits, the
/// sender's standing unchecked.
#[test]
fn with_the_hook_turned_off_nothing_is_judged_or_delivered() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        rig.bridge.work.config.routes[0].results = true;
        let (m, r, _) = rb_replied(&mut rig, &mut host, "RB_HOOK_OFF");
        rig.bridge.remote_deliveries(&rig.sessions);
        let newer = rb_from_b(
            &rig,
            &host,
            host_now().wall_ms + 1_000,
            &rb_resolved(&m, &r, WorkState::Expired),
        );
        ad_deliver(&mut rig, &mut host, &[newer]);
        assert_eq!(rows(&rig, "mailbox_results"), 1);
        rig.bridge.features = HostFeatures::parse("host.delegated").unwrap();
        rb_pass(&mut rig);
        assert_eq!(rows(&rig, "mailbox_results"), 1, "never judged");
        let until = Instant::now() + Duration::from_secs(2);
        rig.until(|_| Instant::now() >= until).await;
        let input = std::fs::read_to_string(rig.fake.join("input")).unwrap_or_default();
        assert!(!input.contains("RB_HOOK_OFF"), "never dispatched");
    });
}

// ------------------------------------------------ `atem message status`

/// Item 3: a message's rows to other hosts in `atem message status` (from
/// the owner's terminal and inside the session that sent it, never in
/// another session's view): before any status, "status pending", and a
/// row waiting for the Station to announce this host's mailbox says so;
/// once statuses and a result came, each task with its state and its
/// reply, delivered or kept. With the hook turned off afterwards, the rows
/// stay readable.
#[test]
fn message_status_shows_rows_to_other_hosts_and_what_came_back() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let now = host_now().wall_ms;
        let (m, r) = rb_send(&mut rig);
        let remote = |rig: &mut LocalRig, caller: Option<&SessionId>| {
            rig.bridge.collab_status(caller, Some(&m)).unwrap()[0]
                .remote
                .clone()
        };
        let row = remote(&mut rig, None).remove(0);
        assert_eq!(
            (row.host_id.as_str(), row.state.as_str(), row.status_pending),
            ("host-b", "ready", true)
        );
        assert_eq!(row.detail, "waiting to be put in the host's mailbox");
        // A new link generation, before its `heads` announce the mailbox.
        use crate::runtime::delegated::station::LinkKind;
        rig.bridge.station.as_mut().unwrap().sync_link(
            Some(2),
            2,
            || LinkKind::Routed,
            || Some(ORIGIN.into()),
        );
        rig.bridge.station_identity();
        let row = remote(&mut rig, None).remove(0);
        assert_eq!(
            row.detail,
            "waiting for the Station to announce this host's mailbox"
        );
        mb_heads(&mut rig, MB_MAILBOX, 0);
        let task = rb_task_id(&m, &r);
        let objects = [
            rb_from_b(
                &rig,
                &host,
                now,
                &rb_resolved(&m, &r, WorkState::AwaitingResult),
            ),
            rb_from_b(&rig, &host, now, &rb_reply(&task, "seen there")),
        ];
        rb_receive(&mut rig, &mut host, &objects);
        let sid = rig.sid.clone();
        for caller in [None, Some(&sid)] {
            let row = remote(&mut rig, caller).remove(0);
            assert_eq!(
                (row.state.as_str(), row.status_pending),
                ("accepted", false)
            );
            let t = &row.tasks[0];
            assert_eq!(
                (t.task_id.as_str(), t.state.as_str(), t.detail.as_str()),
                (task.as_str(), "awaiting_result", "on B")
            );
            let reply = t.reply.as_ref().unwrap();
            assert_eq!(
                (
                    reply.text.as_str(),
                    reply.delivered,
                    reply.delivery.as_str()
                ),
                (
                    "seen there",
                    false,
                    crate::runtime::delegated::results_back::NO_RESULTS
                )
            );
        }
        // Another session sees none of it.
        let other = SessionId::new();
        assert!(
            rig.bridge
                .collab_status(Some(&other), Some(&m))
                .unwrap()
                .is_empty()
        );
        rig.bridge.features = HostFeatures::parse("host.delegated").unwrap();
        assert_eq!(remote(&mut rig, None).len(), 1, "rows stay readable");
    });
}

// ------------------------------------------------------- fix round 1

/// The delivery task's id of B's task `task` for message `m`.
fn rb_delivery(m: &str, task: &str) -> String {
    crate::runtime::delegated::results_back::delivery_id(m, "host-b", task)
}

/// How `atem message status` says the reply to `m`'s first task stands:
/// (delivered, how).
fn rb_delivered(rig: &mut LocalRig, m: &str) -> (bool, String) {
    let view = rig.bridge.collab_status(None, Some(m)).unwrap().remove(0);
    let reply = view.remote[0].tasks[0].reply.clone().unwrap();
    (reply.delivered, reply.delivery)
}

/// Review M1: a reply waiting for its delivery (queued, or due) is kept
/// as data once its sender is no longer at the `add_host` generation and
/// membership epoch its result came under: verified again (a newer
/// `add_host`), or removed and added again. The delivery queued is
/// cancelled.
#[test]
fn a_reply_waiting_for_delivery_is_kept_once_its_sender_moves_in_the_list() {
    use crate::session_protocol::membership::r9log::secret;
    // Verified again while its delivery is queued.
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        rig.bridge.work.config.routes[0].results = true;
        let (m, _, task) = rb_replied(&mut rig, &mut host, "RB_OLD_KEY");
        rig.bridge.remote_deliveries(&rig.sessions);
        assert_eq!(rb_remote(&rig, &m)[0].5.as_deref(), Some("queued"));
        host.s
            .log
            .add_host("host-b", 2, &secret("host b verified again"));
        let entry = host.s.log.entries.last().unwrap().object().to_json();
        carry(&mut rig, &host.s.log, entry);
        mb_tick(&mut rig, &mut host, 0);
        rig.bridge.remote_deliveries(&rig.sessions);
        let record = rig
            .bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .work(&rb_delivery(&m, &task))
            .unwrap()
            .unwrap();
        assert_eq!(
            (record.status.state, record.status.detail.as_str()),
            (
                WorkState::Cancelled,
                "not delivered: result not delivered: sender removed"
            )
        );
        assert_eq!(
            rb_remote(&rig, &m)[0].5.as_deref(),
            Some("kept: result not delivered: sender removed")
        );
    });
    // Removed and added again while it is due.
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        rig.bridge.work.config.routes[0].results = true;
        let (m, _, _) = rb_replied(&mut rig, &mut host, "RB_READDED");
        sign_and_carry(
            &mut rig,
            &mut host.s,
            ListAction::RemoveHost {
                host_id: "host-b".into(),
            },
        );
        host.s
            .log
            .add_host("host-b", 2, &secret("host b added again"));
        let entry = host.s.log.entries.last().unwrap().object().to_json();
        carry(&mut rig, &host.s.log, entry);
        mb_tick(&mut rig, &mut host, 0);
        rig.bridge.remote_deliveries(&rig.sessions);
        assert!(rb_deliveries(&rig).is_empty());
        assert_eq!(
            rb_remote(&rig, &m)[0].5.as_deref(),
            Some("kept: result not delivered: sender removed")
        );
    });
}

/// Review M2: a delivery task that ends without delivering moves its
/// row to a final state with why, and `atem message status` says so,
/// never "being delivered" for good: expired unstarted, failed (its
/// authority lost, or its receipt rejected), cancelled, of unknown
/// outcome; completed is `delivered`.
#[test]
fn a_delivery_that_ends_undelivered_says_why() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        rig.bridge.work.config.routes[0].results = true;
        let ends = [
            (
                WorkState::Expired,
                "expired before submission",
                "kept",
                false,
                "not delivered: expired before submission",
            ),
            (
                WorkState::Failed,
                "sender's authority changed",
                "kept",
                false,
                "not delivered: sender's authority changed",
            ),
            (
                WorkState::Failed,
                "session closed",
                "kept",
                false,
                "not delivered: session closed",
            ),
            (
                WorkState::Cancelled,
                "cancelled before submission",
                "kept",
                false,
                "not delivered: cancelled before submission",
            ),
            (
                WorkState::OutcomeUnknown,
                "receipt no longer available",
                "unknown",
                false,
                "delivery outcome unknown: receipt no longer available",
            ),
            (
                WorkState::Completed,
                "explicit result delivered to the originating agent",
                "delivered",
                true,
                "delivered",
            ),
        ];
        for (state, detail, final_state, delivered, says) in ends {
            let (m, _, task) = rb_replied(&mut rig, &mut host, "RB_ENDS");
            rig.bridge.remote_deliveries(&rig.sessions);
            let store = rig.bridge.work.store.as_ref().unwrap();
            let mut record = store.work(&rb_delivery(&m, &task)).unwrap().unwrap();
            record.status.state = state;
            record.status.detail = detail.into();
            store.save_work(&record).unwrap();
            // Said at once, before the pass settles the row.
            assert_eq!(
                rb_delivered(&mut rig, &m),
                (delivered, says.into()),
                "{state:?}"
            );
            rig.bridge.remote_deliveries(&rig.sessions);
            let row = rb_remote(&rig, &m).remove(0);
            let expected = match final_state {
                "delivered" => "delivered".to_string(),
                other => format!("{other}: {says}"),
            };
            assert_eq!(row.5.as_deref(), Some(expected.as_str()), "{state:?}");
            assert_eq!(
                rb_delivered(&mut rig, &m),
                (delivered, says.into()),
                "{state:?}"
            );
        }
    });
}

/// Review L1, ruling R49: results waiting for their status are bounded
/// apart (half the sender's results share), so the status they wait for
/// still finds room: of four results for a share of four, two are taken
/// and wait, two are left on the Station (none dropped); the status is
/// kept and applied, and the two apply after it in the same drain.
#[test]
fn waiting_results_leave_room_for_their_status() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        rig.bridge.work.mail_limits.results_per_sender = 4;
        let now = host_now().wall_ms;
        let (m, r) = rb_send(&mut rig);
        let sessions = [
            "ses-aaaaaaaaaaaa",
            "ses-cccccccccccc",
            "ses-dddddddddddd",
            "ses-eeeeeeeeeeee",
        ];
        let tasks: Vec<WorkProgress> = sessions
            .iter()
            .map(|sid| rb_progress(&m, &r, sid, WorkState::AwaitingResult, "on B"))
            .collect();
        let results: Vec<Value> = tasks
            .iter()
            .map(|t| rb_from_b(&rig, &host, now, &rb_reply(&t.task_id, "early")))
            .collect();
        rb_receive(&mut rig, &mut host, &results);
        assert_eq!(rows(&rig, "mailbox_results"), 2, "two wait");
        assert!(mb_store(&rig).skipped, "two left on the Station");
        let status = rb_status(&m, &r, Delivery::Resolved { tasks });
        let status = rb_from_b(&rig, &host, now, &status);
        rb_receive(&mut rig, &mut host, &[status]);
        rb_pass(&mut rig);
        assert_eq!(rows(&rig, "mailbox_results"), 0);
        let replies = rb_remote(&rig, &m)
            .into_iter()
            .filter(|row| row.4.is_some())
            .count();
        assert_eq!(replies, 2);
    });
}

/// Review L2: only a result waits for its status; a status that answers
/// no row is dropped at once, even while a row to its host has no status.
#[test]
fn a_status_answering_no_row_never_waits() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let now = host_now().wall_ms;
        let (_m, r) = rb_send(&mut rig);
        let never = uuid::Uuid::new_v4().to_string();
        let stray = rb_from_b(
            &rig,
            &host,
            now,
            &rb_resolved(&never, &r, WorkState::Queued),
        );
        rb_receive(&mut rig, &mut host, &[stray]);
        assert_eq!(rows(&rig, "mailbox_results"), 0);
    });
}

/// Review L3: a task id B reuses across two of this host's messages is
/// caught: the second resolution doesn't take it (its recipient says
/// why), so a result for it answers the first message only, and each
/// message's delivery has its own id.
#[test]
fn a_task_id_reused_across_messages_is_caught() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let now = host_now().wall_ms;
        let (m1, r1) = rb_send(&mut rig);
        let (m2, r2) = rb_send(&mut rig);
        let task = rb_task_id(&m1, &r1);
        let reused = rb_progress(&m1, &r1, RB_SESSION, WorkState::AwaitingResult, "on B");
        let objects = [
            rb_from_b(
                &rig,
                &host,
                now,
                &rb_status(
                    &m1,
                    &r1,
                    Delivery::Resolved {
                        tasks: vec![reused.clone()],
                    },
                ),
            ),
            rb_from_b(
                &rig,
                &host,
                now,
                &rb_status(
                    &m2,
                    &r2,
                    Delivery::Resolved {
                        tasks: vec![reused],
                    },
                ),
            ),
            rb_from_b(&rig, &host, now, &rb_reply(&task, "for the first")),
        ];
        rb_receive(&mut rig, &mut host, &objects);
        assert_eq!(rb_remote(&rig, &m1)[0].1, task);
        assert_eq!(rb_remote(&rig, &m1)[0].4.as_deref(), Some("for the first"));
        assert_eq!(
            rb_remote(&rig, &m2),
            [(
                r2,
                String::new(),
                "refused".into(),
                format!("task id {task} is another message's"),
                None,
                None
            )]
        );
        assert_ne!(rb_delivery(&m1, &task), rb_delivery(&m2, &task));
    });
}

/// Review L5: a result whose sealing fails for a passing fault (the
/// store refusing its enqueue) stays owed and goes on a later pass; one
/// whose record no longer reads is dropped, its mark cleared.
#[test]
fn an_owed_result_survives_a_passing_fault() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = sp_host(&mut rig, root, &os);
        let (_, task) = rb_task(&mut rig);
        let id = task.task.task_id.clone();
        reply(&mut rig, &id, "the answer", &[]).unwrap();
        let db = &rig.bridge.work.store.as_ref().unwrap().db;
        db.execute_batch(
            "CREATE TRIGGER t_block BEFORE INSERT ON mail_outbox
            WHEN NEW.kind='atem-result' AND NEW.bytes IS NOT NULL
            BEGIN SELECT RAISE(ABORT,'blocked'); END;",
        )
        .unwrap();
        rig.bridge.mail_statuses();
        assert!(rb_results(&rig).is_empty());
        assert_eq!(rows(&rig, "mail_result_owed"), 1, "still owed");
        let db = &rig.bridge.work.store.as_ref().unwrap().db;
        db.execute_batch("DROP TRIGGER t_block;").unwrap();
        rig.bridge.mail_statuses();
        assert_eq!(rb_results(&rig).len(), 1);
        // A record that no longer reads: dropped, not owed for good.
        let (_, task) = rb_task(&mut rig);
        let id = task.task.task_id.clone();
        reply(&mut rig, &id, "another", &[]).unwrap();
        let db = &rig.bridge.work.store.as_ref().unwrap().db;
        db.execute(
            "UPDATE results SET record='not json' WHERE task_id=?1",
            [&id],
        )
        .unwrap();
        rig.bridge.mail_statuses();
        assert_eq!(rows(&rig, "mail_result_owed"), 0);
    });
}

// ------------------------------------------------------- fix round 2

/// B's result `plain`, signed at `head` (a head of B's list this host may
/// not hold yet).
fn rb_from_b_at(
    rig: &LocalRig,
    host: &MbHost,
    head: atem_client::membership::Head,
    plain: &ResultPlain,
) -> Value {
    let list = rig.bridge.membership.as_ref().unwrap().membership();
    let now = host_now().wall_ms;
    let fields = atem_client::host_mail::MailFields {
        account_id: "acct".into(),
        genesis_hash: list.genesis_hash(),
        sender: atem_client::host_mail::HostRef {
            host_id: AD_B.into(),
            host_trust_gen: 1,
        },
        recipient: atem_client::host_mail::HostRef {
            host_id: "host".into(),
            host_trust_gen: 1,
        },
        enc_kid: atem_client::keys::enc_kid(&host.enc_pub).unwrap(),
        id: uuid::Uuid::new_v4().to_string(),
        created_at: now - 1_000,
        expires_at: now + HOUR,
        signed_at_head: head,
    };
    atem_client::host_mail::seal_result(
        &host.sender,
        &atem_client::KeyId::new("host-b"),
        &fields,
        plain,
        &host.enc_pub,
    )
    .unwrap()
    .to_json()
}

/// Four tasks of B's for `m`'s recipient `r`, each on its own session.
fn rb_four(m: &str, r: &str) -> Vec<WorkProgress> {
    [
        "ses-aaaaaaaaaaaa",
        "ses-cccccccccccc",
        "ses-dddddddddddd",
        "ses-eeeeeeeeeeee",
    ]
    .iter()
    .map(|sid| rb_progress(m, r, sid, WorkState::AwaitingResult, "on B"))
    .collect()
}

/// The replies recorded for `m`.
fn rb_replies(rig: &LocalRig, m: &str) -> usize {
    rb_remote(rig, m)
        .into_iter()
        .filter(|row| row.4.is_some())
        .count()
}

/// Review N1 (a), ruling R49: objects signed beyond this host's device
/// list wait for the list, never counted toward the bound of results
/// waiting for their status, and none is dropped: past half the sender's
/// share they all stay, and once the list catches up the status and every
/// result apply.
#[test]
fn results_waiting_for_this_hosts_list_are_never_dropped() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        rig.bridge.work.mail_limits.results_per_sender = 4;
        let (m, r) = rb_send(&mut rig);
        let tasks: Vec<_> = rb_four(&m, &r).into_iter().take(3).collect();
        // B signs at a head this host doesn't hold yet.
        let entry = host.s.log.append(
            MAC,
            atem_client::membership::project_set("later", ["host", "host-b"], task_ops(), 0)
                .unwrap(),
        );
        let ahead = host.s.log.log.head();
        let mut objects: Vec<Value> = tasks
            .iter()
            .map(|t| rb_from_b_at(&rig, &host, ahead, &rb_reply(&t.task_id, "ahead")))
            .collect();
        let status = rb_status(&m, &r, Delivery::Resolved { tasks });
        objects.push(rb_from_b_at(&rig, &host, ahead, &status));
        rb_receive(&mut rig, &mut host, &objects);
        rb_pass(&mut rig);
        assert_eq!(rows(&rig, "mailbox_results"), 4, "all wait, none dropped");
        carry(&mut rig, &host.s.log, entry);
        mb_tick(&mut rig, &mut host, 0);
        rb_pass(&mut rig);
        assert_eq!(rows(&rig, "mailbox_results"), 0);
        assert_eq!(rb_replies(&rig, &m), 3);
    });
}

/// Review N1 (b) and (c), ruling R49: a result that would wait for its
/// status while its sender's waiting results already hold their half of
/// the share is left on the Station (no row, no done), never dropped; a
/// drain applies the status it holds before it decides about results, so
/// the results waiting ahead of it apply in that same drain; room frees,
/// the read rewinds, and the result left there is read again and applies.
#[test]
fn a_result_over_the_waiting_bound_is_left_on_the_station_and_read_again() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        rig.bridge.work.mail_limits.results_per_sender = 4;
        let now = host_now().wall_ms;
        let (m, r) = rb_send(&mut rig);
        let tasks: Vec<_> = rb_four(&m, &r).into_iter().take(3).collect();
        let results: Vec<Value> = tasks
            .iter()
            .map(|t| rb_from_b(&rig, &host, now, &rb_reply(&t.task_id, "early")))
            .collect();
        let status = rb_from_b(
            &rig,
            &host,
            now,
            &rb_status(&m, &r, Delivery::Resolved { tasks }),
        );
        let page = |rig: &mut LocalRig, object: &Value| {
            let syncs = ad_syncs(rig);
            mb_receive(rig, &mb_page(&syncs[0], 4, std::slice::from_ref(object)));
        };
        mb_heads(&mut rig, MB_MAILBOX, 4);
        for object in results.iter().chain([&status]) {
            page(&mut rig, object);
        }
        let observed = mb_store(&rig);
        assert!(observed.skipped, "the third left on the Station");
        assert_eq!(observed.owed, [1, 2, 4], "no done for it");
        assert_eq!(rows(&rig, "mailbox_results"), 3);
        rig.bridge.results_drain();
        assert_eq!(rows(&rig, "mailbox_results"), 0);
        assert_eq!(rb_replies(&rig, &m), 2, "both applied in that drain");
        // Room freed: the read rewinds to just before it.
        mb_tick(&mut rig, &mut host, 1_000);
        let syncs = ad_syncs(&mut rig);
        assert_eq!(syncs[0].after, 2, "read again from just before it");
        mb_receive(&mut rig, &mb_page(&syncs[0], 4, &[results[2].clone()]));
        rb_pass(&mut rig);
        assert_eq!(rb_replies(&rig, &m), 3);
    });
}

/// Review N2: the waiting bound counts bytes too, half the results' byte
/// budget: a second waiting result that would pass it is left on the
/// Station though the count allows it.
#[test]
fn the_waiting_bound_counts_bytes_too() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let host = sp_host(&mut rig, root, &os);
        let now = host_now().wall_ms;
        let (m, r) = rb_send(&mut rig);
        let tasks: Vec<_> = rb_four(&m, &r).into_iter().take(2).collect();
        let results: Vec<Value> = tasks
            .iter()
            .map(|t| rb_from_b(&rig, &host, now, &rb_reply(&t.task_id, "early")))
            .collect();
        let size = results[0].to_string().len() as u64;
        // Room for both in the budget, but half of it holds one.
        rig.bridge.work.mail_limits.result_bytes = 3 * size;
        let page = |rig: &mut LocalRig, object: &Value| {
            let syncs = ad_syncs(rig);
            mb_receive(rig, &mb_page(&syncs[0], 2, std::slice::from_ref(object)));
        };
        mb_heads(&mut rig, MB_MAILBOX, 2);
        for object in &results {
            page(&mut rig, object);
        }
        assert_eq!(rows(&rig, "mailbox_results"), 1);
        assert!(mb_store(&rig).skipped);
    });
}

/// Review N3: the task-id reuse check and the per-host read of the
/// recorded resolutions use an index, never a scan of `remote_tasks`
/// (kept for good).
#[test]
fn the_remote_task_reads_use_an_index() {
    use crate::runtime::delegated::results_back::{RECORDED_ELSEWHERE, RECORDED_OF_HOST};
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = sp_host(&mut rig, root, &os);
        let db = &rig.bridge.work.store.as_ref().unwrap().db;
        for sql in [RECORDED_ELSEWHERE, RECORDED_OF_HOST] {
            let mut q = db.prepare(&format!("EXPLAIN QUERY PLAN {sql}")).unwrap();
            let n = q.parameter_count();
            let steps: Vec<String> = q
                .query_map(
                    rusqlite::params_from_iter(std::iter::repeat_n("x", n)),
                    |r| r.get(3),
                )
                .unwrap()
                .map(Result::unwrap)
                .collect();
            assert!(
                steps.iter().any(|s| s.contains("INDEX remote_tasks_host"))
                    && !steps.iter().any(|s| s.starts_with("SCAN remote_tasks")),
                "{sql}: {steps:?}"
            );
        }
    });
}

/// Review N4: an owed result that keeps failing never blocks the later
/// ones (each is tried on its own), and it is settled (its mark cleared)
/// after a bounded number of tries and a minute on the monotonic clock.
#[test]
fn an_owed_result_that_keeps_failing_blocks_no_other() {
    use super::super::delegated_admit_pass::MAX_ADMIT_FAILURES;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = sp_host(&mut rig, root, &os);
        let (_, first) = rb_task(&mut rig);
        let (_, second) = rb_task(&mut rig);
        let (a, b) = (first.task.task_id.clone(), second.task.task_id.clone());
        reply(&mut rig, &a, "one", &[]).unwrap();
        reply(&mut rig, &b, "two", &[]).unwrap();
        // The one owed first, in the owed rows' order, always fails.
        let failing = a.clone().min(b.clone());
        let other = if failing == a { b.clone() } else { a.clone() };
        let db = &rig.bridge.work.store.as_ref().unwrap().db;
        db.execute_batch(&format!(
            "CREATE TRIGGER t_fail BEFORE INSERT ON mail_result_sent
            WHEN NEW.task_id='{failing}' BEGIN SELECT RAISE(ABORT,'always'); END;"
        ))
        .unwrap();
        rig.bridge.mail_statuses();
        let sent: Vec<String> = rb_results(&rig).into_iter().map(|r| r.1).collect();
        assert_eq!(sent, [other], "the later one went");
        for _ in 1..MAX_ADMIT_FAILURES + 4 {
            rig.bridge.mail_statuses();
        }
        assert_eq!(rows(&rig, "mail_result_owed"), 1, "not within a minute");
        rig.bridge.clock.skip(60_000);
        rig.bridge.mail_statuses();
        assert_eq!(rows(&rig, "mail_result_owed"), 0, "settled");
    });
}

/// Review N5: with host senders turned off, a leftover remote delivery
/// waits without holding its session (a local task for that session
/// still runs) and expires at its deadline.
#[test]
fn with_the_hook_off_a_leftover_delivery_holds_no_session() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        rig.bridge.work.config.routes[0].results = true;
        let (m, _, task) = rb_replied(&mut rig, &mut host, "RB_LEFTOVER");
        rig.bridge.remote_deliveries(&rig.sessions);
        rig.bridge.features = HostFeatures::parse("host.delegated").unwrap();
        let local = rig.message();
        rig.publish(&local);
        rig.until(|r| {
            std::fs::read_to_string(r.fake.join("input"))
                .is_ok_and(|i| i.contains("COLLAB_TEST_PROMPT"))
        })
        .await;
        let delivery = rb_delivery(&m, &task);
        let record = |rig: &LocalRig| {
            rig.bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .work(&delivery)
                .unwrap()
                .unwrap()
        };
        assert_eq!(
            (record(&rig).status.state, record(&rig).status.detail),
            (
                WorkState::Blocked,
                "host senders are off on this host".into()
            )
        );
        let mut past = record(&rig);
        past.task.expires_at = host_now().wall_ms - 1;
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .save_work(&past)
            .unwrap();
        rig.until(|r| record(r).status.state == WorkState::Expired)
            .await;
        let input = std::fs::read_to_string(rig.fake.join("input")).unwrap();
        assert!(!input.contains("RB_LEFTOVER"));
    });
}

// ------------------------------------------------------- fix round 3

/// Review R3: a store-wide fault (here the store full: no page left for
/// the result's object, though a row can still be removed) lasting longer
/// than the settle window never settles an owed result: it isn't the
/// result's own failure. It stays owed, and goes once the fault clears.
#[test]
fn a_store_fault_longer_than_the_settle_window_loses_no_result() {
    use super::super::delegated_admit_pass::MAX_ADMIT_FAILURES;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = sp_host(&mut rig, root, &os);
        let (_, task) = rb_task(&mut rig);
        let id = task.task.task_id.clone();
        // Large enough to need pages of its own (overflow pages).
        reply(&mut rig, &id, &"x".repeat(12_000), &[]).unwrap();
        // Full: a page limit just above the store, the room left filled.
        let db = &rig.bridge.work.store.as_ref().unwrap().db;
        let (pages, max): (i64, i64) = db
            .query_row(
                "SELECT page_count, max_page_count FROM pragma_page_count, pragma_max_page_count",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        db.execute_batch(&format!(
            "CREATE TABLE rb_filler(b BLOB); PRAGMA max_page_count={}",
            pages + 4
        ))
        .unwrap();
        while db
            .execute("INSERT INTO rb_filler(b) VALUES(zeroblob(64))", [])
            .is_ok()
        {}
        for _ in 0..MAX_ADMIT_FAILURES + 4 {
            rig.bridge.mail_statuses();
        }
        rig.bridge.clock.skip(120_000);
        rig.bridge.mail_statuses();
        assert!(rb_results(&rig).is_empty(), "the store is full");
        assert_eq!(rows(&rig, "mail_result_owed"), 1, "still owed");
        let db = &rig.bridge.work.store.as_ref().unwrap().db;
        db.execute_batch(&format!("PRAGMA max_page_count={max}"))
            .unwrap();
        rig.bridge.mail_statuses();
        let results = rb_results(&rig);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].1, id);
        assert_eq!(rows(&rig, "mail_result_owed"), 0);
    });
}

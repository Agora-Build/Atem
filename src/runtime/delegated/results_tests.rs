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

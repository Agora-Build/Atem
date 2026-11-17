// Admission of host senders' mail on the receiving host, in the bridge
// (design II.4.2 step 7, II.4.4, II.6, II.7; host-work-v1 §11.5): the
// sending host's rig turned round (`sp_host`: host B has an encryption key,
// project `build` lists this host and B with a task's ops, and route `rh`
// consents to `project:build`); B's objects reach the inbox through this
// host's mailbox, or are written there as the mailbox writes them; then
// admission (`admit_mail`) and the statuses owed (`mail_statuses`). B's
// statuses are opened with B's key and the shared core. Every name here
// starts with `ad_`.

use crate::runtime::delegated::admit;
use atem_client::host_mail::{EnvelopePlain, ResultPlain};
use atem_client::session::messages::{Delivery, RecipientReceipt, WorkProgress};

/// B as this host's own host senders' tests name it.
const AD_B: &str = "host-b";

/// This host as B addresses it.
fn ad_here(rig: &LocalRig) -> HostTarget {
    rig.bridge.work_host()
}

/// B's Message to this host, one recipient per destination: fresh ids,
/// alive an hour.
fn ad_message(rig: &LocalRig, destinations: Vec<Destination>) -> Message {
    let now = host_now().wall_ms;
    Message {
        message_id: uuid::Uuid::new_v4().to_string(),
        workflow_id: uuid::Uuid::new_v4().to_string(),
        sender: "host:host-b".into(),
        kind: Default::default(),
        reply_to: None,
        from_session: None,
        created_at: now - 1_000,
        expires_at: now + HOUR,
        recipients: destinations
            .into_iter()
            .map(|destination| Recipient {
                recipient_id: uuid::Uuid::new_v4().to_string(),
                host: ad_here(rig),
                destination,
            })
            .collect(),
        text: "AD_TASK".into(),
        context: vec![],
        mark: None,
    }
}

fn ad_select(selectors: &[&str], budget: u32) -> Destination {
    Destination::Select {
        selectors: selectors.iter().map(|s| s.to_string()).collect(),
        budget,
        launch: false,
    }
}

/// `plain` as B's envelope `id` to this host (its times `created_at` and
/// `expires_at`), signed at this list's head, sealed with the shared core.
fn ad_seal(
    rig: &LocalRig,
    host: &MbHost,
    id: &str,
    created_at: u64,
    expires_at: u64,
    plain: &EnvelopePlain,
) -> Value {
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
        id: id.into(),
        created_at,
        expires_at,
        signed_at_head: list.head(),
    };
    atem_client::host_mail::seal_envelope(
        &host.sender,
        &atem_client::KeyId::new("host-b"),
        &fields,
        plain,
        &host.enc_pub,
    )
    .unwrap()
    .to_json()
}

/// B's request of `message`.
fn ad_request(rig: &LocalRig, host: &MbHost, message: &Message) -> Value {
    ad_seal(
        rig,
        host,
        &message.message_id,
        message.created_at,
        message.expires_at,
        &EnvelopePlain::Request {
            message: message.clone(),
        },
    )
}

/// The mailbox calls the bridge hands the link now: its syncs (the dones
/// and puts taken with them).
fn ad_syncs(rig: &mut LocalRig) -> Vec<atem_client::host_mail::mailbox::MailboxSync> {
    use crate::runtime::delegated::station::Call;
    rig.bridge
        .mail_outgoing()
        .into_iter()
        .filter_map(|call| match call {
            Call::MailboxSync(sync) => Some(sync),
            _ => None,
        })
        .collect()
}

/// `objects` reach this host's mailbox: each announced, asked for and
/// committed in its own page (a page lists one object), a pause first when
/// no sync is asked at once (it retires any live one); none: one empty
/// page read to the head.
fn ad_deliver(rig: &mut LocalRig, host: &mut MbHost, objects: &[Value]) {
    let pages: Vec<&[Value]> = if objects.is_empty() {
        vec![&[]]
    } else {
        objects.chunks(1).collect()
    };
    for page in pages {
        let at = mb_store(rig).cursor.map_or(0, |(_, at)| at);
        let head = at + page.len() as u64;
        mb_heads(rig, MB_MAILBOX, head);
        let mut syncs = ad_syncs(rig);
        if syncs.is_empty() {
            mb_tick(rig, host, 36_000);
            mb_heads(rig, MB_MAILBOX, head);
            syncs = ad_syncs(rig);
        }
        mb_receive(rig, &mb_page(&syncs[0], head, page));
    }
}

/// `plain`, B's object `id`, written into the inbox as the mailbox writes
/// an opened one (signed at this list's head unless `signed_seq`).
fn ad_inbox(
    rig: &LocalRig,
    id: &str,
    expires_at: u64,
    signed_seq: Option<u64>,
    plain: &EnvelopePlain,
) {
    let seq = signed_seq.unwrap_or_else(|| rig.bridge.membership.as_ref().unwrap().head().seq);
    let kind = match plain {
        EnvelopePlain::Request { .. } => "request",
        EnvelopePlain::Cancel { .. } => "cancel",
        EnvelopePlain::Complete { .. } => "complete",
    };
    rig.bridge
        .work
        .store
        .as_ref()
        .unwrap()
        .db
        .execute(
            "INSERT INTO mailbox_inbox(sender_host, object_id, kind, plain, object_hash, at_ms,
                expires_at, signed_seq) VALUES('host-b', ?1, ?2, ?3, 'x', 0, ?4, ?5)",
            rusqlite::params![
                id,
                kind,
                plain.to_bytes().unwrap().as_slice(),
                expires_at,
                seq
            ],
        )
        .unwrap();
}

/// B's request of `message`, written into the inbox.
fn ad_inbox_request(rig: &LocalRig, message: &Message) {
    ad_inbox(
        rig,
        &message.message_id,
        message.expires_at,
        None,
        &EnvelopePlain::Request {
            message: message.clone(),
        },
    );
}

/// B's `cancel` (or with `result` its `complete`) of `task_id`, written
/// into the inbox: its object id.
fn ad_inbox_stop(rig: &LocalRig, task_id: &str, complete: bool, expires_at: u64) -> String {
    let id = uuid::Uuid::new_v4().to_string();
    let plain = if complete {
        EnvelopePlain::Complete {
            task_id: task_id.into(),
            result: ad_snapshot(),
        }
    } else {
        EnvelopePlain::Cancel {
            task_id: task_id.into(),
        }
    };
    ad_inbox(rig, &id, expires_at, None, &plain);
    id
}

/// A result snapshot, as `work_complete` takes one.
fn ad_snapshot() -> hw::ContextSnapshot {
    hw::ContextSnapshot {
        kind: hw::ContextKind::Memory,
        id: "mem_ad".into(),
        version: 1,
        digest: hw::digest(b"done"),
        text: "done".into(),
    }
}

/// One admission pass.
fn ad_admit(rig: &mut LocalRig) {
    rig.bridge.admit_mail(&rig.sessions);
}

/// The inbox's rows now.
fn ad_inbox_rows(rig: &LocalRig) -> i64 {
    rows(rig, "mailbox_inbox")
}

/// The statuses enqueued for B, oldest first: the engine row's state and
/// the plaintext, opened with B's key after its signature verified with
/// this host's key.
fn ad_statuses(rig: &LocalRig) -> Vec<(String, ResultPlain)> {
    use crate::session_protocol::membership::r9log::secret;
    let db = &rig.bridge.work.store.as_ref().unwrap().db;
    let mut q = db
        .prepare(
            "SELECT state, bytes FROM mail_outbox WHERE kind='atem-result' AND target_host='host-b'
            ORDER BY n",
        )
        .unwrap();
    let rows: Vec<(String, Vec<u8>)> = q
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    let me = rig.bridge.host_key.as_ref().unwrap().public_key().unwrap();
    let mut keys = atem_client::SoftwareKeys::new();
    keys.insert_x25519(atem_client::KeyId::new("enc"), &secret("host b enc"));
    rows.into_iter()
        .map(|(state, bytes)| {
            let object = atem_client::host_mail::parse_object(&bytes).unwrap();
            let verified = atem_client::host_mail::VerifiedMail::verify(&object, &me).unwrap();
            let plain = atem_client::host_mail::unseal_result(
                &keys,
                &atem_client::KeyId::new("enc"),
                &verified,
            )
            .unwrap();
            (state, plain)
        })
        .collect()
}

/// The latest status's plaintext.
fn ad_latest(rig: &LocalRig) -> ResultPlain {
    ad_statuses(rig).pop().expect("a status").1
}

/// The receipts of `message`'s latest status.
fn ad_receipts(rig: &LocalRig, message: &Message) -> Vec<RecipientReceipt> {
    ad_statuses(rig)
        .into_iter()
        .rev()
        .find_map(|(_, plain)| match plain {
            ResultPlain::Status {
                message_id,
                recipients,
            } if message_id == message.message_id => Some(recipients),
            _ => None,
        })
        .expect("a status of the message")
}

/// A recipient's resolved tasks.
fn ad_resolved(receipt: &RecipientReceipt) -> &[WorkProgress] {
    match &receipt.delivery {
        Delivery::Resolved { tasks } => tasks,
        other => panic!("not resolved: {other:?}"),
    }
}

/// Whether host sender `host_id`'s tasks may start as far as host
/// senders' gate goes (its Station's part stood in open).
fn ad_gate_for(rig: &LocalRig, host_id: &str) -> bool {
    use crate::runtime::delegated::gate::GateView;
    rig.bridge.start_view().gates.open_for(
        &DelegatedSender::Host {
            host_id: host_id.into(),
            generation: 1,
            epoch: 1,
        },
        Some(ORIGIN),
    )
}

/// The tasks of `message` on this host.
fn ad_tasks(rig: &LocalRig, message: &Message) -> Vec<WorkRecord> {
    let db = &rig.bridge.work.store.as_ref().unwrap().db;
    let mut q = db
        .prepare(
            "SELECT record FROM work WHERE json_extract(record,'$.message.message_id')=?1
            ORDER BY rowid",
        )
        .unwrap();
    q.query_map([&message.message_id], |r| r.get::<_, String>(0))
        .unwrap()
        .map(|r| serde_json::from_str(&r.unwrap()).unwrap())
        .collect()
}

/// `task`'s state set by hand (as a dispatch or a reply would move it).
fn ad_set_state(rig: &LocalRig, task: &WorkRecord, state: WorkState) {
    let mut r = task.clone();
    r.status.state = state;
    // A completed task carries its result (`work_complete`'s).
    r.status.result = (state == WorkState::Completed).then(ad_snapshot);
    rig.bridge
        .work
        .store
        .as_ref()
        .unwrap()
        .save_work(&r)
        .unwrap();
}

/// A status's single recipient's single task, with its state.
fn ad_one_state(rig: &LocalRig, message: &Message) -> (WorkState, String) {
    let receipts = ad_receipts(rig, message);
    let task = &ad_resolved(&receipts[0])[0];
    (task.state, task.detail.clone())
}

/// A request to this host's agents (`atem:host`) through the mailbox
/// becomes one task, delegated as host B's (its admission recorded from
/// B's permit through `rh`), the message's record and its status, all in
/// one commit (read by another connection) with the inbox row gone; the
/// status is a `resolved` receipt naming the selector task id (§11.5's
/// derivation, checked against the shared vector) and put until stored.
/// With the inbox drained and the head read, host senders' gate opens.
#[test]
fn a_request_is_admitted_with_its_status_in_one_commit() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let message = ad_message(&rig, vec![ad_select(&["atem:host"], 4)]);
        let object = ad_request(&rig, &host, &message);
        ad_deliver(&mut rig, &mut host, &[object]);
        assert_eq!(ad_inbox_rows(&rig), 1, "opened, waiting for admission");
        assert!(!mb_gate(&rig), "the inbox holds the gate");
        ad_admit(&mut rig);
        let other = Store::open(&root.join("runtime")).unwrap();
        let (tasks, inbox, statuses): (i64, i64, i64) = other
            .db
            .query_row(
                "SELECT (SELECT count(*) FROM work WHERE json_extract(record,'$.principal')='host:host-b'),
                    (SELECT count(*) FROM mailbox_inbox),
                    (SELECT count(*) FROM mail_outbox WHERE kind='atem-result')",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!((tasks, inbox, statuses), (1, 0, 1));
        let task = &ad_tasks(&rig, &message)[0];
        assert_eq!(task.principal, "host:host-b");
        assert_eq!(task.route_id, "rh");
        assert_eq!(task.status.state, WorkState::Queued);
        assert_eq!(task.task.target.session_id, rig.sid.as_str());
        let admission = task.delegated.as_ref().expect("delegated");
        assert_eq!(admission.principal, "host:host-b");
        let grant = admission.host.as_ref().unwrap();
        assert_eq!(grant.consent, "project:build");
        let expected = atem_client::session::select::selector_task_id(
            &message.message_id,
            &message.recipients[0].recipient_id,
            rig.sid.as_str(),
        );
        assert_eq!(task.task.task_id, expected);
        // The derivation admission calls is §11.5's (its shared vector).
        assert_eq!(
            atem_client::session::select::selector_task_id(
                "3f1e2d4c-5b6a-4978-8a9b-0c1d2e3f4a5b",
                "7c6b5a49-3827-4e16-9d05-f4e3d2c1b0a9",
                "ses-ab23cd45ef67"
            ),
            "80160896-4fcd-5e6e-adac-98bac5497321"
        );
        let receipts = ad_receipts(&rig, &message);
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].recipient_id, message.recipients[0].recipient_id);
        let resolved = ad_resolved(&receipts[0]);
        assert_eq!(resolved.len(), 1);
        assert_eq!(resolved[0].task_id, expected);
        assert_eq!(resolved[0].state, WorkState::Queued);
        assert_eq!(ad_statuses(&rig)[0].0, "queued", "put until stored");
        assert!(mb_gate(&rig), "the inbox drained, the head read");
    });
}

/// §11.5 "Status forms": a selector matching no agent of a consenting
/// route is `no_match`; with no project B shares granting a task's ops, a
/// `select` is `refused{forbidden}` while a host notice (`message` alone)
/// is `stored`; an agent recipient on a route that doesn't consent to B is
/// `refused{forbidden}`. Nothing is queued for any of them.
#[test]
fn select_resolves_to_no_match_or_forbidden() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let none = ad_message(&rig, vec![ad_select(&["tag:nobody"], 4)]);
        ad_inbox_request(&rig, &none);
        ad_admit(&mut rig);
        let receipts = ad_receipts(&rig, &none);
        assert_eq!(receipts[0].delivery, Delivery::NoMatch {});
        // An agent recipient on route `r` (it consents to `local` only).
        let host_target = ad_here(&rig);
        let agent = Destination::Agent {
            route_id: "r".into(),
            route_revision: 1,
            target: wire::Target {
                account_id: host_target.account_id.clone(),
                atem_device_id: host_target.atem_device_id.clone(),
                host_trust_gen: host_target.host_trust_gen,
                session_id: rig.sid.to_string(),
                process_gen: rig.sessions[&rig.sid].process_gen.clone(),
            },
        };
        let not_consented = ad_message(&rig, vec![agent]);
        ad_inbox_request(&rig, &not_consented);
        ad_admit(&mut rig);
        assert_eq!(
            ad_receipts(&rig, &not_consented)[0].delivery,
            Delivery::Refused {
                code: "forbidden".into()
            }
        );
        // The project narrowed to `message`: no task's ops.
        sign_and_carry(
            &mut rig,
            &mut host.s,
            project_set("build", ["host", "host-b"], [ProjectOp::Message], 0).unwrap(),
        );
        rig.bridge.sync_list_view();
        mb_tick(&mut rig, &mut host, 0);
        let narrowed = ad_message(&rig, vec![ad_select(&["atem:host"], 4), Destination::Host]);
        ad_inbox_request(&rig, &narrowed);
        ad_admit(&mut rig);
        let receipts = ad_receipts(&rig, &narrowed);
        assert_eq!(
            receipts[0].delivery,
            Delivery::Refused {
                code: "forbidden".into()
            }
        );
        assert_eq!(receipts[1].delivery, Delivery::Stored {});
        for m in [&none, &not_consented, &narrowed] {
            assert!(ad_tasks(&rig, m).is_empty());
        }
        assert_eq!(ad_inbox_rows(&rig), 0);
    });
}

/// A session of route `rh`'s profile besides the rig's: its id (not
/// waited for: a candidate once added).
async fn ad_second_session(rig: &mut LocalRig, root: &Path) -> SessionId {
    let launcher = Launcher::InProcess(InProcess {
        state: root.join("runtime"),
        socket_dir: root.join("ws"),
        chat_root: root.join("chat"),
    });
    let request = SpawnRequest {
        session_id: SessionId::new(),
        process_gen: uuid::Uuid::new_v4().to_string(),
        provider: crate::session::Provider::Claude,
        args: vec![],
        cwd: root.join("project"),
        rows: 24,
        cols: 80,
    };
    let fake = root.join("fake-second");
    std::fs::create_dir_all(&fake).unwrap();
    let bin =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/approvals/fake-agent.py");
    let (handle, created) = launcher
        .spawn(
            request.clone(),
            LaunchEnv(vec![
                ("PATH".into(), "/usr/bin:/bin".into()),
                ("HOME".into(), root.display().to_string()),
                ("CLAUDE_CLI_BIN".into(), bin.display().to_string()),
                ("FAKE_DIR".into(), fake.display().to_string()),
            ]),
        )
        .await
        .unwrap();
    let sid = request.session_id.clone();
    rig.sessions.insert(
        sid.clone(),
        BrokerSession::launched(handle, &request, created),
    );
    rig.bridge.session_added(&sid);
    sid
}

/// A recipient's budget bounds its resolution (two agents match, budget 1:
/// one task, in resolve's fixed order), and a second recipient reaches
/// both; recipients for another host (another device, or this one at
/// another trust generation) are left out of the status, and a request
/// with none for this host is refused `stale_target`.
#[test]
fn budgets_bound_a_selector_and_other_hosts_recipients_are_ignored() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = sp_host(&mut rig, root, &os);
        let second = ad_second_session(&mut rig, root).await;
        let mut message = ad_message(
            &rig,
            vec![
                ad_select(&["atem:host"], 1),
                ad_select(&["atem:host/rh"], 2),
                Destination::Host,
            ],
        );
        // Its third recipient is another host's.
        message.recipients[2].host.atem_device_id = "host-c".into();
        ad_inbox_request(&rig, &message);
        ad_admit(&mut rig);
        let receipts = ad_receipts(&rig, &message);
        assert_eq!(receipts.len(), 2, "only this host's recipients");
        let first = ad_resolved(&receipts[0]);
        assert_eq!(first.len(), 1, "budget 1");
        assert_eq!(ad_resolved(&receipts[1]).len(), 2);
        // Resolve's order: the route, then the session's start.
        let order: Vec<_> = ad_resolved(&receipts[1])
            .iter()
            .map(|t| t.task_id.clone())
            .collect();
        let sessions: Vec<_> = [rig.sid.clone(), second.clone()]
            .iter()
            .map(|sid| {
                atem_client::session::select::selector_task_id(
                    &message.message_id,
                    &message.recipients[1].recipient_id,
                    sid.as_str(),
                )
            })
            .collect();
        assert_eq!(order, sessions);
        assert_eq!(ad_tasks(&rig, &message).len(), 3);
        // None for this host's current triple: refused.
        let mut stale = ad_message(&rig, vec![ad_select(&["atem:host"], 1)]);
        stale.recipients[0].host.host_trust_gen = 2;
        ad_inbox_request(&rig, &stale);
        ad_admit(&mut rig);
        assert_eq!(
            ad_latest(&rig),
            ResultPlain::Refusal {
                object_id: stale.message_id.clone(),
                refused: "stale_target".into()
            }
        );
        assert!(ad_tasks(&rig, &stale).is_empty());
    });
}

/// Design II.4.2 "Duplicates", entry criterion 2: the same request again
/// re-sends its current status and changes nothing; the same id with other
/// content is `request_id_reused`, the first standing; an id another
/// principal used here is `request_id_reused` too. After the mailbox's
/// claims were pruned, a copy of the request that comes through the
/// mailbox again is still deduplicated against the message record.
#[test]
fn duplicates_are_judged_against_the_message_records() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let message = ad_message(&rig, vec![ad_select(&["atem:host"], 1)]);
        let object = ad_request(&rig, &host, &message);
        ad_deliver(&mut rig, &mut host, std::slice::from_ref(&object));
        ad_admit(&mut rig);
        assert_eq!(ad_tasks(&rig, &message).len(), 1);
        // The same content again: its status again, nothing else.
        ad_inbox_request(&rig, &message);
        ad_admit(&mut rig);
        assert_eq!(ad_tasks(&rig, &message).len(), 1);
        assert_eq!(ad_statuses(&rig).len(), 2);
        assert_eq!(ad_receipts(&rig, &message).len(), 1);
        // Other content under its id.
        let mut other = message.clone();
        other.text = "AD_OTHER".into();
        ad_inbox_request(&rig, &other);
        ad_admit(&mut rig);
        assert_eq!(
            ad_latest(&rig),
            ResultPlain::Refusal {
                object_id: message.message_id.clone(),
                refused: "request_id_reused".into()
            }
        );
        assert_eq!(ad_tasks(&rig, &message)[0].task.prompt, "AD_TASK");
        // An id the local sender used here.
        let local = rig.message();
        rig.publish(&local);
        let mut taken = ad_message(&rig, vec![ad_select(&["atem:host"], 1)]);
        taken.message_id = local.message_id.clone();
        ad_inbox_request(&rig, &taken);
        ad_admit(&mut rig);
        assert_eq!(
            ad_latest(&rig),
            ResultPlain::Refusal {
                object_id: local.message_id.clone(),
                refused: "request_id_reused".into()
            }
        );
        // The mailbox's claims pruned (a clock step it saw as synchronized):
        // the same object read again opens again, and admission's own
        // record still deduplicates it.
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .execute("DELETE FROM mailbox_claims", [])
            .unwrap();
        let statuses = ad_statuses(&rig).len();
        ad_deliver(&mut rig, &mut host, &[object]);
        assert_eq!(ad_inbox_rows(&rig), 1, "opened again: no claim");
        ad_admit(&mut rig);
        assert_eq!(ad_tasks(&rig, &message).len(), 1, "admitted once");
        assert_eq!(ad_statuses(&rig).len(), statuses + 1);
        assert_eq!(ad_receipts(&rig, &message).len(), 1);
    });
}

/// VII.B 34 and 35: a request with a mark is refused authenticated when it
/// opens (`attachments_not_allowed`), and so is one whose lifetime is too
/// long (`lifetime_too_long`): each refusal marked for its sender is
/// reported once, `{"kind":"status","object_id","refused":
/// "invalid_request"}`, its mark cleared in that commit. Nothing is queued.
#[test]
fn refusals_marked_for_their_sender_are_reported_once() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let host_target = ad_here(&rig);
        let mut marked = ad_message(
            &rig,
            vec![Destination::Agent {
                route_id: "rh".into(),
                route_revision: 1,
                target: wire::Target {
                    account_id: host_target.account_id.clone(),
                    atem_device_id: host_target.atem_device_id.clone(),
                    host_trust_gen: host_target.host_trust_gen,
                    session_id: rig.sid.to_string(),
                    process_gen: rig.sessions[&rig.sid].process_gen.clone(),
                },
            }],
        );
        marked.mark = Some(atem_client::session::mark::MarkTask {
            mark_id: "mark_ad".into(),
            url: "http://localhost:3000/".into(),
            title: "Page".into(),
            screenshot: atem_client::session::attachments::Attachment {
                attachment_id: uuid::Uuid::new_v4().to_string(),
                digest: hw::digest(b"png"),
                size: 68,
                media_type: "image/png".into(),
            },
            annotations: vec![],
        });
        let mark = ad_request(&rig, &host, &marked);
        let mut long = ad_message(&rig, vec![ad_select(&["atem:host"], 1)]);
        long.expires_at = long.created_at + 2 * hw::MAX_LIFETIME_MS;
        let too_long = ad_request(&rig, &host, &long);
        ad_deliver(&mut rig, &mut host, &[mark, too_long]);
        assert_eq!(ad_inbox_rows(&rig), 0);
        let reports: i64 = rig
            .bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .query_row(
                "SELECT count(*) FROM mailbox_refused WHERE report=1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(reports, 2);
        ad_admit(&mut rig);
        ad_admit(&mut rig);
        let statuses: Vec<ResultPlain> = ad_statuses(&rig).into_iter().map(|(_, p)| p).collect();
        assert_eq!(
            statuses,
            [&marked.message_id, &long.message_id].map(|id| ResultPlain::Refusal {
                object_id: id.clone(),
                refused: "invalid_request".into()
            })
        );
        assert!(ad_tasks(&rig, &marked).is_empty());
    });
}

/// II.9's limits, as a channel member's publish meets them, refuse a host
/// sender's request whole, `busy`, recorded for good (a resend gets
/// `busy` again): `per_workflow` messages per workflow, the 256
/// unfinished tasks, and the unresolved outcomes of its sender.
#[test]
fn the_limits_refuse_a_request_busy() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = sp_host(&mut rig, root, &os);
        let busy = |rig: &LocalRig, m: &Message| {
            assert_eq!(
                ad_latest(rig),
                ResultPlain::Refusal {
                    object_id: m.message_id.clone(),
                    refused: "busy".into()
                }
            );
            assert!(ad_tasks(rig, m).is_empty());
        };
        // `per_workflow`.
        rig.bridge.work.config.collab.per_workflow = 1;
        let first = ad_message(&rig, vec![ad_select(&["atem:host"], 1)]);
        let mut second = ad_message(&rig, vec![ad_select(&["atem:host"], 1)]);
        second.workflow_id = first.workflow_id.clone();
        ad_inbox_request(&rig, &first);
        ad_admit(&mut rig);
        assert_eq!(ad_tasks(&rig, &first).len(), 1);
        ad_inbox_request(&rig, &second);
        ad_admit(&mut rig);
        busy(&rig, &second);
        rig.bridge.work.config.collab.per_workflow = 64;
        ad_inbox_request(&rig, &second);
        ad_admit(&mut rig);
        busy(&rig, &second);
        // The 256 unfinished tasks.
        for i in 0..256 {
            rig.bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .db
                .execute(
                    "INSERT INTO work(id,record,state) VALUES(?1,'{}','queued')",
                    [format!("ad-filler-{i}")],
                )
                .unwrap();
        }
        let full = ad_message(&rig, vec![ad_select(&["atem:host"], 1)]);
        ad_inbox_request(&rig, &full);
        ad_admit(&mut rig);
        busy(&rig, &full);
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .execute("DELETE FROM work WHERE id GLOB 'ad-filler-*'", [])
            .unwrap();
        // B's unresolved outcomes (64 alerts).
        for i in 0..64 {
            rig.bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .db
                .execute(
                    "INSERT INTO alerts(alert_id, seq, task_id, session_id, sender, reason,
                        created_ms) VALUES(?1, ?2, ?1, 'ses-x', 'host:host-b', 'agent exited', 0)",
                    rusqlite::params![format!("ad-alert-{i}"), 1_000 + i],
                )
                .unwrap();
        }
        let unresolved = ad_message(&rig, vec![ad_select(&["atem:host"], 1)]);
        ad_inbox_request(&rig, &unresolved);
        ad_admit(&mut rig);
        busy(&rig, &unresolved);
    });
}

/// Design II.7: B's `cancel` cancels its own queued task (`cancelled
/// before submission`) and its `complete` completes its own task awaiting
/// its result, with the snapshot; one that finds its task running, or
/// not awaiting its result, isn't reached. Each enqueues the message's
/// current status. A complete of a task admitted before a revoke (B
/// revoked, then readmitted) isn't reached either: that task is the
/// owner's.
#[test]
fn cancel_and_complete_reach_only_the_senders_current_tasks() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let expires = host_now().wall_ms + HOUR;
        let message = ad_message(&rig, vec![ad_select(&["atem:host"], 1)]);
        ad_inbox_request(&rig, &message);
        ad_admit(&mut rig);
        let task = ad_tasks(&rig, &message).remove(0);
        // Running: the cancel isn't reached.
        ad_set_state(&rig, &task, WorkState::Submitted);
        ad_inbox_stop(&rig, &task.task.task_id, false, expires);
        ad_admit(&mut rig);
        assert_eq!(ad_one_state(&rig, &message).0, WorkState::Submitted);
        // Queued: cancelled.
        ad_set_state(&rig, &task, WorkState::Queued);
        ad_inbox_stop(&rig, &task.task.task_id, false, expires);
        ad_admit(&mut rig);
        assert_eq!(
            ad_one_state(&rig, &message),
            (WorkState::Cancelled, "cancelled before submission".into())
        );
        // A complete of a queued task isn't reached; awaiting, it completes.
        let message = ad_message(&rig, vec![ad_select(&["atem:host"], 1)]);
        ad_inbox_request(&rig, &message);
        ad_admit(&mut rig);
        let task = ad_tasks(&rig, &message).remove(0);
        ad_inbox_stop(&rig, &task.task.task_id, true, expires);
        ad_admit(&mut rig);
        assert_eq!(ad_one_state(&rig, &message).0, WorkState::Queued);
        ad_set_state(&rig, &task, WorkState::AwaitingResult);
        ad_inbox_stop(&rig, &task.task.task_id, true, expires);
        ad_admit(&mut rig);
        assert_eq!(ad_one_state(&rig, &message).0, WorkState::Completed);
        let done = ad_tasks(&rig, &message).remove(0);
        assert_eq!(done.status.result, Some(ad_snapshot()));
        // Admitted before a revoke and a readmit: the owner's alone (the
        // device list's own effects, which would cancel the queued one, not
        // run here).
        let message = ad_message(&rig, vec![ad_select(&["atem:host"], 1)]);
        ad_inbox_request(&rig, &message);
        ad_admit(&mut rig);
        let task = ad_tasks(&rig, &message).remove(0);
        ad_set_state(&rig, &task, WorkState::AwaitingResult);
        let queued = ad_message(&rig, vec![ad_select(&["atem:host"], 1)]);
        ad_inbox_request(&rig, &queued);
        ad_admit(&mut rig);
        let queued_task = ad_tasks(&rig, &queued).remove(0);
        sign_and_carry(
            &mut rig,
            &mut host.s,
            host_sender_revoke("host-b", false, 0).unwrap(),
        );
        sign_and_carry(
            &mut rig,
            &mut host.s,
            host_sender_readmit("host-b", 0).unwrap(),
        );
        rig.bridge.sync_list_view();
        mb_tick(&mut rig, &mut host, 0);
        ad_inbox_stop(&rig, &task.task.task_id, true, expires);
        ad_inbox_stop(&rig, &queued_task.task.task_id, false, expires);
        ad_admit(&mut rig);
        assert_eq!(ad_one_state(&rig, &message).0, WorkState::AwaitingResult);
        assert_eq!(ad_one_state(&rig, &queued).0, WorkState::Queued);
        assert_eq!(ad_inbox_rows(&rig), 0);
    });
}

/// Ruling R38: a cancel that opens before its request (B named the task by
/// its recipient's id) is kept as an early stop, and its request's
/// admission cancels the task at once; one past its expiry is dropped and
/// the request's task queues; a 33rd early stop of one sender stays in
/// the inbox (holding the gate) until its request comes.
#[test]
fn a_stop_before_its_request_is_kept_and_applied_at_admission() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let now = host_now().wall_ms;
        let host_target = ad_here(&rig);
        let agent = |rig: &LocalRig| Destination::Agent {
            route_id: "rh".into(),
            route_revision: 1,
            target: wire::Target {
                account_id: host_target.account_id.clone(),
                atem_device_id: host_target.atem_device_id.clone(),
                host_trust_gen: host_target.host_trust_gen,
                session_id: rig.sid.to_string(),
                process_gen: rig.sessions[&rig.sid].process_gen.clone(),
            },
        };
        // The mailbox read to its head: the gate's part opens.
        ad_deliver(&mut rig, &mut host, &[]);
        assert!(mb_gate(&rig));
        let early = ad_message(&rig, vec![agent(&rig)]);
        let task_id = early.recipients[0].recipient_id.clone();
        ad_inbox_stop(&rig, &task_id, false, now + HOUR);
        ad_admit(&mut rig);
        assert_eq!(ad_inbox_rows(&rig), 0);
        assert_eq!(
            admit::stops(&rig.bridge.work.store.as_ref().unwrap().db).unwrap(),
            [("host-b".to_string(), task_id.clone(), "cancel".to_string())]
        );
        ad_inbox_request(&rig, &early);
        ad_admit(&mut rig);
        let receipts = ad_receipts(&rig, &early);
        let Delivery::Work { work } = &receipts[0].delivery else {
            panic!("not work");
        };
        assert_eq!(work.state, WorkState::Cancelled);
        assert!(
            admit::stops(&rig.bridge.work.store.as_ref().unwrap().db)
                .unwrap()
                .is_empty()
        );
        // Past its expiry on `D`: dropped by the minute prune, the
        // request's task queues.
        let late = ad_message(&rig, vec![agent(&rig)]);
        ad_inbox_stop(&rig, &late.recipients[0].recipient_id, false, now + 60_000);
        ad_admit(&mut rig);
        sp_d(&rig, now + 60_000);
        rig.bridge.work.mail_pruned_at = None;
        mb_tick(&mut rig, &mut host, 1_000);
        assert!(
            admit::stops(&rig.bridge.work.store.as_ref().unwrap().db)
                .unwrap()
                .is_empty()
        );
        sp_d(&rig, now);
        ad_inbox_request(&rig, &late);
        ad_admit(&mut rig);
        assert_eq!(ad_tasks(&rig, &late)[0].status.state, WorkState::Queued);
        // 32 kept; a 33rd stays in the inbox.
        for _ in 0..32 {
            ad_inbox_stop(&rig, &uuid::Uuid::new_v4().to_string(), false, now + HOUR);
        }
        let last = ad_message(&rig, vec![agent(&rig)]);
        ad_inbox_stop(&rig, &last.recipients[0].recipient_id, false, now + HOUR);
        ad_admit(&mut rig);
        assert_eq!(
            admit::stops(&rig.bridge.work.store.as_ref().unwrap().db)
                .unwrap()
                .len(),
            32
        );
        assert_eq!(ad_inbox_rows(&rig), 1, "the 33rd waits");
        mb_tick(&mut rig, &mut host, 0);
        // Ruling R47: it holds its own sender's task starts only.
        assert!(!mb_gate(&rig), "B's tasks wait for its stop");
        assert!(ad_gate_for(&rig, "host-c"), "another sender's don't");
        // Its request: admitted, and the stop waiting in the inbox finds its
        // task at the next pass, queued, and cancels it.
        ad_inbox_request(&rig, &last);
        ad_admit(&mut rig);
        ad_admit(&mut rig);
        assert_eq!(ad_inbox_rows(&rig), 0);
        assert_eq!(ad_tasks(&rig, &last)[0].status.state, WorkState::Cancelled);
        mb_tick(&mut rig, &mut host, 0);
        assert!(mb_gate(&rig));
    });
}

/// II.4.4: a status is owed at every change of a host sender's task's
/// state, marked by the trigger in the statement that changes it (queued,
/// blocked, submitted, awaiting its result, completed; failed by a
/// device-list entry), and sent with every task's current state; a newer
/// status supersedes one not stored yet (the engine settles it, never
/// put), while one stored stays done.
#[test]
fn a_status_is_owed_at_each_change_and_supersedes_the_unstored_one() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let message = ad_message(&rig, vec![ad_select(&["atem:host"], 1)]);
        ad_inbox_request(&rig, &message);
        ad_admit(&mut rig);
        let task = ad_tasks(&rig, &message).remove(0);
        let owed = |rig: &LocalRig| rows(rig, "mail_status_owed");
        assert_eq!(owed(&rig), 0);
        for state in [
            WorkState::Blocked,
            WorkState::Submitted,
            WorkState::AwaitingResult,
            WorkState::Completed,
        ] {
            ad_set_state(&rig, &task, state);
            assert_eq!(owed(&rig), 1, "{state:?}");
            rig.bridge.mail_statuses();
            assert_eq!(owed(&rig), 0);
            assert_eq!(ad_one_state(&rig, &message).0, state);
        }
        // A detail alone changes no state: nothing owed.
        let mut r = ad_tasks(&rig, &message).remove(0);
        r.status.detail = "another detail".into();
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .save_work(&r)
            .unwrap();
        assert_eq!(owed(&rig), 0);
        // Superseded: every status but the newest settled unput.
        let states: Vec<String> = ad_statuses(&rig).into_iter().map(|(s, _)| s).collect();
        assert_eq!(states, ["done", "done", "done", "done", "queued"]);
        // One stored stays as it was when a newer one comes.
        let put = sp_out(&mut rig);
        assert_eq!(put.len(), 1);
        sp_stored(&mut rig, &put[0]);
        // A device-list narrowing fails an unstarted task: owed, sent.
        let queued = ad_message(&rig, vec![ad_select(&["atem:host"], 1)]);
        ad_inbox_request(&rig, &queued);
        ad_admit(&mut rig);
        sign_and_carry(
            &mut rig,
            &mut host.s,
            project_set("build", ["host", "host-b"], [ProjectOp::Message], 0).unwrap(),
        );
        rig.bridge.sync_list_view();
        rig.bridge.host_senders_pass();
        assert_eq!(owed(&rig), 1);
        rig.bridge.mail_statuses();
        assert_eq!(
            ad_one_state(&rig, &queued),
            (WorkState::Failed, "sender's authorization narrowed".into())
        );
        let states: Vec<String> = ad_statuses(&rig).into_iter().map(|(s, _)| s).collect();
        assert_eq!(states[4], "done", "stored, not superseded");
        // A task awaiting its result at its deadline expires (`settle_due`):
        // owed, sent.
        let late = ad_message(&rig, vec![ad_select(&["atem:host"], 1)]);
        sign_and_carry(
            &mut rig,
            &mut host.s,
            project_set("build", ["host", "host-b"], task_ops(), 0).unwrap(),
        );
        rig.bridge.sync_list_view();
        ad_inbox_request(&rig, &late);
        ad_admit(&mut rig);
        ad_set_state(&rig, &ad_tasks(&rig, &late)[0], WorkState::AwaitingResult);
        rig.bridge.mail_statuses();
        let store = rig.bridge.work.store.as_ref().unwrap();
        store
            .settle_due(late.expires_at, Some(late.expires_at))
            .unwrap();
        assert_eq!(owed(&rig), 1);
        rig.bridge.mail_statuses();
        assert_eq!(ad_one_state(&rig, &late).0, WorkState::Expired);
    });
}

/// Entry criterion 1: admission takes every inbox row whatever host
/// senders' gate says (it waits for the inbox, so admission that waited for
/// it would wait for itself): with the mailbox not read to its head, a pass
/// of the runtime (`work_pass`) admits a request; its task then waits for
/// the gate, `blocked`, revocations not yet checked.
#[test]
fn a_pass_admits_mail_while_the_gate_is_closed() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = sp_host(&mut rig, root, &os);
        assert!(!mb_gate(&rig), "the mailbox isn't read yet");
        let message = ad_message(&rig, vec![ad_select(&["atem:host"], 1)]);
        ad_inbox_request(&rig, &message);
        rig.until(|r| rows(r, "mailbox_inbox") == 0).await;
        let task = ad_tasks(&rig, &message).remove(0);
        assert_eq!(ad_receipts(&rig, &message).len(), 1);
        rig.until(|r| {
            ad_tasks(r, &message)[0].status.detail == details::REVOCATIONS_NOT_YET_CHECKED
        })
        .await;
        assert_eq!(
            ad_tasks(&rig, &message)[0].status.state,
            WorkState::Blocked,
            "{:?}",
            task.status
        );
    });
}

/// II.4.4: a sender with no current encryption key gets no status (the
/// record keeps the state): its request is admitted all the same, and
/// nothing is enqueued.
#[test]
fn no_status_goes_to_a_sender_with_no_key() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = mb_host(&mut rig, root, &os);
        mb_tick(&mut rig, &mut host, 0);
        let message = ad_message(&rig, vec![ad_select(&["atem:host"], 1)]);
        ad_inbox_request(&rig, &message);
        ad_admit(&mut rig);
        assert_eq!(ad_tasks(&rig, &message).len(), 1);
        assert_eq!(rows(&rig, "mail_outbox"), 0);
        ad_set_state(&rig, &ad_tasks(&rig, &message)[0], WorkState::Blocked);
        rig.bridge.mail_statuses();
        assert_eq!(rows(&rig, "mail_outbox"), 0);
        assert_eq!(rows(&rig, "mail_status_owed"), 0, "none owed");
    });
}

/// A crash between the admission's commit and the status's put: the
/// status is in the store (another connection reads it), so a new run of
/// the engine puts exactly those bytes, until stored.
#[test]
fn a_status_committed_before_a_crash_is_put_after_it() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = sp_host(&mut rig, root, &os);
        let message = ad_message(&rig, vec![ad_select(&["atem:host"], 1)]);
        ad_inbox_request(&rig, &message);
        ad_admit(&mut rig);
        let other = Store::open(&root.join("runtime")).unwrap();
        let committed: Vec<u8> = other
            .db
            .query_row(
                "SELECT bytes FROM mail_outbox WHERE kind='atem-result'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        // A new link generation, as after a restart: its own heads first.
        use crate::runtime::delegated::station::LinkKind;
        rig.bridge.station.as_mut().unwrap().sync_link(
            Some(2),
            2,
            || LinkKind::Routed,
            || Some(ORIGIN.into()),
        );
        rig.bridge.station_identity();
        assert!(sp_out(&mut rig).is_empty(), "not before the link's heads");
        mb_heads(&mut rig, MB_MAILBOX, 0);
        let put = sp_out(&mut rig);
        assert_eq!(put.len(), 1);
        assert_eq!(
            put[0].object().to_json().to_string().into_bytes(),
            committed
        );
        sp_stored(&mut rig, &put[0]);
        assert_eq!(ad_statuses(&rig)[0].0, "done");
    });
}

/// Hook off = main: without `host.senders` nothing is admitted, no
/// admission table is made and no status goes.
#[test]
fn without_host_senders_nothing_is_admitted() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _s = host_senders_host(&mut rig, root, &os);
        rig.bridge.features = HostFeatures::parse("host.delegated").unwrap();
        rig.bridge.mail_observe();
        ad_admit(&mut rig);
        rig.bridge.mail_statuses();
        let made: bool = rig
            .bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name GLOB 'mail_*')",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!made);
    });
}

/// The delegated clock takes an unsynchronized forward step (two minutes
/// past its last reading): a forward jump's anchor is pending (or, with
/// `synced`, the OS syncs at that reading and the anchor goes).
fn ad_anchor(rig: &mut LocalRig, os: &ManualOs, synced: bool) {
    let tick = |rig: &mut LocalRig| {
        let work = &mut rig.bridge.work;
        work.clock
            .as_mut()
            .unwrap()
            .tick(work.store.as_ref().unwrap());
    };
    tick(rig);
    {
        let mut r = os.0.lock().unwrap();
        if synced {
            r.synced = crate::runtime::host_clock::os::Synced::Yes;
        } else {
            r.synced = crate::runtime::host_clock::os::Synced::No;
            r.wall_ms += 120_000;
        }
    }
    tick(rig);
    assert_eq!(rig.bridge.work.clock.as_ref().unwrap().anchored(), !synced);
}

/// Review M1: early stops are pruned only by the mailbox's minute prune,
/// never while a forward jump's anchor is pending (`D` may still come back
/// down, and the stop's request still come): admission keeps a stop past
/// its expiry on `D` meanwhile, and one arriving then is kept too, not
/// dropped as expired. Once the anchor goes, the minute prune drops both.
#[test]
fn early_stops_are_never_pruned_under_a_clock_anchor() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let now = host_now().wall_ms;
        let db = |rig: &LocalRig| admit::stops(&rig.bridge.work.store.as_ref().unwrap().db);
        ad_inbox_stop(&rig, &uuid::Uuid::new_v4().to_string(), false, now + 60_000);
        ad_admit(&mut rig);
        assert_eq!(db(&rig).unwrap().len(), 1);
        // `D` past the stop's expiry under an anchor: nothing pruned, and a
        // stop arriving past its expiry is kept.
        ad_anchor(&mut rig, &os, false);
        sp_d(&rig, now + 3 * 60_000);
        ad_inbox_stop(&rig, &uuid::Uuid::new_v4().to_string(), false, now + 60_000);
        ad_admit(&mut rig);
        rig.bridge.work.mail_pruned_at = None;
        mb_tick(&mut rig, &mut host, 1_000);
        assert_eq!(db(&rig).unwrap().len(), 2, "held under the anchor");
        assert_eq!(ad_inbox_rows(&rig), 0);
        // The anchor gone: the minute prune drops them.
        ad_anchor(&mut rig, &os, true);
        ad_admit(&mut rig);
        assert_eq!(db(&rig).unwrap().len(), 2, "admission prunes nothing");
        rig.bridge.work.mail_pruned_at = None;
        mb_tick(&mut rig, &mut host, 1_000);
        assert!(db(&rig).unwrap().is_empty());
    });
}

/// Review M2: a row that can't be decided never wedges the gate. Each row
/// and each report is tried on its own (one that fails skips none of the
/// others), and one still failing after [`MAX_ADMIT_FAILURES`] tries is
/// settled as an unreadable record is: refused `busy` to its sender by its
/// own object id (a request also recorded), removed, one runtime.log line.
#[test]
fn a_row_that_cant_be_decided_is_settled_after_bounded_tries() {
    use super::super::delegated_admit_pass::MAX_ADMIT_FAILURES;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        let message = ad_message(&rig, vec![ad_select(&["atem:host"], 1)]);
        ad_inbox_request(&rig, &message);
        ad_admit(&mut rig);
        let task = ad_tasks(&rig, &message).remove(0);
        // Its task's record no longer reads (another build's shape).
        let db = |rig: &LocalRig, sql: &str| {
            rig.bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .db
                .execute_batch(sql)
                .unwrap()
        };
        db(
            &rig,
            &format!(
                "UPDATE work SET record='{{\"shape\":2}}' WHERE id='{}'",
                task.task.task_id
            ),
        );
        let cancel = ad_inbox_stop(&rig, &task.task.task_id, false, host_now().wall_ms + HOUR);
        // A report whose mark can't be cleared (its update fails).
        db(
            &rig,
            "CREATE TRIGGER ad_block BEFORE UPDATE OF report ON mailbox_refused
            BEGIN SELECT RAISE(ABORT, 'blocked'); END;",
        );
        db(
            &rig,
            "INSERT INTO mailbox_refused(evidence, reason, sender_host, object_id, report, bytes,
                keep_until, at_ms) VALUES('ad-evidence', 'expired', 'host-b',
                'b06daa5d-9f48-4512-8a98-c6d98b159d8e', 1, NULL, 9999999999999, 0)",
        );
        // Neither the failing row nor the failing report holds the next row.
        let next = ad_message(&rig, vec![ad_select(&["atem:host"], 1)]);
        ad_inbox_request(&rig, &next);
        ad_admit(&mut rig);
        assert_eq!(ad_tasks(&rig, &next).len(), 1, "the next row admitted");
        assert_eq!(ad_inbox_rows(&rig), 1, "the failing cancel kept");
        for _ in 1..MAX_ADMIT_FAILURES {
            ad_admit(&mut rig);
        }
        assert_eq!(ad_inbox_rows(&rig), 0, "settled");
        assert!(ad_statuses(&rig).iter().any(|(_, s)| *s
            == ResultPlain::Refusal {
                object_id: cancel.clone(),
                refused: "busy".into()
            }));
        mb_tick(&mut rig, &mut host, 0);
        assert_eq!(mb_store(&rig).inbox, 0, "the gate's inbox part drained");
        db(&rig, "DROP TRIGGER ad_block");
    });
}

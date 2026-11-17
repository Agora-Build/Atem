// The sending host in the bridge (design II.4.4, II.6; host-work-v1
// §11.5): the rig's host (`host`, its `atem_id` `atem-host`) as a
// host-sender host whose list gives host B (`host-b`) an encryption key,
// and project `build` lists both with a task's ops. A send to B is planned,
// its envelope sealed to B's key and committed with the message before
// any put. Shares the mailbox tests' rig (`mb_host`); every name here
// starts with `sp_`.

/// The rig as a sending host: `mb_host`, and B's encryption key in the
/// list (its `enc_sig` by B's host key).
fn sp_host(rig: &mut LocalRig, root: &Path, os: &ManualOs) -> MbHost {
    use crate::session_protocol::membership::r9log::secret;
    use atem_client::KeyProvider;
    let mut host = mb_host(rig, root, os);
    let mut keys = atem_client::SoftwareKeys::new();
    let (host_key, enc) = (
        atem_client::KeyId::new("b"),
        atem_client::KeyId::new("b enc"),
    );
    keys.insert_ed25519(host_key.clone(), &secret("host b"));
    keys.insert_x25519(enc.clone(), &secret("host b enc"));
    let enc_key = keys.public_key(&enc).unwrap();
    let sig = atem_client::membership::sign_host_enc_key(
        &keys,
        &host_key,
        "acct",
        &host.s.log.genesis_hash(),
        "host-b",
        1,
        enc_key.as_32().unwrap(),
    )
    .unwrap();
    let action =
        atem_client::membership::host_enc_key("host-b", 1, &enc_key, &sig, false, 0).unwrap();
    sign_and_carry(rig, &mut host.s, action);
    mb_tick(rig, &mut host, 0);
    // The Station associated the link: its `heads` with this host's mailbox.
    mb_heads(rig, MB_MAILBOX, 0);
    host
}

/// B's view of an envelope: its plaintext, opened with B's key after its
/// signature verified with this host's key.
fn sp_open(rig: &LocalRig, bytes: &[u8]) -> atem_client::host_mail::EnvelopePlain {
    use crate::session_protocol::membership::r9log::secret;
    let object = atem_client::host_mail::parse_object(bytes).unwrap();
    let sender = rig.bridge.host_key.as_ref().unwrap().public_key().unwrap();
    let verified = atem_client::host_mail::VerifiedMail::verify(&object, &sender).unwrap();
    let mut keys = atem_client::SoftwareKeys::new();
    keys.insert_x25519(atem_client::KeyId::new("enc"), &secret("host b enc"));
    atem_client::host_mail::unseal_envelope(&keys, &atem_client::KeyId::new("enc"), &verified)
        .unwrap()
}

/// The rows of `message`: (host, state, code).
fn sp_rows(rig: &LocalRig, message: &str) -> Vec<(String, String, Option<String>)> {
    crate::runtime::delegated::remote_send::rows(
        &rig.bridge.work.store.as_ref().unwrap().db,
        message,
    )
    .unwrap()
    .into_iter()
    .map(|r| (r.host_id, r.state, r.code))
    .collect()
}

/// The engine's row of `message` to B: its number, state and bytes.
fn sp_engine(rig: &LocalRig, message: &str) -> (i64, String, Vec<u8>) {
    rig.bridge
        .work
        .store
        .as_ref()
        .unwrap()
        .db
        .query_row(
            "SELECT n, state, bytes FROM mail_outbox WHERE target_host='host-b' AND object_id=?1",
            [message],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap()
}

/// The stage-1 outbox row of `message`: its state, detail and the local
/// message's `select` budget.
fn sp_local(rig: &LocalRig, message: &str) -> (String, String, u32) {
    let (state, detail, envelope): (String, String, String) = rig
        .bridge
        .work
        .store
        .as_ref()
        .unwrap()
        .db
        .query_row(
            "SELECT state, detail, envelope FROM outbox WHERE message_id=?1",
            [message],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .unwrap();
    let envelope: Message = serde_json::from_str(&envelope).unwrap();
    let Destination::Select { budget, .. } = &envelope.recipients[0].destination else {
        panic!("not a select");
    };
    (state, detail, *budget)
}

/// A send of `to` that lives an hour.
fn sp_send(rig: &mut LocalRig, to: &[&str]) -> anyhow::Result<String> {
    let mut request = send_request(to);
    request.expires_ms = HOUR;
    rig.bridge
        .collab_send("atem-host", &rig.sid, request, &rig.sessions)
}

/// A send to B: planned from the committed list, its envelope sealed to
/// B's key (the host-sender Message, `select` for B) and committed with
/// the message, `ready`, before any put; the local part a nominal one
/// that addresses no agent here.
#[test]
fn a_send_to_another_host_commits_its_sealed_envelope_before_any_put() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = sp_host(&mut rig, root, &os);
        let id = sp_send(&mut rig, &["atem:host-b/rh"]).unwrap();
        assert_eq!(
            sp_rows(&rig, &id),
            [("host-b".into(), "ready".into(), None)]
        );
        let (_, state, bytes) = sp_engine(&rig, &id);
        assert_eq!(state, "queued");
        let atem_client::host_mail::EnvelopePlain::Request { message } = sp_open(&rig, &bytes)
        else {
            panic!("not a request");
        };
        assert_eq!(message.message_id, id);
        assert_eq!(message.sender, "host:host");
        assert_eq!(message.text, "check");
        assert_eq!(
            message.recipients[0].destination,
            Destination::Select {
                selectors: vec!["atem:host-b/rh".into()],
                budget: 32,
                launch: false,
            }
        );
        assert_eq!(
            sp_local(&rig, &id),
            ("accepted".into(), "no local agent addressed".into(), 1)
        );
        // Nothing was received here.
        let workflow = message.workflow_id;
        assert_eq!(counted(&rig, &format!("send:{workflow}")), 1);
        assert_eq!(counted(&rig, &format!("receive:{workflow}")), 0);
    });
}

/// A send that reaches this host's agents and B's: the local part keeps
/// stage 1's path with its share of the one budget, B gets the other.
#[test]
fn a_mixed_send_keeps_stage_1_and_splits_the_budget() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = sp_host(&mut rig, root, &os);
        let id = sp_send(&mut rig, &["atem:atem-host", "atem:host-b"]).unwrap();
        let (state, _, budget) = sp_local(&rig, &id);
        assert_eq!((state.as_str(), budget), ("accepted", 16));
        let atem_client::host_mail::EnvelopePlain::Request { message } =
            sp_open(&rig, &sp_engine(&rig, &id).2)
        else {
            panic!("not a request");
        };
        let Destination::Select { budget, .. } = &message.recipients[0].destination else {
            panic!("not a select");
        };
        assert_eq!(*budget, 16);
        let workflow = message.workflow_id;
        assert_eq!(counted(&rig, &format!("receive:{workflow}")), 1);
        // A host the list doesn't have refuses the whole send.
        assert_eq!(
            sp_send(&mut rig, &["tag:x", "atem:host-z"])
                .unwrap_err()
                .to_string(),
            "atem:host-z: no current host of this account's device list has that id"
        );
    });
}

/// A send with context: its row publishes with it, then its envelope is
/// sealed with the frozen snapshot, once.
#[test]
fn a_context_send_seals_its_frozen_context() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = sp_host(&mut rig, root, &os);
        let memories = crate::memory::store::Store::open(&root.join("knowledge.db")).unwrap();
        memories
            .upsert_memory(&crate::memory::model::Memory {
                id: "mem_c0ffee01".into(),
                content: "the orders contract changed".into(),
                ..Default::default()
            })
            .unwrap();
        let mut request = send_request(&["atem:host-b"]);
        request.memory = vec!["mem_c0ffee01".into()];
        let id = rig
            .bridge
            .collab_send("atem-host", &rig.sid, request, &rig.sessions)
            .unwrap();
        assert_eq!(
            sp_rows(&rig, &id),
            [("host-b".into(), "publishing".into(), None)]
        );
        rig.until(|r| r.bridge.work.context_jobs.contains_key(&id))
            .await;
        let (tx, rx) = tokio::sync::oneshot::channel();
        let frozen = snapshot("the orders contract changed");
        tx.send(Ok(vec![frozen.clone()])).unwrap();
        rig.bridge.work.context_jobs.insert(id.clone(), rx);
        rig.until(|r| sp_rows(r, &id)[0].1 == "ready").await;
        let atem_client::host_mail::EnvelopePlain::Request { message } =
            sp_open(&rig, &sp_engine(&rig, &id).2)
        else {
            panic!("not a request");
        };
        assert_eq!(message.context, [frozen]);
        assert_eq!(sp_local(&rig, &id).0, "accepted");
    });
}

/// With the hook off a send is exactly stage 1's: no plan and no outbox
/// table; another host's `atem:` matches nothing here, the whole budget
/// local.
#[test]
fn with_the_hook_off_a_send_is_stage_1() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let id = sp_send(&mut rig, &["atem:host-b"]).unwrap();
        assert_eq!(
            sp_local(&rig, &id),
            ("accepted".into(), "no_match".into(), 32)
        );
        let made: bool = rig
            .bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master
                WHERE name IN ('mail_outbox', 'remote_deliveries'))",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert!(!made);
    });
}

/// The puts the bridge hands the link now.
fn sp_out(rig: &mut LocalRig) -> Vec<atem_client::host_mail::mailbox::MailboxPut> {
    use crate::runtime::delegated::station::Call;
    rig.bridge
        .mail_outgoing()
        .into_iter()
        .filter_map(|call| match call {
            Call::MailboxPut(put) => Some(put),
            _ => None,
        })
        .collect()
}

/// The Station's `mailbox_stored` for `put`, read by the link.
fn sp_stored(rig: &mut LocalRig, put: &atem_client::host_mail::mailbox::MailboxPut) {
    let stored = atem_client::host_mail::mailbox::MailboxStored {
        request_id: put.request_id.clone(),
        id: put.mail().unwrap().1.id,
    };
    mb_receive(rig, &stored.to_json().unwrap().to_string());
}

/// The Station's `mailbox_put_refused` of `put` with `code`.
fn sp_refused(
    rig: &mut LocalRig,
    put: &atem_client::host_mail::mailbox::MailboxPut,
    code: atem_client::host_mail::mailbox::PutRefusal,
) {
    let refused = atem_client::host_mail::mailbox::MailboxPutRefused {
        request_id: put.request_id.clone(),
        id: put.mail().unwrap().1.id,
        code,
    };
    mb_receive(rig, &refused.to_json().unwrap().to_string());
}

/// `D`, moved by the tests.
fn sp_d(rig: &LocalRig, at: u64) {
    rig.bridge.start_view().now_d_ms = Some(at);
}

/// A put carries exactly the sealed bytes; stored, the row is `sent` and
/// the same bytes go again every 10 minutes (fresh ids), never sooner.
#[test]
fn a_put_carries_the_sealed_bytes_and_repeats_every_ten_minutes() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = sp_host(&mut rig, root, &os);
        let t = host_now().wall_ms;
        sp_d(&rig, t);
        let id = sp_send(&mut rig, &["atem:host-b"]).unwrap();
        let puts = sp_out(&mut rig);
        assert_eq!(puts.len(), 1);
        let (_, _, bytes) = sp_engine(&rig, &id);
        assert_eq!(puts[0].object.to_json().to_string().into_bytes(), bytes);
        assert!(sp_out(&mut rig).is_empty(), "live");
        sp_stored(&mut rig, &puts[0]);
        assert_eq!(sp_rows(&rig, &id), [("host-b".into(), "sent".into(), None)]);
        assert_eq!(sp_engine(&rig, &id).1, "stored");
        sp_d(&rig, t + 10 * 60_000 - 1);
        assert!(sp_out(&mut rig).is_empty());
        sp_d(&rig, t + 10 * 60_000);
        let again = sp_out(&mut rig);
        assert_eq!(again.len(), 1);
        assert_ne!(again[0].request_id, puts[0].request_id);
        assert_eq!(again[0].object.to_json().to_string().into_bytes(), bytes);
        sp_stored(&mut rig, &again[0]);
        assert_eq!(sp_rows(&rig, &id)[0].1, "sent");
        assert_eq!(sp_engine(&rig, &id).2, bytes, "never sealed again");
    });
}

/// A put whose `mailbox_stored` is lost goes again after 35 s with a fresh
/// id and the same bytes; the first's late answer is drained.
#[test]
fn a_lost_stored_is_put_again_with_the_same_bytes() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        sp_d(&rig, host_now().wall_ms);
        let id = sp_send(&mut rig, &["atem:host-b"]).unwrap();
        let first = sp_out(&mut rig).remove(0);
        mb_tick(&mut rig, &mut host, 34_999);
        assert!(sp_out(&mut rig).is_empty());
        mb_tick(&mut rig, &mut host, 1);
        let second = sp_out(&mut rig).remove(0);
        assert_ne!(second.request_id, first.request_id);
        assert_eq!(second.object, first.object);
        sp_stored(&mut rig, &first);
        assert_eq!(sp_rows(&rig, &id)[0].1, "ready", "drained");
        sp_stored(&mut rig, &second);
        assert_eq!(sp_rows(&rig, &id)[0].1, "sent");
    });
}

/// `quota`: put again after the backoff; `forbidden`: not again on that
/// link generation, again on the next; `id_reused` (as `expired`): the row
/// refused with the code, put no more.
#[test]
fn quota_is_retried_and_other_refusals_are_final() {
    local_test(async |root| {
        use atem_client::host_mail::mailbox::PutRefusal;
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = sp_host(&mut rig, root, &os);
        let t = host_now().wall_ms;
        sp_d(&rig, t);
        let id = sp_send(&mut rig, &["atem:host-b"]).unwrap();
        let put = sp_out(&mut rig).remove(0);
        sp_refused(&mut rig, &put, PutRefusal::Quota);
        assert_eq!(sp_rows(&rig, &id)[0].1, "ready");
        sp_d(&rig, t + 29_999);
        assert!(sp_out(&mut rig).is_empty());
        sp_d(&rig, t + 30_000);
        let put = sp_out(&mut rig).remove(0);
        // `forbidden`: final on this link generation (ruling R41).
        sp_refused(&mut rig, &put, PutRefusal::Forbidden);
        assert_eq!(
            sp_rows(&rig, &id),
            [("host-b".into(), "ready".into(), Some("forbidden".into()))]
        );
        sp_d(&rig, t + 60_000);
        assert!(sp_out(&mut rig).is_empty(), "not again on this generation");
        rig.bridge.station.as_mut().unwrap().sync_link(
            Some(2),
            1,
            || crate::runtime::delegated::station::LinkKind::Routed,
            || Some(ORIGIN.into()),
        );
        mb_heads(&mut rig, MB_MAILBOX, 0);
        let put = sp_out(&mut rig).remove(0);
        sp_refused(&mut rig, &put, PutRefusal::IdReused);
        assert_eq!(
            sp_rows(&rig, &id),
            [("host-b".into(), "refused".into(), Some("id_reused".into()))]
        );
        sp_d(&rig, t + 3_000_000);
        assert!(sp_out(&mut rig).is_empty());
    });
}

/// A row not accepted by its object's expiry is `expired` and put no more.
#[test]
fn an_object_past_its_expiry_is_never_put_again() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = sp_host(&mut rig, root, &os);
        sp_d(&rig, host_now().wall_ms);
        let id = sp_send(&mut rig, &["atem:host-b"]).unwrap();
        let put = sp_out(&mut rig).remove(0);
        sp_stored(&mut rig, &put);
        let expires_at = put.mail().unwrap().1.expires_at;
        sp_d(&rig, expires_at);
        mb_tick(&mut rig, &mut host, 0);
        assert_eq!(sp_rows(&rig, &id)[0].1, "expired");
        assert_eq!(sp_engine(&rig, &id).1, "expired");
        assert!(sp_out(&mut rig).is_empty());
    });
}

/// An identity change on the live link retires the live puts: their late
/// answers are drained and nothing more is put on that socket; a new
/// socket puts the same bytes again.
#[test]
fn an_identity_change_retires_the_puts() {
    local_test(async |root| {
        use crate::runtime::delegated::station::LinkKind;
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = sp_host(&mut rig, root, &os);
        sp_d(&rig, host_now().wall_ms);
        let id = sp_send(&mut rig, &["atem:host-b"]).unwrap();
        let first = sp_out(&mut rig).remove(0);
        let mut moved = rig.bridge.work_host();
        moved.host_trust_gen = 2;
        let station = rig.bridge.station.as_mut().unwrap();
        station.on_identity(crate::runtime::delegated::sync::HostIdentity {
            host: moved,
            genesis: None,
            host_key: None,
        });
        assert!(sp_out(&mut rig).is_empty(), "nothing on that socket");
        sp_stored(&mut rig, &first);
        assert_eq!(sp_rows(&rig, &id)[0].1, "ready", "drained");
        rig.bridge.station.as_mut().unwrap().sync_link(
            Some(2),
            2,
            || LinkKind::Routed,
            || Some(ORIGIN.into()),
        );
        mb_heads(&mut rig, MB_MAILBOX, 0);
        let again = sp_out(&mut rig).remove(0);
        assert_eq!(again.object, first.object);
    });
}

/// The engine's other policy (ruling R37): a status object, already sealed
/// and enqueued in its caller's transaction, is put until the Station
/// stores it (again on a new link generation while unanswered), never
/// after.
#[test]
fn a_status_object_is_put_until_stored_never_after() {
    local_test(async |root| {
        use crate::runtime::delegated::outbox::{self, Policy};
        use crate::runtime::delegated::station::LinkKind;
        use crate::session_protocol::membership::r9log::secret;
        use atem_client::KeyProvider;
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let host = sp_host(&mut rig, root, &os);
        let t = host_now().wall_ms;
        sp_d(&rig, t);
        // This host's status of a message of B's, sealed to B's key.
        let mut keys = atem_client::SoftwareKeys::new();
        keys.insert_ed25519(atem_client::KeyId::new("host"), &secret("delegated host"));
        keys.insert_x25519(atem_client::KeyId::new("b"), &secret("host b enc"));
        let b_enc = keys.public_key(&atem_client::KeyId::new("b")).unwrap();
        let list = rig.bridge.membership.as_ref().unwrap().membership();
        let fields = atem_client::host_mail::MailFields {
            account_id: "acct".into(),
            genesis_hash: host.s.log.genesis_hash(),
            sender: atem_client::host_mail::HostRef {
                host_id: "host".into(),
                host_trust_gen: 1,
            },
            recipient: atem_client::host_mail::HostRef {
                host_id: "host-b".into(),
                host_trust_gen: 1,
            },
            enc_kid: atem_client::keys::enc_kid(&b_enc).unwrap(),
            id: uuid::Uuid::new_v4().to_string(),
            created_at: t,
            expires_at: t + HOUR,
            signed_at_head: list.head(),
        };
        let plain = atem_client::host_mail::ResultPlain::Refusal {
            object_id: uuid::Uuid::new_v4().to_string(),
            refused: "invalid_request".into(),
        };
        let bytes = atem_client::host_mail::seal_result(
            &keys,
            &atem_client::KeyId::new("host"),
            &fields,
            &plain,
            &b_enc,
        )
        .unwrap()
        .to_json()
        .to_string()
        .into_bytes();
        let store = rig.bridge.work.store.as_ref().unwrap();
        let tx = store.db.unchecked_transaction().unwrap();
        let n = outbox::enqueue(&tx, &bytes, &fields.recipient, Policy::UntilStored).unwrap();
        tx.commit().unwrap();
        let first = sp_out(&mut rig).remove(0);
        assert_eq!(first.object.to_json().to_string().into_bytes(), bytes);
        // Reconnected, unanswered: put again (once the new generation's
        // `heads` came).
        rig.bridge.station.as_mut().unwrap().sync_link(
            Some(2),
            1,
            || LinkKind::Routed,
            || Some(ORIGIN.into()),
        );
        assert!(sp_out(&mut rig).is_empty());
        mb_heads(&mut rig, MB_MAILBOX, 0);
        let second = sp_out(&mut rig).remove(0);
        assert_ne!(second.request_id, first.request_id);
        sp_stored(&mut rig, &second);
        let state = |rig: &LocalRig| {
            outbox::row_state(&rig.bridge.work.store.as_ref().unwrap().db, n)
                .unwrap()
                .unwrap()
                .state
        };
        assert_eq!(state(&rig), "done");
        sp_d(&rig, t + 30 * 60_000);
        assert!(sp_out(&mut rig).is_empty(), "never after it was stored");
    });
}

/// No put goes before the Station associated the link (review M1): the
/// first `heads` of a link generation announcing this host's mailbox; a
/// new generation waits for its own.
#[test]
fn no_put_goes_before_the_links_heads() {
    local_test(async |root| {
        use crate::runtime::delegated::station::LinkKind;
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = sp_host(&mut rig, root, &os);
        sp_d(&rig, host_now().wall_ms);
        rig.bridge.station.as_mut().unwrap().sync_link(
            Some(2),
            2,
            || LinkKind::Routed,
            || Some(ORIGIN.into()),
        );
        let id = sp_send(&mut rig, &["atem:host-b"]).unwrap();
        assert_eq!(sp_engine(&rig, &id).1, "queued");
        assert!(sp_out(&mut rig).is_empty(), "no heads on this generation");
        mb_heads(&mut rig, MB_MAILBOX, 0);
        assert_eq!(sp_out(&mut rig).len(), 1);
    });
}

/// The puts' times are all on `D` (review L1): an answer that comes with
/// no reading of `D` writes nothing (no schedule from another clock); the
/// row is due again, put again once `D` reads.
#[test]
fn an_answer_with_no_reading_of_d_writes_nothing() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = sp_host(&mut rig, root, &os);
        let t = host_now().wall_ms;
        sp_d(&rig, t);
        let id = sp_send(&mut rig, &["atem:host-b"]).unwrap();
        let put = sp_out(&mut rig).remove(0);
        rig.bridge.start_view().now_d_ms = None;
        sp_stored(&mut rig, &put);
        assert_eq!(sp_rows(&rig, &id)[0].1, "ready");
        assert_eq!(sp_engine(&rig, &id).1, "queued");
        assert!(sp_out(&mut rig).is_empty(), "nothing put without `D`");
        sp_d(&rig, t);
        let again = sp_out(&mut rig).remove(0);
        sp_stored(&mut rig, &again);
        assert_eq!(sp_rows(&rig, &id)[0].1, "sent");
    });
}

/// A send to B with `memory` as context, publishing: its id.
fn sp_context_send(rig: &mut LocalRig, root: &Path, to: &[&str]) -> String {
    let memories = crate::memory::store::Store::open(&root.join("knowledge.db")).unwrap();
    memories
        .upsert_memory(&crate::memory::model::Memory {
            id: "mem_c0ffee02".into(),
            content: "the orders contract changed".into(),
            ..Default::default()
        })
        .unwrap();
    let mut request = send_request(to);
    request.memory = vec!["mem_c0ffee02".into()];
    request.expires_ms = HOUR;
    rig.bridge
        .collab_send("atem-host", &rig.sid, request, &rig.sessions)
        .unwrap()
}

/// The publication of `id` completes with its frozen snapshot.
async fn sp_publish(rig: &mut LocalRig, id: &str) {
    rig.until(|r| r.bridge.work.context_jobs.contains_key(id))
        .await;
    let (tx, rx) = tokio::sync::oneshot::channel();
    tx.send(Ok(vec![snapshot("the orders contract changed")]))
        .unwrap();
    rig.bridge.work.context_jobs.insert(id.to_string(), rx);
}

fn sp_outbox(rig: &LocalRig, id: &str) -> (String, String) {
    rig.bridge
        .work
        .store
        .as_ref()
        .unwrap()
        .db
        .query_row(
            "SELECT state, detail FROM outbox WHERE message_id=?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .unwrap()
}

/// A context send whose envelopes can't be sealed when its publication
/// completes (no host key now) waits with its own reason, not the relay's
/// (review L3).
#[test]
fn an_outbox_that_cant_seal_retries_with_its_own_reason() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = sp_host(&mut rig, root, &os);
        let id = sp_context_send(&mut rig, root, &["atem:host-b"]);
        // The host key gone: no envelope can be signed.
        let file = rig
            .bridge
            .pairing
            .as_ref()
            .unwrap()
            .host_channel_key
            .clone();
        let aside = file.with_extension("aside");
        std::fs::rename(&file, &aside).unwrap();
        rig.bridge.host_key = None;
        sp_publish(&mut rig, &id).await;
        rig.until(|r| sp_outbox(r, &id).1 != "waiting for verified context publication")
            .await;
        assert_eq!(
            sp_outbox(&rig, &id),
            (
                "publishing".into(),
                "host senders' outbox unavailable; publication will retry".into()
            )
        );
        assert_eq!(sp_rows(&rig, &id)[0].1, "publishing");
        std::fs::rename(&aside, &file).unwrap();
    });
}

/// A publication completing on a runtime whose `host.senders` is off now
/// seals nothing nothing would put: its rows to other hosts are refused
/// with why, its local part accepted (review L3).
#[test]
fn a_publication_with_host_senders_off_refuses_its_remote_rows() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = sp_host(&mut rig, root, &os);
        let id = sp_context_send(&mut rig, root, &["atem:atem-host", "atem:host-b"]);
        rig.bridge.features = HostFeatures::parse("host.delegated").unwrap();
        sp_publish(&mut rig, &id).await;
        rig.until(|r| sp_outbox(r, &id).0 == "accepted").await;
        let remote = crate::runtime::delegated::remote_send::rows(
            &rig.bridge.work.store.as_ref().unwrap().db,
            &id,
        )
        .unwrap();
        assert_eq!(
            (remote[0].state.as_str(), remote[0].detail.as_str()),
            ("refused", "host senders are off on this host")
        );
        assert_eq!(rows(&rig, "mail_outbox"), 0);
    });
}

/// A row whose bytes no longer read is refused (`malformed`) and leaves
/// the due rows, instead of taking a place every pass (review L4).
#[test]
fn a_row_whose_bytes_dont_read_is_refused() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = sp_host(&mut rig, root, &os);
        sp_d(&rig, host_now().wall_ms);
        let id = sp_send(&mut rig, &["atem:host-b"]).unwrap();
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .execute(
                "UPDATE mail_outbox SET bytes=x'7b7d' WHERE object_id=?1",
                [&id],
            )
            .unwrap();
        assert!(sp_out(&mut rig).is_empty());
        assert_eq!(
            sp_rows(&rig, &id),
            [("host-b".into(), "refused".into(), Some("malformed".into()))]
        );
        let due = crate::runtime::delegated::outbox::due(
            rig.bridge.work.store.as_ref().unwrap(),
            &atem_client::host_mail::HostRef {
                host_id: "host".into(),
                host_trust_gen: 1,
            },
            host_now().wall_ms,
            crate::runtime::delegated::outbox::Place {
                link_gen: 1,
                head_seq: 0,
            },
            &[],
            8,
        )
        .unwrap();
        assert!(due.is_empty());
    });
}

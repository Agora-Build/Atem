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

fn sp_send(rig: &mut LocalRig, to: &[&str]) -> anyhow::Result<String> {
    rig.bridge
        .collab_send("atem-host", &rig.sid, send_request(to), &rig.sessions)
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

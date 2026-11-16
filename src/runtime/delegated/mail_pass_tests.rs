// Host senders' mailbox in the bridge (host-work-v1 §11.5, "The mailbox
// calls"; design II.4.2 to II.5): the rig's host as a host-sender host
// (`host_senders_host`: `host.delegated` and `host.senders` on, its list
// naming this host, host B and the phone), its encryption key made, its
// Station link up by hand (the rig has no r9 link, so these tests drive the
// bridge's mailbox steps as `station_pass_at` does, never a pass), the
// Station's messages read by the link's reader, and B's objects sealed with
// the shared core. Included beside the host senders' tests, whose helpers
// it shares; every name here starts with `mb_` (one module).

const MB_MAILBOX: &str = "9d2f6c1e-3b4a-4c5d-8e6f-7a8b9c0d1e2f";
const MB_MAILBOX_2: &str = "3e9fd05f-183e-4b70-be0e-3ffa66120f48";

/// The rig as a host-sender host with its mailbox link: B's key, this
/// host's encryption key, the host senders' list.
struct MbHost {
    s: HostSenders,
    sender: atem_client::SoftwareKeys,
    enc_pub: atem_client::PublicKey,
    /// The pass's monotonic clock (ms), moved by the tests.
    mono: u64,
}

fn mb_host(rig: &mut LocalRig, root: &Path, os: &ManualOs) -> MbHost {
    use crate::runtime::delegated::station::{LinkKind, Station};
    use crate::session_protocol::membership::r9log::secret;
    use atem_client::KeyProvider;
    let s = host_senders_host(rig, root, os);
    let pairing = crate::profile::Sources::in_dir(&root.join("profile"))
        .paths
        .pairing;
    crate::session_protocol::r9::host_enc::ensure(&pairing, &rig.bridge.dir, 1);
    let receiver = crate::session_protocol::r9::host_enc::recipient_at(&pairing, "host".into(), 1);
    let enc_pub = receiver
        .provider
        .public_key(&receiver.recipient.keys[0].0)
        .unwrap();
    rig.bridge.pairing = Some(pairing);
    rig.bridge.start_view().now_d_ms = Some(host_now().wall_ms);
    let mut station = Station::with_senders(true);
    station.sync_link(Some(1), 1, || LinkKind::Routed, || Some(ORIGIN.into()));
    rig.bridge.station = Some(station);
    rig.bridge.station_identity();
    let mut sender = atem_client::SoftwareKeys::new();
    sender.insert_ed25519(atem_client::KeyId::new("host-b"), &secret("host b"));
    let mut host = MbHost {
        s,
        sender,
        enc_pub,
        mono: 1_000_000,
    };
    mb_tick(rig, &mut host, 0);
    host
}

/// The pass's tick, `ms` later.
fn mb_tick(rig: &mut LocalRig, host: &mut MbHost, ms: u64) {
    host.mono += ms;
    rig.bridge.mail_tick(host.mono);
}

/// A Station message handed to the bridge as `station_pass_at` does: the
/// store observed first, read by the link's reader, then its step.
fn mb_receive(rig: &mut LocalRig, text: &str) {
    use crate::runtime::delegated::station::Inbound;
    rig.bridge.mail_observe();
    let applied = rig.bridge.membership.as_ref().map(|m| m.head());
    let inbound = rig
        .bridge
        .station
        .as_mut()
        .unwrap()
        .receive(text, applied, None);
    match inbound {
        Inbound::Mailbox(message) => rig.bridge.mail_inbound(message),
        Inbound::Heads(..) => rig.bridge.mail_step(),
        other => panic!("not a mailbox message: {other:?}"),
    }
}

/// `heads` announcing the host's own mailbox `mailbox_id` at `head`.
fn mb_heads(rig: &mut LocalRig, mailbox_id: &str, head: u64) {
    let membership = rig.bridge.membership.as_ref().unwrap().head();
    let text = atem_client::control::HeadsWithMailbox {
        heads: atem_client::control::Heads {
            feeds: Vec::new(),
            membership,
        },
        mailbox: Some(atem_client::control::MailboxHead {
            mailbox_id: mailbox_id.into(),
            head,
        }),
    }
    .to_json()
    .unwrap()
    .to_string();
    mb_receive(rig, &text);
}

/// The calls the bridge hands the link now: the syncs, the dones.
fn mb_out(
    rig: &mut LocalRig,
) -> (
    Vec<atem_client::host_mail::mailbox::MailboxSync>,
    Vec<atem_client::host_mail::mailbox::MailboxDone>,
) {
    use crate::runtime::delegated::station::Call;
    let mut out = (Vec::new(), Vec::new());
    for call in rig.bridge.mail_outgoing() {
        match call {
            Call::MailboxSync(sync) => out.0.push(sync),
            Call::MailboxDone(done) => out.1.push(done),
            other => panic!("not a mailbox call: {other:?}"),
        }
    }
    out
}

/// The page answering `call`: its head, `objects` at the positions after
/// its `after` (any JSON), scanned through the last.
fn mb_page(
    call: &atem_client::host_mail::mailbox::MailboxSync,
    head: u64,
    objects: &[Value],
) -> String {
    let through = call.after + objects.len() as u64;
    let items: Vec<String> = objects
        .iter()
        .enumerate()
        .map(|(i, o)| {
            format!(
                r#"{{"position":{},"object":{o}}}"#,
                call.after + 1 + i as u64
            )
        })
        .collect();
    format!(
        r#"{{"type":"relay","op":"mailbox_sync_result","request_id":"{}","mailbox_id":"{}","after":{},"head":{head},"through":{through},"objects":[{}]}}"#,
        call.request_id,
        call.mailbox_id,
        call.after,
        items.join(",")
    )
}

/// B's cancel to this host, signed at `head`, from `sender` (claimed),
/// sealed with `keys` (B's, unless another's).
fn mb_cancel(
    rig: &LocalRig,
    host: &MbHost,
    sender: &str,
    keys: &atem_client::SoftwareKeys,
    head: atem_client::membership::Head,
) -> Value {
    let list = rig.bridge.membership.as_ref().unwrap().membership();
    let now = host_now().wall_ms;
    let fields = atem_client::host_mail::MailFields {
        account_id: "acct".into(),
        genesis_hash: list.genesis_hash(),
        sender: atem_client::host_mail::HostRef {
            host_id: sender.into(),
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
    atem_client::host_mail::seal_envelope(
        keys,
        &atem_client::KeyId::new("host-b"),
        &fields,
        &atem_client::host_mail::EnvelopePlain::Cancel {
            task_id: uuid::Uuid::new_v4().to_string(),
        },
        &host.enc_pub,
    )
    .unwrap()
    .to_json()
}

/// What the store holds for the host's identity now.
fn mb_store(rig: &LocalRig) -> crate::runtime::delegated::mailbox::Observed {
    let identity = crate::runtime::delegated::sync::HostIdentity {
        host: rig.bridge.work_host(),
        genesis: Some(
            rig.bridge
                .membership
                .as_ref()
                .unwrap()
                .membership()
                .genesis_hash(),
        ),
    };
    crate::runtime::delegated::mailbox_store::read(
        rig.bridge.work.store.as_ref().unwrap(),
        &identity,
    )
    .unwrap()
}

/// Whether a host sender's gate is open in the start view (its Station's
/// gate stood in open: the mailbox part decides).
fn mb_gate(rig: &LocalRig) -> bool {
    use crate::runtime::delegated::gate::GateView;
    rig.bridge.start_view().gates.open_for(
        &DelegatedSender::Host {
            host_id: "host-b".into(),
            generation: 1,
            epoch: 1,
        },
        Some(ORIGIN),
    )
}

/// Rule 5 and Astation's ask (#120): a page's decisions, rows, owed dones
/// and cursor commit before any done goes. At the crash point the store
/// owes the done and none is live; the done goes after it, and its answer
/// clears it. The opened cancel waits for admission: host senders' gate is
/// closed until then.
#[test]
fn a_mailbox_page_commits_before_its_done_goes() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = mb_host(&mut rig, root, &os);
        mb_heads(&mut rig, MB_MAILBOX, 1);
        let (syncs, dones) = mb_out(&mut rig);
        assert_eq!((syncs.len(), dones.len()), (1, 0));
        let head = rig.bridge.membership.as_ref().unwrap().head();
        let cancel = mb_cancel(&rig, &host, "host-b", &host.sender, head);
        mb_receive(&mut rig, &mb_page(&syncs[0], 1, &[cancel]));
        assert_eq!(rig.bridge.work.mail_crash_probe, [(vec![1], vec![])]);
        let observed = mb_store(&rig);
        assert_eq!(
            (observed.cursor, observed.inbox),
            (Some((MB_MAILBOX.into(), 1)), 1)
        );
        let (syncs, dones) = mb_out(&mut rig);
        assert!(syncs.is_empty());
        assert_eq!(dones.len(), 1);
        assert_eq!(
            (dones[0].mailbox_id.as_str(), dones[0].position),
            (MB_MAILBOX, 1)
        );
        assert!(!mb_gate(&rig), "the inbox waits for admission");
        let answer = atem_client::host_mail::mailbox::MailboxDoneResult {
            request_id: dones[0].request_id.clone(),
            mailbox_id: MB_MAILBOX.into(),
            position: 1,
        };
        mb_receive(&mut rig, &answer.to_json().unwrap().to_string());
        assert!(mb_store(&rig).owed.is_empty());
        mb_tick(&mut rig, &mut host, 40_000);
        assert_eq!(mb_out(&mut rig), (vec![], vec![]), "nothing again");
    });
}

/// Rule 7: a reset is marked durably before anything is asked for it:
/// while the mark can't be written (its write fails) nothing is asked;
/// once written, the announced mailbox is read from 0 and no done goes to
/// the old one.
#[test]
fn a_mailbox_reset_is_marked_before_anything_is_asked() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = mb_host(&mut rig, root, &os);
        mb_heads(&mut rig, MB_MAILBOX, 1);
        let (syncs, _) = mb_out(&mut rig);
        mb_receive(&mut rig, &mb_page(&syncs[0], 1, &[json!("junk")]));
        assert_eq!(mb_store(&rig).owed, [1]);
        // The mark's write fails: nothing is asked of the new mailbox, and
        // nothing more goes to the old one.
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
            "CREATE TRIGGER mb_block BEFORE UPDATE ON mailbox_cursor BEGIN SELECT RAISE(ABORT, 'blocked'); END;",
        );
        mb_heads(&mut rig, MB_MAILBOX_2, 2);
        mb_tick(&mut rig, &mut host, 2_000);
        assert_eq!(mb_out(&mut rig), (vec![], vec![]));
        assert_eq!(mb_store(&rig).cursor, Some((MB_MAILBOX.into(), 1)));
        db(&rig, "DROP TRIGGER mb_block");
        mb_tick(&mut rig, &mut host, 2_000);
        let observed = mb_store(&rig);
        assert_eq!(observed.cursor, Some((MB_MAILBOX_2.into(), 0)));
        assert!(observed.owed.is_empty(), "the old mailbox's dones dropped");
        let (syncs, dones) = mb_out(&mut rig);
        assert_eq!(syncs.len(), 1);
        assert_eq!(
            (syncs[0].mailbox_id.as_str(), syncs[0].after),
            (MB_MAILBOX_2, 0)
        );
        assert!(dones.is_empty());
        assert!(!mb_gate(&rig), "read to the head first");
    });
}

/// A page that can't be decided now (no reading of `D`), one that doesn't
/// continue the store's cursor (moved under the live call) and one whose
/// transaction fails all commit nothing; the next is asked after the
/// 30 s pause, and then commits.
#[test]
fn a_mailbox_page_that_cant_commit_commits_nothing() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = mb_host(&mut rig, root, &os);
        let head = rig.bridge.membership.as_ref().unwrap().head();
        let cancel = mb_cancel(&rig, &host, "host-b", &host.sender, head);
        // No reading of `D`: undecided.
        let d = rig.bridge.start_view().now_d_ms.take();
        mb_heads(&mut rig, MB_MAILBOX, 1);
        let (syncs, _) = mb_out(&mut rig);
        mb_receive(
            &mut rig,
            &mb_page(&syncs[0], 1, std::slice::from_ref(&cancel)),
        );
        let observed = mb_store(&rig);
        assert_eq!((observed.cursor, observed.inbox), (None, 0));
        mb_tick(&mut rig, &mut host, 29_000);
        assert!(mb_out(&mut rig).0.is_empty(), "paused");
        rig.bridge.start_view().now_d_ms = d;
        mb_tick(&mut rig, &mut host, 2_000);
        let (syncs, _) = mb_out(&mut rig);
        assert_eq!(syncs[0].after, 0);
        // The store's cursor moved under the live call (within the
        // announced head: no reset): its page is stale.
        mb_heads(&mut rig, MB_MAILBOX, 5);
        let store = rig.bridge.work.store.as_ref().unwrap();
        let identity = crate::runtime::delegated::sync::HostIdentity {
            host: rig.bridge.work_host(),
            genesis: Some(head_genesis(&rig)),
        };
        let moved = atem_client::host_mail::mailbox::MailboxSyncResult {
            request_id: syncs[0].request_id.clone(),
            mailbox_id: MB_MAILBOX.into(),
            after: 0,
            head: 5,
            through: 3,
            objects: Vec::new(),
        };
        crate::runtime::delegated::mailbox_store::commit_page(store, &identity, &moved, None)
            .unwrap();
        mb_receive(
            &mut rig,
            &mb_page(&syncs[0], 1, std::slice::from_ref(&cancel)),
        );
        assert_eq!(mb_store(&rig).inbox, 0, "stale: nothing");
        assert_eq!(mb_store(&rig).cursor, Some((MB_MAILBOX.into(), 3)));
        // A transaction that fails.
        mb_tick(&mut rig, &mut host, 31_000);
        let (syncs, _) = mb_out(&mut rig);
        assert_eq!(syncs[0].after, 3);
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .execute_batch("DROP TABLE mailbox_inbox")
            .unwrap();
        mb_receive(
            &mut rig,
            &mb_page(&syncs[0], 5, std::slice::from_ref(&cancel)),
        );
        assert_eq!(mb_store_cursor(&rig), Some((MB_MAILBOX.into(), 3)));
        crate::runtime::delegated::mailbox_store::prepare(rig.bridge.work.store.as_ref().unwrap())
            .unwrap();
        mb_tick(&mut rig, &mut host, 31_000);
        let (syncs, _) = mb_out(&mut rig);
        mb_receive(&mut rig, &mb_page(&syncs[0], 5, &[cancel]));
        assert_eq!(mb_store(&rig).inbox, 1);
    });
}

/// The device list's genesis.
fn head_genesis(rig: &LocalRig) -> atem_client::encoding::Hash32 {
    rig.bridge
        .membership
        .as_ref()
        .unwrap()
        .membership()
        .genesis_hash()
}

/// The stored cursor, read directly (the inbox table may be gone).
fn mb_store_cursor(rig: &LocalRig) -> Option<(String, u64)> {
    use rusqlite::OptionalExtension;
    rig.bridge
        .work
        .store
        .as_ref()
        .unwrap()
        .db
        .query_row("SELECT mailbox_id, cursor FROM mailbox_cursor", [], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })
        .optional()
        .unwrap()
}

/// The mailbox reads and writes only this identity's loaded store: with
/// the control feeds not loaded, or a stored state of another identity,
/// nothing is synced or marked done and the gate's part stays closed.
#[test]
fn the_mailbox_needs_this_identitys_loaded_store() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = mb_host(&mut rig, root, &os);
        mb_heads(&mut rig, MB_MAILBOX, 1);
        let (syncs, _) = mb_out(&mut rig);
        mb_receive(&mut rig, &mb_page(&syncs[0], 1, &[json!("junk")]));
        assert_eq!(mb_store(&rig).owed, [1]);
        // The control feeds not loaded: nothing synced or marked done.
        rig.bridge.work.feeds = crate::runtime::delegated::feeds::Feeds::Unloaded;
        mb_tick(&mut rig, &mut host, 2_000);
        mb_heads(&mut rig, MB_MAILBOX, 2);
        assert_eq!(mb_out(&mut rig), (vec![], vec![]), "not loaded");
        assert!(rig.bridge.mail_status().unwrap().contains("isn't loaded"));
        assert!(!mb_gate(&rig));
        // Loaded again: the owed done goes.
        rig.bridge.ensure_feeds();
        mb_tick(&mut rig, &mut host, 2_000);
        mb_heads(&mut rig, MB_MAILBOX, 2);
        let (_, dones) = mb_out(&mut rig);
        assert_eq!(dones.len(), 1);
        // A stored state of another identity: nothing more.
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .execute("UPDATE mailbox_cursor SET identity='{}'", [])
            .unwrap();
        mb_tick(&mut rig, &mut host, 40_000);
        mb_heads(&mut rig, MB_MAILBOX, 2);
        assert_eq!(mb_out(&mut rig), (vec![], vec![]), "another identity's");
        assert!(rig.bridge.mail_status().unwrap().contains("isn't loaded"));
    });
}

/// Design II.4.2: a waiting object is judged again only once the device
/// list moves: then decided, with its done owed.
#[test]
fn a_waiting_mailbox_object_is_judged_again_when_the_list_moves() {
    use crate::session_protocol::membership::r9log::secret;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = mb_host(&mut rig, root, &os);
        let entry = host.s.log.add_host("host-c", 1, &secret("host c"));
        let mut c = atem_client::SoftwareKeys::new();
        c.insert_ed25519(atem_client::KeyId::new("host-b"), &secret("host c"));
        let cancel = mb_cancel(&rig, &host, "host-c", &c, host.s.log.log.head());
        mb_heads(&mut rig, MB_MAILBOX, 1);
        let (syncs, _) = mb_out(&mut rig);
        mb_receive(&mut rig, &mb_page(&syncs[0], 1, &[cancel]));
        assert!(mb_store(&rig).owed.is_empty(), "it waits");
        mb_tick(&mut rig, &mut host, 2_000);
        assert_eq!(mb_store(&rig).inbox, 0, "the list didn't move");
        carry(&mut rig, &host.s.log, entry);
        rig.bridge.sync_list_view();
        mb_tick(&mut rig, &mut host, 2_000);
        let observed = mb_store(&rig);
        assert_eq!((observed.inbox, observed.owed), (1, vec![1]));
    });
}

/// `atem status`'s `Control feeds:` line names the mailbox part: why it is
/// closed, read to its head once it is, and the mailbox's alerts.
#[test]
fn the_status_names_the_mailbox_part() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _host = mb_host(&mut rig, root, &os);
        let status = rig.bridge.feeds_status().unwrap();
        assert!(
            status.contains(
                "host senders' mailbox not checked (the Station announced no mailbox for this host)"
            ),
            "{status}"
        );
        mb_heads(&mut rig, MB_MAILBOX, 0);
        let (syncs, _) = mb_out(&mut rig);
        mb_receive(&mut rig, &mb_page(&syncs[0], 0, &[]));
        let status = rig.bridge.feeds_status().unwrap();
        assert!(
            status.contains("host senders' mailbox read to its head"),
            "{status}"
        );
        assert!(mb_gate(&rig));
        let mut never = syncs[0].clone();
        never.request_id = "b06daa5d-9f48-4512-8a98-c6d98b159d8e".into();
        mb_receive(&mut rig, &mb_page(&never, 0, &[]));
        let status = rig.bridge.feeds_status().unwrap();
        assert!(
            status.contains("1 mailbox alert(s) since the start, the latest: Station sent a mailbox page it shouldn't (unsolicited)"),
            "{status}"
        );
        assert!(!mb_gate(&rig));
    });
}

/// Hook off = main: without `host.senders` no mailbox table is made and no
/// mailbox call goes, whatever the Station sends.
#[test]
fn without_host_senders_no_mailbox_table_is_made() {
    use crate::runtime::delegated::station::{LinkKind, Station};
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let _s = host_senders_host(&mut rig, root, &os);
        rig.bridge.features = HostFeatures::parse("host.delegated").unwrap();
        let mut station = Station::new();
        station.sync_link(Some(1), 1, || LinkKind::Routed, || Some(ORIGIN.into()));
        rig.bridge.station = Some(station);
        let membership = rig.bridge.membership.as_ref().unwrap().head();
        let text = atem_client::control::HeadsWithMailbox {
            heads: atem_client::control::Heads {
                feeds: Vec::new(),
                membership,
            },
            mailbox: Some(atem_client::control::MailboxHead {
                mailbox_id: MB_MAILBOX.into(),
                head: 1,
            }),
        }
        .to_json()
        .unwrap()
        .to_string();
        rig.bridge.mail_observe();
        let inbound = rig
            .bridge
            .station
            .as_mut()
            .unwrap()
            .receive(&text, Some(membership), None);
        assert_eq!(
            inbound,
            crate::runtime::delegated::station::Inbound::Nothing
        );
        rig.bridge.mail_step();
        rig.bridge.mail_tick(1_000_000);
        assert!(rig.bridge.mail_outgoing().is_empty());
        assert!(rig.bridge.mail_status().is_none());
        assert!(!crate::runtime::delegated::mailbox_store::made_in(
            rig.bridge.work.store.as_ref().unwrap()
        ));
    });
}

/// B's result to this host (`atem-result`), signed at this list's head.
fn mb_result(rig: &LocalRig, host: &MbHost) -> Value {
    let list = rig.bridge.membership.as_ref().unwrap().membership();
    let now = host_now().wall_ms;
    let fields = atem_client::host_mail::MailFields {
        account_id: "acct".into(),
        genesis_hash: list.genesis_hash(),
        sender: atem_client::host_mail::HostRef {
            host_id: "host-b".into(),
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
        signed_at_head: list.head(),
    };
    atem_client::host_mail::seal_result(
        &host.sender,
        &atem_client::KeyId::new("host-b"),
        &fields,
        &atem_client::host_mail::ResultPlain::Refusal {
            object_id: uuid::Uuid::new_v4().to_string(),
            refused: "invalid_request".into(),
        },
        &host.enc_pub,
    )
    .unwrap()
    .to_json()
}

/// Ruling R31 in the bridge: a result over the results' limits is left on
/// the Station (no row, no done) and keeps host senders' gate closed; once
/// room frees (the sending host's check took the kept one), the next step
/// rewinds the cursor durably, the re-read keeps it and its done goes.
#[test]
fn a_result_over_the_limits_is_read_again_once_room_frees() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = mb_host(&mut rig, root, &os);
        rig.bridge.work.mail_limits.results = 1;
        mb_heads(&mut rig, MB_MAILBOX, 2);
        let (syncs, _) = mb_out(&mut rig);
        let first = mb_result(&rig, &host);
        mb_receive(&mut rig, &mb_page(&syncs[0], 2, &[first]));
        let (syncs, dones) = mb_out(&mut rig);
        assert_eq!(dones.iter().map(|d| d.position).collect::<Vec<_>>(), [1]);
        let second = mb_result(&rig, &host);
        mb_receive(
            &mut rig,
            &mb_page(&syncs[0], 2, std::slice::from_ref(&second)),
        );
        let observed = mb_store(&rig);
        assert!(observed.skipped);
        assert_eq!(
            (observed.cursor, observed.owed),
            (Some((MB_MAILBOX.into(), 2)), vec![1])
        );
        assert_eq!(mb_out(&mut rig), (vec![], vec![]), "no done for it");
        assert!(!mb_gate(&rig), "not committed yet");
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .execute("DELETE FROM mailbox_results", [])
            .unwrap();
        mb_tick(&mut rig, &mut host, 1_000);
        let (syncs, _) = mb_out(&mut rig);
        assert_eq!(syncs.len(), 1);
        assert_eq!(syncs[0].after, 1, "read again from just before it");
        mb_receive(&mut rig, &mb_page(&syncs[0], 2, &[second]));
        let observed = mb_store(&rig);
        assert!(!observed.skipped);
        assert_eq!(observed.owed, [1, 2]);
        let (_, dones) = mb_out(&mut rig);
        assert_eq!(dones.iter().map(|d| d.position).collect::<Vec<_>>(), [2]);
    });
}

/// Review O3: nothing is pruned while a forward jump's anchor is pending
/// (`D` may still come back down); once the OS's sync drops the anchor,
/// claims past their margin are pruned.
#[test]
fn nothing_is_pruned_while_a_clock_anchor_is_pending() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = mb_host(&mut rig, root, &os);
        mb_heads(&mut rig, MB_MAILBOX, 1);
        let (syncs, _) = mb_out(&mut rig);
        let head = rig.bridge.membership.as_ref().unwrap().head();
        let cancel = mb_cancel(&rig, &host, "host-b", &host.sender, head);
        mb_receive(&mut rig, &mb_page(&syncs[0], 1, &[cancel]));
        let claims = |rig: &LocalRig| -> u64 {
            rig.bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .db
                .query_row("SELECT count(*) FROM mailbox_claims", [], |r| r.get(0))
                .unwrap()
        };
        assert_eq!(claims(&rig), 1);
        let clock_tick = |rig: &mut LocalRig| {
            let work = &mut rig.bridge.work;
            work.clock
                .as_mut()
                .unwrap()
                .tick(work.store.as_ref().unwrap());
        };
        // A reading, then an unsynchronized wall clock two minutes ahead
        // of it: an anchor.
        clock_tick(&mut rig);
        {
            let mut r = os.0.lock().unwrap();
            r.synced = crate::runtime::host_clock::os::Synced::No;
            r.wall_ms += 120_000;
        }
        clock_tick(&mut rig);
        assert!(rig.bridge.work.clock.as_ref().unwrap().anchored());
        rig.bridge.start_view().now_d_ms = Some(host_now().wall_ms + 3 * 24 * HOUR);
        rig.bridge.work.mail_pruned_at = None;
        mb_tick(&mut rig, &mut host, 1_000);
        assert_eq!(claims(&rig), 1, "held under the anchor");
        // The OS syncs at that reading: the anchor goes; pruning runs.
        os.0.lock().unwrap().synced = crate::runtime::host_clock::os::Synced::Yes;
        clock_tick(&mut rig);
        assert!(!rig.bridge.work.clock.as_ref().unwrap().anchored());
        rig.bridge.work.mail_pruned_at = None;
        mb_tick(&mut rig, &mut host, 1_000);
        assert_eq!(claims(&rig), 0);
    });
}

/// Review P1 (ruling R31's "never loss"): a waiting object that decides
/// to open while the inbox is full keeps waiting (no done), and is judged
/// again as soon as room frees: it opens then, and its done is owed.
#[test]
fn a_waiting_object_with_no_room_is_judged_again_when_room_frees() {
    use crate::session_protocol::membership::r9log::secret;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = mb_host(&mut rig, root, &os);
        rig.bridge.work.mail_limits.inbox = 1;
        let count = |rig: &LocalRig, table: &str| -> u64 {
            rig.bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .db
                .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                .unwrap()
        };
        mb_heads(&mut rig, MB_MAILBOX, 2);
        let (syncs, _) = mb_out(&mut rig);
        let head = rig.bridge.membership.as_ref().unwrap().head();
        let from_b = mb_cancel(&rig, &host, "host-b", &host.sender, head);
        mb_receive(&mut rig, &mb_page(&syncs[0], 2, &[from_b]));
        // C signs at a head this host doesn't hold yet: it waits.
        let entry = host.s.log.add_host("host-c", 1, &secret("host c"));
        let mut c = atem_client::SoftwareKeys::new();
        c.insert_ed25519(atem_client::KeyId::new("host-b"), &secret("host c"));
        let from_c = mb_cancel(&rig, &host, "host-c", &c, host.s.log.log.head());
        let (syncs, _) = mb_out(&mut rig);
        mb_receive(&mut rig, &mb_page(&syncs[0], 2, &[from_c]));
        assert_eq!(count(&rig, "mailbox_pending"), 1);
        // The list moves: C's object would open, but the inbox is full.
        carry(&mut rig, &host.s.log, entry);
        rig.bridge.sync_list_view();
        mb_tick(&mut rig, &mut host, 2_000);
        assert_eq!(
            (count(&rig, "mailbox_pending"), count(&rig, "mailbox_inbox")),
            (1, 1)
        );
        assert_eq!(mb_store(&rig).owed, [1], "no done while it waits");
        // Room frees: judged again at once, opened, its done owed.
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .execute("DELETE FROM mailbox_inbox", [])
            .unwrap();
        mb_tick(&mut rig, &mut host, 2_000);
        assert_eq!(
            (count(&rig, "mailbox_pending"), count(&rig, "mailbox_inbox")),
            (0, 1)
        );
        assert_eq!(mb_store(&rig).owed, [1, 2]);
    });
}

/// Review P4: a skip ends once its object expires: with no room ever
/// freed, the rewind still comes once `D` passes the skipped object's
/// expiry, and the gate's mailbox part no longer waits for it.
#[test]
fn a_skip_ends_in_the_bridge_once_its_object_expires() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = mb_host(&mut rig, root, &os);
        rig.bridge.work.mail_limits.results = 1;
        mb_heads(&mut rig, MB_MAILBOX, 2);
        let (syncs, _) = mb_out(&mut rig);
        let first = mb_result(&rig, &host);
        mb_receive(&mut rig, &mb_page(&syncs[0], 2, &[first]));
        let (syncs, _) = mb_out(&mut rig);
        let second = mb_result(&rig, &host);
        mb_receive(&mut rig, &mb_page(&syncs[0], 2, &[second]));
        assert!(mb_store(&rig).skipped);
        mb_tick(&mut rig, &mut host, 2_000);
        assert!(mb_store(&rig).skipped, "no room, not expired: it waits");
        // `D` passes its expiry (an hour): the Station has dropped it.
        rig.bridge.start_view().now_d_ms = Some(host_now().wall_ms + 2 * HOUR);
        mb_tick(&mut rig, &mut host, 2_000);
        let observed = mb_store(&rig);
        assert!(!observed.skipped);
        assert_eq!(observed.cursor, Some((MB_MAILBOX.into(), 1)));
        let (syncs, _) = mb_out(&mut rig);
        assert_eq!(syncs[0].after, 1);
        // The Station no longer lists it: read to the head, the gate open
        // once the kept result goes.
        mb_receive(&mut rig, &mb_page(&syncs[0], 2, &[]));
        assert!(!mb_store(&rig).skipped);
    });
}

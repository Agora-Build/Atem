// Host senders' encryption key rotated in the bridge (the routine rotation,
// agreed with Astation on 2026-11-23, #120 comment 7089435308): the rig's
// host as the mailbox tests make it (`mb_host`: its list sets the key it
// made), a manager's new key made pending (`host_enc::new_pending`, the op's
// durable part), its entry signed and carried: the device list's commit
// watch stamps the application with the start view's `D` before the list
// is written, the host key pass promotes it, and B's envelopes sealed to
// the old or the new key are opened or refused through the mailbox as the
// receiver's view says. Included beside the mailbox tests, whose helpers
// it shares; every name here starts with `hk_`.

/// The host's key file (JSON).
fn hk_file(rig: &LocalRig) -> Value {
    serde_json::from_slice(
        &std::fs::read(&rig.bridge.pairing.as_ref().unwrap().host_enc_key).unwrap(),
    )
    .unwrap()
}

/// A manager's `host_enc_key_new`, as the op makes it durable: the pending
/// key.
fn hk_new_key(rig: &LocalRig) -> atem_client::PublicKey {
    let pairing = rig.bridge.pairing.clone().unwrap();
    let mut store = crate::session_protocol::membership::store::Store::new(
        &pairing,
        &crate::session_protocol::membership::journal_of(&pairing),
    );
    let (key, _, _) = crate::session_protocol::r9::host_enc::new_pending(
        &mut store,
        &pairing,
        rig.bridge.membership.as_ref().unwrap().membership(),
        rig.bridge.host_key.as_ref().unwrap(),
        "host",
        1,
        &uuid::Uuid::new_v4().to_string(),
    )
    .unwrap();
    key.public
}

/// B's envelope sealed to `key`, delivered through the mailbox at the next
/// position: whether it opened (an inbox row) or why it was refused.
fn hk_deliver(
    rig: &mut LocalRig,
    host: &mut MbHost,
    key: &atem_client::PublicKey,
    position: &mut u64,
) -> Result<(), String> {
    let head = rig.bridge.membership.as_ref().unwrap().head();
    // Its times on the receiver's clock, `D`.
    let now = rig.bridge.start_view().now_d_ms.unwrap();
    let list = rig.bridge.membership.as_ref().unwrap().membership();
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
        enc_kid: atem_client::keys::enc_kid(key).unwrap(),
        id: uuid::Uuid::new_v4().to_string(),
        created_at: now - 1_000,
        expires_at: now + HOUR,
        signed_at_head: head,
    };
    let cancel = atem_client::host_mail::seal_envelope(
        &host.sender,
        &atem_client::KeyId::new("host-b"),
        &fields,
        &atem_client::host_mail::EnvelopePlain::Cancel {
            task_id: uuid::Uuid::new_v4().to_string(),
        },
        key,
    )
    .unwrap()
    .to_json();
    let inbox = mb_store(rig).inbox;
    *position += 1;
    // A call at most once a second.
    mb_tick(rig, host, 2_000);
    mb_heads(rig, MB_MAILBOX, *position);
    let (syncs, _) = mb_out(rig);
    let [sync] = syncs.as_slice() else {
        panic!("one sync: {syncs:?}");
    };
    mb_receive(rig, &mb_page(sync, *position, &[cancel]));
    if mb_store(rig).inbox > inbox {
        return Ok(());
    }
    let db = &rig.bridge.work.store.as_ref().unwrap().db;
    Err(db
        .query_row(
            "SELECT reason FROM mailbox_refused ORDER BY n DESC LIMIT 1",
            [],
            |r| r.get::<_, String>(0),
        )
        .unwrap())
}

/// The rotation's entry for `key` signed into the host's list and carried
/// to it (its commit watch stamps the pending key first).
fn hk_rotate(rig: &mut LocalRig, host: &mut MbHost, key: &atem_client::PublicKey, retire: bool) {
    let entry = mb_enc_entry(&host.s, key, retire);
    sign_and_carry(rig, &mut host.s, entry);
}

/// A routine rotation in the bridge: the commit stamps the pending key
/// with the start view's `D` before the list is written; the host key
/// pass promotes it; B's envelope sealed to the old key still opens, and
/// one sealed to the new key opens; once `D` passes the stamp's `D` + 24 h
/// the old key's secret is erased and its mail is refused
/// `enc_key_not_accepted`.
#[test]
fn a_routine_rotation_keeps_the_old_key_for_mail_in_flight_for_24_hours() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = mb_host(&mut rig, root, &os);
        let d0 = rig.bridge.start_view().now_d_ms.unwrap();
        let old = host.enc_pub.clone();
        let new = hk_new_key(&rig);
        hk_rotate(&mut rig, &mut host, &new, false);
        let stamp = hk_file(&rig)["applied"].clone();
        assert_eq!(stamp["d_ms"], d0, "stamped at the commit: {stamp}");
        assert_eq!(stamp["seq"], host.s.log.log.head().seq);
        rig.bridge.host_key_pass();
        let file = hk_file(&rig);
        assert_eq!(
            file["current"]["pub"],
            json!(atem_client::encoding::b64u(new.as_bytes()))
        );
        assert_eq!(file["previous"]["applied_d_ms"], d0);
        let mut position = 0;
        assert_eq!(hk_deliver(&mut rig, &mut host, &old, &mut position), Ok(()));
        assert_eq!(hk_deliver(&mut rig, &mut host, &new, &mut position), Ok(()));
        // The window ends on `D`: the old secret erased at the pass.
        rig.bridge.start_view().now_d_ms =
            Some(d0 + crate::session_protocol::r9::host_enc::RETAIN_MS);
        rig.bridge.host_key_pass();
        assert!(hk_file(&rig).get("previous").is_none());
        assert_eq!(
            hk_deliver(&mut rig, &mut host, &old, &mut position),
            Err("enc_key_not_accepted".into())
        );
        assert_eq!(hk_deliver(&mut rig, &mut host, &new, &mut position), Ok(()));
    });
}

/// `retire_previous` (a suspected compromise): the old secret is erased
/// when the entry is applied, before any mail is opened under the new
/// state; mail in flight to the old key is refused, the new key's opens.
#[test]
fn retire_previous_refuses_mail_in_flight_to_the_old_key() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = mb_host(&mut rig, root, &os);
        let old = host.enc_pub.clone();
        let new = hk_new_key(&rig);
        hk_rotate(&mut rig, &mut host, &new, true);
        // No host key pass yet: the receiver's view promotes and retires
        // first.
        let mut position = 0;
        assert_eq!(
            hk_deliver(&mut rig, &mut host, &old, &mut position),
            Err("enc_key_not_accepted".into())
        );
        assert!(hk_file(&rig).get("previous").is_none());
        assert_eq!(hk_deliver(&mut rig, &mut host, &new, &mut position), Ok(()));
    });
}

/// On the delegated clock: the wall clock set back keeps the window
/// running (`D` never goes back), and a sleep counts (the boot-time
/// counter): the old key goes when `D` reaches the stamp's `D` + 24 h,
/// whatever the wall clock reads.
#[test]
fn the_window_runs_on_the_delegated_clock_through_sleep_and_a_clock_set_back() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = mb_host(&mut rig, root, &os);
        rig.bridge.clock_pass();
        rig.bridge.take_reading();
        let d0 = rig.bridge.start_view().now_d_ms.unwrap();
        let old = host.enc_pub.clone();
        let new = hk_new_key(&rig);
        hk_rotate(&mut rig, &mut host, &new, false);
        rig.bridge.host_key_pass();
        assert_eq!(hk_file(&rig)["previous"]["applied_d_ms"], d0);
        let accepted = |rig: &mut LocalRig| {
            rig.bridge.clock_pass();
            rig.bridge.take_reading();
            let (_, receiver, _) = rig.bridge.mail_receiver().unwrap();
            receiver.recipient.keys.len()
        };
        // The wall clock set back 10 h, an hour of boot time on: `D` keeps
        // going (an hour on), the window is open.
        {
            let mut r = os.0.lock().unwrap();
            r.wall_ms -= 10 * HOUR;
            r.boot_ns += HOUR * 1_000_000;
        }
        assert_eq!(accepted(&mut rig), 2);
        let d = rig.bridge.start_view().now_d_ms.unwrap();
        assert!(d >= d0 + HOUR, "D never goes back: {d} vs {d0}");
        // A sleep of 22 h 59 min (boot time and wall clock): still open.
        {
            let mut r = os.0.lock().unwrap();
            r.wall_ms += 22 * HOUR + 59 * 60_000 + 10 * HOUR;
            r.boot_ns += (22 * HOUR + 59 * 60_000) * 1_000_000;
        }
        assert_eq!(accepted(&mut rig), 2);
        // Another minute: 24 h of `D` since the application.
        os.pass(60_000);
        assert_eq!(accepted(&mut rig), 1);
        assert!(hk_file(&rig).get("previous").is_none());
        let mut position = 0;
        assert_eq!(
            hk_deliver(&mut rig, &mut host, &old, &mut position),
            Err("enc_key_not_accepted".into())
        );
    });
}

/// Crash point: after the device list committed the rotation's entry,
/// before the promotion (the runtime gone with the key file still holding
/// the pending key, its stamp written). The restarted host promotes it
/// from the stamp: the window ends at the stamp's `D` + 24 h, not 24 h
/// after the restart.
#[test]
fn a_restart_after_the_commit_keeps_the_stamps_deadline() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = mb_host(&mut rig, root, &os);
        let d0 = rig.bridge.start_view().now_d_ms.unwrap();
        let new = hk_new_key(&rig);
        hk_rotate(&mut rig, &mut host, &new, false);
        assert!(hk_file(&rig).get("pending").is_some(), "not promoted yet");
        // The restart comes 20 h later on `D`: the old key's window has
        // 4 h left, not 24.
        rig.bridge.work.host_key_checked = None;
        rig.bridge.start_view().now_d_ms = Some(d0 + 20 * HOUR);
        rig.bridge.host_key_pass();
        assert_eq!(hk_file(&rig)["previous"]["applied_d_ms"], d0);
        assert_eq!(
            rig.bridge.work.host_key_checked.as_ref().unwrap().4,
            Some(d0 + 24 * HOUR)
        );
        rig.bridge.start_view().now_d_ms = Some(d0 + 24 * HOUR);
        rig.bridge.host_key_pass();
        assert!(hk_file(&rig).get("previous").is_none());
    });
}

/// The clock's tick now (its throttle aside), then a pass's reading.
fn hk_tick(rig: &mut LocalRig) {
    let store = rig.bridge.work.store.as_ref().unwrap();
    rig.bridge.work.clock.as_mut().unwrap().tick(store);
    rig.bridge.take_reading();
}

/// Review L2: the commit watch reads `D` fresh from the clock, never the
/// start view's last reading: a commit made after a sleep the pass hasn't
/// read yet stamps the time after it.
#[test]
fn the_stamp_reads_d_fresh_after_a_sleep() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = mb_host(&mut rig, root, &os);
        let d0 = rig.bridge.start_view().now_d_ms.unwrap();
        let new = hk_new_key(&rig);
        // A 10 h sleep (boot time counts it), no pass since.
        os.pass(10 * HOUR);
        hk_rotate(&mut rig, &mut host, &new, false);
        assert_eq!(
            rig.bridge.start_view().now_d_ms,
            Some(d0),
            "the view is stale"
        );
        assert_eq!(hk_file(&rig)["applied"]["d_ms"], d0 + 10 * HOUR);
    });
}

/// Ruling R63 (review M2) on the real delegated clock: `D` ahead at the
/// stamp (an unsynchronized forward jump, its anchor pending), then the
/// jump undone (a repair, recorded with the clock): the previous key is
/// retired at once, since its window could otherwise run longer than 24 h
/// of real time.
#[test]
fn a_clock_repair_after_the_stamp_retires_the_previous_key_at_once() {
    local_test(async |root| {
        use crate::runtime::host_clock::os::Synced;
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut host = mb_host(&mut rig, root, &os);
        hk_tick(&mut rig);
        let old = host.enc_pub.clone();
        // An unsynchronized jump of 2 h: `D` runs ahead.
        {
            let mut r = os.0.lock().unwrap();
            r.wall_ms += 2 * HOUR + 1_000;
            r.boot_ns += 1_000_000_000;
            r.synced = Synced::No;
        }
        hk_tick(&mut rig);
        let ahead = rig.bridge.start_view().now_d_ms.unwrap();
        let new = hk_new_key(&rig);
        hk_rotate(&mut rig, &mut host, &new, false);
        rig.bridge.host_key_pass();
        assert_eq!(hk_file(&rig)["previous"]["applied_d_ms"], ahead);
        let mut position = 0;
        assert_eq!(hk_deliver(&mut rig, &mut host, &old, &mut position), Ok(()));
        // The jump undone a second later: the clock repairs `D`.
        {
            let mut r = os.0.lock().unwrap();
            r.wall_ms -= 2 * HOUR;
            r.boot_ns += 1_000_000_000;
        }
        hk_tick(&mut rig);
        let change = rig.bridge.start_view().clock.as_ref().unwrap().change();
        assert!(change.is_some(), "a repair recorded");
        rig.bridge.work.host_key_checked = None;
        rig.bridge.host_key_pass();
        assert!(hk_file(&rig).get("previous").is_none(), "retired at once");
        assert_eq!(
            hk_deliver(&mut rig, &mut host, &old, &mut position),
            Err("enc_key_not_accepted".into())
        );
    });
}

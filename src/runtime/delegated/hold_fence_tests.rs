// The hold's session-v1 fence in the bridge (host-work-v1 §11.1, Atem's
// reading of Astation's item 7 on #120, 2026-11-14; session-v1 R9.11): a
// control record that holds a service closes its r9 attachments and
// refuses its `hello`s (`busy`, `paused`) until a release, from the
// committed control state, before the hold's result goes to the Station
// and across a crash; reversible, never a revocation. The rig's host with
// the bot covered by its own Station's feed (`fed_bot`), its records read
// through the bridge's sync (`feed`). Included beside the effects' tests,
// whose helpers and imports it shares.

/// What a held service's `hello` and its closed attachments get.
fn paused_refusal() -> (String, Option<String>) {
    ("busy".into(), Some(details::PAUSED.into()))
}

/// The errors `channel` (the bot's, on `handle`) read from the engine's
/// frames since the last flush, and how many closes it got.
fn hf_errors(
    rig: &mut LocalRig,
    channel: &mut atem_client::connect::Attached,
    handle: &str,
) -> (Vec<(String, Option<String>)>, usize) {
    let (frames, closes) = flushed(rig, handle);
    let errors = frames
        .iter()
        .flat_map(|f| channel.on_frame(f, 1).unwrap())
        .filter_map(|e| match e {
            atem_client::connect::Event::Error(e) | atem_client::connect::Event::Fenced(e) => {
                Some((e.code, e.detail))
            }
            _ => None,
        })
        .collect();
    (errors, closes.len())
}

/// The bot's request `frame` on its channel `handle`, as the router
/// delivers it.
fn hf_send(rig: &mut LocalRig, handle: &str, frame: &[u8]) {
    envelope_in(rig, &envelope::frame(handle, frame));
}

/// The bot on `handle` lists the sessions (its client learns the rig's).
fn hf_list(rig: &mut LocalRig, channel: &mut atem_client::connect::Attached, handle: &str) {
    let (_, frame) = channel.list(1).unwrap();
    hf_send(rig, handle, &frame);
    for f in frames_for(rig, handle) {
        channel.on_frame(&f, 1).unwrap();
    }
    assert!(channel.target(rig.sid.as_str()).is_some(), "listed");
}

/// [`fed_bot`] with the bot's grant holding `ops`.
fn fed_bot_ops(
    rig: &mut LocalRig,
    root: &Path,
    os: &ManualOs,
    start: u64,
    ops: &[&str],
) -> Senders {
    let s = with_bot_ops(rig, root, os, start + 3 * HOUR, ops);
    rig.bridge.work.controls = None;
    rig.bridge.start_view().standings.clear();
    feed(rig, &s.log, &[&bot_record(&s.log, ControlAction::Cover, 1)]);
    assert!(matches!(
        rig.bridge.sender_class(BOT),
        SenderClass::Delegated(_)
    ));
    s
}

/// Item 7 (#120): once the hold commits, the bot's live attachment is
/// closed through §H after `busy`, `paused` (its `control_gen` raised once),
/// its new `hello` refused so, the phone (a native) untouched. It is no
/// revocation: the bot's queued delegated task waits `paused` with no
/// attempt counted, and its running turn goes on (no Esc).
#[test]
fn a_hold_fences_a_live_service_and_refuses_its_hello_paused() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = fed_bot(&mut rig, root, &os, start);
        r9_link_up(&mut rig);
        let mut channel = service_hello(&mut rig, &s.log, "bot-1", "svc-bot").unwrap();
        hello_as(&mut rig, &s.log, "phone-1", phone_identity()).unwrap();
        let running = bot_running(&mut rig, &s, "HELD_RUNNING", start).await;
        let queued = bot_task(&mut rig, &s, "HELD_QUEUED", start + HOUR);
        blocked(&mut rig, &queued, BEHIND).await;
        let before = rig.bridge.host.control_gen(BOT);
        feed(
            &mut rig,
            &s.log,
            &[&bot_record(&s.log, ControlAction::Hold, 2)],
        );
        // What the bot got before the hold, read in order.
        let (before_hold, _) = hf_errors(&mut rig, &mut channel, "bot-1");
        assert!(before_hold.is_empty(), "{before_hold:?}");
        passes(&mut rig, 1);
        let (errors, closes) = hf_errors(&mut rig, &mut channel, "bot-1");
        assert_eq!(errors, [paused_refusal()]);
        assert_eq!(closes, 1);
        assert!(!attached(&rig, BOT), "closed");
        assert!(attached(&rig, PHONE), "a native stays");
        assert_eq!(rig.bridge.host.control_gen(BOT), before + 1);
        assert_eq!(
            refusal(service_hello(&mut rig, &s.log, "bot-2", "svc-bot")),
            paused_refusal()
        );
        hello_as(&mut rig, &s.log, "phone-2", phone_identity()).unwrap();
        // A hold, not a revocation.
        assert_eq!(settled(&rig, &queued), outcome(Event::Held));
        assert!(attempts(&rig, &queued).is_empty());
        passes(&mut rig, 3);
        assert_eq!(
            settled(&rig, &running),
            (WorkState::Submitted, "in the agent's turn".into())
        );
        assert_eq!(escs(&rig), 0, "no interrupt");
        assert_eq!(rig.bridge.host.control_gen(BOT), before + 1, "once");
    });
}

/// Items 7 and 16 (#120): in the Station step that commits a hold of the
/// bot, whose channel is live, the bot's attachment is fenced before the
/// hold's result is handed to the link.
#[test]
fn a_holds_ack_goes_after_its_fence() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = fed_bot(&mut rig, root, &os, start);
        r9_link_up(&mut rig);
        service_hello(&mut rig, &s.log, "bot-1", "svc-bot").unwrap();
        assert!(attached(&rig, BOT));
        let _sent = station_up(&mut rig, 7);
        let hold = bot_record(&s.log, ControlAction::Hold, 2);
        let heads = heads_text(&[(ORIGIN, OWN_FEED, 2)], s.log.log.head());
        station_pass(&mut rig, 0, vec![heads]);
        let page = page_text(&rig, 2, &[(2, &hold)]);
        station_pass(&mut rig, 100, vec![page]);
        let id = hold.record_id().to_string();
        let (_, attached_then) = rig
            .bridge
            .work
            .acks_handed
            .iter()
            .find(|(ids, _)| ids.contains(&id))
            .expect("the hold's ack handed to the link")
            .clone();
        assert!(
            !attached_then.iter().any(|p| p == BOT),
            "fenced before its ack: {attached_then:?}"
        );
        assert!(!attached(&rig, BOT));
    });
}

/// Item 7 (#120): what the bot queued before the hold never runs after it,
/// and its release restores nothing. Its prompt, accepted with the lease
/// and held back from dispatch, is rejected (`control revoked`) and never
/// written, the dispatch let go; its lease is revoked. Released, the bot's
/// fresh `hello` is admitted, holding no lease, its prompt still rejected
/// and unwritten.
#[test]
fn a_release_admits_a_fresh_hello_and_restores_no_lease_or_command() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = fed_bot_ops(
            &mut rig,
            root,
            &os,
            start,
            &["message", "notify", "prompt", "stop", "terminal", "view"],
        );
        r9_link_up(&mut rig);
        let mut channel = service_hello(&mut rig, &s.log, "bot-1", "svc-bot").unwrap();
        hf_list(&mut rig, &mut channel, "bot-1");
        rig.bridge.host.hold_dispatch(true);
        let rid = uuid::Uuid::new_v4().to_string();
        let sid = rig.sid.as_str().to_string();
        let (_, frame) = channel
            .submit_prompt(&sid, &rid, "QUEUED_BEFORE_THE_HOLD", 1)
            .unwrap();
        hf_send(&mut rig, "bot-1", &frame);
        assert_eq!(
            rig.bridge.host.receipt(&rid).map(|r| r.state),
            Some(crate::session_protocol::wire::ReceiptState::Accepted)
        );
        assert!(rig.bridge.host.lease_holder(&sid).is_some(), "its lease");
        feed(
            &mut rig,
            &s.log,
            &[&bot_record(&s.log, ControlAction::Hold, 2)],
        );
        passes(&mut rig, 1);
        assert!(!attached(&rig, BOT));
        let receipt = rig.bridge.host.receipt(&rid).unwrap();
        assert_eq!(
            (receipt.state, receipt.detail.as_deref()),
            (
                crate::session_protocol::wire::ReceiptState::Rejected,
                Some("control revoked")
            )
        );
        assert_eq!(rig.bridge.host.lease_holder(&sid), None);
        rig.bridge.host.hold_dispatch(false);
        passes(&mut rig, 3);
        assert!(!input(&rig).contains("QUEUED_BEFORE_THE_HOLD"));
        // Released: a fresh hello; nothing of before comes back.
        feed(
            &mut rig,
            &s.log,
            &[&bot_record(&s.log, ControlAction::Release, 3)],
        );
        passes(&mut rig, 1);
        service_hello(&mut rig, &s.log, "bot-2", "svc-bot").unwrap();
        assert!(attached(&rig, BOT));
        assert_eq!(rig.bridge.host.lease_holder(&sid), None, "no old lease");
        passes(&mut rig, 3);
        assert_eq!(
            rig.bridge.host.receipt(&rid).map(|r| r.state),
            Some(crate::session_protocol::wire::ReceiptState::Rejected)
        );
        assert!(!input(&rig).contains("QUEUED_BEFORE_THE_HOLD"));
    });
}

/// Items 7 and 16 (#120), the crash between a hold's commit and the pass
/// that fences: the run ends with the hold stored and the bot's fence not
/// written. At the next start the loaded control state shows the bot held
/// while the session host still grants it `control`: the fence is written
/// at the load, before any service is admitted (its `hello` is `busy`,
/// `paused`), once; it ends the bot's pre-cover v1 task as any §H fence
/// does (`failed`, `sender's authority changed`, host-work-v1 §11.1), and
/// a later task on that session runs. Another start writes no fence more.
#[test]
fn a_holds_fence_lost_to_a_crash_is_written_at_the_next_load() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        let (busy, v1) = a_v1_task_behind_the_phones_turn(&mut rig, &s, start).await;
        let before = rig.bridge.host.control_gen(BOT);
        assert!(rig.bridge.host.grants_control(BOT));
        feed(
            &mut rig,
            &s.log,
            &[
                &bot_record(&s.log, ControlAction::Cover, 1),
                &bot_record(&s.log, ControlAction::Hold, 2),
            ],
        );
        // The run ends before any pass fenced.
        assert_eq!(rig.bridge.host.control_gen(BOT), before);
        restart(&mut rig, root, &os, false, true);
        assert_eq!(rig.bridge.host.control_gen(BOT), before + 1);
        assert!(!rig.bridge.host.grants_control(BOT));
        r9_link_up(&mut rig);
        assert_eq!(
            refusal(service_hello(&mut rig, &s.log, "bot-2", "svc-bot")),
            paused_refusal()
        );
        rig.bridge.start_view().gates.open_own_station(ORIGIN);
        ended_by_the_fence(&mut rig, &s, &busy, &v1, start).await;
        // Once: another start writes no fence more.
        restart(&mut rig, root, &os, false, true);
        passes(&mut rig, 2);
        assert_eq!(rig.bridge.host.control_gen(BOT), before + 1);
    });
}

/// Item 7 (#120): a hold is reversible, a revoke final. Held, the bot's
/// `hello` is `busy`, `paused`; revoked after, `unauthorized`, `revoked`,
/// its queued task cancelled; a release after the revoke lifts nothing.
#[test]
fn a_hold_then_a_revoke_is_final() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = fed_bot(&mut rig, root, &os, start);
        r9_link_up(&mut rig);
        let task = bot_task(&mut rig, &s, "HELD_THEN_REVOKED", start + HOUR);
        feed(
            &mut rig,
            &s.log,
            &[&bot_record(&s.log, ControlAction::Hold, 2)],
        );
        passes(&mut rig, 1);
        assert_eq!(settled(&rig, &task), outcome(Event::Held));
        assert_eq!(
            refusal(service_hello(&mut rig, &s.log, "bot-1", "svc-bot")),
            paused_refusal()
        );
        feed(&mut rig, &s.log, &[&bot_record(&s.log, revoke(false), 3)]);
        passes(&mut rig, 1);
        assert_eq!(settled(&rig, &task), outcome(Event::Revoked));
        assert_eq!(
            refusal(service_hello(&mut rig, &s.log, "bot-2", "svc-bot")),
            revoked_refusal()
        );
        feed(
            &mut rig,
            &s.log,
            &[&bot_record(&s.log, ControlAction::Release, 4)],
        );
        passes(&mut rig, 1);
        assert_eq!(
            refusal(service_hello(&mut rig, &s.log, "bot-3", "svc-bot")),
            revoked_refusal()
        );
        assert!(rig.bridge.r9.held_services().is_empty());
        assert_eq!(settled(&rig, &task), outcome(Event::Revoked));
    });
}

/// A hold and a revoke of the bot read in one batch (`two_pages`: two pages
/// whose followups one Station step carries out; else one page), the hold
/// first in the feed when `hold_first`: the revoke wins. Only its fence
/// runs (the bot's `control_gen` raised once), so its live channel closes
/// after `unauthorized`, `revoked` (session-v1 R9.7a), never `busy`,
/// `paused`, and before either record's result goes; its next `hello` is
/// refused `revoked`.
fn hold_and_revoke_in_one_batch(two_pages: bool, hold_first: bool) {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = fed_bot(&mut rig, root, &os, start);
        r9_link_up(&mut rig);
        let mut channel = service_hello(&mut rig, &s.log, "bot-1", "svc-bot").unwrap();
        let before = rig.bridge.host.control_gen(BOT);
        let _sent = station_up(&mut rig, 7);
        let (first, second) = if hold_first {
            (ControlAction::Hold, revoke(false))
        } else {
            (revoke(false), ControlAction::Hold)
        };
        let first = bot_record(&s.log, first, 2);
        let second = bot_record(&s.log, second, 3);
        let heads = heads_text(&[(ORIGIN, OWN_FEED, 3)], s.log.log.head());
        station_pass(&mut rig, 0, vec![heads]);
        if two_pages {
            // Each page read as it comes; their followups wait for the
            // Station step that carries them out together.
            bridge_page(&mut rig, 3, &[(2, &first)]);
            bridge_page(&mut rig, 3, &[(3, &second)]);
            station_pass(&mut rig, 100, Vec::new());
        } else {
            let page = page_text(&rig, 3, &[(2, &first), (3, &second)]);
            station_pass(&mut rig, 100, vec![page]);
        }
        let what = format!("two pages {two_pages}, hold first {hold_first}");
        let (errors, closes) = hf_errors(&mut rig, &mut channel, "bot-1");
        assert_eq!(errors, [revoked_refusal()], "{what}");
        assert_eq!(closes, 1, "{what}");
        assert_eq!(rig.bridge.host.control_gen(BOT), before + 1, "{what}");
        for record in [&first, &second] {
            let (attached_then, remote_then) = hf_hold_ack(&rig, record.record_id());
            assert!(!attached_then.iter().any(|p| p == BOT), "{what}");
            assert!(!remote_then.iter().any(|p| p == BOT), "{what}");
        }
        assert_eq!(
            refusal(service_hello(&mut rig, &s.log, "bot-2", "svc-bot")),
            revoked_refusal(),
            "{what}"
        );
    });
}

/// The revoke wins over a hold read with it in one page, in either order
/// (the follow-up to item 7 on #120). With the revoke first the hold is
/// refused after it and asks no fence of its own.
#[test]
fn a_revoke_in_the_holds_page_closes_the_channel_revoked() {
    hold_and_revoke_in_one_batch(false, true);
    hold_and_revoke_in_one_batch(false, false);
}

/// The revoke wins over a hold read in an earlier page of the same Station
/// step, in either order.
#[test]
fn a_revoke_in_the_holds_pass_closes_the_channel_revoked() {
    hold_and_revoke_in_one_batch(true, true);
    hold_and_revoke_in_one_batch(true, false);
}

/// Hook off = main (review m2's rule for session-v1): with `host.delegated`
/// off, a held service's records still reach its tasks, but nothing of
/// session-v1 is fenced or refused for the hold: its `hello` is admitted,
/// its `control_gen` unmoved.
#[test]
fn with_the_hook_off_a_hold_fences_nothing() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = fed_bot(&mut rig, root, &os, start);
        feed(
            &mut rig,
            &s.log,
            &[&bot_record(&s.log, ControlAction::Hold, 2)],
        );
        assert!(rig.bridge.start_view().standings[BOT].held);
        // The hook removed: a restart's fresh engine, the feeds loaded again
        // for the delegated rows.
        rig.bridge.features = HostFeatures::default();
        let effects = rig
            .bridge
            .r9_call(|r9, parts| r9.set_held_services(HashSet::new(), parts));
        assert!(effects.is_empty());
        rig.bridge.work.feeds = Feeds::Unloaded;
        r9_link_up(&mut rig);
        let before = rig.bridge.host.control_gen(BOT);
        passes(&mut rig, 2);
        assert!(matches!(rig.bridge.work.feeds, Feeds::Loaded(_)));
        assert!(rig.bridge.r9.held_services().is_empty());
        service_hello(&mut rig, &s.log, "bot-1", "svc-bot").unwrap();
        assert_eq!(rig.bridge.host.control_gen(BOT), before);
    });
}

/// The bot's prompt on the rig's session, accepted with the lease (its
/// `acquire`) and held back from dispatch (`hold_dispatch`): its request id.
fn hf_queued_prompt(
    rig: &mut LocalRig,
    channel: &mut atem_client::connect::Attached,
    handle: &str,
    text: &str,
) -> String {
    hf_list(rig, channel, handle);
    rig.bridge.host.hold_dispatch(true);
    let rid = uuid::Uuid::new_v4().to_string();
    let sid = rig.sid.as_str().to_string();
    let (_, frame) = channel.submit_prompt(&sid, &rid, text, 1).unwrap();
    hf_send(rig, handle, &frame);
    assert_eq!(
        rig.bridge.host.receipt(&rid).map(|r| r.state),
        Some(crate::session_protocol::wire::ReceiptState::Accepted)
    );
    assert!(rig.bridge.host.lease_holder(&sid).is_some(), "its lease");
    rid
}

/// The hold's ack as it was handed to the link: the r9 attachments' and
/// the session host's remote principals then.
fn hf_hold_ack(rig: &LocalRig, hold: &str) -> (Vec<String>, Vec<String>) {
    let attached = rig
        .bridge
        .work
        .acks_handed
        .iter()
        .find(|(ids, _)| ids.iter().any(|id| id == hold))
        .expect("the hold's ack handed to the link")
        .1
        .clone();
    let remote = rig
        .bridge
        .work
        .acks_remote
        .iter()
        .find(|(ids, _)| ids.iter().any(|id| id == hold))
        .expect("the hold's ack handed to the link")
        .1
        .clone();
    (attached, remote)
}

/// The bot's prompt `rid` was rejected by the fence, never written.
fn hf_rejected(rig: &LocalRig, rid: &str, text: &str) {
    let receipt = rig.bridge.host.receipt(rid).unwrap();
    assert_eq!(
        (receipt.state, receipt.detail.as_deref()),
        (
            crate::session_protocol::wire::ReceiptState::Rejected,
            Some("control revoked")
        )
    );
    assert!(!input(rig).contains(text));
}

/// Items 7 and 16 (#120): a hold and its release read in one page. Both
/// commit and the standings end released, but the hold was in force: its
/// fence runs before its result goes to the Station (the bot's attachment
/// closed, its `control_gen` raised once, its lease revoked, its accepted
/// prompt rejected `control revoked`, never written), and the release then
/// admits a fresh `hello`.
#[test]
fn a_hold_released_in_its_own_page_is_fenced_before_its_ack() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = fed_bot_ops(
            &mut rig,
            root,
            &os,
            start,
            &["message", "notify", "prompt", "stop", "view"],
        );
        r9_link_up(&mut rig);
        let mut channel = service_hello(&mut rig, &s.log, "bot-1", "svc-bot").unwrap();
        let rid = hf_queued_prompt(&mut rig, &mut channel, "bot-1", "HELD_AND_RELEASED");
        let before = rig.bridge.host.control_gen(BOT);
        let _sent = station_up(&mut rig, 7);
        let hold = bot_record(&s.log, ControlAction::Hold, 2);
        let release = bot_record(&s.log, ControlAction::Release, 3);
        let heads = heads_text(&[(ORIGIN, OWN_FEED, 3)], s.log.log.head());
        station_pass(&mut rig, 0, vec![heads]);
        let page = page_text(&rig, 3, &[(2, &hold), (3, &release)]);
        station_pass(&mut rig, 100, vec![page]);
        assert!(!rig.bridge.start_view().standings[BOT].held, "released");
        let (attached_then, remote_then) = hf_hold_ack(&rig, hold.record_id());
        assert!(
            !attached_then.iter().any(|p| p == BOT),
            "fenced before its ack: {attached_then:?}"
        );
        assert!(
            !remote_then.iter().any(|p| p == BOT),
            "fenced before its ack: {remote_then:?}"
        );
        assert_eq!(rig.bridge.host.control_gen(BOT), before + 1);
        assert_eq!(rig.bridge.host.lease_holder(rig.sid.as_str()), None);
        rig.bridge.host.hold_dispatch(false);
        passes(&mut rig, 3);
        hf_rejected(&rig, &rid, "HELD_AND_RELEASED");
        // Released: a fresh hello.
        service_hello(&mut rig, &s.log, "bot-2", "svc-bot").unwrap();
        assert_eq!(rig.bridge.host.control_gen(BOT), before + 1);
    });
}

/// Items 7 and 16 (#120): a hold read during the store's first read (the
/// control state never read in full, so every service is refused as
/// unchecked, and the page short of the announced head). The bot, gone
/// from its channel, still holds `control` and an accepted prompt: the
/// hold's fence runs before its result goes, though the state stays
/// unchecked (its `control_gen` raised once, its prompt rejected `control
/// revoked`, never written).
#[test]
fn a_hold_read_during_the_first_read_is_fenced_before_its_ack() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let s = fed_bot_ops(
            &mut rig,
            root,
            &os,
            start,
            &["message", "notify", "prompt", "stop", "view"],
        );
        r9_link_up(&mut rig);
        let mut channel = service_hello(&mut rig, &s.log, "bot-1", "svc-bot").unwrap();
        let rid = hf_queued_prompt(&mut rig, &mut channel, "bot-1", "HELD_IN_THE_FIRST_READ");
        envelope_in(&mut rig, &envelope::close("bot-1", Some("client_gone")));
        passes(&mut rig, 1);
        assert!(!attached(&rig, BOT));
        assert!(rig.bridge.host.grants_control(BOT));
        // The control state never read in full (a fresh store's mark).
        rig.bridge
            .work
            .store
            .as_ref()
            .unwrap()
            .db
            .execute("INSERT INTO control_unread(one) VALUES(1)", [])
            .unwrap();
        rig.bridge.work.feeds = Feeds::Unloaded;
        rig.bridge.ensure_feeds();
        assert!(rig.bridge.controls_unchecked());
        let before = rig.bridge.host.control_gen(BOT);
        let _sent = station_up(&mut rig, 7);
        let hold = bot_record(&s.log, ControlAction::Hold, 2);
        let heads = heads_text(&[(ORIGIN, OWN_FEED, 3)], s.log.log.head());
        station_pass(&mut rig, 0, vec![heads]);
        let page = page_text(&rig, 3, &[(2, &hold)]);
        station_pass(&mut rig, 100, vec![page]);
        let cursor = match &rig.bridge.work.feeds {
            Feeds::Loaded(feeds) => feeds.cursor(ORIGIN, OWN_FEED),
            _ => None,
        };
        assert_eq!(cursor, Some(2), "short of the head");
        assert!(rig.bridge.start_view().standings[BOT].held);
        assert!(rig.bridge.controls_unchecked(), "still unchecked");
        let (_, remote_then) = hf_hold_ack(&rig, hold.record_id());
        assert!(
            !remote_then.iter().any(|p| p == BOT),
            "fenced before its ack: {remote_then:?}"
        );
        assert_eq!(rig.bridge.host.control_gen(BOT), before + 1);
        rig.bridge.host.hold_dispatch(false);
        passes(&mut rig, 3);
        hf_rejected(&rig, &rid, "HELD_IN_THE_FIRST_READ");
    });
}

// The control-feed sync in the bridge (Task 33; design I.5.2, I.5.4,
// I.5.8; host-work-v1 §11.4; step 4's Decisions 12, 16, 20): the rig's
// host with the bot and no control view standing in for the feeds, its
// Station link to [`ORIGIN`] set by hand (the rig has no r9 link, so these
// tests drive the bridge's feed steps between passes, never a pass), the
// Station's messages read by the Station link's reader. The transport and
// the passes are the binary tests' (`delegated_binary`,
// `control_feed_binary`). Included beside the dispatch's tests, whose
// helpers it shares.

/// The pass's clocks `ms` past the monotonic clock now (no boot-time
/// reading).
fn clocks_after(ms: u64) -> crate::runtime::delegated::sync::Clocks {
    crate::runtime::delegated::sync::Clocks {
        mono_ms: host_now().mono_ms + ms,
        boot_ms: None,
    }
}

/// The feed of the host's own Station in these tests.
const OWN_FEED: &str = "33333333-3333-4333-8333-333333333333";

/// [`with_bot`] with the feeds alone deciding (no control view standing in,
/// every gate closed, the standings the feeds'), and the host's Station
/// link to [`ORIGIN`], up.
fn fed_host(rig: &mut LocalRig, root: &Path, os: &ManualOs) -> Senders {
    use crate::runtime::delegated::feeds::Feeds;
    use crate::runtime::delegated::station::{LinkKind, Station};
    let s = with_bot(rig, root, os, host_now().wall_ms + 3 * HOUR);
    rig.bridge.work.controls = None;
    rig.bridge.start_view().gates = Gates::default();
    if let Feeds::Loaded(feeds) = &mut rig.bridge.work.feeds {
        feeds.publish();
    }
    let mut station = Station::new();
    station.sync_link(Some(1), || LinkKind::Routed, || Some(ORIGIN.to_string()));
    rig.bridge.station = Some(station);
    rig.bridge.ensure_feeds();
    rig.bridge.sync_list_view();
    // What a pass does first: the sync sees the link, the time, the feeds.
    rig.bridge.feed_advance(clocks_after(0));
    assert!(rig.bridge.start_view().list.is_some());
    s
}

/// Another Station's origin.
const OTHER_ORIGIN: &str = "https://station-other.agora.build";

/// The Station's `heads` (its own feed at `head`, the device list at
/// `membership`), read by the link's reader and handed to the bridge: the
/// sync's calls.
fn bridge_heads(
    rig: &mut LocalRig,
    head: u64,
    membership: atem_client::membership::Head,
) -> Vec<crate::runtime::delegated::station::Call> {
    bridge_heads_with(rig, &[(ORIGIN, OWN_FEED, head)], membership)
}

/// [`bridge_heads`] naming `feeds` (origin, feed, head).
fn bridge_heads_with(
    rig: &mut LocalRig,
    feeds: &[(&str, &str, u64)],
    membership: atem_client::membership::Head,
) -> Vec<crate::runtime::delegated::station::Call> {
    use crate::runtime::delegated::station::Inbound;
    use atem_client::control::{FeedHead, Heads};
    let heads = Heads {
        feeds: feeds
            .iter()
            .map(|(origin, feed_id, head)| FeedHead {
                origin: (*origin).into(),
                feed_id: (*feed_id).into(),
                head: *head,
                station_time: host_now().wall_ms,
            })
            .collect(),
        membership,
    };
    let text = heads.to_json().unwrap().to_string();
    let applied = rig.bridge.membership.as_ref().map(|m| m.head());
    let deferred = rig.bridge.list_deferral();
    let inbound = rig
        .bridge
        .station
        .as_mut()
        .unwrap()
        .receive(&text, applied, deferred);
    let Inbound::Heads(heads, _) = inbound else {
        panic!("heads: {inbound:?}");
    };
    let calls = rig.bridge.feed_heads(&heads);
    rig.bridge.publish_feed_gates();
    rig.bridge.refresh_fetch_view();
    calls
}

/// A page of the own feed (`records`: positions and records), read by the
/// link's reader and handed to the bridge: the sync's next call.
fn bridge_page(
    rig: &mut LocalRig,
    head: u64,
    records: &[(u64, &atem_client::control::ControlRecord)],
) -> Vec<crate::runtime::delegated::station::Call> {
    use crate::runtime::delegated::station::Inbound;
    use atem_client::control::{ControlSyncResult, FeedEntry};
    let page = ControlSyncResult {
        origin: ORIGIN.into(),
        feed_id: OWN_FEED.into(),
        head,
        station_time: host_now().wall_ms,
        records: records.iter().map(|(n, r)| FeedEntry::new(*n, r)).collect(),
    };
    let text = page.to_json().unwrap().to_string();
    let inbound = rig
        .bridge
        .station
        .as_mut()
        .unwrap()
        .receive(&text, None, None);
    let Inbound::Page(page) = inbound else {
        panic!("a page: {inbound:?}");
    };
    let calls = rig.bridge.feed_page(page);
    rig.bridge.feeds_reverify();
    rig.bridge.publish_feed_gates();
    calls
}

/// A record of `service` in the own feed, signed with its key.
fn own_record(
    log: &TestLog,
    service: &str,
    action: atem_client::control::ControlAction,
    n: u64,
) -> atem_client::control::ControlRecord {
    crate::runtime::delegated::feeds::signed_record(
        log,
        service,
        service,
        action,
        uuid::Uuid::new_v4().to_string(),
        (ORIGIN, OWN_FEED),
        host_now().wall_ms + n,
    )
}

/// Task 33 (Decisions 13, 16): a `heads` and its page through the bridge,
/// with no pass: the cover makes the bot a delegated sender of the own
/// Station's feed, the standings are in the start view at the page's
/// commit, and the gate's feed part with them; the device-list part is the
/// fetch's (the list holds the announced head), so the start check's gate
/// is open for the bot and for a native.
#[test]
fn a_page_through_the_bridge_reaches_the_start_view_at_its_commit() {
    use crate::runtime::delegated::station::Call;
    use crate::runtime::delegated::{DelegatedSender, gate::GateView};
    use atem_client::control::{ControlAction, ControlSync};
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let s = fed_host(&mut rig, root, &os);
        assert_eq!(rig.bridge.sender_class(BOT), SenderClass::V1);
        let head = s.log.log.head();
        let calls = bridge_heads(&mut rig, 1, head);
        assert_eq!(
            calls,
            [Call::Sync(ControlSync {
                origin: ORIGIN.into(),
                feed_id: Some(OWN_FEED.into()),
                after: 0
            })]
        );
        let native = DelegatedSender::Native {
            device_id: "dev-phone".into(),
        };
        let fetched = |rig: &LocalRig| {
            let view = rig.bridge.start_view();
            let list = view.list.clone().unwrap();
            view.fetched(&list).map(str::to_string)
        };
        assert_eq!(fetched(&rig).as_deref(), Some(ORIGIN), "the list holds it");
        assert!(
            !rig.bridge
                .start_view()
                .gates
                .open_for(&native, Some(ORIGIN)),
            "nothing read yet"
        );
        let cover = own_record(&s.log, "svc-bot", ControlAction::Cover, 1);
        assert_eq!(bridge_page(&mut rig, 1, &[(1, &cover)]), []);
        let coverage = rig.bridge.start_view().standings[BOT].coverage.clone();
        assert_eq!(coverage.map(|c| c.feed_id).as_deref(), Some(OWN_FEED));
        let SenderClass::Delegated(DelegatedSender::Service { feed, .. }) =
            rig.bridge.sender_class(BOT)
        else {
            panic!("a covered bot is delegated");
        };
        assert_eq!(feed.origin, ORIGIN);
        let view = rig.bridge.start_view();
        assert!(view.gates.open_for(&native, Some(ORIGIN)));
        assert!(view.gates.open_for(
            &DelegatedSender::Service {
                device_id: "svc-bot".into(),
                feed
            },
            Some(ORIGIN)
        ));
        drop(view);
        // Hosting paused (a `runtime.toml` that doesn't load): the sync
        // goes on, and a revoke is in the start view at its commit (ledger
        // carry: a sender revoked during a pause keeps no standing).
        rig.bridge.work.config_problem = Some("paused by the test".into());
        // A second on: the sync's pace.
        rig.bridge.feed_advance(clocks_after(2_000));
        bridge_heads(&mut rig, 2, head);
        let revoke = own_record(
            &s.log,
            "svc-bot",
            ControlAction::Revoke {
                interrupt_running: false,
            },
            2,
        );
        bridge_page(&mut rig, 2, &[(2, &revoke)]);
        assert!(rig.bridge.start_view().standings[BOT].revoked.is_some());
    });
}

/// Task 32 review (Task 33's call sites): pending control records are
/// applied again once at start after the feeds load (a list advance that
/// committed before a crash), and whenever the device list moved.
#[test]
fn pending_records_are_reverified_at_load_and_when_the_list_moves() {
    use crate::runtime::delegated::feeds::Feeds;
    use crate::session_protocol::membership::r9log::{auth, secret};
    use atem_client::control::ControlAction;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let mut s = fed_host(&mut rig, root, &os);
        let head = s.log.log.head();
        bridge_heads(&mut rig, 2, head);
        // Two services the list doesn't hold yet: their records wait.
        for service in ["svc-new", "svc-late"] {
            s.log
                .keys
                .insert_ed25519(auth(service), &secret(&format!("{service} auth")));
        }
        let new = own_record(&s.log, "svc-new", ControlAction::Cover, 1);
        let late = own_record(&s.log, "svc-late", ControlAction::Cover, 2);
        bridge_page(&mut rig, 2, &[(1, &new), (2, &late)]);
        let pending = |rig: &LocalRig| match &rig.bridge.work.feeds {
            Feeds::Loaded(feeds) => feeds.pending_len(),
            _ => panic!("loaded"),
        };
        assert_eq!(pending(&rig), 2);
        // The list moves: the one it now holds applies.
        let expiry = host_now().wall_ms + 3 * HOUR;
        let entry = s.log.add_service(
            "svc-new",
            &["host"],
            None,
            &["notify", "prompt", "view"],
            expiry,
        );
        carry(&mut rig, &s.log, entry);
        rig.bridge.feeds_reverify();
        assert_eq!(pending(&rig), 1);
        assert!(
            rig.bridge.start_view().standings["service:svc-new"]
                .coverage
                .is_some()
        );
        // Kept for Task 35 to act on (Task 33 review m4).
        let kept = |rig: &LocalRig| {
            rig.bridge
                .work
                .reapplied
                .iter()
                .map(|r| r.record.principal().name())
                .collect::<Vec<_>>()
        };
        assert_eq!(kept(&rig), ["service:svc-new"]);
        // The other's list advance commits while the feeds aren't loaded
        // (as before a crash): the load re-verifies once, whatever head the
        // last re-verification saw.
        rig.bridge.work.feeds = Feeds::Unloaded;
        let entry = s.log.add_service(
            "svc-late",
            &["host"],
            None,
            &["notify", "prompt", "view"],
            expiry,
        );
        carry(&mut rig, &s.log, entry);
        rig.bridge.feeds_reverify();
        let head = s.log.log.head();
        rig.bridge.work.reverified = Some((head.seq, head.hash));
        rig.bridge.ensure_feeds();
        assert_eq!(pending(&rig), 1, "loaded, not yet re-verified");
        rig.bridge.feeds_reverify();
        assert_eq!(pending(&rig), 0);
        assert_eq!(kept(&rig), ["service:svc-new", "service:svc-late"]);
        assert!(
            rig.bridge.start_view().standings["service:svc-late"]
                .coverage
                .is_some()
        );
    });
}

/// `atem status`'s `Control feeds:` line (host-work-v1 §11.4, Decisions 12
/// and 20): none with the hook off; a damaged control state with the way
/// out; the host's own Station's gate in the start check's order, why it is
/// closed (a refusal: Decision 20's text; a device list that differs from
/// the Station's at the announced `seq`), with the evidence and pending
/// counts.
#[test]
fn the_control_feeds_status_line() {
    use crate::runtime::delegated::feeds::Feeds;
    use crate::runtime::delegated::sync::REFUSED_STATUS;
    use crate::session_protocol::membership::r9log::{auth, secret};
    use atem_client::control::{CallRefused, ControlAction, RefusalCode, RefusedCall};
    use atem_client::encoding::Hash32;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        assert_eq!(rig.bridge.feeds_status(), None, "the hook off: as main");
        let os = ManualOs::at(host_now().wall_ms);
        let mut s = fed_host(&mut rig, root, &os);
        assert_eq!(
            rig.bridge.feeds_status().unwrap(),
            "revocations not yet checked (waiting for the Station's heads); 0 kept as evidence, 0 pending"
        );
        let head = s.log.log.head();
        bridge_heads(&mut rig, 1, head);
        let cover = own_record(&s.log, "svc-bot", ControlAction::Cover, 1);
        bridge_page(&mut rig, 1, &[(1, &cover)]);
        assert_eq!(
            rig.bridge.feeds_status().unwrap(),
            format!("revocations checked ({ORIGIN}); 0 kept as evidence, 0 pending")
        );
        // A record that fails verification (Task 33 review m7: the feed
        // store's alerts are in the summary too).
        s.log
            .keys
            .insert_ed25519(auth("svc-forger"), &secret("forger"));
        let forged = crate::runtime::delegated::feeds::signed_record(
            &s.log,
            "svc-bot",
            "svc-forger",
            ControlAction::Hold,
            uuid::Uuid::new_v4().to_string(),
            (ORIGIN, OWN_FEED),
            host_now().wall_ms + 2,
        );
        rig.bridge.feed_advance(clocks_after(2_000));
        bridge_heads(&mut rig, 2, head);
        bridge_page(&mut rig, 2, &[(2, &forged)]);
        let line = rig.bridge.feeds_status().unwrap();
        assert!(
            line.starts_with(&format!(
                "revocations checked ({ORIGIN}); 1 kept as evidence, 0 pending; 1 alert(s) since the start, the latest: a control record from the feed of {ORIGIN} kept as evidence (bad_signature"
            )),
            "{line}"
        );
        // The feeds loaded again (ruling T33c, N3): the run's count stays.
        rig.bridge.work.feeds = Feeds::Unloaded;
        rig.bridge.ensure_feeds();
        assert_eq!(rig.bridge.feeds_status().unwrap(), line);
        // The Station announces another entry at the list's head `seq`.
        let fork = atem_client::membership::Head {
            seq: head.seq,
            hash: Hash32([9; 32]),
        };
        bridge_heads(&mut rig, 2, fork);
        let line = rig.bridge.feeds_status().unwrap();
        assert!(
            line.starts_with(&format!(
                "revocations not yet checked (the device list differs from the Station's at seq {}); 1 kept as evidence, 0 pending",
                head.seq
            )),
            "{line}"
        );
        // A refusal on the link: the gate's reason and an alert.
        let refused = CallRefused {
            call: RefusedCall::ControlAck,
            code: RefusalCode::Forbidden,
        }
        .to_json()
        .unwrap()
        .to_string();
        rig.bridge
            .station
            .as_mut()
            .unwrap()
            .receive(&refused, None, None);
        assert_eq!(
            rig.bridge.feeds_status().unwrap(),
            format!(
                "revocations not yet checked ({REFUSED_STATUS}); 1 kept as evidence, 0 pending; 2 alert(s) since the start, the latest: {REFUSED_STATUS}"
            )
        );
        // An alert of the sync's: counted, the latest named.
        bridge_heads_with(
            &mut rig,
            &[(ORIGIN, OWN_FEED, 2), (OTHER_ORIGIN, OWN_FEED, 1)],
            head,
        );
        let line = rig.bridge.feeds_status().unwrap();
        assert!(
            line.ends_with(&format!(
                "; 3 alert(s) since the start, the latest: the Station's heads named 1 control feed(s) of another origin than this host's own Station ({ORIGIN}); ignored"
            )),
            "{line}"
        );
        // A deferral comes first (the start check's order).
        if let Some(list) = rig.bridge.start_view().list.as_mut() {
            list.deferred = Some(crate::session_protocol::membership::DeferredStop {
                seq: head.seq + 1,
                until_ms: 0,
                on: None,
            });
        }
        assert!(
            rig.bridge
                .feeds_status()
                .unwrap()
                .starts_with("device list update pending;"),
            "{:?}",
            rig.bridge.feeds_status()
        );
        // A control state that doesn't read: the way out.
        rig.bridge.work.feeds = Feeds::Damaged;
        let line = rig.bridge.feeds_status().unwrap();
        assert!(line.contains("no delegated task starts"), "{line}");
        assert!(line.contains("pair this host again"), "{line}");
        assert!(line.contains("host-work.sqlite"), "{line}");
    });
}

/// Task 33 review I1, the probe's sequence through the bridge: the link
/// drops in an unpaused pass (the feed store's origin goes with it), hosting
/// pauses, the link comes back and the Station rolls its feed back under
/// the same `feed_id`. The sync's page is placed at the link's own Station
/// (the bridge gives the store the link's origin, pause or not), so the
/// gate never opens with the cursor anywhere but the announced head.
#[test]
fn a_reset_read_during_a_pause_lowers_the_cursor_before_the_gate_opens() {
    use crate::runtime::delegated::feeds::Feeds;
    use crate::runtime::delegated::station::LinkKind;
    use crate::runtime::delegated::{DelegatedSender, gate::GateView};
    use atem_client::control::ControlAction;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let s = fed_host(&mut rig, root, &os);
        let head = s.log.log.head();
        bridge_heads(&mut rig, 2, head);
        let cover = own_record(&s.log, "svc-bot", ControlAction::Cover, 1);
        let hold = own_record(&s.log, "svc-bot", ControlAction::Hold, 2);
        bridge_page(&mut rig, 2, &[(1, &cover), (2, &hold)]);
        let native = DelegatedSender::Native {
            device_id: "dev-phone".into(),
        };
        let open = |rig: &LocalRig| {
            rig.bridge
                .start_view()
                .gates
                .open_for(&native, Some(ORIGIN))
        };
        let cursor = |rig: &LocalRig| match &rig.bridge.work.feeds {
            Feeds::Loaded(feeds) => feeds.current_feed(ORIGIN),
            _ => panic!("loaded"),
        };
        assert!(open(&rig));
        // The link drops in an unpaused pass.
        let station = rig.bridge.station.as_mut().unwrap();
        station.sync_link(None, || LinkKind::Routed, || None);
        rig.bridge.ensure_feeds();
        rig.bridge.feed_advance(clocks_after(2_000));
        // Hosting pauses; the link comes back (what each pass does with it).
        rig.bridge.work.config_problem = Some("paused by the test".into());
        let station = rig.bridge.station.as_mut().unwrap();
        station.sync_link(Some(2), || LinkKind::Routed, || Some(ORIGIN.to_string()));
        rig.bridge.feed_advance(clocks_after(4_000));
        // The Station rolled its feed back to position 1.
        bridge_heads(&mut rig, 1, head);
        assert!(!open(&rig));
        bridge_page(&mut rig, 1, &[(1, &cover)]);
        assert_eq!(cursor(&rig), Some((OWN_FEED.to_string(), 1)), "read from 0");
        assert!(open(&rig));
    });
}

/// Task 33 fix round 1 (another path where the sync runs while host-work's
/// pass doesn't): the feeds loaded for a device list that is no longer the
/// committed one (a re-pin while hosting is paused, before the pass moves
/// the store aside) take no page and open no gate.
#[test]
fn feeds_of_another_list_than_the_committed_one_take_no_page() {
    use crate::runtime::delegated::{DelegatedSender, gate::GateView};
    use crate::session_protocol::membership::r9log::secret;
    use atem_client::control::ControlAction;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let os = ManualOs::at(host_now().wall_ms);
        let s = fed_host(&mut rig, root, &os);
        // Another list is committed (another genesis), the feeds not yet
        // loaded for it.
        let mut other = TestLog::genesis("acct", &secret("another astation"));
        other.add_host("host", 1, &secret("delegated host"));
        {
            let mut view = rig.bridge.start_view();
            let list = view.list.as_mut().unwrap();
            list.membership = std::sync::Arc::new(other.log.clone());
        }
        rig.bridge.feed_advance(clocks_after(0));
        let calls = bridge_heads(&mut rig, 1, other.log.head());
        assert_eq!(calls, [], "nothing asked of a store of another list");
        let cover = own_record(&s.log, "svc-bot", ControlAction::Cover, 1);
        bridge_page(&mut rig, 1, &[(1, &cover)]);
        assert!(
            rig.bridge
                .start_view()
                .standings
                .get(BOT)
                .is_none_or(|s| s.coverage.is_none())
        );
        let native = DelegatedSender::Native {
            device_id: "dev-phone".into(),
        };
        assert!(
            !rig.bridge
                .start_view()
                .gates
                .open_for(&native, Some(ORIGIN))
        );
    });
}

/// Ruling T33c: the durable reset mark comes with the feeds' tables, so a
/// host with the hook off (as main) has no such table, and no row.
#[test]
fn the_reset_mark_is_no_table_with_the_hook_off() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        assert!(!rig.bridge.features.delegated);
        passes(&mut rig, 3);
        let store = rig.bridge.work.store.as_ref().expect("hosting on");
        let tables: u32 = store
            .db
            .query_row(
                "SELECT count(*) FROM sqlite_master WHERE name LIKE 'control%'",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(tables, 0);
    });
}

// A host identity change on the live link in the bridge (host-work-v1
// §11.4, "An identity change"; Astation's item 15 on #120): `atem pair
// verify` rebinding the host to its next trust generation while its Station
// link is up. The old association is never relabelled the new identity's:
// its call is retired and its late page drained, nothing more is asked or
// acknowledged on that socket, and the App reconnects it once, so the next
// link is authenticated, and proves its route, under the new identity; that
// link reads the feed from 0 before the gate opens, and its acks are the
// new identity's. Included beside the effects' tests, whose helpers and
// imports it shares.

/// The page of the own feed answering `call` (its `request_id` and
/// `after`), holding `records` at their positions, at `head`.
fn rv_page(
    call: &atem_client::control::ControlSync,
    head: u64,
    records: &[(u64, &ControlRecord)],
) -> String {
    use atem_client::control::{ControlSyncResult, FeedEntry};
    ControlSyncResult {
        request_id: call.request_id.clone(),
        origin: ORIGIN.into(),
        feed_id: OWN_FEED.into(),
        after: call.after,
        head,
        station_time: host_now().wall_ms,
        records: records.iter().map(|(n, r)| FeedEntry::new(*n, r)).collect(),
    }
    .to_json()
    .unwrap()
    .to_string()
}

/// The live `control_sync` of the host's Station link.
fn rv_live(rig: &LocalRig) -> Option<atem_client::control::ControlSync> {
    rig.bridge
        .station
        .as_ref()
        .and_then(|station| station.feed.live_call())
}

/// The `control_sync`s among `texts`, as the shared reader reads them.
fn rv_syncs(texts: &[String]) -> Vec<atem_client::control::ControlSync> {
    use atem_client::control::ToStation;
    texts
        .iter()
        .filter_map(|text| match ToStation::decode(text.as_bytes()) {
            Ok(ToStation::ControlSync(sync)) => Some(sync),
            _ => None,
        })
        .collect()
}

/// The host's own Station's gate, its feed part: why it is closed.
fn rv_closed(rig: &LocalRig) -> Option<crate::runtime::delegated::sync::Closed> {
    rig.bridge.station.as_ref().unwrap().feed.closed()
}

/// The rig's r9 link up as a routed relay link on socket `socket`, link
/// generation `link_gen`, and the bridge's Station link with it to
/// [`ORIGIN`] (the rig's profile selects no Station: its link is set by
/// hand, as the pass then finds it), a pass.
fn rv_link(rig: &mut LocalRig, link_gen: u64, socket: u64) {
    use crate::runtime::delegated::station::{LinkKind, Station};
    rig.app.astation_routed = true;
    rig.app.astation_link_gen = link_gen;
    rig.app.astation_client.socket_id_for_test(socket);
    rig.bridge
        .station
        .get_or_insert_with(Station::new)
        .sync_link(
            Some(link_gen),
            socket,
            || LinkKind::Routed,
            || Some(ORIGIN.to_string()),
        );
    passes(rig, 1);
    let link = rig
        .bridge
        .station
        .as_ref()
        .unwrap()
        .link()
        .cloned()
        .unwrap();
    assert_eq!((link.link_gen, link.socket), (link_gen, socket));
}

/// The bot covered at 1 (read through the bridge's sync, its result owed),
/// on [`with_bot`]'s rig with the feeds alone deciding: the cover.
fn rv_covered(
    rig: &mut LocalRig,
    root: &Path,
    os: &ManualOs,
    start: u64,
) -> (Senders, ControlRecord) {
    let s = with_bot(rig, root, os, start + 3 * HOUR);
    rig.bridge.work.controls = None;
    rig.bridge.start_view().standings.clear();
    let cover = bot_record(&s.log, ControlAction::Cover, 1);
    feed(rig, &s.log, &[&cover]);
    (s, cover)
}

/// Item 15 (#120): `atem pair verify` on the live link while a
/// `control_sync` is in flight. The host's identity moves to its next trust
/// generation on the same link generation and socket: the call is retired
/// and its page, coming late, drained (nothing applies into the fresh
/// store, which stays never read); the link's `heads` ask nothing, no ack
/// goes on it, and the gate stays closed, `atem status` saying why. The App
/// is asked to reconnect that socket, once; the next link (a new socket)
/// asks the feed from 0 at its `heads`, and only that read opens the gate.
/// Its acks are the new identity's (trust generation 2), the cover applied
/// again under it; the old store's owed results went aside with it.
#[test]
fn a_reverify_on_the_live_link_retires_its_call_and_reconnects_for_the_new_identity() {
    use atem_client::control::AckResult;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (mut s, cover) = rv_covered(&mut rig, root, &os, start);
        rv_link(&mut rig, 7, 41);
        let mut sent = rig.app.astation_client.capture_sent_for_test();
        let hold = bot_record(&s.log, ControlAction::Hold, 2);
        let heads = heads_text(&[(ORIGIN, OWN_FEED, 2)], s.log.log.head());
        station_pass(&mut rig, 0, vec![heads.clone()]);
        let old = rv_live(&rig).expect("a call in flight");
        assert_eq!(old.after, 1);
        let before = sent.texts();
        assert_eq!(rv_syncs(&before).len(), 1);
        assert!(acks_in(&before).iter().all(|ack| ack.host_trust_gen == 1));
        // `atem pair verify` ends on the live link: the next trust
        // generation, pinned, the session host rebound to it.
        reverify(&mut rig, root, &mut s);
        passes(&mut rig, 1);
        assert_eq!(rv_live(&rig), None, "retired");
        assert_eq!(
            rig.app.identity_reconnect.map(|(_, socket)| socket),
            Some(41)
        );
        assert_eq!(
            rv_closed(&rig),
            Some(crate::runtime::delegated::sync::Closed::IdentityMoved)
        );
        // The old call's page, late, and the old link's heads: drained,
        // nothing asked, nothing acknowledged there.
        let drained = rig.bridge.station.as_ref().unwrap().feed.dump()["drained"].clone();
        station_pass(
            &mut rig,
            1_100,
            vec![rv_page(&old, 2, &[(2, &hold)]), heads.clone()],
        );
        let feed = rig.bridge.station.as_ref().unwrap().feed.dump();
        assert_eq!(feed["drained"], drained.as_u64().unwrap() + 1);
        assert_eq!(feed["faults"], 0);
        assert!(sent.texts().is_empty(), "nothing on the old association");
        match &rig.bridge.work.feeds {
            Feeds::Loaded(feeds) => {
                assert_eq!(feeds.identity().map(|i| i.host_trust_gen), Some(2));
                assert!(feeds.never_read(), "the fresh store took nothing");
                assert_eq!(feeds.cursor(ORIGIN, OWN_FEED), None);
            }
            _ => panic!("the new identity's feeds loaded"),
        }
        let line = rig.bridge.feeds_status().unwrap();
        assert!(
            line.starts_with(&format!(
                "revocations not yet checked ({}); ",
                crate::runtime::delegated::sync::IDENTITY_MOVED
            )),
            "{line}"
        );
        // The App reconnects that socket, once.
        assert!(rig.app.identity_reconnect_due(false, false));
        assert!(!rig.app.r9_link_up(), "dropped");
        assert_eq!(rig.app.identity_reconnect, None);
        assert!(!rig.app.identity_reconnect_due(false, false), "once");
        passes(&mut rig, 1);
        // The next link: a new socket, authenticated under the new identity.
        rv_link(&mut rig, 8, 42);
        assert_eq!(rig.app.identity_reconnect, None);
        let mut sent = rig.app.astation_client.capture_sent_for_test();
        assert_ne!(rv_closed(&rig), None);
        station_pass(&mut rig, 2_200, vec![heads]);
        let asked = rv_syncs(&sent.texts());
        assert_eq!(asked.len(), 1, "{asked:?}");
        assert_eq!(asked[0].after, 0, "read from 0");
        assert_ne!(asked[0].request_id, old.request_id);
        assert_ne!(rv_closed(&rig), None, "closed until the read");
        station_pass(
            &mut rig,
            2_300,
            vec![rv_page(&asked[0], 2, &[(1, &cover), (2, &hold)])],
        );
        assert_eq!(rv_closed(&rig), None, "open after the full read");
        let acks = acks_in(&sent.texts());
        assert!(!acks.is_empty());
        assert!(acks.iter().all(|ack| ack.host_trust_gen == 2), "{acks:?}");
        let acked: Vec<&str> = acks
            .iter()
            .flat_map(|ack| &ack.results)
            .filter_map(|r| match r {
                AckResult::Record { record_id, .. } => Some(record_id.as_str()),
                AckResult::Entry { .. } => None,
            })
            .collect();
        assert!(acked.contains(&cover.record_id()), "{acked:?}");
        assert!(acked.contains(&hold.record_id()), "{acked:?}");
    });
}

/// Item 15 (#120), the acknowledgments: a result owed under the old
/// identity (the cover's, read with no send) is never sent after the
/// identity moved, neither on the old association nor on the new link;
/// the new link sends only what the new identity's store applied itself.
#[test]
fn an_ack_owed_under_the_old_identity_never_goes_under_the_new_one() {
    use atem_client::control::AckResult;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (mut s, cover) = rv_covered(&mut rig, root, &os, start);
        rv_link(&mut rig, 7, 41);
        let owed = |rig: &LocalRig| -> i64 {
            rig.bridge
                .work
                .store
                .as_ref()
                .unwrap()
                .db
                .query_row(
                    "SELECT count(*) FROM control_acks WHERE sent_gen IS NULL",
                    [],
                    |r| r.get(0),
                )
                .unwrap()
        };
        assert_eq!(owed(&rig), 1, "the cover's result, owed");
        let mut sent = rig.app.astation_client.capture_sent_for_test();
        reverify(&mut rig, root, &mut s);
        passes(&mut rig, 1);
        let heads = heads_text(&[(ORIGIN, OWN_FEED, 1)], s.log.log.head());
        station_pass(&mut rig, 0, vec![heads.clone()]);
        assert!(sent.texts().is_empty(), "nothing on the old association");
        assert_eq!(owed(&rig), 0, "the old store's results went aside");
        rv_link(&mut rig, 8, 42);
        let mut sent = rig.app.astation_client.capture_sent_for_test();
        station_pass(&mut rig, 1_000, vec![heads]);
        let asked = rv_syncs(&sent.texts());
        assert_eq!(asked.len(), 1);
        assert_eq!(asked[0].after, 0);
        station_pass(&mut rig, 1_100, vec![rv_page(&asked[0], 1, &[(1, &cover)])]);
        let acks = acks_in(&sent.texts());
        assert_eq!(acks.len(), 1, "{acks:?}");
        assert_eq!(acks[0].host_trust_gen, 2);
        let AckResult::Record { record_id, .. } = &acks[0].results[0] else {
            panic!("a record's result");
        };
        assert_eq!(record_id, cover.record_id(), "applied again under gen 2");
    });
}

/// Hook off = main: with `host.delegated` off there is no Station link, and
/// a re-verify on the live link asks the App for no reconnect; the link
/// stays, as on main.
#[test]
fn with_the_hook_off_a_reverify_keeps_the_link() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let mut s = with_bot(&mut rig, root, &os, start + 3 * HOUR);
        rig.bridge.features = HostFeatures::default();
        r9_link_up(&mut rig);
        assert!(rig.bridge.station.is_none());
        reverify(&mut rig, root, &mut s);
        passes(&mut rig, 2);
        assert_eq!(rig.app.identity_reconnect, None);
        assert!(!rig.app.identity_reconnect_due(false, false));
        assert!(rig.app.r9_link_up(), "the link stays");
    });
}

/// The broker's loop around the App's link, for the hook-on tests below:
/// the sockets the App reconnected to, and the links the identity
/// reconnect dropped.
struct RvLoop {
    next: (u64, u64),
    reconnects: Vec<u64>,
    drops: usize,
}

/// One broker tick in the rig: the bridge's pass, the release of a
/// verification's hold after it (`Server::host_pass`), the identity
/// reconnect (`op_running` while the operation runs), and at the next
/// tick's start the App's reconnect, when one is due and not held: the
/// next link comes up on the next socket (as `rv_link`).
fn rv_tick(rig: &mut LocalRig, l: &mut RvLoop, op_running: bool) {
    passes(rig, 1);
    rig.app.verify_hold_pass();
    if rig.app.identity_reconnect_due(op_running, false) {
        l.drops += 1;
    }
    let due = !rig.app.r9_link_up() && rig.app.astation_reconnect_at.is_some();
    if due && !rig.app.reconnect_held() {
        rig.app.astation_reconnect_at = None;
        let (link_gen, socket) = l.next;
        rv_link(rig, link_gen, socket);
        l.reconnects.push(socket);
        l.next = (link_gen + 1, socket + 1);
    }
}

/// Astation PR #81 with the hook on: the Station closes the re-verified
/// host's socket with 1013, and the verification's hold
/// (`App::verify_hold`) keeps the reconnect until the operation ended and
/// the pass after it read the new list. Seen before the re-pin, the close
/// leaves the identity change no link, so no identity reconnect is asked
/// (without the hold the next link would come up under the old identity and
/// be dropped again); seen after it, the identity reconnect asked for the
/// old socket ends unused. Either way: one reconnect, on a link that stays.
#[test]
fn a_station_close_after_a_reverify_reconnects_once_with_the_hook_on() {
    for close_first in [true, false] {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let start = host_now().wall_ms;
            let os = ManualOs::at(start);
            let (mut s, _) = rv_covered(&mut rig, root, &os, start);
            rv_link(&mut rig, 7, 41);
            let mut l = RvLoop {
                next: (8, 42),
                reconnects: Vec::new(),
                drops: 0,
            };
            // The certificate went to the operation over the relay.
            rig.app.verify_hold = Some(crate::app::op_route::VerifyHold {
                since: Instant::now(),
                ended: false,
            });
            // The App's pump calls the closed link down.
            let close = |rig: &mut LocalRig| {
                rig.app.astation_routed = false;
                rig.app.astation_client = crate::websocket_client::AstationClient::new();
                rig.app.astation_reconnect_at = Some(Instant::now());
            };
            if close_first {
                close(&mut rig);
                rv_tick(&mut rig, &mut l, true);
            } else {
                // The 100 ms pass read the pin while the operation ran.
                reverify(&mut rig, root, &mut s);
                rv_tick(&mut rig, &mut l, true);
                assert_eq!(
                    rig.app.identity_reconnect.map(|(_, socket)| socket),
                    Some(41)
                );
                close(&mut rig);
                rv_tick(&mut rig, &mut l, true);
            }
            // The operation's tail: nothing reconnects meanwhile.
            assert!(l.reconnects.is_empty(), "held: {:?}", l.reconnects);
            // The operation ends ok; the next pass reads the list it
            // pinned (`check_list`), then the hold is released.
            assert!(rig.app.verification_ended(true));
            if close_first {
                reverify(&mut rig, root, &mut s);
            }
            for _ in 0..4 {
                rv_tick(&mut rig, &mut l, false);
            }
            assert_eq!(
                l.reconnects,
                [42],
                "close_first {close_first}: one reconnect"
            );
            assert_eq!(l.drops, 0, "close_first {close_first}: no identity drop");
            assert!(rig.app.r9_link_up(), "the next link stays");
            assert_eq!(rig.app.astation_client.socket_id(), 42);
            assert_eq!(rig.app.identity_reconnect, None);
            assert!(rig.app.verify_hold.is_none(), "released");
        });
    }
}

/// Design I.5.8 on a local link (`host.delegated` on): the host's identity
/// moving on the live link (a re-verify) retires the socket's local route
/// proof as the bridge's identity rules say, so nothing more is answered on
/// that socket (whatever its authentication), and the App reconnects it
/// once; the next socket's route answers under the new identity.
#[test]
fn a_reverify_on_a_live_local_link_retires_its_route_proof_and_reconnects() {
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (mut s, _) = rv_covered(&mut rig, root, &os, start);
        rv_link(&mut rig, 7, 41);
        let handle = rig.app.host_route.clone();
        rig.app
            .astation_client
            .local_route_for_test(handle.clone(), "room");
        passes(&mut rig, 1);
        assert!(!rig.app.astation_client.local_route_retired());
        assert_eq!(rig.app.identity_reconnect, None);
        reverify(&mut rig, root, &mut s);
        passes(&mut rig, 1);
        assert!(
            rig.app.astation_client.local_route_retired(),
            "nothing more answered on that socket"
        );
        assert_eq!(
            rig.app.identity_reconnect.map(|(_, socket)| socket),
            Some(41)
        );
        assert!(rig.app.identity_reconnect_due(false, false));
        // The next socket: its route answers under the new identity.
        rv_link(&mut rig, 8, 42);
        rig.app.astation_client.local_route_for_test(handle, "room");
        passes(&mut rig, 1);
        assert!(!rig.app.astation_client.local_route_retired());
        assert_eq!(rig.app.identity_reconnect, None);
    });
}

/// A local route that found another route identity on its socket itself
/// (here: bound to one `host_channel_key`, a challenge under another, set
/// on the route's handle alone, so the bridge's own identity rules saw no
/// move) has the App reconnect that socket, as the bridge's rules do: a
/// defence of its own, whatever the bridge saw.
#[test]
fn a_local_route_retired_by_another_identity_reconnects_its_socket() {
    use crate::session_protocol::membership::r9log::{TestLog, secret};
    use crate::session_protocol::r9::route::{self, RouteIdentity, RouteState};
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        rv_covered(&mut rig, root, &os, start);
        rv_link(&mut rig, 7, 41);
        let mut log = TestLog::genesis("acct-rv", &secret("rv astation"));
        log.add_host("host-rv", 1, &secret("rv host 1"));
        let state = |log: &TestLog, seed: &str| RouteState::Ready {
            id: RouteIdentity {
                account_id: "acct-rv".into(),
                genesis_hash: log.log.genesis_hash(),
                host_id: "host-rv".into(),
                head: log.log.head(),
                chain: std::sync::Arc::new(log.log.entries().iter().map(|e| e.hash()).collect()),
            },
            key: std::sync::Arc::new(crate::session_protocol::r9::HostKey::new(&secret(seed))),
        };
        let handle = rig.app.host_route.clone();
        // Bound at its authentication to the first key, then a challenge
        // under a re-verify's new key.
        route::set(&handle, state(&log, "rv host 1"));
        rig.app
            .astation_client
            .local_route_for_test(handle.clone(), "room");
        log.add_host("host-rv", 2, &secret("rv host 2"));
        route::set(&handle, state(&log, "rv host 2"));
        let challenge = atem_client::host_route::HostChallenge::new("room")
            .to_json()
            .to_string();
        assert_eq!(
            rig.app.astation_client.local_route_message(&challenge),
            None
        );
        assert!(
            rig.app.astation_client.local_route_retired(),
            "found itself"
        );
        assert_eq!(rig.app.identity_reconnect, None);
        passes(&mut rig, 1);
        assert_eq!(
            rig.bridge.station.as_ref().unwrap().feed.moved_socket(),
            None,
            "the bridge's rules saw no move"
        );
        assert_eq!(
            rig.app.identity_reconnect.map(|(_, socket)| socket),
            Some(41)
        );
    });
}

/// The rig's link up as Astation's authenticated link, not routed (`local`:
/// Astation's `:8080` link, else the relay identity link), on socket
/// `socket`, link generation `link_gen`, and the bridge's Station link with
/// it to [`ORIGIN`], set by hand in the order the pass's
/// `sync_station_link` takes it (the host's identity first; the rig's
/// profile selects no Station), then a pass.
fn rv_astation_link(rig: &mut LocalRig, link_gen: u64, socket: u64, local: bool) {
    use crate::runtime::delegated::station::{LinkKind, Station};
    rig.app.astation_connected = true;
    rig.app.astation_routed = false;
    rig.app.astation_reauth = None;
    rig.app.astation_link_gen = link_gen;
    rig.app.astation_client.socket_id_for_test(socket);
    let kind = if local {
        rig.app
            .astation_client
            .set_via_for_test(crate::websocket_client::LinkVia::Local);
        LinkKind::Local
    } else {
        LinkKind::Relay
    };
    rig.bridge.station_identity();
    rig.bridge
        .station
        .get_or_insert_with(Station::new)
        .sync_link(Some(link_gen), socket, || kind, || Some(ORIGIN.to_string()));
    passes(rig, 1);
    let link = rig
        .bridge
        .station
        .as_ref()
        .unwrap()
        .link()
        .cloned()
        .unwrap();
    assert_eq!(
        (link.link_gen, link.socket, link.kind),
        (link_gen, socket, kind)
    );
}

/// Astation authenticates the rig's link again (`auth_required` on the
/// live socket): until it answers the link is offline, and the Station link
/// is down (`r9_app_link` names no generation for it); a pass.
fn rv_reauth_starts(rig: &mut LocalRig) {
    rig.app.astation_connected = false;
    rig.app.astation_reauth = Some(Instant::now() + std::time::Duration::from_secs(15));
    passes(rig, 1);
    assert!(
        rig.bridge.station.as_ref().unwrap().link().is_none(),
        "down"
    );
}

/// The host's trust generation moves on to `host_trust_gen` alone (the
/// same account, device, device list and key): what the pass's `sync_link`
/// takes from a new link generation whose pairing `atem pair verify` rebound
/// to its next trust generation (`OpCall::Rebind`).
fn rv_trust_gen(rig: &mut LocalRig, host_trust_gen: u64) {
    let identity = crate::runtime::host_bridge::Identity {
        account_id: "acct".into(),
        atem_device_id: "host".into(),
        host_trust_gen,
    };
    let mut cx = Cx {
        client: &rig.app.astation_client,
        sessions: &mut rig.sessions,
    };
    assert!(rig.bridge.adopt_identity(&identity, &mut cx));
}

/// Item 15 (#120) across a re-authentication, on both carriers (the relay
/// identity link and Astation's local `:8080` link): Astation authenticates
/// the live link again and the host's trust generation alone moves while it
/// does (the same account, device, device list and key), either in the
/// window or as it ends (the pass's `sync_link` takes it from the new link
/// generation, just before the Station link comes back on the same socket).
/// The old association is never relabelled the new identity's: the call
/// retired at the drop is drained when its page comes, nothing is asked or
/// acknowledged on that socket, a local link's route proof answers nothing
/// more there, and once Astation answered (never before) the App
/// reconnects that socket, once. The next socket reads the feed from 0, and
/// its acks are trust generation 2's.
#[test]
fn a_trust_generation_moving_while_astation_reauthenticates_reconnects_the_socket() {
    use crate::runtime::delegated::sync::Closed;
    use atem_client::control::AckResult;
    for local in [false, true] {
        for in_window in [true, false] {
            local_test(async |root| {
                let case = format!("local {local}, in the window {in_window}");
                let mut rig = LocalRig::new(root).await;
                let start = host_now().wall_ms;
                let os = ManualOs::at(start);
                let (s, cover) = rv_covered(&mut rig, root, &os, start);
                rv_astation_link(&mut rig, 7, 41, local);
                let handle = rig.app.host_route.clone();
                if local {
                    rig.app
                        .astation_client
                        .local_route_for_test(handle.clone(), "room");
                }
                let mut sent = rig.app.astation_client.capture_sent_for_test();
                let hold = bot_record(&s.log, ControlAction::Hold, 2);
                let heads = heads_text(&[(ORIGIN, OWN_FEED, 2)], s.log.log.head());
                station_pass(&mut rig, 0, vec![heads.clone()]);
                let old = rv_live(&rig).expect("a call in flight");
                assert_eq!(old.after, 1, "{case}");
                assert!(
                    acks_in(&sent.texts())
                        .iter()
                        .all(|ack| ack.host_trust_gen == 1)
                );
                // Astation authenticates the link again.
                rv_reauth_starts(&mut rig);
                assert_eq!(rv_live(&rig), None, "{case}: retired at the drop");
                if in_window {
                    rv_trust_gen(&mut rig, 2);
                    passes(&mut rig, 1);
                    assert_eq!(
                        rig.app.identity_reconnect.map(|(_, socket)| socket),
                        Some(41),
                        "{case}: the re-authenticating socket"
                    );
                    if local {
                        assert!(rig.app.astation_client.local_route_retired(), "{case}");
                    }
                    assert!(
                        !rig.app.identity_reconnect_due(false, false),
                        "{case}: not while Astation authenticates it"
                    );
                    assert!(rig.app.identity_reconnect.is_some(), "{case}: kept");
                } else {
                    rv_trust_gen(&mut rig, 2);
                }
                // Astation answered: the same socket, a new link generation.
                rv_astation_link(&mut rig, 8, 41, local);
                assert_eq!(rv_closed(&rig), Some(Closed::IdentityMoved), "{case}");
                assert_eq!(
                    rig.app.identity_reconnect.map(|(_, socket)| socket),
                    Some(41),
                    "{case}"
                );
                if local {
                    assert!(rig.app.astation_client.local_route_retired(), "{case}");
                }
                // The old call's late page and the socket's heads: drained,
                // nothing asked, nothing acknowledged there.
                let drained = rig.bridge.station.as_ref().unwrap().feed.dump()["drained"]
                    .as_u64()
                    .unwrap();
                station_pass(
                    &mut rig,
                    1_100,
                    vec![rv_page(&old, 2, &[(2, &hold)]), heads.clone()],
                );
                let feed = rig.bridge.station.as_ref().unwrap().feed.dump();
                assert_eq!(feed["drained"], drained + 1, "{case}");
                assert_eq!(feed["faults"], 0, "{case}");
                assert!(
                    sent.texts().is_empty(),
                    "{case}: nothing on the old association"
                );
                // The App reconnects that socket, once.
                assert!(rig.app.identity_reconnect_due(false, false), "{case}");
                assert!(!rig.app.r9_link_up(), "{case}: dropped");
                assert!(
                    !rig.app.identity_reconnect_due(false, false),
                    "{case}: once"
                );
                passes(&mut rig, 1);
                assert_eq!(rig.app.identity_reconnect, None, "{case}");
                // The next socket: the new identity's association.
                rv_astation_link(&mut rig, 9, 42, local);
                assert_eq!(rig.app.identity_reconnect, None, "{case}");
                if local {
                    rig.app.astation_client.local_route_for_test(handle, "room");
                    passes(&mut rig, 1);
                    assert!(!rig.app.astation_client.local_route_retired(), "{case}");
                }
                let mut sent = rig.app.astation_client.capture_sent_for_test();
                station_pass(&mut rig, 2_200, vec![heads]);
                let asked = rv_syncs(&sent.texts());
                assert_eq!(asked.len(), 1, "{case}: {asked:?}");
                assert_eq!(asked[0].after, 0, "{case}: read from 0");
                assert_ne!(asked[0].request_id, old.request_id, "{case}");
                station_pass(
                    &mut rig,
                    2_300,
                    vec![rv_page(&asked[0], 2, &[(1, &cover), (2, &hold)])],
                );
                assert_eq!(rv_closed(&rig), None, "{case}: open after the full read");
                let acks = acks_in(&sent.texts());
                assert!(!acks.is_empty(), "{case}");
                assert!(
                    acks.iter().all(|ack| ack.host_trust_gen == 2),
                    "{case}: {acks:?}"
                );
                let acked: Vec<&str> = acks
                    .iter()
                    .flat_map(|ack| &ack.results)
                    .filter_map(|r| match r {
                        AckResult::Record { record_id, .. } => Some(record_id.as_str()),
                        AckResult::Entry { .. } => None,
                    })
                    .collect();
                assert!(acked.contains(&cover.record_id()), "{case}: {acked:?}");
            });
        }
    }
}

/// The same re-authentication with no identity change keeps the socket's
/// association: no reconnect is asked, a local link's route stays, and the
/// new link generation asks the feed again from the committed cursor.
#[test]
fn a_reauthentication_with_no_identity_change_keeps_the_link() {
    for local in [false, true] {
        local_test(async |root| {
            let mut rig = LocalRig::new(root).await;
            let start = host_now().wall_ms;
            let os = ManualOs::at(start);
            let (s, _cover) = rv_covered(&mut rig, root, &os, start);
            rv_astation_link(&mut rig, 7, 41, local);
            if local {
                let handle = rig.app.host_route.clone();
                rig.app.astation_client.local_route_for_test(handle, "room");
            }
            let _sent = rig.app.astation_client.capture_sent_for_test();
            let heads = heads_text(&[(ORIGIN, OWN_FEED, 2)], s.log.log.head());
            station_pass(&mut rig, 0, vec![heads.clone()]);
            assert_eq!(rv_live(&rig).map(|call| call.after), Some(1));
            rv_reauth_starts(&mut rig);
            passes(&mut rig, 1);
            rv_astation_link(&mut rig, 8, 41, local);
            assert_eq!(rig.app.identity_reconnect, None, "local {local}");
            assert!(
                !rig.app.astation_client.local_route_retired(),
                "local {local}"
            );
            let mut sent = rig.app.astation_client.capture_sent_for_test();
            station_pass(&mut rig, 1_100, vec![heads]);
            let asked = rv_syncs(&sent.texts());
            assert_eq!(asked.len(), 1, "local {local}: {asked:?}");
            assert_eq!(asked[0].after, 1, "local {local}: from the cursor");
            assert!(!rig.app.identity_reconnect_due(false, false));
            assert!(rig.app.r9_link_up(), "local {local}: the link stays");
            assert_eq!(
                rig.bridge.station.as_ref().unwrap().feed.dump()["identity_moves"],
                0
            );
        });
    }
}

/// The device list re-pinned with this host's `add_host` in trust
/// generation `host_trust_gen` under the key `seed` names, read by the
/// bridge as a pin is (`reopen_list_if_changed`), the session host taking
/// the pin's identity (as `reverify`, whose key is the rig's own).
fn rv_pin(rig: &mut LocalRig, root: &Path, s: &mut Senders, host_trust_gen: u64, seed: &str) {
    use crate::session_protocol::membership::r9log::secret;
    use crate::session_protocol::membership::{HostPin, MembershipHost};
    s.log.add_host("host", host_trust_gen, &secret(seed));
    let pairing = crate::profile::Sources::in_dir(&root.join("profile"))
        .paths
        .pairing;
    MembershipHost::pin(
        &pairing,
        &rig.bridge.dir,
        &HostPin {
            host_id: "host".into(),
            host_trust_gen,
        },
        &s.log.log,
        &secret(seed),
    )
    .unwrap();
    let identity = crate::runtime::host_bridge::Identity {
        account_id: "acct".into(),
        atem_device_id: "host".into(),
        host_trust_gen,
    };
    let mut cx = Cx {
        client: &rig.app.astation_client,
        sessions: &mut rig.sessions,
    };
    rig.bridge.pairing = Some(pairing);
    rig.bridge.reopen_list_if_changed(&mut cx);
    rig.bridge.pairing = None;
    assert!(rig.bridge.adopt_identity(&identity, &mut cx));
}

/// The host's `host_channel_key` is part of the identity a Station link's
/// socket was authenticated under (on the relay its route proof is that
/// key's): a new key alone ends the association as a new trust generation,
/// account or genesis does. Here the host already runs in trust generation
/// 2 on a socket authenticated under it (the move to 2 reconnected the
/// first), and the device list is then re-pinned with this host's new key
/// in that same generation: that socket's association ends, nothing more
/// is asked there, and the App reconnects it, once.
#[test]
fn a_new_host_channel_key_alone_ends_the_association() {
    use crate::runtime::delegated::sync::Closed;
    local_test(async |root| {
        let mut rig = LocalRig::new(root).await;
        let start = host_now().wall_ms;
        let os = ManualOs::at(start);
        let (mut s, _) = rv_covered(&mut rig, root, &os, start);
        rv_astation_link(&mut rig, 7, 41, false);
        rv_trust_gen(&mut rig, 2);
        passes(&mut rig, 1);
        assert!(
            rig.app.identity_reconnect_due(false, false),
            "the move to 2"
        );
        passes(&mut rig, 1);
        rv_astation_link(&mut rig, 8, 42, false);
        assert_eq!(rig.app.identity_reconnect, None);
        assert_ne!(rv_closed(&rig), Some(Closed::IdentityMoved));
        // The same trust generation, a new key.
        rv_pin(&mut rig, root, &mut s, 2, "delegated host, a new key");
        passes(&mut rig, 1);
        assert_eq!(rv_closed(&rig), Some(Closed::IdentityMoved));
        assert_eq!(
            rig.app.identity_reconnect.map(|(_, socket)| socket),
            Some(42)
        );
        let mut sent = rig.app.astation_client.capture_sent_for_test();
        let heads = heads_text(&[(ORIGIN, OWN_FEED, 1)], s.log.log.head());
        station_pass(&mut rig, 1_000, vec![heads]);
        assert!(sent.texts().is_empty(), "nothing on the old association");
        assert!(rig.app.identity_reconnect_due(false, false));
        assert!(!rig.app.identity_reconnect_due(false, false), "once");
    });
}

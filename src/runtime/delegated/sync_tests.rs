// The feed sync and the feed part of the revocation gate (design I.5.2,
// I.5.8, I.6.5; host-work-v1 §11.4; step 4's Decisions 12, 14, 20): a
// host-work store in a temp directory, a test account's device list with a
// bot (a service on this host), records the bot's Station signs with the
// bot's key, the feed store and the delegated clock on a manual clock, and
// the host's link to its own Station.
use super::*;
use crate::runtime::delegated::feeds::signed_record;
use crate::runtime::delegated::station::LinkKind;
use crate::runtime::delegated::{ControlView, FeedRef};
use crate::runtime::host_clock::os::{OsReading, Synced as OsSynced};
use crate::session_protocol::membership::r9log::{TestLog, secret};
use atem_client::control::{ControlAction, ControlRecord, FeedEntry, FeedHead};
use atem_client::membership::HostNow;
use atem_client::session::host_work::HostTarget;
use std::sync::{Arc, Mutex};

const ORIGIN: &str = "https://station-dev.agora.build";
const OTHER: &str = "https://station-other.agora.build";
const FEED: &str = "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b";
const FEED_2: &str = "7a2d3c4b-5e6f-4a71-9b8c-0d1e2f3a4b5c";
const BOT: &str = "service:svc-bot";
const SEC: u64 = 1_000;
const MIN: u64 = 60 * SEC;
const HOUR: u64 = 60 * MIN;

struct Rig {
    _dir: tempfile::TempDir,
    store: Store,
    log: TestLog,
    feeds: FeedStore,
    clock: HostClock,
    os: Arc<Mutex<OsReading>>,
    sync: FeedSync,
    issued: u64,
    minted: u64,
}

fn host() -> HostTarget {
    HostTarget {
        account_id: "acct-s".into(),
        atem_device_id: "host".into(),
        host_trust_gen: 1,
    }
}

fn link(link_gen: u64, origin: &str) -> StationLink {
    StationLink {
        link_gen,
        kind: LinkKind::Routed,
        origin: Some(origin.into()),
    }
}

/// The Mac, this host and the bot (a service on this host).
fn list() -> TestLog {
    let mut log = TestLog::genesis("acct-s", &secret("sync astation"));
    log.add_host("host", 1, &secret("sync host"));
    log.add_service(
        "svc-bot",
        &["host"],
        None,
        &["notify", "prompt", "view"],
        crate::session_protocol::membership::r9log::host_now().wall_ms + 24 * HOUR,
    );
    log
}

fn serving(log: &TestLog) -> ListState {
    ListState {
        membership: Arc::new(log.log.clone()),
        frozen: false,
        held: false,
        faulted: false,
        unpaired: false,
        deferred: None,
    }
}

fn native() -> DelegatedSender {
    DelegatedSender::Native {
        device_id: "dev-phone".into(),
    }
}

fn service(origin: &str) -> DelegatedSender {
    DelegatedSender::Service {
        device_id: "svc-bot".into(),
        feed: FeedRef {
            origin: origin.into(),
            feed_id: FEED.into(),
        },
    }
}

/// A store, the list, the feed store and the clock on a manual clock, and
/// the sync on link 1 to [`ORIGIN`].
fn rig() -> Rig {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store.bind(&host()).unwrap();
    let log = list();
    let os = Arc::new(Mutex::new(OsReading {
        wall_ms: 1_800_000_000_000,
        boot_ns: 10 * HOUR * 1_000_000,
        boot_id: "boot-sync".into(),
        machine: [7; 16],
        timens_boot_ns: 0,
        synced: OsSynced::Yes,
    }));
    let reading = os.clone();
    let clock = HostClock::with_readings(&store, move || Some(reading.lock().unwrap().clone()));
    let reading = os.clone();
    let mut feeds = FeedStore::load(&store, &log.log)
        .unwrap()
        .with_clock(move || {
            let r = reading.lock().unwrap();
            HostNow {
                wall_ms: r.wall_ms,
                mono_ms: r.boot_ns / 1_000_000,
                boot_id: r.boot_id.clone(),
            }
        });
    feeds.set_own_origin(Some(ORIGIN.into()));
    let mut sync = FeedSync::new();
    sync.on_link(Some(&link(1, ORIGIN)));
    let mut rig = Rig {
        _dir: dir,
        store,
        log,
        feeds,
        clock,
        os,
        sync,
        issued: 1_700_000_000_000,
        minted: 0,
    };
    rig.pass(0);
    rig
}

impl Rig {
    fn mono(&self) -> u64 {
        self.os.lock().unwrap().boot_ns / 1_000_000
    }

    fn wall(&self) -> u64 {
        self.os.lock().unwrap().wall_ms
    }

    /// Time passes (wall and monotonic): the pass's tick, its calls.
    fn pass(&mut self, ms: u64) -> Vec<ControlSync> {
        {
            let mut r = self.os.lock().unwrap();
            r.wall_ms += ms;
            r.boot_ns += ms * 1_000_000;
        }
        let now = self.mono();
        self.sync.tick(now, Some(&self.feeds))
    }

    /// `heads` announcing `feeds` (origin, feed, head) at the Station's
    /// time `station_time` (none: the wall clock): its calls.
    fn heads_with(
        &mut self,
        feeds: &[(&str, &str, u64)],
        station_time: Option<u64>,
    ) -> Vec<ControlSync> {
        let st = station_time.unwrap_or_else(|| self.wall());
        let heads = Heads {
            feeds: feeds
                .iter()
                .map(|(origin, feed_id, head)| FeedHead {
                    origin: (*origin).into(),
                    feed_id: (*feed_id).into(),
                    head: *head,
                    station_time: st,
                })
                .collect(),
            membership: self.log.log.head(),
        };
        self.sync.on_heads(
            &heads,
            Some((&mut self.clock, &self.store)),
            Some(&self.feeds),
        )
    }

    /// `heads` announcing the own Station's `feed_id` at `head`.
    fn heads(&mut self, feed_id: &str, head: u64) -> Vec<ControlSync> {
        self.heads_with(&[(ORIGIN, feed_id, head)], None)
    }

    /// A record of the bot in `feed_id`, signed by its key.
    fn record(&mut self, feed_id: &str, action: ControlAction) -> ControlRecord {
        self.issued += SEC;
        self.minted += 1;
        signed_record(
            &self.log,
            "svc-bot",
            "svc-bot",
            action,
            format!("0b9a8c7d-6e5f-4a3b-9c2d-{:012x}", self.minted),
            (ORIGIN, feed_id),
            self.issued,
        )
    }

    /// The page as the reader gives it: `records` (position, the record's
    /// value) of `feed_id`, its head `head`.
    fn page_of(
        &self,
        feed_id: &str,
        head: u64,
        records: Vec<(u64, Value)>,
    ) -> Result<ControlSyncResult, RelayError> {
        let message = json!({
            "type": "relay", "op": "control_sync_result", "origin": ORIGIN,
            "feed_id": feed_id, "head": head, "station_time": self.wall(),
            "records": records.into_iter()
                .map(|(feed_seq, record)| json!({"feed_seq": feed_seq, "record": record}))
                .collect::<Vec<_>>(),
        });
        ControlSyncResult::decode(message.to_string().as_bytes())
    }

    /// `page` handed to the sync, against the list as it serves.
    fn on_page(&mut self, page: Result<ControlSyncResult, RelayError>) -> Synced {
        let list = serving(&self.log);
        self.on_page_with(page, &list)
    }

    fn on_page_with(
        &mut self,
        page: Result<ControlSyncResult, RelayError>,
        list: &ListState,
    ) -> Synced {
        self.sync
            .on_page(
                page,
                Some((&mut self.clock, &self.store)),
                Some(PageCx {
                    store: &self.store,
                    feeds: &mut self.feeds,
                    list,
                    applied_seq: 0,
                }),
            )
            .unwrap()
    }

    /// A page of `feed_id` holding `records` at their positions.
    fn page(&mut self, feed_id: &str, head: u64, records: &[(u64, &ControlRecord)]) -> Synced {
        let records = records
            .iter()
            .map(|(seq, r)| (*seq, FeedEntry::new(*seq, r).raw().clone()))
            .collect();
        let page = self.page_of(feed_id, head, records);
        self.on_page(page)
    }

    /// The gate of `sender`, with the device-list part the host's own
    /// Station's (fetched up to its head).
    fn open(&self, sender: &DelegatedSender) -> bool {
        self.sync.open_for(sender, Some(ORIGIN))
    }

    /// The bot covered at 1 and held at 2 of [`FEED`] (head 2), read: the
    /// gate open.
    fn opened(&mut self) -> (ControlRecord, ControlRecord) {
        let cover = self.record(FEED, ControlAction::Cover);
        let hold = self.record(FEED, ControlAction::Hold);
        assert_eq!(self.heads(FEED, 2), [sync_call(FEED, 0)]);
        self.page(FEED, 2, &[(1, &cover), (2, &hold)]);
        assert!(self.open(&native()), "{:?}", self.sync.closed());
        (cover, hold)
    }

    fn cursor(&self) -> Option<(String, u64)> {
        self.feeds.current_feed(ORIGIN)
    }

    fn d_ms(&self) -> u64 {
        self.clock.reading().unwrap().d_ms
    }
}

fn sync_call(feed_id: &str, after: u64) -> ControlSync {
    ControlSync {
        origin: ORIGIN.into(),
        feed_id: Some(feed_id.into()),
        after,
    }
}

/// I.5.8: an origin's gate opens only once the host applied its feed up to
/// the head the last `heads` announced AND fetched the device list up to
/// its head (or a deferred entry): neither alone. A page short of the head
/// asks the rest at once, the gate still closed.
#[test]
fn the_gate_opens_only_after_feed_and_device_list_reach_the_announced_heads() {
    let mut rig = rig();
    assert_eq!(rig.sync.closed(), Some(Closed::NoHeads));
    let cover = rig.record(FEED, ControlAction::Cover);
    let hold = rig.record(FEED, ControlAction::Hold);
    let release = rig.record(FEED, ControlAction::Release);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 0)]);
    assert!(!rig.open(&native()), "nothing read yet");
    // Two of the three: the rest asked at once.
    let synced = rig.page(FEED, 3, &[(1, &cover), (2, &hold)]);
    assert_eq!(synced.applied.len(), 2);
    assert_eq!(synced.next, Some(sync_call(FEED, 2)));
    assert_eq!(
        rig.sync.closed(),
        Some(Closed::Behind {
            cursor: Some(2),
            head: 3
        })
    );
    assert!(!rig.open(&native()));
    assert!(!rig.open(&service(ORIGIN)));
    // The feed read up to the announced head.
    rig.page(FEED, 3, &[(3, &release)]);
    assert_eq!(rig.sync.closed(), None);
    assert!(rig.open(&native()));
    assert!(rig.open(&service(ORIGIN)));
    // The device-list part is the fetch's: without it, or the fetch of
    // another Station, closed.
    assert!(!rig.sync.open_for(&native(), None));
    assert!(!rig.sync.open_for(&service(ORIGIN), Some(OTHER)));
    // Another origin's gate never opens here.
    assert!(!rig.sync.open_for(&service(OTHER), Some(OTHER)));
    // A newer head announced: closed until it is read.
    assert_eq!(rig.heads(FEED, 4), Vec::new(), "paced: within a second");
    assert!(!rig.open(&native()));
    assert_eq!(rig.pass(SEC), [sync_call(FEED, 3)]);
    rig.page(FEED, 4, &[]);
    assert!(rig.open(&native()), "an empty page reads up to its head");
    assert_eq!(rig.cursor(), Some((FEED.to_string(), 4)));
    // The start view gets the feed part as it changes, once.
    assert_eq!(
        rig.sync.take_gates(),
        Some((
            Some(ORIGIN.to_string()),
            BTreeSet::from([ORIGIN.to_string()])
        ))
    );
    assert_eq!(rig.sync.take_gates(), None);
}

/// I.5.8, §11.4: the gate closes on any disconnect, after 60 seconds with no
/// `heads` (60 s without them, though the feed and the list hold the
/// announced heads), and on a reset; it opens again once the feed is read
/// up to a fresh announcement.
#[test]
fn the_gate_closes_on_disconnect_reset_and_60s_without_heads() {
    let mut rig = rig();
    rig.opened();
    // 60 s without heads.
    rig.pass(NO_HEADS_MS - 1);
    assert!(rig.open(&native()));
    rig.pass(1);
    assert_eq!(rig.sync.closed(), Some(Closed::HeadsLate));
    assert!(!rig.open(&native()));
    assert!(!rig.open(&service(ORIGIN)));
    // A heads at the head the host holds: open again, nothing to ask.
    assert_eq!(rig.heads(FEED, 2), Vec::new());
    assert!(rig.open(&native()));
    // A disconnect: closed; the next generation needs its own heads.
    rig.sync.on_link(None);
    assert_eq!(rig.sync.closed(), Some(Closed::NoLink));
    rig.sync.on_link(Some(&link(2, ORIGIN)));
    assert_eq!(rig.sync.closed(), Some(Closed::NoHeads));
    assert!(!rig.open(&native()));
    assert_eq!(rig.heads(FEED, 2), Vec::new());
    assert!(rig.open(&native()));
    // A reset: a new feed id, read from 0.
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED_2, 1), [sync_call(FEED_2, 0)]);
    assert_eq!(rig.sync.closed(), Some(Closed::Reset));
    assert!(!rig.open(&native()));
    let cover = rig.record(FEED_2, ControlAction::Cover);
    rig.page(FEED_2, 1, &[(1, &cover)]);
    assert!(rig.open(&native()));
}

/// I.5.2, §11.4 "Resets": a new `feed_id`, or a head below the cursor, is a
/// reset: read from position 0, the old cursor replaced in the
/// transaction of the reset's first page (and only then). The snapshot
/// re-issues the stops, and the host's state loses none: a revoke stays
/// final, a hold stays held, coverage follows the new feed.
#[test]
fn a_reset_resyncs_from_zero_and_its_snapshot_loses_no_stop() {
    let mut rig = rig();
    let cover = rig.record(FEED, ControlAction::Cover);
    let hold = rig.record(FEED, ControlAction::Hold);
    assert_eq!(rig.heads(FEED, 2), [sync_call(FEED, 0)]);
    rig.page(FEED, 2, &[(1, &cover), (2, &hold)]);
    assert!(rig.feeds.standing(BOT).held);
    // A new feed: nothing of the old cursor goes before its first page.
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED_2, 2), [sync_call(FEED_2, 0)]);
    assert_eq!(rig.sync.closed(), Some(Closed::Reset));
    assert_eq!(rig.cursor(), Some((FEED.to_string(), 2)), "not yet");
    // Its snapshot: the cover and hold signed anew.
    let cover_2 = rig.record(FEED_2, ControlAction::Cover);
    let hold_2 = rig.record(FEED_2, ControlAction::Hold);
    let synced = rig.page(FEED_2, 2, &[(1, &cover_2), (2, &hold_2)]);
    assert_eq!(synced.applied.len(), 2);
    assert_eq!(rig.cursor(), Some((FEED_2.to_string(), 2)));
    let standing = rig.feeds.standing(BOT);
    assert!(standing.held, "no stop lost");
    assert_eq!(standing.coverage.unwrap().feed_id, FEED_2);
    assert!(rig.open(&native()));
    // A revoke, then the feed rolled back under the same id below it (a
    // head below the cursor): read from 0, the cursor lowered to what the
    // feed holds now; the revoke stays final, the hold held.
    let revoke = rig.record(
        FEED_2,
        ControlAction::Revoke {
            interrupt_running: false,
        },
    );
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED_2, 3), [sync_call(FEED_2, 2)]);
    rig.page(FEED_2, 3, &[(3, &revoke)]);
    assert!(rig.feeds.standing(BOT).revoked.is_some());
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED_2, 1), [sync_call(FEED_2, 0)]);
    assert_eq!(rig.sync.closed(), Some(Closed::Reset));
    rig.page(FEED_2, 1, &[(1, &cover_2)]);
    assert_eq!(rig.cursor(), Some((FEED_2.to_string(), 1)));
    let standing = rig.feeds.standing(BOT);
    assert!(standing.revoked.is_some() && standing.held, "no stop lost");
    assert!(rig.open(&native()));
    // A page whose head is below the cursor: the same, found at the page.
    let release = rig.record(FEED_2, ControlAction::Release);
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED_2, 2), [sync_call(FEED_2, 1)]);
    let synced = rig.page(FEED_2, 2, &[(2, &release)]);
    assert!(synced.next.is_none());
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED_2, 3), [sync_call(FEED_2, 2)]);
    let page = rig.page_of(FEED_2, 1, vec![]);
    let synced = rig.on_page(page);
    assert_eq!(synced.next, Some(sync_call(FEED_2, 0)), "read again from 0");
    assert_eq!(rig.sync.closed(), Some(Closed::Reset));
    assert_eq!(
        rig.cursor(),
        Some((FEED_2.to_string(), 2)),
        "applies nothing"
    );
}

/// §11.4, Decision 12: a page that isn't strict JSON as a whole is a
/// Station fault: nothing applies, the cursor stays, the gate stays closed
/// (until a page that reads), and one alert an hour goes to runtime.log.
#[test]
fn a_non_strict_page_keeps_the_cursor_closes_the_gate_and_alerts() {
    let mut rig = rig();
    rig.opened();
    rig.sync.take_lines();
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
    let synced = rig.on_page(Err(RelayError::NotStrict));
    assert!(synced.applied.is_empty());
    assert_eq!(rig.cursor(), Some((FEED.to_string(), 2)));
    assert_eq!(rig.sync.closed(), Some(Closed::Fault("not_strict")));
    assert!(!rig.open(&native()));
    let lines = rig.sync.take_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains(NOT_STRICT), "{}", lines[0]);
    // Asked again after the pause, refused again: no second line within
    // the hour.
    assert_eq!(rig.pass(SEC), Vec::new(), "paused after a fault");
    assert_eq!(rig.heads(FEED, 3), Vec::new());
    assert_eq!(
        rig.pass(STALL_PAUSE_MS),
        [sync_call(FEED, 2)],
        "at the pass"
    );
    rig.on_page(Err(RelayError::NotStrict));
    assert!(rig.sync.take_lines().is_empty());
    // A page that reads: open again.
    rig.pass(STALL_PAUSE_MS);
    assert_eq!(rig.sync.closed(), Some(Closed::Fault("not_strict")));
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
    rig.page(FEED, 3, &[]);
    assert!(rig.open(&native()));
    // The hour passed: the count of what came is reported.
    rig.pass(HOUR);
    let lines = rig.sync.take_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("1 more"), "{}", lines[0]);
    // An unasked page that isn't strict is a fault too.
    rig.on_page(Err(RelayError::NotStrict));
    assert_eq!(rig.sync.closed(), Some(Closed::Fault("not_strict")));
}

/// §11.4 "A feed page's records are judged one at a time": a record that
/// doesn't parse is kept as evidence, never applied, and the page stands:
/// the records after it apply, the cursor moves past it (delivery, not
/// application) and the gate opens.
#[test]
fn a_record_that_doesnt_parse_is_evidence_and_the_page_stands() {
    let mut rig = rig();
    let cover = rig.record(FEED, ControlAction::Cover);
    let hold = rig.record(FEED, ControlAction::Hold);
    assert_eq!(rig.heads(FEED, 4), [sync_call(FEED, 0)]);
    let page = rig.page_of(
        FEED,
        4,
        vec![
            (1, cover.object().to_json()),
            (2, json!({"body": 1, "sig": "x"})),
            (3, json!("not a record")),
            (4, hold.object().to_json()),
        ],
    );
    let synced = rig.on_page(page);
    assert_eq!(synced.applied.len(), 2);
    assert_eq!(rig.feeds.evidence_count(), 2);
    assert_eq!(rig.cursor(), Some((FEED.to_string(), 4)));
    let standing = rig.feeds.standing(BOT);
    assert!(standing.held && standing.coverage.is_some());
    assert!(rig.open(&service(ORIGIN)));
}

/// I.6.5 "The cap": a `station_time` more than 10 minutes past `H` moves
/// no floor and closes that origin's gate; a `heads` within the cap opens
/// it again (and only that raises the floor).
#[test]
fn a_station_time_beyond_the_cap_closes_the_origins_gate_and_leaves_the_floor() {
    let mut rig = rig();
    rig.opened();
    let d = rig.d_ms();
    rig.pass(SEC);
    let ahead = rig.wall() + 11 * MIN;
    assert_eq!(
        rig.heads_with(&[(ORIGIN, FEED, 2)], Some(ahead)),
        Vec::new()
    );
    assert_eq!(rig.sync.closed(), Some(Closed::ClockAhead));
    assert!(!rig.open(&native()));
    assert!(rig.d_ms() < d + 2 * SEC, "the floor didn't move");
    // A page beyond the cap closes it too, and applies its records.
    let release = rig.record(FEED, ControlAction::Release);
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
    assert_eq!(
        rig.sync.closed(),
        Some(Closed::Behind {
            cursor: Some(2),
            head: 3
        })
    );
    let mut page = rig
        .page_of(FEED, 3, vec![(3, release.object().to_json())])
        .unwrap();
    page.station_time = rig.wall() + 11 * MIN;
    rig.on_page(Ok(page));
    assert!(!rig.feeds.standing(BOT).held, "the release applied");
    assert_eq!(rig.sync.closed(), Some(Closed::ClockAhead));
    // A heads within the cap: open, the floor raised to it.
    rig.pass(SEC);
    let within = rig.wall() + 5 * MIN;
    assert_eq!(
        rig.heads_with(&[(ORIGIN, FEED, 3)], Some(within)),
        Vec::new()
    );
    assert!(rig.open(&native()));
    assert!(rig.d_ms() >= within);
}

/// Decision 20, §11.4 "Refusals": each refusal (of `control_sync`,
/// `membership_fetch`, `control_ack`) closes every gate the link serves and
/// advances nothing: no cursor, announced head, clock floor or
/// acknowledgment. Nothing is asked before the 30-second backoff; then a
/// page asked anew opens the gate again.
#[test]
fn each_refusal_advances_no_cursor_head_floor_or_ack_and_opens_no_gate() {
    for call in [
        RefusedCall::ControlSync,
        RefusedCall::MembershipFetch,
        RefusedCall::ControlAck,
    ] {
        let mut rig = rig();
        rig.opened();
        let rows = |rig: &Rig| -> Vec<(String, i64)> {
            let mut st = rig
                .store
                .db
                .prepare("SELECT feed_id, cursor FROM control_feeds")
                .unwrap();
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))
                .unwrap()
                .map(Result::unwrap)
                .collect()
        };
        let before = (rows(&rig), rig.d_ms(), rig.sync.dump()["announced"].clone());
        rig.sync.on_refused(call);
        assert_eq!(rig.sync.closed(), Some(Closed::Refused), "{call:?}");
        assert_eq!(Closed::Refused.text(), REFUSED_STATUS);
        assert!(!rig.open(&native()) && !rig.open(&service(ORIGIN)));
        let after = (rows(&rig), rig.d_ms(), rig.sync.dump()["announced"].clone());
        assert_eq!(before.0, after.0, "no cursor");
        assert!(after.1 < before.1 + SEC, "no floor");
        assert_eq!(before.2, after.2, "no announced head");
        // The same head announced within the backoff: nothing asked, still
        // closed, though the feed holds it.
        rig.pass(SEC);
        assert_eq!(rig.heads(FEED, 2), Vec::new());
        assert!(!rig.open(&native()));
        // Past the backoff: asked again, and the page that reads opens it.
        rig.pass(REFUSAL_BACKOFF_MS);
        assert_eq!(rig.heads(FEED, 2), [sync_call(FEED, 2)]);
        rig.page(FEED, 2, &[]);
        assert!(rig.open(&native()), "{call:?}");
    }
}

/// §11.4 (Atem's reading): a refusal names a call kind, never a request.
/// It ends the host's own wait (the sync in flight is dropped), and is
/// never an answer: not an empty page (the cursor doesn't move to the
/// head), and the page that answers the earlier call, arriving after it,
/// is one nobody asked for: nothing of it applies.
#[test]
fn a_refusal_correlates_no_request() {
    let mut rig = rig();
    rig.opened();
    let release = rig.record(FEED, ControlAction::Release);
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
    rig.sync.on_refused(RefusedCall::ControlSync);
    assert_eq!(rig.sync.dump()["in_flight"], Value::Null, "the wait ended");
    assert_eq!(rig.cursor(), Some((FEED.to_string(), 2)), "no empty page");
    // The page that answers the earlier call.
    let synced = rig.page(FEED, 3, &[(3, &release)]);
    assert!(synced.applied.is_empty());
    assert!(rig.feeds.standing(BOT).held, "nothing applied");
    assert_eq!(rig.cursor(), Some((FEED.to_string(), 2)));
    assert_eq!(rig.sync.dump()["unasked"], 1);
    assert_eq!(rig.sync.closed(), Some(Closed::Refused));
}

/// Decision 14: the host syncs only its own Station's feed. A `heads` feed
/// of another origin is ignored (counted, alerted hourly): nothing is asked
/// of it, and its gate never opens.
#[test]
fn heads_of_another_origin_are_ignored() {
    let mut rig = rig();
    assert_eq!(rig.heads_with(&[(OTHER, FEED_2, 5)], None), Vec::new());
    assert_eq!(rig.sync.closed(), Some(Closed::NoFeed(0)));
    let lines = rig.sync.take_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(
        lines[0].contains(OTHER) || lines[0].contains("another origin"),
        "{}",
        lines[0]
    );
    rig.pass(SEC);
    let calls = rig.heads_with(&[(OTHER, FEED_2, 5), (ORIGIN, FEED, 0)], None);
    assert_eq!(calls, [sync_call(FEED, 0)]);
    rig.page(FEED, 0, &[]);
    assert!(rig.open(&service(ORIGIN)));
    assert!(!rig.sync.open_for(&service(OTHER), Some(OTHER)));
    assert!(!rig.sync.open_for(&service(OTHER), Some(ORIGIN)));
    assert_eq!(rig.sync.dump()["other_origin"], 2);
    assert!(rig.sync.take_lines().is_empty(), "one line an hour");
    // Two feeds of the own origin: neither is read.
    rig.pass(SEC);
    let calls = rig.heads_with(&[(ORIGIN, FEED, 0), (ORIGIN, FEED_2, 0)], None);
    assert_eq!(calls, Vec::new());
    assert_eq!(rig.sync.closed(), Some(Closed::NoFeed(2)));
}

/// I.5.8 "Native senders", Decision 14: a native member's gate is the
/// host's own Station's (the link's origin), whatever its device-list part
/// names; a link to another Station makes that one the native gate, closed
/// until its own feed is read.
#[test]
fn the_native_gate_is_the_own_stations() {
    let mut rig = rig();
    rig.opened();
    assert!(rig.sync.open_for(&native(), Some(ORIGIN)));
    assert!(!rig.sync.open_for(&native(), Some(OTHER)));
    assert_eq!(rig.sync.own(), Some(ORIGIN));
    rig.sync.take_gates();
    // The link now reaches another Station.
    rig.sync.on_link(Some(&link(2, OTHER)));
    assert_eq!(rig.sync.own(), Some(OTHER));
    assert!(!rig.sync.open_for(&native(), Some(OTHER)));
    assert!(!rig.sync.open_for(&service(ORIGIN), Some(ORIGIN)));
    assert_eq!(
        rig.sync.take_gates(),
        Some((Some(OTHER.to_string()), BTreeSet::new()))
    );
    // The start view's gates: the feed part from the sync, a native's own
    // caught-up channel besides.
    let mut gates = super::super::gate::Gates::default();
    gates.set_feeds(Some(ORIGIN.into()), BTreeSet::from([ORIGIN.to_string()]));
    assert!(gates.open_for(&native(), Some(ORIGIN)));
    assert!(!gates.open_for(&native(), None));
    gates.set_feeds(Some(OTHER.into()), BTreeSet::new());
    assert!(!gates.open_for(&native(), Some(OTHER)));
    gates.set_caught_up(BTreeSet::from(["member:dev-phone".to_string()]));
    assert!(gates.open_for(&native(), None));
}

/// The pacing (as the fetch's, Task 30 I1): one call in flight; the calls a
/// `heads` starts at most one a second, none for 30 s after a page that
/// moved nothing; one unanswered for 30 s asked again.
#[test]
fn syncs_are_paced_like_the_fetch() {
    let mut rig = rig();
    assert_eq!(rig.heads(FEED, 2), [sync_call(FEED, 0)]);
    assert_eq!(rig.heads(FEED, 2), Vec::new(), "one in flight");
    assert_eq!(rig.pass(SYNC_TIMEOUT_MS - 1), Vec::new());
    assert_eq!(rig.pass(1), [sync_call(FEED, 0)], "asked again");
    // A page that moved nothing: a pause.
    let beyond = rig.record(FEED, ControlAction::Cover);
    let page = rig.page_of(FEED, 0, vec![]);
    assert!(rig.on_page(page).applied.is_empty(), "{beyond:?}");
    assert_eq!(rig.heads(FEED, 2), Vec::new());
    assert_eq!(rig.pass(STALL_PAUSE_MS - 1), Vec::new());
    assert_eq!(rig.heads(FEED, 2), Vec::new());
    assert_eq!(rig.pass(1), [sync_call(FEED, 0)]);
}

/// I.5.4, R9.3: a page stops at a record while the device list doesn't
/// serve: nothing is consumed, the cursor stays, the gate stays closed.
#[test]
fn a_page_stops_while_the_list_doesnt_serve() {
    let mut rig = rig();
    let cover = rig.record(FEED, ControlAction::Cover);
    assert_eq!(rig.heads(FEED, 1), [sync_call(FEED, 0)]);
    let mut frozen = serving(&rig.log);
    frozen.frozen = true;
    let page = rig.page_of(FEED, 1, vec![(1, cover.object().to_json())]);
    let synced = rig.on_page_with(page, &frozen);
    assert!(synced.applied.is_empty());
    assert_eq!(rig.cursor(), None);
    assert!(!rig.open(&native()));
}

/// §11.4's open question (the fake Station's `StaleFeed::ServeCurrent`): a
/// page of another feed than the one asked applies nothing and reads as a
/// reset; the next `heads` announcing the new feed reads it from 0.
#[test]
fn a_page_of_another_feed_than_asked_applies_nothing() {
    let mut rig = rig();
    rig.opened();
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
    let cover = rig.record(FEED_2, ControlAction::Cover);
    let synced = rig.page(FEED_2, 1, &[(1, &cover)]);
    assert!(synced.applied.is_empty());
    assert_eq!(rig.sync.closed(), Some(Closed::Reset));
    assert_eq!(rig.cursor(), Some((FEED.to_string(), 2)));
    rig.pass(STALL_PAUSE_MS);
    assert_eq!(rig.heads(FEED_2, 1), [sync_call(FEED_2, 0)]);
    rig.page(FEED_2, 1, &[(1, &cover)]);
    assert!(rig.open(&native()));
    assert_eq!(rig.cursor(), Some((FEED_2.to_string(), 1)));
}

/// §11.4's open question, the other answer (the fake Station's
/// `StaleFeed::Refuse`): the sync of the old feed in flight at a reset is
/// refused. The gate closes and nothing is asked before the backoff, even
/// at a `heads` naming the new feed; then the new feed is read from 0.
#[test]
fn a_refused_stale_feed_is_read_anew_after_the_backoff() {
    let mut rig = rig();
    rig.opened();
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
    rig.sync.on_refused(RefusedCall::ControlSync);
    assert_eq!(rig.sync.closed(), Some(Closed::Refused));
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED_2, 1), Vec::new(), "within the backoff");
    assert_eq!(rig.pass(REFUSAL_BACKOFF_MS), Vec::new(), "only at a heads");
    assert_eq!(rig.heads(FEED_2, 1), [sync_call(FEED_2, 0)]);
    let cover = rig.record(FEED_2, ControlAction::Cover);
    rig.page(FEED_2, 1, &[(1, &cover)]);
    assert!(rig.open(&native()));
    assert_eq!(rig.cursor(), Some((FEED_2.to_string(), 1)));
}

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
    /// The host's monotonic clock (ms): apart from the boot-time counter
    /// (`os.boot_ns`), which also counts a suspend.
    mono_ms: u64,
    issued: u64,
    minted: u64,
    /// Every call the sync asked, as sent (each `request_id` checked fresh
    /// and lowercase v4 when asked).
    asked: Vec<ControlSync>,
}

fn host() -> HostTarget {
    HostTarget {
        account_id: "acct-s".into(),
        atem_device_id: "host".into(),
        host_trust_gen: 1,
    }
}

/// The socket the link generations of these tests run on, unless one names
/// another (a reconnect).
const SOCKET: u64 = 1;

/// Link generation `link_gen` on [`SOCKET`].
fn link(link_gen: u64, origin: &str) -> StationLink {
    link_on(link_gen, SOCKET, origin)
}

/// Link generation `link_gen` on socket `socket`.
fn link_on(link_gen: u64, socket: u64, origin: &str) -> StationLink {
    StationLink {
        link_gen,
        socket,
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
        mono_ms: 3 * HOUR,
        issued: 1_700_000_000_000,
        minted: 0,
        asked: Vec::new(),
    };
    rig.pass(0);
    rig
}

impl Rig {
    /// The pass's clocks: the monotonic one and the boot-time counter.
    fn clocks(&self) -> Clocks {
        Clocks {
            mono_ms: self.mono_ms,
            boot_ms: Some(self.os.lock().unwrap().boot_ns / 1_000_000),
        }
    }

    /// A suspend of `ms` (Linux: `CLOCK_MONOTONIC` stops, the boot-time
    /// counter and the wall clock go on), then the pass's tick.
    fn suspend(&mut self, ms: u64) -> Vec<ControlSync> {
        {
            let mut r = self.os.lock().unwrap();
            r.wall_ms += ms;
            r.boot_ns += ms * 1_000_000;
        }
        self.sync.tick(self.clocks(), Some(&self.feeds))
    }

    fn wall(&self) -> u64 {
        self.os.lock().unwrap().wall_ms
    }

    /// Time passes (wall, monotonic and boot time): the pass's tick, its
    /// calls.
    fn pass(&mut self, ms: u64) -> Vec<ControlSync> {
        {
            let mut r = self.os.lock().unwrap();
            r.wall_ms += ms;
            r.boot_ns += ms * 1_000_000;
        }
        self.mono_ms += ms;
        let calls = self.sync.tick(self.clocks(), Some(&self.feeds));
        self.marked(calls)
    }

    /// What the bridge does after each step of the sync: a reset found is
    /// marked durably, and its read from 0 asked then. The calls as
    /// [`Rig::seen`] gives them.
    fn marked(&mut self, mut calls: Vec<ControlSync>) -> Vec<ControlSync> {
        // A mark that can't be written is tried again at the next step.
        if let Ok(Some(ask)) = self.sync.persist_mark(&self.store, &mut self.feeds) {
            calls.push(ask);
        }
        self.seen(calls)
    }

    /// Calls the sync asked: each `request_id` a lowercase UUID v4 from no
    /// earlier call (wire rule 11), kept in [`Rig::asked`]; given back with
    /// the id blanked, to compare with [`sync_call`].
    fn seen(&mut self, calls: Vec<ControlSync>) -> Vec<ControlSync> {
        calls
            .into_iter()
            .map(|call| {
                let id = &call.request_id;
                let parsed = uuid::Uuid::parse_str(id).expect("a UUID");
                assert_eq!(parsed.get_version_num(), 4, "{id}");
                assert_eq!(parsed.hyphenated().to_string(), *id, "lowercase: {id}");
                assert!(
                    self.asked.iter().all(|a| a.request_id != *id),
                    "a fresh id: {id}"
                );
                self.asked.push(call.clone());
                ControlSync {
                    request_id: String::new(),
                    ..call
                }
            })
            .collect()
    }

    /// The host restarts (a crash): the feed store loaded again from the
    /// store, a new sync on a new link, the clocks going on.
    fn restart(&mut self) {
        let reading = self.os.clone();
        self.feeds = FeedStore::load(&self.store, &self.log.log)
            .unwrap()
            .with_clock(move || {
                let r = reading.lock().unwrap();
                HostNow {
                    wall_ms: r.wall_ms,
                    mono_ms: r.boot_ns / 1_000_000,
                    boot_id: r.boot_id.clone(),
                }
            });
        self.feeds.set_own_origin(Some(ORIGIN.into()));
        self.sync = FeedSync::new();
        self.sync.on_link(Some(&link(9, ORIGIN)));
        self.pass(SEC);
    }

    /// Whether the durable reset mark of [`ORIGIN`] is stored.
    fn mark_row(&self) -> Option<String> {
        self.store
            .db
            .query_row(
                "SELECT restarted FROM control_resets WHERE origin=?1",
                [ORIGIN],
                |r| r.get(0),
            )
            .ok()
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
        let calls = self.sync.on_heads(
            &heads,
            Some((&mut self.clock, &self.store)),
            Some(&self.feeds),
        );
        self.marked(calls)
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
    /// value) of `feed_id`, its head `head`, answering the call in flight
    /// (its `request_id` and `after`: wire rule 11); with none in flight,
    /// a call never asked (a fresh id, `after` just before its first
    /// record, or its head).
    fn page_of(
        &self,
        feed_id: &str,
        head: u64,
        records: Vec<(u64, Value)>,
    ) -> Result<ControlSyncResult, RelayError> {
        let call = self.sync.live_call().unwrap_or_else(|| ControlSync {
            request_id: uuid::Uuid::new_v4().to_string(),
            origin: ORIGIN.into(),
            feed_id: Some(feed_id.into()),
            after: records.first().map_or(head, |(seq, _)| seq - 1),
        });
        self.page_for(&call, feed_id, head, records)
    }

    /// The page as the reader gives it, answering `call` (its `request_id`
    /// and `after`), of `feed_id` (the call's, unless a test says another).
    fn page_for(
        &self,
        call: &ControlSync,
        feed_id: &str,
        head: u64,
        records: Vec<(u64, Value)>,
    ) -> Result<ControlSyncResult, RelayError> {
        let message = json!({
            "type": "relay", "op": "control_sync_result", "request_id": call.request_id,
            "origin": ORIGIN, "feed_id": feed_id, "after": call.after, "head": head,
            "station_time": self.wall(),
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
        let mut synced = self
            .sync
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
            .unwrap();
        synced.next = self.seen(synced.next.into_iter().collect()).pop();
        if let Some(ask) = self.marked(Vec::new()).pop() {
            synced.next = synced.next.or(Some(ask));
        }
        synced
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

    /// The call asked last, as sent.
    fn last(&self) -> ControlSync {
        self.asked.last().expect("a call asked").clone()
    }

    /// The page answering `call` (its id and `after`, on the feed it
    /// named), holding `records`, handed to the sync.
    fn answer(
        &mut self,
        call: &ControlSync,
        head: u64,
        records: &[(u64, &ControlRecord)],
    ) -> Synced {
        let feed_id = call.feed_id.clone().expect("a named feed");
        let records = records
            .iter()
            .map(|(seq, r)| (*seq, FeedEntry::new(*seq, r).raw().clone()))
            .collect();
        let page = self.page_for(call, &feed_id, head, records);
        self.on_page(page)
    }

    /// Pages drained so far: answers to retired calls.
    fn drained(&self) -> u64 {
        self.sync.dump()["drained"].as_u64().unwrap()
    }

    fn d_ms(&self) -> u64 {
        self.clock.reading().unwrap().d_ms
    }
}

/// A call as [`Rig::seen`] gives it back: its `request_id` blanked.
fn sync_call(feed_id: &str, after: u64) -> ControlSync {
    ControlSync {
        request_id: String::new(),
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
    let alerts = rig.sync.alerts().0;
    rig.on_page(Ok(page));
    assert!(!rig.feeds.standing(BOT).held, "the release applied");
    assert_eq!(rig.sync.closed(), Some(Closed::ClockAhead));
    assert_eq!(rig.sync.alerts().0, alerts + 1, "counted (ruling T33c, N3)");
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

/// §11.4 (Atem's reading; ruling C1b-a): a refusal names a call kind,
/// never a request. It retires the live sync call, and is never an answer:
/// not an empty page (the cursor doesn't move to the head), and the page
/// that answers the retired call, arriving after it, is drained: nothing
/// of it applies.
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
    let a = rig.last();
    let synced = rig.answer(&a, 3, &[(3, &release)]);
    assert!(synced.applied.is_empty());
    assert!(rig.feeds.standing(BOT).held, "nothing applied");
    assert_eq!(rig.cursor(), Some((FEED.to_string(), 2)));
    assert_eq!(rig.drained(), 1, "its id retired: drained");
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
/// moved nothing. (One unanswered for 30 s is retired and asked again: see
/// `an_unanswered_sync_is_retired_and_asked_again_with_a_fresh_id`.)
#[test]
fn syncs_are_paced_like_the_fetch() {
    let mut rig = rig();
    assert_eq!(rig.heads(FEED, 2), [sync_call(FEED, 0)]);
    assert_eq!(rig.heads(FEED, 2), Vec::new(), "one in flight");
    // Read to 0 of 2: the rest asked at once.
    let page = rig.page_of(FEED, 0, vec![]);
    assert_eq!(rig.on_page(page).next, Some(sync_call(FEED, 0)));
    // A page that moved nothing: a pause.
    let page = rig.page_of(FEED, 0, vec![]);
    assert_eq!(rig.on_page(page).next, None);
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

/// Task 33 review I1: a page that applied nothing (the feed store had no
/// own Station's origin to place it: the pass that sets it skipped, a
/// pause) is no read. A reset's read keeps the reset (the gate closed, the
/// old cursor where it was, the read from 0 asked again after the pause);
/// a refusal's resynchronization keeps the refusal's closure.
#[test]
fn a_page_that_applied_nothing_keeps_the_reset_and_the_gate_closed() {
    let mut rig = rig();
    rig.opened();
    // The feed rolled back under the same id.
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 1), [sync_call(FEED, 0)]);
    assert_eq!(rig.sync.closed(), Some(Closed::Reset));
    rig.feeds.set_own_origin(None);
    let cover = rig.record(FEED, ControlAction::Cover);
    let synced = rig.page(FEED, 1, &[(1, &cover)]);
    assert!(synced.applied.is_empty() && synced.next.is_none());
    assert_eq!(rig.sync.closed(), Some(Closed::Reset), "no read");
    assert!(!rig.open(&native()));
    assert_eq!(rig.cursor(), Some((FEED.to_string(), 2)));
    // Asked again (from 0) once the pause passed, and read then.
    assert_eq!(rig.pass(SEC), Vec::new(), "paused");
    rig.feeds.set_own_origin(Some(ORIGIN.into()));
    assert_eq!(rig.pass(STALL_PAUSE_MS), [sync_call(FEED, 0)]);
    rig.page(FEED, 1, &[(1, &cover)]);
    assert_eq!(rig.cursor(), Some((FEED.to_string(), 1)));
    assert!(rig.open(&native()));

    // A refusal's resynchronization: a page that applied nothing doesn't
    // end it.
    rig.sync.on_refused(RefusedCall::MembershipFetch);
    rig.pass(REFUSAL_BACKOFF_MS);
    assert_eq!(rig.heads(FEED, 1), [sync_call(FEED, 1)]);
    rig.feeds.set_own_origin(None);
    rig.page(FEED, 1, &[]);
    assert_eq!(rig.sync.closed(), Some(Closed::Refused));
    assert!(!rig.open(&native()));
}

/// Task 33 review I2 (I.6.5: the delegated lifecycle's elapsed time is boot
/// time, which counts a suspend): the 60 s without `heads` are measured on
/// the larger of the monotonic and the boot-time elapsed times, never
/// shorter than either. A Linux host that slept (the boot-time counter on,
/// the monotonic clock still) finds its gate closed at once on waking.
#[test]
fn sixty_seconds_without_heads_count_a_suspend() {
    let mut rig = rig();
    rig.opened();
    rig.suspend(2 * HOUR);
    assert_eq!(rig.sync.closed(), Some(Closed::HeadsLate));
    assert!(!rig.open(&native()));
    assert_eq!(rig.heads(FEED, 2), Vec::new());
    assert!(rig.open(&native()));
    // Short of 60 s on both: open; at 60 s on the boot-time counter alone
    // (a suspend of the rest): closed.
    rig.pass(NO_HEADS_MS - 2 * SEC);
    assert!(rig.open(&native()));
    rig.suspend(2 * SEC);
    assert_eq!(rig.sync.closed(), Some(Closed::HeadsLate));
    // The monotonic clock alone counts too (no boot-time reading).
    assert_eq!(rig.heads(FEED, 2), Vec::new());
    rig.mono_ms += NO_HEADS_MS;
    rig.sync.tick(
        Clocks {
            mono_ms: rig.mono_ms,
            boot_ms: None,
        },
        Some(&rig.feeds),
    );
    assert_eq!(rig.sync.closed(), Some(Closed::HeadsLate));
}

/// Task 33 review m3: a cursor above the announced head of the same feed
/// is a reset wherever it is found, not only at the `heads`: here the
/// `heads` came while the feeds weren't loaded, and the load finds it. A
/// page whose head is above the announced one raises the announcement
/// (the gate needs that much read), never a false reset.
#[test]
fn a_cursor_above_the_announced_head_is_a_reset_once_the_feeds_load() {
    let mut rig = rig();
    rig.opened();
    rig.pass(SEC);
    // The feeds unloaded: a heads naming a head below the cursor.
    rig.sync.tick(rig.clocks(), None);
    let heads = Heads {
        feeds: vec![FeedHead {
            origin: ORIGIN.into(),
            feed_id: FEED.into(),
            head: 1,
            station_time: rig.wall(),
        }],
        membership: rig.log.log.head(),
    };
    assert_eq!(
        rig.sync
            .on_heads(&heads, Some((&mut rig.clock, &rig.store)), None),
        Vec::new()
    );
    assert_eq!(rig.sync.closed(), Some(Closed::Unloaded));
    // Loaded again: a reset, read from 0.
    assert_eq!(rig.pass(SEC), [sync_call(FEED, 0)]);
    assert_eq!(rig.sync.closed(), Some(Closed::Reset));
    let cover = rig.record(FEED, ControlAction::Cover);
    let hold = rig.record(FEED, ControlAction::Hold);
    let release = rig.record(FEED, ControlAction::Release);
    // The read from 0 finds the feed grown past the announcement.
    rig.page(FEED, 3, &[(1, &cover), (2, &hold), (3, &release)]);
    assert_eq!(rig.cursor(), Some((FEED.to_string(), 3)));
    assert_eq!(rig.sync.closed(), None);
    assert_eq!(rig.pass(SEC), Vec::new(), "no false reset");
    assert_eq!(rig.sync.closed(), None);
}

/// Task 33 review m5: the start's recovery (design I.6.2 step 7) closes
/// the gate until a page asked from then reads, even with the cursor at the
/// announced head; a `heads` alone doesn't reopen it.
#[test]
fn the_recoverys_restart_waits_for_a_fresh_page() {
    let mut rig = rig();
    rig.opened();
    rig.sync.restart();
    assert_eq!(rig.sync.closed(), Some(Closed::Restarted));
    assert!(!rig.open(&native()));
    assert_eq!(rig.pass(SEC), [sync_call(FEED, 2)], "asked at once");
    assert_eq!(rig.heads(FEED, 2), Vec::new(), "one in flight");
    assert!(!rig.open(&native()), "a heads doesn't reopen it");
    rig.page(FEED, 2, &[]);
    assert!(rig.open(&native()));
}

/// Task 37 finding (VII.A test 7 against the fake Station): a
/// resynchronization's page that finds the host at the announced head (the
/// start's recovery, a refusal's) moves nothing, as expected: it pauses
/// nothing, so a record announced a second later is asked for at once.
/// The 30-second pause is for a page that leaves the host behind the head
/// the Station announced (`syncs_are_paced_like_the_fetch`); taken after
/// every resynchronization, it kept the first record after each restart
/// unread for up to 30 seconds, its gate closed meanwhile.
#[test]
fn a_resync_page_at_the_head_pauses_nothing() {
    let mut rig = rig();
    rig.opened();
    // The start's recovery: its page finds the host at the head.
    rig.sync.restart();
    assert_eq!(rig.pass(SEC), [sync_call(FEED, 2)]);
    assert!(rig.page(FEED, 2, &[]).next.is_none());
    assert!(rig.open(&native()));
    // A record more, a second later: asked at once, and read.
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
    let release = rig.record(FEED, ControlAction::Release);
    rig.page(FEED, 3, &[(3, &release)]);
    assert!(rig.open(&native()));
    // A refusal's resynchronization, past its backoff: the same.
    rig.pass(SEC);
    rig.sync.on_refused(RefusedCall::ControlSync);
    assert!(!rig.open(&native()));
    rig.pass(REFUSAL_BACKOFF_MS);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 3)]);
    assert!(rig.page(FEED, 3, &[]).next.is_none());
    assert!(rig.open(&native()));
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 4), [sync_call(FEED, 3)]);
}

/// Task 37 re-review N1 (ruling T37b), the sync's side: a page that moved
/// nothing pauses the calls while the host is behind the highest head the
/// Station named since the call was sent, not only the latest `heads`'. A
/// Station that announces a head beyond the host's, then names the host's
/// own cursor while that call is in flight, and answers with a page that
/// moves nothing, gets the 30-second pause all the same. (The page's own
/// head counts as named too.)
#[test]
fn a_station_that_names_a_lower_head_mid_call_still_pauses_the_sync() {
    let mut rig = rig();
    rig.opened();
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 4), [sync_call(FEED, 2)]);
    // In flight, the Station names the host's own cursor.
    assert_eq!(rig.heads(FEED, 2), Vec::new(), "one in flight");
    // Its page: the cursor's own head, no record. Nothing moved, and the
    // host stayed behind the 4 the call was asked for.
    let page = rig.page_of(FEED, 2, vec![]);
    assert!(rig.on_page(page).next.is_none());
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 4), Vec::new(), "paused");
    assert_eq!(rig.pass(STALL_PAUSE_MS - SEC - 1), Vec::new());
    assert_eq!(rig.heads(FEED, 4), Vec::new(), "paused");
    assert_eq!(rig.pass(1), [sync_call(FEED, 2)], "asked once it passed");

    // A page at the head the call was asked for pauses nothing, as
    // `a_resync_page_at_the_head_pauses_nothing`: the same shape with the
    // Station's word never beyond the cursor.
    let mut rig = self::rig();
    rig.opened();
    rig.sync.restart();
    assert_eq!(rig.pass(SEC), [sync_call(FEED, 2)]);
    assert_eq!(rig.heads(FEED, 2), Vec::new(), "one in flight");
    let page = rig.page_of(FEED, 2, vec![]);
    assert!(rig.on_page(page).next.is_none());
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)], "not paused");
}

/// Task 33 review m5: a `station_time` the delegated clock can't record
/// (here no clock at all) counts as no `station_time`: the gate closes until
/// a `heads` whose time is recorded within the cap.
#[test]
fn an_unrecorded_station_time_closes_the_gate() {
    let mut rig = rig();
    rig.opened();
    rig.pass(SEC);
    let heads = Heads {
        feeds: vec![FeedHead {
            origin: ORIGIN.into(),
            feed_id: FEED.into(),
            head: 2,
            station_time: rig.wall(),
        }],
        membership: rig.log.log.head(),
    };
    assert_eq!(
        rig.sync.on_heads(&heads, None, Some(&rig.feeds)),
        Vec::new()
    );
    assert_eq!(rig.sync.closed(), Some(Closed::ClockUnrecorded));
    assert!(!rig.open(&native()));
    assert_eq!(rig.heads(FEED, 2), Vec::new());
    assert!(rig.open(&native()));
}

/// Task 33 review m5, ruling C1b-a: a page with the live call's id that
/// names another origin than the call's (the host's own Station's) doesn't
/// answer it: a Station fault (nothing applies, the gate closes); a page
/// that arrives while the feeds aren't loaded applies nothing, and the
/// feed is asked again once they are.
#[test]
fn a_page_of_another_origin_or_without_the_feeds_applies_nothing() {
    let mut rig = rig();
    rig.opened();
    rig.sync.take_lines();
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
    let release = rig.record(FEED, ControlAction::Release);
    let mut page = rig
        .page_of(FEED, 3, vec![(3, release.object().to_json())])
        .unwrap();
    page.origin = OTHER.into();
    let synced = rig.on_page(Ok(page));
    assert!(synced.applied.is_empty());
    assert!(rig.feeds.standing(BOT).held);
    assert_eq!(rig.sync.closed(), Some(Closed::Fault(MISMATCHED_ORIGIN)));
    assert_eq!(rig.sync.take_lines().len(), 1);
    // Asked again after the pause; its page comes while the feeds aren't
    // loaded.
    assert_eq!(rig.pass(STALL_PAUSE_MS), [sync_call(FEED, 2)]);
    let page = rig.page_of(FEED, 3, vec![(3, release.object().to_json())]);
    let synced = rig
        .sync
        .on_page(page, Some((&mut rig.clock, &rig.store)), None)
        .unwrap();
    assert!(synced.applied.is_empty() && !synced.read);
    assert!(rig.feeds.standing(BOT).held);
    assert!(!rig.open(&native()));
    // Loaded again: asked after the pause (at the next heads: the last
    // came 60 s ago), read.
    assert_eq!(rig.pass(STALL_PAUSE_MS), Vec::new());
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
    rig.page(FEED, 3, &[(3, &release)]);
    assert!(!rig.feeds.standing(BOT).held);
    assert!(rig.open(&native()));
}

/// Ruling T33c (the review's out-of-scope finding): a reset is marked
/// durably, per origin, before anything is asked for it, and the mark is
/// cleared only by the commit that reads the feed from 0 up to the
/// announced head. A crash after the reset was found, the feed grown back
/// past the old cursor with other records: the host still reads it from 0
/// and applies the records in between (a stop among them). A crash part
/// way through the read goes on from where it was (its cursor already
/// replaced), the gate closed until the read reaches the head.
#[test]
fn a_reset_found_before_a_crash_is_read_from_0_after_it() {
    let mut rig = rig();
    let cover = rig.record(FEED, ControlAction::Cover);
    let hold = rig.record(FEED, ControlAction::Hold);
    let release = rig.record(FEED, ControlAction::Release);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 0)]);
    rig.page(FEED, 3, &[(1, &cover), (2, &hold), (3, &release)]);
    assert!(rig.open(&native()));
    assert!(!rig.feeds.standing(BOT).held);
    // The feed rolled back under the same id: found, marked, asked from 0.
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 1), [sync_call(FEED, 0)]);
    assert_eq!(rig.mark_row().as_deref(), Some(""));
    // The host crashes before the read. The feed grows back past the old
    // cursor with other records: a hold and a revoke where the release was.
    rig.restart();
    assert_eq!(rig.sync.closed(), Some(Closed::NoHeads));
    let hold_2 = rig.record(FEED, ControlAction::Hold);
    let revoke = rig.record(
        FEED,
        ControlAction::Revoke {
            interrupt_running: false,
        },
    );
    let later = rig.record(FEED, ControlAction::Hold);
    assert_eq!(rig.heads(FEED, 4), [sync_call(FEED, 0)], "from 0");
    assert_eq!(rig.sync.closed(), Some(Closed::Reset));
    // The read from 0, in two pages; a crash after the first.
    rig.page(FEED, 4, &[(1, &cover), (2, &hold_2)]);
    assert_eq!(rig.cursor(), Some((FEED.to_string(), 2)), "lowered");
    assert_eq!(rig.mark_row().as_deref(), Some(FEED), "begun, not done");
    assert!(rig.feeds.standing(BOT).held);
    rig.restart();
    assert_eq!(rig.heads(FEED, 4), [sync_call(FEED, 2)], "goes on");
    assert_eq!(rig.sync.closed(), Some(Closed::Reset));
    assert!(!rig.open(&native()));
    rig.page(FEED, 4, &[(3, &revoke), (4, &later)]);
    assert_eq!(rig.mark_row(), None, "cleared with the read's last page");
    assert!(rig.feeds.standing(BOT).revoked.is_some(), "the stop read");
    assert!(rig.open(&native()));
}

/// Ruling T33c: nothing is asked for a reset before its mark is durable; a
/// mark that can't be written keeps the gate closed and is written again at
/// the next step, and the read from 0 is asked then.
#[test]
fn a_reset_asks_nothing_before_its_mark_is_written() {
    let mut rig = rig();
    rig.opened();
    rig.store
        .db
        .execute_batch(
            "CREATE TRIGGER no_mark BEFORE INSERT ON control_resets
             BEGIN SELECT RAISE(ABORT, 'no mark'); END;",
        )
        .unwrap();
    rig.pass(SEC);
    let heads = Heads {
        feeds: vec![FeedHead {
            origin: ORIGIN.into(),
            feed_id: FEED.into(),
            head: 1,
            station_time: rig.wall(),
        }],
        membership: rig.log.log.head(),
    };
    assert_eq!(
        rig.sync
            .on_heads(&heads, Some((&mut rig.clock, &rig.store)), Some(&rig.feeds)),
        Vec::new(),
        "nothing before the mark"
    );
    assert!(rig.sync.persist_mark(&rig.store, &mut rig.feeds).is_err());
    assert_eq!(rig.sync.closed(), Some(Closed::Reset));
    assert_eq!(rig.pass(SEC), Vec::new(), "still unmarked");
    rig.store.db.execute_batch("DROP TRIGGER no_mark;").unwrap();
    assert_eq!(rig.pass(SEC), [sync_call(FEED, 0)]);
    assert_eq!(rig.mark_row().as_deref(), Some(""));
}

/// Task 33 re-review 2, R2-1 (ruling T33d): a page that isn't part of the
/// read from 0 never clears a reset's mark. A continuation (after 3) is in
/// flight; a `heads` reports a rollback under the same `feed_id` and the
/// mark is written; the old call's answer then comes with the feed regrown
/// past 3. It applies as the continuation it is, the mark stays, and the
/// host asks the feed from 0, the gate closed until that read is done.
#[test]
fn a_continuation_in_flight_never_ends_a_reset() {
    let mut rig = rig();
    let cover = rig.record(FEED, ControlAction::Cover);
    let hold = rig.record(FEED, ControlAction::Hold);
    let release = rig.record(FEED, ControlAction::Release);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 0)]);
    rig.page(FEED, 3, &[(1, &cover), (2, &hold), (3, &release)]);
    // A continuation in flight.
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 4), [sync_call(FEED, 3)]);
    // The rollback found: marked, nothing asked (one in flight).
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 1), Vec::new());
    assert_eq!(rig.mark_row().as_deref(), Some(""));
    assert_eq!(rig.sync.closed(), Some(Closed::Reset));
    // The old call's answer, the feed regrown past 3.
    let x = rig.record(FEED, ControlAction::Hold);
    let y = rig.record(FEED, ControlAction::Release);
    let synced = rig.page(FEED, 5, &[(4, &x), (5, &y)]);
    assert_eq!(synced.applied.len(), 2, "the continuation it is");
    assert_eq!(rig.mark_row().as_deref(), Some(""), "the mark stays");
    assert_eq!(rig.sync.closed(), Some(Closed::Reset));
    assert!(!rig.open(&native()));
    assert_eq!(synced.next, Some(sync_call(FEED, 0)), "from 0");
    // The read from 0 finds a revoke below the old cursor.
    let revoke = rig.record(
        FEED,
        ControlAction::Revoke {
            interrupt_running: false,
        },
    );
    rig.page(
        FEED,
        5,
        &[(1, &cover), (2, &revoke), (3, &release), (4, &x), (5, &y)],
    );
    assert!(rig.feeds.standing(BOT).revoked.is_some());
    assert_eq!(rig.mark_row(), None);
    assert!(rig.open(&native()));
}

/// Ruling T33d ("any other page that could be taken for the read from 0"):
/// a refusal of another call than `control_sync` doesn't answer the sync in
/// flight, so the call stays in flight (its answer would otherwise come
/// after a later ask and be taken for its page). Its answer applies as what
/// it is, but ends neither the refusal's resynchronization (it was asked
/// before) nor a reset found meanwhile.
#[test]
fn a_refusal_of_another_call_keeps_the_sync_in_flight() {
    let mut rig = rig();
    let cover = rig.record(FEED, ControlAction::Cover);
    let hold = rig.record(FEED, ControlAction::Hold);
    let release = rig.record(FEED, ControlAction::Release);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 0)]);
    rig.page(FEED, 3, &[(1, &cover), (2, &hold), (3, &release)]);
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 4), [sync_call(FEED, 3)]);
    rig.sync.on_refused(RefusedCall::MembershipFetch);
    assert_eq!(rig.sync.closed(), Some(Closed::Refused));
    // The rollback found meanwhile, marked.
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 1), Vec::new());
    // The call's answer: applied, nothing ended.
    let x = rig.record(FEED, ControlAction::Hold);
    let synced = rig.page(FEED, 4, &[(4, &x)]);
    assert_eq!(synced.applied.len(), 1);
    assert_eq!(synced.next, None, "the backoff");
    assert_eq!(rig.sync.closed(), Some(Closed::Refused));
    assert_eq!(rig.mark_row().as_deref(), Some(""));
    // Past the backoff, at a heads: the read from 0, which ends both.
    rig.pass(REFUSAL_BACKOFF_MS);
    assert_eq!(rig.heads(FEED, 4), [sync_call(FEED, 0)]);
    rig.page(FEED, 4, &[(1, &cover), (2, &hold), (3, &release), (4, &x)]);
    assert_eq!(rig.mark_row(), None);
    assert!(rig.open(&native()));
}

/// Ruling T33d: the start's restart keeps a call in flight (its answer is
/// owed, and dropped it would be taken for the next call's page); that
/// page applies but doesn't end the restart's resynchronization: a page
/// asked after it does.
#[test]
fn the_restart_keeps_a_call_in_flight_and_its_page_ends_nothing() {
    let mut rig = rig();
    rig.opened();
    let release = rig.record(FEED, ControlAction::Release);
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
    rig.sync.restart();
    assert_eq!(rig.pass(SEC), Vec::new(), "one in flight");
    let synced = rig.page(FEED, 3, &[(3, &release)]);
    assert_eq!(synced.applied.len(), 1);
    assert_eq!(rig.sync.closed(), Some(Closed::Restarted));
    assert!(!rig.open(&native()));
    // A page asked after the restart, at once.
    assert_eq!(synced.next, Some(sync_call(FEED, 3)));
    rig.page(FEED, 3, &[]);
    assert!(rig.open(&native()));
}

// ------------------------------------------------------- correlation (C1b)

/// Ruling C1b-a (wire rule 11; Astation's "same-cursor retries"): a call
/// unanswered for 30 s is retired by its id, and a new one, with a fresh
/// id, goes at once at the same cursor. The retired call's late page is
/// drained (counted, never applied, no Station fault: bytes written before
/// the retry may still come); only the live id's page applies, whichever
/// of the two arrives first.
#[test]
fn a_same_cursor_retry_applies_only_the_live_ids_page() {
    for live_first in [false, true] {
        let mut rig = rig();
        rig.opened();
        let release = rig.record(FEED, ControlAction::Release);
        rig.pass(SEC);
        assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
        let a = rig.last();
        assert_eq!(
            rig.pass(SYNC_TIMEOUT_MS),
            [sync_call(FEED, 2)],
            "retried at once"
        );
        let b = rig.last();
        assert_ne!(a.request_id, b.request_id);
        assert_eq!(rig.sync.closed(), Some(Closed::Unanswered));
        let faults = rig.sync.dump()["faults"].clone();
        if live_first {
            rig.answer(&b, 3, &[(3, &release)]);
            assert!(!rig.feeds.standing(BOT).held);
            assert!(rig.open(&native()));
        }
        // A's late page: drained.
        let synced = rig.answer(&a, 3, &[(3, &release)]);
        assert!(synced.applied.is_empty() && synced.next.is_none());
        assert_eq!(rig.drained(), 1);
        assert_eq!(rig.sync.dump()["faults"], faults, "no Station fault");
        if !live_first {
            assert!(rig.feeds.standing(BOT).held, "nothing applied");
            assert_eq!(rig.cursor(), Some((FEED.to_string(), 2)));
            assert!(!rig.open(&native()));
            assert_eq!(
                rig.sync.live_call().map(|c| c.request_id),
                Some(b.request_id.clone()),
                "B still live"
            );
            rig.answer(&b, 3, &[(3, &release)]);
            assert!(!rig.feeds.standing(BOT).held);
        }
        assert!(rig.open(&native()), "live first: {live_first}");
        assert_eq!(rig.cursor(), Some((FEED.to_string(), 3)));
    }
}

/// Ruling C1b-a (Astation: a call gets its result within 30 s, or the
/// Station fences the link): a call unanswered for 30 s is retired, an
/// hourly Station-fault alert goes, `atem status` says so (with no way out
/// to name: the sync goes on by itself), and the same pass asks again,
/// with a fresh id, under the pacing. A later timeout retires its call too
/// (no second line within the hour); the live call's page opens the gate.
#[test]
fn an_unanswered_sync_is_retired_and_asked_again_with_a_fresh_id() {
    let mut rig = rig();
    rig.opened();
    rig.sync.take_lines();
    let release = rig.record(FEED, ControlAction::Release);
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
    assert_eq!(rig.pass(SYNC_TIMEOUT_MS - 1), Vec::new());
    assert_eq!(
        rig.sync.closed(),
        Some(Closed::Behind {
            cursor: Some(2),
            head: 3
        })
    );
    assert_eq!(rig.pass(1), [sync_call(FEED, 2)], "retired, asked again");
    assert_eq!(rig.sync.closed(), Some(Closed::Unanswered));
    assert_eq!(Closed::Unanswered.text(), UNANSWERED);
    assert!(!UNANSWERED.contains("atem runtime restart"), "{UNANSWERED}");
    assert!(!rig.open(&native()));
    let lines = rig.sync.take_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("unanswered"), "{}", lines[0]);
    assert_eq!(rig.sync.dump()["timeouts"], 1);
    // Unanswered again (a heads keeps the window): retired, asked again;
    // the alert counted, no second line within the hour.
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), Vec::new(), "one live call");
    assert_eq!(rig.pass(SYNC_TIMEOUT_MS), [sync_call(FEED, 2)]);
    assert!(rig.sync.take_lines().is_empty());
    assert_eq!(rig.sync.dump()["timeouts"], 2);
    // The live call's page: read, open.
    let live = rig.last();
    rig.answer(&live, 3, &[(3, &release)]);
    assert_eq!(rig.sync.closed(), None);
    assert!(rig.open(&native()));
}

/// Ruling C1b-a (Astation's "reordered old replies"): the pages of retired
/// calls, in any order (here the newer retired call's first), are drained;
/// only the live call's applies.
#[test]
fn reordered_old_replies_are_drained() {
    let mut rig = rig();
    rig.opened();
    let release = rig.record(FEED, ControlAction::Release);
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
    let a = rig.last();
    // A new generation on the same socket retires A; its heads asks B.
    rig.sync.on_link(Some(&link(2, ORIGIN)));
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
    let b = rig.last();
    // B unanswered for 30 s: retired, C asked.
    assert_eq!(rig.pass(SYNC_TIMEOUT_MS), [sync_call(FEED, 2)]);
    let c = rig.last();
    // B's page, then A's: drained.
    for old in [&b, &a] {
        let synced = rig.answer(old, 3, &[(3, &release)]);
        assert!(synced.applied.is_empty());
    }
    assert_eq!(rig.drained(), 2);
    assert_eq!(rig.sync.dump()["faults"], 0);
    assert!(rig.feeds.standing(BOT).held);
    assert!(!rig.open(&native()));
    // C's page applies.
    rig.answer(&c, 3, &[(3, &release)]);
    assert!(!rig.feeds.standing(BOT).held);
    assert!(rig.open(&native()));
}

/// Ruling C1b-a, probe F (Astation's "same-socket re-authentication and
/// routed upgrade"): a new link generation on the same socket retires the
/// call in flight (the Station cancels the old generation's jobs, and
/// bytes written before that may still come: their retired id is
/// drained). The new generation asks with a fresh id at its `heads`, and
/// its gate opens only after a full read. With truncated pages the old
/// call's page is never taken for a new call's, so a revoke is never read
/// past.
#[test]
fn a_new_generation_on_the_same_socket_retires_the_call_and_asks_afresh() {
    let mut rig = rig();
    rig.opened();
    let r3 = rig.record(FEED, ControlAction::Release);
    let r4 = rig.record(FEED, ControlAction::Hold);
    let revoke = rig.record(
        FEED,
        ControlAction::Revoke {
            interrupt_running: false,
        },
    );
    let r6 = rig.record(FEED, ControlAction::Release);
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 6), [sync_call(FEED, 2)], "A");
    let a = rig.last();
    rig.sync.on_link(Some(&link(2, ORIGIN)));
    assert_eq!(rig.sync.live_call(), None, "A retired");
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 6), [sync_call(FEED, 2)], "B, a fresh id");
    let b = rig.last();
    assert_ne!(a.request_id, b.request_id);
    // A's page (truncated at 4): drained.
    let synced = rig.answer(&a, 6, &[(3, &r3), (4, &r4)]);
    assert!(synced.applied.is_empty());
    assert_eq!(rig.cursor(), Some((FEED.to_string(), 2)));
    // B's page, truncated at 4: applied, C asked at once; not open yet.
    let synced = rig.answer(&b, 6, &[(3, &r3), (4, &r4)]);
    assert_eq!(synced.applied.len(), 2);
    assert_eq!(synced.next, Some(sync_call(FEED, 4)), "C");
    let c = rig.last();
    assert!(!rig.open(&native()), "open only after a full read");
    // A's page again: drained; the revoke isn't read past.
    let synced = rig.answer(&a, 6, &[(3, &r3), (4, &r4)]);
    assert!(synced.applied.is_empty());
    assert_eq!(rig.drained(), 2);
    assert_eq!(rig.sync.dump()["faults"], 0);
    assert!(rig.feeds.standing(BOT).revoked.is_none());
    // C's page: the revoke read; open.
    rig.answer(&c, 6, &[(5, &revoke), (6, &r6)]);
    assert!(rig.feeds.standing(BOT).revoked.is_some());
    assert_eq!(rig.cursor(), Some((FEED.to_string(), 6)));
    assert!(rig.open(&native()));
}

/// Ruling C1b-a, probe G: the same with a rollback under the same
/// `feed_id` found on the new generation. The old continuation's page (the
/// feed regrown past it) is drained, never taken as a continuation: the
/// new generation reads the feed from 0 at once (its mark written), and
/// only that read ends the reset.
#[test]
fn a_reset_on_the_next_generation_never_takes_the_old_continuations_page() {
    let mut rig = rig();
    let cover = rig.record(FEED, ControlAction::Cover);
    let hold = rig.record(FEED, ControlAction::Hold);
    let release = rig.record(FEED, ControlAction::Release);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 0)]);
    rig.page(FEED, 3, &[(1, &cover), (2, &hold), (3, &release)]);
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 4), [sync_call(FEED, 3)], "A");
    let a = rig.last();
    rig.sync.on_link(Some(&link(2, ORIGIN)));
    rig.pass(SEC);
    // The rollback on the new generation: marked, read from 0 at once.
    assert_eq!(rig.heads(FEED, 1), [sync_call(FEED, 0)], "B");
    let b = rig.last();
    assert_eq!(rig.mark_row().as_deref(), Some(""));
    assert_eq!(rig.sync.closed(), Some(Closed::Reset));
    // A's page, the feed regrown to 5: drained.
    let x = rig.record(FEED, ControlAction::Hold);
    let y = rig.record(FEED, ControlAction::Release);
    let synced = rig.answer(&a, 5, &[(4, &x), (5, &y)]);
    assert!(synced.applied.is_empty());
    assert_eq!(rig.mark_row().as_deref(), Some(""));
    assert_eq!(rig.cursor(), Some((FEED.to_string(), 3)));
    assert!(!rig.open(&native()));
    // B's page: the read from 0 finds a revoke below the old cursor.
    let revoke = rig.record(
        FEED,
        ControlAction::Revoke {
            interrupt_running: false,
        },
    );
    rig.answer(
        &b,
        5,
        &[(1, &cover), (2, &revoke), (3, &release), (4, &x), (5, &y)],
    );
    assert!(rig.feeds.standing(BOT).revoked.is_some());
    assert_eq!(rig.mark_row(), None);
    assert!(rig.open(&native()));
}

/// Ruling C1b-a (Astation's "a reset between call and result"): the feed
/// goes back under the same id while a continuation is in flight, and the
/// call's own answer says so: its `head` below its echoed `after`, with no
/// record (the reader refuses one). A reset: its mark is written durably,
/// the cursor never moves on that page, and the read from 0 goes at once;
/// only that read ends the reset. The same when a `heads` announced the
/// rollback between the call and its answer.
#[test]
fn an_answer_whose_head_is_below_its_after_is_a_reset() {
    for heads_between in [false, true] {
        let mut rig = rig();
        let cover = rig.record(FEED, ControlAction::Cover);
        let hold = rig.record(FEED, ControlAction::Hold);
        let release = rig.record(FEED, ControlAction::Release);
        assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 0)]);
        rig.page(FEED, 3, &[(1, &cover), (2, &hold), (3, &release)]);
        rig.pass(SEC);
        assert_eq!(rig.heads(FEED, 4), [sync_call(FEED, 3)]);
        let a = rig.last();
        if heads_between {
            rig.pass(SEC);
            assert_eq!(rig.heads(FEED, 1), Vec::new(), "A live");
            assert_eq!(rig.mark_row().as_deref(), Some(""));
        }
        assert_eq!(
            rig.page_for(&a, FEED, 1, vec![(1, cover.object().to_json())]),
            Err(RelayError::Malformed("feed_seq")),
            "no record with a head below after"
        );
        let synced = rig.answer(&a, 1, &[]);
        assert!(synced.applied.is_empty());
        assert_eq!(synced.next, Some(sync_call(FEED, 0)), "the read from 0");
        assert_eq!(rig.mark_row().as_deref(), Some(""));
        assert_eq!(
            rig.cursor(),
            Some((FEED.to_string(), 3)),
            "never moved on it"
        );
        assert_eq!(rig.sync.closed(), Some(Closed::Reset));
        let b = rig.last();
        let synced = rig.answer(&b, 1, &[(1, &cover)]);
        assert_eq!(rig.cursor(), Some((FEED.to_string(), 1)));
        if !heads_between {
            // The announced target (4) is kept, never lowered by a page:
            // the read goes on toward it, and its mark stays until a
            // `heads` announces the rolled-back head and the feed is read
            // to it.
            assert_eq!(synced.next, Some(sync_call(FEED, 1)));
            let c = rig.last();
            rig.answer(&c, 1, &[]);
            assert_eq!(rig.mark_row().as_deref(), Some(FEED), "begun");
            assert_eq!(rig.sync.closed(), Some(Closed::Reset));
            assert!(!rig.open(&native()));
            rig.pass(SEC);
            assert_eq!(rig.heads(FEED, 1), Vec::new(), "the pause");
            assert_eq!(rig.pass(STALL_PAUSE_MS), [sync_call(FEED, 1)]);
            let d = rig.last();
            rig.answer(&d, 1, &[]);
        }
        assert_eq!(rig.mark_row(), None);
        assert!(rig.open(&native()), "heads between: {heads_between}");
    }
}

/// Ruling C1b-a (Astation's "mismatched echoes"): a page carrying the live
/// call's id that doesn't answer it (`ControlSyncResult::answers`: another
/// origin, feed or `after`) is a Station fault: nothing of it applies (its
/// records, head and time), the gate stays closed and the alert goes. The
/// call is retired (its id answered: a second page with it is drained) and
/// asked again after the pause, with a fresh id. (Another id: see
/// `an_unknown_id_is_an_unsolicited_station_fault` and the drained pages.)
#[test]
fn a_page_with_the_live_id_and_another_echo_is_a_station_fault() {
    for (field, code) in [
        ("origin", MISMATCHED_ORIGIN),
        ("feed_id", MISMATCHED_FEED),
        ("after", MISMATCHED_AFTER),
    ] {
        let mut rig = rig();
        rig.opened();
        rig.sync.take_lines();
        let release = rig.record(FEED, ControlAction::Release);
        rig.pass(SEC);
        assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
        let a = rig.last();
        let d = rig.d_ms();
        let mut page = rig
            .page_for(&a, FEED, 3, vec![(3, release.object().to_json())])
            .unwrap();
        match field {
            "origin" => page.origin = OTHER.into(),
            "feed_id" => page.feed_id = FEED_2.into(),
            _ => page.after = 1,
        }
        assert_eq!(page.answers(&a).map_err(|m| m.code()), Err(field));
        // Within the cap, ahead: it would raise the floor if it counted.
        page.station_time = rig.wall() + 5 * MIN;
        let synced = rig.on_page(Ok(page));
        assert!(synced.applied.is_empty(), "{field}");
        assert!(rig.feeds.standing(BOT).held, "{field}");
        assert_eq!(rig.cursor(), Some((FEED.to_string(), 2)), "{field}");
        assert!(rig.d_ms() < d + 2 * SEC, "{field}: the time didn't count");
        assert_eq!(rig.sync.closed(), Some(Closed::Fault(code)), "{field}");
        assert!(!rig.open(&native()));
        let lines = rig.sync.take_lines();
        assert_eq!(lines.len(), 1, "{field}: {lines:?}");
        assert!(lines[0].contains("doesn't answer its call"), "{}", lines[0]);
        assert_eq!(rig.sync.live_call(), None, "{field}: retired");
        // A second page with its id: drained.
        assert!(rig.answer(&a, 3, &[(3, &release)]).applied.is_empty());
        assert_eq!(rig.drained(), 1, "{field}");
        assert!(rig.feeds.standing(BOT).held, "{field}");
        // Asked again after the pause, with a fresh id: open with its page.
        assert_eq!(rig.pass(SEC), Vec::new(), "{field}: the pause");
        assert_eq!(rig.pass(STALL_PAUSE_MS), [sync_call(FEED, 2)], "{field}");
        let b = rig.last();
        assert_ne!(b.request_id, a.request_id);
        rig.answer(&b, 3, &[(3, &release)]);
        assert!(rig.open(&native()), "{field}");
    }
}

/// Ruling C1b-a: a page whose `request_id` the host never sent is
/// unsolicited: a Station fault (an hourly alert; nothing applied; the
/// gate closes, or stays closed). The live call stays live: its own page
/// still applies, but only a page asked after the fault ends it.
#[test]
fn an_unknown_id_is_an_unsolicited_station_fault() {
    let mut rig = rig();
    rig.opened();
    rig.sync.take_lines();
    let release = rig.record(FEED, ControlAction::Release);
    let stranger = |rig: &mut Rig| ControlSync {
        request_id: uuid::Uuid::new_v4().to_string(),
        ..rig.last()
    };
    // The gate open, nothing asked: closed by it.
    let unsolicited = stranger(&mut rig);
    let synced = rig.answer(&unsolicited, 3, &[(3, &release)]);
    assert!(synced.applied.is_empty());
    assert!(rig.feeds.standing(BOT).held);
    assert_eq!(rig.sync.closed(), Some(Closed::Fault(UNSOLICITED)));
    assert!(!rig.open(&native()));
    assert_eq!(rig.sync.dump()["unsolicited"], 1);
    assert_eq!(rig.drained(), 0);
    let lines = rig.sync.take_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    // Asked again after the pause; another unsolicited page meanwhile.
    assert_eq!(rig.pass(STALL_PAUSE_MS), [sync_call(FEED, 2)]);
    let a = rig.last();
    let unsolicited = stranger(&mut rig);
    assert!(
        rig.answer(&unsolicited, 3, &[(3, &release)])
            .applied
            .is_empty()
    );
    assert_eq!(rig.sync.dump()["unsolicited"], 2);
    assert_eq!(
        rig.sync.live_call().map(|c| c.request_id),
        Some(a.request_id.clone()),
        "the live call stays"
    );
    // Its page applies, but ends no fault: it was asked before it.
    let synced = rig.answer(&a, 3, &[(3, &release)]);
    assert_eq!(synced.applied.len(), 1);
    assert!(!rig.feeds.standing(BOT).held);
    assert_eq!(rig.sync.closed(), Some(Closed::Fault(UNSOLICITED)));
    // A page asked after it (at once: that page moved the cursor): open.
    assert_eq!(synced.next, Some(sync_call(FEED, 3)));
    let b = rig.last();
    rig.answer(&b, 3, &[]);
    assert!(rig.open(&native()));
}

/// Ruling C1b-a (Astation's "late refusal"): a refusal names a call kind,
/// never a request, so a `control_sync_refused` retires whatever sync call
/// is live, even one asked after the call it was meant for. That costs
/// liveness only: the live call's page, arriving after, is drained; the
/// gate stays closed through the backoff, and a call asked after it, with
/// a fresh id, opens it.
#[test]
fn a_late_refusal_retires_the_live_call_and_costs_liveness_only() {
    let mut rig = rig();
    rig.opened();
    let release = rig.record(FEED, ControlAction::Release);
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
    // A unanswered for 30 s: retired; B asked.
    assert_eq!(rig.pass(SYNC_TIMEOUT_MS), [sync_call(FEED, 2)]);
    let b = rig.last();
    // A's refusal, late: it retires B.
    rig.sync.on_refused(RefusedCall::ControlSync);
    assert_eq!(rig.sync.live_call(), None);
    assert_eq!(rig.sync.closed(), Some(Closed::Refused));
    // B's page: drained.
    assert!(rig.answer(&b, 3, &[(3, &release)]).applied.is_empty());
    assert!(rig.feeds.standing(BOT).held);
    assert_eq!(rig.drained(), 1);
    assert_eq!(rig.sync.closed(), Some(Closed::Refused));
    // Past the backoff, at a heads: a fresh call; read, open.
    rig.pass(REFUSAL_BACKOFF_MS);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
    let c = rig.last();
    assert_ne!(c.request_id, b.request_id);
    rig.answer(&c, 3, &[(3, &release)]);
    assert!(!rig.feeds.standing(BOT).held);
    assert!(rig.open(&native()));
}

/// Ruling C1b-a: a page answering the live call applies only under the
/// account and genesis the call was asked under (the feeds it was asked
/// against): handed to the feeds of another device list (a re-pin the
/// pass hasn't moved the store aside for), it is drained, nothing applied.
#[test]
fn a_page_asked_under_another_device_list_applies_nothing() {
    let mut rig = rig();
    rig.opened();
    let release = rig.record(FEED, ControlAction::Release);
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
    let a = rig.last();
    // Another account's list and its feeds, in another store.
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(dir.path()).unwrap();
    store.bind(&host()).unwrap();
    let mut other = TestLog::genesis("acct-other", &secret("other astation"));
    other.add_host("host", 1, &secret("other host"));
    let mut feeds = FeedStore::load(&store, &other.log).unwrap();
    feeds.set_own_origin(Some(ORIGIN.into()));
    let page = rig.page_for(&a, FEED, 3, vec![(3, release.object().to_json())]);
    let list = serving(&other);
    let synced = rig
        .sync
        .on_page(
            page,
            None,
            Some(PageCx {
                store: &store,
                feeds: &mut feeds,
                list: &list,
                applied_seq: 0,
            }),
        )
        .unwrap();
    assert!(synced.applied.is_empty());
    assert_eq!(
        feeds.current_feed(ORIGIN),
        None,
        "nothing in the other store"
    );
    assert_eq!(feeds.evidence_count(), 0);
    assert_eq!(rig.drained(), 1);
    assert_eq!(rig.sync.dump()["faults"], 0);
    assert_eq!(rig.sync.live_call(), None);
    assert!(rig.feeds.standing(BOT).held);
}

/// Ruling C1b-a: what a page carrying the live call's id is to that call.
/// A discovery call (no `feed_id`, `after: 0`; this host never makes one,
/// it names the announced feed) is answered only on the own feed this
/// generation's `heads` announced; a named call by the shared helper's
/// rules; a call captured on another link generation or socket, or under
/// another account or genesis, is stale (its page drained).
#[test]
fn a_page_answers_the_live_call_only_as_it_was_captured() {
    let rig = rig();
    let list_id = rig.feeds.list_id().clone();
    let discovery = ControlSync {
        request_id: "5d0e9a3c-2b1f-4c8d-9e7a-6b5c4d3e2f10".into(),
        origin: ORIGIN.into(),
        feed_id: None,
        after: 0,
    };
    let ask = |call: &ControlSync| Ask {
        call: call.clone(),
        link_gen: 1,
        socket: SOCKET,
        list: list_id.clone(),
        sent_at: 0,
        restart: true,
        epoch: 0,
        named: 0,
    };
    let here = Some((1, SOCKET));
    let page = rig.page_for(&discovery, FEED, 0, vec![]).unwrap();
    let d = ask(&discovery);
    assert_eq!(
        d.judge(&page, here, Some(&list_id), Some(FEED)),
        Verdict::Answers
    );
    for announced in [Some(FEED_2), None] {
        assert_eq!(
            d.judge(&page, here, Some(&list_id), announced),
            Verdict::Fault(MISMATCHED_FEED),
            "{announced:?}"
        );
    }
    // A named call: the helper's rules, whatever the announcement.
    let named = ControlSync {
        feed_id: Some(FEED.into()),
        ..discovery.clone()
    };
    let n = ask(&named);
    assert_eq!(
        n.judge(&page, here, Some(&list_id), Some(FEED_2)),
        Verdict::Answers
    );
    let mut elsewhere = page.clone();
    elsewhere.feed_id = FEED_2.into();
    assert_eq!(
        n.judge(&elsewhere, here, Some(&list_id), Some(FEED_2)),
        Verdict::Fault(MISMATCHED_FEED)
    );
    let mut later = page.clone();
    later.after = 1;
    later.head = 1;
    assert_eq!(
        n.judge(&later, here, Some(&list_id), Some(FEED)),
        Verdict::Fault(MISMATCHED_AFTER)
    );
    // Captured elsewhere: stale.
    let other_account = ("acct-other".to_string(), list_id.1);
    let other_genesis = (list_id.0.clone(), atem_client::encoding::Hash32([9; 32]));
    for (link, list) in [
        (Some((2, SOCKET)), &list_id),
        (Some((1, SOCKET + 1)), &list_id),
        (None, &list_id),
        (here, &other_account),
        (here, &other_genesis),
    ] {
        assert_eq!(
            n.judge(&page, link, Some(list), Some(FEED)),
            Verdict::Stale,
            "{link:?} {list:?}"
        );
    }
}

/// Ruling C1b-a: the link dropping ends its generation: the live call is
/// retired at once (no call is timed while no link is up), and back on a
/// link, the same socket or another, its page is drained; the new
/// generation's own call, with a fresh id, opens the gate once read.
#[test]
fn a_link_that_drops_retires_the_live_call() {
    for socket in [SOCKET, SOCKET + 1] {
        let mut rig = rig();
        rig.opened();
        let release = rig.record(FEED, ControlAction::Release);
        rig.pass(SEC);
        assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
        let a = rig.last();
        rig.sync.on_link(None);
        assert_eq!(rig.sync.live_call(), None);
        rig.sync.take_lines();
        assert_eq!(rig.pass(SYNC_TIMEOUT_MS), Vec::new());
        assert_eq!(rig.sync.closed(), Some(Closed::NoLink));
        assert!(rig.sync.take_lines().is_empty(), "nothing timed while down");
        rig.sync.on_link(Some(&link_on(2, socket, ORIGIN)));
        assert_eq!(rig.sync.closed(), Some(Closed::NoHeads));
        // A's page: drained.
        assert!(rig.answer(&a, 3, &[(3, &release)]).applied.is_empty());
        assert_eq!(rig.drained(), 1, "socket {socket}");
        assert!(rig.feeds.standing(BOT).held);
        // Its own call, answered.
        rig.pass(SEC);
        assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
        let b = rig.last();
        assert_ne!(a.request_id, b.request_id);
        rig.answer(&b, 3, &[(3, &release)]);
        assert!(!rig.feeds.standing(BOT).held);
        assert!(rig.open(&native()), "socket {socket}");
    }
}

/// Wire rule 11, ruling C1b-a: a page holding a record at or below its own
/// `after` doesn't read (the reader refuses it, `malformed`): a Station
/// fault, nothing of it applies, the gate stays closed and the alert goes.
/// It can't be matched to a call, so it is taken as the live call's answer
/// (the call is retired: its own page, should it still come, is drained),
/// and the feed is asked again after the pause.
#[test]
fn a_page_with_a_record_at_or_below_its_own_after_doesnt_read() {
    let mut rig = rig();
    let (_, hold) = rig.opened();
    rig.sync.take_lines();
    let release = rig.record(FEED, ControlAction::Release);
    let revoke = rig.record(
        FEED,
        ControlAction::Revoke {
            interrupt_running: false,
        },
    );
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 4), [sync_call(FEED, 2)]);
    let a = rig.last();
    let page = rig.page_for(
        &a,
        FEED,
        4,
        vec![
            (2, hold.object().to_json()),
            (3, release.object().to_json()),
        ],
    );
    assert_eq!(page, Err(RelayError::Malformed("feed_seq")));
    let synced = rig.on_page(page);
    assert!(synced.applied.is_empty() && synced.next.is_none());
    assert!(rig.feeds.standing(BOT).held);
    assert_eq!(rig.cursor(), Some((FEED.to_string(), 2)));
    assert_eq!(rig.sync.closed(), Some(Closed::Fault("malformed")));
    assert!(!rig.open(&native()));
    assert_eq!(rig.sync.take_lines().len(), 1);
    assert_eq!(rig.sync.live_call(), None, "retired");
    // A's own page, late: drained.
    assert!(
        rig.answer(&a, 4, &[(3, &release), (4, &revoke)])
            .applied
            .is_empty()
    );
    assert_eq!(rig.drained(), 1);
    // Asked again after the pause: read, open.
    assert_eq!(rig.pass(STALL_PAUSE_MS), [sync_call(FEED, 2)]);
    let b = rig.last();
    rig.answer(&b, 4, &[(3, &release), (4, &revoke)]);
    assert!(rig.feeds.standing(BOT).revoked.is_some());
    assert!(rig.open(&native()));
}

/// Wire rule 11 (Astation, #164: a stale named feed is refused, never
/// answered on the new feed): a page answering the live call on another
/// feed than it named doesn't answer it, a Station fault, nothing of it
/// applied. The next `heads` announcing the new feed reads it from 0 (a
/// reset, at once once its mark is written), which ends both.
#[test]
fn a_page_of_another_feed_than_asked_is_a_station_fault() {
    let mut rig = rig();
    rig.opened();
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
    let cover = rig.record(FEED_2, ControlAction::Cover);
    // The call's id, the new feed from 0.
    let live = rig.last();
    let page = rig.page_for(
        &ControlSync { after: 0, ..live },
        FEED_2,
        1,
        vec![(1, cover.object().to_json())],
    );
    let synced = rig.on_page(page);
    assert!(synced.applied.is_empty());
    assert_eq!(rig.sync.closed(), Some(Closed::Fault(MISMATCHED_FEED)));
    assert_eq!(rig.cursor(), Some((FEED.to_string(), 2)));
    rig.pass(SEC);
    assert_eq!(
        rig.heads(FEED_2, 1),
        [sync_call(FEED_2, 0)],
        "a reset, read at once"
    );
    let b = rig.last();
    rig.answer(&b, 1, &[(1, &cover)]);
    assert!(rig.open(&native()));
    assert_eq!(rig.cursor(), Some((FEED_2.to_string(), 1)));
}

/// Astation (#164, "Restore/reset"): a rescan from 0 never erases committed
/// holds or revokes merely because a replacement page omits them. The feed
/// went back under the same id and regrew without the earlier hold and
/// revoke: read from 0 to its head (the reset done), the bot stays held
/// and revoked.
#[test]
fn a_rescan_keeps_the_committed_stops_a_regrown_feed_omits() {
    let mut rig = rig();
    let (cover, _) = rig.opened();
    let revoke = rig.record(
        FEED,
        ControlAction::Revoke {
            interrupt_running: false,
        },
    );
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
    rig.page(FEED, 3, &[(3, &revoke)]);
    let standing = rig.feeds.standing(BOT);
    assert!(standing.held && standing.revoked.is_some());
    // Rolled back to 1, announced: read from 0, which finds it regrown to
    // 4 with covers only.
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 1), [sync_call(FEED, 0)]);
    let b = rig.last();
    let c2 = rig.record(FEED, ControlAction::Cover);
    let c3 = rig.record(FEED, ControlAction::Cover);
    let c4 = rig.record(FEED, ControlAction::Cover);
    rig.answer(&b, 4, &[(1, &cover), (2, &c2), (3, &c3), (4, &c4)]);
    assert_eq!(rig.cursor(), Some((FEED.to_string(), 4)));
    assert_eq!(rig.mark_row(), None, "the reset done");
    assert!(rig.open(&native()));
    let standing = rig.feeds.standing(BOT);
    assert!(standing.held, "the hold kept");
    assert!(standing.revoked.is_some(), "the revoke kept");
}

// ------------------------------------------------- C1b fix round 1 (C1b-b)

/// Ruling C1b-b, m1 (the review's probe): `atem status` says a call went
/// unanswered and was asked again only while that retry is live. A `heads`
/// lowers the announced head to the cursor under the same `feed_id` (no
/// reset: not below the cursor) while a call is live; the call times out,
/// is retired, and nothing is left to ask: no "asked again", and the gate
/// isn't held closed for the rest of the generation.
#[test]
fn a_timeout_with_nothing_left_to_ask_neither_says_asked_again_nor_holds_the_gate() {
    let mut rig = rig();
    rig.opened();
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)], "A");
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 2), Vec::new(), "A live; no reset");
    // A unanswered: retired, nothing asked.
    assert_eq!(rig.pass(SYNC_TIMEOUT_MS - SEC), Vec::new());
    assert_eq!(rig.sync.live_call(), None, "retired");
    assert_eq!(rig.sync.dump()["timeouts"], 1);
    assert_eq!(rig.sync.dump()["unanswered"], false, "no retry asked");
    assert_ne!(rig.sync.closed(), Some(Closed::Unanswered));
    assert_eq!(rig.sync.closed(), None, "read to the announced head");
    assert!(rig.open(&native()));
    let lines = rig.sync.take_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(!lines[0].contains("asked again"), "{}", lines[0]);
    // Later `heads`: still open.
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 2), Vec::new());
    assert!(rig.open(&native()));
}

/// Ruling C1b-b, m1: after a refusal the retry of a call that timed out
/// waits for a `heads` past the backoff; meanwhile nothing says it was
/// asked again, and once it is, `atem status` says so until its page.
#[test]
fn unanswered_is_said_only_while_the_retry_is_live() {
    let mut rig = rig();
    rig.opened();
    let release = rig.record(FEED, ControlAction::Release);
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
    rig.sync.on_refused(RefusedCall::MembershipFetch);
    // A times out in the refusal's backoff: retired, not asked again.
    assert_eq!(rig.pass(SYNC_TIMEOUT_MS), Vec::new());
    assert_eq!(rig.sync.live_call(), None);
    assert_eq!(rig.sync.closed(), Some(Closed::Refused));
    // Past the backoff, at a heads: asked (no "asked again" for a call the
    // refusal's resynchronization asks).
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
    assert_eq!(rig.sync.dump()["unanswered"], false);
    let b = rig.last();
    rig.answer(&b, 3, &[(3, &release)]);
    assert!(rig.open(&native()));
    // A timeout whose retry goes at once: said while it is live.
    let hold = rig.record(FEED, ControlAction::Hold);
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 4), [sync_call(FEED, 3)]);
    assert_eq!(rig.pass(SYNC_TIMEOUT_MS), [sync_call(FEED, 3)]);
    assert_eq!(rig.sync.closed(), Some(Closed::Unanswered));
    let c = rig.last();
    rig.answer(&c, 4, &[(4, &hold)]);
    assert_eq!(rig.sync.closed(), None);
    // A retry the link didn't take: no longer said once it isn't live.
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 5), [sync_call(FEED, 4)]);
    assert_eq!(rig.pass(SYNC_TIMEOUT_MS), [sync_call(FEED, 4)]);
    assert_eq!(rig.sync.closed(), Some(Closed::Unanswered));
    let d = rig.last();
    rig.sync.unsent(&d.request_id);
    assert_eq!(
        rig.sync.closed(),
        Some(Closed::Behind {
            cursor: Some(4),
            head: 5
        })
    );
}

/// Ruling C1b-b, m2: a call that couldn't be handed to the link is dropped
/// by its id: a newer live call stays live. A call retired in the pass
/// that asked it (here by a page the reader refused, the reset found next
/// letting the read from 0 go) is never sent: the pass's calls go only
/// while they are the live call, and the retired one leaves the retired
/// ids (never sent: a page naming it is unsolicited).
#[test]
fn an_unsent_call_is_dropped_by_its_id_and_a_retired_one_never_goes() {
    let mut rig = rig();
    rig.opened();
    rig.pass(SEC);
    // One pass: A asked; a page the reader refuses retires A; a rollback
    // found lets B (the read from 0) go.
    let mut calls = rig.heads(FEED, 3);
    let a = rig.last();
    rig.on_page(Err(RelayError::NotStrict));
    calls.extend(rig.heads(FEED, 1));
    let b = rig.last();
    assert_eq!(calls, [sync_call(FEED, 2), sync_call(FEED, 0)]);
    assert_ne!(a.request_id, b.request_id);
    // Only B goes.
    let sending = rig.sync.outgoing(vec![a.clone(), b.clone()]);
    assert_eq!(sending, [b.clone()]);
    // A failed send of A (had it gone) leaves B live.
    rig.sync.unsent(&a.request_id);
    assert_eq!(rig.sync.live_call(), Some(b.clone()));
    // A's id never went: a page naming it is unsolicited.
    let faults = rig.sync.dump()["faults"].as_u64().unwrap();
    rig.answer(&a, 3, &[]);
    assert_eq!(rig.sync.dump()["unsolicited"], 1);
    assert_eq!(rig.drained(), 0);
    assert_eq!(rig.sync.dump()["faults"], faults + 1);
    // B's own failed send: none live.
    rig.sync.unsent(&b.request_id);
    assert_eq!(rig.sync.live_call(), None);
}

/// Ruling C1b-b, m3: the host keeps the latest 256 retired ids. A page
/// naming the oldest one kept is drained; one naming an id older than
/// those reads as unsolicited, a Station fault (fail closed).
#[test]
fn the_latest_256_retired_ids_are_kept_and_an_older_one_is_unsolicited() {
    let mut rig = rig();
    rig.opened();
    // 257 calls, each retired by the next link generation.
    let mut ids = Vec::new();
    for link_gen in 2..=258 {
        rig.pass(SEC);
        assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)], "{link_gen}");
        ids.push(rig.last());
        rig.sync.on_link(Some(&link(link_gen, ORIGIN)));
    }
    // With `opened`'s call, 258 retired: the latest 256 kept.
    assert_eq!(rig.sync.dump()["retired"], 256);
    rig.answer(&ids[1], 3, &[]);
    assert_eq!(rig.drained(), 1, "the oldest kept");
    assert_eq!(rig.sync.dump()["faults"], 0);
    rig.answer(&ids[0], 3, &[]);
    assert_eq!(rig.sync.dump()["unsolicited"], 1, "evicted");
    assert_eq!(rig.sync.closed(), Some(Closed::Fault(UNSOLICITED)));
}

/// Ruling C1b-b, m6: the host's deadline is 35 s, a 5 s grace over the
/// Station's agreed 30 s (Atem-internal, §11.4): a page that comes at 34 s
/// answers its call; at 35 s the call is retired.
#[test]
fn the_hosts_deadline_is_the_stations_30_s_and_a_5_s_grace() {
    assert_eq!(SYNC_TIMEOUT_MS, 35_000);
    let mut rig = rig();
    rig.opened();
    let release = rig.record(FEED, ControlAction::Release);
    let hold = rig.record(FEED, ControlAction::Hold);
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
    let a = rig.last();
    assert_eq!(rig.pass(34 * SEC), Vec::new(), "not retired at 34 s");
    assert_eq!(rig.sync.live_call(), Some(a.clone()));
    rig.answer(&a, 3, &[(3, &release)]);
    assert!(!rig.feeds.standing(BOT).held);
    assert_eq!(rig.drained(), 0);
    // The next call: retired at 35 s.
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 4), [sync_call(FEED, 3)]);
    assert_eq!(rig.pass(35 * SEC - 1), Vec::new());
    assert_eq!(rig.pass(1), [sync_call(FEED, 3)], "retired, asked again");
    let b = rig.last();
    rig.answer(&b, 4, &[(4, &hold)]);
    assert!(rig.open(&native()));
}

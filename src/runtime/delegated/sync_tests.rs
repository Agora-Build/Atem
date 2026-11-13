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
/// moved nothing. (One unanswered for 30 s is never asked again: see
/// `an_unanswered_sync_waits_for_its_answer_or_a_new_socket`.)
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
    // The call's id, the new feed from 0.
    let live = rig.sync.live_call().unwrap();
    let page = rig.page_for(
        &ControlSync { after: 0, ..live },
        FEED_2,
        1,
        vec![(1, cover.object().to_json())],
    );
    let synced = rig.on_page(page);
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

/// Task 33 review m5: a page that names another origin than the host's own
/// Station's is a Station fault (nothing applies, the gate closes); a page
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
    assert_eq!(rig.sync.closed(), Some(Closed::Fault("another_origin")));
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

/// Ruling T33d, T33e (matching after a timeout): a page carries no echo of
/// its call, so after a `control_sync` unanswered for 30 s nothing more is
/// asked on its socket (a re-send could bring two answers): the gate stays
/// closed, the Station-fault alert goes, and `atem status` names the way
/// out. A new link generation on the same socket still waits for that
/// answer; only a new socket, where it can't come, syncs afresh, its gate
/// opening only after a full read.
#[test]
fn an_unanswered_sync_waits_for_its_answer_or_a_new_socket() {
    let mut rig = rig();
    rig.opened();
    rig.sync.take_lines();
    let release = rig.record(FEED, ControlAction::Release);
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
    assert_eq!(rig.pass(SYNC_TIMEOUT_MS - 1), Vec::new());
    assert_eq!(rig.pass(1), Vec::new(), "no re-ask");
    assert_eq!(rig.sync.closed(), Some(Closed::Unanswered));
    assert!(
        Closed::Unanswered.text().contains("`atem runtime restart`"),
        "{}",
        Closed::Unanswered.text()
    );
    assert!(!rig.open(&native()));
    let lines = rig.sync.take_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("unanswered"), "{}", lines[0]);
    assert_eq!(rig.heads(FEED, 3), Vec::new());
    assert_eq!(rig.pass(STALL_PAUSE_MS), Vec::new());
    // A new link generation on the same socket: still waiting.
    rig.sync.on_link(Some(&link(2, ORIGIN)));
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), Vec::new(), "the same socket");
    assert_eq!(rig.sync.closed(), Some(Closed::Unanswered));
    assert_eq!(rig.cursor(), Some((FEED.to_string(), 2)));
    // A new socket: synced again, open only once read.
    rig.sync.on_link(Some(&link_on(3, 2, ORIGIN)));
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
    assert!(!rig.open(&native()));
    rig.page(FEED, 3, &[(3, &release)]);
    assert!(!rig.feeds.standing(BOT).held);
    assert!(rig.open(&native()));
}

/// Ruling T33e: after a timeout nothing is asked again on its socket, so a
/// late page there can only be the timed-out call's: it is taken as that
/// call's answer (its own `after`), and the sync resumes, on the same link
/// generation or on a later one on the same socket.
#[test]
fn a_late_answer_on_the_same_socket_resumes_the_sync() {
    let mut rig = rig();
    rig.opened();
    let release = rig.record(FEED, ControlAction::Release);
    let hold = rig.record(FEED, ControlAction::Hold);
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
    assert_eq!(rig.pass(SYNC_TIMEOUT_MS), Vec::new());
    assert_eq!(rig.sync.closed(), Some(Closed::Unanswered));
    assert_eq!(rig.heads(FEED, 3), Vec::new(), "nothing asked again");
    // The late answer: the timed-out call's.
    let synced = rig.page(FEED, 3, &[(3, &release)]);
    assert_eq!(synced.applied.len(), 1);
    assert!(!rig.feeds.standing(BOT).held);
    assert_eq!(rig.sync.closed(), None);
    assert!(rig.open(&native()));
    // Again, with a new link generation on the same socket in between: the
    // call still owed there, its late answer resumes the sync.
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 4), [sync_call(FEED, 3)]);
    assert_eq!(rig.pass(SYNC_TIMEOUT_MS), Vec::new());
    rig.sync.on_link(Some(&link(2, ORIGIN)));
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 4), Vec::new());
    assert_eq!(rig.sync.closed(), Some(Closed::Unanswered));
    let synced = rig.page(FEED, 4, &[(4, &hold)]);
    assert_eq!(synced.applied.len(), 1);
    assert!(rig.feeds.standing(BOT).held);
    assert!(rig.open(&native()));
    // And on: the next call goes as usual.
    let release_2 = rig.record(FEED, ControlAction::Release);
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 5), [sync_call(FEED, 4)]);
    rig.page(FEED, 5, &[(5, &release_2)]);
    assert!(rig.open(&native()));
}

/// Ruling T33e (b): a new socket drops the owed call (its answer can't
/// come on it), and a page arriving on it is matched only to a call asked
/// on it: one before any is unasked and applies nothing. While the link is
/// down the owed call isn't timed (its socket may come back); back on the
/// same socket its 30 s are judged at once, and the sync waits for its
/// answer or a new socket.
#[test]
fn a_new_socket_drops_the_owed_call() {
    let mut rig = rig();
    rig.opened();
    let release = rig.record(FEED, ControlAction::Release);
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
    // The link down (a re-authentication over the open socket) past 30 s.
    rig.sync.on_link(None);
    rig.sync.take_lines();
    assert_eq!(rig.pass(SYNC_TIMEOUT_MS), Vec::new());
    assert_eq!(rig.sync.closed(), Some(Closed::NoLink));
    assert!(rig.sync.take_lines().is_empty(), "not timed while down");
    // Back on the same socket: still owed, and unanswered past 30 s.
    rig.sync.on_link(Some(&link(2, ORIGIN)));
    assert_eq!(rig.pass(SEC), Vec::new());
    assert_eq!(rig.sync.closed(), Some(Closed::Unanswered));
    assert_eq!(rig.sync.take_lines().len(), 1);
    assert_eq!(rig.heads(FEED, 3), Vec::new());
    // A new socket: the owed call dropped.
    rig.sync.on_link(None);
    rig.sync.on_link(Some(&link_on(3, 2, ORIGIN)));
    assert_eq!(rig.sync.closed(), Some(Closed::NoHeads));
    // A page before any call on it: unasked, nothing applied.
    let synced = rig.page(FEED, 3, &[(3, &release)]);
    assert!(synced.applied.is_empty());
    assert!(rig.feeds.standing(BOT).held);
    assert_eq!(rig.cursor(), Some((FEED.to_string(), 2)));
    // Its own call, answered.
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 2)]);
    rig.page(FEED, 3, &[(3, &release)]);
    assert!(!rig.feeds.standing(BOT).held);
    assert!(rig.open(&native()));
}

/// Ruling T33e (a): a page carries "the records after `after`" (§11.4), so
/// one holding a record at or below its call's `after` contradicts its
/// call: a Station fault. Nothing of it applies (not even its records past
/// `after`), the cursor stays, the gate stays closed and the Station-fault
/// alert goes; it is asked again after the pause, and a page that reads
/// opens the gate.
#[test]
fn a_page_with_a_record_at_or_below_its_after_is_a_station_fault() {
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
    // Another call's page (its own `after` 1; one holding a record at or
    // below its own `after` doesn't read at all, wire rule 11): only a
    // record at 2, it would read as "no record after the cursor".
    let other = |rig: &Rig| ControlSync {
        after: 1,
        ..rig.sync.live_call().unwrap()
    };
    let page = rig.page_for(&other(&rig), FEED, 4, vec![(2, hold.object().to_json())]);
    let synced = rig.on_page(page);
    assert!(synced.applied.is_empty() && synced.next.is_none());
    assert_eq!(rig.cursor(), Some((FEED.to_string(), 2)));
    assert_eq!(rig.sync.closed(), Some(Closed::Fault(CONTRADICTS_CALL)));
    assert!(!rig.open(&native()));
    let lines = rig.sync.take_lines();
    assert_eq!(lines.len(), 1, "{lines:?}");
    assert!(lines[0].contains("contradicts its call"), "{}", lines[0]);
    // Asked again after the pause: records at and after 2, a fault too.
    assert_eq!(rig.pass(STALL_PAUSE_MS), [sync_call(FEED, 2)]);
    let records = [(2, &hold), (3, &release), (4, &revoke)]
        .iter()
        .map(|(n, r)| (*n, r.object().to_json()))
        .collect();
    let page = rig.page_for(&other(&rig), FEED, 4, records);
    let synced = rig.on_page(page);
    assert!(synced.applied.is_empty());
    assert!(rig.feeds.standing(BOT).held, "the release not applied");
    assert_eq!(rig.cursor(), Some((FEED.to_string(), 2)));
    assert!(!rig.open(&native()));
    // The page as asked: read, the gate open.
    rig.pass(STALL_PAUSE_MS);
    assert_eq!(rig.heads(FEED, 4), [sync_call(FEED, 2)]);
    rig.page(FEED, 4, &[(3, &release), (4, &revoke)]);
    assert!(rig.feeds.standing(BOT).revoked.is_some());
    assert!(rig.open(&native()));
}

/// Task 33 re-review 3, R3-1, probe F (ruling T33e (b)): a new link
/// generation on the same socket (Astation re-authenticating it, a routed
/// link's upgrade) keeps the owed call, since the Station still answers it
/// on that socket: the new generation asks nothing until its answer comes,
/// taken with its own `after`. Before, with truncated pages, the old call's
/// page was taken for a new call and the new call's for the continuation,
/// and a revoke was read past. A page taken for a call it contradicts (the
/// same page again) is a Station fault (a), and the revoke is read next.
#[test]
fn a_new_generation_on_the_same_socket_keeps_the_owed_call() {
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
    let a_call = rig.asked.last().unwrap().clone();
    // A new generation on the same socket: A's answer still owed on it.
    rig.sync.on_link(Some(&link(2, ORIGIN)));
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 6), Vec::new(), "A owed: nothing asked");
    assert!(!rig.open(&native()));
    // A's page, truncated at 4: A's answer; C asked at once.
    let a = rig.page(FEED, 6, &[(3, &r3), (4, &r4)]);
    assert_eq!(a.applied.len(), 2);
    assert_eq!(a.next, Some(sync_call(FEED, 4)), "C");
    // The same page again (A's), taken for C: it contradicts C, a fault.
    rig.sync.take_lines();
    let records = [(3, &r3), (4, &r4)]
        .iter()
        .map(|(n, r)| (*n, r.object().to_json()))
        .collect();
    let page = rig.page_for(&a_call, FEED, 6, records);
    let stale = rig.on_page(page);
    assert!(stale.applied.is_empty());
    assert_eq!(rig.cursor(), Some((FEED.to_string(), 4)));
    assert_eq!(rig.sync.closed(), Some(Closed::Fault(CONTRADICTS_CALL)));
    assert_eq!(rig.sync.take_lines().len(), 1);
    assert!(rig.feeds.standing(BOT).revoked.is_none());
    assert!(!rig.open(&native()));
    // Asked again after the pause: the revoke read, then the gate opens.
    assert_eq!(rig.pass(STALL_PAUSE_MS), [sync_call(FEED, 4)]);
    rig.page(FEED, 6, &[(5, &revoke), (6, &r6)]);
    assert!(rig.feeds.standing(BOT).revoked.is_some());
    assert_eq!(rig.cursor(), Some((FEED.to_string(), 6)));
    assert!(rig.open(&native()));
}

/// Task 33 re-review 3, R3-1, probe G (ruling T33e (b)): the same with a
/// rollback under the same `feed_id` found on the new generation. The owed
/// continuation keeps its own `after` and kind, so its page (the feed
/// regrown) applies as the continuation it is and ends no reset: the read
/// from 0 is asked once it is answered, and only that read ends the reset.
#[test]
fn an_owed_continuation_never_ends_a_reset_found_on_the_next_generation() {
    let mut rig = rig();
    let cover = rig.record(FEED, ControlAction::Cover);
    let hold = rig.record(FEED, ControlAction::Hold);
    let release = rig.record(FEED, ControlAction::Release);
    assert_eq!(rig.heads(FEED, 3), [sync_call(FEED, 0)]);
    rig.page(FEED, 3, &[(1, &cover), (2, &hold), (3, &release)]);
    rig.pass(SEC);
    assert_eq!(rig.heads(FEED, 4), [sync_call(FEED, 3)], "A");
    rig.sync.on_link(Some(&link(2, ORIGIN)));
    rig.pass(SEC);
    // The rollback on the new generation: marked, nothing asked (A owed).
    assert_eq!(rig.heads(FEED, 1), Vec::new());
    assert_eq!(rig.mark_row().as_deref(), Some(""));
    assert_eq!(rig.sync.closed(), Some(Closed::Reset));
    // A's answer, the feed regrown to 5: the continuation it is.
    let x = rig.record(FEED, ControlAction::Hold);
    let y = rig.record(FEED, ControlAction::Release);
    let synced = rig.page(FEED, 5, &[(4, &x), (5, &y)]);
    assert_eq!(synced.applied.len(), 2);
    assert_eq!(rig.mark_row().as_deref(), Some(""), "the mark stays");
    assert_eq!(rig.sync.closed(), Some(Closed::Reset));
    assert!(!rig.open(&native()));
    assert_eq!(synced.next, Some(sync_call(FEED, 0)), "the read from 0");
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

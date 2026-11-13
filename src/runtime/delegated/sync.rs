//! The host's sync of its own Station's control feed and the feed part of
//! the revocation gate (the delegated host-work design I.5.2, I.5.8, I.6.5;
//! host-work-v1 §11.4 "Heads, resets and the gate"; step 4's Decisions 12,
//! 14, 16 and 20). Only with `host.delegated` on (Decision 11), on the
//! host's Station link ([`super::station`]); records apply through the feed
//! store ([`FeedStore`], I.5.5).
//!
//! - **One origin.** The host syncs only the feed of its own Station (the
//!   link's origin, Decision 14). A `heads` feed of another origin is
//!   ignored, counted and alerted (hourly); its gate is never opened. The
//!   own origin's `heads` must name exactly one feed ("One feed per
//!   account", §11.4): none, or more than one, keeps the gate closed.
//! - **Heads** (I.5.8). Each `heads` refreshes the 60-second window
//!   (measured on the larger of the monotonic and the boot-time elapsed
//!   times, [`Clocks`]: a suspend counts, I.6.5) and announces the feed's
//!   head. Its `station_time` goes through the
//!   delegated clock's cap ([`HostClock::station_time`], I.6.5): one beyond
//!   `H` + 10 minutes (or one the clock couldn't record) moves no floor and
//!   closes the origin's gate until a `heads` within the cap; a page's
//!   `station_time` is taken the same way (I.6.5: both carry it), and one
//!   beyond the cap closes the gate too.
//! - **Resets** (I.5.2, §11.4). The announced feed isn't the one the host
//!   read (an unknown `feed_id` for a known origin), or its head is below
//!   the host's cursor (the feed rolled back under the same id), or a page
//!   names a head below the cursor: a reset, wherever it is found (at a
//!   `heads`, a page, or when the feeds load). The gate stays closed until
//!   the feed is read again from position 0, and that read's first page
//!   replaces the origin's old cursor in its own transaction
//!   ([`FeedStore::restart`]), only then. A reset is marked durably in the
//!   feed store before anything is asked for it ([`FeedSync::persist_mark`],
//!   the bridge's step after every call), and only the commit that reads
//!   the feed from 0 up to the announced head clears the mark: a start
//!   finds it and reads from 0 again, or goes on with a read from 0 that
//!   began (ruling T33c). Only a page read to its end ends a reset (or a
//!   refusal's, a fault's or the recovery's resynchronization): one that
//!   applied nothing, as with no own Station to place it at, ends none
//!   ([`Synced::read`]). A feed the host never read is read from 0 too (no
//!   reset counted, no mark).
//! - **Only the announced feed is synced.** `control_sync` names the feed
//!   the last `heads` announced, and a page applies only as the answer to
//!   the live call (see "Matching"): positions come only from that page's
//!   own feed.
//! - **Pages** (§11.4). A page the reader refused as a whole (not strict
//!   JSON, or out of its grammar) is a Station fault: nothing applies, the
//!   cursor stays, the gate stays closed until a page that reads, and an
//!   owner alert goes to `runtime.log` (one an hour per kind, Decision 12).
//!   A record that doesn't parse is evidence ([`FeedStore::unparsed`]) and
//!   the page stands: delivery progress, never application evidence. Each
//!   page is one `BEGIN IMMEDIATE` transaction ([`FeedStore::begin`]): its
//!   records in order, the pending records re-verified after a record whose
//!   revocation applied, then the commit, which adopts the state and
//!   publishes the standings (Decision 16). A page stops at a record the
//!   device list can't serve, or a position that isn't the host's own
//!   Station's: what applied before commits, the cursor stays there. A page
//!   with no record reads the feed up to its head (§11.4 rule 7: gaps are
//!   allowed, and an empty page after the cursor says none remains). A page
//!   holds only the records strictly after its echoed `after` (wire rule
//!   11): one that doesn't is refused by the reader, a fault as above.
//! - **Pacing** (as the device-list fetch's, Task 30 I1). One `control_sync`
//!   in flight at a time. Those a `heads` or the pass start are at most one
//!   a second, and none for 30 seconds after a page that moved nothing or
//!   was refused. After a page that moved the cursor while the feed is
//!   still ahead, the next is asked at once (real records bound it), and
//!   so is a reset's read from 0 once its mark is written (one call in
//!   flight, and a reset counts once until its read begins, so it stays
//!   bounded by the pages).
//! - **Matching** (wire rule 11, ruling C1b-a). Every call gets a fresh
//!   `request_id` (a lowercase UUID v4 from the OS CSPRNG): a retry and a
//!   new link generation's call too, whatever the cursor. At most one call
//!   is live per socket. A page applies only when it carries the live
//!   call's id, [`ControlSyncResult::answers`] that call (its origin, feed
//!   and `after`), and the link generation and socket, and the account and
//!   genesis, are those captured with the call; a discovery call's (no
//!   `feed_id`; this host never makes one) only on the own feed this
//!   generation's `heads` announced ([`Ask::judge`]). A call is retired by
//!   its id when it is answered, when it goes unanswered for 35 seconds
//!   ([`SYNC_TIMEOUT_MS`]: the Station's agreed 30 and a 5-second grace;
//!   an hourly Station-fault alert, and a new call with a fresh id goes at
//!   once under the pacing, or after a refusal at the next `heads` past
//!   its backoff; `atem status` says it was asked again only while that
//!   retry is live), and when the link generation changes (the Station
//!   cancels the old generation's jobs; bytes written before may still
//!   come). A call retired before it went (in the pass that asked it) is
//!   never sent ([`FeedSync::outgoing`]), and one the link didn't take is
//!   dropped by its id ([`FeedSync::unsent`]). A
//!   page with a retired id is drained: counted, nothing advanced, no gate
//!   opened, no fault. A page with an id the host never sent (or no longer
//!   keeps: the last [`RETIRED_KEPT`]) is unsolicited: a Station fault. A
//!   page with the live id that doesn't answer it (another origin, feed or
//!   `after`) is a Station fault too, and retires the call; so does a page
//!   the reader refuses (its id can't be read: it is taken as the live
//!   call's answer). A page with the live id whose `head` is below its
//!   `after` (no records: the reader refuses any) is a reset: marked, the
//!   cursor never moved on it.
//! - **Refusals** (Decision 20). Any refusal on the link
//!   (`control_sync_refused`, `membership_fetch_refused`,
//!   `control_ack_refused`) closes every gate the link serves: nothing
//!   advances (no cursor, announced head, clock floor or acknowledgment).
//!   A refusal names a call kind, never a request: a
//!   `control_sync_refused` retires the live sync call, whichever call it
//!   was meant for (a late one costs liveness only: the live call's page is
//!   then drained); another call's refusal leaves the sync call live, and
//!   its page applies but ends nothing (it was asked before). The gate stays
//!   closed until a page asked for after a 30-second backoff reads
//!   ("repairs the association and resynchronizes"), at a `heads`, or on
//!   the next link generation. A refusal completes and correlates nothing.
//! - **The gate** (I.5.8). An origin's feed part is open while the link is
//!   up, a `heads` came within 60 seconds, its `station_time` is within the
//!   cap, no refusal, fault or reset waits, and the feed the last `heads`
//!   announced is read up to its head. The device-list part is the host's
//!   own fetch's ([`super::fetch::ListPart`]): [`GateView`] ANDs them. The
//!   native gate is the host's own Station's. Closed on any disconnect (a
//!   new link generation starts afresh), on a reset, after 60 seconds
//!   without `heads`, on a Station clock beyond the cap, on any refusal or
//!   Station fault (until a page asked after it reads), and while the feed
//!   isn't read to the announced head.
//! - **The start view** ([`super::gate::Gates`]) gets the feed part as it
//!   changes ([`FeedSync::take_gates`]), so the start check reads it at
//!   once (Decision 16).
use super::DelegatedSender;
use super::feeds::{FeedStore, ListNotServing, NotOwnStation, Reapplied};
use super::fetch::{HEADS_PACE_MS, REFUSAL_BACKOFF_MS, STALL_PAUSE_MS};
use super::gate::GateView;
use super::station::StationLink;
use crate::runtime::host_clock::{HostClock, StationTime};
use crate::runtime::host_work::Store;
use crate::session_protocol::membership::ListState;
use atem_client::control::{
    Applied, ControlSync, ControlSyncResult, FeedPos, Heads, HostAction, RefusedCall, RelayError,
    SyncMismatch,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

/// The gate closes when no `heads` came for this long (I.5.8), on the
/// larger of the monotonic and the boot-time elapsed times ([`Clocks`]).
pub const NO_HEADS_MS: u64 = 60_000;

/// The host's elapsed-time clocks at a pass, in ms: `CLOCK_MONOTONIC`
/// (`host_now().mono_ms`, the pacing's clock) and the delegated clock's
/// boot-time counter (I.6.5: it counts a suspend, which Linux's monotonic
/// clock doesn't; `None` when it can't be read). The 60 s without `heads`
/// are measured on both, and end on whichever passes them first, so a host
/// that slept finds its gate closed when it wakes (Task 33 review I2).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Clocks {
    pub mono_ms: u64,
    pub boot_ms: Option<u64>,
}
/// A `control_sync` unanswered this long is retired (ruling C1b-a): a new
/// call, with a fresh id, may go. The Station's agreed deadline is 30 s
/// (Astation on #164: a bounded result within 30 seconds, or the link
/// fenced); the host waits 5 s more, so a result written just inside it
/// isn't drained in transit (ruling C1b-b, Atem-internal: §11.4).
pub const SYNC_TIMEOUT_MS: u64 = 35_000;
/// The retired `request_id`s kept: a page with one of them is drained;
/// one older than these reads as unsolicited (a fault: fail closed).
pub const RETIRED_KEPT: usize = 256;
/// One alert line an hour per kind (Decision 12, as I.5.4's alerts).
pub const ALERT_EVERY_MS: u64 = 3_600_000;

/// Why the host's own Station's feed part of the gate is closed, as
/// `atem status` says it ([`Closed::text`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Closed {
    /// No Station link, or its Station's origin can't be read.
    NoLink,
    /// The control state isn't loaded.
    Unloaded,
    /// No `heads` yet on this link.
    NoHeads,
    /// No `heads` for 60 seconds.
    HeadsLate,
    /// A refusal on the link (Decision 20).
    Refused,
    /// A `control_sync` went unanswered for 35 s, was retired and asked
    /// again, and that retry is live (rulings C1b-a, C1b-b).
    Unanswered,
    /// A Station fault (its code): a page the reader refused as a whole,
    /// one that doesn't answer the live call, an unsolicited one.
    Fault(&'static str),
    /// A `station_time` beyond the cap.
    ClockAhead,
    /// A `station_time` the delegated clock couldn't record.
    ClockUnrecorded,
    /// The last `heads` announced no feed of the host's own Station, or
    /// more than one (how many).
    NoFeed(usize),
    /// A reset: the feed is read again from position 0.
    Reset,
    /// The start's recovery (design I.6.2 step 7): the feed is read again.
    Restarted,
    /// The feed isn't read up to the announced head yet.
    Behind { cursor: Option<u64>, head: u64 },
}

impl Closed {
    /// The reason `atem status` gives.
    pub fn text(&self) -> String {
        match self {
            Closed::NoLink => "no Station link".into(),
            Closed::Unloaded => "the control state isn't loaded".into(),
            Closed::NoHeads => "waiting for the Station's heads".into(),
            Closed::HeadsLate => "no heads from the Station for 60 s".into(),
            Closed::Refused => REFUSED_STATUS.into(),
            Closed::Unanswered => UNANSWERED.into(),
            Closed::Fault(code) => fault_text(code),
            Closed::ClockAhead => "Station clock ahead of this host".into(),
            Closed::ClockUnrecorded => "the host clock didn't record the Station's time".into(),
            Closed::NoFeed(0) => "the Station announced no control feed for this host".into(),
            Closed::NoFeed(n) => {
                format!("the Station announced {n} control feeds for this host's account")
            }
            Closed::Reset => "the control feed was reset; reading it again from position 0".into(),
            Closed::Restarted => "reading the control feed again since the start".into(),
            Closed::Behind {
                cursor: Some(cursor),
                head,
            } => format!("reading the control feed ({cursor} of {head})"),
            Closed::Behind { cursor: None, head } => {
                format!("reading the control feed (0 of {head})")
            }
        }
    }
}

/// Decision 20's `atem status` text.
pub const REFUSED_STATUS: &str = "Station refused feed access (forbidden); retrying";
/// The status while the retry of a `control_sync` that went unanswered for
/// 35 s is live (rulings C1b-a, C1b-b).
pub const UNANSWERED: &str =
    "a control_sync went unanswered for 35 s; asked again with a new request id";

/// Decision 12's alert for a page that isn't strict JSON.
pub const NOT_STRICT: &str = "Station sent a page that isn't strict JSON";

/// The fault code of a page whose `request_id` the host never sent (ruling
/// C1b-a).
pub const UNSOLICITED: &str = "unsolicited";
/// The fault codes of a page that carries the live call's id and doesn't
/// answer it ([`ControlSyncResult::answers`]): another origin, feed or
/// `after` (ruling C1b-a).
pub const MISMATCHED_ORIGIN: &str = "mismatched_origin";
pub const MISMATCHED_FEED: &str = "mismatched_feed_id";
pub const MISMATCHED_AFTER: &str = "mismatched_after";

/// What a page that carries the live call's `request_id` is to that call
/// ([`Ask::judge`], ruling C1b-a).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// It answers the call: it may apply.
    Answers,
    /// It doesn't answer it: a Station fault, its code.
    Fault(&'static str),
    /// The call was captured on another link generation or socket, or
    /// under another account or genesis: drained.
    Stale,
}

impl Ask {
    /// What `page` (carrying this call's id) is to this call (ruling
    /// C1b-a): `link`, the link's generation and socket now (`None`: down);
    /// `list`, the feed store's account and genesis now (`None`: not
    /// loaded, nothing applies anyway); `announced`, the own feed this
    /// generation's `heads` announced. Stale when captured on another
    /// generation or socket, or under another account or genesis; else the
    /// shared helper decides ([`ControlSyncResult::answers`]: the same
    /// origin, feed when named and `after`), and a discovery call (no
    /// `feed_id`) is answered only on the announced own feed.
    fn judge(
        &self,
        page: &ControlSyncResult,
        link: Option<(u64, u64)>,
        list: Option<&ListId>,
        announced: Option<&str>,
    ) -> Verdict {
        if link != Some((self.link_gen, self.socket)) || list.is_some_and(|l| *l != self.list) {
            return Verdict::Stale;
        }
        if let Err(m) = page.answers(&self.call) {
            return Verdict::Fault(match m {
                SyncMismatch::Origin => MISMATCHED_ORIGIN,
                SyncMismatch::FeedId => MISMATCHED_FEED,
                SyncMismatch::After => MISMATCHED_AFTER,
                // The caller matched the id: unsolicited otherwise.
                SyncMismatch::RequestId => UNSOLICITED,
            });
        }
        if self.call.feed_id.is_none() && announced != Some(page.feed_id.as_str()) {
            return Verdict::Fault(MISMATCHED_FEED);
        }
        Verdict::Answers
    }
}

/// A Station fault's text (`atem status`, the alert), by its code.
fn fault_text(code: &str) -> String {
    match code {
        "not_strict" => NOT_STRICT.into(),
        UNSOLICITED => "Station sent a page for a call this host never made".into(),
        MISMATCHED_ORIGIN => {
            "Station sent a page that doesn't answer its call (another origin)".into()
        }
        MISMATCHED_FEED => "Station sent a page that doesn't answer its call (another feed)".into(),
        MISMATCHED_AFTER => {
            "Station sent a page that doesn't answer its call (another position asked after)".into()
        }
        code => format!("Station sent a page the reader refused ({code})"),
    }
}

/// Why a fresh page is needed before the gate opens.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Resync {
    Refused,
    Fault(&'static str),
    Restarted,
}

/// The feed of the host's own Station the last `heads` announced.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Announced {
    feed_id: String,
    head: u64,
}

/// A reset pending (ruling T33c).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Reset {
    /// The feed whose read from 0 began (its cursor replaced): it goes on
    /// after the cursor; none before (it starts from 0).
    begun: Option<String>,
    /// Its mark is written (`FeedStore::mark_reset`): nothing is asked for
    /// it before.
    durable: bool,
}

/// The account and genesis of the device list a feed store was loaded
/// for ([`FeedStore::list_id`]).
pub(crate) type ListId = (String, atem_client::encoding::Hash32);

/// The live `control_sync` (ruling C1b-a): what it was captured with.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ask {
    /// The call as sent.
    call: ControlSync,
    /// The link generation it went on.
    link_gen: u64,
    /// The socket it went on ([`StationLink::socket`]): its answer can come
    /// only there, whatever the link generation.
    socket: u64,
    /// The account and genesis it was asked under.
    list: ListId,
    sent_at: u64,
    /// Read from the feed's start (a reset, or a feed never read): its page
    /// replaces the origin's cursor first.
    restart: bool,
    /// The sync's epoch when it was asked: a page asked before the latest
    /// refusal, fault or restart ends no resynchronization.
    epoch: u64,
}

/// What a page brought, committed. Its records' effects on tasks are PR
/// 11's (Task 35: `applied` and `reapplied` carry their actions); the
/// bridge reads only `next` until then.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct Synced {
    /// The records applied, each with its position, in feed order.
    pub applied: Vec<(FeedPos, Applied)>,
    /// Pending records applied again in the page's transaction (after a
    /// record whose revocation applied).
    pub reapplied: Vec<Reapplied>,
    /// The next page, asked at once: the feed is still ahead.
    pub next: Option<ControlSync>,
    /// The page was read to its end (every record past the cursor handled,
    /// or an empty page's head taken): only then does it end a reset, a
    /// refusal's or a fault's resynchronization (Task 33 review I1). False
    /// for a page that applied nothing or stopped part way (a list that
    /// doesn't serve, no position).
    pub read: bool,
}

/// What a page is applied against.
pub struct PageCx<'a> {
    pub store: &'a Store,
    pub feeds: &'a mut FeedStore,
    /// The device list as it is now.
    pub list: &'a ListState,
    /// Host-work's applied device-list `seq` (a host principal's interrupt
    /// waits for it).
    pub applied_seq: u64,
}

/// One kind of alert's hourly limit (Decision 12).
#[derive(Debug, Default, Clone)]
struct Hourly {
    last: Option<u64>,
    counted: u64,
    text: Option<String>,
}

/// The kinds of the sync's own alerts.
#[derive(Debug, Clone, Copy)]
enum Alert {
    Page = 0,
    Reset = 1,
    OtherOrigin = 2,
    Feeds = 3,
}

/// The host's sync of its own Station's control feed (the module docs).
#[derive(Debug)]
pub struct FeedSync {
    /// The link generation, its socket and its Station's origin (none: no
    /// link).
    link_gen: Option<u64>,
    socket: Option<u64>,
    own: Option<String>,
    /// The host's monotonic clock at the last tick (ms): the pacing's.
    now: u64,
    /// The boot-time counter at the last tick (ms), if it read.
    boot: Option<u64>,
    /// The last `heads` on this link generation, on both clocks.
    heads_at: Option<Clocks>,
    announced: Option<Announced>,
    /// How many feeds of the host's own Station the last `heads` named.
    own_feeds: usize,
    /// The last `station_time` that didn't count, until a `heads` within
    /// the cap.
    clock: Option<StationTime>,
    resync: Option<Resync>,
    /// A reset waits for the feed to be read from position 0 (its durable
    /// mark is the feed store's: ruling T33c).
    reset: Option<Reset>,
    /// Bumped at each refusal, Station fault and the start's restart: a
    /// page asked before ends no resynchronization.
    epoch: u64,
    /// The feed store's committed feed of the own origin, as last seen:
    /// `(feed_id, cursor)`.
    synced: Option<(String, u64)>,
    /// The account and genesis of the feed store's device list, as last
    /// seen (a call is asked under it).
    list_id: Option<ListId>,
    loaded: bool,
    /// The live call (ruling C1b-a).
    in_flight: Option<Ask>,
    /// The ids of the calls retired, the latest [`RETIRED_KEPT`]: their
    /// pages are drained.
    retired: std::collections::VecDeque<String>,
    /// The live call is the retry of one that went unanswered (asked in
    /// the tick that retired it), not answered yet: what `atem status`
    /// says only while that retry is live (ruling C1b-b, m1).
    unanswered: bool,
    refused_at: Option<u64>,
    /// The last ask a `heads` or the pass started, and the last page that
    /// moved nothing (monotonic ms): the pacing, kept across generations.
    paced_at: Option<u64>,
    stalled_at: Option<u64>,
    alerts: [Hourly; 4],
    lines: Vec<String>,
    /// The sync's alerts in this run, and the latest's text (`atem
    /// status`).
    alerts_in_run: u64,
    last_alert: Option<(String, std::time::Instant)>,
    /// What the start view was last given: the own origin and whether its
    /// feed part is open.
    published: (Option<String>, bool),
    // Counts, for the state dump.
    heads: u64,
    pages: u64,
    refusals: u64,
    faults: u64,
    resets: u64,
    other_origin: u64,
    failures: u64,
    mark_failures: u64,
    timeouts: u64,
    /// Pages of retired calls, drained.
    drained: u64,
    /// Pages of calls never made (a Station fault).
    unsolicited: u64,
}

impl Default for FeedSync {
    fn default() -> Self {
        FeedSync::new()
    }
}

impl FeedSync {
    pub fn new() -> FeedSync {
        FeedSync {
            link_gen: None,
            socket: None,
            own: None,
            now: 0,
            boot: None,
            heads_at: None,
            announced: None,
            own_feeds: 0,
            clock: None,
            resync: None,
            reset: None,
            epoch: 0,
            synced: None,
            list_id: None,
            loaded: false,
            in_flight: None,
            retired: std::collections::VecDeque::new(),
            unanswered: false,
            refused_at: None,
            paced_at: None,
            stalled_at: None,
            alerts: Default::default(),
            lines: Vec::new(),
            alerts_in_run: 0,
            last_alert: None,
            published: (None, false),
            heads: 0,
            pages: 0,
            refusals: 0,
            faults: 0,
            resets: 0,
            other_origin: 0,
            failures: 0,
            mark_failures: 0,
            timeouts: 0,
            drained: 0,
            unsolicited: 0,
        }
    }

    /// The link as the Station has it (`None`: down). A new generation
    /// starts afresh: no `heads`, nothing announced, no refusal's backoff
    /// and nothing waiting to be read again but a reset (the gate is closed
    /// until its `heads`); the pacing carries over. The live call is
    /// retired, whatever the socket (ruling C1b-a: the Station cancels the
    /// old generation's jobs; a page with its id that still comes is
    /// drained), and the new generation asks with a fresh id.
    pub fn on_link(&mut self, link: Option<&StationLink>) {
        let Some(link) = link else {
            self.on_link_down();
            return;
        };
        if self.link_gen == Some(link.link_gen) && self.socket == Some(link.socket) {
            return;
        }
        self.retire_live();
        self.fresh_generation();
        self.link_gen = Some(link.link_gen);
        self.socket = Some(link.socket);
        self.own = link.origin.clone();
    }

    /// The link went down: every gate it served closes, and its generation
    /// ends: the live call is retired (ruling C1b-a).
    pub fn on_link_down(&mut self) {
        self.retire_live();
        self.fresh_generation();
        self.link_gen = None;
        self.socket = None;
        self.own = None;
    }

    fn fresh_generation(&mut self) {
        self.heads_at = None;
        self.announced = None;
        self.own_feeds = 0;
        self.clock = None;
        self.resync = None;
        self.refused_at = None;
        self.unanswered = false;
    }

    /// The live call, if any, retired by its id: a page that carries it is
    /// drained from now on.
    fn retire_live(&mut self) {
        if let Some(ask) = self.in_flight.take() {
            self.retire(ask.call.request_id);
        }
    }

    /// `request_id` retired (the latest [`RETIRED_KEPT`] are kept).
    fn retire(&mut self, request_id: String) {
        if self.retired.len() >= RETIRED_KEPT {
            self.retired.pop_front();
        }
        self.retired.push_back(request_id);
    }

    /// The start's recovery (design I.6.2 step 7): the gate closes until a
    /// page asked from now reads. The live call stays live (its page still
    /// applies, matched by its id), but ends no resynchronization.
    pub fn restart(&mut self) {
        self.resync = Some(Resync::Restarted);
        self.epoch += 1;
    }

    /// The pass's monotonic time and the feed store (`None`: not loaded):
    /// a live call unanswered for 35 s retired ([`SYNC_TIMEOUT_MS`], ruling
    /// C1b-a: an hourly Station-fault alert), then a `control_sync` due now
    /// (one the feed needs while a recent `heads` announced it, a new one
    /// with a fresh id after a timeout, under the pacing; after a refusal,
    /// none before a `heads` past its backoff), and the hourly alert counts
    /// due. A retry asked here is what `atem status` reports as asked again
    /// (ruling C1b-b, m1: never when nothing was asked). The bridge runs it
    /// after the pass's messages, so a page that came in time answers its
    /// call first (Task 33 re-review 3, m1).
    pub fn tick(&mut self, now: Clocks, feeds: Option<&FeedStore>) -> Vec<ControlSync> {
        self.advance(now, feeds);
        let mut timed_out = false;
        if let Some(ask) = &self.in_flight
            && self.now >= ask.sent_at.saturating_add(SYNC_TIMEOUT_MS)
        {
            let origin = ask.call.origin.clone();
            self.retire_live();
            self.unanswered = false;
            timed_out = true;
            self.timeouts += 1;
            self.alert(
                Alert::Page,
                format!(
                    "a control_sync to {origin} went unanswered for 35 s and was retired; a new call, with a new request id, goes when the feed needs a page"
                ),
            );
        }
        // After a refusal, only a `heads` past the backoff asks again
        // (Decision 20).
        if !self.heads_fresh() || self.resync == Some(Resync::Refused) {
            return Vec::new();
        }
        let call = self.ask(true);
        // Only a retry actually asked is reported as one.
        if timed_out && call.is_some() {
            self.unanswered = true;
        }
        call.into_iter().collect()
    }

    /// The monotonic time and the feed store (`None`: not loaded) as they
    /// are now, with no call: what the gate reads (60 s without `heads`),
    /// and the hourly alert counts due.
    pub fn advance(&mut self, now: Clocks, feeds: Option<&FeedStore>) {
        self.now = now.mono_ms;
        self.boot = now.boot_ms;
        self.observe(feeds);
        self.alerts_due();
    }

    /// A reset's mark couldn't be written: whether to log it (the first,
    /// then at powers of two). Nothing is asked meanwhile; it is written
    /// again at the next step.
    pub fn mark_failed(&mut self) -> bool {
        self.mark_failures += 1;
        self.mark_failures.is_power_of_two()
    }

    /// A page couldn't be applied (its transaction failed and rolled back:
    /// nothing of it applied): asked again after the pause. Whether to log
    /// it (the first, then at powers of two).
    pub fn failed(&mut self) -> bool {
        self.stalled_at = Some(self.now);
        self.failures += 1;
        self.failures.is_power_of_two()
    }

    /// The Station's `heads` on the link: the clock (and its store) takes
    /// the own feed's `station_time`; `feeds` is the feed store (`None`: not
    /// loaded). The `control_sync` to send, if any.
    pub fn on_heads(
        &mut self,
        h: &Heads,
        clock: Option<(&mut HostClock, &Store)>,
        feeds: Option<&FeedStore>,
    ) -> Vec<ControlSync> {
        if self.link_gen.is_none() {
            return Vec::new();
        }
        self.heads += 1;
        self.heads_at = Some(Clocks {
            mono_ms: self.now,
            boot_ms: self.boot,
        });
        let Some(own) = self.own.clone() else {
            return Vec::new();
        };
        let (mine, others): (Vec<_>, Vec<_>) = h.feeds.iter().partition(|f| f.origin == own);
        if !others.is_empty() {
            self.other_origin += others.len() as u64;
            self.alert(
                Alert::OtherOrigin,
                format!(
                    "the Station's heads named {} control feed(s) of another origin than this host's own Station ({own}); ignored",
                    others.len()
                ),
            );
        }
        self.own_feeds = mine.len();
        self.announced = match mine.as_slice() {
            [one] => Some(Announced {
                feed_id: one.feed_id.clone(),
                head: one.head,
            }),
            [] => None,
            many => {
                self.alert(
                    Alert::Feeds,
                    format!(
                        "the Station's heads named {} control feeds of {own} for this host; none is read",
                        many.len()
                    ),
                );
                None
            }
        };
        if let [one] = mine.as_slice() {
            let verdict = match clock {
                Some((clock, store)) => clock.station_time(&own, one.station_time, store),
                None => StationTime::Unrecorded,
            };
            if verdict == StationTime::Ahead && self.clock != Some(StationTime::Ahead) {
                // The clock writes its own hourly line.
                self.note_alert("Station clock ahead of this host".into());
            }
            self.clock = (verdict != StationTime::Within).then_some(verdict);
        }
        self.observe(feeds);
        self.ask(true).into_iter().collect()
    }

    /// A `control_sync_result` on the link, or a message that was one and
    /// the reader refused (`Err`), matched to the live call by its
    /// `request_id` (ruling C1b-a; the module docs): applied in one
    /// transaction only when it answers that call as captured (`cx`: the
    /// feed store and the list; none while the feeds aren't loaded, and
    /// then nothing applies). A retired id's page is drained; an id never
    /// sent is a Station fault; so is a page with the live id that doesn't
    /// answer it, and a page the reader refused (taken as the live call's
    /// answer: its id can't be read). An error: the transaction failed and
    /// rolled back (nothing applied, the cursor stays); the page is asked
    /// again.
    pub fn on_page(
        &mut self,
        page: Result<ControlSyncResult, RelayError>,
        clock: Option<(&mut HostClock, &Store)>,
        cx: Option<PageCx<'_>>,
    ) -> anyhow::Result<Synced> {
        if self.link_gen.is_none() {
            // Nothing arrives with no link (the bridge drops it).
            return Ok(Synced::default());
        }
        let page = match page {
            Ok(page) => page,
            Err(e) => {
                // Its id can't be read: taken as the live call's answer
                // (a Station answers calls), so that call is retired; a
                // Station fault either way.
                self.retire_live();
                self.fault(e.code());
                return Ok(Synced::default());
            }
        };
        let live = self
            .in_flight
            .as_ref()
            .is_some_and(|ask| ask.call.request_id == page.request_id);
        if !live {
            if self.retired.contains(&page.request_id) {
                // A retired call's (timed out, refused, answered, or of an
                // earlier link generation): bytes the Station wrote before
                // it saw the retirement. Nothing advances; no fault.
                self.drained += 1;
            } else {
                self.unsolicited += 1;
                self.fault(UNSOLICITED);
            }
            return Ok(Synced::default());
        }
        // The live call's answer, whatever it holds: retired now (a second
        // page with its id is drained).
        let Some(ask) = self.in_flight.take() else {
            return Ok(Synced::default());
        };
        self.retire(ask.call.request_id.clone());
        self.unanswered = false;
        let link = self.link_gen.zip(self.socket);
        let list = cx.as_ref().map(|cx| cx.feeds.list_id().clone());
        let announced = self.announced.as_ref().map(|a| a.feed_id.clone());
        match ask.judge(&page, link, list.as_ref(), announced.as_deref()) {
            Verdict::Answers => {}
            Verdict::Stale => {
                self.drained += 1;
                return Ok(Synced::default());
            }
            Verdict::Fault(code) => {
                // Nothing of it applies, its head and time included.
                self.fault(code);
                return Ok(Synced::default());
            }
        }
        let Some(own) = self.own.clone() else {
            return Ok(Synced::default());
        };
        if let Some((clock, store)) = clock {
            let verdict = clock.station_time(&own, page.station_time, store);
            if verdict != StationTime::Within {
                if verdict == StationTime::Ahead && self.clock != Some(StationTime::Ahead) {
                    // Counted as a `heads`' (ruling T33c, N3).
                    self.note_alert("Station clock ahead of this host".into());
                }
                self.clock = Some(verdict);
            }
        }
        let Some(cx) = cx else {
            // The feeds aren't loaded: nothing applies; asked again later.
            self.stalled_at = Some(self.now);
            return Ok(Synced::default());
        };
        self.observe(Some(cx.feeds));
        // The feed went back under the same id: the answer's `head` below
        // its `after` (no records: the reader refuses any), or below the
        // cursor. A reset: marked (the bridge's next step), the cursor never
        // moved on this page.
        let below = self
            .synced
            .as_ref()
            .is_some_and(|(feed_id, cursor)| *feed_id == page.feed_id && page.head < *cursor);
        if page.head < ask.call.after || (!ask.restart && below) {
            self.note_reset(if page.head < ask.call.after {
                "its answer's head below the position asked after"
            } else {
                "its head below this host's cursor"
            });
            let next = self.ask(false);
            return Ok(Synced {
                next,
                ..Synced::default()
            });
        }
        if !FeedStore::serves(cx.list) {
            // Nothing applies while the list doesn't serve: the record
            // isn't consumed, the feed is read on from here once it does
            // (asked again after the pause).
            self.stalled_at = Some(self.now);
            return Ok(Synced::default());
        }
        let before = self.synced.clone();
        // A reset is done with the commit that reads its feed from 0 up to
        // the announced head (the page's own, if higher): only a page of
        // that read from 0, the one that begins it (`ask.restart`) or one
        // after it on the feed it began on. Any other (a continuation that
        // was in flight when the reset was found) applies as what it is and
        // ends nothing (Task 33 re-review 2, R2-1).
        let of_the_read = self.reset.as_ref().is_some_and(|reset| {
            ask.restart || reset.begun.as_deref() == Some(page.feed_id.as_str())
        });
        let complete_at = of_the_read.then(|| {
            self.announced
                .as_ref()
                .filter(|a| a.feed_id == page.feed_id)
                .map_or(page.head, |a| a.head.max(page.head))
        });
        let mut synced = apply_page(
            &page,
            &ask,
            cx.store,
            cx.feeds,
            cx.list,
            cx.applied_seq,
            complete_at,
        )?;
        self.pages += 1;
        // The page's head is the Station's word as fresh as a `heads`': the
        // gate needs that much read (never lowered: below is a reset).
        if let Some(announced) = self
            .announced
            .as_mut()
            .filter(|a| a.feed_id == page.feed_id)
        {
            announced.head = announced.head.max(page.head);
        }
        self.observe(Some(cx.feeds));
        if !synced.read {
            // Not read to its end: whatever waits for a read (a reset, a
            // resynchronization) still does; asked again after the pause.
            self.stalled_at = Some(self.now);
            return Ok(synced);
        }
        // Only a page asked after the latest refusal, Station fault or
        // restart ends its resynchronization.
        if ask.epoch == self.epoch {
            self.resync = None;
        }
        let moved = self.synced != before;
        synced.next = if moved {
            self.ask(false)
        } else {
            self.stalled_at = Some(self.now);
            None
        };
        Ok(synced)
    }

    /// A refusal of `call` on the link (Decision 20): nothing advances,
    /// every gate the link serves closes, and a page is asked again only
    /// after the backoff. A refusal names a call kind, never a request: a
    /// `control_sync_refused` retires the live sync call, whichever it was
    /// meant for (ruling C1b-a: a late one costs liveness only, its page
    /// then drained); another call's refusal leaves it live, its page
    /// applying but ending nothing (the epoch).
    pub fn on_refused(&mut self, call: RefusedCall) {
        if self.link_gen.is_none() {
            return;
        }
        self.refusals += 1;
        self.note_alert(REFUSED_STATUS.into());
        self.resync = Some(Resync::Refused);
        self.refused_at = Some(self.now);
        self.epoch += 1;
        if call == RefusedCall::ControlSync {
            self.retire_live();
        }
    }

    /// A reset found and not marked yet: its mark written in the feed
    /// store (its own transaction), before anything is asked for it; then
    /// the read from 0, if it may go now (ruling T33c). The bridge calls it
    /// after every step of the sync. An error: the mark isn't written,
    /// nothing is asked, the gate stays closed, and it is tried again at
    /// the next step.
    pub fn persist_mark(
        &mut self,
        store: &Store,
        feeds: &mut FeedStore,
    ) -> anyhow::Result<Option<ControlSync>> {
        let Some(own) = self.own.clone() else {
            return Ok(None);
        };
        if self.reset.as_ref().is_none_or(|r| r.durable) {
            return Ok(None);
        }
        feeds.mark_reset(store, &own)?;
        self.reset = Some(Reset {
            begun: None,
            durable: true,
        });
        // As the step that found it would have asked (a heads' pacing was
        // never reached: nothing went before the mark). One in flight at a
        // time, and a reset counts once until a read from 0 begins, so marks
        // and reads stay bounded by the pages.
        Ok(self.ask(false))
    }

    /// The call `request_id` wasn't handed to the link (ruling C1b-b, m2):
    /// never sent. If it is the live call, none is live (asked again at
    /// the next `heads` or pass); a newer live call stays. Its id leaves
    /// the retired ones: a page naming it is unsolicited.
    pub fn unsent(&mut self, request_id: &str) {
        if self
            .in_flight
            .as_ref()
            .is_some_and(|ask| ask.call.request_id == request_id)
        {
            self.in_flight = None;
        }
        self.retired.retain(|id| id != request_id);
    }

    /// The pass's `control_sync`s as they may go: only the live call. One
    /// retired in the same pass (a page, a refusal or a new generation
    /// came after it was asked) is never sent ([`FeedSync::unsent`]).
    pub fn outgoing(&mut self, calls: Vec<ControlSync>) -> Vec<ControlSync> {
        let (live, retired): (Vec<_>, Vec<_>) = calls.into_iter().partition(|call| {
            self.in_flight
                .as_ref()
                .is_some_and(|ask| ask.call.request_id == call.request_id)
        });
        for call in retired {
            self.unsent(&call.request_id);
        }
        live
    }

    /// The start view's copy of the feed part, when it changed since the
    /// last: the host's own Station's origin, and the origins whose feed
    /// part is open (that one, or none).
    pub fn take_gates(&mut self) -> Option<(Option<String>, BTreeSet<String>)> {
        let now = (self.own.clone(), self.closed().is_none());
        if now == self.published {
            return None;
        }
        self.published = now.clone();
        let open = match (&now.0, now.1) {
            (Some(own), true) => BTreeSet::from([own.clone()]),
            _ => BTreeSet::new(),
        };
        Some((now.0, open))
    }

    /// Why the host's own Station's feed part is closed (`None`: open), in
    /// the order `atem status` reports it.
    pub fn closed(&self) -> Option<Closed> {
        if self.link_gen.is_none() || self.own.is_none() {
            return Some(Closed::NoLink);
        }
        match self.resync {
            Some(Resync::Refused) => return Some(Closed::Refused),
            Some(Resync::Fault(code)) => return Some(Closed::Fault(code)),
            _ => {}
        }
        if !self.loaded {
            return Some(Closed::Unloaded);
        }
        if self.heads_at.is_none() {
            return Some(Closed::NoHeads);
        }
        if !self.heads_fresh() {
            return Some(Closed::HeadsLate);
        }
        match self.clock {
            Some(StationTime::Ahead) => return Some(Closed::ClockAhead),
            Some(_) => return Some(Closed::ClockUnrecorded),
            None => {}
        }
        let Some(announced) = &self.announced else {
            return Some(Closed::NoFeed(self.own_feeds));
        };
        if self.unanswered && self.in_flight.is_some() {
            return Some(Closed::Unanswered);
        }
        if self.reset.is_some() {
            return Some(Closed::Reset);
        }
        if self.resync == Some(Resync::Restarted) {
            return Some(Closed::Restarted);
        }
        match &self.synced {
            Some((feed_id, cursor)) if *feed_id == announced.feed_id => (*cursor < announced.head)
                .then_some(Closed::Behind {
                    cursor: Some(*cursor),
                    head: announced.head,
                }),
            _ => Some(Closed::Behind {
                cursor: None,
                head: announced.head,
            }),
        }
    }

    /// The host's own Station's origin, on the link now.
    pub fn own(&self) -> Option<&str> {
        self.own.as_deref()
    }

    /// The alerts on the link in this run (the runtime.log lines are at
    /// most one an hour per kind: the sync's own, the refusals' and the
    /// clock's "Station clock ahead") and the latest one (its text, when).
    pub fn alerts(&self) -> (u64, Option<&(String, std::time::Instant)>) {
        (self.alerts_in_run, self.last_alert.as_ref())
    }

    /// An alert counted for `atem status` (its line is whoever raised it).
    fn note_alert(&mut self, text: String) {
        self.alerts_in_run += 1;
        self.last_alert = Some((text, std::time::Instant::now()));
    }

    /// The `runtime.log` lines not taken yet (alerts).
    pub fn take_lines(&mut self) -> Vec<String> {
        std::mem::take(&mut self.lines)
    }

    /// For the state dump (debug builds).
    #[cfg_attr(not(debug_assertions), allow(dead_code))]
    pub fn dump(&self) -> Value {
        json!({
            "own": self.own,
            "open": self.closed().is_none(),
            "closed": self.closed().map(|c| c.text()),
            "announced": self.announced.as_ref().map(|a| json!({"feed_id": a.feed_id, "head": a.head})),
            "synced": self.synced.as_ref().map(|(feed_id, cursor)| json!({"feed_id": feed_id, "cursor": cursor})),
            "in_flight": self.in_flight.as_ref().map(|a| json!({"request_id": a.call.request_id, "feed_id": a.call.feed_id, "after": a.call.after})),
            "heads": self.heads,
            "pages": self.pages,
            "refusals": self.refusals,
            "faults": self.faults,
            "resets": self.resets,
            "timeouts": self.timeouts,
            "unanswered": self.unanswered,
            "drained": self.drained,
            "unsolicited": self.unsolicited,
            "retired": self.retired.len(),
            "reset": self.reset.as_ref().map(|r| json!({"begun": r.begun, "durable": r.durable})),
            "other_origin": self.other_origin,
        })
    }

    // ------------------------------------------------------------ inside

    /// The feed store's committed feed of the own origin, as it is now,
    /// against the announcement (a reset, wherever it is found: Task 33
    /// review m3).
    fn observe(&mut self, feeds: Option<&FeedStore>) {
        self.loaded = feeds.is_some();
        self.list_id = feeds.map(|feeds| feeds.list_id().clone());
        self.synced = match (feeds, &self.own) {
            (Some(feeds), Some(own)) => feeds.current_feed(own),
            _ => None,
        };
        // The durable mark (ruling T33c) is what a written reset is: a
        // start finds one found before it, a read's commits move it on and
        // clear it. One not written yet is this sync's until it is.
        if let (Some(feeds), Some(own)) = (feeds, self.own.clone()) {
            let mark = feeds
                .reset_pending(&own)
                .map(|begun| (!begun.is_empty()).then(|| begun.to_string()));
            match (mark, self.reset.as_mut()) {
                (Some(begun), Some(reset)) if reset.durable => reset.begun = begun,
                (Some(begun), None) => {
                    self.reset = Some(Reset {
                        begun,
                        durable: true,
                    });
                    self.resets += 1;
                    self.alert(
                        Alert::Reset,
                        format!(
                            "the control feed of {own} was reset before this start; reading it again from position 0"
                        ),
                    );
                }
                (None, Some(reset)) if reset.durable => self.reset = None,
                _ => {}
            }
        }
        self.check_reset();
    }

    /// A `heads` came within 60 s on both clocks (each elapsed time
    /// measured on its own; a boot-time reading missing at either end
    /// leaves the monotonic one alone).
    fn heads_fresh(&self) -> bool {
        self.heads_at.is_some_and(|at| {
            let mono = self.now.saturating_sub(at.mono_ms);
            let boot = at
                .boot_ms
                .zip(self.boot)
                .map_or(0, |(then, now)| now.saturating_sub(then));
            mono.max(boot) < NO_HEADS_MS
        })
    }

    /// The announced feed against the one read: another feed, or a cursor
    /// above the announced head of the same one, is a reset.
    fn check_reset(&mut self) {
        let (Some(announced), Some((feed_id, cursor))) = (&self.announced, &self.synced) else {
            return;
        };
        if *feed_id != announced.feed_id {
            self.note_reset("a new feed id");
        } else if announced.head < *cursor {
            self.note_reset("its head below this host's cursor");
        }
    }

    /// A reset: the feed is read from position 0, once its mark is written
    /// (counted once until that read is done; one found during the read
    /// starts it again).
    fn note_reset(&mut self, why: &str) {
        if self.reset.as_ref().is_some_and(|r| r.begun.is_none()) {
            return;
        }
        self.reset = Some(Reset {
            begun: None,
            durable: false,
        });
        self.resets += 1;
        let origin = self.own.clone().unwrap_or_default();
        self.alert(
            Alert::Reset,
            format!(
                "the control feed of {origin} was reset ({why}); reading it again from position 0"
            ),
        );
    }

    /// A Station fault (a page the reader refused, one with the live id
    /// that doesn't answer it, an unsolicited one): the gate closes until a
    /// page asked after it reads (the epoch; ruling C1b-a).
    fn fault(&mut self, code: &'static str) {
        self.faults += 1;
        self.epoch += 1;
        self.resync = Some(Resync::Fault(code));
        self.stalled_at = Some(self.now);
        let origin = self.own.clone().unwrap_or_default();
        let what = fault_text(code);
        self.alert(
            Alert::Page,
            format!("{what} ({origin}); its gate stays closed and the page is asked again"),
        );
    }

    /// The `control_sync` the announced feed needs now, if any: one at a
    /// time, none in a refusal's backoff; `paced`: one a `heads` or the pass
    /// starts (at most one a second, none for 30 seconds after a page that
    /// moved nothing).
    fn ask(&mut self, paced: bool) -> Option<ControlSync> {
        let own = self.own.clone()?;
        let announced = self.announced.clone()?;
        if !self.loaded || self.in_flight.is_some() {
            return None;
        }
        // Nothing for a reset before its mark is written (ruling T33c).
        if self.reset.as_ref().is_some_and(|r| !r.durable) {
            return None;
        }
        let socket = self.socket?;
        if let Some(at) = self.refused_at {
            if self.now < at.saturating_add(REFUSAL_BACKOFF_MS) {
                return None;
            }
            self.refused_at = None;
        }
        let read = self
            .synced
            .as_ref()
            .filter(|(feed_id, _)| *feed_id == announced.feed_id)
            .map(|(_, cursor)| *cursor);
        let behind = read.is_none_or(|cursor| cursor < announced.head);
        if !(behind || self.reset.is_some() || self.resync.is_some()) {
            return None;
        }
        if paced {
            let within =
                |at: Option<u64>, ms: u64| at.is_some_and(|at| self.now < at.saturating_add(ms));
            if within(self.paced_at, HEADS_PACE_MS) || within(self.stalled_at, STALL_PAUSE_MS) {
                return None;
            }
            self.paced_at = Some(self.now);
        }
        // From 0 unless the reset's read from 0 began on this very feed.
        let restart = match &self.reset {
            Some(reset) => reset.begun.as_deref() != Some(announced.feed_id.as_str()),
            None => read.is_none(),
        };
        let after = if restart { 0 } else { read.unwrap_or(0) };
        let list = self.list_id.clone()?;
        let link_gen = self.link_gen?;
        let call = ControlSync {
            request_id: fresh_request_id(),
            origin: own,
            feed_id: Some(announced.feed_id),
            after,
        };
        // A new call: no retry's, unless the tick that retired one says so.
        self.unanswered = false;
        self.in_flight = Some(Ask {
            call: call.clone(),
            link_gen,
            socket,
            list,
            sent_at: self.now,
            restart,
            epoch: self.epoch,
        });
        Some(call)
    }

    /// The call in flight, as it was sent (tests answer it).
    #[cfg(test)]
    pub(crate) fn live_call(&self) -> Option<ControlSync> {
        self.in_flight.as_ref().map(|ask| ask.call.clone())
    }

    /// One line now for `kind` when its hour passed, else counted (the
    /// latest kept for the line at the hour's end).
    fn alert(&mut self, kind: Alert, text: String) {
        self.note_alert(text.clone());
        let h = &mut self.alerts[kind as usize];
        let due = h
            .last
            .is_none_or(|last| self.now < last || self.now >= last.saturating_add(ALERT_EVERY_MS));
        if due {
            let more = std::mem::take(&mut h.counted);
            h.text = None;
            h.last = Some(self.now);
            self.line(text, more);
        } else {
            h.counted += 1;
            h.text = Some(text);
        }
    }

    /// The counted alerts whose hour passed: the latest, with how many came
    /// since the last line.
    fn alerts_due(&mut self) {
        for kind in [Alert::Page, Alert::Reset, Alert::OtherOrigin, Alert::Feeds] {
            let h = &mut self.alerts[kind as usize];
            let due = h.last.is_some_and(|last| {
                self.now < last || self.now >= last.saturating_add(ALERT_EVERY_MS)
            });
            if due && let Some(text) = h.text.take() {
                let more = std::mem::take(&mut h.counted);
                h.last = Some(self.now);
                self.line(text, more);
            }
        }
    }

    fn line(&mut self, text: String, more: u64) {
        let more = if more > 0 {
            format!(" ({more} more since the last such line)")
        } else {
            String::new()
        };
        self.lines.push(format!(
            "atem runtime: {text}{more}; at most one such line an hour"
        ));
    }
}

/// A fresh `request_id` for a `control_sync` (wire rule 11): a lowercase
/// UUID v4 from the operating system's CSPRNG, never derived from the
/// cursor, the feed or the link generation (two calls at the same cursor
/// differ only by it).
fn fresh_request_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut bytes);
    uuid::Builder::from_random_bytes(bytes)
        .into_uuid()
        .hyphenated()
        .to_string()
}

impl GateView for FeedSync {
    /// The feed part (this sync's) AND the device-list part (`fetched`,
    /// the host's own fetch's): only the host's own Station's gate can
    /// open; a native's is that one.
    fn open_for(&self, sender: &DelegatedSender, fetched: Option<&str>) -> bool {
        let origin = match sender {
            DelegatedSender::Native { .. } => self.own.as_deref(),
            DelegatedSender::Service { feed, .. } => Some(feed.origin.as_str()),
        };
        origin.is_some_and(|origin| {
            self.own.as_deref() == Some(origin)
                && self.closed().is_none()
                && fetched == Some(origin)
        })
    }
}

/// A page's records in one transaction, its commit included: applied in
/// order (a record that doesn't parse kept as evidence), the pending
/// records re-verified after a record whose revocation applied; stopped at
/// a record the list can't serve or a position that isn't the host's own
/// Station's (what applied before commits). Every record is after the
/// call's `after` ([`FeedSync::on_page`] faults a page that isn't). A page
/// with no record reads the feed up to its head. A reset's read
/// (`ask.restart`) replaces the origin's cursor first.
fn apply_page(
    page: &ControlSyncResult,
    ask: &Ask,
    store: &Store,
    feeds: &mut FeedStore,
    list: &ListState,
    applied_seq: u64,
    complete_at: Option<u64>,
) -> anyhow::Result<Synced> {
    let pos = |feeds: &FeedStore, seq: u64| feeds.position(&page.feed_id, seq);
    // No position can be formed (the store has no own Station's origin):
    // nothing applies, and the page isn't read (Task 33 review I1).
    if pos(feeds, 0).is_none() {
        return Ok(Synced::default());
    }
    let tx = feeds.begin(store)?;
    if ask.restart {
        let Some(start) = pos(feeds, 0) else {
            return Ok(Synced::default());
        };
        feeds.restart(&tx, start.clone())?;
        feeds.reset_begun(&tx, &start)?;
    }
    // How far the feed is read with this page.
    let mut reached = if ask.restart { 0 } else { ask.call.after };
    let mut applied = Vec::new();
    let mut reapplied = Vec::new();
    let mut stopped = false;
    for entry in &page.records {
        let Some(at) = pos(feeds, entry.feed_seq) else {
            stopped = true;
            break;
        };
        reached = entry.feed_seq;
        match entry.parse_record() {
            Err(e) => feeds.unparsed(&tx, &entry.raw().to_string(), e.code(), at)?,
            Ok(record) => match feeds.apply(&tx, &record, list, at.clone(), applied_seq) {
                Ok(a) => {
                    let revoked = a
                        .actions
                        .iter()
                        .any(|action| matches!(action, HostAction::Revoke(_)));
                    applied.push((at, a));
                    if revoked {
                        reapplied.extend(feeds.reverify_pending(&tx, list, applied_seq)?);
                    }
                }
                Err(e) if e.is::<ListNotServing>() || e.is::<NotOwnStation>() => {
                    // Not consumed: the read reached the record before.
                    stopped = true;
                    break;
                }
                Err(e) => return Err(e),
            },
        }
    }
    if !stopped && page.records.is_empty() {
        match pos(feeds, page.head.max(ask.call.after)) {
            Some(head) => {
                reached = page.head.max(ask.call.after);
                feeds.advance(&tx, head)?;
            }
            None => stopped = true,
        }
    }
    // The reset is done with this commit when its read reached the
    // announced head (ruling T33c).
    if !stopped
        && complete_at.is_some_and(|head| reached >= head)
        && let Some(origin) = feeds.position(&page.feed_id, 0).map(|p| p.origin)
    {
        feeds.clear_reset(&tx, &origin)?;
    }
    feeds.commit(tx)?;
    Ok(Synced {
        applied,
        reapplied,
        next: None,
        read: !stopped,
    })
}

#[cfg(test)]
#[path = "sync_tests.rs"]
mod tests;

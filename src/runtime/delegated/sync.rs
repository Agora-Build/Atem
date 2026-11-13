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
//!   the last `heads` announced, and a page is taken only for the call in
//!   flight, whose `(origin, feed_id)` it must carry: positions come only
//!   from that page's own feed. A page of another feed (a Station serving
//!   its current feed for an old `feed_id`, §11.4's open question) applies
//!   nothing and reads as a reset; one nobody asked for applies nothing.
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
//!   holds "the records after `after`" (§11.4), so one holding a record at
//!   or below its call's `after` contradicts its call: a Station fault
//!   ([`CONTRADICTS_CALL`], ruling T33e), nothing of it applied.
//! - **Pacing** (as the device-list fetch's, Task 30 I1). One `control_sync`
//!   in flight at a time. Those a `heads` or the pass start are at most one
//!   a second, and none for 30 seconds after a page that moved nothing or
//!   was refused. After a page that moved the cursor while the feed is
//!   still ahead, the next is asked at once (real records bound it), and
//!   so is a reset's read from 0 once its mark is written (one call in
//!   flight, and a reset counts once until its read begins, so it stays
//!   bounded by the pages).
//! - **Matching** (rulings T33d, T33e). A page names no call (no echo of
//!   `feed_id` and `after`; gaps are legal), so it is matched to the one
//!   call in flight by order, and at most one call is owed per socket: a
//!   call is never dropped while its answer may still come. A new link
//!   generation on the same socket (Astation re-authenticating it, a routed
//!   link's upgrade; [`StationLink::socket`]) keeps it, and asks nothing
//!   until its answer comes, taken as that call's (its own `after` and
//!   kind: a continuation's page never ends a reset); a new socket drops
//!   it, since its answer can't come there. A call unanswered for 30
//!   seconds (timed only while a link is up) stops the sync: its gate stays
//!   closed, nothing more is asked on its socket, and the Station-fault
//!   alert goes. Its late answer is still that call's (nothing was asked
//!   after it) and resumes the sync; one that never comes waits for a new
//!   socket (the host has no safe way to ask for a fresh link: `atem
//!   status` names `atem runtime restart`).
//! - **Refusals** (Decision 20). Any refusal on the link
//!   (`control_sync_refused`, `membership_fetch_refused`,
//!   `control_ack_refused`) closes every gate the link serves: nothing
//!   advances (no cursor, announced head, clock floor or acknowledgment).
//!   A `control_sync_refused` ends the host's own wait for the sync in
//!   flight, timed out or not (it is its answer, so a page arriving after
//!   it is one nobody asked for); another call's refusal leaves the sync in
//!   flight (its answer is owed) but its page ends nothing. The gate stays
//!   closed until a page asked for after a 30-second backoff reads
//!   ("repairs the association and resynchronizes"), at a `heads`, or on
//!   the next link generation. A refusal completes and correlates nothing.
//! - **The gate** (I.5.8). An origin's feed part is open while the link is
//!   up, a `heads` came within 60 seconds, its `station_time` is within the
//!   cap, no refusal, fault or reset waits, and the feed the last `heads`
//!   announced is read up to its head. The device-list part is the host's
//!   own fetch's ([`super::fetch::ListPart`]): [`GateView`] ANDs them. The
//!   native gate is the host's own Station's. Closed on any disconnect (a
//!   new link generation starts afresh, but for a call still owed on its
//!   socket), on a reset, after 60 seconds without `heads`, on a Station
//!   clock beyond the cap, on any refusal, and while a call is unanswered.
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
/// A `control_sync` unanswered this long stops the sync until its answer
/// comes or a new socket (ruling T33e): nothing is asked again.
pub const SYNC_TIMEOUT_MS: u64 = 30_000;
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
    /// A `control_sync` went unanswered for 30 s: nothing more is asked on
    /// its socket (a re-send could bring two answers), so the sync waits
    /// for its answer or a new socket (rulings T33d, T33e).
    Unanswered,
    /// A page the reader refused as a whole (its code).
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
/// The status of a sync that waits for its unanswered call's answer or a
/// new socket (rulings T33d, T33e), with the way out.
pub const UNANSWERED: &str = "a control_sync went unanswered; nothing more is asked until its answer comes or the link reconnects: run `atem runtime restart` to reconnect now";

/// Decision 12's alert for a page that isn't strict JSON.
pub const NOT_STRICT: &str = "Station sent a page that isn't strict JSON";

/// The fault code of a page that contradicts its call: it holds a record
/// at or below the call's `after` (ruling T33e).
pub const CONTRADICTS_CALL: &str = "contradicts_call";

/// A Station fault's text (`atem status`, the alert), by its code.
fn fault_text(code: &str) -> String {
    match code {
        "not_strict" => NOT_STRICT.into(),
        "another_origin" => "Station sent a page of another origin".into(),
        CONTRADICTS_CALL => {
            "Station sent a page that contradicts its call (a record at or below the position asked after)".into()
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

/// The `control_sync` in flight: its answer is owed (rulings T33d, T33e).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Ask {
    /// Its `request_id` (wire rule 11): fresh for every call.
    request_id: String,
    origin: String,
    feed_id: String,
    after: u64,
    sent_at: u64,
    /// The socket it went on ([`StationLink::socket`]): its answer can come
    /// only there, whatever the link generation.
    socket: u64,
    /// Unanswered for 30 s: nothing more is asked on its socket; a late
    /// answer is still this call's.
    timed_out: bool,
    /// Read from the feed's start (a reset, or a feed never read): its page
    /// replaces the origin's cursor first.
    restart: bool,
    /// The sync's epoch when it was asked: a page asked before the latest
    /// refusal or restart ends no resynchronization.
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
    /// The last announcement is stale (the Station served another feed
    /// than it named): nothing is asked before the next `heads`.
    wait_heads: bool,
    /// Bumped at each refusal and at the start's restart: a page asked
    /// before ends no resynchronization.
    epoch: u64,
    /// The feed store's committed feed of the own origin, as last seen:
    /// `(feed_id, cursor)`.
    synced: Option<(String, u64)>,
    loaded: bool,
    /// The call whose answer is owed, kept while its socket may still bring
    /// it (across link generations on that socket; ruling T33e).
    in_flight: Option<Ask>,
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
    unasked: u64,
    refusals: u64,
    faults: u64,
    resets: u64,
    other_origin: u64,
    failures: u64,
    mark_failures: u64,
    timeouts: u64,
    /// Late answers taken (a timed-out call's).
    late: u64,
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
            wait_heads: false,
            epoch: 0,
            synced: None,
            loaded: false,
            in_flight: None,
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
            unasked: 0,
            refusals: 0,
            faults: 0,
            resets: 0,
            other_origin: 0,
            failures: 0,
            mark_failures: 0,
            timeouts: 0,
            late: 0,
        }
    }

    /// The link as the Station has it (`None`: down). A new generation
    /// starts afresh: no `heads`, nothing announced, no refusal's backoff
    /// and nothing waiting to be read again but a reset (the gate is closed
    /// until its `heads`); the pacing carries over. A call whose answer is
    /// owed stays in flight on its own socket (the Station answers it there,
    /// whatever the generation: ruling T33e), timed out or not, so the new
    /// generation asks nothing until it is answered; a new socket drops it
    /// (its answer can't come there).
    pub fn on_link(&mut self, link: Option<&StationLink>) {
        let Some(link) = link else {
            self.on_link_down();
            return;
        };
        if self.link_gen == Some(link.link_gen) && self.socket == Some(link.socket) {
            return;
        }
        self.fresh_generation();
        if self
            .in_flight
            .as_ref()
            .is_some_and(|ask| ask.socket != link.socket)
        {
            self.in_flight = None;
        }
        self.link_gen = Some(link.link_gen);
        self.socket = Some(link.socket);
        self.own = link.origin.clone();
    }

    /// The link went down: every gate it served closes. A call in flight
    /// stays owed: the next generation may come on its socket (a
    /// re-authentication), and only a new socket drops it ([`Self::on_link`]).
    pub fn on_link_down(&mut self) {
        self.fresh_generation();
        self.link_gen = None;
        self.socket = None;
        self.own = None;
    }

    fn fresh_generation(&mut self) {
        self.heads_at = None;
        self.wait_heads = false;
        self.announced = None;
        self.own_feeds = 0;
        self.clock = None;
        self.resync = None;
        self.refused_at = None;
    }

    /// The call in flight went unanswered for 30 s and is still owed.
    fn unanswered(&self) -> bool {
        self.in_flight.as_ref().is_some_and(|ask| ask.timed_out)
    }

    /// The start's recovery (design I.6.2 step 7): the gate closes until a
    /// page asked from now reads. A call in flight stays (its answer is
    /// owed: dropped, it would come after the next ask and be taken for its
    /// page), and its page ends no resynchronization.
    pub fn restart(&mut self) {
        self.resync = Some(Resync::Restarted);
        self.epoch += 1;
    }

    /// The pass's monotonic time and the feed store (`None`: not loaded):
    /// a `control_sync` due now (one the feed needs while a recent `heads`
    /// announced it), a call in flight timed out (30 s unanswered while a
    /// link is up: its socket may come back while none is), and the hourly
    /// alert counts due. The bridge runs it after the pass's messages, so a
    /// page that came in time answers its call first (Task 33 re-review 3,
    /// m1).
    pub fn tick(&mut self, now: Clocks, feeds: Option<&FeedStore>) -> Vec<ControlSync> {
        self.advance(now, feeds);
        let up = self.link_gen.is_some();
        if let Some(ask) = self.in_flight.as_mut()
            && up
            && !ask.timed_out
            && self.now >= ask.sent_at.saturating_add(SYNC_TIMEOUT_MS)
        {
            // No page names its call (§11.4: no echo; gaps are legal), so
            // nothing more is asked on its socket (a re-send could bring two
            // answers): the call stays owed, its late answer still its own,
            // and the sync waits for it or a new socket (rulings T33d, T33e).
            ask.timed_out = true;
            let origin = ask.origin.clone();
            self.timeouts += 1;
            self.alert(
                Alert::Page,
                format!(
                    "a control_sync to {origin} went unanswered for 30 s; its gate stays closed and nothing more is asked until its answer comes or the link reconnects: run `atem runtime restart` to reconnect now"
                ),
            );
            return Vec::new();
        }
        // After a refusal, only a `heads` past the backoff asks again
        // (Decision 20); after a page of another feed, only a `heads`
        // (its announcement is stale).
        if !self.heads_fresh() || self.resync == Some(Resync::Refused) || self.wait_heads {
            return Vec::new();
        }
        self.ask(true).into_iter().collect()
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
        self.wait_heads = false;
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
    /// the reader refused (`Err`). Applied in one transaction when it
    /// answers the call in flight (`cx`: the feed store and the list; none
    /// while the feeds aren't loaded, and then nothing applies), as that
    /// call's answer whatever the link generation (its own `after` and
    /// kind), a timed-out call's too: nothing was asked on its socket after
    /// it (ruling T33e). An error: the transaction failed and rolled back
    /// (nothing applied, the cursor stays); the page is asked again.
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
        let Some(ask) = self.in_flight.take() else {
            self.unasked += 1;
            if let Err(e) = page {
                self.fault(e.code());
            }
            return Ok(Synced::default());
        };
        if ask.timed_out {
            // Its late answer: the sync resumes with it (ruling T33e).
            self.late += 1;
        }
        let page = match page {
            Ok(page) => page,
            Err(e) => {
                self.fault(e.code());
                return Ok(Synced::default());
            }
        };
        let Some(own) = self.own.clone() else {
            return Ok(Synced::default());
        };
        if page.origin != own {
            self.fault("another_origin");
            return Ok(Synced::default());
        }
        if page.feed_id != ask.feed_id {
            // The Station served another feed than the one asked: a reset
            // (its current feed for an old id). Nothing of it applies.
            self.note_reset("the Station served another feed than the one asked");
            self.stalled_at = Some(self.now);
            // The announcement is stale: nothing more is asked of it.
            self.wait_heads = true;
            return Ok(Synced::default());
        }
        if page.records.iter().any(|entry| entry.feed_seq <= ask.after) {
            // A page carries "the records after `after`" (§11.4): one at or
            // below it answers another call (or none), so the page
            // contradicts its call: a Station fault, nothing of it applied,
            // its head and time included (ruling T33e).
            self.fault(CONTRADICTS_CALL);
            return Ok(Synced::default());
        }
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
        let below = self
            .synced
            .as_ref()
            .is_some_and(|(feed_id, cursor)| *feed_id == page.feed_id && page.head < *cursor);
        if !ask.restart && below {
            self.note_reset("its head below this host's cursor");
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
        // Only a page asked after the latest refusal or restart ends its
        // resynchronization.
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
    /// after the backoff. A `control_sync_refused` answers the sync in
    /// flight (timed out or not), ending the host's wait for it; another
    /// call's refusal leaves it owed.
    pub fn on_refused(&mut self, call: RefusedCall) {
        if self.link_gen.is_none() {
            return;
        }
        self.refusals += 1;
        self.note_alert(REFUSED_STATUS.into());
        self.resync = Some(Resync::Refused);
        self.refused_at = Some(self.now);
        self.epoch += 1;
        // A `control_sync_refused` answers the sync in flight: its wait
        // ends. Another call's refusal doesn't: the sync's answer is still
        // owed, so the call stays in flight (dropped, its answer would come
        // after a later ask and be taken for that one's page); its page
        // ends no resynchronization (ruling T33d).
        if call == RefusedCall::ControlSync {
            self.in_flight = None;
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

    /// The call just asked for couldn't be handed to the link: none in
    /// flight (asked again at the next `heads` or pass).
    pub fn unsent(&mut self) {
        self.in_flight = None;
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
        if self.unanswered() {
            return Some(Closed::Unanswered);
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
            "in_flight": self.in_flight.as_ref().map(|a| json!({"feed_id": a.feed_id, "after": a.after, "timed_out": a.timed_out})),
            "heads": self.heads,
            "pages": self.pages,
            "unasked": self.unasked,
            "refusals": self.refusals,
            "faults": self.faults,
            "resets": self.resets,
            "timeouts": self.timeouts,
            "late": self.late,
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

    /// A page the reader refused, one that names another origin, or one
    /// that contradicts its call: a Station fault.
    fn fault(&mut self, code: &'static str) {
        self.faults += 1;
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
        // Nothing for a reset before its mark is written (ruling T33c), nor
        // of a stale announcement before the next `heads` (a call whose
        // answer is owed, timed out or not, is the one in flight: ruling
        // T33e).
        if self.reset.as_ref().is_some_and(|r| !r.durable) || self.wait_heads {
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
        let request_id = fresh_request_id();
        self.in_flight = Some(Ask {
            request_id: request_id.clone(),
            origin: own.clone(),
            feed_id: announced.feed_id.clone(),
            after,
            sent_at: self.now,
            socket,
            timed_out: false,
            restart,
            epoch: self.epoch,
        });
        Some(ControlSync {
            request_id,
            origin: own,
            feed_id: Some(announced.feed_id),
            after,
        })
    }

    /// The call in flight, as it was sent (tests answer it).
    #[cfg(test)]
    pub(crate) fn live_call(&self) -> Option<ControlSync> {
        self.in_flight.as_ref().map(|ask| ControlSync {
            request_id: ask.request_id.clone(),
            origin: ask.origin.clone(),
            feed_id: Some(ask.feed_id.clone()),
            after: ask.after,
        })
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
    let mut reached = if ask.restart { 0 } else { ask.after };
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
        match pos(feeds, page.head.max(ask.after)) {
            Some(head) => {
                reached = page.head.max(ask.after);
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

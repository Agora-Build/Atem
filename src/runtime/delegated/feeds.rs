//! The host's control feed store (the delegated host-work design I.5.4,
//! I.5.5; host-work-v1 §11.1, "Application" and "The state, per
//! principal"; the bindings' §9, "Persistence and the order of calls"):
//! signed control records applied through the shared core's
//! [`ControlState`], durably, with the feed cursor, the pending records and
//! the evidence.
//!
//! - **One transaction.** A record is verified and applied
//!   ([`ControlState::apply`]) against the device list as it commits, and
//!   what it changes is written in the store's own `BEGIN IMMEDIATE`
//!   transaction ([`FeedStore::begin`] gives a [`FeedTx`], the only
//!   transaction records apply in): the touched principals' parts (one
//!   `control_principals` row each), the feed's cursor (`control_feeds`),
//!   a record kept pending, and evidence when it is due. The caller writes
//!   the record's effects (Task 35) in the same transaction (a `FeedTx`
//!   derefs to it). The next state is adopted only by [`FeedStore::commit`],
//!   once the transaction committed: a transaction in which a step failed
//!   is rolled back by it, one dropped forgets what it staged, and either
//!   loses no effect: the record applied again to the state kept gives the
//!   same results and actions. Nothing applies while the device list is
//!   frozen, held, faulted or gone ([`ListNotServing`]): the record isn't
//!   consumed.
//! - **Positions.** A record read from a feed is at the host's own
//!   configured Station's origin, always ([`FeedStore::position`]): never
//!   one taken from a page or a record (§11.1's host rule, which bounds a
//!   part's `order`). Any other position is refused ([`NotOwnStation`]).
//!   One feed per origin is kept: another feed of the origin (a reset's
//!   new one, or one a carrier minted) replaces the old one's cursor in the
//!   transaction that reads it. A reset the sync found is marked per origin
//!   (`control_resets`, [`FeedStore::mark_reset`]) before anything is asked
//!   for it, and cleared only by the commit that reads the feed from 0 up
//!   to the announced head: a start with the mark reads the feed from 0
//!   again (ruling T33c). Records carried over a channel
//!   ([`FeedStore::apply_carried`]) have no position.
//! - **Loading** ([`FeedStore::load`]) reads the parts of the host's pinned
//!   device list ([`ControlState::from_parts`]): a part of another list (an
//!   unexpected mismatch under this pairing), or a part of the current list
//!   that doesn't read, fails the load, and the caller keeps delegated work
//!   stopped (never an empty state in its place: [`Feeds::Damaged`]). A
//!   store starts empty only when it is new, which a new host identity (a
//!   new pairing or verification, the only pairing change that permits a
//!   fresh state: Astation on #120, 2026-11-13) makes it: the old one is
//!   moved aside.
//!   The `control_*` tables are made by the first load: a store whose
//!   feeds never load (the hook off, no delegated task) has none, as on
//!   main.
//! - **Pending records** (I.5.4) wait, written with the record's
//!   transaction (a stop past the cursor survives a crash), and are applied
//!   again by [`FeedStore::reverify_pending`] after every device-list
//!   advance, every advance of host-work's applied device-list `seq`, and
//!   every revocation applied. **Evidence** (a record that failed
//!   verification, another body under a counted `record_id`, a possible
//!   replay, a record that doesn't parse) is kept and alerted. Both keep a
//!   count and the [`KEPT`] most recent; evidence is written at most once a
//!   minute ([`PERSIST_EVERY_MS`], as R9.3 bounds device-list evidence),
//!   counted in memory in between and written by [`FeedStore::tick`].
//! - **Alerts** (Decision 12: local, `runtime.log`) after the commit, at
//!   most one line an hour per source ([`ALERT_EVERY_MS`]): per origin for
//!   a feed, per carrying principal for a channel; what came within the
//!   hour is reported with its count when the hour has passed.
//! - **The standings** ([`ControlView`]) are the committed state's, and go
//!   to the start view's publisher at each commit (Decision 16), whatever
//!   host-work's pass does.
// The feeds' sync (Task 33) applies records, re-verifies pending ones and
// keeps unparsed ones; until it exists only the tests do.
#![cfg_attr(not(test), allow(dead_code))]
use super::{ControlView, FeedRef, SenderStanding};
use crate::runtime::host_work::Store;
use crate::session_protocol::membership::ListState;
use anyhow::{Context, Result, anyhow, bail};
use atem_client::canonical::{Numbers, parse_strict};
use atem_client::control::{ApplicationResult, Applied, ControlRecord, ControlState, FeedPos, Why};
use atem_client::membership::{HostNow, Membership};
use rusqlite::{Connection, Transaction, params};
use serde_json::{Value, json};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

/// Pending records and evidence each keep a count and this many of the
/// most recent (design I.5.4, as R9.3 bounds device-list evidence).
pub const KEPT: usize = 32;
/// Evidence is written at most this often (I.5.4); in between it is
/// counted in memory.
pub const PERSIST_EVERY_MS: u64 = 60_000;
/// One alert line an hour per source (I.5.4, Decision 12).
pub const ALERT_EVERY_MS: u64 = 3_600_000;
/// A part read at load: far above a part's bound (§11.1: about 32 KB).
const MAX_PART_BYTES: usize = 1 << 20;
/// A record kept as evidence keeps at most this much of its text.
const MAX_KEPT_TEXT: usize = 16 * 1024;
/// The feeds' tables, made by their first load (Task 32 review m8): a
/// store whose feeds never load (the hook off, no delegated task: main)
/// has none. Additive, as every host-work table.
const TABLES: &str = "
    CREATE TABLE IF NOT EXISTS control_feeds (
        origin TEXT NOT NULL, feed_id TEXT NOT NULL, cursor INTEGER NOT NULL,
        PRIMARY KEY(origin, feed_id)) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS control_principals (
        principal TEXT PRIMARY KEY, part TEXT NOT NULL) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS control_pending (
        n INTEGER PRIMARY KEY, principal TEXT NOT NULL, record_id TEXT NOT NULL,
        record TEXT NOT NULL, pos TEXT, source TEXT NOT NULL, reason TEXT NOT NULL,
        at_ms INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS control_evidence (
        n INTEGER PRIMARY KEY, source TEXT NOT NULL, record TEXT NOT NULL,
        reason TEXT NOT NULL, at_ms INTEGER NOT NULL);
    CREATE TABLE IF NOT EXISTS control_counts (
        kind TEXT PRIMARY KEY, count INTEGER NOT NULL) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS control_resets (
        origin TEXT PRIMARY KEY, restarted TEXT NOT NULL) WITHOUT ROWID;
    CREATE TABLE IF NOT EXISTS control_unread (
        one INTEGER PRIMARY KEY CHECK (one = 1)) WITHOUT ROWID;";

/// A run's count of control alerts and the latest one's text with when it
/// came, shared by whatever counts into it (`atem status`).
#[derive(Clone, Default)]
pub struct AlertTally(Arc<std::sync::Mutex<Tally>>);

/// How many alerts, and the latest one's text with when it came.
pub type Tally = (u64, Option<(String, std::time::Instant)>);

impl AlertTally {
    /// One alert more, `text` the latest.
    pub fn note(&self, text: String) {
        let mut t = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        t.0 += 1;
        t.1 = Some((text, std::time::Instant::now()));
    }

    /// How many, and the latest.
    pub fn get(&self) -> Tally {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// Where the start view's standings go when what they show commits
/// (Decision 16).
pub type StandingsPublisher = Box<dyn FnMut(BTreeMap<String, SenderStanding>) + Send + Sync>;

/// The device list doesn't serve (frozen, held, faulted or gone): nothing
/// applies, nothing is written, and the record isn't consumed (R9.3, R9.4;
/// design I.5.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListNotServing;

impl std::fmt::Display for ListNotServing {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("the device list doesn't serve: no control record applies")
    }
}

impl std::error::Error for ListNotServing {}

/// A position that isn't in the host's own Station's feed (§11.1's host
/// rule): refused before anything is written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NotOwnStation;

impl std::fmt::Display for NotOwnStation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("a feed position names another origin than the host's own Station")
    }
}

impl std::error::Error for NotOwnStation {}

/// A pending record applied again ([`FeedStore::reverify_pending`]): the
/// record, where it was read, and what it did now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reapplied {
    pub record: ControlRecord,
    pub pos: Option<FeedPos>,
    pub applied: Applied,
}

/// Where records come from: what alerts are rate-limited by (I.5.4).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Source {
    /// A feed of this Station origin.
    Feed(String),
    /// Records carried over a channel by this principal.
    Carrier(String),
}

impl Source {
    fn stored(&self) -> String {
        match self {
            Source::Feed(origin) => format!("feed:{origin}"),
            Source::Carrier(principal) => format!("carrier:{principal}"),
        }
    }

    fn read(text: &str) -> Option<Source> {
        match text.split_once(':')? {
            ("feed", origin) => Some(Source::Feed(origin.to_string())),
            ("carrier", principal) => Some(Source::Carrier(principal.to_string())),
            _ => None,
        }
    }

    fn label(&self) -> String {
        match self {
            Source::Feed(origin) => format!("the feed of {origin}"),
            Source::Carrier(principal) => format!("records carried by {principal}"),
        }
    }
}

/// A record kept pending.
#[derive(Debug, Clone)]
struct Pending {
    /// Its row (`control_pending.n`): oldest first.
    n: i64,
    record: ControlRecord,
    /// Its wire text, as stored.
    text: String,
    pos: Option<FeedPos>,
    source: Source,
}

/// Evidence counted and not written yet (at most [`KEPT`]).
#[derive(Debug, Clone)]
struct Kept {
    /// Its ordinal: the count when it was kept.
    n: u64,
    source: Source,
    text: String,
    reason: String,
    at_ms: u64,
}

/// The evidence's count, what isn't written yet and when it last was
/// (`CLOCK_MONOTONIC`, ms).
#[derive(Debug, Clone, Default)]
struct Evidence {
    count: u64,
    unwritten: VecDeque<Kept>,
    written_at: Option<u64>,
}

/// One record to alert about once its transaction committed.
#[derive(Debug, Clone)]
struct Alertable {
    source: Source,
    /// Why it was kept, and which record (never its content).
    what: String,
}

/// What the store holds in memory: the committed state, or the one a
/// transaction is building ([`FeedStore::begin`] to [`FeedStore::commit`]).
#[derive(Clone)]
struct Mem {
    state: ControlState,
    /// (origin, feed_id) → cursor.
    cursors: BTreeMap<(String, String), u64>,
    /// Oldest first, at most [`KEPT`].
    pending: Vec<Pending>,
    pending_count: u64,
    evidence: Evidence,
    /// Alerts of the transaction, raised once it committed.
    alerts: Vec<Alertable>,
    /// The resets pending, per origin: the feed whose read from 0 began
    /// (its cursor replaced), or `""` before it did (ruling T33c).
    resets: BTreeMap<String, String>,
    /// The store's control state was never read in full (ruling T35d, B):
    /// made with the tables, gone with the commit that first reads the own
    /// Station's feed up to its announced head.
    unread: bool,
}

/// Per source: when its last line went and what came since.
#[derive(Default)]
struct Hourly {
    last_ms: Option<u64>,
    counted: u64,
    latest: Option<Alertable>,
}

impl Hourly {
    /// A line for what was counted, when there is any and the hour since
    /// the last one passed (or none went yet).
    fn report(&mut self, now_ms: u64, lines: &mut Vec<String>) {
        let due = self
            .last_ms
            .is_none_or(|last| now_ms.saturating_sub(last) >= ALERT_EVERY_MS);
        if due && let Some(latest) = self.latest.take() {
            lines.push(alert_line(&latest, self.counted));
            self.counted = 0;
            self.last_ms = Some(now_ms);
        }
    }
}

/// The alerts' rate limit (in memory: a restart may alert again at once).
#[derive(Default)]
struct Alerts(BTreeMap<Source, Hourly>);

impl Alerts {
    fn note(&mut self, alert: Alertable, now_ms: u64, lines: &mut Vec<String>) {
        let h = self.0.entry(alert.source.clone()).or_default();
        h.counted += 1;
        h.latest = Some(alert);
        h.report(now_ms, lines);
    }

    fn due(&mut self, now_ms: u64, lines: &mut Vec<String>) {
        for h in self.0.values_mut() {
            h.report(now_ms, lines);
        }
    }
}

fn alert_line(alert: &Alertable, n: u64) -> String {
    format!(
        "atem runtime: {n} control record(s) from {} kept as evidence (the latest: {}); at most one such line an hour per source",
        alert.source.label(),
        alert.what
    )
}

/// A feed store's transaction ([`FeedStore::begin`]): a `BEGIN IMMEDIATE`
/// transaction on the store, the only one its records apply in. What the
/// caller writes with them (a record's effects) goes in the same
/// transaction (it derefs to it). Committed by [`FeedStore::commit`];
/// dropped, it rolls back, and the store forgets what it staged (nothing
/// builds on it).
pub struct FeedTx<'s> {
    tx: Option<Transaction<'s>>,
    /// Which of the store's transactions it is.
    generation: u64,
    /// The store's open transaction's generation (0: none).
    open: Arc<AtomicU64>,
}

impl<'s> std::ops::Deref for FeedTx<'s> {
    type Target = Transaction<'s>;
    fn deref(&self) -> &Transaction<'s> {
        self.tx
            .as_ref()
            .expect("a feed transaction is open until its commit")
    }
}

impl Drop for FeedTx<'_> {
    fn drop(&mut self) {
        // No longer the store's open transaction: what it staged is
        // forgotten at the store's next step.
        let _ = self
            .open
            .compare_exchange(self.generation, 0, Ordering::SeqCst, Ordering::SeqCst);
    }
}

/// The host's control feeds (the module docs give the rules).
pub struct FeedStore {
    /// As committed.
    mem: Mem,
    /// As the open transaction builds it.
    staged: Option<Mem>,
    /// Something failed in the open transaction: it is rolled back, never
    /// committed.
    failed: bool,
    /// The latest transaction's generation, and the open one's (shared
    /// with its [`FeedTx`]; 0 once it committed or was dropped).
    generation: u64,
    open: Arc<AtomicU64>,
    /// The host's own configured Station's origin.
    own: Option<String>,
    /// The device list it was loaded for: its account and genesis.
    list: (String, atem_client::encoding::Hash32),
    alerts: Alerts,
    /// The alerts raised in this run (their lines are hourly), and the
    /// latest's text with when it came (`atem status`, Task 33 review m7):
    /// a tally the bridge keeps for the run, so a store loaded again (a new
    /// identity) goes on counting (ruling T33c, N3).
    tally: AlertTally,
    /// `runtime.log` lines not taken yet.
    lines: Vec<String>,
    publisher: Option<StandingsPublisher>,
    clock: Box<dyn Fn() -> HostNow + Send + Sync>,
}

impl FeedStore {
    /// The control feeds `store` holds for `list`, the host's pinned device
    /// list (see the module docs). Parts of another list are logged and
    /// deleted; anything of the current list that doesn't read is an
    /// error: the caller keeps delegated work stopped.
    pub fn load(store: &Store, list: &Membership) -> Result<FeedStore> {
        let db = &store.db;
        Self::prepare(store)?;
        let rows: Vec<(String, String)> = {
            let mut st = db.prepare("SELECT principal, part FROM control_principals")?;
            st.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<rusqlite::Result<_>>()?
        };
        let mut parts = Vec::with_capacity(rows.len());
        for (principal, text) in rows {
            let part = parse_strict(text.as_bytes(), MAX_PART_BYTES, Numbers::IntegersOnly)
                .map_err(|e| {
                    anyhow!("the control state of {principal} isn't strict JSON: {e:?}")
                })?;
            parts.push((principal, part));
        }
        let loaded = ControlState::from_parts(list, parts)
            .map_err(|e| anyhow!("the stored control state doesn't read: {e}"))?;
        // Only a pairing change this host made itself starts a fresh state,
        // and that moves the store aside (a new host identity): parts of
        // another list in this pairing's store are damage, never cleaned up
        // (Astation on #120, 2026-11-13; ruling A6).
        if !loaded.foreign.is_empty() {
            bail!(
                "the stored control state of {} belongs to another device list than this pairing's",
                loaded.foreign.join(", ")
            );
        }
        let lines = Vec::new();
        let mut cursors = BTreeMap::new();
        {
            let mut st = db.prepare("SELECT origin, feed_id, cursor FROM control_feeds")?;
            let rows = st.query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, i64>(2)?,
                ))
            })?;
            for row in rows {
                let (origin, feed_id, cursor) = row?;
                let cursor = u64::try_from(cursor).context("a feed cursor below 0")?;
                cursors.insert((origin, feed_id), cursor);
            }
        }
        let mut pending = Vec::new();
        {
            let mut st =
                db.prepare("SELECT n, record, pos, source FROM control_pending ORDER BY n")?;
            let rows = st.query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, Option<String>>(2)?,
                    r.get::<_, String>(3)?,
                ))
            })?;
            for row in rows {
                let (n, text, pos, source) = row?;
                let record = ControlRecord::parse(text.as_bytes())
                    .map_err(|e| anyhow!("a pending control record doesn't read: {}", e.code()))?;
                let pos = pos.as_deref().map(read_pos).transpose()?;
                let source = Source::read(&source)
                    .ok_or_else(|| anyhow!("a pending control record's source doesn't read"))?;
                pending.push(Pending {
                    n,
                    record,
                    text,
                    pos,
                    source,
                });
            }
        }
        let resets = {
            let mut st = db.prepare("SELECT origin, restarted FROM control_resets")?;
            st.query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))?
                .collect::<rusqlite::Result<BTreeMap<_, _>>>()?
        };
        let unread = db.query_row("SELECT EXISTS(SELECT 1 FROM control_unread)", [], |r| {
            r.get(0)
        })?;
        let mem = Mem {
            resets,
            unread,
            state: loaded.state,
            cursors,
            pending,
            pending_count: count_of(db, "pending")?,
            evidence: Evidence {
                count: count_of(db, "evidence")?,
                ..Evidence::default()
            },
            alerts: Vec::new(),
        };
        Ok(FeedStore {
            mem,
            staged: None,
            failed: false,
            generation: 0,
            open: Arc::new(AtomicU64::new(0)),
            own: None,
            list: (list.account_id().to_string(), list.genesis_hash()),
            alerts: Alerts::default(),
            tally: AlertTally::default(),
            lines,
            publisher: None,
            clock: Box::new(crate::session_protocol::membership::host_now),
        })
    }

    /// The control tables of `store`, made if it has none yet, in one
    /// transaction with the durable "never read" mark (ruling T35d, B): a
    /// fresh store's control state is unchecked until its first complete
    /// read. A store that has them keeps its mark as it is (one from before
    /// the mark existed reads as read).
    pub fn prepare(store: &Store) -> Result<()> {
        let tx = store.immediate()?;
        let fresh = !Self::kept_in_db(&tx)?;
        tx.execute_batch(TABLES)?;
        if fresh {
            tx.execute("INSERT INTO control_unread(one) VALUES(1)", [])?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Whether `store` keeps a control state: its control tables exist
    /// (ruling T35d, A). Read only.
    pub fn kept_in(store: &Store) -> Result<bool> {
        Self::kept_in_db(&store.db)
    }

    fn kept_in_db(db: &Connection) -> Result<bool> {
        Ok(db.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='control_principals')",
            [],
            |r| r.get(0),
        )?)
    }

    /// The store's control state was never read in full (ruling T35d, B),
    /// as committed: services are unchecked until it is.
    pub fn never_read(&self) -> bool {
        self.mem.unread
    }

    /// The own Station's feed is read in full for the first time, in `tx`
    /// (the commit that reaches its announced head).
    pub fn clear_unread(&mut self, tx: &FeedTx) -> Result<()> {
        self.ours(tx)?;
        let mut mem = self.staged.take().unwrap_or_else(|| self.mem.clone());
        let out = (|| {
            tx.execute("DELETE FROM control_unread", [])?;
            mem.unread = false;
            Ok(())
        })();
        self.stage(mem, out)
    }

    /// A `BEGIN IMMEDIATE` transaction on `store` for records to apply in
    /// ([`FeedTx`]); whatever an earlier one left uncommitted is forgotten.
    /// One at a time: another can't begin while one is open.
    pub fn begin<'s>(&mut self, store: &'s Store) -> Result<FeedTx<'s>> {
        let tx = store.immediate()?;
        self.generation += 1;
        self.open.store(self.generation, Ordering::SeqCst);
        self.staged = None;
        self.failed = false;
        Ok(FeedTx {
            tx: Some(tx),
            generation: self.generation,
            open: self.open.clone(),
        })
    }

    /// Applies `rec`, read at `pos` of the host's own Station's feed, in
    /// `tx`, verified against `list` as it is now; `applied_seq` is
    /// host-work's applied device-list `seq`. Writes the touched parts, the
    /// cursor, a pending record and evidence when due; adopted at
    /// [`FeedStore::commit`]. After a record whose revocation applied, call
    /// [`FeedStore::reverify_pending`] (`interrupt`s may wait for it).
    /// Refused, with nothing written: [`ListNotServing`],
    /// [`NotOwnStation`]. Any other error fails `tx` (its commit rolls it
    /// back).
    pub fn apply(
        &mut self,
        tx: &FeedTx,
        rec: &ControlRecord,
        list: &ListState,
        pos: FeedPos,
        applied_seq: u64,
    ) -> Result<Applied> {
        let source = Source::Feed(pos.origin.clone());
        self.apply_from(tx, rec, list, Some(pos), source, applied_seq)
    }

    /// [`FeedStore::apply`] for a record `carrier` brought over a channel
    /// (no position): its alerts are rate-limited per carrier.
    pub fn apply_carried(
        &mut self,
        tx: &FeedTx,
        rec: &ControlRecord,
        list: &ListState,
        carrier: &str,
        applied_seq: u64,
    ) -> Result<Applied> {
        self.apply_from(
            tx,
            rec,
            list,
            None,
            Source::Carrier(carrier.to_string()),
            applied_seq,
        )
    }

    fn apply_from(
        &mut self,
        tx: &FeedTx,
        rec: &ControlRecord,
        list: &ListState,
        pos: Option<FeedPos>,
        source: Source,
        applied_seq: u64,
    ) -> Result<Applied> {
        self.ours(tx)?;
        serving(list)?;
        if let Some(p) = &pos {
            self.own_position(p)?;
        }
        let now = (self.clock)();
        let mut mem = self.staged.take().unwrap_or_else(|| self.mem.clone());
        let out = mem.apply(tx, rec, list, pos, &source, applied_seq, &now);
        self.stage(mem, out)
    }

    /// The host's own Station's feed `pos.feed_id` is read up to
    /// `pos.feed_seq` (a page with no record, a reset's empty feed), in
    /// `tx`.
    pub fn advance(&mut self, tx: &FeedTx, pos: FeedPos) -> Result<()> {
        self.ours(tx)?;
        self.own_position(&pos)?;
        let mut mem = self.staged.take().unwrap_or_else(|| self.mem.clone());
        let out = mem.advance(tx, &pos);
        self.stage(mem, out)
    }

    /// The host's own Station's feed `pos.feed_id` is read again from its
    /// start (a reset, §11.4: a new `feed_id`, or a head below the cursor),
    /// in `tx`: the origin's cursors go (one feed per origin) and this
    /// feed's is `pos.feed_seq` exactly, lower than it was if need be. In
    /// the transaction of the reset's first page, before its records: the
    /// old cursor goes then, and only then.
    pub fn restart(&mut self, tx: &FeedTx, pos: FeedPos) -> Result<()> {
        self.ours(tx)?;
        self.own_position(&pos)?;
        let mut mem = self.staged.take().unwrap_or_else(|| self.mem.clone());
        let out = mem.restart(tx, &pos);
        self.stage(mem, out)
    }

    /// A reset of the host's own Station's feed was found (ruling T33c):
    /// marked durably, in its own transaction, before anything is asked
    /// for it; the read from 0 hasn't begun (a mark already there is
    /// replaced: a new reset during a read starts it again). Cleared only
    /// by the commit that reads the feed from 0 up to the announced head
    /// ([`FeedStore::clear_reset`]); while it is there, a start reads the
    /// feed from 0 again (or goes on with a read that began).
    pub fn mark_reset(&mut self, store: &Store, origin: &str) -> Result<()> {
        if self.own.as_deref() != Some(origin) {
            return Err(NotOwnStation.into());
        }
        let tx = self.begin(store)?;
        let mut mem = self.staged.take().unwrap_or_else(|| self.mem.clone());
        let out = mem.set_reset(&tx, origin, "");
        self.stage(mem, out)?;
        self.commit(tx)
    }

    /// The reset of `pos.origin` began its read from 0 of `pos.feed_id`
    /// (its cursor replaced), in `tx`; nothing without a reset pending.
    pub fn reset_begun(&mut self, tx: &FeedTx, pos: &FeedPos) -> Result<()> {
        self.ours(tx)?;
        let mut mem = self.staged.take().unwrap_or_else(|| self.mem.clone());
        let out = if mem.resets.contains_key(&pos.origin) {
            mem.set_reset(tx, &pos.origin, &pos.feed_id)
        } else {
            Ok(())
        };
        self.stage(mem, out)
    }

    /// The reset of `origin` is done: its feed read from 0 up to the
    /// announced head, in `tx` (the commit that completes the read).
    pub fn clear_reset(&mut self, tx: &FeedTx, origin: &str) -> Result<()> {
        self.ours(tx)?;
        let mut mem = self.staged.take().unwrap_or_else(|| self.mem.clone());
        let out = (|| {
            tx.execute("DELETE FROM control_resets WHERE origin=?1", [origin])?;
            mem.resets.remove(origin);
            Ok(())
        })();
        self.stage(mem, out)
    }

    /// The reset of `origin` pending, as committed: the feed whose read
    /// from 0 began, or `""` before it did.
    pub fn reset_pending(&self, origin: &str) -> Option<&str> {
        self.mem.resets.get(origin).map(String::as_str)
    }

    /// A record of the feed at `pos` that doesn't parse (`code`, the
    /// parse's): kept as evidence, the cursor past it, in `tx`.
    pub fn unparsed(&mut self, tx: &FeedTx, text: &str, code: &str, pos: FeedPos) -> Result<()> {
        self.ours(tx)?;
        self.own_position(&pos)?;
        let now = (self.clock)();
        let mut mem = self.staged.take().unwrap_or_else(|| self.mem.clone());
        let out = (|| {
            mem.advance(tx, &pos)?;
            let what = format!("{code}, a record that doesn't parse");
            mem.keep_evidence(tx, Source::Feed(pos.origin.clone()), text, code, what, &now)
        })();
        self.stage(mem, out)
    }

    /// The pending records applied again, oldest first, in `tx`, against
    /// `list` as it is now (I.5.4: after every device-list advance, every
    /// advance of host-work's applied `seq` and every revocation applied),
    /// until none changes: those no longer pending leave the store and are
    /// returned with what they did. Nothing while the list doesn't serve.
    pub fn reverify_pending(
        &mut self,
        tx: &FeedTx,
        list: &ListState,
        applied_seq: u64,
    ) -> Result<Vec<Reapplied>> {
        self.ours(tx)?;
        if serving(list).is_err() {
            return Ok(Vec::new());
        }
        let now = (self.clock)();
        let mut mem = self.staged.take().unwrap_or_else(|| self.mem.clone());
        let out = mem.reverify(tx, list, applied_seq, &now);
        self.stage(mem, out)
    }

    /// Commits `tx`, then adopts what it applied, raises its alerts and
    /// publishes the standings. A transaction in which something failed is
    /// rolled back instead (an error), as is one whose commit fails: the
    /// state applied on is kept.
    pub fn commit(&mut self, mut tx: FeedTx) -> Result<()> {
        self.ours(&tx)?;
        let inner = tx.tx.take().expect("open until its commit");
        drop(tx);
        if self.failed {
            drop(inner);
            self.discard();
            bail!("a control record's transaction failed; rolled back");
        }
        if let Err(e) = inner.commit() {
            self.discard();
            return Err(e.into());
        }
        if let Some(mut mem) = self.staged.take() {
            let alerts = std::mem::take(&mut mem.alerts);
            self.mem = mem;
            let now = (self.clock)().mono_ms;
            for alert in alerts {
                self.tally.note(format!(
                    "a control record from {} kept as evidence ({})",
                    alert.source.label(),
                    alert.what
                ));
                self.alerts.note(alert, now, &mut self.lines);
            }
            self.publish();
        }
        Ok(())
    }

    /// Forgets what the open transaction applied (it was rolled back or
    /// dropped).
    fn discard(&mut self) {
        self.staged = None;
        self.failed = false;
    }

    /// `tx` is this store's open transaction, its latest: what is staged
    /// is its own. Anything else is refused, nothing done.
    fn ours(&mut self, tx: &FeedTx) -> Result<()> {
        if self.open.load(Ordering::SeqCst) != self.generation {
            // The latest transaction is gone (dropped): nothing of it stays.
            self.discard();
        }
        if !Arc::ptr_eq(&tx.open, &self.open)
            || tx.generation != self.generation
            || self.open.load(Ordering::SeqCst) != tx.generation
        {
            bail!("not this feed store's open transaction");
        }
        Ok(())
    }

    /// What is due outside a record's transaction: evidence counted in
    /// memory, written once a minute has passed since the last write (in
    /// its own transaction); an alert line for a source whose hour passed
    /// with records counted.
    pub fn tick(&mut self, store: &Store) -> Result<()> {
        if self.open.load(Ordering::SeqCst) != self.generation {
            self.discard();
        }
        let now = (self.clock)();
        if !self.mem.evidence.unwritten.is_empty() && self.mem.evidence.due(&now) {
            let mut evidence = self.mem.evidence.clone();
            let tx = store.immediate()?;
            evidence.write(&tx, &now)?;
            tx.commit()?;
            self.mem.evidence = evidence;
        }
        self.alerts.due(now.mono_ms, &mut self.lines);
        Ok(())
    }

    /// The `runtime.log` lines not taken yet (alerts).
    pub fn take_lines(&mut self) -> Vec<String> {
        std::mem::take(&mut self.lines)
    }

    /// The host's own configured Station's origin (normalized, as
    /// `StationLink::origin`): the only one a position may name.
    pub fn set_own_origin(&mut self, origin: Option<String>) {
        self.own = origin;
    }

    /// The position `feed_seq` of the feed `feed_id` of the host's own
    /// Station: none while the host has none.
    pub fn position(&self, feed_id: &str, feed_seq: u64) -> Option<FeedPos> {
        Some(FeedPos {
            origin: self.own.clone()?,
            feed_id: feed_id.to_string(),
            feed_seq,
        })
    }

    /// The feed of `origin` the host reads, as committed: its `feed_id`
    /// and cursor (one feed per origin, Task 32 review m4). None when it has
    /// read none, or holds more than one (a store from before m4): unknown,
    /// so the feed is read from its start.
    pub fn current_feed(&self, origin: &str) -> Option<(String, u64)> {
        let mut of = self
            .mem
            .cursors
            .iter()
            .filter(|((o, _), _)| o == origin)
            .map(|((_, feed_id), cursor)| (feed_id.clone(), *cursor));
        let one = of.next()?;
        of.next().is_none().then_some(one)
    }

    /// Whether it was loaded for `list` (its account and genesis): the
    /// feeds of another list (a re-pin the host's pass hasn't moved the
    /// store aside for yet) take no record.
    pub fn for_list(&self, list: &Membership) -> bool {
        self.list.0 == list.account_id() && self.list.1 == list.genesis_hash()
    }

    /// The account and genesis of the device list it was loaded for.
    pub fn list_id(&self) -> &(String, atem_client::encoding::Hash32) {
        &self.list
    }

    /// The host's own Station's origin, as set.
    pub fn own_origin(&self) -> Option<&str> {
        self.own.as_deref()
    }

    /// Whether a record may apply against `list` now: it serves (not
    /// frozen, held, faulted or gone).
    pub fn serves(list: &ListState) -> bool {
        serving(list).is_ok()
    }

    /// The committed cursor of a feed.
    pub fn cursor(&self, origin: &str, feed_id: &str) -> Option<u64> {
        self.mem
            .cursors
            .get(&(origin.to_string(), feed_id.to_string()))
            .copied()
    }

    /// The committed standings, by principal.
    pub fn standings(&self) -> BTreeMap<String, SenderStanding> {
        self.mem
            .state
            .principals()
            .into_iter()
            .map(|principal| {
                let standing = self.standing(&principal);
                (principal, standing)
            })
            .collect()
    }

    /// Where the standings go at each commit ([`FeedStore::publish`] gives
    /// them the committed ones now).
    pub fn set_publisher(&mut self, publisher: StandingsPublisher) {
        self.publisher = Some(publisher);
    }

    /// The committed standings to the publisher, now.
    pub fn publish(&mut self) {
        let standings = self.standings();
        if let Some(publisher) = self.publisher.as_mut() {
            publisher(standings);
        }
    }

    /// The run's alert tally this store counts into (the bridge's: it
    /// outlives a store loaded again).
    pub fn set_alert_tally(&mut self, tally: AlertTally) {
        self.tally = tally;
    }

    /// Records kept as evidence, ever (this list's store).
    pub fn evidence_count(&self) -> u64 {
        self.mem.evidence.count
    }

    /// Records kept pending, ever.
    pub fn pending_count(&self) -> u64 {
        self.mem.pending_count
    }

    /// Records pending now (at most [`KEPT`]).
    pub fn pending_len(&self) -> usize {
        self.mem.pending.len()
    }

    /// Tests: readings from `clock`.
    #[cfg(test)]
    pub fn with_clock(mut self, clock: impl Fn() -> HostNow + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }

    fn own_position(&self, pos: &FeedPos) -> Result<()> {
        if self.own.as_deref() == Some(pos.origin.as_str()) {
            Ok(())
        } else {
            Err(NotOwnStation.into())
        }
    }

    /// Keeps what a step of the open transaction built, or marks the
    /// transaction failed.
    fn stage<T>(&mut self, mem: Mem, out: Result<T>) -> Result<T> {
        match out {
            Ok(value) => {
                self.staged = Some(mem);
                Ok(value)
            }
            Err(e) => {
                self.staged = None;
                self.failed = true;
                Err(e)
            }
        }
    }
}

impl ControlView for FeedStore {
    /// As committed.
    fn standing(&self, principal: &str) -> SenderStanding {
        let s = self.mem.state.standing(principal);
        SenderStanding {
            revoked: s.revoked,
            held: s.held,
            coverage: s.coverage.map(|c| FeedRef {
                origin: c.origin,
                feed_id: c.feed_id,
            }),
        }
    }
}

impl Mem {
    #[allow(clippy::too_many_arguments)]
    fn apply(
        &mut self,
        tx: &Transaction,
        rec: &ControlRecord,
        list: &ListState,
        pos: Option<FeedPos>,
        source: &Source,
        applied_seq: u64,
        now: &HostNow,
    ) -> Result<Applied> {
        let t = self
            .state
            .apply(rec, &list.membership, pos.clone(), applied_seq);
        write_parts(tx, &t.next, &t.touched())?;
        if let Some(p) = &pos {
            self.advance(tx, p)?;
        }
        let applied = t.applied.clone();
        self.state = t.next;
        if applied.record_result == ApplicationResult::Pending {
            self.keep_pending(tx, rec, pos, source, &applied, now)?;
        }
        if applied.evidence {
            let what = what(rec, &applied);
            let reason = why_code(&applied);
            self.keep_evidence(tx, source.clone(), &record_text(rec), reason, what, now)?;
        }
        Ok(applied)
    }

    fn reverify(
        &mut self,
        tx: &Transaction,
        list: &ListState,
        applied_seq: u64,
        now: &HostNow,
    ) -> Result<Vec<Reapplied>> {
        let mut out = Vec::new();
        loop {
            let mut changed = false;
            let mut i = 0;
            while i < self.pending.len() {
                let p = self.pending[i].clone();
                let t = self
                    .state
                    .apply(&p.record, &list.membership, p.pos.clone(), applied_seq);
                write_parts(tx, &t.next, &t.touched())?;
                self.state = t.next;
                if t.applied.record_result == ApplicationResult::Pending {
                    i += 1;
                    continue;
                }
                tx.execute("DELETE FROM control_pending WHERE n=?1", [p.n])?;
                self.pending.remove(i);
                if t.applied.evidence {
                    let what = what(&p.record, &t.applied);
                    let reason = why_code(&t.applied);
                    self.keep_evidence(tx, p.source.clone(), &p.text, reason, what, now)?;
                }
                out.push(Reapplied {
                    record: p.record,
                    pos: p.pos,
                    applied: t.applied,
                });
                changed = true;
            }
            if !changed {
                return Ok(out);
            }
        }
    }

    /// The feed's cursor past `pos` (it never goes back). One feed per
    /// origin is kept (Task 32 review m4): another feed of the origin (the
    /// one a reset replaced, or one a carrier minted) goes in the same
    /// transaction, so feed ids never add rows.
    fn advance(&mut self, tx: &Connection, pos: &FeedPos) -> Result<()> {
        let key = (pos.origin.clone(), pos.feed_id.clone());
        let cursor = self
            .cursors
            .get(&key)
            .map_or(pos.feed_seq, |c| (*c).max(pos.feed_seq));
        tx.execute(
            "DELETE FROM control_feeds WHERE origin=?1 AND feed_id<>?2",
            params![pos.origin, pos.feed_id],
        )?;
        self.cursors
            .retain(|(origin, feed_id), _| *origin != pos.origin || *feed_id == pos.feed_id);
        tx.execute(
            "INSERT INTO control_feeds(origin,feed_id,cursor) VALUES(?1,?2,?3)
            ON CONFLICT(origin,feed_id) DO UPDATE SET cursor=excluded.cursor",
            params![pos.origin, pos.feed_id, i64::try_from(cursor)?],
        )?;
        self.cursors.insert(key, cursor);
        Ok(())
    }

    /// `origin`'s reset mark, `restarted` the feed whose read from 0 began
    /// (`""`: none yet).
    fn set_reset(&mut self, tx: &Connection, origin: &str, restarted: &str) -> Result<()> {
        tx.execute(
            "INSERT INTO control_resets(origin,restarted) VALUES(?1,?2)
            ON CONFLICT(origin) DO UPDATE SET restarted=excluded.restarted",
            params![origin, restarted],
        )?;
        self.resets
            .insert(origin.to_string(), restarted.to_string());
        Ok(())
    }

    /// The origin's cursors replaced by `pos`'s, exactly ([`FeedStore::restart`]).
    fn restart(&mut self, tx: &Connection, pos: &FeedPos) -> Result<()> {
        tx.execute(
            "DELETE FROM control_feeds WHERE origin=?1",
            params![pos.origin],
        )?;
        self.cursors.retain(|(origin, _), _| *origin != pos.origin);
        tx.execute(
            "INSERT INTO control_feeds(origin,feed_id,cursor) VALUES(?1,?2,?3)",
            params![pos.origin, pos.feed_id, i64::try_from(pos.feed_seq)?],
        )?;
        self.cursors
            .insert((pos.origin.clone(), pos.feed_id.clone()), pos.feed_seq);
        Ok(())
    }

    /// `rec` kept pending (once: the same record again is the one kept),
    /// the oldest beyond [`KEPT`] dropped, the count raised.
    fn keep_pending(
        &mut self,
        tx: &Connection,
        rec: &ControlRecord,
        pos: Option<FeedPos>,
        source: &Source,
        applied: &Applied,
        now: &HostNow,
    ) -> Result<()> {
        let text = record_text(rec);
        let principal = rec.principal().name();
        if self.pending.iter().any(|p| p.text == text) {
            return Ok(());
        }
        tx.execute(
            "INSERT INTO control_pending(principal,record_id,record,pos,source,reason,at_ms)
            VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![
                principal,
                rec.record_id(),
                text,
                pos.as_ref().map(pos_text),
                source.stored(),
                why_code(applied),
                i64::try_from(now.wall_ms)?,
            ],
        )?;
        self.pending.push(Pending {
            n: tx.last_insert_rowid(),
            record: rec.clone(),
            text,
            pos,
            source: source.clone(),
        });
        while self.pending.len() > KEPT {
            let oldest = self.pending.remove(0);
            tx.execute("DELETE FROM control_pending WHERE n=?1", [oldest.n])?;
        }
        self.pending_count += 1;
        write_count(tx, "pending", self.pending_count)
    }

    /// A record kept as evidence: counted, its alert raised after the
    /// commit, written now when a minute passed since the last write.
    fn keep_evidence(
        &mut self,
        tx: &Connection,
        source: Source,
        text: &str,
        reason: &str,
        what: String,
        now: &HostNow,
    ) -> Result<()> {
        let ev = &mut self.evidence;
        ev.count += 1;
        ev.unwritten.push_back(Kept {
            n: ev.count,
            source: source.clone(),
            text: bounded(text),
            reason: reason.to_string(),
            at_ms: now.wall_ms,
        });
        while ev.unwritten.len() > KEPT {
            ev.unwritten.pop_front();
        }
        self.alerts.push(Alertable { source, what });
        if self.evidence.due(now) {
            self.evidence.write(tx, now)?;
        }
        Ok(())
    }
}

impl Evidence {
    /// A write may happen now: never yet in this run, or a minute ago.
    fn due(&self, now: &HostNow) -> bool {
        self.written_at
            .is_none_or(|at| now.mono_ms.saturating_sub(at) >= PERSIST_EVERY_MS)
    }

    /// What isn't written yet, the rows beyond the [`KEPT`] most recent
    /// dropped, the count.
    fn write(&mut self, tx: &Connection, now: &HostNow) -> Result<()> {
        for k in &self.unwritten {
            tx.execute(
                "INSERT OR REPLACE INTO control_evidence(n,source,record,reason,at_ms)
                VALUES(?1,?2,?3,?4,?5)",
                params![
                    i64::try_from(k.n)?,
                    k.source.stored(),
                    k.text,
                    k.reason,
                    i64::try_from(k.at_ms)?
                ],
            )?;
        }
        let oldest_kept = self.count.saturating_sub(KEPT as u64);
        tx.execute(
            "DELETE FROM control_evidence WHERE n<=?1",
            [i64::try_from(oldest_kept)?],
        )?;
        write_count(tx, "evidence", self.count)?;
        self.unwritten.clear();
        self.written_at = Some(now.mono_ms);
        Ok(())
    }
}

/// The parts of `next` that `touched` names, written; a principal with no
/// part left, deleted.
fn write_parts(tx: &Connection, next: &ControlState, touched: &[String]) -> Result<()> {
    for principal in touched {
        match next.part(principal) {
            Some(part) => tx.execute(
                "INSERT INTO control_principals(principal,part) VALUES(?1,?2)
                ON CONFLICT(principal) DO UPDATE SET part=excluded.part",
                params![principal, part.to_string()],
            )?,
            None => tx.execute(
                "DELETE FROM control_principals WHERE principal=?1",
                [principal],
            )?,
        };
    }
    Ok(())
}

fn write_count(tx: &Connection, kind: &str, count: u64) -> Result<()> {
    tx.execute(
        "INSERT INTO control_counts(kind,count) VALUES(?1,?2)
        ON CONFLICT(kind) DO UPDATE SET count=excluded.count",
        params![kind, i64::try_from(count)?],
    )?;
    Ok(())
}

fn count_of(db: &Connection, kind: &str) -> Result<u64> {
    use rusqlite::OptionalExtension;
    let count: Option<i64> = db
        .query_row(
            "SELECT count FROM control_counts WHERE kind=?1",
            [kind],
            |r| r.get(0),
        )
        .optional()?;
    Ok(u64::try_from(count.unwrap_or(0))?)
}

/// A position as `control_pending.pos` keeps it.
fn pos_text(pos: &FeedPos) -> String {
    json!({"origin": pos.origin, "feed_id": pos.feed_id, "feed_seq": pos.feed_seq}).to_string()
}

fn read_pos(text: &str) -> Result<FeedPos> {
    let v: Value = serde_json::from_str(text)?;
    let field = |k: &str| {
        v.get(k)
            .ok_or_else(|| anyhow!("a pending record's position has no {k}"))
    };
    Ok(FeedPos {
        origin: field("origin")?
            .as_str()
            .context("a position's origin")?
            .to_string(),
        feed_id: field("feed_id")?
            .as_str()
            .context("a position's feed_id")?
            .to_string(),
        feed_seq: field("feed_seq")?
            .as_u64()
            .context("a position's feed_seq")?,
    })
}

/// A record's wire text.
fn record_text(rec: &ControlRecord) -> String {
    rec.object().to_json().to_string()
}

/// At most [`MAX_KEPT_TEXT`] bytes of `text`, cut at a character.
fn bounded(text: &str) -> String {
    if text.len() <= MAX_KEPT_TEXT {
        return text.to_string();
    }
    let mut end = MAX_KEPT_TEXT;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_string()
}

fn why_code(applied: &Applied) -> &'static str {
    applied.why.map_or("evidence", Why::code)
}

/// What an alert says of a record: why, its principal and id.
fn what(rec: &ControlRecord, applied: &Applied) -> String {
    format!(
        "{}, {} record {}",
        why_code(applied),
        rec.principal().name(),
        rec.record_id()
    )
}

/// Whether a record may apply now: the device list serves (R9.3, R9.4).
fn serving(list: &ListState) -> Result<()> {
    if list.frozen
        || list.held
        || list.faulted
        || list.unpaired
        || list.membership.frozen().is_some()
    {
        return Err(ListNotServing.into());
    }
    Ok(())
}

/// Whether the host's control feeds loaded.
pub enum Feeds {
    /// Not loaded yet: no store, or no device list.
    Unloaded,
    Loaded(Box<FeedStore>),
    /// The stored control state of the pinned list couldn't be read: no
    /// delegated task starts until it is repaired (fail closed).
    Damaged,
}

/// Tests: a record of `service:<service>` in the feed `feed_id` of
/// `origin`, signed with `log`'s key `key` (the service's own, or another,
/// which gives a bad signature), as its Station issues it.
#[cfg(test)]
pub(crate) fn signed_record(
    log: &crate::session_protocol::membership::r9log::TestLog,
    service: &str,
    key: &str,
    action: atem_client::control::ControlAction,
    record_id: String,
    (origin, feed_id): (&str, &str),
    issued_at: u64,
) -> ControlRecord {
    use crate::session_protocol::membership::r9log::auth;
    use atem_client::KeyProvider;
    use atem_client::control::{
        ControlAbout, ControlBody, ControlFeed, ControlPrincipal, ControlSigner, build_control,
        principal_key_of,
    };
    let public = log.keys.public_key(&auth(service)).unwrap();
    let body = ControlBody {
        account_id: log.account.clone(),
        genesis_hash: log.genesis_hash(),
        feed: Some(ControlFeed {
            origin: origin.into(),
            feed_id: feed_id.into(),
        }),
        principal: ControlPrincipal::Service(service.into()),
        principal_key: Some(principal_key_of(&public).unwrap()),
        signer: ControlSigner::Principal,
        action,
        record_id,
        issued_at,
        about: ControlAbout {
            integration_id: Some(format!("i-{service}")),
            by: "owner".into(),
        },
    };
    let object = build_control(&log.keys, &auth(key), &body).unwrap();
    ControlRecord::from_signed(object).unwrap()
}

#[cfg(test)]
#[path = "feeds_tests.rs"]
mod tests;

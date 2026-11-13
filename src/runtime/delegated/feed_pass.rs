//! The host's control-feed sync in the bridge (the delegated host-work
//! design I.5.2, I.5.4, I.5.8; host-work-v1 §11.4; step 4's Decisions 12,
//! 16, 20): the Station link's `heads` and pages handed to the sync
//! ([`FeedSync`]) with the feed store, the delegated clock and the device
//! list as it committed; the gate's feed part copied into the start view as
//! it changes; the pending records re-verified when the list moves; the
//! `atem status` line.
//!
//! - **When the sync runs.** On every pass with `host.delegated` on, the
//!   feeds loaded and the receipt database healthy, a pause included (an
//!   invalid `runtime.toml`, hosting switched off): a record's standing is
//!   published at its commit whatever host-work's pass does (Decision 16),
//!   so a sender revoked during a pause doesn't keep its standing. A
//!   runtime started paused loads the feeds when hosting resumes; until
//!   then nothing syncs, services are `busy` and no delegated task starts
//!   (fail closed).
//! - **Re-verification** (Task 32 review). The pending records are applied
//!   again once at start after the load, and whenever the device list the
//!   start view holds moved (its head, every commit path alike: carriages,
//!   the host's own fetch, recovery approvals and vetoes), in their own
//!   transaction; after a record whose revocation applied, in that
//!   record's own (the sync does it). Host-work's applied device-list
//!   `seq` is 0 in step 4: no host sender's revoke entry is applied here
//!   (`host.senders` isn't served), so a host principal's interrupt waits.
//! - **What the feed store sees** (Task 33 review I1). The sync runs
//!   whether or not host-work's pass does (a pause skips it), so each step
//!   gives the store the Station link's own origin itself (positions name
//!   it only), and takes the store only while it was loaded for the device
//!   list that committed (a re-pin the pass hasn't moved the store aside for
//!   yet takes nothing).
//! - **Never with the start view locked.** A commit publishes the
//!   standings, which locks the view: the list is copied out first.
use super::*;
use crate::runtime::delegated::feeds::Reapplied;
use crate::runtime::delegated::station::Call;
use crate::runtime::delegated::sync::{Clocks, Closed, PageCx};
use crate::session_protocol::membership::ListState;
use atem_client::control::{ControlSyncResult, Heads, RelayError};

/// Host-work's applied device-list `seq` in step 4 (see the module docs).
const APPLIED_SEQ: u64 = 0;

/// The re-verified records kept for Task 35 at most (`keep_reapplied`).
pub(crate) const KEPT_REAPPLIED: usize = 64;

/// The feed store when its records may be read and applied: loaded for
/// the device list that committed (`list`: the start view's; feeds of
/// another list, a re-pin the pass hasn't moved the store aside for yet,
/// take nothing), the receipt database healthy.
fn loaded<'a>(work: &'a State, list: Option<&ListState>) -> Option<&'a FeedStore> {
    match (&work.feeds, &work.store, work.error, list) {
        (Feeds::Loaded(feeds), Some(_), false, Some(list)) if feeds.for_list(&list.membership) => {
            Some(feeds)
        }
        _ => None,
    }
}

/// The host's elapsed-time clocks now: the monotonic one (the pacing's) and
/// the delegated clock's boot-time counter (I.6.5; Task 33 review I2).
pub(crate) fn sync_clocks() -> Clocks {
    Clocks {
        mono_ms: host_now().mono_ms,
        boot_ms: crate::runtime::host_clock::boot_ms(),
    }
}

impl HostBridge {
    /// The committed device list (copied out of the start view), and the
    /// feed store given the Station link's own origin: positions name it
    /// only, and the sync hands the store pages and `heads` whether or not
    /// host-work's pass ran (a pause skips it; Task 33 review I1).
    fn sync_list(&mut self) -> Option<ListState> {
        let own = self
            .station
            .as_ref()
            .and_then(|station| station.link())
            .and_then(|link| link.origin.clone());
        if let Feeds::Loaded(feeds) = &mut self.work.feeds
            && feeds.own_origin() != own.as_deref()
        {
            feeds.set_own_origin(own);
        }
        self.start_view().list.clone()
    }

    /// A reset the sync found and hasn't marked yet: marked in the feed
    /// store, durably, before anything is asked for it (ruling T33c); the
    /// read from 0 to ask then, if it may go now. A write that fails is
    /// logged (the first, then at powers of two) and tried again at the next
    /// step: nothing is asked meanwhile, the gate stays closed.
    fn persist_reset_mark(&mut self, list: Option<&ListState>) -> Option<Call> {
        let fits = loaded(&self.work, list).is_some();
        let State {
            feeds: Feeds::Loaded(feeds),
            store: Some(store),
            ..
        } = &mut self.work
        else {
            return None;
        };
        let station = self.station.as_mut()?;
        if !fits {
            return None;
        }
        match station.feed.persist_mark(store, feeds) {
            Ok(ask) => ask.map(Call::Sync),
            Err(error) => {
                if station.feed.mark_failed() {
                    eprintln!(
                        "atem runtime: a control feed's reset couldn't be marked ({error:#}); nothing is asked of it until it is"
                    );
                }
                None
            }
        }
    }

    /// The pass's clocks: the gate follows them (60 s without `heads`)
    /// with no call; the start view gets the change.
    pub(crate) fn feed_advance(&mut self, now: Clocks) {
        let list = self.sync_list();
        let feeds = loaded(&self.work, list.as_ref());
        if let Some(station) = self.station.as_mut() {
            station.feed.advance(now, feeds);
        }
        // No reset's mark is written here: the pass's tick (`feed_tick`, in
        // the same pass) writes it and returns the read from 0 it lets go
        // (Task 33 re-review 2, R2-2: a call asked here would be dropped).
        self.publish_feed_gates();
    }

    /// The sync's calls due at the pass (a timeout, a feed that needs a
    /// page while a recent `heads` announced it).
    pub(crate) fn feed_tick(&mut self, now: Clocks) -> Vec<Call> {
        let list = self.sync_list();
        let feeds = loaded(&self.work, list.as_ref());
        let Some(station) = self.station.as_mut() else {
            return Vec::new();
        };
        let mut calls: Vec<Call> = station
            .feed
            .tick(now, feeds)
            .into_iter()
            .map(Call::Sync)
            .collect();
        calls.extend(self.persist_reset_mark(list.as_ref()));
        calls
    }

    /// The Station's `heads`: the sync's calls.
    pub(crate) fn feed_heads(&mut self, heads: &Heads) -> Vec<Call> {
        let list = self.sync_list();
        let fits = loaded(&self.work, list.as_ref()).is_some();
        let State {
            feeds,
            store,
            clock,
            error,
            ..
        } = &mut self.work;
        let feeds = match &*feeds {
            Feeds::Loaded(feeds) if fits => Some(feeds.as_ref()),
            _ => None,
        };
        let clock = match (clock.as_mut(), store.as_ref(), *error) {
            (Some(clock), Some(store), false) => Some((clock, store)),
            _ => None,
        };
        let Some(station) = self.station.as_mut() else {
            return Vec::new();
        };
        let mut calls: Vec<Call> = station
            .feed
            .on_heads(heads, clock, feeds)
            .into_iter()
            .map(Call::Sync)
            .collect();
        calls.extend(self.persist_reset_mark(list.as_ref()));
        calls
    }

    /// A page (or a message that was one, refused by the reader): applied
    /// against the device list as it committed. Its effects on tasks are
    /// PR 11's (Task 35); here the standings follow at its commit. The next
    /// page, when it asks one at once.
    pub(crate) fn feed_page(&mut self, page: Result<ControlSyncResult, RelayError>) -> Vec<Call> {
        // Copied out: a commit publishes the standings into the view.
        let list = self.sync_list();
        let fits = loaded(&self.work, list.as_ref()).is_some();
        let State {
            feeds,
            store,
            clock,
            error,
            ..
        } = &mut self.work;
        let healthy = !*error;
        let cx = match (feeds, store.as_ref(), list.as_ref()) {
            (Feeds::Loaded(feeds), Some(store), Some(list)) if fits => Some(PageCx {
                store,
                feeds: feeds.as_mut(),
                list,
                applied_seq: APPLIED_SEQ,
            }),
            _ => None,
        };
        let clock = match (clock.as_mut(), store.as_ref()) {
            (Some(clock), Some(store)) if healthy => Some((clock, store)),
            _ => None,
        };
        let Some(station) = self.station.as_mut() else {
            return Vec::new();
        };
        let mut calls: Vec<Call> = match station.feed.on_page(page, clock, cx) {
            Ok(synced) => synced.next.map(Call::Sync).into_iter().collect(),
            Err(error) => {
                if station.feed.failed() {
                    eprintln!(
                        "atem runtime: a control feed page couldn't be applied ({error:#}); nothing of it applied, asked again"
                    );
                }
                Vec::new()
            }
        };
        calls.extend(self.persist_reset_mark(list.as_ref()));
        calls
    }

    /// The pending control records applied again when the device list the
    /// start view holds moved since they last were (and once after the
    /// feeds load), in their own transaction. Nothing while the list
    /// doesn't serve; a transaction that fails is tried again at the next
    /// pass.
    pub(crate) fn feeds_reverify(&mut self) {
        if !self.may_hold_delegated() {
            return;
        }
        let Some(list) = self.start_view().list.clone() else {
            return;
        };
        if !FeedStore::serves(&list) {
            return;
        }
        let head = list.membership.head();
        let key = (head.seq, head.hash);
        if self.work.reverified == Some(key) {
            return;
        }
        if loaded(&self.work, Some(&list)).is_none() {
            return;
        }
        let State {
            feeds: Feeds::Loaded(feeds),
            store: Some(store),
            ..
        } = &mut self.work
        else {
            return;
        };
        if feeds.pending_len() > 0 {
            let again = (|| -> anyhow::Result<Vec<Reapplied>> {
                let tx = feeds.begin(store)?;
                let again = feeds.reverify_pending(&tx, &list, APPLIED_SEQ)?;
                feeds.commit(tx)?;
                Ok(again)
            })();
            let Ok(again) = again else {
                return;
            };
            self.keep_reapplied(again);
        }
        self.work.reverified = Some(key);
    }

    /// Records a re-verification applied (Task 33 review m4): kept for
    /// Task 35, which acts on them (their effects and intents, in their
    /// record's transaction), at most [`KEPT_REAPPLIED`], the oldest dropped
    /// first. Nothing reads them yet: until then a record that applied here
    /// changes the standings only (as one a page applies).
    fn keep_reapplied(&mut self, again: Vec<Reapplied>) {
        let kept = &mut self.work.reapplied;
        kept.extend(again);
        if kept.len() > KEPT_REAPPLIED {
            let excess = kept.len() - KEPT_REAPPLIED;
            kept.drain(..excess);
        }
    }

    /// The gate's feed part into the start view when it changed, and the
    /// sync's alert lines into runtime.log.
    pub(crate) fn publish_feed_gates(&mut self) {
        let Some(station) = self.station.as_mut() else {
            return;
        };
        for line in station.feed.take_lines() {
            eprintln!("{line}");
        }
        if let Some((own, open)) = station.feed.take_gates() {
            self.start_view().gates.set_feeds(own, open);
        }
    }

    /// The start's recovery (design I.6.2 step 7): every Station's gate
    /// closes until its feed is read again.
    pub(crate) fn feeds_restart(&mut self) {
        if let Some(station) = self.station.as_mut() {
            station.feed.restart();
        }
        self.start_view().gates.close_stations();
        self.publish_feed_gates();
    }

    /// `atem status`'s `Control feeds:` line (host-work-v1 §11.4, Decisions
    /// 12 and 20): a control state that doesn't read, with the way out;
    /// else, with `host.delegated` on, the host's own Station's gate in the
    /// start check's order (`device list update pending` before
    /// `revocations not yet checked`), with the evidence and pending
    /// counts and the sync's alerts (how many in this run, the latest; their
    /// runtime.log lines are hourly). None otherwise (the hook off: as
    /// main).
    pub fn feeds_status(&self) -> Option<String> {
        if matches!(self.work.feeds, Feeds::Damaged) {
            return Some(format!(
                "the stored control state doesn't read; no delegated task starts. Restore {} from a backup, or pair this host again (a new identity starts a fresh store), then run `atem runtime restart`",
                self.dir
                    .parent()
                    .unwrap_or(&self.dir)
                    .join("host-work.sqlite")
                    .display()
            ));
        }
        let station = self.station.as_ref()?;
        let view = self.start_view();
        let list = view.list.as_ref();
        let deferred = list.is_some_and(|l| l.deferred.is_some());
        let gate = if deferred {
            crate::runtime::delegated::details::DEVICE_LIST_UPDATE_PENDING.to_string()
        } else if let Some(closed) = station.feed.closed() {
            format!(
                "{} ({})",
                crate::runtime::delegated::details::REVOCATIONS_NOT_YET_CHECKED,
                closed.text()
            )
        } else if let Some(why) = list.and_then(|l| list_part_closed(&view, l, station)) {
            format!(
                "{} ({why})",
                crate::runtime::delegated::details::REVOCATIONS_NOT_YET_CHECKED
            )
        } else {
            format!(
                "revocations checked ({})",
                station.feed.own().unwrap_or_default()
            )
        };
        let counts = loaded(&self.work, list).map(|feeds| {
            format!(
                "; {} kept as evidence, {} pending",
                feeds.evidence_count(),
                feeds.pending_len()
            )
        });
        // Every control alert's summary (Task 33 review m7): the link's
        // (the sync's, the refusals', the Station clock ahead) and the feed
        // store's (records kept as evidence), how many in this run, the
        // latest.
        let (link_n, link_latest) = station.feed.alerts();
        let (store_n, store_latest) = self.work.alert_tally.get();
        let latest = match (link_latest, store_latest.as_ref()) {
            (Some(a), Some(b)) => Some(if b.1 > a.1 { b } else { a }),
            (a, b) => a.or(b),
        };
        let alerts = match (link_n + store_n, latest) {
            (0, _) | (_, None) => String::new(),
            (n, Some((latest, _))) => {
                format!("; {n} alert(s) since the start, the latest: {latest}")
            }
        };
        Some(format!("{gate}{}{alerts}", counts.unwrap_or_default()))
    }
}

/// Why the device-list part of the host's own Station's gate is closed,
/// when the feed part is open (Task 31 review: a list with another entry
/// at the announced `seq` differs from the Station's).
fn list_part_closed(
    view: &crate::runtime::delegated::start::StartView,
    list: &crate::session_protocol::membership::ListState,
    station: &crate::runtime::delegated::station::Station,
) -> Option<String> {
    if view.fetched(list).is_some() {
        return None;
    }
    let part = station.fetch.part();
    Some(match part.announced {
        Some(head) if list.membership.entry(head.seq).is_some() => format!(
            "the device list differs from the Station's at seq {}",
            head.seq
        ),
        Some(head) => format!(
            "device list behind the Station's head ({} of {})",
            list.membership.head().seq,
            head.seq
        ),
        None => Closed::NoHeads.text(),
    })
}

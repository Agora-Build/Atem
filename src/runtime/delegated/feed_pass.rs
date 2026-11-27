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
//!   the host's own fetch, recovery approvals and vetoes) or host-work's
//!   applied device-list `seq` did, in their own transaction; after a
//!   record whose revocation applied, in that record's own (the sync does
//!   it). Host-work's applied device-list `seq` is the one host senders'
//!   device-list effects are written up to (`host_senders_pass`), with
//!   `host.senders` on; with it off it is 0, so a host principal's
//!   interrupt waits, as in step 4.
//! - **Records carried on channels** (design II.3.1, host-work-v1 §11.1
//!   "Carriage"), with `host.senders` on: a native member's
//!   `control_records`, host principals' records only (the r9 engine
//!   refused anything else), applied as a feed's records are, in one
//!   transaction with their effects, and answered on the channel
//!   ([`HostBridge::control_records_pass`]).
//! - **What the feed store sees** (Task 33 review I1). The sync runs
//!   whether or not host-work's pass does (a pause skips it), so each step
//!   gives the store the Station link's own origin itself (positions name
//!   it only), and takes the store only while it was loaded for the device
//!   list that committed (a re-pin the pass hasn't moved the store aside for
//!   yet takes nothing).
//! - **Never with the start view locked.** A commit publishes the
//!   standings, which locks the view: the list is copied out first.
//! - **Only this identity's store** (Task 35 re-review 2, notes for Task
//!   36): the store takes pages and re-verifications, and acknowledges
//!   them, only while it is bound to the host's current identity
//!   ([`loaded`]); another identity's (kept while hosting is paused across
//!   a re-verify) or one not bound yet takes nothing and sends nothing.
//! - **Acknowledgments** (Task 36, [`super::acks`]): each record's result
//!   is written in its transaction (`apply_page`, `feeds_reverify`); the
//!   bridge hands the acks due to the link at the end of its Station step,
//!   after the records' followups and the services' admission they move (a
//!   revoke's and a hold's session-v1 fences: [`HostBridge::acks_due`],
//!   [`HostBridge::acks_sent`]); a `control_ack_refused` holds them for the
//!   connection ([`HostBridge::ack_refused`]).
use super::*;
use crate::runtime::delegated::acks::DueAck;
use crate::runtime::delegated::effects::{Followup, act};
use crate::runtime::delegated::feeds::Reapplied;
use crate::runtime::delegated::station::Call;
use crate::runtime::delegated::sync::{Clocks, Closed, PageCx};
use crate::session_protocol::membership::ListState;
use atem_client::control::{ControlSyncResult, Heads, RelayError};

/// Why a `control_records` call isn't applied now (`busy`): the hook off,
/// the device list not serving, the control state not loaded, or its
/// transaction failed. The carrier delivers it again.
const RECORDS_NOT_APPLIED: &str = "control records not applied now";

/// The re-verified records kept for Task 35 at most (`keep_reapplied`).
pub(crate) const KEPT_REAPPLIED: usize = 64;

/// The feed store when its records may be read and applied, and
/// acknowledged: loaded for the device list that committed (`list`: the
/// start view's; feeds of another list, a re-pin the pass hasn't moved the
/// store aside for yet, take nothing), its store bound to the host's
/// current identity (`identity`; Task 35 re-review 2, notes for Task 36:
/// another identity's store, kept while hosting is paused across a
/// re-verify, or a store not bound yet, takes no page, no re-verification
/// and sends no ack), the receipt database healthy.
pub(super) fn loaded<'a>(
    work: &'a State,
    list: Option<&ListState>,
    identity: &HostTarget,
) -> Option<&'a FeedStore> {
    match (&work.feeds, &work.store, work.error, list) {
        (Feeds::Loaded(feeds), Some(_), false, Some(list))
            if feeds.for_list(&list.membership) && feeds.identity() == Some(identity) =>
        {
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
    /// Host-work's applied device-list `seq` for `list` (design II.3.1): host
    /// senders' device-list effects are durable up to it
    /// (`host_senders_pass`), with `host.senders` on; 0 otherwise, as in step
    /// 4 (nothing writes them: a host principal's interrupt waits). A row
    /// that can't be read counts as 0: the interrupt waits (fail closed),
    /// and the next pass of host senders' effects faults on it. Kept in
    /// memory once that pass wrote or read it, for this identity and list;
    /// the store is read only while it is unknown.
    pub(crate) fn host_applied_seq(&self, list: &ListState) -> u64 {
        if !(self.features.delegated && self.features.senders) {
            return 0;
        }
        let genesis = list.membership.genesis_hash();
        if let Some((identity, kept, seq)) = &self.work.applied_seq
            && *kept == genesis
            && *identity == self.work_host()
        {
            return *seq;
        }
        self.work
            .store
            .as_ref()
            .and_then(|store| {
                crate::runtime::delegated::host_senders::applied_seq(&store.db, &genesis).ok()
            })
            .unwrap_or(0)
    }

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
        let fits = loaded(&self.work, list, &self.work_host()).is_some();
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

    /// The host's identity as its Station association names it
    /// (host-work-v1 §11.4, "An identity change"; Astation's item 15 on
    /// #120): the session host's account, device and trust generation, the
    /// pinned device list's genesis and the host's `host_channel_key`,
    /// handed to the Station link before each of its steps (the pass's
    /// first, its Station step, its end). One its link's socket wasn't
    /// authenticated under (a re-verify on the live link, a new trust
    /// generation, account, genesis or key, while the link is up or while
    /// Astation authenticates it again) ends that link's association: its
    /// call retired, nothing more asked, fetched or acknowledged on it, its
    /// gate closed (`Station::on_identity`), and the App asked to reconnect
    /// it at the pass's end.
    pub(crate) fn station_identity(&mut self) {
        // No Station link without `host.delegated`: nothing to hand over.
        if self.station.is_none() {
            return;
        }
        let identity = crate::runtime::delegated::sync::HostIdentity {
            host: self.work_host(),
            genesis: self
                .membership
                .as_ref()
                .filter(|m| !m.unpaired())
                .map(|m| m.membership().genesis_hash()),
            host_key: self.host_key.as_ref().and_then(|key| key.public_key()),
        };
        if let Some(station) = self.station.as_mut() {
            station.on_identity(identity);
        }
    }

    /// The pass's clocks: the gate follows them (60 s without `heads`)
    /// with no call; the start view gets the change.
    pub(crate) fn feed_advance(&mut self, now: Clocks) {
        let list = self.sync_list();
        let feeds = loaded(&self.work, list.as_ref(), &self.work_host());
        if let Some(station) = self.station.as_mut() {
            station.feed.advance(now, feeds);
        }
        // No reset's mark is written here: the pass's tick (`feed_tick`, in
        // the same pass) writes it and returns the read from 0 it lets go
        // (Task 33 re-review 2, R2-2: a call asked here would be dropped).
        self.publish_feed_gates();
    }

    /// The sync's calls due at the pass, after its messages (a feed that
    /// needs a page while a recent `heads` announced it, a reset's read from
    /// 0 its mark lets go, a new call after one went unanswered for 35 s:
    /// retired, ruling C1b-a).
    pub(crate) fn feed_tick(&mut self, now: Clocks) -> Vec<Call> {
        let list = self.sync_list();
        let feeds = loaded(&self.work, list.as_ref(), &self.work_host());
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
        // The delegated clock its `station_time` goes through, built now if
        // it isn't yet, as host-work's pass builds it: the Station's messages
        // come first in a pass, and after a restart the passes adopting
        // surviving workers skip both, so a `heads` that came meanwhile is
        // handled before host-work's first pass. Without the clock its time
        // would be one the clock couldn't record, closing the gate until the
        // Station's next `heads` (Task 34).
        self.ensure_clock();
        let list = self.sync_list();
        let fits = loaded(&self.work, list.as_ref(), &self.work_host()).is_some();
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
    /// against the device list as it committed, its records' effects on
    /// the tasks in its transaction (`effects::act`); the standings follow
    /// at its commit, and what the effects ask after it waits for
    /// `effects_pass`. The next page, when it asks one at once.
    pub(crate) fn feed_page(&mut self, page: Result<ControlSyncResult, RelayError>) -> Vec<Call> {
        // Its `station_time` too (`feed_heads`).
        self.ensure_clock();
        // Copied out: a commit publishes the standings into the view.
        let list = self.sync_list();
        let fits = loaded(&self.work, list.as_ref(), &self.work_host()).is_some();
        let applied_seq = list.as_ref().map_or(0, |l| self.host_applied_seq(l));
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
                applied_seq,
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
            Ok(synced) => {
                // What its records' effects ask now that the page committed
                // (`effects_pass` carries it out).
                self.work.followups.extend(synced.followups);
                synced.next.map(Call::Sync).into_iter().collect()
            }
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
        let applied_seq = self.host_applied_seq(&list);
        let key = (head.seq, head.hash, applied_seq);
        if self.work.reverified == Some(key) {
            return;
        }
        if loaded(&self.work, Some(&list), &self.work_host()).is_none() {
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
            // Each record applied again with its effects on the tasks, in
            // the same transaction (I.5.5), what they ask of the bridge
            // taken only once it committed.
            let again = (|| -> anyhow::Result<(Vec<Reapplied>, Vec<Followup>)> {
                let tx = feeds.begin(store)?;
                let again = feeds.reverify_pending(&tx, &list, applied_seq)?;
                let mut followups = Vec::new();
                let mut acked = Vec::new();
                for r in &again {
                    followups.extend(act(store, &tx, &r.applied.actions)?);
                    // A channel's record is answered there only (never
                    // acknowledged to the Station).
                    acked.extend(r.acked());
                }
                // Their results, owed the Station (Task 36), in the same
                // transaction.
                feeds.acknowledge(&tx, &acked)?;
                feeds.commit(tx)?;
                Ok((again, followups))
            })();
            let Ok((again, followups)) = again else {
                return;
            };
            self.work.followups.extend(followups);
            self.keep_reapplied(again);
        }
        self.work.reverified = Some(key);
    }

    /// The `control_records` calls the r9 engine took from native members'
    /// channels, each applied ([`HostBridge::apply_carried_records`]) and
    /// answered on its channel: its `control_records_result`, or `busy` when
    /// it couldn't be applied now. A stop: served while hosting is paused
    /// too.
    pub(crate) fn control_records_pass(&mut self) {
        for call in self.r9.take_control_records() {
            let reply = self.apply_carried_records(&call.carrier, &call.request.records);
            let now = self.clock.now();
            self.r9
                .control_records_reply(&call.attachment, &call.request.id, reply, now);
        }
    }

    /// `records` (host principals' `interrupt_running`, design II.3.1, "A
    /// later interrupt"), carried by `carrier` (no authority from carrying):
    /// applied in one transaction, verified against the device list as it
    /// committed, as the feed's records are (`FeedStore::apply_carried`:
    /// pending until host-work's applied device-list `seq` reaches the
    /// revoke, a duplicate for a revoke already interrupted), with their
    /// effects on the tasks (`effects::act`: an intent for each of the
    /// host's tasks admitted before that revoke whose turn may run). Their
    /// results, in order, once committed; what the effects ask after the
    /// commit goes with the feed's. `busy` with nothing applied: the hook
    /// off, the list not serving, the control state not loaded for it, or a
    /// transaction that failed.
    pub(crate) fn apply_carried_records(
        &mut self,
        carrier: &str,
        records: &[atem_client::control::ControlRecord],
    ) -> Result<Vec<atem_client::session::r9::RecordResult>, HostWorkError> {
        use atem_client::session::r9::RecordResult;
        let busy = HostWorkError {
            code: "busy",
            detail: Some(RECORDS_NOT_APPLIED),
        };
        if !(self.features.delegated && self.features.senders) {
            return Err(busy);
        }
        let list = self.start_view().list.clone().ok_or(busy)?;
        if !FeedStore::serves(&list) || loaded(&self.work, Some(&list), &self.work_host()).is_none()
        {
            return Err(busy);
        }
        let applied_seq = self.host_applied_seq(&list);
        let State {
            feeds: Feeds::Loaded(feeds),
            store: Some(store),
            ..
        } = &mut self.work
        else {
            return Err(busy);
        };
        let applied = (|| -> anyhow::Result<(Vec<RecordResult>, Vec<Followup>)> {
            let tx = feeds.begin(store)?;
            let mut results = Vec::new();
            let mut followups = Vec::new();
            for record in records {
                let applied = feeds.apply_carried(&tx, record, &list, carrier, applied_seq)?;
                followups.extend(act(store, &tx, &applied.actions)?);
                results.push(RecordResult::of(record, &applied));
            }
            feeds.commit(tx)?;
            Ok((results, followups))
        })();
        match applied {
            Ok((results, followups)) => {
                self.work.followups.extend(followups);
                Ok(results)
            }
            Err(error) => {
                eprintln!(
                    "atem runtime: control records carried by {carrier} couldn't be applied ({error:#}); nothing of them applied"
                );
                Err(busy)
            }
        }
    }

    /// Records a re-verification applied (Task 33 review m4), their
    /// effects (Task 35) and their results owed the Station (Task 36)
    /// written in their transaction: the latest kept in memory for the
    /// tests, at most [`KEPT_REAPPLIED`], the oldest dropped first; dropped
    /// with the store when a new identity moves it aside.
    fn keep_reapplied(&mut self, again: Vec<Reapplied>) {
        let kept = &mut self.work.reapplied;
        kept.extend(again);
        if kept.len() > KEPT_REAPPLIED {
            let excess = kept.len() - KEPT_REAPPLIED;
            kept.drain(..excess);
        }
    }

    /// The acknowledgments due to the host's own Station now (Task 36,
    /// host-work-v1 §11.4 "Acknowledgments"; [`super::acks`]): only from a
    /// feed store that may be acknowledged ([`loaded`]: this identity's,
    /// for the committed list, healthy), on a Station link authenticated
    /// under this identity (none after an identity change until the next
    /// link), at `D`. The
    /// bridge hands them to the link at the end of its Station step, after
    /// the records' followups (a revoke's session-v1 fence, then a hold's in
    /// `sync_services`), so a result goes once its effects are durable and
    /// its fence ran.
    pub(crate) fn acks_due(&self) -> Vec<DueAck> {
        // None on a link whose association is another identity's (§11.4
        // "An identity change"), or whose socket the Station suspended
        // this host's service on (III.5): its acks wait for the next link.
        if self
            .station
            .as_ref()
            .is_some_and(|station| station.feed.socket_ended())
        {
            return Vec::new();
        }
        let list = self.start_view().list.clone();
        let Some(feeds) = loaded(&self.work, list.as_ref(), &self.work_host()) else {
            return Vec::new();
        };
        let Some(link) = self.station.as_ref().and_then(|station| station.link()) else {
            return Vec::new();
        };
        let now_d = self.start_view().now_d_ms;
        // Host senders' revoke entries' results only with `host.senders`:
        // with it off, rows an earlier run wrote wait as they are (ruling
        // R57, L1).
        let entries = self.features.delegated && self.features.senders;
        feeds.acks_due(link, now_d, entries)
    }

    /// An ack's wire text, by the shared core's builder; one it refuses
    /// stays owed, unsent, and is logged (the first, then at powers of
    /// two).
    pub(crate) fn ack_text(&mut self, due: &DueAck) -> Option<String> {
        #[cfg(test)]
        {
            use atem_client::control::AckResult;
            let ids: Vec<String> = due
                .ack
                .results
                .iter()
                .filter_map(|r| match r {
                    AckResult::Record { record_id, .. } => Some(record_id.clone()),
                    AckResult::Entry { .. } => None,
                })
                .collect();
            let attached = self
                .r9
                .attachments()
                .into_iter()
                .map(|(_, principal)| principal)
                .collect();
            self.work
                .acks_remote
                .push((ids.clone(), self.host.remote_principals()));
            self.work.acks_handed.push((ids, attached));
        }
        match due.ack.to_json() {
            Ok(text) => Some(text.to_string()),
            Err(error) => {
                self.work.ack_unbuilt += 1;
                if self.work.ack_unbuilt.is_power_of_two() {
                    eprintln!(
                        "atem runtime: {} control acknowledgment(s) the shared builder refused ({}); kept, not sent",
                        self.work.ack_unbuilt,
                        error.code()
                    );
                }
                None
            }
        }
    }

    /// `sent`, acks [`HostBridge::acks_due`] gave, were handed to the link:
    /// marked sent (what is spent leaves the book), in their own
    /// transaction. A write that fails is logged (the first, then at powers
    /// of two): the sends are marked in memory all the same, so none goes
    /// again on this connection (review m5); what is spent leaves the book
    /// once a write succeeds, and a restart may send them once more.
    pub(crate) fn acks_sent(&mut self, sent: &[DueAck]) {
        let list = self.start_view().list.clone();
        if loaded(&self.work, list.as_ref(), &self.work_host()).is_none() {
            return;
        }
        let Some(link) = self
            .station
            .as_ref()
            .and_then(|station| station.link())
            .cloned()
        else {
            return;
        };
        let now_d = self.start_view().now_d_ms;
        let State {
            feeds: Feeds::Loaded(feeds),
            store: Some(store),
            ..
        } = &mut self.work
        else {
            return;
        };
        let sent = feeds.acks_sent(store, &link, now_d, sent);
        for line in feeds.take_ack_lines() {
            eprintln!("{line}");
        }
        if let Err(error) = sent {
            self.work.ack_failures += 1;
            if self.work.ack_failures.is_power_of_two() {
                eprintln!(
                    "atem runtime: {} control acknowledgment(s) couldn't be marked sent ({error:#}); none goes again on this connection",
                    self.work.ack_failures
                );
            }
        }
    }

    /// `control_ack_refused` on the Station link (Decision 20): the feed
    /// sync closed the gates already; the book takes nothing as delivered
    /// and sends nothing more on that connection ([`super::acks`]).
    pub(crate) fn ack_refused(&mut self) {
        if let Feeds::Loaded(feeds) = &mut self.work.feeds {
            feeds.acks_refused();
        }
    }

    /// The App's record of a `service_suspended` notice (the delegated
    /// host-work design III.5), taken once (its number) and applied to the
    /// Station link on the socket it came on, whatever that link's
    /// generation (a suspension is the socket's): its calls retired and its
    /// gates closed ([`super::station::Station::on_suspended`]), and the
    /// book's acknowledgments of every connection on that socket sent
    /// again on the next ([`HostBridge::acks_suspended`]). The bridge asks
    /// at the start of its pass, before anything of it reads the link or
    /// dispatches (the link as the last pass left it), and again right
    /// after it synced the link (one the App installed or authenticated
    /// again in the same tick as the notice), before the pass reads the
    /// Station's messages. A notice waits while the Station link isn't on
    /// its socket yet and the App's link still is; it is dropped only once
    /// neither is (the socket gone), the book's acknowledgments sent on
    /// that socket still read as never sent, so they go again on the next
    /// link (review N2). With no Station link (the hook off) it does
    /// nothing.
    pub(crate) fn station_suspension(&mut self, app: &crate::app::App) {
        if let Some(s) = app.service_suspension.as_ref()
            && let (Some(notice), Some(socket)) = (s.notice, s.socket())
            && notice > self.suspension_applied
        {
            self.suspension_applied = notice;
            self.suspension_pending = Some((socket, s.text.clone()));
        }
        let Some((socket, text)) = self.suspension_pending.clone() else {
            return;
        };
        let Some(station) = self.station.as_mut() else {
            self.suspension_pending = None;
            return;
        };
        if station.link().is_none_or(|l| l.socket != socket) {
            if app.astation_client.socket_id() != socket {
                // The socket gone before a Station link took the notice
                // (review N2): what was acknowledged on it goes again on the
                // next link.
                self.suspension_pending = None;
                if let Feeds::Loaded(feeds) = &mut self.work.feeds {
                    feeds.acks_socket_suspended(socket);
                }
            }
            return;
        }
        self.suspension_pending = None;
        station.on_suspended(&text);
        self.acks_suspended();
        self.publish_feed_gates();
        self.refresh_fetch_view();
    }

    /// Review M3: whatever suspension the App recorded (the relay's at a
    /// connect or on an open link, or the local link's) is lifted once the
    /// Station serves this host again: its feed gate open, on whatever link
    /// (a local link's open gate says the account is served again), unless
    /// a notice still waits for its link.
    pub(crate) fn lift_suspension(
        &mut self,
        recorded: &mut Option<crate::app::suspension::Suspension>,
    ) {
        if recorded.is_some()
            && self.suspension_pending.is_none()
            && self
                .station
                .as_ref()
                .is_some_and(|station| station.feed.closed().is_none())
        {
            *recorded = None;
            self.suspension = None;
        }
    }

    /// A local link's suspension ended (the delegated host-work design
    /// III.5; reviews M2, N1): the Station served the link's feed again
    /// (the resynchronization read after the latest refusal's backoff,
    /// whatever refusals came during the suspension), or its link
    /// generation ended, so the book's hold ends
    /// ([`super::acks::AckBook::on_resumed`]). The mailbox ends its own done
    /// hold with its own resynchronization.
    pub(crate) fn station_resumed(&mut self) {
        let Some(station) = self.station.as_mut() else {
            return;
        };
        if !station.feed.take_suspension_ended() {
            return;
        }
        if let Feeds::Loaded(feeds) = &mut self.work.feeds {
            feeds.acks_resumed();
        }
    }

    /// The Station suspended this host's service on its link (the
    /// delegated host-work design III.5): the book takes nothing as
    /// delivered, sends nothing more on that connection, and what went on
    /// it goes again on the next ([`super::acks::AckBook::on_suspended`]).
    pub(crate) fn acks_suspended(&mut self) {
        let Some(link) = self.station.as_ref().and_then(|s| s.link()).cloned() else {
            return;
        };
        if let Feeds::Loaded(feeds) = &mut self.work.feeds {
            feeds.acks_suspended(&link);
        }
    }

    /// What control records' effects asked of the bridge once their
    /// transaction committed ([`Followup`], design I.5.5 to I.5.7), carried
    /// out after the Station's messages and in host-work's pass, hosting
    /// paused or not (a stop always wins), in their order:
    /// - **the fences** first, at once (a later error drops none): with
    ///   `host.delegated` on, session-v1's §H fence of the revoked service,
    ///   each attachment closed after `unauthorized`, `revoked`
    ///   (`R9Host::fence_revoked`, once per revoke), and of the held one,
    ///   each closed after `busy`, `paused` (`R9Host::fence_held`, when the
    ///   session host knows it), checked or not, released since or not, so
    ///   a hold's result goes only after its fence; a hold of a service the
    ///   same batch revokes (one page or pass, either order) asks none: the
    ///   revoke's fence wins and closes after `unauthorized`, `revoked`;
    ///   with it off a record
    ///   still reaches the tasks it holds, but nothing of session-v1 (hook
    ///   off = main);
    /// - then the services' r9 admission as the control state stands
    ///   ([`HostBridge::sync_services`]: the held services' `hello`s
    ///   refused, `HostBridge::sync_held`);
    /// - **a withdrawal and the intents** once the store was recovered
    ///   (before that, the start's recovery withdraws every attempt still
    ///   `accepted` and reconciles the rest, and they wait), with no
    ///   receipt-database fault (then they go: the restart it asks for
    ///   recovers the store): [`HostBridge::withdraw_for_record`], and the
    ///   pending intents carried out (`carry_out_intents`, as every
    ///   scheduling pass does).
    ///
    /// A store write that fails is a receipt-database fault (`work_fail`).
    pub(in crate::runtime::host_bridge) fn effects_pass(&mut self, cx: &mut Cx) {
        let followups = std::mem::take(&mut self.work.followups);
        // A revoke wins over a hold of the same service in the same batch
        // (one page or one pass, in either order): only the revoke's fence
        // runs, so the service's channels close after `unauthorized`,
        // `revoked` (session-v1 R9.7a); it covers all the hold's would, and
        // also runs before either record's result goes.
        let revoked: HashSet<String> = followups
            .iter()
            .filter_map(|followup| match followup {
                Followup::Fence { principal } => Some(principal.clone()),
                _ => None,
            })
            .collect();
        let mut rest = Vec::new();
        for followup in followups {
            match followup {
                Followup::Fence { principal } => {
                    if self.features.delegated {
                        let effects = self.r9_call(|r9, parts| r9.fence_revoked(&principal, parts));
                        self.r9_exec(effects, cx);
                    }
                }
                Followup::HoldFence { principal } => {
                    if self.features.delegated && !revoked.contains(&principal) {
                        let effects = self.r9_call(|r9, parts| r9.fence_held(&principal, parts));
                        self.r9_exec(effects, cx);
                    }
                }
                other => rest.push(other),
            }
        }
        self.sync_services(cx);
        if rest.is_empty() {
            return;
        }
        let mut later = Vec::new();
        let mut intents = false;
        for followup in rest {
            match followup {
                _ if self.work.error || self.work.store.is_none() => {}
                f if !self.work.recovered => later.push(f),
                Followup::Withdraw {
                    task_id,
                    attempt_id,
                    then,
                } => {
                    if self
                        .withdraw_for_record(&task_id, &attempt_id, then, cx)
                        .is_err()
                    {
                        self.work_fail();
                        return;
                    }
                }
                Followup::Intents { .. } => intents = true,
                Followup::Fence { .. } | Followup::HoldFence { .. } => {}
            }
        }
        self.work.followups = later;
        if intents && self.carry_out_intents(cx).is_err() {
            self.work_fail();
        }
    }

    /// The services' r9 admission as the host's control state stands, so
    /// it never disagrees with host work's answer to the same service
    /// (`service_refused`; ruling T35c). Only with `host.delegated` on;
    /// with it off nothing is refused for the control state, delegated rows
    /// or not (review m2: hook off = main for session-v1).
    /// - **Unchecked** (`controls_unchecked`: damaged, not loaded, never
    ///   read, another identity's, or a receipt-database fault): every
    ///   service's `hello` is refused `busy`, `revocations not yet
    ///   checked`, and entering that state fences every live service
    ///   attachment (`R9Host::set_services_unchecked`). The engine starts
    ///   so (`HostBridge::open`), and the runtime calls this before every
    ///   pass's `hello`s, after a load and after the records' followups.
    /// - **Checked** (loaded): the revoked services follow the committed
    ///   standings ([`HostBridge::sync_revoked`]), and so do the held ones
    ///   ([`HostBridge::sync_held`]), in that order: a revoke wins.
    ///
    /// The order of a service's `hello` refusals is the r9 engine's
    /// (session-v1 R9.11): the device list's own, then `unauthorized`,
    /// `revoked`, then `busy`, `revocations not yet checked`, then `busy`,
    /// `paused`.
    pub(in crate::runtime::host_bridge) fn sync_services(&mut self, cx: &mut Cx) {
        if self.features.delegated {
            self.read_kept();
        }
        let unchecked = self.features.delegated && self.controls_unchecked();
        if unchecked != self.r9.services_unchecked() {
            let effects = self.r9_call(|r9, parts| r9.set_services_unchecked(unchecked, parts));
            self.r9_exec(effects, cx);
        }
        if !self.features.delegated {
            if !self.r9.revoked_services().is_empty() {
                self.r9.set_revoked_services(HashSet::new());
            }
            self.clear_held(cx);
            return;
        }
        if !unchecked {
            self.sync_revoked(cx);
            self.sync_held(cx);
        } else if self.kept_elsewhere() {
            // Another identity's standings aren't this one's (a new
            // identity, a new store): its services wait as unchecked
            // (ruling T35e).
            if !self.r9.revoked_services().is_empty() {
                self.r9.set_revoked_services(HashSet::new());
            }
            self.clear_held(cx);
        }
    }

    /// The r9 engine's held services (host-work-v1 §11.1, the hold's
    /// session-v1 fence; **Atem's reading of Astation's item 7 on #120,
    /// 2026-11-14**) as the committed standings have them: a service a
    /// `hold` holds and no `revoke` revoked (the revoke wins), the control
    /// feeds loaded. Never from memory alone: after a restart the stored
    /// state loads first, and this runs before any service's `hello` (the
    /// engine refuses every service as unchecked until then).
    ///
    /// The live fence is the hold's own followup (`Followup::HoldFence`,
    /// `R9Host::fence_held`), carried out in `effects_pass` before the
    /// record's result goes, whatever the standings show by then (a release
    /// in the same page) and checked or not. Here the engine's refusal set
    /// follows the standings (its later `hello`s refused `busy`, `paused`),
    /// and a service newly in it that the session host still knows (an
    /// attachment, a lease, accepted work or `control`) is fenced through
    /// §H: a fence a run that ended between the hold's commit and its
    /// followup lost, written at the first read of the loaded state, before
    /// admission. One fenced already is known no more: nothing twice. A
    /// release lifts the refusal; nothing of before comes back. A hold
    /// changes no delegated task here (the record's own effects did); a v1
    /// task the service had from before its cover ends as any §H fence ends
    /// it (`sender's authority changed`).
    fn sync_held(&mut self, cx: &mut Cx) {
        if !matches!(self.work.feeds, Feeds::Loaded(_)) || self.controls_stood_in() {
            return;
        }
        let held: HashSet<String> = self
            .start_view()
            .standings
            .iter()
            .filter(|(principal, standing)| {
                standing.held && standing.revoked.is_none() && principal.starts_with("service:")
            })
            .map(|(principal, _)| principal.clone())
            .collect();
        if &held == self.r9.held_services() {
            return;
        }
        let effects = self.r9_call(|r9, parts| r9.set_held_services(held, parts));
        self.r9_exec(effects, cx);
    }

    /// No service held in the r9 engine (the hook off, as on main; or
    /// another identity's standings): nothing is fenced for it.
    fn clear_held(&mut self, cx: &mut Cx) {
        if self.r9.held_services().is_empty() {
            return;
        }
        let effects = self.r9_call(|r9, parts| r9.set_held_services(HashSet::new(), parts));
        self.r9_exec(effects, cx);
    }

    /// The r9 engine's revoked services (their `hello`s refused, design
    /// I.5.5 step 2) as the committed standings have them, the control
    /// feeds loaded (a new host identity clears them with its store). A
    /// service revoked whose channel is live when the loaded state is read
    /// (one admitted before) is fenced then, once; so is one the session
    /// host still grants `control` (Task 37 review I1, ruling T37a): its
    /// revoke's fence, a followup in memory, was lost with a run that ended
    /// between the record's commit and its followups. Written now, durably,
    /// it ends the service's v1 tasks as the fence would have (§11.1:
    /// `sender's authority changed`), rather than leave them holding their
    /// sessions until their deadlines; a service fenced already holds no
    /// `control`, so nothing is written twice.
    fn sync_revoked(&mut self, cx: &mut Cx) {
        if !matches!(self.work.feeds, Feeds::Loaded(_)) || self.controls_stood_in() {
            return;
        }
        let revoked: HashSet<String> = self
            .start_view()
            .standings
            .iter()
            .filter(|(_, standing)| standing.revoked.is_some())
            .map(|(principal, _)| principal.clone())
            .collect();
        if &revoked == self.r9.revoked_services() {
            return;
        }
        let mut fence: std::collections::BTreeSet<String> = self
            .r9
            .attachments()
            .into_iter()
            .map(|(_, principal)| principal)
            .filter(|principal| revoked.contains(principal))
            .collect();
        fence.extend(
            revoked
                .iter()
                .filter(|principal| self.host.grants_control(principal))
                .cloned(),
        );
        self.r9.set_revoked_services(revoked);
        for principal in fence {
            let effects = self.r9_call(|r9, parts| r9.fence_revoked(&principal, parts));
            self.r9_exec(effects, cx);
        }
    }

    /// [`Followup::Withdraw`] (design I.5.5, I.5.6): task `task_id`'s live
    /// attempt `attempt_id` is withdrawn in the session host, and the task
    /// settles from the withdrawal with the attempt's end, in one `BEGIN
    /// IMMEDIATE` transaction (`end_attempt`): `then`'s state
    /// (`Event::outcome`) when it never ran, a hold's withdrawal not
    /// counted. Left to its receipt when it started (it runs: never
    /// `cancelled` while its turn runs) or when the withdrawal can't be
    /// recorded (the journal halted: nothing starts until the restart,
    /// which withdraws it). A hold lifted since asks nothing (the attempt
    /// goes on). An attempt no longer live (ended by the scheduling pass, a
    /// cancel or an earlier followup) leaves the task as it is, but for a
    /// revoke, which cancels it if it waits.
    fn withdraw_for_record(
        &mut self,
        task_id: &str,
        attempt_id: &str,
        then: crate::runtime::delegated::start::Event,
        cx: &mut Cx,
    ) -> anyhow::Result<()> {
        use crate::runtime::delegated::attempts::{AttemptEnd, SessionAnswer, attempt_end};
        use crate::runtime::delegated::start::Event;
        use crate::session_protocol::host::{Immutable, Provenance, Withdrawal};
        let store = self.work.store.as_ref().unwrap();
        let Some(mut r) = store.work(task_id)? else {
            return Ok(());
        };
        let next = then.outcome();
        let held = then == Event::Held;
        if held
            && !self
                .start_view()
                .standings
                .get(&r.principal)
                .is_some_and(|s| s.held)
        {
            return Ok(());
        }
        let Some(attempt) = store
            .live_attempt(task_id)?
            .filter(|a| a.attempt_id == attempt_id)
        else {
            if next.0.terminal() && matches!(r.status.state, WorkState::Queued | WorkState::Blocked)
            {
                self.settle_task(&mut r, next.0, next.1)?;
            }
            return Ok(());
        };
        let end = match self.host.attempt_receipt(attempt_id, task_id) {
            // Absent from the journal: never admitted (I.6.3).
            None => AttemptEnd::NotAdmitted,
            Some(rc) => {
                match attempt_end(SessionAnswer::Receipt(rc.state, rc.detail.as_deref()), held) {
                    Some(AttemptEnd::Started) => return Ok(()),
                    Some(end) => end,
                    // `accepted`: withdrawn in the session host, which finds it
                    // by its id (these values go nowhere).
                    None => {
                        if self.host.journal_halted() {
                            return Ok(());
                        }
                        let immutable = Immutable {
                            target: r.task.target.clone(),
                            payload_digest: String::new(),
                            provenance: Provenance {
                                task_id: task_id.to_string(),
                                sender: r.principal.clone(),
                            },
                        };
                        let withdrawal = self.host.withdraw(attempt_id, &immutable);
                        let effects = self.host.take_effects();
                        self.exec(effects, cx);
                        match withdrawal {
                            Withdrawal::Started | Withdrawal::Halted => return Ok(()),
                            w => attempt_end(SessionAnswer::Withdrawal(w), held)
                                .unwrap_or(AttemptEnd::Withdrawn { counted: !held }),
                        }
                    }
                }
            }
        };
        self.end_attempt(&mut r, &attempt, end, next)
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
        let store = self
            .dir
            .parent()
            .unwrap_or(&self.dir)
            .join("host-work.sqlite");
        if matches!(self.work.feeds, Feeds::Damaged) {
            // Services are refused for it only with the hook on (ruling
            // T35f, m2: with it off nothing is, as on main).
            let services = if self.features.delegated {
                "; services are refused (busy) until it reads"
            } else {
                ""
            };
            return Some(format!(
                "the stored control state doesn't read; no delegated task starts. Restore {} from a backup, or pair this host again (a new identity starts a fresh store), then run `atem runtime restart`{services}",
                store.display()
            ));
        }
        let station = self.station.as_ref()?;
        let view = self.start_view();
        let list = view.list.as_ref();
        let deferred = list.is_some_and(|l| l.deferred.is_some());
        // The Station's suspension of this host's service (the delegated
        // host-work design III.5), while the gate is closed: its origin and
        // text, as the gate's reason only with no Station link up (the
        // relay refused or closed) or when it came on the link up now
        // (review N3: a relay's is never the local link's reason).
        let suspended = self.suspension.as_ref().filter(|(_, _, socket)| {
            station.feed.closed().is_some()
                && station
                    .link()
                    .is_none_or(|l| socket.is_some_and(|s| s == l.socket))
        });
        let gate = if let Some((origin, text, _)) = suspended {
            let origin = origin
                .as_deref()
                .or(station.feed.own())
                .unwrap_or("the Station");
            format!(
                "{} ({origin}: {}; retrying)",
                crate::runtime::delegated::details::REVOCATIONS_NOT_YET_CHECKED,
                crate::app::suspension::shown(text)
            )
        } else if deferred {
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
        let counts = loaded(&self.work, list, &self.work_host()).map(|feeds| {
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
        // Why services are refused, if they are (ruling T35d), with the way
        // out.
        let services = if !(self.features.delegated && self.controls_unchecked()) {
            String::new()
        } else if matches!(self.work.kept, Some(super::KeptControls::Unreadable)) {
            // First: a store that can't be opened faults the receipt
            // database too, and a restart alone fails the same way.
            format!(
                "; services are refused (busy) until the control state loads: {} can't be opened (move it aside or restore it, then run `atem runtime restart`)",
                store.display()
            )
        } else if self.work.error {
            "; services are refused (busy) until `atem runtime restart` (the receipt database failed)"
                .to_string()
        } else if self.kept_elsewhere() {
            // Hosting makes it, and so does an owner's command that opens
            // the store while hosting is paused (ruling T35f, m4).
            "; services are refused (busy) until this host identity's own store is made (by hosting, `enabled = true` in runtime.toml, or by an owner command that opens the store, such as `atem task list --unknown` or `atem message status`) and has read its Station's control feed in full".to_string()
        } else if matches!(self.work.feeds, Feeds::Loaded(_)) {
            "; services are refused (busy) until this host's first complete read of its Station's control feed (it needs the Station's heads)".to_string()
        } else {
            "; services are refused (busy) until the control state loads".to_string()
        };
        // Host senders' mailbox part (design II.5), with `host.senders`.
        let mail = self
            .mail_status()
            .map(|m| format!("; {m}"))
            .unwrap_or_default();
        Some(format!(
            "{gate}{}{mail}{alerts}{services}",
            counts.unwrap_or_default()
        ))
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

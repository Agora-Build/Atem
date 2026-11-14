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
//! - **Only this identity's store** (Task 35 re-review 2, notes for Task
//!   36): the store takes pages and re-verifications, and acknowledges
//!   them, only while it is bound to the host's current identity
//!   ([`loaded`]); another identity's (kept while hosting is paused across
//!   a re-verify) or one not bound yet takes nothing and sends nothing.
//! - **Acknowledgments** (Task 36, [`super::acks`]): each record's result
//!   is written in its transaction (`apply_page`, `feeds_reverify`); the
//!   bridge hands the acks due to the link at the end of its Station step,
//!   after the records' followups ([`HostBridge::acks_due`],
//!   [`HostBridge::acks_sent`]); a `control_ack_refused` holds them for the
//!   connection ([`HostBridge::ack_refused`]).
use super::*;
use crate::runtime::delegated::acks::{Acked, DueAck};
use crate::runtime::delegated::effects::{Followup, act};
use crate::runtime::delegated::feeds::Reapplied;
use crate::runtime::delegated::station::Call;
use crate::runtime::delegated::sync::{Clocks, Closed, PageCx};
use crate::session_protocol::membership::ListState;
use atem_client::control::{ControlSyncResult, Heads, RelayError};

/// Host-work's applied device-list `seq` in step 4 (see the module docs).
const APPLIED_SEQ: u64 = 0;

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
fn loaded<'a>(
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
        let key = (head.seq, head.hash);
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
                let again = feeds.reverify_pending(&tx, &list, APPLIED_SEQ)?;
                let mut followups = Vec::new();
                let mut acked = Vec::new();
                for r in &again {
                    followups.extend(act(store, &tx, &r.applied.actions)?);
                    acked.push(Acked::of(&r.record, &r.applied, r.pos.as_ref()));
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
    /// for the committed list, healthy), on the Station link, at `D`. The
    /// bridge hands them to the link at the end of its Station step, after
    /// the records' followups (a revoke's session-v1 fence), so a result
    /// goes once its effects are durable and its fence ran.
    pub(crate) fn acks_due(&self) -> Vec<DueAck> {
        let list = self.start_view().list.clone();
        let Some(feeds) = loaded(&self.work, list.as_ref(), &self.work_host()) else {
            return Vec::new();
        };
        let Some(link) = self.station.as_ref().and_then(|station| station.link()) else {
            return Vec::new();
        };
        let now_d = self.start_view().now_d_ms;
        feeds.acks_due(link, now_d)
    }

    /// An ack's wire text, by the shared core's builder; one it refuses
    /// stays owed, unsent, and is logged (the first, then at powers of
    /// two).
    pub(crate) fn ack_text(&mut self, due: &DueAck) -> Option<String> {
        #[cfg(test)]
        {
            use atem_client::control::AckResult;
            let ids = due
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

    /// What control records' effects asked of the bridge once their
    /// transaction committed ([`Followup`], design I.5.5 to I.5.7), carried
    /// out after the Station's messages and in host-work's pass, hosting
    /// paused or not (a stop always wins), in their order:
    /// - **the fences** first, at once (a later error drops none): with
    ///   `host.delegated` on, session-v1's §H fence of the revoked service,
    ///   each attachment closed after `unauthorized`, `revoked`
    ///   (`R9Host::fence_revoked`, once per revoke); with it off a record
    ///   still reaches the tasks it holds, but nothing of session-v1 (hook
    ///   off = main);
    /// - then the services' r9 admission as the control state stands
    ///   ([`HostBridge::sync_services`]);
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
        let mut rest = Vec::new();
        for followup in followups {
            match followup {
                Followup::Fence { principal } => {
                    if self.features.delegated {
                        let effects = self.r9_call(|r9, parts| r9.fence_revoked(&principal, parts));
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
                Followup::Fence { .. } => {}
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
    ///   standings ([`HostBridge::sync_revoked`]).
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
            return;
        }
        if !unchecked {
            self.sync_revoked(cx);
        } else if self.kept_elsewhere() && !self.r9.revoked_services().is_empty() {
            // Another identity's standings aren't this one's (a new
            // identity, a new store): its services wait as unchecked
            // (ruling T35e).
            self.r9.set_revoked_services(HashSet::new());
        }
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
        Some(format!(
            "{gate}{}{alerts}{services}",
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

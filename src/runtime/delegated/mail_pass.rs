//! The receiving host's mailbox client in the bridge (host-work-v1 §11.5,
//! "The mailbox calls"; the delegated host-work design II.4.2, II.4.3,
//! II.5), with the debug-only hook's `host.senders` on: the Station link's
//! mailbox messages handed to the client ([`MailboxClient`]) with the store
//! as committed, each page committed in one transaction before anything of
//! it is visible ([`mailbox_store::commit_page`]), a reset marked durably
//! before it is read, the client's calls handed to the link at the end of
//! the Station step, and the gate's mailbox part copied into the start view.
//!
//! The mailbox reads and writes only while the store is this identity's
//! (the control feeds loaded for the committed device list and the host's
//! identity, the receipt database healthy, a pinned list): another
//! identity's store, kept while hosting is paused across a re-verify, takes
//! nothing and owes nothing on this link. With the hook off nothing here
//! runs: no table is made, no call goes.
use super::*;
use crate::runtime::delegated::mailbox::PageCheck;
use crate::runtime::delegated::mailbox_store::{self, Commit};
use crate::runtime::delegated::station::Call;
use crate::runtime::delegated::sync::HostIdentity;
use atem_client::control::RelayError;
use atem_client::host_mail::mailbox::MailboxToHost;
use std::sync::atomic::{AtomicU64, Ordering};

/// A runtime.log line that would come at every pass (a store the mailbox
/// can't use): the first, then at powers of two.
pub(super) fn log_limited(count: &AtomicU64, line: impl FnOnce() -> String) {
    let n = count.fetch_add(1, Ordering::Relaxed) + 1;
    if n.is_power_of_two() {
        eprintln!("{} ({n} so far)", line());
    }
}

static UNPREPARED: AtomicU64 = AtomicU64::new(0);
static UNREADABLE: AtomicU64 = AtomicU64::new(0);
static UNJUDGED: AtomicU64 = AtomicU64::new(0);
static UNPRUNED: AtomicU64 = AtomicU64::new(0);
static UNMARKED: AtomicU64 = AtomicU64::new(0);
static UNREWOUND: AtomicU64 = AtomicU64::new(0);

/// While the device list stands still, the waiting objects are judged
/// again for a passed expiry at most this often.
const MAIL_REJUDGE_EVERY: std::time::Duration = std::time::Duration::from_secs(10);
/// The mailbox's claims and evidence are pruned at most this often.
const MAIL_PRUNE_EVERY: std::time::Duration = std::time::Duration::from_secs(60);

impl HostBridge {
    /// The host's identity as the mailbox binds it: the session host's
    /// account, device and trust generation and the pinned list's genesis.
    fn mail_identity(&self) -> Option<HostIdentity> {
        let genesis = self
            .membership
            .as_ref()
            .filter(|m| !m.unpaired())
            .map(|m| m.membership().genesis_hash())?;
        Some(HostIdentity {
            host: self.work_host(),
            genesis: Some(genesis),
            host_key: self.host_key.as_ref().and_then(|key| key.public_key()),
        })
    }

    /// The store the mailbox reads and writes, and the identity it binds
    /// (the module docs): none with the hook's `host.senders` off.
    pub(crate) fn mail_store(&self) -> Option<(&Store, HostIdentity)> {
        if !(self.features.delegated && self.features.senders) {
            return None;
        }
        let identity = self.mail_identity()?;
        let list = self.start_view().list.clone();
        delegated_feed_pass::loaded(&self.work, list.as_ref(), &identity.host)?;
        Some((self.work.store.as_ref()?, identity))
    }

    /// The store as committed, for the client (none: not loaded, or a
    /// stored state of another identity, fail closed). The mailbox's
    /// tables are made in this identity's store first.
    pub(crate) fn mail_observe(&mut self) {
        if !self.features.senders || self.station.is_none() {
            return;
        }
        if let Some((store, identity)) = self.mail_store()
            && self.work.mail_prepared.as_ref() != Some(&identity.host)
        {
            // The sending host's outbox tables too (`remote_send`),
            // admission's (`admit`) and the results back's
            // (`results_back`).
            match mailbox_store::prepare(store)
                .and_then(|()| crate::runtime::delegated::remote_send::prepare(store))
                .and_then(|()| crate::runtime::delegated::admit::prepare(store))
                .and_then(|()| crate::runtime::delegated::results_back::prepare(store))
            {
                Ok(()) => self.work.mail_prepared = Some(identity.host),
                Err(error) => log_limited(&UNPREPARED, || {
                    format!(
                        "atem runtime: host senders' mailbox tables couldn't be made ({error:#})"
                    )
                }),
            }
        }
        let observed = self.mail_store().and_then(|(store, identity)| {
            match mailbox_store::read(store, &identity) {
                Ok(observed) => Some(observed),
                Err(error) => {
                    log_limited(&UNREADABLE, || {
                        format!("atem runtime: host senders' mailbox state unreadable ({error:#})")
                    });
                    None
                }
            }
        });
        if let Some(station) = self.station.as_mut() {
            station.mailbox.observe(observed);
        }
    }

    /// A mailbox message on the link, after it was read strictly.
    pub(crate) fn mail_inbound(&mut self, message: Result<MailboxToHost, RelayError>) {
        self.mail_observe();
        let Some(station) = self.station.as_mut() else {
            return;
        };
        let check = match message {
            Ok(MailboxToHost::SyncResult(page)) => station.mailbox.on_page(Ok(page)),
            Err(error) => station.mailbox.on_page(Err(error)),
            Ok(MailboxToHost::SyncRefused(_)) => {
                station.mailbox.on_sync_refused();
                PageCheck::Nothing
            }
            Ok(MailboxToHost::DoneRefused(_)) => {
                station.mailbox.on_done_refused();
                PageCheck::Nothing
            }
            Ok(MailboxToHost::DoneResult(result)) => {
                if let Some((mailbox_id, position)) = station.mailbox.on_done_result(result) {
                    self.mail_done_answered(&mailbox_id, position);
                }
                PageCheck::Nothing
            }
            // Answers to this host's own puts (the sending host's outbox).
            Ok(answer @ (MailboxToHost::Stored(_) | MailboxToHost::PutRefused(_))) => {
                self.outbox_answer(answer);
                PageCheck::Nothing
            }
        };
        if let PageCheck::Apply(applying) = check {
            self.mail_commit(applying);
        }
        self.mail_step();
    }

    /// The done of `position` answered: no longer owed (a write that fails
    /// leaves it owed, sent again: harmless).
    fn mail_done_answered(&mut self, mailbox_id: &str, position: u64) {
        if let Some((store, identity)) = self.mail_store()
            && let Err(error) = mailbox_store::done_answered(store, &identity, mailbox_id, position)
        {
            eprintln!("atem runtime: an answered mailbox done couldn't be cleared ({error:#})");
        }
        self.mail_observe();
    }

    /// This host as the receiver its objects are decided with (design
    /// II.4.2): its committed device list, its own identity's host id and
    /// trust generation with that generation's key and record
    /// (`host_enc::recipient_at`), and the delegated clock's `D`. None
    /// while the list doesn't serve or `D` can't be read: nothing is
    /// decided then.
    fn mail_receiver(
        &self,
    ) -> Option<(
        crate::session_protocol::membership::ListState,
        crate::session_protocol::r9::host_enc::HostRecipient,
        u64,
    )> {
        let view = self.start_view();
        let list = view.list.clone().filter(FeedStore::serves)?;
        let now_ms = view.now_d_ms?;
        drop(view);
        let host = self.work_host();
        let receiver = crate::session_protocol::r9::host_enc::recipient_at(
            self.pairing.as_ref()?,
            host.atem_device_id,
            host.host_trust_gen,
        );
        Some((list, receiver, now_ms))
    }

    /// A page that answers the live call, committed from the store's own
    /// cursor in one transaction: its objects' decisions, their rows, the
    /// dones owed and the cursor. Only then is any done sent.
    fn mail_commit(&mut self, applying: crate::runtime::delegated::mailbox::Applying) {
        let receiver = if applying.page.objects.is_empty() {
            None
        } else {
            self.mail_receiver()
        };
        let committed = match self.mail_store() {
            Some((store, identity)) => {
                let cx = receiver
                    .as_ref()
                    .map(|(list, r, now_ms)| mailbox_store::DecideCx {
                        list: &list.membership,
                        recipient: &r.recipient,
                        provider: &r.provider,
                        now_ms: *now_ms,
                        limits: self.work.mail_limits,
                    });
                mailbox_store::commit_page(store, &identity, &applying.page, cx.as_ref())
            }
            None => Ok(Commit::Undecided),
        };
        // Debug builds: the runtime is killed here, the page's decisions
        // and owed dones durable, no done sent yet (tests: what the store
        // owes and which dones are live at that point).
        if matches!(&committed, Ok(Commit::Committed(c)) if !c.decided.is_empty()) {
            #[cfg(not(test))]
            crate::runtime::test_hooks::crash_point(
                "crash_after_mailbox_commit",
                "after a mailbox page's commit, before its dones",
            );
            #[cfg(test)]
            {
                let owed = self
                    .mail_store()
                    .and_then(|(store, identity)| mailbox_store::owed_dones(store, &identity).ok())
                    .unwrap_or_default();
                let live = self
                    .station
                    .as_ref()
                    .map(|station| station.mailbox.live_done_positions())
                    .unwrap_or_default();
                self.work.mail_crash_probe.push((owed, live));
            }
        }
        self.mail_observe();
        // Admission takes what the page opened on the next pass.
        if matches!(&committed, Ok(Commit::Committed(c)) if !c.decided.is_empty()) {
            self.work.admit_due = true;
        }
        let Some(station) = self.station.as_mut() else {
            return;
        };
        match committed {
            Ok(Commit::Committed(_)) => station.mailbox.committed(applying),
            Ok(Commit::Stale) => {
                station.mailbox.failed();
            }
            Ok(Commit::Undecided) => station.mailbox.failed(),
            Err(error) => {
                eprintln!(
                    "atem runtime: a mailbox page couldn't be committed ({error:#}); nothing of it applied, asked again"
                );
                station.mailbox.failed();
            }
        }
    }

    /// After every mailbox step: a reset found is marked durably before
    /// it is read (rule 7), and the gate's mailbox part goes to the start
    /// view.
    pub(crate) fn mail_step(&mut self) {
        if !self.features.senders {
            return;
        }
        let due = self
            .station
            .as_ref()
            .and_then(|station| station.mailbox.reset_due());
        if let Some(mailbox_id) = due {
            let marked = self
                .mail_store()
                .map(|(store, identity)| mailbox_store::mark_reset(store, &identity, &mailbox_id));
            match marked {
                Some(Ok(())) => {
                    self.mail_observe();
                    if let Some(station) = self.station.as_mut() {
                        station.mailbox.reset_written();
                    }
                }
                // Nothing is asked of it until it is marked.
                Some(Err(error)) => log_limited(&UNMARKED, || {
                    format!("atem runtime: host senders' mailbox reset not marked ({error:#})")
                }),
                None => {}
            }
        }
        // Room freed since an object was left on the Station for want of
        // it (ruling R31), or `D` past the expiry of every such object
        // (review P4: the Station has dropped them): the cursor rewound
        // durably, then read again.
        let now_d = self.start_view().now_d_ms;
        let due = self.station.as_ref().is_some_and(|station| {
            station.mailbox.rewind_due()
                || station
                    .mailbox
                    .skip_expires()
                    .zip(now_d)
                    .is_some_and(|(expires, now)| expires <= now)
        });
        if due {
            let now = now_d.unwrap_or(0);
            let rewound = self
                .mail_store()
                .map(|(store, identity)| mailbox_store::rewind_if_room(store, &identity, now));
            match rewound {
                Some(Ok(true)) => {
                    self.mail_observe();
                    if let Some(station) = self.station.as_mut() {
                        station.mailbox.cursor_rewound();
                    }
                }
                Some(Err(error)) => log_limited(&UNREWOUND, || {
                    format!("atem runtime: host senders' mailbox not rewound ({error:#})")
                }),
                _ => {}
            }
        }
        self.publish_mail_gate();
    }

    /// The waiting objects judged again, in one transaction, after the
    /// committed device list moved or once one's expiry passed (design
    /// II.4.2): those decided owe their dones. Nothing is read beyond the
    /// store while nothing waits or neither changed.
    fn mail_rejudge(&mut self) {
        let due = {
            let Some((store, identity)) = self.mail_store() else {
                return;
            };
            let Ok(Some(earliest)) = mailbox_store::pending_expiry(store) else {
                return;
            };
            let view = self.start_view();
            let Some(head) = view.list.as_ref().map(|l| l.membership.head()) else {
                return;
            };
            // A passed expiry, or a failed attempt, is tried again only
            // after the throttle; a list that moved at once.
            let throttled = self
                .work
                .mail_rejudge_at
                .is_some_and(|at| at.elapsed() < MAIL_REJUDGE_EVERY);
            let expired = view.now_d_ms.is_some_and(|now| earliest <= now) && !throttled;
            // Room freed since moves it too (review P1): a waiting object
            // that decided to open with no room is judged again then.
            let freed = mailbox_store::freed(store).unwrap_or(0);
            let key = (identity.host, head.seq, head.hash, freed);
            let moved = self.work.mail_rejudged.as_ref() != Some(&key)
                && !(self.work.mail_rejudge_failed && throttled);
            (expired || moved).then_some(key)
        };
        let Some(key) = due else {
            return;
        };
        self.work.mail_rejudge_at = Some(std::time::Instant::now());
        let Some((list, receiver, now_ms)) = self.mail_receiver() else {
            return;
        };
        let Some((store, identity)) = self.mail_store() else {
            return;
        };
        let cx = mailbox_store::DecideCx {
            list: &list.membership,
            recipient: &receiver.recipient,
            provider: &receiver.provider,
            now_ms,
            limits: self.work.mail_limits,
        };
        let judged = mailbox_store::rejudge_pending(store, &identity, &cx);
        self.work.mail_rejudge_failed = judged.is_err();
        match judged {
            Ok(decided) => {
                self.work.mail_rejudged = Some(key);
                // Admission takes what opened on the next pass.
                self.work.admit_due |= !decided.is_empty();
            }
            Err(error) => log_limited(&UNJUDGED, || {
                format!(
                    "atem runtime: host senders' waiting mailbox objects not judged again ({error:#})"
                )
            }),
        }
    }

    /// The claims, evidence and kept results whose time is over (a margin
    /// after their object's expiry, on the delegated clock's `D`), at most
    /// once a minute.
    fn mail_prune(&mut self) {
        if self
            .work
            .mail_pruned_at
            .is_some_and(|at| at.elapsed() < MAIL_PRUNE_EVERY)
        {
            return;
        }
        let Some(now_ms) = self.start_view().now_d_ms else {
            return;
        };
        // Not while a forward jump's anchor is pending: `D` may still come
        // back down, and pruning on it would be early (review O3). A step
        // the OS reports synchronized makes no anchor: admission's own
        // dedupe of `(sender host, message id)` against its permanent
        // records is what keeps a pruned claim from re-admitting a request.
        if self
            .work
            .clock
            .as_ref()
            .is_some_and(crate::runtime::host_clock::HostClock::anchored)
        {
            return;
        }
        let Some((store, _)) = self.mail_store() else {
            return;
        };
        // Admission's early stops past their expiry too: their request can
        // no longer come (review M1: here, never under an anchor).
        let pruned = mailbox_store::prune(store, now_ms)
            .and_then(|_| crate::runtime::delegated::admit::prune_stops(&store.db, now_ms))
            .and_then(|_| crate::runtime::delegated::admit::prune_refusals(&store.db, now_ms));
        if let Err(error) = pruned {
            log_limited(&UNPRUNED, || {
                format!("atem runtime: host senders' mailbox records not pruned ({error:#})")
            });
        }
        self.work.mail_pruned_at = Some(std::time::Instant::now());
    }

    /// The pass's tick, after its messages: the waiting objects judged
    /// again when due, a call unanswered for 35 s retired, a sync due
    /// asked.
    pub(crate) fn mail_tick(&mut self, now_mono: u64) {
        if !self.features.senders {
            return;
        }
        // The tables made first (N1), then the waiting objects and pruning.
        self.mail_observe();
        self.mail_rejudge();
        self.mail_prune();
        self.mail_observe();
        if let Some(station) = self.station.as_mut() {
            station.mailbox.tick(now_mono);
        }
        self.mail_step();
        // The sending host's puts.
        self.outbox_tick(now_mono);
    }

    /// The gate's mailbox part into the start view (host senders only,
    /// design II.5).
    /// The mailbox's alert lines go to runtime.log here.
    pub(crate) fn publish_mail_gate(&mut self) {
        let Some(station) = self.station.as_mut() else {
            self.start_view().gates.set_mailbox(false);
            return;
        };
        for line in station.mailbox.take_lines() {
            eprintln!("{line}");
        }
        let open = station.mailbox.open();
        let held = station.mailbox.held();
        let mut view = self.start_view();
        view.gates.set_mailbox(open);
        view.gates.set_mailbox_held(held);
    }

    /// `atem status`'s mailbox part, on the `Control feeds:` line (with
    /// `host.senders` on).
    pub(crate) fn mail_status(&self) -> Option<String> {
        if !(self.features.delegated && self.features.senders) {
            return None;
        }
        let station = self.station.as_ref()?;
        let part = match station.mailbox.closed() {
            None => "host senders' mailbox read to its head".to_string(),
            Some(why) => format!("host senders' mailbox not checked ({why})"),
        };
        Some(match station.mailbox.alerts() {
            (0, _) | (_, None) => part,
            (n, Some(latest)) => {
                format!("{part}; {n} mailbox alert(s) since the start, the latest: {latest}")
            }
        })
    }

    /// The mailbox calls to hand the link now, this host's puts last.
    pub(crate) fn mail_outgoing(&mut self) -> Vec<Call> {
        let Some(station) = self.station.as_mut() else {
            return Vec::new();
        };
        let out = station.mailbox.take_outgoing();
        let mut calls: Vec<Call> = out
            .sync
            .into_iter()
            .map(Call::MailboxSync)
            .chain(out.dones.into_iter().map(Call::MailboxDone))
            .collect();
        calls.extend(self.outbox_outgoing());
        calls
    }
}

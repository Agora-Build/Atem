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
fn log_limited(count: &AtomicU64, line: impl FnOnce() -> String) {
    let n = count.fetch_add(1, Ordering::Relaxed) + 1;
    if n.is_power_of_two() {
        eprintln!("{} ({n} so far)", line());
    }
}

static UNPREPARED: AtomicU64 = AtomicU64::new(0);
static UNREADABLE: AtomicU64 = AtomicU64::new(0);

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
        })
    }

    /// The store the mailbox reads and writes, and the identity it binds
    /// (the module docs): none with the hook's `host.senders` off.
    fn mail_store(&self) -> Option<(&Store, HostIdentity)> {
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
            match mailbox_store::prepare(store) {
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
            // This host puts nothing (the sending host's outbox isn't
            // built): answers to puts it never made change nothing (rule 8).
            Ok(MailboxToHost::Stored(_) | MailboxToHost::PutRefused(_)) => PageCheck::Nothing,
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
                        limits: mailbox_store::Limits::default(),
                    });
                mailbox_store::commit_page(store, &identity, &applying.page, cx.as_ref())
            }
            None => Ok(Commit::Undecided),
        };
        // Debug builds: the runtime is killed here, the page's decisions
        // and owed dones durable, no done sent yet.
        #[cfg(not(test))]
        if matches!(&committed, Ok(Commit::Committed(c)) if !c.decided.is_empty()) {
            crate::runtime::test_hooks::crash_point(
                "crash_after_mailbox_commit",
                "after a mailbox page's commit, before its dones",
            );
        }
        self.mail_observe();
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
                Some(Err(error)) => {
                    eprintln!("atem runtime: host senders' mailbox reset not marked ({error:#})")
                }
                None => {}
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
            let expired = view.now_d_ms.is_some_and(|now| earliest <= now);
            let key = (identity.host, head.seq, head.hash);
            (expired || self.work.mail_rejudged.as_ref() != Some(&key)).then_some(key)
        };
        let Some(key) = due else {
            return;
        };
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
            limits: mailbox_store::Limits::default(),
        };
        match mailbox_store::rejudge_pending(store, &identity, &cx) {
            Ok(_) => self.work.mail_rejudged = Some(key),
            Err(error) => eprintln!(
                "atem runtime: host senders' waiting mailbox objects not judged again ({error:#})"
            ),
        }
    }

    /// The pass's tick, after its messages: the waiting objects judged
    /// again when due, a call unanswered for 35 s retired, a sync due
    /// asked.
    pub(crate) fn mail_tick(&mut self, now_mono: u64) {
        if !self.features.senders {
            return;
        }
        self.mail_rejudge();
        self.mail_observe();
        if let Some(station) = self.station.as_mut() {
            station.mailbox.tick(now_mono);
        }
        self.mail_step();
    }

    /// The gate's mailbox part into the start view (host senders only,
    /// design II.5).
    pub(crate) fn publish_mail_gate(&mut self) {
        let open = self
            .station
            .as_ref()
            .is_some_and(|station| station.mailbox.open());
        self.start_view().gates.set_mailbox(open);
    }

    /// `atem status`'s mailbox part, on the `Control feeds:` line (with
    /// `host.senders` on).
    pub(crate) fn mail_status(&self) -> Option<String> {
        if !(self.features.delegated && self.features.senders) {
            return None;
        }
        let station = self.station.as_ref()?;
        Some(match station.mailbox.closed() {
            None => "host senders' mailbox read to its head".into(),
            Some(why) => format!("host senders' mailbox not checked ({why})"),
        })
    }

    /// The mailbox calls to hand the link now.
    pub(crate) fn mail_outgoing(&mut self) -> Vec<Call> {
        let Some(station) = self.station.as_mut() else {
            return Vec::new();
        };
        let out = station.mailbox.take_outgoing();
        out.sync
            .into_iter()
            .map(Call::MailboxSync)
            .chain(out.dones.into_iter().map(Call::MailboxDone))
            .collect()
    }
}

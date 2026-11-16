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
    /// stored state of another identity, fail closed).
    pub(crate) fn mail_observe(&mut self) {
        if !self.features.senders || self.station.is_none() {
            return;
        }
        let observed = self.mail_store().and_then(|(store, identity)| {
            match mailbox_store::read(store, &identity) {
                Ok(observed) => Some(observed),
                Err(error) => {
                    eprintln!("atem runtime: host senders' mailbox state unreadable ({error:#})");
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
            // This host puts nothing (the sending host's outbox isn't
            // built), and marks nothing done yet: answers to calls it never
            // made change nothing (rule 8).
            Ok(_) => PageCheck::Nothing,
        };
        if let PageCheck::Apply(applying) = check {
            self.mail_commit(applying);
        }
        self.mail_step();
    }

    /// A page that answers the live call, committed from the store's own
    /// cursor in one transaction.
    fn mail_commit(&mut self, applying: crate::runtime::delegated::mailbox::Applying) {
        let committed = match self.mail_store() {
            Some((store, identity)) => {
                mailbox_store::commit_page(store, &identity, &applying.page, None)
            }
            None => Ok(Commit::Undecided),
        };
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
    /// it is read (rule 7).
    pub(crate) fn mail_step(&mut self) {
        if !self.features.senders {
            return;
        }
        let due = self
            .station
            .as_ref()
            .and_then(|station| station.mailbox.reset_due());
        if let Some(mailbox_id) = due {
            let marked = match self.mail_store() {
                Some((store, identity)) => mailbox_store::mark_reset(store, &identity, &mailbox_id),
                None => Err(anyhow::anyhow!("the mailbox state isn't loaded")),
            };
            match marked {
                Ok(()) => {
                    self.mail_observe();
                    if let Some(station) = self.station.as_mut() {
                        station.mailbox.reset_written();
                    }
                }
                Err(error) => eprintln!(
                    "atem runtime: host senders' mailbox reset couldn't be marked ({error:#}); nothing is asked of it until it is"
                ),
            }
        }
    }

    /// The pass's tick, after its messages: a call unanswered for 35 s
    /// retired, a sync due asked.
    pub(crate) fn mail_tick(&mut self, now_mono: u64) {
        if !self.features.senders {
            return;
        }
        self.mail_observe();
        if let Some(station) = self.station.as_mut() {
            station.mailbox.tick(now_mono);
        }
        self.mail_step();
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

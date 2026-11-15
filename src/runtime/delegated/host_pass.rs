//! Host senders' device-list effects in the bridge (the delegated host-work
//! design II.2.2, II.3.1 "Crash safety", II.8): each pass, with
//! `host.senders` on, the entries of the committed device list after
//! host-work's applied `seq` reach host senders' tasks
//! ([`host_senders::list_effects`]) in one transaction with the new applied
//! `seq`; what they ask after the commit (a live attempt's withdrawal, the
//! interrupt intents) goes with the control records' followups
//! (`effects_pass`). It runs where the control feeds' pending records are
//! applied again when the list moved (`feeds_reverify`), just before them,
//! so a host principal's `interrupt_running` record waiting for its
//! revoke's effects sees them; at a start that is before the recovery of
//! delegated tasks, so a crash between an entry's commit and its effects
//! is replayed before anything is dispatched and ahead of the recovery's
//! interrupt-intent step (design I.6.2).
//!
//! Nothing runs with the hook off (no table is made: hook off = main),
//! while the device list doesn't serve (frozen, held, faulted, gone: the
//! start check fails or holds every delegated task then), with a
//! receipt-database fault, or on a store bound to another identity.
use super::*;
use crate::runtime::delegated::effects::Followup;
use crate::runtime::delegated::host_senders;

impl HostBridge {
    /// See the module doc. A store error is a receipt-database fault.
    pub(crate) fn host_senders_pass(&mut self) {
        if !(self.features.delegated && self.features.senders) || self.work.error {
            return;
        }
        self.sync_list_view();
        let Some(list) = self.start_view().list.clone() else {
            return;
        };
        if !FeedStore::serves(&list) {
            return;
        }
        let identity = self.work_host();
        let head = list.membership.head();
        let key = (identity.clone(), head.seq, head.hash);
        if self.work.host_applied.as_ref() == Some(&key) {
            return;
        }
        let Some(store) = self.work.store.as_ref() else {
            return;
        };
        if !matches!(store.bound(), Ok(Some(bound)) if bound == identity) {
            return;
        }
        let genesis = list.membership.genesis_hash();
        let done = (|| -> anyhow::Result<(u64, Vec<Followup>)> {
            let after = host_senders::applied_seq(&store.db, &genesis)?;
            if after >= head.seq {
                return Ok((after, Vec::new()));
            }
            let tx = store.immediate()?;
            let followups = host_senders::list_effects(
                store,
                &tx,
                &list.membership,
                &identity.atem_device_id,
                after,
            )?;
            host_senders::set_applied_seq(&tx, &genesis, head.seq)?;
            tx.commit()?;
            Ok((head.seq, followups))
        })();
        match done {
            Ok((applied, followups)) => {
                self.work.followups.extend(followups);
                self.work.host_applied = Some(key);
                // Kept in memory from its commit (or its read): the sync and
                // the re-verification read it from here.
                self.work.applied_seq = Some((identity, genesis, applied));
            }
            Err(error) => {
                eprintln!(
                    "atem runtime: host senders' device-list effects couldn't be written ({error:#})"
                );
                self.work_fail();
            }
        }
    }
}

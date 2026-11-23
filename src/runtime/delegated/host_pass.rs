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
//! interrupt-intent step (design I.6.2). The applied `seq` goes into the
//! start view once written or read: until it reaches the committed head, a
//! host sender's task doesn't start (`StartView::host_effects_at`), since a
//! project entry is judged on the list as of that entry, and the head alone
//! may cover a task an entry before it stopped (the owner's decision,
//! 2026-11-22). A spawn is a start (ruling R51): this run's queued launches
//! on message are judged per entry too, one an entry stopped leaving the
//! queue (the launcher's spawn check refuses one it holds,
//! `StartView::stop_launch`).
//!
//! Each `host_sender_revoke` applied gets its result owed the host's own
//! Station in the same transaction (host-work-v1 §11.4, wire rule 4's
//! entry form, `acks::Acked::entry`; design II.3.1, "Reporting a revoke as
//! applied"): through the acknowledgments' book in a feed transaction
//! (`FeedStore::acknowledge`) when the feeds are loaded for this identity
//! and list, else into the book's table (`AckBook::owe`), for the book that
//! loads it. It goes with the next acknowledgments, after the commit; a
//! crash before the commit loses it with the effects, and the replay writes
//! both once. Nothing is reported before the effects are written (never
//! `pending`: Atem's reading, for Astation's confirmation).
//!
//! Nothing runs with the hook off (no table is made: hook off = main),
//! while the device list doesn't serve (frozen, held, faulted, gone: the
//! start check fails or holds every delegated task then), with a
//! receipt-database fault, or on a store bound to another identity.
use super::delegated_feed_pass::loaded;
use super::*;
use crate::runtime::delegated::acks::{AckBook, Acked};
use crate::runtime::delegated::effects::Followup;
use crate::runtime::delegated::feeds::Feeds;
use crate::runtime::delegated::host_senders::{self, ListEffects, QueuedLaunch};
use crate::runtime::delegated::start::Event;
use rusqlite::Transaction;

/// What the entries' transaction wrote: their effects (what they ask after
/// the commit), and the revokes' results owed the host's own Station.
type Written = (ListEffects, Vec<Acked>);

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
        let genesis = list.membership.genesis_hash();
        // This run's launches on message not spawned (ruling R51), read
        // after the head moved: no spawn check has let one go since, as
        // it waits for these effects.
        let launches = self.queued_host_launches();
        // The revokes' results owed the host's own Station go in the
        // effects' transaction (host-work-v1 §11.4): through the
        // acknowledgments' book when the feeds are loaded for this identity
        // and list, else into its table, for the book that loads it.
        let book = loaded(&self.work, Some(&list), &identity).is_some();
        let State {
            feeds,
            store: Some(store),
            ..
        } = &mut self.work
        else {
            return;
        };
        if !matches!(store.bound(), Ok(Some(bound)) if bound == identity) {
            return;
        }
        let done = (|| -> anyhow::Result<(u64, ListEffects)> {
            let after = host_senders::applied_seq(&store.db, &genesis)?;
            if after >= head.seq {
                return Ok((after, ListEffects::default()));
            }
            // The entries' effects, host-work's applied `seq` and the
            // revokes' results, in `tx`.
            let write = |tx: &Transaction| -> anyhow::Result<Written> {
                let effects = host_senders::list_effects(
                    store,
                    tx,
                    &list.membership,
                    &identity.atem_device_id,
                    after,
                    &launches,
                )?;
                host_senders::set_applied_seq(tx, &genesis, head.seq)?;
                let owed = effects
                    .revokes
                    .iter()
                    .map(|r| Acked::entry(&r.host_id, r.entry, r.interrupt_running, head.seq))
                    .collect();
                Ok((effects, owed))
            };
            let effects = match feeds {
                Feeds::Loaded(feeds) if book => {
                    let tx = feeds.begin(store)?;
                    let (effects, owed) = write(&tx)?;
                    feeds.acknowledge(&tx, &owed)?;
                    feeds.commit(tx)?;
                    effects
                }
                _ => {
                    let tx = store.immediate()?;
                    let (effects, owed) = write(&tx)?;
                    AckBook::owe(&tx, &owed)?;
                    tx.commit()?;
                    effects
                }
            };
            Ok((head.seq, effects))
        })();
        match done {
            Ok((applied, effects)) => {
                // A live attempt's stop is on its record (review H1); the
                // view's copy of it is told too (below), so the session
                // host's check at `executing` refuses it.
                let stopped: Vec<(String, Event)> = effects
                    .followups
                    .iter()
                    .filter_map(|followup| match followup {
                        Followup::Withdraw {
                            attempt_id, then, ..
                        } => Some((attempt_id.clone(), *then)),
                        _ => None,
                    })
                    .collect();
                self.work.followups.extend(effects.followups);
                self.work.host_applied = Some(key);
                // The launches an entry stopped leave the queue; one the
                // launcher holds is refused by its spawn check, marked
                // before the applied `seq` lets that check go on.
                let mut held = Vec::new();
                for (request_id, detail) in effects.launches {
                    self.work.pending.remove(&request_id);
                    let queued = self.work.launches.len();
                    self.work.launches.retain(|l| l.request_id != request_id);
                    if self.work.launches.len() == queued {
                        held.push((request_id.clone(), detail));
                    }
                    eprintln!(
                        "atem runtime: launch {request_id} failed before its spawn: {detail} (device list)"
                    );
                }
                let mut view = self.start_view();
                for (request_id, detail) in held {
                    view.stop_launch(&request_id, detail);
                }
                for (attempt_id, event) in stopped {
                    view.list_stop(&attempt_id, event);
                }
                // Host senders' tasks and launches start once it reaches
                // the head the start view shows (`StartView::host_effects_at`).
                view.host_applied = Some((genesis, applied));
                drop(view);
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

    /// Host senders' launches on message this run reserved that no spawn
    /// check let go (ruling R51), by request id.
    fn queued_host_launches(&self) -> Vec<QueuedLaunch> {
        let view = self.start_view();
        let mut out: Vec<QueuedLaunch> = self
            .work
            .pending
            .iter()
            .filter_map(|(request_id, p)| {
                let d = p.delegated.as_ref()?;
                d.launch.admission.host_admitted()?;
                (!view.launch_gone(request_id)).then(|| QueuedLaunch {
                    request_id: request_id.clone(),
                    admission: d.launch.admission.clone(),
                })
            })
            .collect();
        out.sort_by(|a, b| a.request_id.cmp(&b.request_id));
        out
    }
}

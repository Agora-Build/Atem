//! The sending host's side of host senders in the bridge (the delegated
//! host-work design II.4.4, II.6; host-work-v1 §11.5), with the
//! debug-only hook's `host.senders` on (with it off, `atem message send`
//! is exactly stage 1's): a send's plan of other hosts
//! ([`super::send_plan`]), its delivery rows reserved with a send whose
//! context publishes, and its envelopes sealed and enqueued in the
//! transaction that accepts the message ([`super::remote_send`]).
//!
//! The puts ([`super::puts`]): each pass's tick (a put unanswered for 35 s
//! retired, expired rows), the due rows handed to the link with the
//! mailbox's calls, and the Station's answers written to the engine's
//! rows ([`super::outbox`]). Time is the delegated clock's `D`: with no
//! reading nothing is put or expired.
//!
//! The outbox writes only while the store is this identity's (the mailbox
//! client's rule: the control feeds loaded for the committed device list
//! and the host's identity), and plans from the committed device list.
use super::*;
use crate::runtime::delegated::outbox;
use crate::runtime::delegated::puts::{Answer, MAX_LIVE_PUTS};
use crate::runtime::delegated::remote_send::{self, RemotePart, Sealer};
use crate::runtime::delegated::send_plan::{self, Me};
use crate::runtime::delegated::station::Call;
use anyhow::{Result, anyhow, bail};
use atem_client::host_mail::HostRef;
use atem_client::host_mail::mailbox::MailboxToHost;
use atem_client::session::messages::Message;
use atem_client::session::select::{Label, Selector};
use std::sync::atomic::{AtomicU64, Ordering};

impl HostBridge {
    /// The hook's `host.senders` (with `host.delegated`).
    pub(crate) fn senders_on(&self) -> bool {
        self.features.delegated && self.features.senders
    }

    /// The committed device list, when it serves.
    fn send_list(&self) -> Option<std::sync::Arc<atem_client::membership::Membership>> {
        self.start_view()
            .list
            .clone()
            .filter(FeedStore::serves)
            .map(|l| l.membership)
    }

    /// The other hosts `to` reaches (`atem_id`: this host's), with the
    /// send's `launch`: the local part's budget and the part for them; none
    /// with the hook off or when no selector plans another host. The store
    /// must be this identity's, its outbox tables made.
    pub(super) fn remote_plan(
        &mut self,
        atem_id: &str,
        to: &[String],
        launch: bool,
    ) -> Result<Option<(u32, RemotePart)>> {
        if !self.senders_on() {
            return Ok(None);
        }
        let host = self.work_host();
        let Some(list) = self.send_list() else {
            // Only selectors that can't reach another host plan without it.
            let remote = to.iter().any(|s| match s.parse::<Selector>() {
                Ok(Selector::Instance { atem_id: id, .. }) => {
                    id != atem_id && id != host.atem_device_id
                }
                Ok(Selector::All(labels)) => labels.iter().any(|l| matches!(l, Label::Project(_))),
                Err(_) => false,
            });
            if remote {
                bail!("the device list isn't loaded yet; see `atem status`");
            }
            return Ok(None);
        };
        let me = Me {
            host_id: &host.atem_device_id,
            atem_id,
            host_trust_gen: host.host_trust_gen,
        };
        let plan = send_plan::plan(&list, me, to, launch).map_err(|e| anyhow!("{e}"))?;
        if plan.remote.is_empty() {
            return Ok(None);
        }
        self.mail_observe();
        if self.mail_store().is_none() || self.work.mail_prepared.as_ref() != Some(&host) {
            bail!(
                "host senders' outbox unavailable (the control feeds aren't loaded); see `atem status`"
            );
        }
        Ok(Some((
            plan.local.unwrap_or(1),
            RemotePart::of(&plan, &host.account_id),
        )))
    }

    /// The envelopes of `message` (accepted, its context frozen) to `part`'s
    /// hosts, sealed and enqueued in the accepting transaction `tx`.
    pub(super) fn remote_seal(
        &self,
        tx: &rusqlite::Transaction,
        atem_id: &str,
        message: &Message,
        part: &RemotePart,
    ) -> Result<()> {
        let (Some(list), Some(key)) = (self.send_list(), self.host_key.clone()) else {
            bail!("host senders' outbox unavailable (no device list or host key)");
        };
        let host = self.work_host();
        let sealer = Sealer {
            list: &list,
            me: Me {
                host_id: &host.atem_device_id,
                atem_id,
                host_trust_gen: host.host_trust_gen,
            },
            account: &host.account_id,
            key: &key,
        };
        remote_send::commit_request(tx, &sealer, message, part)
    }

    /// The store the outbox writes (its tables made): none with the hook
    /// off, or while it isn't this identity's.
    fn outbox_store(&self) -> Option<&Store> {
        let (store, identity) = self.mail_store()?;
        (self.work.mail_prepared.as_ref() == Some(&identity.host)).then_some(store)
    }

    /// The pass's tick: a put unanswered for 35 s retired; rows past their
    /// expiry on `D` expired, and final rows' bytes pruned once a minute.
    pub(crate) fn outbox_tick(&mut self, now_mono: u64) {
        if !self.senders_on() {
            return;
        }
        if let Some(station) = self.station.as_mut() {
            station.puts.tick(now_mono);
        }
        let Some(now) = self.start_view().now_d_ms else {
            return;
        };
        let prune = self
            .work
            .outbox_pruned_at
            .is_none_or(|at| at.elapsed() >= std::time::Duration::from_secs(60));
        let Some(store) = self.outbox_store() else {
            return;
        };
        let written = outbox::expire(store, now).and_then(|_| {
            if prune {
                outbox::prune(store, now)?;
            }
            Ok(())
        });
        if prune {
            self.work.outbox_pruned_at = Some(std::time::Instant::now());
        }
        if let Err(error) = written {
            outbox_fault(error);
        }
    }

    /// This host's puts to hand the link now: its due rows on `D`, as many
    /// as may be live.
    pub(crate) fn outbox_outgoing(&mut self) -> Vec<Call> {
        if !self.senders_on() {
            return Vec::new();
        }
        let Some(now) = self.start_view().now_d_ms else {
            return Vec::new();
        };
        let host = self.work_host();
        let me = HostRef {
            host_id: host.atem_device_id,
            host_trust_gen: host.host_trust_gen,
        };
        let live = match self.station.as_ref() {
            Some(station) => station.puts.live_rows(),
            None => return Vec::new(),
        };
        let Some(place) = self.outbox_place() else {
            return Vec::new();
        };
        let due = match self
            .outbox_store()
            .map(|store| outbox::due(store, &me, now, place, &live, MAX_LIVE_PUTS))
        {
            Some(Ok(due)) => due,
            Some(Err(error)) => {
                outbox_fault(error);
                return Vec::new();
            }
            None => return Vec::new(),
        };
        let Some(station) = self.station.as_mut() else {
            return Vec::new();
        };
        station
            .puts
            .take(due)
            .into_iter()
            .map(Call::MailboxPut)
            .collect()
    }

    /// Where a put goes now: the link generation and the committed
    /// device-list head (none without a link).
    fn outbox_place(&self) -> Option<outbox::Place> {
        let link_gen = self.station.as_ref()?.link()?.link_gen;
        let head_seq = self.send_list().map_or(0, |list| list.head().seq);
        Some(outbox::Place { link_gen, head_seq })
    }

    /// The Station's answer to a put: written to its row when it answers a
    /// live put (a write that fails leaves the row due: put again, harmless).
    pub(crate) fn outbox_answer(&mut self, answer: MailboxToHost) {
        let Some(station) = self.station.as_mut() else {
            return;
        };
        let (n, code) = match &answer {
            MailboxToHost::Stored(stored) => (station.puts.on_stored(stored), None),
            MailboxToHost::PutRefused(refused) => {
                (station.puts.on_refused(refused), Some(refused.code))
            }
            _ => return,
        };
        let Answer::Row(n) = n else {
            return;
        };
        let now = self
            .start_view()
            .now_d_ms
            .unwrap_or_else(|| host_now().wall_ms);
        let Some(place) = self.outbox_place() else {
            return;
        };
        let Some(store) = self.outbox_store() else {
            return;
        };
        let written = match code {
            None => outbox::stored(store, n, now),
            Some(code) => outbox::refused(store, n, code, now, place),
        };
        if let Err(error) = written {
            outbox_fault(error);
        }
    }
}

/// A runtime.log line for an outbox write that failed: the first, then at
/// powers of two.
fn outbox_fault(error: anyhow::Error) {
    static FAULTS: AtomicU64 = AtomicU64::new(0);
    let n = FAULTS.fetch_add(1, Ordering::Relaxed) + 1;
    if n.is_power_of_two() {
        eprintln!("atem runtime: host senders' outbox not written ({error:#}) ({n} so far)");
    }
}

//! The sending host's side of host senders in the bridge (the delegated
//! host-work design II.4.4, II.6; host-work-v1 §11.5), with the
//! debug-only hook's `host.senders` on (with it off, `atem message send`
//! is exactly stage 1's): a send's plan of other hosts
//! ([`super::send_plan`]), its delivery rows reserved with a send whose
//! context publishes, and its envelopes sealed and enqueued in the
//! transaction that accepts the message ([`super::remote_send`]).
//!
//! The outbox writes only while the store is this identity's (the mailbox
//! client's rule: the control feeds loaded for the committed device list
//! and the host's identity), and plans from the committed device list.
use super::*;
use crate::runtime::delegated::remote_send::{self, RemotePart, Sealer};
use crate::runtime::delegated::send_plan::{self, Me};
use anyhow::{Result, anyhow, bail};
use atem_client::session::messages::Message;
use atem_client::session::select::{Label, Selector};

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
}

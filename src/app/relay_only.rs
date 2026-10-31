//! Relay only (§R9.8a): while the host policy a manager set says so (or it
//! can't be read, or a write of it is still uncertain), this host reaches
//! Astation only through its relay identity room, never the local
//! `astation_ws`. The policy is set inside an r9 channel
//! (`session_protocol::r9::host_policy`); there is no plaintext message for
//! it. The connect loop (`App::spawn_astation_connect`) reads it with
//! [`local_allowed`]; a commit of `true` while the link is local closes
//! that link once the channel's result was written (at most 5 s).
use super::App;
use crate::websocket_client::{DeliveryReceipt, LinkVia};
use std::time::{Duration, Instant};

/// How long a drop waits for the result to be written once no operation
/// runs on the link.
const RESULT_FLUSH: Duration = Duration::from_secs(5);

/// What a drop waits for before it closes the link.
#[derive(Debug)]
enum Barrier {
    /// Nothing to deliver (a link that landed under relay only).
    None,
    /// The result is queued in its channel, not yet handed to the writer.
    Queued,
    /// The writer has the result; its receipt.
    Writing(DeliveryReceipt),
}

/// A local link drop relay only scheduled (`App::relay_only_drop`): after
/// any Astation operation on that link and the result's delivery.
#[derive(Debug)]
pub struct RelayOnlyDrop {
    /// The link it applies to; a replaced link forgets it.
    link_gen: u64,
    barrier: Barrier,
    /// Set once no operation runs on the link: the drop happens by then
    /// even if the writer never wrote the result.
    due: Option<Instant>,
}

impl RelayOnlyDrop {
    /// Whether the result was written (or can no longer be): no wait.
    fn delivered(&mut self) -> bool {
        match &mut self.barrier {
            Barrier::None => true,
            Barrier::Queued => false,
            Barrier::Writing(receipt) => !matches!(
                receipt.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            ),
        }
    }
}

/// The status after a local link was dropped for relay only.
pub(super) const RELAY_ONLY_RECONNECT: &str =
    "Astation allows only the relay; reconnecting through it";

/// This profile's pairing record, read the one way every link decision
/// reads it: from the profile's pairing path, which doesn't depend on
/// config.toml, so a broken config.toml is never taken for a damaged record.
pub(super) fn stored_record() -> anyhow::Result<Option<crate::records::PairingRecord>> {
    crate::records::PairingRecord::load(&crate::paths::ProfilePaths::default_paths().pairing)
}

/// Whether the host policy allows a local link (no policy, or a readable
/// durable `relay_only: false`; see `host_policy::local_allowed`).
pub(super) fn local_allowed() -> bool {
    crate::session_protocol::r9::host_policy::local_allowed(
        &crate::paths::ProfilePaths::default_paths().pairing,
    )
}

impl App {
    /// The runtime's session host committed `relay_only` (§R9.8a). `true`
    /// on a local link: no new operation or channel is handed this link,
    /// and it closes once the result was written ([`App::relay_only_receipt`])
    /// and no operation runs on it, at most 5 s later. `false` cancels a
    /// drop still waiting. Never waits itself (`check_relay_only_drop`).
    pub(crate) fn host_policy_changed(&mut self, relay_only: bool) {
        if !relay_only {
            self.relay_only_drop = None;
            return;
        }
        if !self.astation_connected || self.astation_client.via() != Some(&LinkVia::Local) {
            return;
        }
        match &mut self.relay_only_drop {
            Some(pending) if pending.link_gen == self.astation_link_gen => {
                // A later result is the barrier (the writer keeps the order).
                pending.barrier = Barrier::Queued;
            }
            _ => {
                self.relay_only_drop = Some(RelayOnlyDrop {
                    link_gen: self.astation_link_gen,
                    barrier: Barrier::Queued,
                    due: None,
                });
            }
        }
    }

    /// The result's frame was handed to the writer: the drop waits for it.
    pub(crate) fn relay_only_receipt(&mut self, receipt: DeliveryReceipt) {
        if let Some(pending) = self.relay_only_drop.as_mut()
            && pending.link_gen == self.astation_link_gen
        {
            pending.barrier = Barrier::Writing(receipt);
        }
    }

    /// Whether an Astation operation runs on the current link.
    fn op_on_link(&self) -> bool {
        self.op_route
            .as_ref()
            .is_some_and(|route| route.link_gen == self.astation_link_gen && !route.tx.is_closed())
    }

    /// Whether relay only is about to drop the current link: no Astation
    /// operation or r9 channel is handed this link (they wait for the next).
    pub(crate) fn relay_only_drop_pending(&self) -> bool {
        self.astation_connected && self.drop_waits()
    }

    /// A local link that (re)authenticated while the host policy says relay
    /// only (or can't be read): dropped by the next pass.
    pub(super) fn drop_local_link_if_relay_only(&mut self) {
        if self.astation_client.via() != Some(&LinkVia::Local) || self.drop_waits() {
            return;
        }
        if stored_record().is_err() || !local_allowed() {
            self.relay_only_drop = Some(RelayOnlyDrop {
                link_gen: self.astation_link_gen,
                barrier: Barrier::None,
                due: None,
            });
        }
    }

    /// Whether a drop of the current link is still waiting.
    fn drop_waits(&self) -> bool {
        self.relay_only_drop
            .as_ref()
            .is_some_and(|pending| pending.link_gen == self.astation_link_gen)
    }

    /// The local link drop relay only scheduled: done once no operation runs
    /// on that link and the result was written (at most `RESULT_FLUSH`
    /// after that, never waiting in the pass); forgotten when the link
    /// already went, or when the policy allows local again by then.
    pub(super) fn check_relay_only_drop(&mut self) {
        if self.relay_only_drop.is_none() {
            return;
        }
        if !self.astation_connected || !self.drop_waits() {
            self.relay_only_drop = None;
            return;
        }
        if self.op_on_link() {
            return;
        }
        let Some(pending) = self.relay_only_drop.as_mut() else {
            return;
        };
        let due = *pending
            .due
            .get_or_insert_with(|| Instant::now() + RESULT_FLUSH);
        if pending.delivered() || Instant::now() >= due {
            self.relay_only_drop = None;
            // Checked again at the close: a later `false` cancels it.
            if stored_record().is_ok() && local_allowed() {
                return;
            }
            self.drop_astation_link(RELAY_ONLY_RECONNECT.into());
        }
    }
}

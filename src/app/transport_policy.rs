//! Astation's transport policy (`transportPolicy`): while `relay_only`, this
//! host reaches Astation only through its relay identity room, never the
//! local `astation_ws`. The value is kept in the pairing record the link
//! authenticated under (`PairingRecord::relay_only`), so `atem unpair` clears
//! it, and the connect loop (`App::spawn_astation_connect`) reads it.
use super::App;
use crate::websocket_client::{AstationMessage, DeliveryReceipt, LinkVia};
use std::time::{Duration, Instant};

/// How long a drop waits for its ack to be written once no operation runs
/// on the link.
const ACK_FLUSH: Duration = Duration::from_secs(5);

/// A local link drop relay only scheduled (`App::relay_only_drop`): after
/// any Astation operation on that link and the ack's delivery.
#[derive(Debug)]
pub struct RelayOnlyDrop {
    /// The link it applies to; a replaced link forgets it.
    link_gen: u64,
    /// The latest ack's delivery: the socket closes only once it was
    /// written (or failed), so the ack reaches Astation before the close.
    receipt: Option<DeliveryReceipt>,
    /// Set once no operation runs on the link: the drop happens by then
    /// even if the writer never wrote the ack.
    due: Option<Instant>,
}

impl RelayOnlyDrop {
    /// Whether the ack was written (or can no longer be): no wait.
    fn delivered(&mut self) -> bool {
        self.receipt.as_mut().is_none_or(|receipt| {
            !matches!(
                receipt.try_recv(),
                Err(tokio::sync::oneshot::error::TryRecvError::Empty)
            )
        })
    }
}

/// The status after a local link was dropped for relay only.
pub(super) const RELAY_ONLY_RECONNECT: &str =
    "Astation allows only the relay; reconnecting through it";

/// Why a `transportPolicy` was not stored (the ack's `reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotStored {
    /// The link has no bound pairing with its Astation (e.g. the loopback
    /// proof without a saved pairing): nothing is created.
    NotPaired,
    /// The pairing or saved session the link authenticated under changed
    /// (unpair, re-pair, a stale link).
    PairingChanged,
    /// The record could not be written.
    SaveFailed,
}

impl NotStored {
    fn code(self) -> &'static str {
        match self {
            NotStored::NotPaired => "not_paired",
            NotStored::PairingChanged => "pairing_changed",
            NotStored::SaveFailed => "save_failed",
        }
    }
}

impl App {
    /// Stores `relay_only` under the link's bound pairing and acknowledges
    /// the result (`stored`, else `stored: false` with a reason; another
    /// binding is never touched). A stored `true` on a local link drops it
    /// once the ack was written (at most 5 s), so the reconnect takes the
    /// relay; while an Astation operation runs on that link the drop waits
    /// until it ends. Never waits itself (`check_relay_only_drop` polls).
    pub(super) async fn transport_policy(&mut self, relay_only: bool) {
        let ack = match self.store_transport_policy(relay_only) {
            Ok(()) => AstationMessage::TransportPolicyAck {
                relay_only,
                stored: true,
                reason: None,
            },
            Err(why) => {
                self.status_message = Some(format!("Transport policy not saved: {}", why.code()));
                AstationMessage::TransportPolicyAck {
                    relay_only,
                    stored: false,
                    reason: Some(why.code().into()),
                }
            }
        };
        let stored = matches!(
            ack,
            AstationMessage::TransportPolicyAck { stored: true, .. }
        );
        let local = self.astation_client.via() == Some(&LinkVia::Local);
        if !stored || !relay_only {
            if stored {
                // Local is allowed again: a drop still waiting is not needed.
                self.relay_only_drop = None;
            }
            let _ = self.astation_client.send_message(ack).await;
        } else if !local {
            // A relay link: nothing more to do.
            let _ = self.astation_client.send_message(ack).await;
        } else {
            // A local link: dropped by `check_relay_only_drop` (this pass,
            // never waiting in it) once no operation runs on it and this
            // ack was written, at most 5 s later. A repeat's ack is the
            // later one (the writer keeps the order), so it is the barrier.
            let receipt = self.astation_client.send_message_with_receipt(ack).ok();
            match &mut self.relay_only_drop {
                Some(pending) if pending.link_gen == self.astation_link_gen => {
                    pending.receipt = receipt;
                }
                _ => {
                    self.relay_only_drop = Some(RelayOnlyDrop {
                        link_gen: self.astation_link_gen,
                        receipt,
                        due: None,
                    });
                }
            }
        }
    }

    /// The store itself: only under the pairing this link authenticated
    /// with, while it is still current.
    fn store_transport_policy(&self, relay_only: bool) -> Result<(), NotStored> {
        let client = &self.astation_client;
        let astation_id = client
            .connected_astation_id()
            .ok_or(NotStored::NotPaired)?
            .to_string();
        let bound = client
            .capture()
            .is_some_and(|capture| capture.bound_to(&astation_id).is_ok());
        if !bound {
            return Err(NotStored::NotPaired);
        }
        let src = client.profile().map_err(|_| NotStored::SaveFailed)?;
        let saved = client.apply_bound(&astation_id, || {
            crate::records::PairingRecord::set_relay_only(
                &src.paths.pairing,
                &astation_id,
                relay_only,
            )
        });
        match saved {
            Ok(true) => Ok(()),
            // The record went (or names another Astation) under the lock.
            Ok(false) => Err(NotStored::PairingChanged),
            Err(_) if !client.capture_current() => Err(NotStored::PairingChanged),
            Err(_) => Err(NotStored::SaveFailed),
        }
    }

    /// Whether an Astation operation runs on the current link.
    fn op_on_link(&self) -> bool {
        self.op_route
            .as_ref()
            .is_some_and(|route| route.link_gen == self.astation_link_gen && !route.tx.is_closed())
    }

    /// Whether relay only is about to drop the current link: no Astation
    /// operation is handed this link (it waits for the next one).
    pub(crate) fn relay_only_drop_pending(&self) -> bool {
        self.astation_connected && self.drop_waits()
    }

    /// A local link that (re)authenticated while the stored record says
    /// relay only (or can't be read): dropped like after a policy, by the
    /// next pass (no ack: no policy message to answer).
    pub(super) fn drop_local_link_if_relay_only(&mut self) {
        if self.astation_client.via() != Some(&LinkVia::Local) || self.drop_waits() {
            return;
        }
        let loaded = self
            .astation_client
            .profile()
            .and_then(|src| crate::records::PairingRecord::load(&src.paths.pairing));
        if !crate::records::PairingRecord::local_allowed(loaded.as_ref().map(Option::as_ref)) {
            self.relay_only_drop = Some(RelayOnlyDrop {
                link_gen: self.astation_link_gen,
                receipt: None,
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
    /// on that link and the ack was written (at most `ACK_FLUSH` after that,
    /// never waiting in the pass); forgotten when the link already went.
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
            .get_or_insert_with(|| Instant::now() + ACK_FLUSH);
        if pending.delivered() || Instant::now() >= due {
            self.relay_only_drop = None;
            self.drop_astation_link(RELAY_ONLY_RECONNECT.into());
        }
    }
}

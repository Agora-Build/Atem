//! Astation's transport policy (`transportPolicy`): while `relay_only`, this
//! host reaches Astation only through its relay identity room, never the
//! local `astation_ws`. The value is kept in the pairing record the link
//! authenticated under (`PairingRecord::relay_only`), so `atem unpair` clears
//! it, and the connect loop (`App::spawn_astation_connect`) reads it.
use super::App;
use crate::websocket_client::{AstationMessage, LinkVia};

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
    /// after the ack, so the reconnect takes the relay; while an Astation
    /// operation runs on that link the drop waits until it ends.
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
        } else if !local || self.relay_only_drop == Some(self.astation_link_gen) {
            // A relay link, or a repeat while the drop waits: nothing to do.
            let _ = self.astation_client.send_message(ack).await;
        } else if self.op_on_link() {
            let _ = self.astation_client.send_message(ack).await;
            self.relay_only_drop = Some(self.astation_link_gen);
        } else {
            // Written before the socket closes (or given up after 5 s).
            let _ = self.astation_client.send_message_flushed(ack).await;
            self.drop_astation_link(RELAY_ONLY_RECONNECT.into());
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

    /// The local link drop relay only deferred: done once the operation on
    /// that link ended; forgotten when the link already went.
    pub(super) fn check_relay_only_drop(&mut self) {
        let Some(link_gen) = self.relay_only_drop else {
            return;
        };
        if !self.astation_connected || self.astation_link_gen != link_gen {
            self.relay_only_drop = None;
        } else if !self.op_on_link() {
            self.relay_only_drop = None;
            self.drop_astation_link(RELAY_ONLY_RECONNECT.into());
        }
    }
}

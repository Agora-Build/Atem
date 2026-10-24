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

impl App {
    /// Stores `relay_only` under the link's bound pairing and acknowledges
    /// it; a local link is then dropped, so the reconnect takes the relay.
    /// Without a bound pairing nothing is stored and nothing acknowledged.
    pub(super) async fn transport_policy(&mut self, relay_only: bool) {
        let Some(astation_id) = self
            .astation_client
            .connected_astation_id()
            .map(str::to_string)
        else {
            self.status_message =
                Some("Transport policy not saved: Astation's identity is unknown".into());
            return;
        };
        let saved = self.astation_client.profile().and_then(|src| {
            self.astation_client.apply_bound(&astation_id, || {
                crate::records::PairingRecord::set_relay_only(
                    &src.paths.pairing,
                    &astation_id,
                    relay_only,
                )
            })
        });
        if let Err(error) = saved {
            self.status_message = Some(format!("Transport policy not saved: {error:#}"));
            return;
        }
        let ack = AstationMessage::TransportPolicyAck { relay_only };
        let local = self.astation_client.via() == Some(&LinkVia::Local);
        if relay_only && local {
            // Written before the socket closes.
            let _ = self.astation_client.send_message_flushed(ack).await;
            self.drop_astation_link(RELAY_ONLY_RECONNECT.into());
        } else {
            let _ = self.astation_client.send_message(ack).await;
        }
    }
}

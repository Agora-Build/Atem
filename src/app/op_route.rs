//! `atem runtime`'s Astation operations on the App's link (see
//! `runtime/ops.rs`): while one runs, the handshake replies it waits for go to
//! it instead of the general handler; with none running they are dropped.
//! See designs/agent-runtime.md "Astation operations through the runtime".

use super::App;
use crate::websocket_client::{AstationClient, AstationMessage};
use std::time::{Duration, Instant};
use tokio::sync::mpsc;

/// How long a verification's relay reconnect waits at most for its
/// operation to end (`App::verify_hold`): far beyond its tail on a closed
/// link (the apply, then sends that fail at once), well below the 30 s
/// retry a proof under the old key would cost.
pub const VERIFY_HOLD: Duration = Duration::from_secs(10);

/// A verification's relay reconnect waits (`App::verify_hold`).
#[derive(Debug, Clone, Copy)]
pub struct VerifyHold {
    /// When its certificate went to the operation.
    pub since: Instant,
    /// The operation ended ok: released after the broker's next pass.
    pub ended: bool,
}

/// Where the running operation's replies go.
pub struct OpRoute {
    /// The link the operation runs on; another link's messages never reach it.
    pub link_gen: u64,
    pub tx: mpsc::Sender<AstationMessage>,
    /// `encryptionMode`/`keyGrant` go to the operation (verification holds
    /// them until it pinned Astation's keys; unlock applies them itself).
    pub encryption: bool,
    /// `credentialSync` goes to the operation (the token refresh).
    pub credentials: bool,
}

/// Replies only an operation waits for: never applied by the general handler.
fn operation_only(message: &AstationMessage) -> bool {
    matches!(
        message,
        AstationMessage::VerifyKeys { .. }
            | AstationMessage::DeviceVerified { .. }
            | AstationMessage::VerifyAbort { .. }
            | AstationMessage::UnlockGrant { .. }
            | AstationMessage::UnlockDenied { .. }
            | AstationMessage::StorageKeyAck { .. }
            | AstationMessage::StorageKeyRejected { .. }
    )
}

/// The wire `type` of `message`, for the log.
fn kind(message: &AstationMessage) -> String {
    serde_json::to_value(message)
        .ok()
        .and_then(|value| value.get("type")?.as_str().map(str::to_string))
        .unwrap_or_else(|| "message".into())
}

impl App {
    /// Routes `message` to the running operation when it is one of its
    /// replies (`None` back: taken or dropped); else gives it back for the
    /// general handler.
    pub(crate) fn route_to_op(&mut self, message: AstationMessage) -> Option<AstationMessage> {
        let only = operation_only(&message);
        let encryption = matches!(
            message,
            AstationMessage::EncryptionMode { .. } | AstationMessage::KeyGrant { .. }
        );
        let credentials = matches!(message, AstationMessage::CredentialSync { .. });
        if !(only || encryption || credentials) {
            return Some(message);
        }
        let route = self
            .op_route
            .as_ref()
            .filter(|route| route.link_gen == self.astation_link_gen && !route.tx.is_closed());
        match route {
            Some(route)
                if only
                    || (encryption && route.encryption)
                    || (credentials && route.credentials) =>
            {
                let what = kind(&message);
                let certificate = matches!(message, AstationMessage::DeviceVerified { .. });
                if route.tx.try_send(message).is_err() {
                    eprintln!("atem: dropped a {what}: the Astation operation isn't reading");
                } else if certificate
                    && matches!(
                        self.astation_client.via(),
                        Some(crate::websocket_client::LinkVia::Relay { .. })
                    )
                {
                    // The operation pins the new device list next: a relay
                    // reconnect meanwhile would prove its route under the
                    // old one (`verify_hold`).
                    self.verify_hold = Some(VerifyHold {
                        since: Instant::now(),
                        ended: false,
                    });
                }
                None
            }
            _ if only => {
                eprintln!(
                    "atem: dropped a {} from Astation: no pairing or unlock is in progress",
                    kind(&message)
                );
                None
            }
            _ => Some(message),
        }
    }

    /// A handle on the authenticated link for one operation, its replies
    /// routed to it from now on; `None` while the link is down.
    pub(crate) fn open_op_route(
        &mut self,
        encryption: bool,
        credentials: bool,
    ) -> Option<AstationClient> {
        if !self.astation_connected || self.relay_only_drop_pending() {
            return None;
        }
        let (view, tx) = self.astation_client.op_view();
        self.op_route = Some(OpRoute {
            link_gen: self.astation_link_gen,
            tx,
            encryption,
            credentials,
        });
        Some(view)
    }

    /// The operation ended (or its link went away): its replies are dropped
    /// from now on.
    pub(crate) fn close_op_route(&mut self) {
        self.op_route = None;
    }

    /// The verification operation ended (`ok`: a pairing or verification
    /// that succeeded): whether the broker's next pass must read the
    /// device list (it pinned one) before the held reconnect goes on.
    pub(crate) fn verification_ended(&mut self, ok: bool) -> bool {
        match self.verify_hold.as_mut() {
            Some(hold) if ok => {
                hold.ended = true;
                true
            }
            _ => {
                self.verify_hold = None;
                false
            }
        }
    }

    /// The broker's pass ran: a hold waiting for it (its operation ended
    /// ok, and this pass read the list it pinned) ends.
    pub(crate) fn verify_hold_pass(&mut self) {
        if self.verify_hold.is_some_and(|hold| hold.ended) {
            self.verify_hold = None;
        }
    }

    /// Whether a reconnect waits for a verification (`verify_hold`); past
    /// [`VERIFY_HOLD`] the hold ends, and the reconnect goes on as before.
    pub(crate) fn reconnect_held(&mut self) -> bool {
        let Some(hold) = self.verify_hold else {
            return false;
        };
        if hold.since.elapsed() < VERIFY_HOLD {
            return true;
        }
        self.verify_hold = None;
        if !hold.ended {
            eprintln!(
                "atem runtime: the device verification didn't end within {} s; reconnecting anyway",
                VERIFY_HOLD.as_secs()
            );
        }
        false
    }

    /// The link the running operation uses, if its route is still open.
    pub(crate) fn op_route_gen(&self) -> Option<u64> {
        self.op_route.as_ref().map(|route| route.link_gen)
    }

    /// `atem pair verify`: the link's pairing moves to a new binding in the
    /// next trust generation (`pairing::rebind_for_verification`), and the
    /// link adopts it, so it stays current. Returns (before, after) for the
    /// operation's own handle.
    pub(crate) fn rebind_for_verification(
        &mut self,
        astation_id: &str,
    ) -> anyhow::Result<(crate::pairing::TrustState, crate::pairing::TrustState)> {
        let capture = self
            .astation_client
            .capture()
            .cloned()
            .ok_or_else(|| anyhow::anyhow!(crate::pairing::NO_BINDING))?;
        let before = capture.state.clone();
        let after =
            crate::pairing::rebind_for_verification(capture.sources(), &before, astation_id)?;
        self.astation_client.adopt_binding(&before, &after)?;
        Ok((before, after))
    }

    /// A first pairing made `client` (authenticated, bound to the new
    /// pairing): it replaces the link, as a reconnect would.
    pub(crate) fn install_astation_link(&mut self, client: AstationClient) {
        self.astation_connect_rx = None;
        self.astation_reconnect_at = None;
        self.astation_reauth = None;
        self.connected_astation_id = client.connected_astation_id().map(str::to_string);
        self.astation_client = client;
        self.astation_connected = true;
        self.astation_connected_at = Some(std::time::Instant::now());
        self.astation_routed = false;
        self.astation_link_gen += 1;
        self.pairing_code = None;
        self.last_session_refresh = Some(Instant::now());
        self.rebuild_menu();
        self.status_message = Some("Connected to Astation".to_string());
    }
}

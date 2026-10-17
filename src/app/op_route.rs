//! `atem runtime`'s Astation operations on the App's link (see
//! `runtime/ops.rs`): while one runs, the handshake replies it waits for go to
//! it instead of the general handler; with none running they are dropped.
//! See designs/agent-runtime.md "Astation operations through the runtime".

use super::App;
use crate::websocket_client::{AstationClient, AstationMessage};
use std::time::Instant;
use tokio::sync::mpsc;

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
                if route.tx.try_send(message).is_err() {
                    eprintln!("atem: dropped a {what}: the Astation operation isn't reading");
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
        if !self.astation_connected {
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

    /// The link the running operation uses, if its route is still open.
    pub(crate) fn op_route_gen(&self) -> Option<u64> {
        self.op_route.as_ref().map(|route| route.link_gen)
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
        self.astation_link_gen += 1;
        self.pairing_code = None;
        self.last_session_refresh = Some(Instant::now());
        self.rebuild_menu();
        self.status_message = Some("Connected to Astation".to_string());
    }
}

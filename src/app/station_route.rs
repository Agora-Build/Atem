//! Select a transport without touching the broker, workers or receipts.
use std::time::{Duration, Instant};

use super::App;
use atem_client::station_route::{Accepted, Message, Request};

const REFRESH: Duration = Duration::from_secs(30);

#[derive(Default)]
pub(super) struct Routing {
    link_gen: u64,
    pending: Option<(Request, Instant)>,
    next: Option<Instant>,
    sent: Option<Instant>,
    switch: Option<Switch>,
    switch_receipt: Option<crate::websocket_client::DeliveryReceipt>,
    switch_due: Option<Instant>,
}

enum Switch {
    Station { generation: u64, block_direct: bool },
    Direct { generation: u64 },
}

impl Switch {
    fn generation(&self) -> u64 {
        match self {
            Self::Station { generation, .. } | Self::Direct { generation } => *generation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::websocket_client::{AstationClient, LinkVia};
    use atem_client::station_route::Offer;

    async fn connected() -> (App, tempfile::TempDir, crate::test_profile::Scope) {
        let (dir, scope) = crate::test_profile::temp();
        crate::pairing::tests::write_bound(
            dir.path(),
            "native-test",
            2,
            "binding-test",
            ("session-test", "test-token"),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
            use futures_util::StreamExt;
            while ws.next().await.is_some() {}
        });
        let mut app = App::new();
        app.astation_client = AstationClient::new_with_test_state("atem-test", dir.path());
        app.astation_client
            .connect_raw(&format!("ws://{address}"))
            .await
            .unwrap();
        app.astation_client.pin_astation_for_test("native-test");
        app.astation_client.set_via_for_test(LinkVia::Local);
        app.astation_connected = true;
        app.astation_link_gen = 1;
        app.poll_station_route();
        (app, dir, scope)
    }

    fn offer(app: &App) -> String {
        let request = app.station_routing.pending.as_ref().unwrap().0.clone();
        Message::Offer {
            v: 1,
            offer: Offer::sign(
                request,
                "https://station-dev.agora.build",
                true,
                b"test-token",
            )
            .unwrap(),
        }
        .to_json()
    }

    #[tokio::test]
    async fn station_route_nonce_is_single_use_expiring_and_bound_to_its_link() {
        let (mut app, dir, _scope) = connected().await;
        let text = offer(&app);
        let pending = app.station_routing.pending.clone();
        app.station_routing.pending.as_mut().unwrap().1 = Instant::now() - Duration::from_secs(1);
        app.receive_station_route(&text);
        assert!(!dir.path().join("pairing/station_route.json").exists());
        app.station_routing.pending = pending;
        app.astation_link_gen += 1;
        app.receive_station_route(&text);
        assert!(!dir.path().join("pairing/station_route.json").exists());
        app.astation_link_gen -= 1;
        app.receive_station_route(&text);
        assert!(dir.path().join("pairing/station_route.json").exists());
        assert!(app.station_direct_blocked());
        let saved = std::fs::read(dir.path().join("pairing/station_route.json")).unwrap();
        app.receive_station_route(&text);
        assert_eq!(
            std::fs::read(dir.path().join("pairing/station_route.json")).unwrap(),
            saved
        );
        let deadline = Instant::now() + Duration::from_secs(1);
        while app.astation_connected && Instant::now() < deadline {
            tokio::time::sleep(Duration::from_millis(5)).await;
            app.check_station_switch();
        }
        assert!(!app.astation_connected);
        assert!(app.astation_reconnect_at.is_some());
    }

    #[tokio::test]
    async fn station_route_replaced_pairing_or_session_cannot_apply_old_offer() {
        let (mut app, dir, _scope) = connected().await;
        let text = offer(&app);
        crate::pairing::tests::write_bound(
            dir.path(),
            "native-test",
            3,
            "new-binding",
            ("new-session", "new-token"),
        );
        app.receive_station_route(&text);
        assert!(!dir.path().join("pairing/station_route.json").exists());
        assert!(app.astation_connected);
    }

    #[tokio::test]
    async fn station_route_migration_survives_reauthentication_and_waits_for_an_operation() {
        let (mut app, _dir, _scope) = connected().await;
        let operation = app.open_op_route(false, false).unwrap();
        app.receive_station_route(&offer(&app));
        app.check_station_switch();
        assert!(
            app.astation_connected,
            "the running operation keeps its socket"
        );
        app.astation_link_gen += 1;
        app.poll_station_route();
        assert!(
            app.station_direct_blocked(),
            "the durable selection survives the old nonce/generation"
        );
        drop(operation);
        app.close_op_route();
        app.check_station_switch();
        assert!(!app.astation_connected);
    }

    #[test]
    fn short_lived_connections_use_a_bounded_retry_delay() {
        let (_dir, _scope) = crate::test_profile::temp();
        let mut app = App::new();
        app.astation_connected_at = Some(Instant::now());
        assert!(app.connected_retry_at().duration_since(Instant::now()) > Duration::from_secs(29));
        app.astation_connected_at = Some(Instant::now() - Duration::from_secs(11));
        assert!(app.connected_retry_at() <= Instant::now());
    }

    #[tokio::test]
    async fn allow_direct_before_a_station_handoff_keeps_the_relay() {
        let (mut app, _dir, _scope) = connected().await;
        app.astation_client.set_via_for_test(LinkVia::Relay {
            label: "test relay".into(),
        });
        app.host_policy_changed(false);
        assert!(app.station_routing.switch.is_none());
        assert!(app.astation_connected);
    }

    #[tokio::test]
    async fn an_unsupported_station_protocol_requires_upgrade_and_backs_off() {
        for version in [None, Some(0), Some(2)] {
            let (mut app, dir, _scope) = connected().await;
            let mut message: serde_json::Value = serde_json::from_str(&offer(&app)).unwrap();
            match version {
                Some(version) => message["data"]["v"] = version.into(),
                None => {
                    message["data"].as_object_mut().unwrap().remove("v");
                }
            }
            app.receive_station_route(&message.to_string());
            assert!(!app.astation_connected);
            assert!(
                app.status_message
                    .as_deref()
                    .unwrap()
                    .contains("upgrade Atem and Astation")
            );
            assert!(
                app.astation_reconnect_at
                    .unwrap()
                    .duration_since(Instant::now())
                    > Duration::from_secs(29)
            );
            assert!(!dir.path().join("pairing/station_route.json").exists());
        }
    }
}

impl App {
    pub(super) fn poll_station_route(&mut self) {
        if !self.astation_connected || self.astation_reauth.is_some() {
            self.station_routing = Routing::default();
            return;
        }
        if self.station_routing.link_gen != self.astation_link_gen {
            self.station_routing = Routing {
                link_gen: self.astation_link_gen,
                ..Routing::default()
            };
        }
        let now = Instant::now();
        if self.station_routing.next.is_some_and(|next| now < next) {
            return;
        }
        self.station_routing.next = Some(now + REFRESH);
        self.station_routing.pending = None;
        let request = self
            .astation_client
            .with_station_route(|src, context, token| {
                let previous = crate::station_route::load(src, context, token)?;
                let request = Request {
                    id: uuid::Uuid::new_v4().to_string(),
                    context: context.clone(),
                    route_revision: previous
                        .as_ref()
                        .map_or(0, crate::station_route::Selection::revision),
                    policy_revision: crate::station_route::policy_revision(&src.paths.pairing)?,
                };
                Ok((request, previous))
            });
        if let Ok((request, previous)) = request {
            if let Some(selection) = previous {
                self.plan_station_switch(&selection.offer.relay_url, selection.direct_blocked);
            }
            let message = Message::Request {
                v: 1,
                request: request.clone(),
            };
            if self
                .astation_client
                .try_send_wire(message.to_json(), false)
                .is_ok()
            {
                self.station_routing.pending = Some((request, now + REFRESH));
                self.station_routing.sent = Some(now);
            }
        }
    }

    pub(super) fn receive_station_route(&mut self, text: &str) {
        if !self.astation_connected || self.station_routing.link_gen != self.astation_link_gen {
            return;
        }
        let message = match Message::parse(text.as_bytes()) {
            Ok(message) => message,
            Err(atem_client::station_route::UNSUPPORTED_VERSION) => {
                let reason = atem_client::station_route::UNSUPPORTED_VERSION;
                eprintln!("atem runtime: {reason}");
                self.drop_astation_link(reason.into());
                self.astation_reconnect_at = Some(Instant::now() + REFRESH);
                return;
            }
            Err(_) => return,
        };
        if matches!(message, Message::Changed { .. }) {
            let due = self
                .station_routing
                .sent
                .map_or_else(Instant::now, |sent| sent + Duration::from_secs(2));
            self.station_routing.next =
                Some(self.station_routing.next.map_or(due, |next| next.min(due)));
            return;
        }
        let Message::Offer { offer, .. } = message else {
            return;
        };
        let Some((request, deadline)) = &self.station_routing.pending else {
            return;
        };
        if Instant::now() >= *deadline || offer.request != *request {
            return;
        }
        let result = self
            .astation_client
            .with_station_route(|src, context, token| {
                crate::station_route::apply(src, context, token, request, &offer)?;
                let blocked = crate::station_route::load(src, context, token)?
                    .is_some_and(|s| s.direct_blocked);
                let accepted = Accepted::sign(offer.clone(), blocked, token.as_bytes())
                    .map_err(|e| anyhow::anyhow!(e))?;
                Ok((blocked, Message::Accepted { v: 1, accepted }.to_json()))
            });
        if let Ok((block_direct, acceptance)) = result {
            // Spend a valid challenge even for an unchanged selection.
            self.station_routing.pending = None;
            self.station_routing.next = Some(Instant::now() + REFRESH);
            self.plan_station_switch(&offer.relay_url, block_direct);
            if let Ok(receipt) = self.astation_client.try_send_wire_receipt(acceptance)
                && self.station_routing.switch.is_some()
            {
                self.station_routing.switch_receipt = Some(receipt);
                self.station_routing.switch_due = None;
            }
        }
    }

    fn plan_station_switch(&mut self, relay: &str, block_direct: bool) {
        let is_local = self.astation_client.via() == Some(&crate::websocket_client::LinkVia::Local);
        let same_relay = self.astation_client.relay_origin() == Some(relay);
        if !same_relay && (!is_local || block_direct || !super::relay_only::local_allowed()) {
            self.station_routing.switch = Some(Switch::Station {
                generation: self.astation_link_gen,
                block_direct,
            });
        } else if block_direct
            || !matches!(self.station_routing.switch, Some(Switch::Direct { .. }))
        {
            self.station_routing.switch = None;
        }
    }

    pub(super) fn check_station_switch(&mut self) {
        let Some(switch) = &self.station_routing.switch else {
            return;
        };
        let generation = switch.generation();
        if generation != self.astation_link_gen || !self.astation_connected {
            self.station_routing.switch = None;
            return;
        }
        // Existing pairing/unlock work owns its socket until it finishes.
        if self
            .op_route
            .as_ref()
            .is_some_and(|r| r.link_gen == generation && !r.tx.is_closed())
            || self.relay_only_drop.is_some()
        {
            return;
        }
        if matches!(switch, Switch::Direct { .. }) || self.station_routing.switch_receipt.is_some()
        {
            let deadline = *self
                .station_routing
                .switch_due
                .get_or_insert_with(|| Instant::now() + Duration::from_secs(5));
            let delivered = self
                .station_routing
                .switch_receipt
                .as_mut()
                .is_some_and(|receipt| {
                    !matches!(
                        receipt.try_recv(),
                        Err(tokio::sync::oneshot::error::TryRecvError::Empty)
                    )
                });
            if !delivered && Instant::now() < deadline {
                return;
            }
        }
        let reason = match self.station_routing.switch.take().unwrap() {
            Switch::Station { .. } => "Astation selected another Station; reconnecting",
            Switch::Direct { .. } => "Astation allowed direct routing; reconnecting",
        };
        self.drop_astation_link(reason.into());
    }

    pub(crate) fn station_direct_blocked(&self) -> bool {
        self.station_routing.switch.as_ref().is_some_and(|switch|
            matches!(switch, Switch::Station { generation, block_direct: true } if *generation == self.astation_link_gen)
            && self.astation_client.via() == Some(&crate::websocket_client::LinkVia::Local))
    }

    fn cancel_station_direct_switch(&mut self) {
        if self.station_direct_blocked() {
            self.station_routing.switch = None;
        }
        self.station_routing.pending = None;
    }

    pub(super) fn station_policy_changed(&mut self, relay_only: bool) {
        self.cancel_station_direct_switch();
        if relay_only {
            if matches!(self.station_routing.switch, Some(Switch::Direct { .. })) {
                self.station_routing.switch = None;
            }
        } else if self.astation_connected
            && matches!(
                self.astation_client.via(),
                Some(crate::websocket_client::LinkVia::Relay { .. })
            )
            && super::relay_only::local_allowed()
            && self
                .astation_client
                .with_station_route(|src, context, token| {
                    // Existing relay clients keep their socket unless a
                    // selected-Station handoff needs to return to direct.
                    Ok(crate::station_route::load(src, context, token)?
                        .is_some_and(|selection| !selection.direct_blocked))
                })
                .unwrap_or(false)
        {
            self.station_routing.switch = Some(Switch::Direct {
                generation: self.astation_link_gen,
            });
            self.station_routing.switch_receipt = None;
            self.station_routing.switch_due = None;
        }
    }

    pub(super) fn station_policy_receipt(
        &mut self,
        receipt: crate::websocket_client::DeliveryReceipt,
    ) {
        if matches!(self.station_routing.switch, Some(Switch::Direct { .. })) {
            self.station_routing.switch_receipt = Some(receipt);
        }
    }
}

//! Re-authentication over an already-open Astation socket.
//!
//! When Astation alone reconnects to the relay, the relay keeps this socket
//! open and Astation challenges it again with `auth_required`. Until the proof
//! is accepted the socket is alive but not authenticated: Atem shows
//! `Astation ✗`, revokes remote terminals and ignores Astation's requests.
use super::App;
use crate::websocket_client::{AstationClient, AstationMessage, AuthResponse, is_auth_required};
use std::time::{Duration, Instant};

/// How long Astation has to accept the proof before the socket is dropped.
pub(super) const REAUTH_TIMEOUT: Duration = Duration::from_secs(15);

impl App {
    /// Handles `auth_required` and, while re-authentication is pending, every
    /// other message. Returns true when the message was consumed.
    pub(super) async fn intercept_astation_reauth(&mut self, message: &AstationMessage) -> bool {
        if is_auth_required(message) {
            // Only a connection that authenticated before is challenged again;
            // anything else here is a socket the TUI already gave up on.
            if self.astation_connected || self.astation_reauth.is_some() {
                self.answer_astation_challenge(message).await;
            }
            return true;
        }
        if self.astation_reauth.is_none() {
            return false;
        }
        let astation_id = self
            .astation_client
            .connected_astation_id()
            .unwrap_or_default()
            .to_string();
        match self
            .astation_client
            .auth_response(message, &astation_id, false)
        {
            // Not an auth response: nothing else is acted on until Astation
            // accepts the proof (no input, terminal, voice, task or launch).
            Ok(None) => {}
            Ok(Some(AuthResponse::Authenticated)) => self.finish_astation_reauth().await,
            Ok(Some(AuthResponse::Denied(reason))) => self.fail_astation_reauth(format!(
                "Astation refused to re-authenticate this device ({reason}). {}",
                reauth_advice(self.astation_client.profile_paired())
            )),
            Ok(Some(AuthResponse::SessionExpired)) => self.fail_astation_reauth(format!(
                "Astation session expired. {}",
                reauth_advice(self.astation_client.profile_paired())
            )),
            Err(error) => {
                self.fail_astation_reauth(format!("Astation re-authentication failed: {error}"))
            }
        }
        true
    }

    /// Fails a re-authentication Astation did not answer in time, or whose
    /// socket closed (the ordinary disconnect check only covers online links).
    pub(super) fn check_astation_reauth_deadline(&mut self) {
        let Some(deadline) = self.astation_reauth else {
            return;
        };
        if self.astation_client.is_ws_closed() {
            self.fail_astation_reauth(
                "Astation closed the connection during re-authentication; reconnecting".to_string(),
            );
        } else if Instant::now() >= deadline {
            self.fail_astation_reauth(format!(
                "Astation did not answer re-authentication within {}s; reconnecting",
                REAUTH_TIMEOUT.as_secs()
            ));
        }
    }

    async fn answer_astation_challenge(&mut self, message: &AstationMessage) {
        // A repeat of the challenge already answered on this socket (at
        // connect or re-auth) by the same Astation is spent; another
        // astation_id goes on to the pin check and fails closed.
        if self.astation_client.is_answered_challenge(message) {
            return;
        }
        if self.astation_reauth.is_none() {
            self.suspend_astation();
        }
        match self.astation_client.answer_auth_required(message).await {
            Ok(()) => {
                self.astation_reauth = Some(Instant::now() + REAUTH_TIMEOUT);
                self.status_message = Some("Astation re-authenticating…".to_string());
            }
            Err(error) => {
                self.fail_astation_reauth(format!("Astation re-authentication failed: {error}"))
            }
        }
    }

    /// The socket is open but no longer authenticated: offline, remote
    /// terminals revoked, chat conversations closed, Astation-routed work
    /// dropped. The local agent PTY and anything typed into it are left alone.
    pub(super) fn suspend_astation(&mut self) {
        self.astation_connected = false;
        self.disconnect_terminals();
        self.close_chat_conversations();
        self.pending_astation_command = None;
        self.pending_voice_request = None;
        self.rebuild_menu();
    }

    /// Stay offline, say why, and close this socket so the normal reconnect
    /// schedule (saved session only, never pairing) takes over.
    fn fail_astation_reauth(&mut self, reason: String) {
        self.astation_reauth = None;
        self.suspend_astation();
        self.terminal_ui.record(reason.clone());
        self.status_message = Some(reason);
        self.on_astation_disconnect();
        // Dropping the client aborts its transport, closing the socket.
        self.astation_client = AstationClient::new();
        self.astation_reconnect_at = Some(Instant::now());
    }

    /// Back online; report state as a fresh connect does. Remote viewers
    /// subscribe again (view-only); no lease or input is resumed.
    async fn finish_astation_reauth(&mut self) {
        self.astation_reauth = None;
        self.astation_connected = true;
        self.astation_client.reauthenticated();
        self.rebuild_menu();
        self.status_message = Some("Astation reconnected".to_string());
        let agents = self.agent_registry.all();
        let _ = self.astation_client.send_agent_list(agents).await;
    }
}

/// What to do after Astation refused or expired the session: `atem unpair`
/// first on a `paired` profile (`atem pair` alone only shows the status).
fn reauth_advice(paired: bool) -> String {
    crate::status::pairing_advice(paired, "Run `atem pair`.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::AppMode;
    use crate::terminal_share::{Message, SharedTerminal};
    use crate::websocket_client::device_auth_proof;
    use futures_util::{SinkExt, StreamExt};
    use std::collections::HashMap;
    use tokio::sync::mpsc;
    use tokio_tungstenite::tungstenite::Message as WsMessage;

    const ASTATION: &str = "astation-pinned";
    const ATEM_ID: &str = "atem-test-reauth";
    const SESSION_ID: &str = "session-reauth";
    const TOKEN: &str = "token-reauth";

    /// The Astation end of the socket: what it sends, and what Atem sent it
    /// (`None` once Atem closed the socket).
    struct Peer {
        send: mpsc::UnboundedSender<AstationMessage>,
        recv: mpsc::UnboundedReceiver<Option<AstationMessage>>,
        _state: tempfile::TempDir,
    }

    fn status(status: &str, data: &[(&str, &str)]) -> AstationMessage {
        AstationMessage::StatusUpdate {
            status: status.into(),
            data: data
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        }
    }

    fn auth_required(astation_id: &str, challenge: &str) -> AstationMessage {
        status(
            "auth_required",
            &[
                ("astation_id", astation_id),
                ("challenge", challenge),
                ("transport", "relay"),
                ("protocol", "2"),
            ],
        )
    }

    /// An App whose socket authenticated with `ASTATION` (a saved session in a
    /// temp dir; never the user's config) and a scripted Astation peer.
    async fn connected_app() -> (App, Peer) {
        let state = tempfile::tempdir().unwrap();
        let session_path = state.path().join("sessions.json");
        let mut sessions = crate::auth::SessionManager::default();
        sessions.insert_session(crate::auth::AuthSession::new(
            SESSION_ID.into(),
            TOKEN.into(),
            ASTATION.into(),
            "test-machine".into(),
        ));
        sessions.save_to(&session_path).unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (send, mut outgoing) = mpsc::unbounded_channel::<AstationMessage>();
        let (incoming, recv) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            loop {
                tokio::select! {
                    message = outgoing.recv() => {
                        let Some(message) = message else { break };
                        let json = serde_json::to_string(&message).unwrap();
                        if socket.send(WsMessage::Text(json)).await.is_err() {
                            let _ = incoming.send(None);
                            break;
                        }
                    }
                    frame = socket.next() => match frame {
                        Some(Ok(WsMessage::Text(text))) => {
                            let _ = incoming.send(Some(serde_json::from_str(&text).unwrap()));
                        }
                        Some(Ok(WsMessage::Close(_))) | Some(Err(_)) | None => {
                            let _ = incoming.send(None);
                            break;
                        }
                        Some(Ok(_)) => {}
                    }
                }
            }
        });

        let mut app = App::new();
        // Keep process_astation_messages away from the user's sessions.json.
        app.last_session_refresh = Some(Instant::now());
        app.astation_client = AstationClient::new_with_test_state(ATEM_ID, session_path);
        app.astation_client
            .connect_raw(&format!("ws://{address}"))
            .await
            .unwrap();
        // The connect-time authentication is covered by websocket_client tests.
        app.astation_client.pin_astation_for_test(ASTATION);
        app.astation_connected = true;
        (
            app,
            Peer {
                send,
                recv,
                _state: state,
            },
        )
    }

    /// Adds a live `cat` PTY as Codex with a remote viewer that holds control.
    fn share_codex_with_remote_controller(app: &mut App) {
        let session = crate::pty_session::spawn("cat", &[]).unwrap();
        app.codex_sender = Some(session.sender);
        app.codex_receiver = Some(session.receiver);
        app.codex_resize_handle = Some(session.resize_handle);
        app.codex_share = Some(SharedTerminal::new("codex"));
        app.mode = AppMode::MainMenu;
        let generation = app.codex_share.as_ref().unwrap().generation.clone();
        app.handle_terminal_message(
            Message::Subscribe {
                terminal_id: "codex".into(),
                generation: generation.clone(),
            }
            .into(),
        );
        let stream_id = app
            .terminal_outbox
            .iter()
            .find_map(|message| match message {
                Message::Attached { stream_id, .. } => Some(stream_id.clone()),
                _ => None,
            })
            .expect("viewer attached");
        app.handle_terminal_message(
            Message::Control {
                terminal_id: "codex".into(),
                generation,
                stream_id,
                take: true,
            }
            .into(),
        );
        assert!(app.codex_share.as_ref().unwrap().has_viewer());
        assert!(app.codex_sender.as_ref().unwrap().remote_controlled());
    }

    /// Runs the TUI's Astation step until the peer receives an `auth` message
    /// (skipping anything else Atem sends). Panics if the socket closes.
    async fn next_auth(app: &mut App, peer: &mut Peer) -> HashMap<String, String> {
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                app.process_astation_messages().await;
                while let Ok(frame) = peer.recv.try_recv() {
                    match frame {
                        Some(AstationMessage::StatusUpdate { status, data })
                            if status == "auth" =>
                        {
                            return data;
                        }
                        Some(_) => {}
                        None => panic!("Atem closed the socket instead of answering"),
                    }
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("no auth message reached Astation")
    }

    /// Runs the TUI's Astation step for a while; returns what Atem sent.
    async fn pump(app: &mut App, peer: &mut Peer) -> Vec<Option<AstationMessage>> {
        let mut frames = Vec::new();
        for _ in 0..30 {
            app.process_astation_messages().await;
            tokio::time::sleep(Duration::from_millis(5)).await;
            while let Ok(frame) = peer.recv.try_recv() {
                frames.push(frame);
            }
        }
        frames
    }

    /// Runs the TUI's Astation step until Atem closed the socket; returns what
    /// it sent before.
    async fn until_closed(app: &mut App, peer: &mut Peer) -> Vec<AstationMessage> {
        tokio::time::timeout(Duration::from_secs(3), async {
            let mut frames = Vec::new();
            loop {
                app.process_astation_messages().await;
                while let Ok(frame) = peer.recv.try_recv() {
                    match frame {
                        Some(message) => frames.push(message),
                        None => return frames,
                    }
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("Atem kept the unauthenticated socket open")
    }

    fn is_auth(message: &AstationMessage) -> bool {
        matches!(message, AstationMessage::StatusUpdate { status, .. } if status == "auth")
    }

    fn expected_session_proof(challenge: &str) -> String {
        device_auth_proof(TOKEN, challenge, ASTATION, ATEM_ID, SESSION_ID).unwrap()
    }

    #[tokio::test]
    async fn auth_required_goes_offline_revokes_terminals_and_answers_with_the_session_proof() {
        let (mut app, mut peer) = connected_app().await;
        share_codex_with_remote_controller(&mut app);
        let challenge = "b".repeat(64);
        peer.send.send(auth_required(ASTATION, &challenge)).unwrap();

        let proof = next_auth(&mut app, &mut peer).await;
        assert!(!app.astation_connected, "status bar must show Astation ✗");
        assert!(!app.codex_share.as_ref().unwrap().has_viewer());
        assert!(!app.codex_sender.as_ref().unwrap().remote_controlled());
        assert!(app.terminal_outbox.is_empty());
        assert_eq!(proof["session_id"], SESSION_ID);
        assert_eq!(proof["atem_id"], ATEM_ID);
        assert_eq!(proof["proof"], expected_session_proof(&challenge));
        assert!(!proof.contains_key("pairing_code"));

        // Still unauthenticated while Astation hasn't answered; socket open.
        let frames = pump(&mut app, &mut peer).await;
        assert!(frames.iter().all(Option::is_some));
        assert!(!app.astation_connected);
        assert!(app.astation_reconnect_at.is_none());
    }

    #[tokio::test]
    async fn authenticated_reply_restores_online_and_resends_the_agent_list_view_only() {
        let (mut app, mut peer) = connected_app().await;
        share_codex_with_remote_controller(&mut app);
        let generation = app.codex_share.as_ref().unwrap().generation.clone();
        peer.send
            .send(auth_required(ASTATION, &"b".repeat(64)))
            .unwrap();
        next_auth(&mut app, &mut peer).await;

        peer.send
            .send(status("authenticated", &[("method", "session_proof")]))
            .unwrap();
        let frames = pump(&mut app, &mut peer).await;
        assert!(app.astation_connected);
        assert!(app.astation_reauth.is_none());
        assert_eq!(app.status_message.as_deref(), Some("Astation reconnected"));
        assert!(
            frames
                .iter()
                .any(|frame| matches!(frame, Some(AstationMessage::AgentListResponse { .. }))),
            "agent list not re-sent: {frames:?}"
        );
        // Remote viewers start again from a fresh subscribe; nothing resumes.
        assert!(!app.codex_share.as_ref().unwrap().has_viewer());
        assert!(!app.codex_sender.as_ref().unwrap().remote_controlled());

        // The local PTY is the same process, still running.
        assert_eq!(app.codex_share.as_ref().unwrap().generation, generation);
        app.send_codex_data("still alive\n");
        tokio::time::timeout(Duration::from_secs(3), async {
            while !app
                .codex_terminal
                .screen()
                .contents()
                .contains("still alive")
            {
                app.process_codex_output();
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("local PTY stopped answering");
    }

    async fn assert_fails_closed(app: &mut App, peer: &mut Peer, notice: &str) {
        until_closed(app, peer).await;
        assert!(!app.astation_connected);
        assert!(app.astation_reauth.is_none());
        assert!(
            app.astation_reconnect_at.is_some(),
            "normal reconnect not scheduled"
        );
        assert!(
            app.terminal_ui.messages.iter().any(|m| m.contains(notice)),
            "no notice containing {notice:?}: {:?}",
            app.terminal_ui.messages
        );
        // Nothing afterwards marks it online.
        app.process_astation_messages().await;
        assert!(!app.astation_connected);
    }

    #[tokio::test]
    async fn denied_reply_stays_offline_and_closes_for_reconnect() {
        let (mut app, mut peer) = connected_app().await;
        peer.send
            .send(auth_required(ASTATION, &"b".repeat(64)))
            .unwrap();
        next_auth(&mut app, &mut peer).await;
        peer.send
            .send(status(
                "auth",
                &[("status", "denied"), ("message", "revoked")],
            ))
            .unwrap();
        assert_fails_closed(&mut app, &mut peer, "atem pair").await;
    }

    #[tokio::test]
    async fn expired_session_stays_offline_and_closes_for_reconnect() {
        let (mut app, mut peer) = connected_app().await;
        peer.send
            .send(auth_required(ASTATION, &"b".repeat(64)))
            .unwrap();
        next_auth(&mut app, &mut peer).await;
        peer.send
            .send(status("error", &[("message", "Session expired")]))
            .unwrap();
        assert_fails_closed(&mut app, &mut peer, "atem pair").await;
    }

    #[tokio::test]
    async fn a_paired_profile_is_told_to_unpair_then_pair() {
        // The client's profile (a temp dir) holds a saved session: paired.
        let (mut app, mut peer) = connected_app().await;
        peer.send
            .send(auth_required(ASTATION, &"b".repeat(64)))
            .unwrap();
        next_auth(&mut app, &mut peer).await;
        peer.send
            .send(status(
                "auth",
                &[("status", "denied"), ("message", "revoked")],
            ))
            .unwrap();
        assert_fails_closed(&mut app, &mut peer, crate::status::SESSION_GONE).await;
        assert_eq!(reauth_advice(false), "Run `atem pair`.");
    }

    #[tokio::test]
    async fn unanswered_proof_times_out_and_closes_for_reconnect() {
        let (mut app, mut peer) = connected_app().await;
        peer.send
            .send(auth_required(ASTATION, &"b".repeat(64)))
            .unwrap();
        next_auth(&mut app, &mut peer).await;
        let deadline = app.astation_reauth.as_mut().expect("re-auth pending");
        assert!(*deadline > Instant::now() + REAUTH_TIMEOUT - Duration::from_secs(2));
        *deadline = Instant::now();
        assert_fails_closed(&mut app, &mut peer, "did not answer").await;
    }

    #[tokio::test]
    async fn socket_closing_during_reauthentication_reconnects_at_once() {
        let (mut app, mut peer) = connected_app().await;
        peer.send
            .send(auth_required(ASTATION, &"b".repeat(64)))
            .unwrap();
        next_auth(&mut app, &mut peer).await;
        let (closed, _) = mpsc::unbounded_channel();
        drop(std::mem::replace(&mut peer.send, closed)); // the peer hangs up
        tokio::time::timeout(Duration::from_secs(3), async {
            while app.astation_reauth.is_some() {
                app.process_astation_messages().await;
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("waited for the deadline after the socket closed");
        assert!(!app.astation_connected);
        assert!(app.astation_reconnect_at.is_some());
    }

    #[tokio::test]
    async fn a_repeat_of_the_connect_time_challenge_is_ignored() {
        let (mut app, mut peer) = connected_app().await;
        // Authenticate this socket the way connect does, with challenge "a…".
        app.astation_connected = false;
        let connect_challenge = "a".repeat(64);
        peer.send
            .send(auth_required(ASTATION, &connect_challenge))
            .unwrap();
        peer.send
            .send(status("authenticated", &[("method", "session_proof")]))
            .unwrap();
        app.astation_client.authenticate_for_test().await.unwrap();
        app.astation_connected = true;
        let connect_proof = next_auth(&mut app, &mut peer).await;
        assert_eq!(
            connect_proof["proof"],
            expected_session_proof(&connect_challenge)
        );

        // Astation re-sends that pending challenge (a hello raced it).
        peer.send
            .send(auth_required(ASTATION, &connect_challenge))
            .unwrap();
        let frames = pump(&mut app, &mut peer).await;
        assert!(
            !frames.iter().flatten().any(is_auth),
            "answered a spent challenge"
        );
        assert!(app.astation_connected, "went offline for a spent challenge");
        assert!(app.astation_reauth.is_none());
    }

    #[tokio::test]
    async fn the_pending_challenge_from_another_astation_fails_closed() {
        let (mut app, mut peer) = connected_app().await;
        let challenge = "b".repeat(64);
        peer.send.send(auth_required(ASTATION, &challenge)).unwrap();
        next_auth(&mut app, &mut peer).await;

        peer.send
            .send(auth_required("astation-impostor", &challenge))
            .unwrap();
        let frames = until_closed(&mut app, &mut peer).await;
        assert!(!frames.iter().any(is_auth), "answered a foreign Astation");
        assert!(!app.astation_connected);
        assert!(app.astation_reauth.is_none());
        assert!(app.astation_reconnect_at.is_some());
    }

    #[tokio::test]
    async fn a_grant_during_reauthentication_never_replaces_the_saved_session() {
        let (mut app, mut peer) = connected_app().await;
        peer.send
            .send(auth_required(ASTATION, &"b".repeat(64)))
            .unwrap();
        next_auth(&mut app, &mut peer).await;
        peer.send
            .send(status(
                "auth",
                &[
                    ("status", "granted"),
                    ("session_id", "session-other"),
                    ("token", "token-other"),
                ],
            ))
            .unwrap();
        pump(&mut app, &mut peer).await;
        assert!(app.astation_connected);
        let sessions =
            crate::auth::SessionManager::load_from(&peer._state.path().join("sessions.json"))
                .unwrap();
        let session = sessions.get(ASTATION).expect("saved session kept");
        assert_eq!(session.session_id, SESSION_ID);
        assert_eq!(session.token, TOKEN);
    }

    #[tokio::test]
    async fn auth_required_from_another_astation_is_not_answered() {
        let (mut app, mut peer) = connected_app().await;
        peer.send
            .send(auth_required("astation-impostor", &"b".repeat(64)))
            .unwrap();
        let frames = until_closed(&mut app, &mut peer).await;
        assert!(!frames.iter().any(is_auth), "answered a foreign Astation");
        assert!(!app.astation_connected);
        assert!(app.astation_reconnect_at.is_some());
        assert!(
            app.terminal_ui
                .messages
                .iter()
                .any(|m| m.contains("astation-impostor"))
        );
    }

    #[tokio::test]
    async fn duplicate_challenge_is_answered_once_and_a_new_one_resets_the_deadline() {
        let (mut app, mut peer) = connected_app().await;
        let first = "b".repeat(64);
        peer.send.send(auth_required(ASTATION, &first)).unwrap();
        next_auth(&mut app, &mut peer).await;
        let first_deadline = app.astation_reauth.unwrap();

        peer.send.send(auth_required(ASTATION, &first)).unwrap();
        let frames = pump(&mut app, &mut peer).await;
        assert!(
            !frames.iter().flatten().any(is_auth),
            "answered a duplicate challenge"
        );
        assert_eq!(app.astation_reauth.unwrap(), first_deadline);

        let second = "c".repeat(64);
        peer.send.send(auth_required(ASTATION, &second)).unwrap();
        let proof = next_auth(&mut app, &mut peer).await;
        assert_eq!(proof["proof"], expected_session_proof(&second));
        assert!(app.astation_reauth.unwrap() > first_deadline);
        assert!(!app.astation_connected);
    }

    #[tokio::test]
    async fn requests_are_ignored_while_reauthentication_is_pending() {
        let (mut app, mut peer) = connected_app().await;
        let (input, mut written) = crate::pty_session::PtyInput::test_channel();
        app.claude_sender = Some(input);
        peer.send
            .send(auth_required(ASTATION, &"b".repeat(64)))
            .unwrap();
        next_auth(&mut app, &mut peer).await;

        peer.send
            .send(AstationMessage::AgentInput {
                agent_id: None,
                kind: "text".into(),
                text: Some("rm -rf build".into()),
                key: None,
            })
            .unwrap();
        peer.send
            .send(AstationMessage::Terminal(Message::List.into()))
            .unwrap();
        peer.send.send(AstationMessage::AgentListRequest).unwrap();
        let frames = pump(&mut app, &mut peer).await;
        assert!(written.try_recv().is_err(), "agent input reached the PTY");
        assert!(app.terminal_outbox.is_empty());
        assert!(
            !frames
                .iter()
                .any(|frame| matches!(frame, Some(AstationMessage::AgentListResponse { .. }))),
            "answered a request while unauthenticated"
        );
        assert!(!app.astation_connected);
    }
}

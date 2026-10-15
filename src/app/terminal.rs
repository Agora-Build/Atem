use super::{App, AppMode};
use crate::pty_session::PtyEvent;
use crate::session::{Provider, Session, SessionId};
use crate::terminal_share::{Envelope, Message};

pub(super) fn append_log(log: &mut String, offset: &mut usize, text: &str) {
    const LIMIT: usize = 1024 * 1024;
    log.push_str(text);
    if log.len() > LIMIT {
        let mut start = log.len() - LIMIT;
        while !log.is_char_boundary(start) {
            start += 1;
        }
        log.drain(..start);
        *offset += start;
    }
}

pub(super) fn log_since(log: &str, offset: usize, position: usize) -> &str {
    let mut start = position.saturating_sub(offset).min(log.len());
    while !log.is_char_boundary(start) {
        start += 1;
    }
    &log[start..]
}

impl App {
    pub fn handle_terminal_legacy_rejection(&mut self) {
        self.status_message = Some("Use terminal-v1 control for an attached terminal".into());
        self.queue_terminal(Message::Error {
            terminal_id: None,
            message: "Use terminal-v1 input and its control lease for an attached terminal".into(),
        });
    }

    pub fn disconnect_terminals(&mut self) {
        for session in self.sessions.iter_mut() {
            if let Some(input) = &session.input {
                session.share.disconnect(input);
            }
        }
        self.terminal_outbox.clear();
    }

    fn queue_terminal(&mut self, message: Message) {
        if self.terminal_outbox.len() >= 128 {
            self.disconnect_terminals();
            self.terminal_outbox.push_back(Message::Error {
                terminal_id: None,
                message: "Terminal transport congested; subscribe again".into(),
            });
        } else {
            self.terminal_outbox.push_back(message);
        }
    }

    pub fn handle_terminal_message(&mut self, envelope: Envelope) {
        // Set only while the connection is authenticated (cleared during re-authentication).
        if !self.astation_connected || self.astation_client.is_ws_closed() {
            return;
        }
        if envelope.v != 1 {
            self.queue_terminal(Message::Error {
                terminal_id: None,
                message: "Unsupported terminal protocol version".into(),
            });
            return;
        }
        if matches!(envelope.message, Message::List) {
            // Every session with a process (exited ones carry their exit status),
            // in creation order.
            let sessions = self
                .sessions
                .iter()
                .filter(|s| s.input.is_some() && s.handle.is_some())
                .map(|s| s.share.info(s.terminal.screen()))
                .collect();
            self.queue_terminal(Message::Sessions {
                sessions,
                terminal_ids: Some("session".into()),
            });
            return;
        }
        let mut message = envelope.message;
        let Some(requested) = message.request_terminal_id().map(str::to_string) else {
            return;
        };
        // A session id, or the claude/codex alias for the most recently used
        // live session of that provider (resolved for each request).
        let target = match Provider::from_alias(&requested) {
            Some(provider) => self.sessions.latest(provider),
            None => SessionId::parse(&requested).filter(|id| self.sessions.get(id).is_some()),
        };
        let Some(target) = target else {
            self.queue_terminal(Message::Error {
                terminal_id: Some(requested),
                message: "Unknown terminal".into(),
            });
            return;
        };
        message.set_request_terminal_id(target.as_str());
        let id = target.to_string();
        let is_input = matches!(message, Message::Input { .. });
        let result = match self.sessions.get_mut(&target) {
            Some(Session {
                share,
                terminal,
                input: Some(input),
                handle: Some(handle),
                last_used,
                ..
            }) => {
                let result = share.handle(message, terminal, input, handle);
                if is_input && result.is_ok() {
                    *last_used = std::time::Instant::now();
                }
                result
            }
            _ => Err("Terminal unavailable; launch the CLI in Atem first".into()),
        };
        match result {
            Ok(messages) => {
                for message in messages {
                    self.queue_terminal(message);
                }
            }
            Err(message) => self.queue_terminal(Message::Error {
                terminal_id: Some(id),
                message,
            }),
        }
    }

    pub fn process_terminal_output(&mut self, id: &SessionId) {
        let Some(session) = self.sessions.get_mut(id) else {
            return;
        };
        let label = session.provider.as_str();
        let Session {
            share,
            terminal: parser,
            input: Some(input),
            events: Some(receiver),
            raw_log: log,
            raw_log_start: log_offset,
            ..
        } = session
        else {
            return;
        };
        let mut replies = Vec::new();
        let mut exit = false;
        for _ in 0..64 {
            match receiver.try_recv() {
                Ok(PtyEvent::Output(bytes)) => {
                    append_log(log, log_offset, &share.process(parser, input, &bytes));
                }
                Ok(PtyEvent::Error(error)) => {
                    self.status_message = Some(format!("{label}: {error}"))
                }
                Ok(PtyEvent::Written { sequence, result }) => {
                    if let Some(reply) = share.written(sequence, result.err()) {
                        replies.push(reply);
                    }
                }
                Ok(PtyEvent::Exit(status)) => {
                    share.exited(status, input);
                    exit = true;
                    break;
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
                    share.exited("PTY transport closed".into(), input);
                    exit = true;
                    break;
                }
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
            }
        }
        for reply in replies {
            self.queue_terminal(reply);
        }
        self.update_output_from_terminal(id);
        if exit {
            self.finalize_session(id);
        }
    }

    pub fn pump_terminals(&mut self) {
        if !self.astation_connected {
            return;
        }
        let mut messages = Vec::new();
        for session in self.sessions.iter_mut() {
            let Session {
                share,
                terminal: parser,
                input: Some(input),
                ..
            } = session
            else {
                continue;
            };
            match share.frames(parser.screen()) {
                Ok(frames) => messages.extend(frames),
                Err(error) => {
                    share.disconnect(input);
                    messages.push(Message::Error {
                        terminal_id: Some(share.id.clone()),
                        message: error,
                    });
                }
            }
        }
        for message in messages {
            self.queue_terminal(message);
        }
        while let Some(message) = self.terminal_outbox.front() {
            if self
                .astation_client
                .try_send_terminal(message.clone().into())
                .is_err()
            {
                break;
            }
            self.terminal_outbox.pop_front();
        }
    }

    pub fn leave_terminal_view(&mut self) {
        self.terminal_ui.reset_view();
        self.force_terminal_redraw = true;
        let action = match self.focused_session().map(|s| s.provider) {
            Some(Provider::Codex) => super::MenuAction::LaunchCodex,
            _ => super::MenuAction::LaunchClaude,
        };
        self.rebuild_menu();
        if let Some(index) = self.menu_actions.iter().position(|item| *item == action) {
            self.selected_index = index;
        }
        self.mode = AppMode::MainMenu;
        self.output_text.clear();
        self.status_message = Some(
            "Terminal still running. Reopen it from the menu; quitting Atem stops its sessions."
                .into(),
        );
    }

    pub fn reclaim_terminal(&mut self) {
        let Some(session) = self.focused_session_mut() else {
            return;
        };
        let message = match &session.input {
            Some(input) => session.share.reclaim(input),
            None => None,
        };
        // Force the local viewport to regain size ownership on the next draw.
        session.view.0 = 0;
        if let Some(message) = message {
            self.queue_terminal(message);
        }
        self.status_message = Some("Local control restored; unfinished input preserved".into());
    }

    pub fn stop_terminal(&mut self) {
        self.reclaim_terminal();
        if let Some(id) = self.focused_session().map(|s| s.id.clone()) {
            self.stop_session(&id);
        }
    }

    pub fn terminal_paste(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        let Some(session) = self.focused_session_mut() else {
            self.input_text.push_str(text);
            return;
        };
        let data = crate::terminal_keys::paste(text, session.terminal.screen().bracketed_paste());
        let Some(sender) = &session.input else {
            return;
        };
        // One paste is atomic at the writer. Never partially submit a large paste.
        match sender.send(data) {
            Ok(()) => session.last_used = std::time::Instant::now(),
            Err(error) => self.status_message = Some(error.to_string()),
        }
    }

    pub fn browse_terminal(&mut self, offset: usize) {
        let Some(session) = self.focused_session_mut() else {
            return;
        };
        let parser = &mut session.terminal;
        // Browsing never changes the canonical screen sent to Astation or query replies.
        parser.set_scrollback(offset);
        let screen = parser.screen().clone();
        let offset = screen.scrollback();
        parser.set_scrollback(0);
        let (rows, cols) = screen.size();
        let viewport = self.terminal_ui.viewport;
        let rows = if viewport.0 == 0 {
            rows
        } else {
            rows.min(viewport.0)
        };
        let cols = if viewport.1 == 0 {
            cols
        } else {
            cols.min(viewport.1)
        };
        let cursor = self
            .terminal_ui
            .browse
            .as_ref()
            .map_or((0, 0), |b| b.cursor);
        self.terminal_ui.browse = Some(crate::tui::terminal_view::Browse {
            screen,
            viewport: (rows, cols),
            offset,
            cursor: (cursor.0.min(rows - 1), cursor.1.min(cols - 1)),
            anchor: None,
        });
    }
}

#[cfg(test)]
mod live_tests;

#[cfg(test)]
mod tests {
    use super::*;

    /// A live `cat` PTY as `provider`'s session, shown by the terminal view.
    fn app_with_cat_as(provider: Provider) -> App {
        let mut app = App::new();
        let mut session = Session::new(
            provider,
            crate::pty_session::DEFAULT_ROWS,
            crate::pty_session::DEFAULT_COLS,
        );
        session.attach(crate::pty_session::spawn("cat", &[]).unwrap());
        let id = app.sessions.insert(session).unwrap().id.clone();
        app.focused = Some(id);
        app.mode = AppMode::Terminal;
        app
    }

    fn app_with_cat() -> App {
        app_with_cat_as(Provider::Codex)
    }

    fn codex_id(app: &App) -> SessionId {
        codex(app).id.clone()
    }

    fn codex(app: &App) -> &Session {
        app.sessions
            .iter()
            .filter(|s| s.provider == Provider::Codex)
            .last()
            .unwrap()
    }

    #[tokio::test]
    async fn hiding_the_view_preserves_the_same_process_and_drains_output() {
        let mut app = app_with_cat();
        let id = codex_id(&app);
        let generation = codex(&app).share.generation.clone();
        app.leave_terminal_view();
        app.send_data(&id, "still alive\n");
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while !codex(&app)
                .terminal
                .screen()
                .contents()
                .contains("still alive")
            {
                app.process_terminal_output(&id);
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(codex(&app).share.generation, generation);
        // The menu resumes the same session.
        app.launch_from_menu(Provider::Codex).await;
        assert_eq!(app.focused, Some(id));
        assert_eq!(app.sessions.iter().count(), 1);
    }

    #[test]
    fn disconnected_peer_cannot_subscribe_and_legacy_input_cannot_bypass_lease() {
        let mut app = app_with_cat();
        let generation = codex(&app).share.generation.clone();
        let request = Message::Subscribe {
            terminal_id: "codex".into(),
            generation,
        };
        app.handle_terminal_message(request.clone().into());
        assert!(!codex(&app).share.has_viewer());
        app.astation_connected = true;
        app.handle_terminal_message(request.into());
        assert!(codex(&app).share.has_viewer());
        app.handle_agent_input(None, "key".into(), None, Some("enter".into()));
        assert!(app.status_message.as_ref().unwrap().contains("terminal-v1"));
        app.disconnect_terminals();
        assert!(!codex(&app).share.has_viewer());
    }

    #[test]
    fn remote_size_survives_local_redraw_until_local_reclaim() {
        let mut app = app_with_cat();
        let id = codex_id(&app);
        app.sessions.get_mut(&id).unwrap().terminal.set_size(30, 90);
        codex(&app).input.as_ref().unwrap().set_remote(true);
        app.adjust_terminal_size(&id, 40, 120);
        assert_eq!(codex(&app).terminal.screen().size(), (30, 90));
        app.reclaim_terminal();
        app.adjust_terminal_size(&id, 40, 120);
        assert_eq!(codex(&app).terminal.screen().size(), (40, 120));
    }

    #[test]
    fn remote_release_restores_the_cached_local_size_for_both_providers() {
        for provider in ["codex", "claude"] {
            let mut app = app_with_cat_as(Provider::from_alias(provider).unwrap());
            app.astation_connected = true;
            let id = app.focused.clone().unwrap();
            let resize = |app: &mut App, rows, cols| app.adjust_terminal_size(&id, rows, cols);
            resize(&mut app, 40, 120);
            let generation = app.sessions.get(&id).unwrap().share.generation.clone();
            app.handle_terminal_message(
                Message::Subscribe {
                    terminal_id: provider.into(),
                    generation: generation.clone(),
                }
                .into(),
            );
            let Message::Attached { stream_id, .. } = app.terminal_outbox.pop_front().unwrap()
            else {
                panic!("expected attachment")
            };
            app.handle_terminal_message(
                Message::Control {
                    terminal_id: provider.into(),
                    generation: generation.clone(),
                    stream_id: stream_id.clone(),
                    take: true,
                }
                .into(),
            );
            let Message::Controller {
                lease_id: Some(lease_id),
                ..
            } = app.terminal_outbox.pop_front().unwrap()
            else {
                panic!("expected lease")
            };
            app.handle_terminal_message(
                Message::Resize {
                    terminal_id: provider.into(),
                    generation: generation.clone(),
                    stream_id: stream_id.clone(),
                    lease_id,
                    rows: 30,
                    cols: 90,
                }
                .into(),
            );
            resize(&mut app, 40, 120);
            let screen = app.sessions.get(&id).unwrap().terminal.screen();
            assert_eq!(screen.size(), (30, 90));
            app.handle_terminal_message(
                Message::Control {
                    terminal_id: provider.into(),
                    generation,
                    stream_id,
                    take: false,
                }
                .into(),
            );
            // No explicit local reclaim and no change to the cached viewport dimensions.
            resize(&mut app, 40, 120);
            let screen = app.sessions.get(&id).unwrap().terminal.screen();
            assert_eq!(screen.size(), (40, 120));
        }
    }

    #[test]
    fn history_browsing_never_changes_the_canonical_screen_or_discards_new_output() {
        let mut app = App::new();
        let mut session = Session::new(Provider::Codex, 3, 40);
        session.terminal = vt100::Parser::new(3, 40, 20);
        let id = app.sessions.insert(session).unwrap().id.clone();
        app.focused = Some(id.clone());
        app.mode = AppMode::Terminal;
        fn terminal<'a>(app: &'a mut App, id: &SessionId) -> &'a mut vt100::Parser {
            &mut app.sessions.get_mut(id).unwrap().terminal
        }
        terminal(&mut app, &id).process(b"old\r\none\r\ntwo\r\nthree\r\nfour");
        let live = terminal(&mut app, &id).screen().contents();
        app.browse_terminal(2);
        assert!(
            app.terminal_ui
                .browse
                .as_ref()
                .unwrap()
                .screen
                .contents()
                .contains("one")
        );
        assert_eq!(terminal(&mut app, &id).screen().scrollback(), 0);
        assert_eq!(terminal(&mut app, &id).screen().contents(), live);
        terminal(&mut app, &id).process(b"\r\nnew output");
        assert!(
            terminal(&mut app, &id)
                .screen()
                .contents()
                .contains("new output")
        );
        assert!(
            !app.terminal_ui
                .browse
                .as_ref()
                .unwrap()
                .screen
                .contents()
                .contains("new output")
        );
    }

    #[test]
    fn bounded_logs_keep_absolute_offsets_and_valid_utf8() {
        let mut log = String::new();
        let mut offset = 0;
        append_log(&mut log, &mut offset, &"\u{4e2d}".repeat(400000));
        assert!(log.len() <= 1024 * 1024);
        assert_eq!(log.len() + offset, 1200000);
        let position = offset + log.len();
        append_log(&mut log, &mut offset, "tail");
        assert_eq!(log_since(&log, offset, position), "tail");
        assert!(std::str::from_utf8(log_since(&log, offset, offset + 1).as_bytes()).is_ok());
    }

    #[tokio::test]
    async fn websocket_peer_views_and_controls_the_same_hidden_pty() {
        use crate::websocket_client::AstationMessage;
        use base64::{Engine, engine::general_purpose::STANDARD};
        use futures_util::{SinkExt, StreamExt};
        use tokio_tungstenite::tungstenite::Message as WsMessage;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(socket).await.unwrap();
            let encode = |message: Message| {
                WsMessage::Text(
                    serde_json::to_string(&AstationMessage::Terminal(message.into())).unwrap(),
                )
            };
            socket.send(encode(Message::List)).await.unwrap();
            let mut remote = vt100::Parser::new(24, 80, 0);
            let mut written = false;
            let mut displayed = false;
            while let Some(frame) = socket.next().await {
                let WsMessage::Text(json) = frame.unwrap() else {
                    continue;
                };
                let AstationMessage::Terminal(envelope) = serde_json::from_str(&json).unwrap()
                else {
                    continue;
                };
                match envelope.message {
                    Message::Sessions { sessions, .. } => {
                        assert_eq!(sessions.len(), 1);
                        socket
                            .send(encode(Message::Subscribe {
                                terminal_id: sessions[0].terminal_id.clone(),
                                generation: sessions[0].generation.clone(),
                            }))
                            .await
                            .unwrap();
                    }
                    Message::Attached { session, stream_id } => {
                        socket
                            .send(encode(Message::Control {
                                terminal_id: session.terminal_id,
                                generation: session.generation,
                                stream_id,
                                take: true,
                            }))
                            .await
                            .unwrap();
                    }
                    Message::Controller {
                        terminal_id,
                        generation,
                        stream_id,
                        lease_id: Some(lease_id),
                    } => {
                        socket
                            .send(encode(Message::Input {
                                terminal_id,
                                generation,
                                stream_id,
                                lease_id,
                                sequence: 0,
                                bytes: STANDARD.encode(b"REMOTE\n"),
                            }))
                            .await
                            .unwrap();
                    }
                    Message::Written {
                        sequence: 0,
                        error: None,
                        ..
                    } => written = true,
                    Message::Frame {
                        terminal_id,
                        generation,
                        stream_id,
                        offset,
                        bytes,
                        reset,
                        rows,
                        cols,
                        ..
                    } => {
                        if reset {
                            remote = vt100::Parser::new(rows, cols, 0);
                        }
                        let bytes = STANDARD.decode(bytes).unwrap();
                        remote.process(&bytes);
                        socket
                            .send(encode(Message::Ack {
                                terminal_id,
                                generation,
                                stream_id,
                                offset: offset + bytes.len() as u64,
                            }))
                            .await
                            .unwrap();
                        displayed |= remote.screen().contents().contains("REMOTE");
                    }
                    message => panic!("unexpected response: {message:?}"),
                }
                if written && displayed {
                    socket.close(None).await.unwrap();
                    return;
                }
            }
            panic!("peer disconnected before remote input was displayed");
        });
        let mut app = app_with_cat();
        let id = codex_id(&app);
        app.leave_terminal_view();
        app.astation_client
            .connect_raw(&format!("ws://{address}"))
            .await
            .unwrap();
        // Authentication is covered by websocket_client tests; inject its result here.
        app.astation_connected = true;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                while let Some(message) = app.astation_client.recv_message() {
                    if let AstationMessage::Terminal(envelope) = message {
                        app.handle_terminal_message(envelope);
                    }
                }
                app.process_terminal_output(&id);
                app.pump_terminals();
                if app.astation_client.is_ws_closed() {
                    app.disconnect_terminals();
                    break;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        peer.await.unwrap();
        assert!(matches!(app.mode, AppMode::MainMenu));
        assert!(codex(&app).events.is_some());
        assert!(!codex(&app).input.as_ref().unwrap().remote_controlled());
        assert!(codex(&app).terminal.screen().contents().contains("REMOTE"));
    }
}

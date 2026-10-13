use super::{App, AppMode};
use crate::pty_session::PtyEvent;
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
    pub(super) fn replace_terminal(&mut self, provider: &str) {
        let slot = if provider == "codex" {
            &mut self.codex_share
        } else {
            &mut self.claude_share
        };
        let previous = slot.replace(crate::terminal_share::SharedTerminal::new(provider));
        if let Some(previous) = previous.filter(|s| s.has_viewer()) {
            self.queue_terminal(Message::Exited {
                terminal_id: previous.id,
                generation: previous.generation,
                status: "Session replaced; refresh the terminal list".into(),
            });
        }
    }

    pub fn handle_terminal_legacy_rejection(&mut self) {
        self.status_message = Some("Use terminal-v1 control for an attached terminal".into());
        self.queue_terminal(Message::Error {
            terminal_id: None,
            message: "Use terminal-v1 input and its control lease for an attached terminal".into(),
        });
    }

    pub fn disconnect_terminals(&mut self) {
        for (share, input) in [
            (&mut self.codex_share, &self.codex_sender),
            (&mut self.claude_share, &self.claude_sender),
        ] {
            if let (Some(share), Some(input)) = (share, input) {
                share.disconnect(input);
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
        // This flag is set only after the authenticated connection completes.
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
            let sessions = [
                (&self.codex_share, &self.codex_terminal),
                (&self.claude_share, &self.claude_terminal),
            ]
            .into_iter()
            .filter_map(|(share, parser)| share.as_ref().map(|s| s.info(parser.screen())))
            .collect();
            self.queue_terminal(Message::Sessions { sessions });
            return;
        }
        let id = match &envelope.message {
            Message::Subscribe { terminal_id, .. }
            | Message::Unsubscribe { terminal_id, .. }
            | Message::Ack { terminal_id, .. }
            | Message::Control { terminal_id, .. }
            | Message::Input { terminal_id, .. }
            | Message::Resize { terminal_id, .. }
            | Message::Stop { terminal_id, .. } => terminal_id.clone(),
            _ => return,
        };
        let (share, parser, input, handle) = match id.as_str() {
            "codex" => (
                &mut self.codex_share,
                &mut self.codex_terminal,
                &self.codex_sender,
                &self.codex_resize_handle,
            ),
            "claude" => (
                &mut self.claude_share,
                &mut self.claude_terminal,
                &self.claude_sender,
                &self.claude_resize_handle,
            ),
            _ => {
                self.queue_terminal(Message::Error {
                    terminal_id: Some(id),
                    message: "Unknown terminal".into(),
                });
                return;
            }
        };
        let result = if let (Some(share), Some(input), Some(handle)) = (share, input, handle) {
            share.handle(envelope.message, parser, input, handle)
        } else {
            Err("Terminal unavailable; launch the CLI in Atem first".into())
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

    pub fn process_terminal_output(&mut self, id: &str) {
        let (share, parser, input, receiver, log, log_offset) = if id == "codex" {
            (
                &mut self.codex_share,
                &mut self.codex_terminal,
                &self.codex_sender,
                &mut self.codex_receiver,
                &mut self.codex_raw_log,
                &mut self.codex_raw_log_start,
            )
        } else {
            (
                &mut self.claude_share,
                &mut self.claude_terminal,
                &self.claude_sender,
                &mut self.claude_receiver,
                &mut self.claude_raw_log,
                &mut self.claude_raw_log_start,
            )
        };
        let (Some(share), Some(input), Some(receiver)) = (share, input, receiver) else {
            return;
        };
        let mut replies = Vec::new();
        let mut exit = false;
        for _ in 0..64 {
            match receiver.try_recv() {
                Ok(PtyEvent::Output(bytes)) => {
                    append_log(log, log_offset, &share.process(parser, input, &bytes));
                }
                Ok(PtyEvent::Error(error)) => self.status_message = Some(format!("{id}: {error}")),
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
        if id == "codex" {
            self.update_codex_output_from_terminal();
            if exit {
                self.finalize_codex_session();
            }
        } else {
            self.update_claude_output_from_terminal();
            if exit {
                self.finalize_claude_session();
            }
        }
    }

    pub fn pump_terminals(&mut self) {
        if !self.astation_connected {
            return;
        }
        let mut messages = Vec::new();
        for (share, parser, input) in [
            (
                &mut self.codex_share,
                &self.codex_terminal,
                &self.codex_sender,
            ),
            (
                &mut self.claude_share,
                &self.claude_terminal,
                &self.claude_sender,
            ),
        ] {
            if let (Some(share), Some(input)) = (share, input) {
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
        let action = match self.mode {
            AppMode::CodexChat => super::MenuAction::LaunchCodex,
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
        let (share, input) = match self.mode {
            AppMode::CodexChat => (&mut self.codex_share, &self.codex_sender),
            AppMode::ClaudeChat => (&mut self.claude_share, &self.claude_sender),
            _ => return,
        };
        if let (Some(share), Some(input)) = (share, input)
            && let Some(message) = share.reclaim(input)
        {
            self.queue_terminal(message);
        }
        // Force the local viewport to regain size ownership on the next draw.
        match self.mode {
            AppMode::CodexChat => self.codex_view_rows = 0,
            AppMode::ClaudeChat => self.claude_view_rows = 0,
            _ => {}
        }
        self.status_message = Some("Local control restored; unfinished input preserved".into());
    }

    pub fn stop_terminal(&mut self) {
        self.reclaim_terminal();
        let handle = match self.mode {
            AppMode::CodexChat => &self.codex_resize_handle,
            AppMode::ClaudeChat => &self.claude_resize_handle,
            _ => return,
        };
        if let Some(handle) = handle
            && let Err(error) = handle.stop()
        {
            self.status_message = Some(error.to_string());
        }
    }

    pub fn terminal_paste(&mut self, text: &str) {
        if text.is_empty() {
            return;
        }
        let (parser, sender) = match self.mode {
            AppMode::CodexChat => (&self.codex_terminal, &self.codex_sender),
            AppMode::ClaudeChat => (&self.claude_terminal, &self.claude_sender),
            _ => {
                self.input_text.push_str(text);
                return;
            }
        };
        let data = crate::terminal_keys::paste(text, parser.screen().bracketed_paste());
        if let Some(sender) = sender {
            // One paste is atomic at the writer. Never partially submit a large paste.
            if let Err(error) = sender.send(data) {
                self.status_message = Some(error.to_string());
            }
        }
    }

    pub fn browse_terminal(&mut self, offset: usize) {
        let parser = match self.mode {
            AppMode::CodexChat => &mut self.codex_terminal,
            AppMode::ClaudeChat => &mut self.claude_terminal,
            _ => return,
        };
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
    use crate::terminal_share::SharedTerminal;

    fn app_with_cat() -> App {
        let mut app = App::new();
        let session = crate::pty_session::spawn("cat", &[]).unwrap();
        app.codex_sender = Some(session.sender);
        app.codex_receiver = Some(session.receiver);
        app.codex_resize_handle = Some(session.resize_handle);
        app.codex_share = Some(SharedTerminal::new("codex"));
        app.mode = AppMode::CodexChat;
        app
    }

    #[tokio::test]
    async fn hiding_the_view_preserves_the_same_process_and_drains_output() {
        let mut app = app_with_cat();
        let generation = app.codex_share.as_ref().unwrap().generation.clone();
        app.leave_terminal_view();
        app.send_codex_data("still alive\n");
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            while !app
                .codex_terminal
                .screen()
                .contents()
                .contains("still alive")
            {
                app.process_codex_output();
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(app.codex_share.as_ref().unwrap().generation, generation);
        assert!(!app.ensure_codex_session().await.unwrap());
        assert!(matches!(app.mode, AppMode::MainMenu));
    }

    #[test]
    fn disconnected_peer_cannot_subscribe_and_legacy_input_cannot_bypass_lease() {
        let mut app = app_with_cat();
        let generation = app.codex_share.as_ref().unwrap().generation.clone();
        let request = Message::Subscribe {
            terminal_id: "codex".into(),
            generation,
        };
        app.handle_terminal_message(request.clone().into());
        assert!(!app.codex_share.as_ref().unwrap().has_viewer());
        app.astation_connected = true;
        app.handle_terminal_message(request.into());
        assert!(app.codex_share.as_ref().unwrap().has_viewer());
        app.handle_agent_input(None, "key".into(), None, Some("enter".into()));
        assert!(app.status_message.as_ref().unwrap().contains("terminal-v1"));
        app.disconnect_terminals();
        assert!(!app.codex_share.as_ref().unwrap().has_viewer());
    }

    #[test]
    fn remote_size_survives_local_redraw_until_local_reclaim() {
        let mut app = app_with_cat();
        app.codex_terminal.set_size(30, 90);
        app.codex_sender.as_ref().unwrap().set_remote(true);
        app.adjust_codex_terminal_size(40, 120);
        assert_eq!(app.codex_terminal.screen().size(), (30, 90));
        app.reclaim_terminal();
        app.adjust_codex_terminal_size(40, 120);
        assert_eq!(app.codex_terminal.screen().size(), (40, 120));
    }

    #[test]
    fn remote_release_restores_the_cached_local_size_for_both_providers() {
        for provider in ["codex", "claude"] {
            let mut app = app_with_cat();
            app.astation_connected = true;
            if provider == "claude" {
                app.claude_sender = app.codex_sender.take();
                app.claude_receiver = app.codex_receiver.take();
                app.claude_resize_handle = app.codex_resize_handle.take();
                app.codex_share = None;
                app.claude_share = Some(SharedTerminal::new(provider));
                app.mode = AppMode::ClaudeChat;
            }
            let resize = if provider == "codex" {
                App::adjust_codex_terminal_size
            } else {
                App::adjust_claude_terminal_size
            };
            resize(&mut app, 40, 120);
            let generation = if provider == "codex" {
                &app.codex_share
            } else {
                &app.claude_share
            }
            .as_ref()
            .unwrap()
            .generation
            .clone();
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
            let screen = if provider == "codex" {
                app.codex_terminal.screen()
            } else {
                app.claude_terminal.screen()
            };
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
            let screen = if provider == "codex" {
                app.codex_terminal.screen()
            } else {
                app.claude_terminal.screen()
            };
            assert_eq!(screen.size(), (40, 120));
        }
    }

    #[test]
    fn history_browsing_never_changes_the_canonical_screen_or_discards_new_output() {
        let mut app = App::new();
        app.mode = AppMode::CodexChat;
        app.codex_terminal = vt100::Parser::new(3, 40, 20);
        app.codex_terminal
            .process(b"old\r\none\r\ntwo\r\nthree\r\nfour");
        let live = app.codex_terminal.screen().contents();
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
        assert_eq!(app.codex_terminal.screen().scrollback(), 0);
        assert_eq!(app.codex_terminal.screen().contents(), live);
        app.codex_terminal.process(b"\r\nnew output");
        assert!(
            app.codex_terminal
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
                    Message::Sessions { sessions } => {
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
                app.process_codex_output();
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
        assert!(app.codex_receiver.is_some());
        assert!(!app.codex_sender.as_ref().unwrap().remote_controlled());
        assert!(app.codex_terminal.screen().contents().contains("REMOTE"));
    }
}

use super::{App, AppMode};
use crate::pty_session::PtyEvent;
use crate::session::{Provider, Session, SessionId};

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

impl App {
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
        let mut exit = false;
        for _ in 0..64 {
            match receiver.try_recv() {
                Ok(PtyEvent::Output(bytes)) => {
                    append_log(log, log_offset, &share.process(parser, input, &bytes));
                }
                Ok(PtyEvent::Error(error)) => {
                    self.status_message = Some(format!("{label}: {error}"))
                }
                // Only remote writes report back, and there are none.
                Ok(PtyEvent::Written { .. } | PtyEvent::Fenced { .. }) => {}
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
        self.update_output_from_terminal(id);
        if exit {
            self.finalize_session(id);
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
        if let Some(id) = self.focused_session().map(|s| s.id.clone()) {
            self.reclaim_session(&id);
        }
    }

    /// Take control of session `id` back from a remote controller; the local
    /// view regains size ownership.
    pub fn reclaim_session(&mut self, id: &SessionId) {
        let Some(session) = self.sessions.get_mut(id) else {
            return;
        };
        if let Some(input) = &session.input {
            input.set_remote(false);
        }
        // Force the local viewport to regain size ownership on the next draw.
        session.view.0 = 0;
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
        append_log(&mut log, &mut offset, "tail");
        assert!(log.ends_with("tail"));
        assert_eq!(log.len() + offset, 1200004);
    }
}

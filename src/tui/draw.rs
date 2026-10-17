use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
};
use vt100::{Cell as VtCell, Color as VtColor};

use crate::app::{App, AppMode};

pub(crate) fn draw_ui(frame: &mut Frame, app: &mut App) {
    let size = frame.area();
    frame.render_widget(Clear, size);

    // Create layout
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header
            Constraint::Min(0),    // Main content
            Constraint::Length(3), // Footer
        ])
        .split(size);

    // Header
    let header = Paragraph::new("\u{1f680} ATEM - Agora.io AI CLI Tool")
        .style(
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        )
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Blue)),
        );
    frame.render_widget(header, chunks[0]);

    // Main content based on mode
    match app.mode {
        AppMode::MainMenu => draw_main_menu(frame, chunks[1], app),
        AppMode::TokenGeneration => draw_output_view(frame, chunks[1], app),
        AppMode::CommandExecution => draw_command_input(frame, chunks[1], app),
        AppMode::AgentPanel => draw_agent_panel(frame, chunks[1], app),
    }

    // Footer
    let base_footer = match app.mode {
        AppMode::MainMenu => "\u{2191}\u{2193}/jk: Navigate | Enter: Select | q: Quit",
        AppMode::CommandExecution => "Type command + Enter | b: Back | q: Quit",
        AppMode::AgentPanel => {
            "\u{2191}\u{2193}/jk: Navigate | Enter: Open | r: Refresh | b: Back"
        }
        AppMode::TokenGeneration if !app.cached_projects.is_empty() => {
            if app.show_certificates {
                "s: Hide Certificates | b: Back | q: Quit"
            } else {
                "s: Show Certificates | b: Back | q: Quit"
            }
        }
        _ => "b: Back | q: Quit",
    };

    let footer_text = if let Some(status) = &app.status_message {
        if status.is_empty() {
            base_footer.to_string()
        } else {
            format!("{} | {}", status, base_footer)
        }
    } else {
        base_footer.to_string()
    };

    let footer = Paragraph::new(footer_text)
        .style(Style::default().fg(Color::Yellow))
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Gray)),
        );
    frame.render_widget(footer, chunks[2]);

    // Draw popup if needed
    if app.show_popup {
        draw_popup(frame, app);
    }
}

/// The main menu's credential line for a paired device, with its
/// verification (`TrustStore::verification_status`) when known.
pub(crate) fn paired_status_line(
    login_id: &str,
    status: Option<crate::memory::trust::VerificationStatus>,
) -> String {
    use crate::memory::trust::VerificationStatus;
    let suffix = match status {
        Some(VerificationStatus::Verified) => " \u{b7} verified",
        Some(VerificationStatus::NotVerified) => {
            " \u{b7} not verified \u{2014} run `atem pair verify`"
        }
        Some(VerificationStatus::Revoked) => {
            " \u{b7} revoked \u{2014} run `atem unpair`, then `atem pair`"
        }
        None => "",
    };
    format!("\u{1f517} Paired (SSO: {login_id}){suffix}")
}

pub(crate) fn draw_main_menu(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    // Build credential status line
    let store = crate::credentials::CredentialStore::load();
    let (cred_line, cred_style) = if let Some(sso) = store.find_sso() {
        let id = sso.login_id.as_deref().unwrap_or("-");
        (
            format!("\u{1f511} Logged in (SSO: {})", id),
            Style::default().fg(Color::Green),
        )
    } else if let Some(p) = store
        .entries
        .iter()
        .find(|e| e.source == crate::credentials::CredentialSource::AstationPaired)
    {
        let id = p.login_id.as_deref().unwrap_or("-");
        // Read where the credential store is (each draw); a missing or
        // unreadable trust file just leaves the suffix out.
        let status = p.astation_id.as_deref().and_then(|astation_id| {
            crate::memory::trust::TrustStore::load_from(&crate::memory::trust::trust_path())
                .ok()
                .map(|trust| trust.verification_status(astation_id))
        });
        (
            paired_status_line(id, status),
            Style::default().fg(Color::Cyan),
        )
    } else {
        (
            "\u{26a0}\u{fe0f}  Not logged in — run `atem login` or `atem pair`".to_string(),
            Style::default().fg(Color::Yellow),
        )
    };

    let cred_paragraph = Paragraph::new(cred_line)
        .style(cred_style)
        .block(Block::default().borders(Borders::NONE));

    // The atem runtime holds the Astation link; the menu shows its state.
    let pairing_line = if !app.astation_connected {
        Some("Astation \u{2717} (the atem runtime holds the connection; pair to control agents remotely)")
    } else {
        None
    };

    let num_status_lines = 1 + if pairing_line.is_some() { 1 } else { 0 };

    // Split area: status lines + menu list
    let chunks = ratatui::layout::Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(num_status_lines), Constraint::Min(0)])
        .split(area);

    if let Some(pairing_text) = pairing_line {
        // Two status lines: credential + pairing
        let status_chunks = ratatui::layout::Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Length(1)])
            .split(chunks[0]);

        frame.render_widget(cred_paragraph, status_chunks[0]);

        let pairing_paragraph = Paragraph::new(pairing_text)
            .style(Style::default().fg(Color::DarkGray))
            .block(Block::default().borders(Borders::NONE));
        frame.render_widget(pairing_paragraph, status_chunks[1]);
    } else {
        frame.render_widget(cred_paragraph, chunks[0]);
    }

    let items: Vec<ListItem> = app
        .main_menu_items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let style = if i == app.selected_index {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(item.as_str()).style(style)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Main Menu")
                .border_style(Style::default().fg(Color::Green)),
        )
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));

    frame.render_widget(list, chunks[1]);
}

pub(crate) fn draw_output_view(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let output = Paragraph::new(app.output_text.as_str())
        .style(Style::default().fg(Color::White))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Output")
                .border_style(Style::default().fg(Color::Green)),
        )
        .wrap(Wrap { trim: true });

    frame.render_widget(output, area);
}

pub(crate) fn draw_command_input(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(5),    // Output
            Constraint::Length(3), // Input
        ])
        .split(area);

    // Output area
    let output = Paragraph::new(app.output_text.as_str())
        .style(Style::default().fg(Color::White))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Command Output")
                .border_style(Style::default().fg(Color::Green)),
        )
        .wrap(Wrap { trim: true });
    frame.render_widget(output, chunks[0]);

    // Input area
    let input = Paragraph::new(app.input_text.as_str())
        .style(Style::default().fg(Color::Yellow))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Command Input")
                .border_style(Style::default().fg(Color::Cyan)),
        );
    frame.render_widget(input, chunks[1]);
}

/// `screen` in `area`, cell by cell, with the browse selection and the
/// screen's cursor (hidden while browsing or showing help).
pub(crate) fn draw_terminal_screen(
    frame: &mut Frame,
    area: ratatui::layout::Rect,
    screen: &vt100::Screen,
    browse: Option<&super::terminal_view::Browse>,
    help: bool,
) {
    let buffer = frame.buffer_mut();
    for row in 0..area.height {
        for col in 0..area.width {
            let Some(target) = buffer.cell_mut((area.x + col, area.y + row)) else {
                continue;
            };
            let Some(cell) = screen.cell(row, col) else {
                target.set_symbol(" ").set_style(Style::default());
                continue;
            };
            if cell.is_wide_continuation() {
                target.set_symbol(" ").set_skip(true);
                continue;
            }
            let symbol = cell.contents();
            let clipped_wide = cell.is_wide() && col + 1 == area.width;
            let mut style = style_from_cell(cell);
            if browse.is_some_and(|b| {
                b.selected(row, col)
                    || b.cursor == (row, col)
                    || (cell.is_wide() && b.cursor == (row, col + 1))
            }) {
                style = style.add_modifier(Modifier::REVERSED);
            }
            target
                .set_symbol(if symbol.is_empty() || clipped_wide {
                    " "
                } else {
                    &symbol
                })
                .set_style(style);
        }
    }
    if !help && browse.is_none() && !screen.hide_cursor() {
        let (row, col) = screen.cursor_position();
        if row < area.height && col < area.width {
            frame.set_cursor_position((area.x + col, area.y + row));
        }
    }
}

pub(crate) fn draw_popup(frame: &mut Frame, app: &App) {
    let size = frame.area();
    let popup_area = centered_rect(60, 70, size);

    frame.render_widget(Clear, popup_area);

    let popup = Paragraph::new(app.popup_message.as_str())
        .style(Style::default().fg(Color::White).bg(Color::Blue))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Help")
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .wrap(Wrap { trim: true });

    frame.render_widget(popup, popup_area);
}

pub(crate) fn centered_rect(
    percent_x: u16,
    percent_y: u16,
    r: ratatui::layout::Rect,
) -> ratatui::layout::Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

pub(crate) fn vt_color_to_tui(color: VtColor) -> Color {
    match color {
        VtColor::Default => Color::Reset,
        VtColor::Idx(idx) => Color::Indexed(idx),
        VtColor::Rgb(r, g, b) => Color::Rgb(r, g, b),
    }
}

/// The runtime's sessions (the menu's agent panel).
pub(crate) fn draw_agent_panel(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let sessions = &app.runtime_sessions;
    if sessions.is_empty() {
        let note = app
            .runtime_note
            .as_deref()
            .unwrap_or("No sessions. Launch Claude Code or Codex from the menu.");
        let msg = Paragraph::new(format!(
            "{note}\n\n\
             Sessions run in the atem runtime and keep running when you\n\
             detach; `atem agent list` shows them too.\n\n\
             Press 'b' to go back."
        ))
        .style(Style::default().fg(Color::DarkGray))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" \u{1f916} Agent Sessions ")
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .wrap(Wrap { trim: false });
        frame.render_widget(msg, area);
        return;
    }

    let items: Vec<ListItem> = sessions
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let line = format!(
                "{}  {:<6}  {:<17}  {:<7}  {}{}",
                s.id,
                s.provider,
                s.state,
                s.status,
                s.cwd.display(),
                if s.attached { "  (attached)" } else { "" },
            );
            let style = if i == app.agent_panel_selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };
            ListItem::new(line).style(style)
        })
        .collect();

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(format!(" \u{1f916} Agent Sessions \u{2014} {} ", sessions.len()))
            .border_style(Style::default().fg(Color::Green)),
    );
    frame.render_widget(list, area);
}

pub(crate) fn style_from_cell(cell: &VtCell) -> Style {
    let fg = vt_color_to_tui(cell.fgcolor());
    let bg = vt_color_to_tui(cell.bgcolor());

    let mut style = Style::default();
    if fg != Color::Reset {
        style = style.fg(fg);
    }
    if bg != Color::Reset {
        style = style.bg(bg);
    }
    if cell.inverse() {
        style = style.add_modifier(Modifier::REVERSED);
    }
    if cell.bold() {
        style = style.add_modifier(Modifier::BOLD);
    }
    if cell.italic() {
        style = style.add_modifier(Modifier::ITALIC);
    }
    if cell.underline() {
        style = style.add_modifier(Modifier::UNDERLINED);
    }
    style
}

#[cfg(test)]
mod paired_status_tests {
    use super::paired_status_line;
    use crate::memory::trust::VerificationStatus;
    use crate::tui::frontend::View;
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    #[derive(Clone)]
    struct Recording(Arc<Mutex<Vec<u8>>>);

    impl Write for Recording {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn reverse_video_preserves_default_colors_and_explicit_colors() {
        let mut parser = vt100::Parser::new(2, 20, 0);
        parser.process(b"\x1b[7mdefault\x1b[0m\r\n\x1b[31;44;7mcolored");
        let default = super::style_from_cell(parser.screen().cell(0, 0).unwrap());
        assert!(
            default
                .add_modifier
                .contains(ratatui::style::Modifier::REVERSED)
        );
        let colored = super::style_from_cell(parser.screen().cell(1, 0).unwrap());
        assert_eq!(colored.fg, Some(ratatui::style::Color::Indexed(1)));
        assert_eq!(colored.bg, Some(ratatui::style::Color::Indexed(4)));
        assert!(
            colored
                .add_modifier
                .contains(ratatui::style::Modifier::REVERSED)
        );
    }

    /// A frontend view of a `provider` session with a `rows` x `cols` screen.
    fn view(provider: &str, rows: u16, cols: u16) -> View {
        let mut view = View::new("ses-abcdefghijkl", false, None);
        view.apply(crate::runtime::protocol::RuntimeMsg::Attached {
            session: crate::runtime::protocol::SessionSummary {
                id: "ses-abcdefghijkl".into(),
                provider: provider.into(),
                cwd: "/tmp".into(),
                created_at_ms: 1,
                state: "running".into(),
                status: "unknown".into(),
                attached: true,
                remote_controlled: false,
                exited: None,
                rows,
                cols,
                generation: "g".into(),
            },
            restore: String::new(),
            offset: 0,
        });
        view.ui.viewport = (rows, cols);
        view
    }

    #[test]
    fn connected_claude_keeps_the_terminal_renderer_and_size() {
        let backend = ratatui::backend::TestBackend::new(100, 40);
        let mut terminal = ratatui::Terminal::new(backend).unwrap();
        let mut view = view("claude", 39, 100);
        view.astation = true;
        terminal.draw(|frame| view.draw(frame)).unwrap();
        assert_eq!(view.parser.screen().size(), (39, 100));
        let text: String = terminal
            .backend()
            .buffer()
            .content()
            .iter()
            .map(|cell| cell.symbol())
            .collect();
        assert!(text.contains("Atem | Claude | Local | Astation \u{2713}"));
    }

    #[test]
    fn ansi_redraw_clears_stale_art_and_keeps_one_footer_and_native_cursor() {
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let backend = ratatui::backend::CrosstermBackend::new(Recording(bytes.clone()));
        let mut terminal = ratatui::Terminal::with_options(
            backend,
            ratatui::TerminalOptions {
                viewport: ratatui::Viewport::Fixed(ratatui::layout::Rect::new(0, 0, 80, 25)),
            },
        )
        .unwrap();
        let mut view = view("codex", 24, 80);
        view.parser
            .process("\x1b[4;40H\u{28ff}\u{28fe}\u{28fc}\x1b[24;1H? for shortcuts".as_bytes());
        let mut outer = vt100::Parser::new(25, 80, 0);
        terminal
            .draw(|frame| view.draw(frame))
            .unwrap();
        outer.process(&std::mem::take(&mut *bytes.lock().unwrap()));
        assert!(outer.screen().contents().contains('\u{28ff}'));

        view.parser.process("\x1b[2J\x1b[HATEM_READY \u{4e2d}\u{6587}\x1b[24;1H? for shortcuts\x1b[24;55H2 warnings\x1b[23;3H\x1b[?25h".as_bytes());
        view.ui.record("A very long credential notification that belongs in details, never over the agent screen".repeat(10));
        terminal
            .draw(|frame| view.draw(frame))
            .unwrap();
        outer.process(&std::mem::take(&mut *bytes.lock().unwrap()));
        let text = outer.screen().contents();
        assert!(!text.contains('\u{28ff}'));
        assert_eq!(text.matches("? for shortcuts").count(), 1);
        assert_eq!(text.matches("2 warnings").count(), 1);
        assert_eq!(text.matches("Atem |").count(), 1);
        assert!(!text.contains("credential notification"));
        assert_eq!(outer.screen().cursor_position(), (22, 2));
        assert!(!outer.screen().hide_cursor());
        for row in 0..24 {
            for col in 0..80 {
                let actual = outer.screen().cell(row, col).unwrap().contents();
                let expected = view
                    .parser
                    .screen()
                    .cell(row, col)
                    .unwrap()
                    .contents();
                assert_eq!(actual.trim_end(), expected.trim_end(), "cell {row},{col}");
            }
        }
    }

    #[test]
    fn captured_codex_repaints_match_the_canonical_grid_without_stale_animation() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../tests/fixtures/codex-terminal-repaint.json"
        ))
        .unwrap();
        let bytes = Arc::new(Mutex::new(Vec::new()));
        let mut terminal = ratatui::Terminal::with_options(
            ratatui::backend::CrosstermBackend::new(Recording(bytes.clone())),
            ratatui::TerminalOptions {
                viewport: ratatui::Viewport::Fixed(ratatui::layout::Rect::new(0, 0, 152, 52)),
            },
        )
        .unwrap();
        let mut view = view("codex", 51, 152);
        let mut outer = vt100::Parser::new(52, 152, 0);
        let mut saw_animation = false;
        for (index, frame) in fixture["frames"].as_array().unwrap().iter().enumerate() {
            // Real Codex clears its animation with incremental edits, without a full clear.
            for chunk in frame.as_str().unwrap().as_bytes().chunks(37) {
                view.parser.process(chunk);
            }
            terminal
                .draw(|frame| view.draw(frame))
                .unwrap();
            outer.process(&std::mem::take(&mut *bytes.lock().unwrap()));
            let dots = outer
                .screen()
                .contents()
                .chars()
                .filter(|c| ('\u{2800}'..='\u{28ff}').contains(c))
                .count();
            saw_animation |= dots > 100;
            for row in 0..51 {
                for col in 0..152 {
                    let expected = view.parser.screen().cell(row, col).unwrap();
                    let actual = outer.screen().cell(row, col).unwrap();
                    assert_eq!(
                        actual.contents().trim_end(),
                        expected.contents().trim_end(),
                        "frame {index}, cell {row},{col}"
                    );
                }
            }
        }
        assert!(
            saw_animation,
            "fixture must exercise the original animation"
        );
        let text = outer.screen().contents();
        // Codex's live status spinner is valid output and must be preserved.
        assert!(
            text.chars()
                .filter(|c| ('\u{2800}'..='\u{28ff}').contains(c))
                .count()
                <= 1
        );
        assert_eq!(text.matches("Atem |").count(), 1);
        assert_eq!(
            outer.screen().cursor_position(),
            view.parser.screen().cursor_position()
        );
        assert_eq!(
            outer.screen().hide_cursor(),
            view.parser.screen().hide_cursor()
        );
    }

    #[test]
    fn the_paired_line_shows_the_verification() {
        assert_eq!(
            paired_status_line("me", Some(VerificationStatus::Verified)),
            "\u{1f517} Paired (SSO: me) \u{b7} verified"
        );
        assert_eq!(
            paired_status_line("me", Some(VerificationStatus::NotVerified)),
            "\u{1f517} Paired (SSO: me) \u{b7} not verified \u{2014} run `atem pair verify`"
        );
        assert_eq!(
            paired_status_line("me", Some(VerificationStatus::Revoked)),
            "\u{1f517} Paired (SSO: me) \u{b7} revoked \u{2014} run `atem unpair`, then `atem pair`"
        );
        assert_eq!(paired_status_line("me", None), "\u{1f517} Paired (SSO: me)");
    }
}

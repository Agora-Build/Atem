use ratatui::{
    Frame,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
};
use vt100::{Cell as VtCell, Color as VtColor};

use crate::agent_client::{AgentProtocol, AgentStatus};
use crate::app::{App, AppMode};

pub(crate) fn draw_ui(frame: &mut Frame, app: &mut App) {
    let size = frame.area();

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
        AppMode::ClaudeChat => {
            if app.astation_connected {
                draw_output_view(frame, chunks[1], app)
            } else {
                draw_claude_panel(frame, chunks[1], app)
            }
        }
        AppMode::CommandExecution => draw_command_input(frame, chunks[1], app),
        AppMode::CodexChat => draw_codex_panel(frame, chunks[1], app),
        AppMode::AgentPanel => draw_agent_panel(frame, chunks[1], app),
    }

    // Footer
    let base_footer = match app.mode {
        AppMode::MainMenu => "\u{2191}\u{2193}/jk: Navigate | Enter: Select | c: Copy Mode | q: Quit",
        AppMode::CommandExecution => "Type command + Enter | b: Back | q: Quit",
        AppMode::CodexChat => "All input goes to Codex | Ctrl+B: Back to menu",
        AppMode::ClaudeChat if !app.astation_connected => {
            "All input goes to Claude | Ctrl+B: Back to menu"
        }
        AppMode::AgentPanel => "\u{2191}\u{2193}/jk: Navigate | Enter: Set Active | r: Refresh | b: Back",
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

pub(crate) fn draw_main_menu(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    // Build credential status line
    let cred_line = if app.synced_customer_id.is_some() {
        format!(
            "\u{1f511} Credentials: synced from Astation{}",
            if app.astation_connected { " | \u{1f7e2} Astation connected" } else { "" }
        )
    } else if app.config.customer_id.is_some() {
        "\u{1f511} Credentials: from config file".to_string()
    } else {
        "\u{26a0}\u{fe0f}  No credentials — run `atem login` or set AGORA_CUSTOMER_ID".to_string()
    };

    let cred_style = if app.synced_customer_id.is_some() || app.config.customer_id.is_some() {
        Style::default().fg(Color::Green)
    } else {
        Style::default().fg(Color::Yellow)
    };

    let cred_paragraph = Paragraph::new(cred_line)
        .style(cred_style)
        .block(Block::default().borders(Borders::NONE));

    // Split area: credential status bar (1 line) + menu list
    let chunks = ratatui::layout::Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(0),
        ])
        .split(area);

    frame.render_widget(cred_paragraph, chunks[0]);

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

pub(crate) fn draw_codex_panel(frame: &mut Frame, area: ratatui::layout::Rect, app: &mut App) {
    let terminal_block = Block::default()
        .borders(Borders::ALL)
        .title("Codex Terminal [Ctrl+B: back to menu]")
        .border_style(Style::default().fg(Color::Green));
    let terminal_inner = terminal_block.inner(area);
    frame.render_widget(terminal_block, area);

    app.adjust_codex_terminal_size(terminal_inner.height, terminal_inner.width);

    if terminal_inner.width > 0 && terminal_inner.height > 0 {
        let screen = app.codex_terminal.screen();
        let cursor_pos = screen.cursor_position();
        let cursor_hidden = screen.hide_cursor();

        {
            let buffer = frame.buffer_mut();
            for row in 0..terminal_inner.height {
                let mut col = 0;
                while col < terminal_inner.width {
                    let gx = terminal_inner.x + col;
                    let gy = terminal_inner.y + row;

                    let cell_opt = screen.cell(row, col);
                    if let Some(cell) = cell_opt {
                        if cell.is_wide_continuation() {
                            if let Some(buf_cell) = buffer.cell_mut((gx, gy)) {
                                buf_cell.set_symbol(" ").set_style(Style::default());
                            }
                            col += 1;
                            continue;
                        }

                        let mut symbol = cell.contents();
                        if symbol.is_empty() {
                            symbol.push(' ');
                        }

                        let style = style_from_cell(cell);
                        if let Some(buf_cell) = buffer.cell_mut((gx, gy)) {
                            buf_cell.set_symbol(symbol.as_str()).set_style(style);
                        }

                        if cell.is_wide() && col + 1 < terminal_inner.width {
                            let gx_next = terminal_inner.x + col + 1;
                            if let Some(buf_cell) = buffer.cell_mut((gx_next, gy)) {
                                buf_cell.set_symbol(" ").set_style(style);
                            }
                            col += 2;
                        } else {
                            col += 1;
                        }
                    } else {
                        if let Some(buf_cell) = buffer.cell_mut((gx, gy)) {
                            buf_cell.set_symbol(" ").set_style(Style::default());
                        }
                        col += 1;
                    }
                }
            }

            if !cursor_hidden {
                let (cursor_row, cursor_col) = cursor_pos;
                if cursor_row < terminal_inner.height && cursor_col < terminal_inner.width {
                    let gx = terminal_inner.x + cursor_col;
                    let gy = terminal_inner.y + cursor_row;
                    let base_style = screen
                        .cell(cursor_row, cursor_col)
                        .map(style_from_cell)
                        .unwrap_or_else(Style::default);
                    let mut symbol = screen
                        .cell(cursor_row, cursor_col)
                        .map(|cell| cell.contents())
                        .unwrap_or_else(|| " ".to_string());
                    if symbol.is_empty() {
                        symbol.push(' ');
                    }
                    if let Some(buf_cell) = buffer.cell_mut((gx, gy)) {
                        buf_cell
                            .set_symbol(symbol.as_str())
                            .set_style(base_style.add_modifier(Modifier::REVERSED));
                    }
                }
            }
        }
    }
}

pub(crate) fn draw_claude_panel(frame: &mut Frame, area: ratatui::layout::Rect, app: &mut App) {
    let terminal_block = Block::default()
        .borders(Borders::ALL)
        .title("Claude Terminal [Ctrl+B: back to menu]")
        .border_style(Style::default().fg(Color::Green));
    let terminal_inner = terminal_block.inner(area);
    frame.render_widget(terminal_block, area);

    app.adjust_claude_terminal_size(terminal_inner.height, terminal_inner.width);

    if terminal_inner.width > 0 && terminal_inner.height > 0 {
        let screen = app.claude_terminal.screen();
        let cursor_pos = screen.cursor_position();
        let cursor_hidden = screen.hide_cursor();

        {
            let buffer = frame.buffer_mut();
            for row in 0..terminal_inner.height {
                let mut col = 0;
                while col < terminal_inner.width {
                    let gx = terminal_inner.x + col;
                    let gy = terminal_inner.y + row;

                    let cell_opt = screen.cell(row, col);
                    if let Some(cell) = cell_opt {
                        if cell.is_wide_continuation() {
                            if let Some(buf_cell) = buffer.cell_mut((gx, gy)) {
                                buf_cell.set_symbol(" ").set_style(Style::default());
                            }
                            col += 1;
                            continue;
                        }

                        let mut symbol = cell.contents();
                        if symbol.is_empty() {
                            symbol.push(' ');
                        }

                        let style = style_from_cell(cell);
                        if let Some(buf_cell) = buffer.cell_mut((gx, gy)) {
                            buf_cell.set_symbol(symbol.as_str()).set_style(style);
                        }

                        if cell.is_wide() && col + 1 < terminal_inner.width {
                            let gx_next = terminal_inner.x + col + 1;
                            if let Some(buf_cell) = buffer.cell_mut((gx_next, gy)) {
                                buf_cell.set_symbol(" ").set_style(style);
                            }
                            col += 2;
                        } else {
                            col += 1;
                        }
                    } else {
                        if let Some(buf_cell) = buffer.cell_mut((gx, gy)) {
                            buf_cell.set_symbol(" ").set_style(Style::default());
                        }
                        col += 1;
                    }
                }
            }

            if !cursor_hidden {
                let (cursor_row, cursor_col) = cursor_pos;
                if cursor_row < terminal_inner.height && cursor_col < terminal_inner.width {
                    let gx = terminal_inner.x + cursor_col;
                    let gy = terminal_inner.y + cursor_row;
                    let base_style = screen
                        .cell(cursor_row, cursor_col)
                        .map(style_from_cell)
                        .unwrap_or_default();
                    let mut symbol = screen
                        .cell(cursor_row, cursor_col)
                        .map(|cell| cell.contents())
                        .unwrap_or_else(|| " ".to_string());
                    if symbol.is_empty() {
                        symbol.push(' ');
                    }
                    if let Some(buf_cell) = buffer.cell_mut((gx, gy)) {
                        buf_cell
                            .set_symbol(symbol.as_str())
                            .set_style(base_style.add_modifier(Modifier::REVERSED));
                    }
                }
            }
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

pub(crate) fn draw_agent_panel(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let agents = app.agent_registry.all();

    if agents.is_empty() {
        let msg = Paragraph::new(
            "No agents registered.\n\n\
             Agents are discovered automatically when Claude Code or Codex\n\
             processes are running (via their lockfiles), or can be connected\n\
             manually with `atem agent connect <url>`.\n\n\
             Press 'r' to refresh, 'b' to go back.",
        )
        .style(Style::default().fg(Color::DarkGray))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" \u{1f916} Agent Panel — No Agents ")
                .border_style(Style::default().fg(Color::Yellow)),
        )
        .wrap(Wrap { trim: false });
        frame.render_widget(msg, area);
        return;
    }

    let items: Vec<ListItem> = agents
        .iter()
        .enumerate()
        .map(|(i, info)| {
            let is_selected = i == app.agent_panel_selected;
            let is_active = app.active_agent_id.as_deref() == Some(info.id.as_str());

            let protocol_badge = match info.protocol {
                AgentProtocol::Acp => "[ACP]",
                AgentProtocol::Pty => "[PTY]",
            };

            let status_icon = match info.status {
                AgentStatus::Idle => "\u{26aa}",            // grey circle
                AgentStatus::Thinking => "\u{1f7e1}",       // yellow circle
                AgentStatus::WaitingForInput => "\u{1f7e2}", // green circle
                AgentStatus::Disconnected => "\u{1f534}",   // red circle
            };

            let active_marker = if is_active { " \u{2605}" } else { "" }; // ★

            let kind_label = format!("{:?}", info.kind);
            let sessions = info.session_ids.len();
            let session_info = if sessions > 0 {
                format!(" ({} session{})", sessions, if sessions == 1 { "" } else { "s" })
            } else {
                String::new()
            };

            let line = format!(
                "{} {} {} {}{}{} — {}",
                status_icon,
                protocol_badge,
                kind_label,
                info.id,
                active_marker,
                session_info,
                info.acp_url.as_deref().unwrap_or("pty"),
            );

            let style = if is_selected {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else if is_active {
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            ListItem::new(line).style(style)
        })
        .collect();

    let active_label = app
        .active_agent_id
        .as_deref()
        .unwrap_or("none");
    let title = format!(" \u{1f916} Agent Panel — {} agents | active: {} ", agents.len(), active_label);

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(Color::Green)),
        )
        .highlight_style(Style::default().add_modifier(Modifier::BOLD));

    frame.render_widget(list, area);
}

pub(crate) fn style_from_cell(cell: &VtCell) -> Style {
    let mut fg = vt_color_to_tui(cell.fgcolor());
    let mut bg = vt_color_to_tui(cell.bgcolor());
    if cell.inverse() {
        std::mem::swap(&mut fg, &mut bg);
    }

    let mut style = Style::default();
    if fg != Color::Reset {
        style = style.fg(fg);
    }
    if bg != Color::Reset {
        style = style.bg(bg);
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

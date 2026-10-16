mod clipboard;
pub mod draw;
pub mod terminal_view;
pub mod voice_fx;

use anyhow::Result;
use crossterm::{
    event::{
        self, DisableBracketedPaste, EnableBracketedPaste, Event, KeyCode, KeyEventKind,
        KeyModifiers,
    },
    execute,
    terminal::{EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode},
};
use ratatui::{Terminal, backend::CrosstermBackend};
use std::io::{self, Stdout};
use tokio::time::Duration;

use crate::agora_api::format_projects;
use crate::app::{App, AppMode, MenuAction};
use crate::session::{Provider, Session};
use draw::draw_ui;

pub async fn run_tui() -> Result<()> {
    run_agent_tui(None, &[]).await
}

struct TerminalGuard;

impl TerminalGuard {
    fn enter() -> Result<Self> {
        enable_raw_mode()?;
        let guard = Self;
        execute!(io::stdout(), EnterAlternateScreen, EnableBracketedPaste)?;
        Ok(guard)
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(
            io::stdout(),
            LeaveAlternateScreen,
            DisableBracketedPaste,
            crossterm::cursor::Show
        );
    }
}

pub async fn run_agent_tui(agent: Option<&str>, agent_args: &[String]) -> Result<()> {
    let diagnostics = crate::diagnostics::Capture::start();
    let _guard = TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;
    let mut app = App::new();
    let provider = match agent {
        Some("codex") => Some(Provider::Codex),
        Some("claude") | Some("claude-code") => Some(Provider::Claude),
        Some(_) => anyhow::bail!("Expected claude, claude-code or codex"),
        None => None,
    };
    if let Some(provider) = provider {
        // Kept on the client, so a relaunch from the menu gets them too.
        match provider {
            Provider::Codex => app.codex_client.append_launch_args(agent_args),
            Provider::Claude => app.claude_client.append_launch_args(agent_args),
        }
        sync_terminal_sizes(&mut app, terminal.size()?);
        let (rows, cols) = app.launch_size();
        let request = crate::session::LaunchRequest::here(provider, Vec::new(), rows, cols);
        let id = app.launch_session(request).await?;
        app.focus_session(&id);
    }
    terminal.clear()?;
    run_tui_loop(&mut terminal, &mut app, &diagnostics).await
}

fn sync_terminal_sizes(app: &mut App, size: ratatui::layout::Size) {
    let rows = size.height.saturating_sub(1).clamp(2, 200);
    let cols = size.width.clamp(2, 400);
    app.terminal_ui.viewport = (rows, cols);
    // The focused session follows the local viewport.
    if let Some(id) = app.focused.clone().filter(|id| app.is_focused(id)) {
        app.adjust_terminal_size(&id, rows, cols);
    }
}

/// The session local keys go to: the focused one, else the latest Claude one.
fn key_target(app: &App) -> Option<&Session> {
    app.focused_session().or_else(|| {
        let id = app.sessions.latest(Provider::Claude)?;
        app.sessions.get(&id)
    })
}

fn send_agent(app: &mut App, bytes: &str) {
    if let Some(id) = key_target(app).map(|s| s.id.clone()) {
        app.send_data(&id, bytes);
    }
}

async fn copy_terminal(app: &mut App) {
    let text = if let Some(view) = &app.terminal_ui.browse {
        view.text()
    } else {
        key_target(app).map_or_else(String::new, |s| {
            terminal_view::visible_text(s.terminal.screen(), app.terminal_ui.viewport)
        })
    };
    match clipboard::copy(&text).await {
        Ok(message) => {
            app.terminal_ui.browse = None;
            app.status_message = Some(message.into());
        }
        Err(error) => app.status_message = Some(error.to_string()),
    }
    if let Some(message) = &app.status_message {
        app.terminal_ui.feedback = Some((message.clone(), std::time::Instant::now()));
    }
}

async fn handle_terminal_key(app: &mut App, key: crossterm::event::KeyEvent) {
    use terminal_view::Action;
    if app.terminal_ui.help {
        match key.code {
            KeyCode::Esc | KeyCode::Enter => app.terminal_ui.help = false,
            KeyCode::Up => {
                app.terminal_ui.help_scroll = app.terminal_ui.help_scroll.saturating_sub(1)
            }
            KeyCode::Down => {
                app.terminal_ui.help_scroll = app.terminal_ui.help_scroll.saturating_add(1)
            }
            KeyCode::PageUp => {
                app.terminal_ui.help_scroll = app.terminal_ui.help_scroll.saturating_sub(10)
            }
            KeyCode::PageDown => {
                app.terminal_ui.help_scroll = app.terminal_ui.help_scroll.saturating_add(10)
            }
            _ => {}
        }
        return;
    }
    let action = app.terminal_ui.key(key);
    match action {
        Action::Prefix | Action::Cancel => {}
        Action::Hide => app.leave_terminal_view(),
        Action::Take => app.reclaim_terminal(),
        Action::Stop => app.stop_terminal(),
        Action::Redraw => app.force_terminal_redraw = true,
        Action::Help => {
            app.terminal_ui.help = true;
            app.terminal_ui.help_scroll = 0;
        }
        Action::Browse => app.browse_terminal(0),
        Action::Copy => copy_terminal(app).await,
        Action::SendPrefix => send_agent(app, &app.terminal_ui.prefix.bytes()),
        Action::Agent(key) if app.terminal_ui.browse.is_some() => {
            let view = app.terminal_ui.browse.as_mut().unwrap();
            let (rows, cols) = view.viewport;
            let offset = view.offset;
            match key.code {
                KeyCode::Esc => app.terminal_ui.browse = None,
                KeyCode::Enter => copy_terminal(app).await,
                KeyCode::PageUp => {
                    app.browse_terminal(offset.saturating_add(usize::from(rows.saturating_sub(1))))
                }
                KeyCode::PageDown => {
                    app.browse_terminal(offset.saturating_sub(usize::from(rows.saturating_sub(1))))
                }
                KeyCode::Up => view.cursor.0 = view.cursor.0.saturating_sub(1),
                KeyCode::Down => view.cursor.0 = (view.cursor.0 + 1).min(rows - 1),
                KeyCode::Left => view.cursor.1 = view.cursor.1.saturating_sub(1),
                KeyCode::Right => view.cursor.1 = (view.cursor.1 + 1).min(cols - 1),
                KeyCode::Home => view.cursor.1 = 0,
                KeyCode::End => view.cursor.1 = cols - 1,
                KeyCode::Char(' ') => {
                    view.anchor = if view.anchor.is_some() {
                        None
                    } else {
                        Some(view.cursor)
                    }
                }
                _ => {}
            }
        }
        Action::Agent(key) | Action::AgentWithPrefix(key) => {
            let application_cursor =
                key_target(app).is_some_and(|s| s.terminal.screen().application_cursor());
            if let Some(bytes) = crate::terminal_keys::encode(key, application_cursor) {
                let bytes = if matches!(action, Action::AgentWithPrefix(_)) {
                    app.terminal_ui.prefix.bytes() + &bytes
                } else {
                    bytes
                };
                send_agent(app, &bytes);
            }
        }
    }
}

async fn run_tui_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    diagnostics: &crate::diagnostics::Capture,
) -> Result<()> {
    sync_terminal_sizes(app, terminal.size()?);
    terminal.draw(|frame| draw_ui(frame, app))?;

    // Kick off Astation connection in the background — won't block the UI.
    app.spawn_astation_connect();

    loop {
        terminal.autoresize()?;
        for message in diagnostics.drain() {
            app.terminal_ui.record(message);
        }
        app.tick_host().await;
        // After the host drained the old geometry's bytes, follow the local viewport.
        sync_terminal_sizes(app, terminal.size()?);

        if app.force_terminal_redraw {
            terminal.clear()?;
            app.force_terminal_redraw = false;
        }

        app.terminal_ui.observe_status(&app.status_message);
        terminal.draw(|f| draw_ui(f, app))?;

        if event::poll(Duration::from_millis(16))? {
            let event = event::read()?;
            if let Event::Resize(_, _) = &event {
                app.terminal_ui.reset_view();
                app.force_terminal_redraw = true;
            }
            if let Event::Paste(text) = &event {
                if app.terminal_ui.help {
                    app.status_message = Some("Close help before pasting into the agent".into());
                } else {
                    app.terminal_ui.browse = None;
                    if app.terminal_ui.pending {
                        app.terminal_ui.pending = false;
                        send_agent(app, &app.terminal_ui.prefix.bytes());
                    }
                    app.terminal_paste(text);
                }
            }
            if let Event::Key(key) = event {
                if key.kind != KeyEventKind::Release {
                    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

                    if matches!(app.mode, AppMode::Terminal) {
                        handle_terminal_key(app, key).await;
                        continue;
                    }

                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') if !ctrl => return Ok(()),
                        KeyCode::Char('b') | KeyCode::Char('B') if !ctrl => {
                            app.mode = AppMode::MainMenu;
                            app.show_popup = false;
                            app.output_text.clear();
                            app.input_text.clear();
                        }
                        _ => {
                            if app.show_popup {
                                app.show_popup = false;
                                continue;
                            }

                            match app.mode {
                                AppMode::AgentPanel => match key.code {
                                    KeyCode::Down | KeyCode::Char('j') => {
                                        let count = app.agent_registry.all().len();
                                        if count > 0 {
                                            app.agent_panel_selected =
                                                (app.agent_panel_selected + 1) % count;
                                        }
                                    }
                                    KeyCode::Up | KeyCode::Char('k') => {
                                        let count = app.agent_registry.all().len();
                                        if count > 0 {
                                            app.agent_panel_selected =
                                                if app.agent_panel_selected == 0 {
                                                    count - 1
                                                } else {
                                                    app.agent_panel_selected - 1
                                                };
                                        }
                                    }
                                    KeyCode::Enter => {
                                        let agents = app.agent_registry.all();
                                        if let Some(info) = agents.get(app.agent_panel_selected) {
                                            let id = info.id.clone();
                                            app.active_agent_id = Some(id.clone());
                                            app.status_message =
                                                Some(format!("Active agent: {}", id));
                                        }
                                    }
                                    _ => {}
                                },
                                AppMode::MainMenu => match key.code {
                                    KeyCode::Down | KeyCode::Char('j') => app.next_item(),
                                    KeyCode::Up | KeyCode::Char('k') => app.previous_item(),
                                    KeyCode::Enter => {
                                        if app.menu_actions.get(app.selected_index)
                                            == Some(&MenuAction::Exit)
                                        {
                                            return Ok(());
                                        }
                                        app.handle_selection().await?;
                                    }
                                    _ => {}
                                },
                                AppMode::CommandExecution => match key.code {
                                    KeyCode::Enter => {
                                        if !app.input_text.is_empty() {
                                            let cmd = app.input_text.clone();
                                            app.input_text.clear();
                                            app.execute_command(&cmd).await?;
                                        }
                                    }
                                    KeyCode::Backspace => {
                                        app.input_text.pop();
                                    }
                                    KeyCode::Char(c) if !ctrl => {
                                        app.input_text.push(c);
                                    }
                                    _ => {}
                                },
                                AppMode::TokenGeneration => match key.code {
                                    KeyCode::Char('s') | KeyCode::Char('S') if !ctrl => {
                                        if !app.cached_projects.is_empty() {
                                            app.show_certificates = !app.show_certificates;
                                            let info = format_projects(
                                                &app.cached_projects,
                                                app.show_certificates,
                                            );
                                            app.output_text = format!("Agora Projects\n\n{}", info);
                                        }
                                    }
                                    _ => {}
                                },
                                _ => {}
                            }
                        }
                    }
                }
            }
        }
    }
}

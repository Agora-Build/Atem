mod clipboard;
pub mod draw;
pub mod frontend;
pub mod terminal_view;

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
use std::time::Instant;
use tokio::time::Duration;

use crate::agora_api::format_projects;
use crate::app::{App, AppMode, MenuAction};
use crate::runtime::client::RuntimeClient;
use draw::draw_ui;

/// How often the menu asks the runtime for its sessions.
const RUNTIME_REFRESH: Duration = Duration::from_secs(3);

/// Bare `atem`: the menu. Its agent entries launch and attach sessions
/// through `atem runtime`; the menu itself opens no Astation connection.
pub async fn run_tui() -> Result<()> {
    let diagnostics = crate::diagnostics::Capture::start();
    let _guard = TerminalGuard::enter()?;
    let backend = CrosstermBackend::new(io::stdout());
    let mut terminal = Terminal::new(backend)?;
    let mut app = App::new();
    terminal.clear()?;
    run_tui_loop(&mut terminal, &mut app, &diagnostics).await
}

pub(crate) struct TerminalGuard;

impl TerminalGuard {
    pub(crate) fn enter() -> Result<Self> {
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

/// The runtime's sessions and Astation link for the menu, when a runtime
/// answers (the menu never starts one just to look).
async fn refresh_runtime(app: &mut App) {
    match RuntimeClient::existing().await {
        Ok(Some(mut client)) => match crate::runtime::commands::sessions(&mut client).await {
            Ok(sessions) => {
                app.astation_connected = client.welcome.astation;
                app.runtime_sessions = sessions;
                app.runtime_note = None;
            }
            Err(error) => app.runtime_note = Some(format!("The atem runtime didn't list its sessions: {error:#}")),
        },
        Ok(None) => {
            app.astation_connected = false;
            app.runtime_sessions.clear();
            app.runtime_note = Some("No atem runtime is running; launching an agent starts one.".into());
        }
        Err(error) => {
            app.astation_connected = false;
            app.runtime_sessions.clear();
            app.runtime_note = Some(format!("The atem runtime can't be reached: {error:#}"));
        }
    }
    if app.agent_panel_selected >= app.runtime_sessions.len() {
        app.agent_panel_selected = app.runtime_sessions.len().saturating_sub(1);
    }
    app.rebuild_menu();
}

/// Launches `provider` (or attaches to `attach`) through the runtime and
/// runs the frontend in the menu's terminal until it ends.
async fn open_session(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    diagnostics: &crate::diagnostics::Capture,
    provider: Option<&str>,
    attach: Option<String>,
) {
    let opened = async {
        let mut client = RuntimeClient::connect_or_start().await?;
        let sid = match (provider, attach) {
            (_, Some(sid)) => sid,
            (Some(provider), None) => {
                let size = frontend::viewport_size(terminal.size()?);
                crate::runtime::commands::launch_session(&mut client, provider, Vec::new(), size)
                    .await?
                    .id
            }
            (None, None) => anyhow::bail!("Nothing to open"),
        };
        let exit = frontend::attach_in(terminal, client, &sid, diagnostics).await?;
        anyhow::Ok(exit.message(&sid))
    }
    .await;
    app.status_message = Some(match opened {
        Ok(message) => message,
        Err(error) => format!("\u{274c} {error:#}"),
    });
    let _ = terminal.clear();
    refresh_runtime(app).await;
}

async fn run_tui_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    diagnostics: &crate::diagnostics::Capture,
) -> Result<()> {
    refresh_runtime(app).await;
    let mut refreshed = Instant::now();
    loop {
        terminal.autoresize()?;
        for message in diagnostics.drain() {
            app.status_message = Some(message);
        }
        if refreshed.elapsed() >= RUNTIME_REFRESH
            && matches!(app.mode, AppMode::MainMenu | AppMode::AgentPanel)
        {
            refresh_runtime(app).await;
            refreshed = Instant::now();
        }

        if app.force_terminal_redraw {
            terminal.clear()?;
            app.force_terminal_redraw = false;
        }

        terminal.draw(|f| draw_ui(f, app))?;

        if event::poll(Duration::from_millis(16))? {
            let event = event::read()?;
            if let Event::Resize(_, _) = &event {
                app.force_terminal_redraw = true;
            }
            if let Event::Paste(text) = &event
                && matches!(app.mode, AppMode::CommandExecution)
            {
                app.input_text.push_str(text);
            }
            if let Event::Key(key) = event {
                if key.kind != KeyEventKind::Release {
                    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

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
                                        let count = app.runtime_sessions.len();
                                        if count > 0 {
                                            app.agent_panel_selected =
                                                (app.agent_panel_selected + 1) % count;
                                        }
                                    }
                                    KeyCode::Up | KeyCode::Char('k') => {
                                        let count = app.runtime_sessions.len();
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
                                        let selected = app
                                            .runtime_sessions
                                            .get(app.agent_panel_selected)
                                            .map(|s| s.id.clone());
                                        if let Some(sid) = selected {
                                            open_session(terminal, app, diagnostics, None, Some(sid))
                                                .await;
                                        }
                                    }
                                    KeyCode::Char('r') if !ctrl => {
                                        refresh_runtime(app).await;
                                        refreshed = Instant::now();
                                    }
                                    _ => {}
                                },
                                AppMode::MainMenu => match key.code {
                                    KeyCode::Down | KeyCode::Char('j') => app.next_item(),
                                    KeyCode::Up | KeyCode::Char('k') => app.previous_item(),
                                    KeyCode::Enter => {
                                        match app.menu_actions.get(app.selected_index).copied() {
                                            Some(MenuAction::Exit) => return Ok(()),
                                            Some(MenuAction::LaunchClaude) => {
                                                open_session(terminal, app, diagnostics, Some("claude"), None)
                                                    .await;
                                            }
                                            Some(MenuAction::LaunchCodex) => {
                                                open_session(terminal, app, diagnostics, Some("codex"), None)
                                                    .await;
                                            }
                                            Some(MenuAction::AgentPanel) => {
                                                app.handle_selection().await?;
                                                refresh_runtime(app).await;
                                                refreshed = Instant::now();
                                            }
                                            _ => app.handle_selection().await?,
                                        }
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
                            }
                        }
                    }
                }
            }
        }
    }
}

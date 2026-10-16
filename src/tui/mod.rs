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
use crate::runtime::protocol::SessionSummary;
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

/// How long the menu waits for the runtime's answer.
const LOOK_WAIT: Duration = Duration::from_secs(2);

/// What the menu learned from the runtime: its Astation link and sessions,
/// `None` when none runs, or why it couldn't be asked.
type Look = Result<Option<(bool, Vec<SessionSummary>)>, String>;

/// Asks the runtime at `locator` for its sessions as a passive client (it
/// never keeps the runtime running, and none is started), within `wait`.
async fn look_at(locator: crate::runtime::client::Locator, wait: Duration) -> Look {
    let looked = tokio::time::timeout(wait, async {
        match RuntimeClient::existing_at(&locator, true).await {
            Ok(Some(mut client)) => crate::runtime::commands::sessions(&mut client)
                .await
                .map(|sessions| Some((client.welcome.astation, sessions)))
                .map_err(|e| format!("The atem runtime didn't list its sessions: {e:#}")),
            Ok(None) => Ok(None),
            Err(error) => Err(format!("The atem runtime can't be reached: {error:#}")),
        }
    })
    .await;
    looked.unwrap_or_else(|_| Err("The atem runtime didn't answer".into()))
}

fn apply_look(app: &mut App, look: Look) {
    match look {
        Ok(Some((astation, sessions))) => {
            app.astation_connected = astation;
            app.runtime_sessions = sessions;
            app.runtime_note = None;
        }
        Ok(None) => {
            app.astation_connected = false;
            app.runtime_sessions.clear();
            app.runtime_note =
                Some("No atem runtime is running; launching an agent starts one.".into());
        }
        Err(note) => {
            app.astation_connected = false;
            app.runtime_sessions.clear();
            app.runtime_note = Some(note);
        }
    }
    if app.agent_panel_selected >= app.runtime_sessions.len() {
        app.agent_panel_selected = app.runtime_sessions.len().saturating_sub(1);
    }
    app.rebuild_menu();
}

/// The menu's looks at the runtime, on their own task so the UI loop never
/// waits for them: one at a time, every `RUNTIME_REFRESH` while the menu
/// shows, and at once when asked.
#[derive(Default)]
struct Looks {
    task: Option<tokio::task::JoinHandle<Look>>,
    last: Option<Instant>,
    due: bool,
}

impl Looks {
    fn request(&mut self) {
        self.due = true;
    }

    fn poll(&mut self, app: &mut App) {
        use futures_util::FutureExt;
        if self.task.as_ref().is_some_and(|t| t.is_finished())
            && let Some(Ok(look)) = self.task.take().and_then(|t| t.now_or_never())
        {
            apply_look(app, look);
        }
        let shown = matches!(app.mode, AppMode::MainMenu | AppMode::AgentPanel);
        let stale = self.last.is_none_or(|at| at.elapsed() >= RUNTIME_REFRESH);
        if self.task.is_none() && (self.due || (shown && stale)) {
            self.due = false;
            self.last = Some(Instant::now());
            let locator = crate::runtime::client::Locator::default_paths();
            self.task = Some(tokio::spawn(look_at(locator, LOOK_WAIT)));
        }
    }
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
}

async fn run_tui_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    diagnostics: &crate::diagnostics::Capture,
) -> Result<()> {
    let mut looks = Looks::default();
    loop {
        terminal.autoresize()?;
        for message in diagnostics.drain() {
            app.status_message = Some(message);
        }
        looks.poll(app);

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
                                            looks.request();
                                        }
                                    }
                                    KeyCode::Char('r') if !ctrl => {
                                        looks.request();
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
                                                looks.request();
                                            }
                                            Some(MenuAction::LaunchCodex) => {
                                                open_session(terminal, app, diagnostics, Some("codex"), None)
                                                    .await;
                                                looks.request();
                                            }
                                            Some(MenuAction::AgentPanel) => {
                                                app.handle_selection().await?;
                                                looks.request();
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_look_at_a_runtime_that_never_answers_ends_within_its_wait() {
        let _profile = crate::test_profile::temp();
        let dir = tempfile::Builder::new()
            .prefix("atem-look")
            .tempdir_in("/tmp")
            .unwrap();
        let socket = dir.path().join("rt.sock");
        // Accepts connections (the backlog) but never answers a hello.
        let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
        let locator = crate::runtime::client::Locator {
            socket: socket.clone(),
            record: dir.path().join("none"),
            log: dir.path().join("log"),
        };
        let started = Instant::now();
        let look = look_at(locator, Duration::from_millis(300)).await;
        assert!(started.elapsed() < Duration::from_secs(2));
        assert_eq!(look, Err("The atem runtime didn't answer".to_string()));
        let mut app = App::new();
        apply_look(&mut app, look);
        assert_eq!(app.runtime_note.as_deref(), Some("The atem runtime didn't answer"));
        assert!(!app.astation_connected && app.runtime_sessions.is_empty());
    }

    #[tokio::test]
    async fn without_a_runtime_the_menu_says_launching_starts_one() {
        let dir = tempfile::tempdir().unwrap();
        let locator = crate::runtime::client::Locator {
            socket: dir.path().join("rt.sock"),
            record: dir.path().join("none"),
            log: dir.path().join("log"),
        };
        let look = look_at(locator, Duration::from_secs(2)).await;
        assert_eq!(look, Ok(None));
    }
}

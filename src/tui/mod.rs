pub mod draw;
pub mod voice_fx;

use anyhow::Result;
use crossterm::{
    event::{
        self, Event, KeyCode, KeyEventKind, KeyModifiers,
    },
    execute,
    terminal::{
        EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode,
        enable_raw_mode,
    },
};
use ratatui::{
    Terminal,
    backend::CrosstermBackend,
};
use std::io::{self, Stdout};
use tokio::time::Duration;

use crate::agora_api::format_projects;
use crate::app::{App, AppMode};
use draw::draw_ui;

pub async fn run_tui() -> Result<()> {
    // Interactive TUI mode
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    let result = run_tui_loop(&mut terminal, &mut app).await;

    // Cleanup
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;

    result
}

async fn run_tui_loop(terminal: &mut Terminal<CrosstermBackend<Stdout>>, app: &mut App) -> Result<()> {
    // Fast startup: scan lockfiles (no network), then render immediately.
    app.startup_scan_agents().await;

    // Kick off Astation connection in the background — won't block the UI.
    app.spawn_astation_connect();

    loop {
        // Check if background Astation connection has completed
        app.poll_astation_connect();

        // Process any pending Astation messages
        app.process_astation_messages().await;
        app.process_codex_output();
        app.process_claude_output();
        // Forward ACP agent events to Astation
        app.poll_acp_events().await;

        // Dispatcher: drain triage verdicts and try to send next task to main
        app.dispatcher.poll_triage_results();
        app.try_dispatch_main().await;

        // Dispatcher: collect completed background task results
        for result in app.dispatcher.poll_background_results() {
            let _ = app.astation_client
                .send_mark_result(&result.task_id, result.success, &result.output).await;
            app.work_items.remove(&result.task_id);
        }

        // Dispatcher: deferred finalize flag (set when Claude session ends mid-task)
        if app.dispatcher.take_main_needs_finalize() {
            app.finalize_mark_task(true).await;
        }
        if let Err(err) = app.process_rtm_messages().await {
            app.status_message = Some(format!("RTM processing error: {}", err));
        }

        if app.force_terminal_redraw {
            terminal.clear()?;
            app.force_terminal_redraw = false;
        }

        terminal.draw(|f| draw_ui(f, app))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    app.register_local_activity(true).await;
                    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

                    // In Codex mode, forward ALL keystrokes directly to
                    // Codex's PTY.  Only Ctrl+B escapes back to the menu.
                    if matches!(app.mode, AppMode::CodexChat) {
                        if ctrl && matches!(key.code, KeyCode::Char('b') | KeyCode::Char('B'))
                        {
                            app.finalize_codex_session();
                            continue;
                        }

                        let data: Option<String> = if ctrl {
                            match key.code {
                                KeyCode::Char(c) => {
                                    let byte =
                                        (c.to_ascii_lowercase() as u8).wrapping_sub(b'a' - 1);
                                    Some(String::from(byte as char))
                                }
                                _ => None,
                            }
                        } else {
                            match key.code {
                                KeyCode::Char(c) => Some(String::from(c)),
                                KeyCode::Enter => Some("\r".to_string()),
                                KeyCode::Backspace => Some("\x7f".to_string()),
                                KeyCode::Tab => Some("\t".to_string()),
                                KeyCode::Esc => Some("\x1b".to_string()),
                                KeyCode::Up => Some("\x1b[A".to_string()),
                                KeyCode::Down => Some("\x1b[B".to_string()),
                                KeyCode::Right => Some("\x1b[C".to_string()),
                                KeyCode::Left => Some("\x1b[D".to_string()),
                                KeyCode::Home => Some("\x1b[H".to_string()),
                                KeyCode::End => Some("\x1b[F".to_string()),
                                KeyCode::PageUp => Some("\x1b[5~".to_string()),
                                KeyCode::PageDown => Some("\x1b[6~".to_string()),
                                KeyCode::Delete => Some("\x1b[3~".to_string()),
                                KeyCode::Insert => Some("\x1b[2~".to_string()),
                                KeyCode::F(n) => Some(match n {
                                    1 => "\x1bOP".to_string(),
                                    2 => "\x1bOQ".to_string(),
                                    3 => "\x1bOR".to_string(),
                                    4 => "\x1bOS".to_string(),
                                    5 => "\x1b[15~".to_string(),
                                    6 => "\x1b[17~".to_string(),
                                    7 => "\x1b[18~".to_string(),
                                    8 => "\x1b[19~".to_string(),
                                    9 => "\x1b[20~".to_string(),
                                    10 => "\x1b[21~".to_string(),
                                    11 => "\x1b[23~".to_string(),
                                    12 => "\x1b[24~".to_string(),
                                    _ => format!("\x1b[{}~", n),
                                }),
                                _ => None,
                            }
                        };

                        if let Some(bytes) = data {
                            app.send_codex_data(&bytes);
                        }
                        continue;
                    }

                    // In Claude mode, forward ALL keystrokes directly to
                    // Claude Code's PTY.  Only Ctrl+B escapes back to the menu.
                    if matches!(app.mode, AppMode::ClaudeChat) {
                        if ctrl && matches!(key.code, KeyCode::Char('b') | KeyCode::Char('B'))
                        {
                            app.finalize_claude_session();
                            continue;
                        }

                        // Convert the key event to bytes and send to PTY.
                        let data: Option<String> = if ctrl {
                            match key.code {
                                KeyCode::Char(c) => {
                                    // Ctrl+A..Z -> 0x01..0x1A
                                    let byte =
                                        (c.to_ascii_lowercase() as u8).wrapping_sub(b'a' - 1);
                                    Some(String::from(byte as char))
                                }
                                _ => None,
                            }
                        } else {
                            match key.code {
                                KeyCode::Char(c) => Some(String::from(c)),
                                KeyCode::Enter => Some("\r".to_string()),
                                KeyCode::Backspace => Some("\x7f".to_string()),
                                KeyCode::Tab => Some("\t".to_string()),
                                KeyCode::Esc => Some("\x1b".to_string()),
                                KeyCode::Up => Some("\x1b[A".to_string()),
                                KeyCode::Down => Some("\x1b[B".to_string()),
                                KeyCode::Right => Some("\x1b[C".to_string()),
                                KeyCode::Left => Some("\x1b[D".to_string()),
                                KeyCode::Home => Some("\x1b[H".to_string()),
                                KeyCode::End => Some("\x1b[F".to_string()),
                                KeyCode::PageUp => Some("\x1b[5~".to_string()),
                                KeyCode::PageDown => Some("\x1b[6~".to_string()),
                                KeyCode::Delete => Some("\x1b[3~".to_string()),
                                KeyCode::Insert => Some("\x1b[2~".to_string()),
                                KeyCode::F(n) => Some(match n {
                                    1 => "\x1bOP".to_string(),
                                    2 => "\x1bOQ".to_string(),
                                    3 => "\x1bOR".to_string(),
                                    4 => "\x1bOS".to_string(),
                                    5 => "\x1b[15~".to_string(),
                                    6 => "\x1b[17~".to_string(),
                                    7 => "\x1b[18~".to_string(),
                                    8 => "\x1b[19~".to_string(),
                                    9 => "\x1b[20~".to_string(),
                                    10 => "\x1b[21~".to_string(),
                                    11 => "\x1b[23~".to_string(),
                                    12 => "\x1b[24~".to_string(),
                                    _ => format!("\x1b[{}~", n),
                                }),
                                _ => None,
                            }
                        };

                        if let Some(bytes) = data {
                            app.send_claude_data(&bytes);
                        }
                        continue;
                    }

                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') if !ctrl => return Ok(()),
                        // Handle credential save prompt (y/n)
                        KeyCode::Char('y') | KeyCode::Char('Y') if !ctrl && app.pending_credential_save.is_some() => {
                            if let Some((customer_id, customer_secret)) = app.pending_credential_save.take() {
                                let id_preview = customer_id[..4.min(customer_id.len())].to_string();
                                // Save to config file
                                let mut cfg = crate::config::AtemConfig::load().unwrap_or_default();
                                cfg.customer_id = Some(customer_id.clone());
                                cfg.customer_secret = Some(customer_secret.clone());
                                if let Err(e) = cfg.save_to_disk() {
                                    app.status_message = Some(format!("\u{26a0}\u{fe0f} Could not save credentials: {}", e));
                                } else {
                                    // Update in-memory config to reflect saved state
                                    app.config.customer_id = Some(customer_id);
                                    app.config.customer_secret = Some(customer_secret);
                                    // Clear synced credentials so banner shows "from config file"
                                    app.synced_customer_id = None;
                                    app.synced_customer_secret = None;
                                    app.status_message = Some(format!("\u{2705} Credentials saved ({}...)", id_preview));
                                    // Force redraw to update banner
                                    app.force_terminal_redraw = true;
                                }
                            }
                        }
                        KeyCode::Char('n') | KeyCode::Char('N') if !ctrl && app.pending_credential_save.is_some() => {
                            if let Some((customer_id, _)) = app.pending_credential_save.take() {
                                let id_preview = customer_id[..4.min(customer_id.len())].to_string();
                                app.status_message = Some(format!("\u{1f511} Using for session only ({}...)", id_preview));
                            }
                        }
                        KeyCode::Char('c') | KeyCode::Char('C')
                            if !ctrl
                                && !matches!(
                                    app.mode,
                                    AppMode::CommandExecution
                                ) =>
                        {
                            // Copy mode - just display content without leaving TUI
                            app.show_popup = true;

                            let content = match app.mode {
                                AppMode::MainMenu => {
                                    format!(
                                        "\u{1f680} ATEM - Agora.io AI CLI Tool\n\nMain Menu:\n{}",
                                        app.main_menu_items
                                            .iter()
                                            .enumerate()
                                            .map(|(i, item)| if i == app.selected_index {
                                                format!("  \u{2192} {}", item)
                                            } else {
                                                format!("    {}", item)
                                            })
                                            .collect::<Vec<_>>()
                                            .join("\n")
                                    )
                                }
                                _ => app.output_text.clone(),
                            };

                            app.popup_message = format!(
                                "\u{1f4cb} COPY MODE\n\
                                \u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\n\
                                {}\n\
                                \u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\u{2550}\n\
                                Content displayed above. Use Ctrl+Shift+C or right-click\n\
                                to copy from terminal. Press any key to close.",
                                if content.is_empty() {
                                    "No content to display".to_string()
                                } else {
                                    content
                                }
                            );
                        }
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
                                            app.agent_panel_selected = if app.agent_panel_selected == 0 {
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
                                            app.status_message = Some(format!("Active agent: {}", id));
                                        }
                                    }
                                    KeyCode::Char('r') | KeyCode::Char('R') if !ctrl => {
                                        // Refresh: rescan lockfiles
                                        app.startup_scan_agents().await;
                                        app.status_message = Some("Agent list refreshed".to_string());
                                    }
                                    _ => {}
                                },
                                AppMode::MainMenu => match key.code {
                                    KeyCode::Down | KeyCode::Char('j') => app.next_item(),
                                    KeyCode::Up | KeyCode::Char('k') => app.previous_item(),
                                    KeyCode::Enter => {
                                        if app.selected_index == 6 {
                                            // Exit
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
                                            let info = format_projects(&app.cached_projects, app.show_certificates);
                                            app.output_text = format!(
                                                "Agora Projects\n\n{}",
                                                info
                                            );
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

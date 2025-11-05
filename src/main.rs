use anyhow::Result;
use base64::{Engine as _, engine::general_purpose};
use clap::{Parser, Subcommand};
use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    },
    execute,
    terminal::{
        Clear as CtClear, ClearType, EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode,
        enable_raw_mode,
    },
};
use ratatui::{
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
};
use std::{
    fs,
    io::{self, Stdout, Write},
    path::PathBuf,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::mpsc::{UnboundedReceiver, UnboundedSender, error::TryRecvError},
    time::{Duration, sleep},
};
use uuid::Uuid;
use vt100::{Cell as VtCell, Color as VtColor, Parser as VtParser};

mod codex_client;
mod websocket_client;
use codex_client::{CodexClient, CodexResizeHandle};
use websocket_client::{AstationClient, AstationMessage};

#[derive(Parser)]
#[command(name = "atem")]
#[command(about = "Agora.io CLI tool with AI integration")]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Token {
        #[command(subcommand)]
        token_command: TokenCommands,
    },
}

#[derive(Subcommand)]
enum TokenCommands {
    Rtc {
        #[command(subcommand)]
        rtc_command: RtcCommands,
    },
}

#[derive(Subcommand)]
enum RtcCommands {
    Create,
}

#[derive(Debug, Clone)]
enum AppMode {
    MainMenu,
    TokenGeneration,
    ClaudeChat,
    CodexChat,
    CommandExecution,
}

#[derive(Debug, Clone)]
struct TokenInfo {
    token: String,
    channel: String,
    uid: String,
    expires_in: String,
}

struct App {
    mode: AppMode,
    selected_index: usize,
    main_menu_items: Vec<String>,
    output_text: String,
    input_text: String,
    show_popup: bool,
    popup_message: String,
    status_message: Option<String>,
    token_info: Option<TokenInfo>,
    astation_client: AstationClient,
    astation_connected: bool,
    codex_client: CodexClient,
    codex_output_log: String,
    codex_raw_log: String,
    codex_user_actions: Vec<String>,
    codex_log_file: Option<PathBuf>,
    codex_summary_file: Option<PathBuf>,
    codex_terminal: VtParser,
    codex_sender: Option<UnboundedSender<String>>,
    codex_receiver: Option<UnboundedReceiver<String>>,
    codex_waiting_exit: bool,
    codex_resize_handle: Option<CodexResizeHandle>,
    codex_view_rows: u16,
    codex_view_cols: u16,
    force_terminal_redraw: bool,
}

impl App {
    fn new() -> Self {
        Self {
            mode: AppMode::MainMenu,
            selected_index: 0,
            main_menu_items: vec![
                "📋 List Agora Projects".to_string(),
                "🤖 Launch Claude Code".to_string(),
                "🧠 Launch Codex".to_string(),
                "💻 Execute Shell Command".to_string(),
                "❓ Help".to_string(),
                "🚪 Exit".to_string(),
            ],
            output_text: String::new(),
            input_text: String::new(),
            show_popup: false,
            popup_message: String::new(),
            status_message: None,
            token_info: None,
            astation_client: AstationClient::new(),
            astation_connected: false,
            codex_client: CodexClient::new(),
            codex_output_log: String::new(),
            codex_raw_log: String::new(),
            codex_user_actions: Vec::new(),
            codex_log_file: None,
            codex_summary_file: None,
            codex_terminal: VtParser::new(200, 80, 0),
            codex_sender: None,
            codex_receiver: None,
            codex_waiting_exit: false,
            codex_resize_handle: None,
            codex_view_rows: 0,
            codex_view_cols: 0,
            force_terminal_redraw: false,
        }
    }

    fn next_item(&mut self) {
        if !self.main_menu_items.is_empty() {
            self.selected_index = (self.selected_index + 1) % self.main_menu_items.len();
        }
    }

    fn previous_item(&mut self) {
        if !self.main_menu_items.is_empty() {
            self.selected_index = if self.selected_index == 0 {
                self.main_menu_items.len() - 1
            } else {
                self.selected_index - 1
            };
        }
    }

    async fn handle_selection(&mut self) -> Result<()> {
        self.status_message = None;
        match self.selected_index {
            0 => {
                // List Agora Projects
                self.mode = AppMode::TokenGeneration; // Reusing this mode for project listing
                self.output_text = "📋 Fetching Agora Projects...\n\n".to_string();

                if self.astation_connected {
                    // Request projects from Astation
                    if let Err(e) = self.astation_client.request_projects().await {
                        self.output_text = format!(
                            "❌ Failed to request projects from Astation: {}\n\nPress 'b' to go back to main menu",
                            e
                        );
                    } else {
                        self.output_text = "📋 Requesting projects from Astation...\n\nPress 'b' to go back to main menu".to_string();
                    }
                } else {
                    match list_agora_projects().await {
                        Ok(projects_info) => {
                            self.output_text = format!(
                                "📋 Agora Projects List (Local Demo)\n\n\
                                {}\n\n\
                                💡 To generate RTC tokens, use:\n\
                                • Go to '💻 Execute Shell Command'\n\
                                • Run: atem token rtc create --channel <name> --uid <id>\n\n\
                                Press 'b' to go back to main menu",
                                projects_info
                            );
                        }
                        Err(_e) => {
                            self.output_text = format!(
                                "❌ Failed to fetch Agora projects (demo mode)\n\n\
                                💡 This is a demo - showing sample projects instead:\n\n\
                                🏢 Sample Projects:\n\
                                • Project A (ID: proj_001) - Live Streaming\n\
                                • Project B (ID: proj_002) - Video Calling\n\
                                • Project C (ID: proj_003) - Voice Chat\n\n\
                                💡 To generate RTC tokens, use:\n\
                                • Go to '💻 Execute Shell Command'\n\
                            • Run: atem token rtc create --channel <name> --uid <id>\n\n\
                            Press 'b' to go back to main menu"
                            );
                        }
                    }
                }
            }
            1 => {
                // Launch Claude Code
                self.mode = AppMode::ClaudeChat;
                self.output_text = "🤖 Launching Claude Code...\n\n⚠️  Your terminal will temporarily switch to Claude Code.\nReturn here when you exit Claude Code.\n\n🔄 Starting Claude Code...".to_string();

                if self.astation_connected {
                    // Request Claude launch through Astation
                    if let Err(e) = self.astation_client.launch_claude(None).await {
                        self.output_text = format!(
                            "❌ Failed to request Claude launch from Astation: {}\n\nPress 'b' to go back to main menu",
                            e
                        );
                    } else {
                        self.output_text = "🤖 Requesting Claude Code launch from Astation...\n\nPress 'b' to go back to main menu".to_string();
                    }
                } else {
                    // Launch Claude locally
                    match launch_claude_async().await {
                        Ok(output) => {
                            self.output_text = format!(
                                "🤖 Claude Code Session Result (Local):\n{}\n\nPress 'b' to go back to main menu",
                                output
                            );
                        }
                        Err(e) => {
                            self.output_text = format!(
                                "❌ Error launching Claude Code: {}\n\nPress 'b' to go back to main menu",
                                e
                            );
                        }
                    }
                }
            }
            2 => {
                // Launch Codex
                self.mode = AppMode::CodexChat;
                self.input_text.clear();
                self.codex_waiting_exit = false;
                if self.codex_output_log.is_empty() {
                    self.codex_output_log = "🧠 Codex CLI Session\n\n\
                        Atem routes your input to the Codex CLI and streams its replies back here.\n\
                        Type commands in the input box and press Enter to send them to Codex.\n\
                        Press Ctrl+C to end the Codex session and return to the main menu.\n\
                        After a session, press 'u' to save a summary report.\n"
                        .to_string();
                }

                match self.ensure_codex_session().await {
                    Ok(new_session_started) => {
                        if new_session_started {
                            self.record_codex_output("🔌 Codex CLI session started.\n");
                        }
                        self.refresh_codex_view();
                    }
                    Err(err) => {
                        self.record_codex_output(&format!(
                            "❌ Unable to start Codex CLI: {}\n",
                            err
                        ));
                        self.refresh_codex_view();
                    }
                }
            }
            3 => {
                // Execute Shell Command
                self.mode = AppMode::CommandExecution;
                self.output_text = "💻 Shell Command Mode\n\n\
                    📝 Example commands:\n\
                    • atem token rtc create  (generate RTC token)\n\
                    • export API_KEY=your_key  (set environment variables)\n\
                    • ls -la  (list files)\n\
                    • git status  (check git status)\n\
                    • claude  (launch Claude AI)\n\n\
                    Type your command and press Enter\n\
                    Press 'b' to go back to main menu"
                    .to_string();
                self.input_text.clear();
            }
            4 => {
                // Help
                self.show_help_popup();
            }
            5 => {
                // Exit - handled by caller
            }
            _ => {}
        }
        Ok(())
    }

    fn show_help_popup(&mut self) {
        self.show_popup = true;
        self.popup_message = "🚀 Atem - Agora.io AI CLI Tool\n\n\
            Navigation:\n\
            • ↑/↓ or j/k: Navigate menu\n\
            • Enter: Select item\n\
            • c: Copy mode (select/copy text)\n\
            • b: Go back\n\
            • q: Quit\n\n\
            Features:\n\
            • 📋 List Agora.io projects\n\
            • 🤖 Launch Claude Code\n\
            • 🧠 Send tasks to Codex\n\
            • 💻 Execute shell commands\n\
            • 🎯 Generate RTC tokens (via shell)\n\
            • Press 'u' in Codex view to save a session summary\n\n\
            Token Generation:\n\
            Use '💻 Execute Shell Command' and run:\n\
            atem token rtc create\n\n\
            Press any key to close this help"
            .to_string();
    }

    async fn execute_command(&mut self, command: &str) -> Result<()> {
        self.output_text = format!("Executing: {}\n\n", command);

        // Check if this is an interactive command that needs terminal access
        let interactive_commands = [
            "vi", "vim", "nano", "emacs", "less", "more", "man", "claude",
        ];
        let is_interactive = interactive_commands
            .iter()
            .any(|&cmd| command.trim().starts_with(cmd));

        if is_interactive {
            // Handle interactive commands by temporarily exiting TUI
            disable_raw_mode()?;
            execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture)?;

            let result = tokio::task::spawn_blocking({
                let cmd = command.to_string();
                move || -> Result<String> {
                    match Command::new("sh").arg("-c").arg(&cmd).status() {
                        Ok(status) => {
                            if status.success() {
                                Ok(format!("✅ Command '{}' completed successfully.", cmd))
                            } else {
                                Ok(format!("⚠️ Command '{}' exited with non-zero status.", cmd))
                            }
                        }
                        Err(e) => Ok(format!("❌ Error executing '{}': {}", cmd, e)),
                    }
                }
            })
            .await??;

            // Restore TUI state
            enable_raw_mode()?;
            execute!(io::stdout(), EnterAlternateScreen, EnableMouseCapture)?;

            self.output_text.push_str(&result);
        } else {
            // Handle non-interactive commands normally
            let output = tokio::task::spawn_blocking({
                let cmd = command.to_string();
                move || -> Result<String> {
                    let output = if cmd.starts_with("export ") {
                        // Handle export commands
                        if let Some(eq_pos) = cmd.find('=') {
                            let var_part = &cmd[7..eq_pos].trim();
                            let val_part = &cmd[eq_pos + 1..].trim();
                            unsafe {
                                std::env::set_var(var_part, val_part);
                            }
                            format!("✅ Environment variable set: {}={}", var_part, val_part)
                        } else {
                            "❌ Invalid export syntax".to_string()
                        }
                    } else {
                        // Execute regular command
                        match Command::new("sh").arg("-c").arg(&cmd).output() {
                            Ok(output) => {
                                let stdout = String::from_utf8_lossy(&output.stdout);
                                let stderr = String::from_utf8_lossy(&output.stderr);
                                format!("{}{}", stdout, stderr)
                            }
                            Err(e) => format!("❌ Error: {}", e),
                        }
                    };
                    Ok(output)
                }
            })
            .await??;

            self.output_text.push_str(&output);
        }

        self.output_text
            .push_str("\n\nPress 'b' to go back or type another command");
        Ok(())
    }

    async fn send_codex_prompt(&mut self, prompt: &str) -> Result<()> {
        let trimmed = prompt.trim();
        if trimmed.is_empty() {
            return Ok(());
        }
        if self.codex_waiting_exit {
            self.status_message =
                Some("Codex is shutting down. Please wait for the session to exit.".to_string());
            return Ok(());
        }

        let is_quit_cmd =
            trimmed.eq_ignore_ascii_case("quit") || trimmed.eq_ignore_ascii_case("exit");

        match self.ensure_codex_session().await {
            Ok(new_session_started) => {
                if new_session_started {
                    self.record_codex_output("🔌 Codex CLI session started.\n");
                }
            }
            Err(err) => {
                self.record_codex_output(&format!("❌ Unable to start Codex CLI: {}\n", err));
                self.refresh_codex_view();
                return Ok(());
            }
        }

        self.record_codex_output(&format!("> {}\n", trimmed));
        self.codex_user_actions.push(trimmed.to_string());

        if self.codex_sender.is_some() {
            self.send_codex_data(trimmed);

            // Split into a raw newline and a CR so Codex sees both.
            if self.codex_sender.is_some() {
                self.send_codex_data("\n");
            }
            if self.codex_sender.is_some() {
                self.send_codex_data("\r");
            }

            if self.codex_sender.is_none() {
                self.record_codex_output("⚠️ Codex CLI session is unavailable (send failed).\n");
                self.codex_receiver = None;
                self.codex_resize_handle = None;
                self.codex_waiting_exit = false;
            } else if is_quit_cmd {
                self.codex_waiting_exit = true;
                self.status_message = Some(
                    "Codex exit requested. Waiting for the session to shut down...".to_string(),
                );
            }
        } else {
            self.record_codex_output("⚠️ Codex CLI session is unavailable.\n");
        }

        self.refresh_codex_view();
        Ok(())
    }

    async fn ensure_codex_session(&mut self) -> Result<bool> {
        let needs_session = self.codex_sender.is_none() || self.codex_receiver.is_none();
        if !needs_session {
            return Ok(false);
        }

        let session = self.codex_client.start_session().await?;
        self.codex_sender = Some(session.sender);
        self.codex_receiver = Some(session.receiver);
        self.codex_resize_handle = Some(session.resize_handle);
        self.codex_raw_log.clear();
        self.codex_output_log.clear();
        self.codex_user_actions.clear();
        self.codex_log_file = None;
        self.codex_summary_file = None;
        let rows = if self.codex_view_rows == 0 {
            200
        } else {
            self.codex_view_rows
        };
        let cols = if self.codex_view_cols == 0 {
            80
        } else {
            self.codex_view_cols
        };
        self.codex_terminal = VtParser::new(rows, cols, 0);
        if let Some(handle) = &self.codex_resize_handle {
            if let Err(err) = handle.resize(rows, cols) {
                self.status_message = Some(format!("Failed to sync Codex terminal size: {}", err));
            }
        }
        self.codex_waiting_exit = false;
        Ok(true)
    }

    fn send_codex_interrupt(&mut self) {
        if !matches!(self.mode, AppMode::CodexChat) {
            return;
        }

        let Some(sender) = self.codex_sender.clone() else {
            self.record_codex_output("⚠️ Codex CLI session not available.\n");
            self.refresh_codex_view();
            return;
        };

        if sender.send("\u{3}".to_string()).is_err() {
            self.record_codex_output("⚠️ Codex CLI session is unavailable (interrupt failed).\n");
            self.codex_sender = None;
            self.codex_receiver = None;
            self.codex_resize_handle = None;
            self.codex_waiting_exit = false;
        } else {
            self.record_codex_output("^C\n");
            self.codex_waiting_exit = true;
            self.status_message =
                Some("Sent Ctrl+C to Codex. Waiting for the session to exit...".to_string());
        }

        self.refresh_codex_view();
    }

    fn record_codex_output(&mut self, data: impl AsRef<str>) {
        let text = data.as_ref();
        self.codex_raw_log.push_str(text);

        self.codex_terminal.process(text.as_bytes());
        self.update_codex_output_from_terminal();
    }

    fn update_codex_output_from_terminal(&mut self) {
        let screen = self.codex_terminal.screen();
        let (_rows, cols) = screen.size();

        let mut lines: Vec<String> = screen
            .rows(0, cols)
            .map(|line| line.replace('\u{0000}', ""))
            .collect();

        while lines.last().map_or(false, |line| line.trim().is_empty()) {
            lines.pop();
        }

        self.codex_output_log = lines.join("\n");
        if matches!(self.mode, AppMode::CodexChat) {
            self.output_text = self.codex_output_log.clone();
        }
    }

    fn send_codex_data(&mut self, data: &str) {
        let Some(sender) = self.codex_sender.clone() else {
            return;
        };
        if sender.send(data.to_string()).is_err() {
            self.codex_sender = None;
            self.codex_receiver = None;
            self.codex_resize_handle = None;
            self.codex_waiting_exit = false;
        }
    }

    fn enter_codex_copy_mode(&mut self) -> Result<()> {
        if !matches!(self.mode, AppMode::CodexChat) {
            return Ok(());
        }

        disable_raw_mode()?;
        execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture)?;

        let result = (|| -> Result<()> {
            println!("📋 Codex Output (copy with your terminal selection)\n");
            if self.codex_output_log.is_empty() {
                println!("(No Codex output yet.)");
            } else {
                println!("{}", self.codex_output_log);
            }
            println!("\nPress Enter to return to Atem...");
            io::stdout().flush()?;
            let mut buffer = String::new();
            std::io::stdin().read_line(&mut buffer)?;
            Ok(())
        })();

        enable_raw_mode()?;
        execute!(
            io::stdout(),
            EnterAlternateScreen,
            EnableMouseCapture,
            CtClear(ClearType::All)
        )?;

        match result {
            Ok(()) => {
                self.rebuild_codex_terminal();
                self.status_message = Some(
                    "Copy mode closed. Use Codex panel Enter to send new commands.".to_string(),
                );
                self.force_terminal_redraw = true;
                self.refresh_codex_view();
                Ok(())
            }
            Err(err) => {
                self.rebuild_codex_terminal();
                self.status_message = Some(format!("Copy mode error: {}", err));
                self.force_terminal_redraw = true;
                self.refresh_codex_view();
                Err(err)
            }
        }
    }

    fn respond_codex_cursor_position(&mut self) {
        let (row, col) = self.codex_terminal.screen().cursor_position();
        let response = format!("\u{1b}[{};{}R", row + 1, col + 1);
        self.send_codex_data(&response);
    }

    fn handle_codex_control_sequences(&mut self, chunk: &str) {
        if chunk.contains("\u{1b}[6n") {
            // Device Status Report - cursor position
            let occurrences = chunk.matches("\u{1b}[6n").count();
            for _ in 0..occurrences {
                self.respond_codex_cursor_position();
            }
        }
        if chunk.contains("\u{1b}[5n") {
            // Status report request - respond OK
            let occurrences = chunk.matches("\u{1b}[5n").count();
            for _ in 0..occurrences {
                self.send_codex_data("\u{1b}[0n");
            }
        }
    }

    fn refresh_codex_view(&mut self) {
        if matches!(self.mode, AppMode::CodexChat) {
            self.output_text = self.codex_output_log.clone();
        }
    }

    fn rebuild_codex_terminal(&mut self) {
        let rows = if self.codex_view_rows > 0 {
            self.codex_view_rows
        } else {
            200
        };
        let cols = if self.codex_view_cols > 0 {
            self.codex_view_cols
        } else {
            80
        };

        self.codex_terminal = VtParser::new(rows, cols, 0);
        if !self.codex_raw_log.is_empty() {
            self.codex_terminal.process(self.codex_raw_log.as_bytes());
        }
        self.update_codex_output_from_terminal();
    }

    fn adjust_codex_terminal_size(&mut self, rows: u16, cols: u16) {
        if rows == 0 || cols == 0 {
            return;
        }
        if self.codex_view_rows == rows && self.codex_view_cols == cols {
            return;
        }

        self.codex_view_rows = rows;
        self.codex_view_cols = cols;
        self.rebuild_codex_terminal();

        if let Some(handle) = &self.codex_resize_handle {
            if let Err(err) = handle.resize(rows, cols) {
                self.status_message = Some(format!("Failed to resize Codex terminal: {}", err));
            }
        }
    }

    fn process_codex_output(&mut self) {
        let mut new_chunks: Vec<String> = Vec::new();
        let mut disconnected = false;

        if let Some(receiver) = &mut self.codex_receiver {
            loop {
                match receiver.try_recv() {
                    Ok(line) => new_chunks.push(line),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        disconnected = true;
                        break;
                    }
                }
            }
        }

        if disconnected {
            new_chunks.push("⚠️ Codex CLI session disconnected.\n".to_string());
        }

        let exit_detected = new_chunks.iter().any(|chunk| {
            chunk.contains("Codex CLI exited with status") || chunk.contains("Codex CLI wait error")
        });

        if !new_chunks.is_empty() {
            for chunk in &new_chunks {
                self.record_codex_output(chunk);
                self.handle_codex_control_sequences(chunk);
            }

            if !(disconnected || exit_detected) {
                self.refresh_codex_view();
            }
        }

        if disconnected || exit_detected {
            self.finalize_codex_session();
        }
    }

    fn finalize_codex_session(&mut self) {
        if !matches!(self.mode, AppMode::CodexChat) {
            return;
        }

        let had_activity_before_finalize = !self.codex_raw_log.trim().is_empty();

        self.record_codex_output("⚙️ Codex CLI session ended.\n");

        let mut status_parts: Vec<String> = Vec::new();

        if had_activity_before_finalize {
            match self.persist_codex_log() {
                Ok(Some(path)) => {
                    let msg = format!("📝 Codex log saved to {}", path.display());
                    self.record_codex_output(&format!("{}\n", msg));
                    status_parts.push(msg);
                }
                Ok(None) => {
                    status_parts.push("Codex session ended with no output to save.".to_string());
                }
                Err(err) => {
                    let msg = format!("⚠️ Failed to save Codex log: {}", err);
                    self.record_codex_output(&format!("{}\n", msg));
                    status_parts.push(msg);
                }
            }

            let summary = self.generate_codex_summary();
            match self.write_codex_summary_file(&summary) {
                Ok(path) => {
                    let msg = format!("📄 Summary saved to {}", path.display());
                    self.record_codex_output(&format!("{}\n", msg));
                    status_parts.push(msg);
                }
                Err(err) => {
                    let msg = format!("⚠️ Failed to save Codex summary: {}", err);
                    self.record_codex_output(&format!("{}\n", msg));
                    status_parts.push(msg);
                }
            }
        } else {
            status_parts.push("Codex session ended (no output captured).".to_string());
        }

        self.codex_sender = None;
        self.codex_receiver = None;
        self.codex_resize_handle = None;

        self.mode = AppMode::MainMenu;
        self.show_popup = false;
        self.popup_message.clear();
        self.output_text.clear();
        self.input_text.clear();
        self.status_message = if status_parts.is_empty() {
            Some("Codex session ended.".to_string())
        } else {
            Some(status_parts.join(" | "))
        };
        self.codex_waiting_exit = false;
    }

    fn persist_codex_log(&mut self) -> Result<Option<PathBuf>> {
        if self.codex_raw_log.trim().is_empty() {
            return Ok(None);
        }
        if let Some(path) = &self.codex_log_file {
            return Ok(Some(path.clone()));
        }

        let dir = PathBuf::from("codex_logs");
        fs::create_dir_all(&dir)?;
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let path = dir.join(format!("codex-session-{}.ansi", timestamp));
        fs::write(&path, self.codex_raw_log.as_bytes())?;
        self.codex_log_file = Some(path.clone());
        Ok(Some(path))
    }

    fn generate_codex_summary(&self) -> String {
        let mut summary = String::new();
        summary.push_str("# Codex Session Summary\n\n");
        summary.push_str(&format!(
            "Commands executed: {}\n",
            self.codex_user_actions.len()
        ));
        if !self.codex_user_actions.is_empty() {
            summary.push_str("\n## Commands\n");
            let max_commands = 10;
            for cmd in self.codex_user_actions.iter().take(max_commands) {
                summary.push_str("- ");
                summary.push_str(cmd);
                summary.push('\n');
            }
            if self.codex_user_actions.len() > max_commands {
                summary.push_str("- …\n");
            }
        }
        summary.push_str("\n");
        summary.push_str(&format!(
            "Total output lines captured: {}\n",
            self.codex_output_log.lines().count()
        ));
        if let Some(path) = &self.codex_log_file {
            summary.push_str(&format!("Full log saved at: {}\n", path.display()));
        } else {
            summary.push_str("Full log has not been saved yet.\n");
        }
        summary
    }

    fn write_codex_summary_file(&mut self, summary: &str) -> Result<PathBuf> {
        let dir = PathBuf::from("codex_logs");
        fs::create_dir_all(&dir)?;
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let path = dir.join(format!("codex-summary-{}.md", timestamp));
        fs::write(&path, summary)?;
        self.codex_summary_file = Some(path.clone());
        Ok(path)
    }

    fn handle_codex_summary_request(&mut self) -> Result<()> {
        if self.codex_raw_log.trim().is_empty() {
            self.show_popup = true;
            self.popup_message =
                "Codex summary not available yet. Run a Codex session first.".to_string();
            return Ok(());
        }

        if self.codex_sender.is_some() {
            self.show_popup = true;
            self.popup_message =
                "Codex session is still running. Exit the session before generating a summary."
                    .to_string();
            return Ok(());
        }

        if let Err(err) = self.persist_codex_log() {
            self.show_popup = true;
            self.popup_message = format!("Failed to save Codex log: {}", err);
            return Ok(());
        }

        let summary = self.generate_codex_summary();
        match self.write_codex_summary_file(&summary) {
            Ok(path) => {
                self.record_codex_output(&format!(
                    "📤 Codex summary saved to {}\n",
                    path.display()
                ));
                self.show_popup = true;
                self.popup_message =
                    format!("Codex summary saved to {}\n\n{}", path.display(), summary);
            }
            Err(err) => {
                self.record_codex_output(&format!("⚠️ Failed to save Codex summary: {}\n", err));
                self.show_popup = true;
                self.popup_message = format!("Failed to save Codex summary: {}", err);
            }
        }

        self.refresh_codex_view();
        Ok(())
    }

    async fn try_connect_astation(&mut self) -> Result<()> {
        if !self.astation_connected {
            match self.astation_client.connect("ws://127.0.0.1:8080/ws").await {
                Ok(_) => {
                    self.astation_connected = true;
                    println!("🔌 Connected to Astation successfully");
                }
                Err(e) => {
                    println!("⚠️ Failed to connect to Astation: {}", e);
                    // Continue in local mode
                }
            }
        }
        Ok(())
    }

    async fn handle_astation_message(&mut self, message: AstationMessage) {
        match message {
            AstationMessage::ProjectListResponse {
                projects,
                timestamp: _,
            } => {
                let projects_info = projects
                    .iter()
                    .map(|p| {
                        format!(
                            "• {} (ID: {}) - {} [{}]",
                            p.name, p.id, p.description, p.status
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");

                self.output_text = format!(
                    "📋 Agora Projects List (from Astation)\n\n\
                    {}\n\n\
                    💡 To generate RTC tokens, use:\n\
                    • Go to '💻 Execute Shell Command'\n\
                    • Run: atem token rtc create --channel <name> --uid <id>\n\n\
                    Press 'b' to go back to main menu",
                    projects_info
                );
            }
            AstationMessage::TokenResponse {
                token,
                channel,
                uid,
                expires_in,
                timestamp: _,
            } => {
                self.token_info = Some(TokenInfo {
                    token: token.clone(),
                    channel: channel.clone(),
                    uid: uid.clone(),
                    expires_in: expires_in.clone(),
                });

                self.output_text = format!(
                    "🔑 RTC Token Generated (from Astation):\n\n\
                    Channel: {}\n\
                    UID: {}\n\
                    Token: {}\n\
                    Expires: {}\n\n\
                    Press 'b' to go back to main menu",
                    channel, uid, token, expires_in
                );
            }
            AstationMessage::ClaudeLaunchResponse {
                success,
                message,
                timestamp: _,
            } => {
                if success {
                    self.output_text = format!(
                        "✅ Claude Code launched from Astation: {}\n\nPress 'b' to go back to main menu",
                        message
                    );
                } else {
                    self.output_text = format!(
                        "❌ Failed to launch Claude Code from Astation: {}\n\nPress 'b' to go back to main menu",
                        message
                    );
                }
            }
            AstationMessage::StatusUpdate { status, data } => {
                println!("📊 Status update from Astation: {} - {:?}", status, data);
            }
            AstationMessage::CodexTaskResponse {
                output,
                success,
                timestamp: _,
            } => {
                if success {
                    self.record_codex_output(&format!("🧠 [Astation] {}\n", output));
                } else {
                    self.record_codex_output(&format!("❌ [Astation] {}\n", output));
                }

                if matches!(self.mode, AppMode::CodexChat) {
                    self.refresh_codex_view();
                } else if success {
                    self.output_text = format!("🧠 Codex response (via Astation):\n\n{}", output);
                } else {
                    self.output_text = format!("❌ Codex task failed (via Astation): {}", output);
                }
            }
            _ => {
                println!("📨 Received message from Astation: {:?}", message);
            }
        }
    }

    async fn process_astation_messages(&mut self) {
        if let Some(message) = self.astation_client.recv_message().await {
            self.handle_astation_message(message).await;
        }
    }
}

async fn list_agora_projects() -> Result<String> {
    // Simulate API call with a small delay
    sleep(Duration::from_millis(800)).await;

    // In a real implementation, this would call the Agora API
    // For now, simulate with sample data
    let sample_projects = vec![
        ("MyLiveStream", "proj_001", "Live Streaming App"),
        ("VideoCall Pro", "proj_002", "Video Conferencing"),
        ("VoiceChat Room", "proj_003", "Voice Communication"),
        ("GameStream", "proj_004", "Gaming Live Stream"),
    ];

    let mut projects_text = String::new();
    projects_text.push_str("🏢 Your Agora Projects:\n\n");

    for (i, (name, id, description)) in sample_projects.iter().enumerate() {
        projects_text.push_str(&format!(
            "{}. 📱 {}\n   ID: {}\n   📝 {}\n\n",
            i + 1,
            name,
            id,
            description
        ));
    }

    Ok(projects_text)
}

async fn generate_rtc_token() -> Result<TokenInfo> {
    // Simulate token generation with a small delay for UX
    sleep(Duration::from_millis(500)).await;

    let uuid = Uuid::new_v4();
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    let payload = serde_json::json!({
        "uid": "user123",
        "exp": timestamp + 3600,
        "iat": timestamp,
        "channel": "test-channel",
        "uuid": uuid.to_string()
    });

    let token = general_purpose::STANDARD.encode(payload.to_string().as_bytes());

    Ok(TokenInfo {
        token,
        channel: "test-channel".to_string(),
        uid: "user123".to_string(),
        expires_in: "1 hour".to_string(),
    })
}

async fn launch_claude_async() -> Result<String> {
    // First, restore terminal to normal state
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen, DisableMouseCapture)?;

    let result = tokio::task::spawn_blocking(|| -> Result<String> {
        // Try to launch Claude interactively
        match Command::new("claude")
            .envs(std::env::vars())
            .status() // Use .status() instead of .output() for interactive commands
        {
            Ok(status) => {
                if status.success() {
                    Ok("✅ Claude session completed successfully.".to_string())
                } else {
                    Ok("⚠️ Claude session ended with non-zero exit code.".to_string())
                }
            }
            Err(_) => {
                Ok("❌ Claude CLI not found.\nInstall it from: https://claude.ai/code\n\nTry: npm install -g @anthropic-ai/claude-code".to_string())
            }
        }
    }).await??;

    // Restore TUI state
    enable_raw_mode()?;
    execute!(io::stdout(), EnterAlternateScreen, EnableMouseCapture)?;

    Ok(result)
}

fn draw_ui(frame: &mut Frame, app: &mut App) {
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
    let header = Paragraph::new("🚀 ATEM - Agora.io AI CLI Tool")
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
        AppMode::TokenGeneration | AppMode::ClaudeChat => draw_output_view(frame, chunks[1], app),
        AppMode::CommandExecution => draw_command_input(frame, chunks[1], app),
        AppMode::CodexChat => draw_codex_panel(frame, chunks[1], app),
    }

    // Footer
    let base_footer = match app.mode {
        AppMode::MainMenu => "↑↓/jk: Navigate | Enter: Select | c: Copy Mode | q: Quit",
        AppMode::CommandExecution => "Type command + Enter | b: Back | q: Quit",
        AppMode::CodexChat => {
            "Enter: Send | Ctrl+C: Exit Codex | u: Summary | b: Back | q: Quit"
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

fn draw_main_menu(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
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

    frame.render_widget(list, area);
}

fn draw_output_view(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
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

fn draw_command_input(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
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

fn draw_codex_panel(frame: &mut Frame, area: ratatui::layout::Rect, app: &mut App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(5),    // Terminal view
            Constraint::Length(3), // Input
        ])
        .split(area);

    let terminal_block = Block::default()
        .borders(Borders::ALL)
        .title("Codex Terminal")
        .border_style(Style::default().fg(Color::Green));
    let terminal_inner = terminal_block.inner(chunks[0]);
    frame.render_widget(terminal_block, chunks[0]);

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

    let input = Paragraph::new(app.input_text.as_str())
        .style(Style::default().fg(Color::Yellow))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title("Codex Input")
                .border_style(Style::default().fg(Color::Cyan)),
        );
    frame.render_widget(input, chunks[1]);
}

fn vt_color_to_tui(color: VtColor) -> Color {
    match color {
        VtColor::Default => Color::Reset,
        VtColor::Idx(idx) => Color::Indexed(idx),
        VtColor::Rgb(r, g, b) => Color::Rgb(r, g, b),
    }
}

fn style_from_cell(cell: &VtCell) -> Style {
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

fn draw_popup(frame: &mut Frame, app: &App) {
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

fn centered_rect(
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

async fn run_app() -> Result<()> {
    // Handle command line arguments first
    let cli = Cli::parse();

    if let Some(command) = cli.command {
        // Non-interactive mode - handle CLI commands directly
        match command {
            Commands::Token { token_command } => match token_command {
                TokenCommands::Rtc { rtc_command } => match rtc_command {
                    RtcCommands::Create => {
                        let token_info = generate_rtc_token().await?;
                        println!("✅ RTC Token created successfully:");
                        println!("{}", token_info.token);
                        println!("\n📋 Token Details:");
                        println!("  Channel: {}", token_info.channel);
                        println!("  UID: {}", token_info.uid);
                        println!("  Valid for: {}", token_info.expires_in);
                        return Ok(());
                    }
                },
            },
        }
    }

    // Interactive TUI mode
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    let result = run_tui(&mut terminal, &mut app).await;

    // Cleanup
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

async fn run_tui(terminal: &mut Terminal<CrosstermBackend<Stdout>>, app: &mut App) -> Result<()> {
    // Try to connect to Astation at startup
    let _ = app.try_connect_astation().await;

    loop {
        // Process any pending Astation messages
        app.process_astation_messages().await;
        app.process_codex_output();

        if app.force_terminal_redraw {
            terminal.clear()?;
            app.force_terminal_redraw = false;
        }

        terminal.draw(|f| draw_ui(f, app))?;

        if event::poll(Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);

                    if ctrl && matches!(app.mode, AppMode::CodexChat) {
                        match key.code {
                            KeyCode::Char('c') | KeyCode::Char('C') => {
                                app.send_codex_interrupt();
                                continue;
                            }
                            _ => {}
                        }
                    }

                    match key.code {
                        KeyCode::Char('q') | KeyCode::Char('Q') if !ctrl => return Ok(()),
                        KeyCode::Char('c') | KeyCode::Char('C')
                            if !ctrl
                                && !matches!(
                                    app.mode,
                                    AppMode::CommandExecution | AppMode::CodexChat
                                ) =>
                        {
                            // Copy mode - just display content without leaving TUI
                            app.show_popup = true;

                            let content = match app.mode {
                                AppMode::MainMenu => {
                                    format!(
                                        "🚀 ATEM - Agora.io AI CLI Tool\n\nMain Menu:\n{}",
                                        app.main_menu_items
                                            .iter()
                                            .enumerate()
                                            .map(|(i, item)| if i == app.selected_index {
                                                format!("  → {}", item)
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
                                "📋 COPY MODE\n\
                                ═══════════════════════════════════════\n\
                                {}\n\
                                ═══════════════════════════════════════\n\
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
                                AppMode::MainMenu => match key.code {
                                    KeyCode::Down | KeyCode::Char('j') => app.next_item(),
                                    KeyCode::Up | KeyCode::Char('k') => app.previous_item(),
                                    KeyCode::Enter => {
                                        if app.selected_index == 5 {
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
                                AppMode::CodexChat => match key.code {
                                    KeyCode::Enter => {
                                        if !app.input_text.is_empty() {
                                            let prompt = app.input_text.clone();
                                            app.input_text.clear();
                                            app.send_codex_prompt(&prompt).await?;
                                        }
                                    }
                                    KeyCode::Backspace => {
                                        app.input_text.pop();
                                    }
                                    KeyCode::Char(c) if !ctrl && (c == 'c' || c == 'C') => {
                                        app.enter_codex_copy_mode()?;
                                    }
                                    KeyCode::Char(c) if !ctrl && (c == 'u' || c == 'U') => {
                                        app.handle_codex_summary_request()?;
                                    }
                                    KeyCode::Char(c) if !ctrl => {
                                        app.input_text.push(c);
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

#[tokio::main]
async fn main() -> Result<()> {
    run_app().await
}

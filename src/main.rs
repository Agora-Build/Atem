use anyhow::Result;
use base64::{Engine as _, engine::general_purpose};
use clap::{Parser, Subcommand};
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
    Frame, Terminal,
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout},
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap},
};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    collections::VecDeque,
    fs,
    io::{self, Stdout},
    path::PathBuf,
    process::Command,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::mpsc::{UnboundedReceiver, UnboundedSender, error::TryRecvError},
    time::{Duration, sleep},
};
use uuid::Uuid;
use vt100::{Cell as VtCell, Color as VtColor, Parser as VtParser};

mod claude_client;
mod codex_client;
mod rtm_client;
mod token;
mod websocket_client;
use claude_client::{ClaudeClient, ClaudeResizeHandle};
use codex_client::{CodexClient, CodexResizeHandle};
use rtm_client::{RtmClient, RtmConfig, RtmEvent};
use token::generate_rtm_token;

const AGORA_APP_ID: &str = "YOUR_AGORA_APP_ID";
const AGORA_APP_CERTIFICATE: &str = "YOUR_AGORA_APP_CERTIFICATE";
const AGORA_RTM_CHANNEL: &str = "atem_channel";
const AGORA_RTM_ACCOUNT: &str = "atem01";
const AGORA_RTM_TOKEN_TTL_SECS: u32 = 3600;
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

#[derive(Deserialize)]
struct AgoraApiResponse {
    projects: Vec<AgoraApiProject>,
}

#[derive(Clone, Debug, Deserialize)]
struct AgoraApiProject {
    #[allow(dead_code)]
    id: String,
    name: String,
    vendor_key: String,
    sign_key: String,
    #[allow(dead_code)]
    recording_server: Option<String>,
    status: i32,
    created: u64,
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
    claude_client: ClaudeClient,
    claude_output_log: String,
    claude_raw_log: String,
    claude_user_actions: Vec<String>,
    claude_log_file: Option<PathBuf>,
    claude_summary_file: Option<PathBuf>,
    claude_terminal: VtParser,
    claude_sender: Option<UnboundedSender<String>>,
    claude_receiver: Option<UnboundedReceiver<String>>,
    claude_waiting_exit: bool,
    claude_resize_handle: Option<ClaudeResizeHandle>,
    claude_view_rows: u16,
    claude_view_cols: u16,
    force_terminal_redraw: bool,
    rtm_client: Option<RtmClient>,
    rtm_client_id: String,
    rtm_certificate: String,
    last_activity_ping: Option<Instant>,
    activity_ping_interval: Duration,
    pending_transcriptions: VecDeque<String>,
    rtm_token_expires_at: Option<Instant>,
    show_certificates: bool,
    cached_projects: Vec<AgoraApiProject>,
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
            claude_client: ClaudeClient::new(),
            claude_output_log: String::new(),
            claude_raw_log: String::new(),
            claude_user_actions: Vec::new(),
            claude_log_file: None,
            claude_summary_file: None,
            claude_terminal: VtParser::new(200, 80, 0),
            claude_sender: None,
            claude_receiver: None,
            claude_waiting_exit: false,
            claude_resize_handle: None,
            claude_view_rows: 0,
            claude_view_cols: 0,
            force_terminal_redraw: false,
            rtm_client: None,
            rtm_client_id: AGORA_RTM_ACCOUNT.to_string(),
            rtm_certificate: AGORA_APP_CERTIFICATE.to_string(),
            last_activity_ping: None,
            activity_ping_interval: Duration::from_secs(2),
            pending_transcriptions: VecDeque::new(),
            rtm_token_expires_at: None,
            show_certificates: false,
            cached_projects: Vec::new(),
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
                    match fetch_agora_projects().await {
                        Ok(projects) => {
                            self.show_certificates = false;
                            let info = format_projects(&projects, self.show_certificates);
                            self.cached_projects = projects;
                            self.output_text = format!(
                                "Agora Projects\n\n{}",
                                info
                            );
                        }
                        Err(e) => {
                            self.cached_projects.clear();
                            self.output_text = format!(
                                "Failed to fetch Agora projects: {}\n\n\
                                Set AGORA_CUSTOMER_ID and AGORA_CUSTOMER_SECRET environment variables.\n\
                                Get these from https://console.agora.io -> RESTful API\n\n\
                                Press 'b' to go back to main menu",
                                e
                            );
                        }
                    }
                }
            }
            1 => {
                // Launch Claude Code
                self.mode = AppMode::ClaudeChat;

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
                    // Launch Claude locally via PTY
                    self.input_text.clear();
                    self.claude_waiting_exit = false;
                    if self.claude_output_log.is_empty() {
                        self.claude_output_log = "🤖 Claude Code CLI Session\n\n\
                            Atem routes your input to the Claude Code CLI and streams its replies back here.\n\
                            Type commands in the input box and press Enter to send them to Claude.\n\
                            Press Ctrl+C to end the Claude session and return to the main menu.\n\
                            After a session, press 'u' to save a summary report.\n"
                            .to_string();
                    }

                    match self.ensure_claude_session().await {
                        Ok(new_session_started) => {
                            if new_session_started {
                                self.record_claude_output("🔌 Claude Code CLI session started.\n");
                            }
                            self.refresh_claude_view();
                        }
                        Err(err) => {
                            self.record_claude_output(format!(
                                "❌ Unable to start Claude Code CLI: {}\n",
                                err
                            ));
                            self.refresh_claude_view();
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
            execute!(io::stdout(), LeaveAlternateScreen)?;

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
            execute!(io::stdout(), EnterAlternateScreen)?;

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

    async fn ensure_rtm_client(&mut self) -> Result<()> {
        let needs_new_client = self.rtm_client.is_none()
            || self
                .rtm_token_expires_at
                .map(|expiry| expiry <= Instant::now())
                .unwrap_or(true);

        if !needs_new_client {
            return Ok(());
        }

        let token = generate_rtm_token(
            AGORA_APP_ID,
            &self.rtm_certificate,
            AGORA_RTM_ACCOUNT,
            AGORA_RTM_TOKEN_TTL_SECS,
        );

        let config = RtmConfig {
            app_id: AGORA_APP_ID.to_string(),
            token: token.clone(),
            channel: AGORA_RTM_CHANNEL.to_string(),
            client_id: self.rtm_client_id.clone(),
        };

        let client = RtmClient::new(config).map_err(|err| {
            self.status_message = Some(format!("Failed to connect to Astation signaling: {}", err));
            err
        })?;

        if let Err(err) = client
            .login_and_join(&token, AGORA_RTM_ACCOUNT, AGORA_RTM_CHANNEL)
            .await
        {
            self.status_message = Some(format!("Failed to login/join signaling: {}", err));
            return Err(err);
        }

        let refresh_margin = if AGORA_RTM_TOKEN_TTL_SECS > 120 {
            AGORA_RTM_TOKEN_TTL_SECS as u64 - 60
        } else {
            (AGORA_RTM_TOKEN_TTL_SECS as u64).saturating_sub(10)
        };
        self.rtm_token_expires_at = Some(Instant::now() + Duration::from_secs(refresh_margin));
        self.rtm_client = Some(client);
        self.status_message = Some("Connected to Astation signaling.".to_string());
        Ok(())
    }

    async fn send_activity_ping(&mut self, focused: bool) -> Result<()> {
        self.ensure_rtm_client().await?;
        let client = match &self.rtm_client {
            Some(client) => client,
            None => return Ok(()),
        };

        let payload = json!({
            "type": "activity",
            "client_id": self.rtm_client_id,
            "focused": focused,
            "timestamp": current_timestamp_ms(),
        })
        .to_string();

        client.publish_channel(&payload).await?;
        Ok(())
    }

    async fn maybe_send_activity_ping(&mut self, focused: bool) {
        let should_send = match self.last_activity_ping {
            Some(last) => last.elapsed() >= self.activity_ping_interval,
            None => true,
        };

        if should_send {
            match self.send_activity_ping(focused).await {
                Ok(()) => {
                    self.last_activity_ping = Some(Instant::now());
                }
                Err(err) => {
                    self.status_message = Some(format!("Failed to send activity ping: {}", err));
                }
            }
        }
    }

    async fn process_rtm_messages(&mut self) -> Result<()> {
        if let Some(client) = &self.rtm_client {
            let events = client.drain_events().await;
            for event in events {
                self.handle_rtm_event(event);
            }
        }

        self.flush_pending_transcriptions().await?;
        Ok(())
    }

    fn handle_rtm_event(&mut self, event: RtmEvent) {
        if event.payload.trim().is_empty() {
            return;
        }

        match serde_json::from_str::<Value>(&event.payload) {
            Ok(value) => {
                if let Some(kind) = value.get("type").and_then(|v| v.as_str()) {
                    match kind {
                        "transcription" => {
                            let target = value
                                .get("target")
                                .and_then(|v| v.as_str())
                                .unwrap_or_default();
                            if target == self.rtm_client_id {
                                if let Some(text) = value.get("text").and_then(|v| v.as_str()) {
                                    self.pending_transcriptions.push_back(text.to_string());
                                }
                            }
                        }
                        "active_update" => {
                            if let Some(active) =
                                value.get("active_atem_id").and_then(|v| v.as_str())
                            {
                                if active == self.rtm_client_id {
                                    self.status_message =
                                        Some("Astation marked this Atem as active.".to_string());
                                } else {
                                    self.status_message =
                                        Some(format!("Astation active Atem: {}", active));
                                }
                            }
                        }
                        "dictation_state" => {
                            if let Some(state) = value.get("enabled").and_then(|v| v.as_bool()) {
                                self.status_message = Some(if state {
                                    "Astation dictation enabled.".to_string()
                                } else {
                                    "Astation dictation paused.".to_string()
                                });
                            }
                        }
                        _ => {}
                    }
                }
            }
            Err(err) => {
                self.status_message = Some(format!(
                    "Failed to parse RTM message '{}' ({})",
                    event.payload, err
                ));
            }
        }
    }

    async fn flush_pending_transcriptions(&mut self) -> Result<()> {
        while let Some(text) = self.pending_transcriptions.pop_front() {
            if matches!(self.mode, AppMode::CodexChat) {
                if let Err(err) = self.send_codex_prompt(&text).await {
                    self.status_message =
                        Some(format!("Failed to send transcription to Codex: {}", err));
                    return Err(err);
                }
            } else if matches!(self.mode, AppMode::ClaudeChat) && !self.astation_connected {
                if let Err(err) = self.send_claude_prompt(&text).await {
                    self.status_message =
                        Some(format!("Failed to send transcription to Claude: {}", err));
                    return Err(err);
                }
            } else {
                self.status_message = Some(format!(
                    "Transcription received (switch to Codex/Claude): {}",
                    text
                ));
                self.pending_transcriptions.push_front(text);
                break;
            }
        }
        Ok(())
    }

    async fn register_local_activity(&mut self, focused: bool) {
        self.maybe_send_activity_ping(focused).await;
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

    async fn send_claude_prompt(&mut self, prompt: &str) -> Result<()> {
        let trimmed = prompt.trim();
        if trimmed.is_empty() {
            return Ok(());
        }
        if self.claude_waiting_exit {
            self.status_message =
                Some("Claude is shutting down. Please wait for the session to exit.".to_string());
            return Ok(());
        }

        let is_quit_cmd =
            trimmed.eq_ignore_ascii_case("quit") || trimmed.eq_ignore_ascii_case("exit");

        match self.ensure_claude_session().await {
            Ok(new_session_started) => {
                if new_session_started {
                    self.record_claude_output("🔌 Claude Code CLI session started.\n");
                }
            }
            Err(err) => {
                self.record_claude_output(format!(
                    "❌ Unable to start Claude Code CLI: {}\n",
                    err
                ));
                self.refresh_claude_view();
                return Ok(());
            }
        }

        self.record_claude_output(format!("> {}\n", trimmed));
        self.claude_user_actions.push(trimmed.to_string());

        if self.claude_sender.is_some() {
            self.send_claude_data(trimmed);

            if self.claude_sender.is_some() {
                self.send_claude_data("\n");
            }
            if self.claude_sender.is_some() {
                self.send_claude_data("\r");
            }

            if self.claude_sender.is_none() {
                self.record_claude_output(
                    "⚠️ Claude Code CLI session is unavailable (send failed).\n",
                );
                self.claude_receiver = None;
                self.claude_resize_handle = None;
                self.claude_waiting_exit = false;
            } else if is_quit_cmd {
                self.claude_waiting_exit = true;
                self.status_message = Some(
                    "Claude exit requested. Waiting for the session to shut down...".to_string(),
                );
            }
        } else {
            self.record_claude_output("⚠️ Claude Code CLI session is unavailable.\n");
        }

        self.refresh_claude_view();
        Ok(())
    }

    async fn ensure_claude_session(&mut self) -> Result<bool> {
        let needs_session = self.claude_sender.is_none() || self.claude_receiver.is_none();
        if !needs_session {
            return Ok(false);
        }

        let session = self.claude_client.start_session().await?;
        self.claude_sender = Some(session.sender);
        self.claude_receiver = Some(session.receiver);
        self.claude_resize_handle = Some(session.resize_handle);
        self.claude_raw_log.clear();
        self.claude_output_log.clear();
        self.claude_user_actions.clear();
        self.claude_log_file = None;
        self.claude_summary_file = None;
        let rows = if self.claude_view_rows == 0 {
            200
        } else {
            self.claude_view_rows
        };
        let cols = if self.claude_view_cols == 0 {
            80
        } else {
            self.claude_view_cols
        };
        self.claude_terminal = VtParser::new(rows, cols, 0);
        if let Some(handle) = &self.claude_resize_handle
            && let Err(err) = handle.resize(rows, cols)
        {
            self.status_message =
                Some(format!("Failed to sync Claude terminal size: {}", err));
        }
        self.claude_waiting_exit = false;
        Ok(true)
    }

    fn record_claude_output(&mut self, data: impl AsRef<str>) {
        let text = data.as_ref();
        self.claude_raw_log.push_str(text);

        self.claude_terminal.process(text.as_bytes());
        self.update_claude_output_from_terminal();
    }

    fn update_claude_output_from_terminal(&mut self) {
        let screen = self.claude_terminal.screen();
        let (_rows, cols) = screen.size();

        let mut lines: Vec<String> = screen
            .rows(0, cols)
            .map(|line| line.replace('\u{0000}', ""))
            .collect();

        while lines.last().is_some_and(|line| line.trim().is_empty()) {
            lines.pop();
        }

        self.claude_output_log = lines.join("\n");
        if matches!(self.mode, AppMode::ClaudeChat) && !self.astation_connected {
            self.output_text = self.claude_output_log.clone();
        }
    }

    fn send_claude_data(&mut self, data: &str) {
        let Some(sender) = self.claude_sender.clone() else {
            return;
        };
        if sender.send(data.to_string()).is_err() {
            self.claude_sender = None;
            self.claude_receiver = None;
            self.claude_resize_handle = None;
            self.claude_waiting_exit = false;
        }
    }

    fn respond_claude_cursor_position(&mut self) {
        let (row, col) = self.claude_terminal.screen().cursor_position();
        let response = format!("\u{1b}[{};{}R", row + 1, col + 1);
        self.send_claude_data(&response);
    }

    fn handle_claude_control_sequences(&mut self, chunk: &str) {
        if chunk.contains("\u{1b}[6n") {
            let occurrences = chunk.matches("\u{1b}[6n").count();
            for _ in 0..occurrences {
                self.respond_claude_cursor_position();
            }
        }
        if chunk.contains("\u{1b}[5n") {
            let occurrences = chunk.matches("\u{1b}[5n").count();
            for _ in 0..occurrences {
                self.send_claude_data("\u{1b}[0n");
            }
        }
        // Device Attributes query - Claude CLI may send this
        if chunk.contains("\u{1b}[c") {
            let occurrences = chunk.matches("\u{1b}[c").count();
            for _ in 0..occurrences {
                // Respond as VT100
                self.send_claude_data("\u{1b}[?1;0c");
            }
        }
    }

    fn refresh_claude_view(&mut self) {
        if matches!(self.mode, AppMode::ClaudeChat) && !self.astation_connected {
            self.output_text = self.claude_output_log.clone();
        }
    }

    fn rebuild_claude_terminal(&mut self) {
        let rows = if self.claude_view_rows > 0 {
            self.claude_view_rows
        } else {
            200
        };
        let cols = if self.claude_view_cols > 0 {
            self.claude_view_cols
        } else {
            80
        };

        self.claude_terminal = VtParser::new(rows, cols, 0);
        if !self.claude_raw_log.is_empty() {
            self.claude_terminal.process(self.claude_raw_log.as_bytes());
        }
        self.update_claude_output_from_terminal();
    }

    fn adjust_claude_terminal_size(&mut self, rows: u16, cols: u16) {
        if rows == 0 || cols == 0 {
            return;
        }
        if self.claude_view_rows == rows && self.claude_view_cols == cols {
            return;
        }

        self.claude_view_rows = rows;
        self.claude_view_cols = cols;
        self.rebuild_claude_terminal();

        if let Some(handle) = &self.claude_resize_handle
            && let Err(err) = handle.resize(rows, cols)
        {
            self.status_message =
                Some(format!("Failed to resize Claude terminal: {}", err));
        }
    }

    fn process_claude_output(&mut self) {
        if self.astation_connected {
            return;
        }

        let mut new_chunks: Vec<String> = Vec::new();
        let mut disconnected = false;

        if let Some(receiver) = &mut self.claude_receiver {
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
            new_chunks.push("⚠️ Claude Code CLI session disconnected.\n".to_string());
        }

        let exit_detected = new_chunks.iter().any(|chunk| {
            chunk.contains("Claude CLI exited with status")
                || chunk.contains("Claude CLI wait error")
        });

        if !new_chunks.is_empty() {
            for chunk in &new_chunks {
                self.record_claude_output(chunk);
                self.handle_claude_control_sequences(chunk);
            }

            if !(disconnected || exit_detected) {
                self.refresh_claude_view();
            }
        }

        if disconnected || exit_detected {
            self.finalize_claude_session();
        }
    }

    fn finalize_claude_session(&mut self) {
        if !matches!(self.mode, AppMode::ClaudeChat) || self.astation_connected {
            return;
        }

        let had_activity_before_finalize = !self.claude_raw_log.trim().is_empty();

        self.record_claude_output("⚙️ Claude Code CLI session ended.\n");

        let mut status_parts: Vec<String> = Vec::new();

        if had_activity_before_finalize {
            match self.persist_claude_log() {
                Ok(Some(path)) => {
                    let msg = format!("📝 Claude log saved to {}", path.display());
                    self.record_claude_output(format!("{}\n", msg));
                    status_parts.push(msg);
                }
                Ok(None) => {
                    status_parts
                        .push("Claude session ended with no output to save.".to_string());
                }
                Err(err) => {
                    let msg = format!("⚠️ Failed to save Claude log: {}", err);
                    self.record_claude_output(format!("{}\n", msg));
                    status_parts.push(msg);
                }
            }

            let summary = self.generate_claude_summary();
            match self.write_claude_summary_file(&summary) {
                Ok(path) => {
                    let msg = format!("📄 Summary saved to {}", path.display());
                    self.record_claude_output(format!("{}\n", msg));
                    status_parts.push(msg);
                }
                Err(err) => {
                    let msg = format!("⚠️ Failed to save Claude summary: {}", err);
                    self.record_claude_output(format!("{}\n", msg));
                    status_parts.push(msg);
                }
            }
        } else {
            status_parts.push("Claude session ended (no output captured).".to_string());
        }

        self.claude_sender = None;
        self.claude_receiver = None;
        self.claude_resize_handle = None;

        self.mode = AppMode::MainMenu;
        self.show_popup = false;
        self.popup_message.clear();
        self.output_text.clear();
        self.input_text.clear();
        self.status_message = if status_parts.is_empty() {
            Some("Claude session ended.".to_string())
        } else {
            Some(status_parts.join(" | "))
        };
        self.claude_waiting_exit = false;
    }

    fn persist_claude_log(&mut self) -> Result<Option<PathBuf>> {
        if self.claude_raw_log.trim().is_empty() {
            return Ok(None);
        }
        if let Some(path) = &self.claude_log_file {
            return Ok(Some(path.clone()));
        }

        let dir = PathBuf::from("claude_logs");
        fs::create_dir_all(&dir)?;
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let path = dir.join(format!("claude-session-{}.ansi", timestamp));
        fs::write(&path, self.claude_raw_log.as_bytes())?;
        self.claude_log_file = Some(path.clone());
        Ok(Some(path))
    }

    fn generate_claude_summary(&self) -> String {
        let mut summary = String::new();
        summary.push_str("# Claude Code Session Summary\n\n");
        summary.push_str(&format!(
            "Commands executed: {}\n",
            self.claude_user_actions.len()
        ));
        if !self.claude_user_actions.is_empty() {
            summary.push_str("\n## Commands\n");
            let max_commands = 10;
            for cmd in self.claude_user_actions.iter().take(max_commands) {
                summary.push_str("- ");
                summary.push_str(cmd);
                summary.push('\n');
            }
            if self.claude_user_actions.len() > max_commands {
                summary.push_str("- …\n");
            }
        }
        summary.push('\n');
        summary.push_str(&format!(
            "Total output lines captured: {}\n",
            self.claude_output_log.lines().count()
        ));
        if let Some(path) = &self.claude_log_file {
            summary.push_str(&format!("Full log saved at: {}\n", path.display()));
        } else {
            summary.push_str("Full log has not been saved yet.\n");
        }
        summary
    }

    fn write_claude_summary_file(&mut self, summary: &str) -> Result<PathBuf> {
        let dir = PathBuf::from("claude_logs");
        fs::create_dir_all(&dir)?;
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let path = dir.join(format!("claude-summary-{}.md", timestamp));
        fs::write(&path, summary)?;
        self.claude_summary_file = Some(path.clone());
        Ok(path)
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

async fn fetch_agora_projects() -> Result<Vec<AgoraApiProject>> {
    let customer_id = std::env::var("AGORA_CUSTOMER_ID")
        .map_err(|_| anyhow::anyhow!("AGORA_CUSTOMER_ID environment variable not set"))?;
    let customer_secret = std::env::var("AGORA_CUSTOMER_SECRET")
        .map_err(|_| anyhow::anyhow!("AGORA_CUSTOMER_SECRET environment variable not set"))?;

    let credentials = general_purpose::STANDARD.encode(format!("{}:{}", customer_id, customer_secret));

    let client = reqwest::Client::new();
    let resp = client
        .get("https://api.agora.io/dev/v1/projects")
        .header("Authorization", format!("Basic {}", credentials))
        .send()
        .await?;

    if !resp.status().is_success() {
        return Err(anyhow::anyhow!(
            "Agora API returned status {}",
            resp.status()
        ));
    }

    let api_response: AgoraApiResponse = resp.json().await?;
    Ok(api_response.projects)
}

fn format_projects(projects: &[AgoraApiProject], show_certificates: bool) -> String {
    if projects.is_empty() {
        return "No projects found in your Agora account.\n".to_string();
    }

    let mut text = String::new();
    for (i, project) in projects.iter().enumerate() {
        let status_str = if project.status == 1 {
            "Enabled"
        } else {
            "Disabled"
        };
        let created_date = format_unix_timestamp(project.created);
        text.push_str(&format!(
            "{}. {}\n   App ID: {}\n",
            i + 1,
            project.name,
            project.vendor_key,
        ));
        if show_certificates {
            let cert_display = if project.sign_key.is_empty() {
                "(none)"
            } else {
                &project.sign_key
            };
            text.push_str(&format!("   Certificate: {}\n", cert_display));
        }
        text.push_str(&format!(
            "   Status: {}  |  Created: {}\n\n",
            status_str, created_date,
        ));
    }
    text
}

fn format_unix_timestamp(ts: u64) -> String {
    let secs = ts;
    let days_since_epoch = secs / 86400;
    // Compute year/month/day from days since 1970-01-01
    let mut remaining_days = days_since_epoch as i64;
    let mut year = 1970i64;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }
    let days_in_months: [i64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    let mut month = 0;
    for (i, &dim) in days_in_months.iter().enumerate() {
        if remaining_days < dim {
            month = i + 1;
            break;
        }
        remaining_days -= dim;
    }
    let day = remaining_days + 1;
    format!("{:04}-{:02}-{:02}", year, month, day)
}

fn is_leap_year(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
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
    }

    // Footer
    let base_footer = match app.mode {
        AppMode::MainMenu => "↑↓/jk: Navigate | Enter: Select | c: Copy Mode | q: Quit",
        AppMode::CommandExecution => "Type command + Enter | b: Back | q: Quit",
        AppMode::CodexChat => "All input goes to Codex | Ctrl+B: Back to menu",
        AppMode::ClaudeChat if !app.astation_connected => {
            "All input goes to Claude | Ctrl+B: Back to menu"
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

fn draw_claude_panel(frame: &mut Frame, area: ratatui::layout::Rect, app: &mut App) {
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

fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_millis() as u64
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
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new();
    let result = run_tui(&mut terminal, &mut app).await;

    // Cleanup
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen
    )?;
    terminal.show_cursor()?;

    result
}

async fn run_tui(terminal: &mut Terminal<CrosstermBackend<Stdout>>, app: &mut App) -> Result<()> {
    // Try to connect to Astation at startup
    let _ = app.try_connect_astation().await;
    let _ = app.ensure_rtm_client().await;

    loop {
        // Process any pending Astation messages
        app.process_astation_messages().await;
        app.process_codex_output();
        app.process_claude_output();
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

                    // In local Claude mode, forward ALL keystrokes directly to
                    // Claude Code's PTY.  Only Ctrl+B escapes back to the menu.
                    if matches!(app.mode, AppMode::ClaudeChat) && !app.astation_connected {
                        if ctrl && matches!(key.code, KeyCode::Char('b') | KeyCode::Char('B'))
                        {
                            app.finalize_claude_session();
                            continue;
                        }

                        // Convert the key event to bytes and send to PTY.
                        let data: Option<String> = if ctrl {
                            match key.code {
                                KeyCode::Char(c) => {
                                    // Ctrl+A..Z → 0x01..0x1A
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

#[tokio::main]
async fn main() -> Result<()> {
    run_app().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_unix_timestamp_known_date() {
        // 2016-05-25 in UTC corresponds to unix timestamp 1464134400
        // The created value 1464165672 is 2016-05-25 (with some hours offset)
        assert_eq!(format_unix_timestamp(1464165672), "2016-05-25");
    }

    #[test]
    fn format_unix_timestamp_epoch() {
        assert_eq!(format_unix_timestamp(0), "1970-01-01");
    }

    #[test]
    fn format_unix_timestamp_leap_year() {
        // 2020-02-29 00:00:00 UTC = 1582934400
        assert_eq!(format_unix_timestamp(1582934400), "2020-02-29");
    }

    #[tokio::test]
    async fn fetch_agora_projects_missing_credentials() {
        // Ensure env vars are not set for this test
        // SAFETY: test is single-threaded for env access
        unsafe {
            std::env::remove_var("AGORA_CUSTOMER_ID");
            std::env::remove_var("AGORA_CUSTOMER_SECRET");
        }

        let result = fetch_agora_projects().await;
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("AGORA_CUSTOMER_ID"),
            "Error should mention AGORA_CUSTOMER_ID, got: {}",
            err_msg
        );
    }

    #[test]
    fn format_timestamps_from_real_api_data() {
        // Timestamps from the actual API response
        assert_eq!(format_unix_timestamp(1736297713), "2025-01-08"); // Demo for 128
        assert_eq!(format_unix_timestamp(1715721645), "2024-05-14"); // Demo for Conv API
        assert_eq!(format_unix_timestamp(1715297148), "2024-05-09"); // Demo for OJ
        assert_eq!(format_unix_timestamp(1714432004), "2024-04-29"); // W/O Certificate
        assert_eq!(format_unix_timestamp(1476599483), "2016-10-16"); // Demo for realtime TTS
    }

    fn make_test_project(name: &str, vendor_key: &str, sign_key: &str, status: i32) -> AgoraApiProject {
        AgoraApiProject {
            id: "test_id".to_string(),
            name: name.to_string(),
            vendor_key: vendor_key.to_string(),
            sign_key: sign_key.to_string(),
            recording_server: None,
            status,
            created: 1736297713,
        }
    }

    #[test]
    fn format_projects_hides_certificates_by_default() {
        let projects = vec![
            make_test_project("MyApp", "appid123", "cert456", 1),
        ];
        let output = format_projects(&projects, false);
        assert!(output.contains("MyApp"));
        assert!(output.contains("appid123"));
        assert!(!output.contains("Certificate:"), "Certificate should be hidden, got:\n{}", output);
        assert!(!output.contains("cert456"), "sign_key should not appear, got:\n{}", output);
    }

    #[test]
    fn format_projects_shows_certificates_when_toggled() {
        let projects = vec![
            make_test_project("MyApp", "appid123", "cert456", 1),
        ];
        let output = format_projects(&projects, true);
        assert!(output.contains("MyApp"));
        assert!(output.contains("appid123"));
        assert!(output.contains("Certificate: cert456"), "Certificate should be visible, got:\n{}", output);
    }

    #[test]
    fn format_projects_shows_none_for_empty_certificate() {
        let projects = vec![
            make_test_project("NoCert", "appid789", "", 1),
        ];
        let output = format_projects(&projects, true);
        assert!(output.contains("Certificate: (none)"), "Empty cert should show (none), got:\n{}", output);
    }

    #[test]
    fn format_projects_empty_list() {
        let output = format_projects(&[], false);
        assert!(output.contains("No projects found"));
    }

    /// Run with: AGORA_CUSTOMER_ID=... AGORA_CUSTOMER_SECRET=... cargo test -- --ignored
    #[tokio::test]
    #[ignore]
    async fn fetch_agora_projects_with_real_credentials() {
        let result = fetch_agora_projects().await;
        assert!(result.is_ok(), "API call failed: {:?}", result.err());

        let projects = result.unwrap();
        assert!(!projects.is_empty(), "Project list should not be empty");

        // Verify known project from the account
        let demo128 = projects.iter().find(|p| p.name == "Demo for 128");
        assert!(demo128.is_some(), "Expected 'Demo for 128' project");
        let demo128 = demo128.unwrap();
        assert_eq!(demo128.vendor_key, "2655d20a82fc47cebcff82d5bd5d53ef");
        assert_eq!(demo128.status, 1);

        // Verify formatting with certificates hidden
        let output_hidden = format_projects(&projects, false);
        assert!(!output_hidden.contains("Certificate:"));
        assert!(output_hidden.contains("Enabled"));

        // Verify formatting with certificates shown
        let output_shown = format_projects(&projects, true);
        assert!(output_shown.contains("Certificate:"));
        // "W/O Certificate" project has empty sign_key
        assert!(output_shown.contains("(none)"));
    }
}

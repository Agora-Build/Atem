use anyhow::Result;
use crossterm::{
    execute,
    terminal::{
        EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode,
        enable_raw_mode,
    },
};
use serde_json::{Value, json};
use std::{
    collections::{HashMap, VecDeque},
    fs,
    io,
    path::PathBuf,
    process::Command,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    sync::mpsc::{UnboundedReceiver, UnboundedSender, error::TryRecvError},
    time::Duration,
};
use vt100::Parser as VtParser;

use crate::agora_api::{AgoraApiProject, fetch_agora_projects, format_projects};
use crate::claude_client::{ClaudeClient, ClaudeResizeHandle};
use crate::codex_client::{CodexClient, CodexResizeHandle};
use crate::command::StreamBuffer;
use crate::dispatch::{TaskDispatcher, WorkItem, WorkKind};
use crate::config::AtemConfig;
use crate::rtm_client::{RtmClient, RtmConfig, RtmEvent};
use crate::token::generate_rtm_token;
use crate::websocket_client::{AstationClient, AstationMessage};
use crate::agent_client::{AgentEvent, AgentInfo, AgentKind, AgentOrigin, AgentProtocol, AgentStatus};
use crate::agent_registry::AgentRegistry;
use crate::acp_client::AcpClient;

pub const AGORA_RTM_TOKEN_TTL_SECS: u32 = 3600;

#[derive(Debug, Clone)]
pub enum AppMode {
    MainMenu,
    TokenGeneration,
    ClaudeChat,
    CodexChat,
    CommandExecution,
    AgentPanel,
}

/// Which CLI backend is currently active for routing commands.
#[derive(Debug, Clone, PartialEq)]
pub enum ActiveCli {
    Claude,
    Codex,
}

#[derive(Debug, Clone)]
pub struct TokenInfo {
    pub token: String,
    pub channel: String,
    pub uid: String,
    pub expires_in: String,
}

pub struct App {
    pub mode: AppMode,
    pub selected_index: usize,
    pub main_menu_items: Vec<String>,
    pub output_text: String,
    pub input_text: String,
    pub show_popup: bool,
    pub popup_message: String,
    pub status_message: Option<String>,
    pub token_info: Option<TokenInfo>,
    pub astation_client: AstationClient,
    pub astation_connected: bool,
    pub codex_client: CodexClient,
    pub codex_output_log: String,
    pub codex_raw_log: String,
    pub codex_user_actions: Vec<String>,
    pub codex_log_file: Option<PathBuf>,
    pub codex_summary_file: Option<PathBuf>,
    pub codex_terminal: VtParser,
    pub codex_sender: Option<UnboundedSender<String>>,
    pub codex_receiver: Option<UnboundedReceiver<String>>,
    pub codex_waiting_exit: bool,
    pub codex_resize_handle: Option<CodexResizeHandle>,
    pub codex_view_rows: u16,
    pub codex_view_cols: u16,
    pub claude_client: ClaudeClient,
    pub claude_output_log: String,
    pub claude_raw_log: String,
    pub claude_user_actions: Vec<String>,
    pub claude_log_file: Option<PathBuf>,
    pub claude_summary_file: Option<PathBuf>,
    pub claude_terminal: VtParser,
    pub claude_sender: Option<UnboundedSender<String>>,
    pub claude_receiver: Option<UnboundedReceiver<String>>,
    pub claude_waiting_exit: bool,
    pub claude_resize_handle: Option<ClaudeResizeHandle>,
    pub claude_view_rows: u16,
    pub claude_view_cols: u16,
    pub force_terminal_redraw: bool,
    pub rtm_client: Option<RtmClient>,
    pub rtm_client_id: String,
    pub last_activity_ping: Option<Instant>,
    pub activity_ping_interval: Duration,
    pub pending_transcriptions: VecDeque<String>,
    pub rtm_token_expires_at: Option<Instant>,
    pub show_certificates: bool,
    pub cached_projects: Vec<AgoraApiProject>,
    pub voice_volume: f32,
    pub voice_active: bool,
    pub video_active: bool,
    pub peer_atems: Vec<crate::websocket_client::AtemInstance>,
    pub voice_fx_tick: u64,
    pub config: AtemConfig,
    pub dispatcher: TaskDispatcher,
    pub work_items: HashMap<String, WorkItem>,
    pub voice_commands: StreamBuffer,
    pub active_cli: ActiveCli,
    pub pinned_cli: Option<ActiveCli>,
    pub pairing_code: Option<String>,
    /// Registry of all known agents (PTY + ACP, launched or discovered).
    pub agent_registry: AgentRegistry,
    /// Live ACP WebSocket connections keyed by agent_id.
    pub acp_clients: HashMap<String, AcpClient>,
    /// ID of the agent currently selected as the active routing target.
    pub active_agent_id: Option<String>,
    /// Cursor position in the AgentPanel list.
    pub agent_panel_selected: usize,
    /// Credentials synced from Astation via WebSocket. Highest priority over env/config.
    pub synced_customer_id: Option<String>,
    pub synced_customer_secret: Option<String>,
}

impl App {
    pub fn new() -> Self {
        let config = crate::config::AtemConfig::load().unwrap_or_default();
        let rtm_client_id = config.rtm_account().to_string();
        Self {
            mode: AppMode::MainMenu,
            selected_index: 0,
            main_menu_items: vec![
                "\u{1f4cb} List Agora Projects".to_string(),
                "\u{1f916} Launch Claude Code".to_string(),
                "\u{1f9e0} Launch Codex".to_string(),
                "\u{1f4bb} Execute Shell Command".to_string(),
                "\u{1f916} Agent Panel".to_string(),
                "\u{2753} Help".to_string(),
                "\u{1f6aa} Exit".to_string(),
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
            rtm_client_id,
            last_activity_ping: None,
            activity_ping_interval: Duration::from_secs(2),
            pending_transcriptions: VecDeque::new(),
            rtm_token_expires_at: None,
            show_certificates: false,
            cached_projects: Vec::new(),
            voice_volume: 0.0,
            voice_active: false,
            video_active: false,
            peer_atems: Vec::new(),
            voice_fx_tick: 0,
            config,
            dispatcher: TaskDispatcher::new(),
            work_items: HashMap::new(),
            voice_commands: StreamBuffer::new(&["execute", "run it", "do it", "go ahead", "send it"]),
            active_cli: ActiveCli::Claude,
            pinned_cli: None,
            pairing_code: None,
            agent_registry: AgentRegistry::new(),
            acp_clients: HashMap::new(),
            active_agent_id: None,
            agent_panel_selected: 0,
            synced_customer_id: None,
            synced_customer_secret: None,
        }
    }

    pub fn next_item(&mut self) {
        if !self.main_menu_items.is_empty() {
            self.selected_index = (self.selected_index + 1) % self.main_menu_items.len();
        }
    }

    pub fn previous_item(&mut self) {
        if !self.main_menu_items.is_empty() {
            self.selected_index = if self.selected_index == 0 {
                self.main_menu_items.len() - 1
            } else {
                self.selected_index - 1
            };
        }
    }

    pub fn update_voice_volume(&mut self, level: f32) {
        self.voice_volume = level.clamp(0.0, 1.0);
        self.voice_active = level > 0.05; // above noise floor
        if self.voice_active {
            self.voice_fx_tick = self.voice_fx_tick.wrapping_add(1);
        }
    }

    pub async fn handle_selection(&mut self) -> Result<()> {
        self.status_message = None;
        match self.selected_index {
            0 => {
                // List Agora Projects
                self.mode = AppMode::TokenGeneration; // Reusing this mode for project listing
                self.output_text = "\u{1f4cb} Fetching Agora Projects...\n\n".to_string();

                if self.astation_connected {
                    // Request projects from Astation
                    if let Err(e) = self.astation_client.request_projects().await {
                        self.output_text = format!(
                            "\u{274c} Failed to request projects from Astation: {}\n\nPress 'b' to go back to main menu",
                            e
                        );
                    } else {
                        self.output_text = "\u{1f4cb} Requesting projects from Astation...\n\nPress 'b' to go back to main menu".to_string();
                    }
                } else {
                    // Priority: synced from Astation > env vars > config file
                    let fetch_result = if let (Some(cid), Some(csecret)) = (
                        self.synced_customer_id.as_deref(),
                        self.synced_customer_secret.as_deref(),
                    ) {
                        crate::agora_api::fetch_agora_projects_with_credentials(cid, csecret).await
                    } else {
                        fetch_agora_projects().await
                    };
                    match fetch_result {
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
                                Configure credentials in ~/.config/atem/config.toml or set\n\
                                AGORA_CUSTOMER_ID and AGORA_CUSTOMER_SECRET environment variables.\n\
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
                self.active_cli = ActiveCli::Claude;

                if self.astation_connected {
                    // Request Claude launch through Astation
                    if let Err(e) = self.astation_client.launch_claude(None).await {
                        self.output_text = format!(
                            "\u{274c} Failed to request Claude launch from Astation: {}\n\nPress 'b' to go back to main menu",
                            e
                        );
                    } else {
                        self.output_text = "\u{1f916} Requesting Claude Code launch from Astation...\n\nPress 'b' to go back to main menu".to_string();
                    }
                } else {
                    // Launch Claude locally via PTY
                    self.input_text.clear();
                    self.claude_waiting_exit = false;
                    if self.claude_output_log.is_empty() {
                        self.claude_output_log = "\u{1f916} Claude Code CLI Session\n\n\
                            Atem routes your input to the Claude Code CLI and streams its replies back here.\n\
                            Type commands in the input box and press Enter to send them to Claude.\n\
                            Press Ctrl+C to end the Claude session and return to the main menu.\n\
                            After a session, press 'u' to save a summary report.\n"
                            .to_string();
                    }

                    match self.ensure_claude_session().await {
                        Ok(new_session_started) => {
                            if new_session_started {
                                self.record_claude_output("\u{1f50c} Claude Code CLI session started.\n");
                            }
                            self.refresh_claude_view();
                        }
                        Err(err) => {
                            self.record_claude_output(format!(
                                "\u{274c} Unable to start Claude Code CLI: {}\n",
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
                self.active_cli = ActiveCli::Codex;
                self.input_text.clear();
                self.codex_waiting_exit = false;
                if self.codex_output_log.is_empty() {
                    self.codex_output_log = "\u{1f9e0} Codex CLI Session\n\n\
                        Atem routes your input to the Codex CLI and streams its replies back here.\n\
                        Type commands in the input box and press Enter to send them to Codex.\n\
                        Press Ctrl+C to end the Codex session and return to the main menu.\n\
                        After a session, press 'u' to save a summary report.\n"
                        .to_string();
                }

                match self.ensure_codex_session().await {
                    Ok(new_session_started) => {
                        if new_session_started {
                            self.record_codex_output("\u{1f50c} Codex CLI session started.\n");
                        }
                        self.refresh_codex_view();
                    }
                    Err(err) => {
                        self.record_codex_output(&format!(
                            "\u{274c} Unable to start Codex CLI: {}\n",
                            err
                        ));
                        self.refresh_codex_view();
                    }
                }
            }
            3 => {
                // Execute Shell Command
                self.mode = AppMode::CommandExecution;
                self.output_text = "\u{1f4bb} Shell Command Mode\n\n\
                    \u{1f4dd} Example commands:\n\
                    \u{2022} atem token rtc create  (generate RTC token)\n\
                    \u{2022} export API_KEY=your_key  (set environment variables)\n\
                    \u{2022} ls -la  (list files)\n\
                    \u{2022} git status  (check git status)\n\
                    \u{2022} claude  (launch Claude AI)\n\n\
                    Type your command and press Enter\n\
                    Press 'b' to go back to main menu"
                    .to_string();
                self.input_text.clear();
            }
            4 => {
                // Agent Panel
                self.mode = AppMode::AgentPanel;
                self.agent_panel_selected = 0;
            }
            5 => {
                // Help
                self.show_help_popup();
            }
            6 => {
                // Exit - handled by caller
            }
            _ => {}
        }
        Ok(())
    }

    pub fn show_help_popup(&mut self) {
        self.show_popup = true;
        self.popup_message = "\u{1f680} Atem - Agora.io AI CLI Tool\n\n\
            Navigation:\n\
            \u{2022} \u{2191}/\u{2193} or j/k: Navigate menu\n\
            \u{2022} Enter: Select item\n\
            \u{2022} c: Copy mode (select/copy text)\n\
            \u{2022} b: Go back\n\
            \u{2022} q: Quit\n\n\
            Features:\n\
            \u{2022} \u{1f4cb} List Agora.io projects\n\
            \u{2022} \u{1f916} Launch Claude Code\n\
            \u{2022} \u{1f9e0} Send tasks to Codex\n\
            \u{2022} \u{1f4bb} Execute shell commands\n\
            \u{2022} \u{1f3af} Generate RTC tokens (via shell)\n\
            \u{2022} Press 'u' in Codex view to save a session summary\n\n\
            Token Generation:\n\
            Use '\u{1f4bb} Execute Shell Command' and run:\n\
            atem token rtc create\n\n\
            Press any key to close this help"
            .to_string();
    }

    pub async fn execute_command(&mut self, command: &str) -> Result<()> {
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
                                Ok(format!("\u{2705} Command '{}' completed successfully.", cmd))
                            } else {
                                Ok(format!("\u{26a0}\u{fe0f} Command '{}' exited with non-zero status.", cmd))
                            }
                        }
                        Err(e) => Ok(format!("\u{274c} Error executing '{}': {}", cmd, e)),
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
                            format!("\u{2705} Environment variable set: {}={}", var_part, val_part)
                        } else {
                            "\u{274c} Invalid export syntax".to_string()
                        }
                    } else {
                        // Execute regular command
                        match Command::new("sh").arg("-c").arg(&cmd).output() {
                            Ok(output) => {
                                let stdout = String::from_utf8_lossy(&output.stdout);
                                let stderr = String::from_utf8_lossy(&output.stderr);
                                format!("{}{}", stdout, stderr)
                            }
                            Err(e) => format!("\u{274c} Error: {}", e),
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

    pub async fn send_codex_prompt(&mut self, prompt: &str) -> Result<()> {
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
                    self.record_codex_output("\u{1f50c} Codex CLI session started.\n");
                }
            }
            Err(err) => {
                self.record_codex_output(&format!("\u{274c} Unable to start Codex CLI: {}\n", err));
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
                self.record_codex_output("\u{26a0}\u{fe0f} Codex CLI session is unavailable (send failed).\n");
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
            self.record_codex_output("\u{26a0}\u{fe0f} Codex CLI session is unavailable.\n");
        }

        self.refresh_codex_view();
        Ok(())
    }

    pub async fn ensure_codex_session(&mut self) -> Result<bool> {
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

    pub fn record_codex_output(&mut self, data: impl AsRef<str>) {
        let text = data.as_ref();
        self.codex_raw_log.push_str(text);

        self.codex_terminal.process(text.as_bytes());
        self.update_codex_output_from_terminal();
    }

    pub fn update_codex_output_from_terminal(&mut self) {
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

    pub fn send_codex_data(&mut self, data: &str) {
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

    pub fn respond_codex_cursor_position(&mut self) {
        let (row, col) = self.codex_terminal.screen().cursor_position();
        let response = format!("\u{1b}[{};{}R", row + 1, col + 1);
        self.send_codex_data(&response);
    }

    pub fn handle_codex_control_sequences(&mut self, chunk: &str) {
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

    pub fn refresh_codex_view(&mut self) {
        if matches!(self.mode, AppMode::CodexChat) {
            self.output_text = self.codex_output_log.clone();
        }
    }

    pub fn rebuild_codex_terminal(&mut self) {
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

    pub fn adjust_codex_terminal_size(&mut self, rows: u16, cols: u16) {
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

    pub fn process_codex_output(&mut self) {
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
            new_chunks.push("\u{26a0}\u{fe0f} Codex CLI session disconnected.\n".to_string());
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

    pub async fn ensure_rtm_client(&mut self) -> Result<()> {
        let needs_new_client = self.rtm_client.is_none()
            || self
                .rtm_token_expires_at
                .map(|expiry| expiry <= Instant::now())
                .unwrap_or(true);

        if !needs_new_client {
            return Ok(());
        }

        // Resolve app_id and certificate from active project
        let app_id = match crate::config::ActiveProject::resolve_app_id(None) {
            Ok(id) => id,
            Err(err) => {
                self.status_message = Some(format!("RTM: {}", err));
                return Err(err);
            }
        };
        let app_certificate = match crate::config::ActiveProject::resolve_app_certificate(None) {
            Ok(cert) => cert,
            Err(err) => {
                self.status_message = Some(format!("RTM: {}", err));
                return Err(err);
            }
        };

        let rtm_account = self.config.rtm_account().to_string();
        let rtm_channel = self.config.rtm_channel().to_string();

        let token = generate_rtm_token(
            &app_id,
            &app_certificate,
            &rtm_account,
            AGORA_RTM_TOKEN_TTL_SECS,
        );

        let config = RtmConfig {
            app_id,
            token: token.clone(),
            channel: rtm_channel.clone(),
            client_id: self.rtm_client_id.clone(),
        };

        let client = RtmClient::new(config).map_err(|err| {
            self.status_message = Some(format!("Failed to connect to Astation signaling: {}", err));
            err
        })?;

        if let Err(err) = client
            .login_and_join(&token, &rtm_account, &rtm_channel)
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

    pub async fn send_activity_ping(&mut self, focused: bool) -> Result<()> {
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

    pub async fn maybe_send_activity_ping(&mut self, focused: bool) {
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

    pub async fn process_rtm_messages(&mut self) -> Result<()> {
        if let Some(client) = &self.rtm_client {
            let events = client.drain_events().await;
            for event in events {
                self.handle_rtm_event(event);
            }
        }

        self.flush_pending_transcriptions().await?;
        Ok(())
    }

    pub fn handle_rtm_event(&mut self, event: RtmEvent) {
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

    pub async fn flush_pending_transcriptions(&mut self) -> Result<()> {
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

    pub async fn register_local_activity(&mut self, focused: bool) {
        self.maybe_send_activity_ping(focused).await;
    }

    pub fn finalize_codex_session(&mut self) {
        if !matches!(self.mode, AppMode::CodexChat) {
            return;
        }

        let had_activity_before_finalize = !self.codex_raw_log.trim().is_empty();

        self.record_codex_output("\u{2699}\u{fe0f} Codex CLI session ended.\n");

        let mut status_parts: Vec<String> = Vec::new();

        if had_activity_before_finalize {
            match self.persist_codex_log() {
                Ok(Some(path)) => {
                    let msg = format!("\u{1f4dd} Codex log saved to {}", path.display());
                    self.record_codex_output(&format!("{}\n", msg));
                    status_parts.push(msg);
                }
                Ok(None) => {
                    status_parts.push("Codex session ended with no output to save.".to_string());
                }
                Err(err) => {
                    let msg = format!("\u{26a0}\u{fe0f} Failed to save Codex log: {}", err);
                    self.record_codex_output(&format!("{}\n", msg));
                    status_parts.push(msg);
                }
            }

            let summary = self.generate_codex_summary();
            match self.write_codex_summary_file(&summary) {
                Ok(path) => {
                    let msg = format!("\u{1f4c4} Summary saved to {}", path.display());
                    self.record_codex_output(&format!("{}\n", msg));
                    status_parts.push(msg);
                }
                Err(err) => {
                    let msg = format!("\u{26a0}\u{fe0f} Failed to save Codex summary: {}", err);
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

    pub fn persist_codex_log(&mut self) -> Result<Option<PathBuf>> {
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

    pub fn generate_codex_summary(&self) -> String {
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
                summary.push_str("- \u{2026}\n");
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

    pub fn write_codex_summary_file(&mut self, summary: &str) -> Result<PathBuf> {
        let dir = PathBuf::from("codex_logs");
        fs::create_dir_all(&dir)?;
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let path = dir.join(format!("codex-summary-{}.md", timestamp));
        fs::write(&path, summary)?;
        self.codex_summary_file = Some(path.clone());
        Ok(path)
    }

    pub async fn send_claude_prompt(&mut self, prompt: &str) -> Result<()> {
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
                    self.record_claude_output("\u{1f50c} Claude Code CLI session started.\n");
                }
            }
            Err(err) => {
                self.record_claude_output(format!(
                    "\u{274c} Unable to start Claude Code CLI: {}\n",
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
                    "\u{26a0}\u{fe0f} Claude Code CLI session is unavailable (send failed).\n",
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
            self.record_claude_output("\u{26a0}\u{fe0f} Claude Code CLI session is unavailable.\n");
        }

        self.refresh_claude_view();
        Ok(())
    }

    pub async fn ensure_claude_session(&mut self) -> Result<bool> {
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

        // Register (or re-register) the Claude PTY session in the agent registry.
        // We generate a stable ID by checking if one already exists for a Launched
        // Claude PTY; if not, mint a new one.
        let existing_id = self
            .agent_registry
            .by_protocol(AgentProtocol::Pty)
            .into_iter()
            .find(|a| a.kind == AgentKind::ClaudeCode && a.origin == AgentOrigin::Launched)
            .map(|a| a.id);
        let agent_id = existing_id.unwrap_or_else(|| {
            format!("claude-pty-{}", uuid::Uuid::new_v4())
        });
        self.agent_registry.register(AgentInfo {
            id: agent_id.clone(),
            name: "claude-code".to_string(),
            kind: AgentKind::ClaudeCode,
            protocol: AgentProtocol::Pty,
            origin: AgentOrigin::Launched,
            status: AgentStatus::Idle,
            session_ids: vec![],
            acp_url: None,
            pty_pid: None,
        });

        Ok(true)
    }

    /// Scan lockfiles for externally started agents and register them.
    ///
    /// Called once at startup (or on demand).  Agents that are already in
    /// the registry (same ACP URL) are skipped.
    pub async fn startup_scan_agents(&mut self) {
        use crate::agent_detector::scan_lockfiles;

        let detected = scan_lockfiles();
        for agent in detected {
            if self.agent_registry.has_acp_url(&agent.acp_url) {
                continue; // already registered
            }
            let id = format!(
                "{}-ext-{}",
                agent.kind,
                agent.pid.map(|p| p.to_string()).unwrap_or_else(|| uuid::Uuid::new_v4().to_string())
            );
            self.agent_registry.register(AgentInfo {
                id,
                name: agent.kind.to_string(),
                kind: agent.kind,
                protocol: AgentProtocol::Acp,
                origin: AgentOrigin::External,
                status: AgentStatus::Idle,
                session_ids: vec![],
                acp_url: Some(agent.acp_url),
                pty_pid: agent.pid,
            });
        }

        // Push current agent list to Astation so the UI is immediately up-to-date.
        let agents = self.agent_registry.all();
        if !agents.is_empty() {
            let _ = self.astation_client.send_agent_list(agents).await;
        }
    }

    /// Connect to an ACP agent by ID, run the handshake, and store the live
    /// client.  The agent must already be in the registry with an `acp_url`.
    pub async fn connect_acp_agent(&mut self, agent_id: &str) -> anyhow::Result<()> {
        let info = self
            .agent_registry
            .get(agent_id)
            .ok_or_else(|| anyhow::anyhow!("Unknown agent: {}", agent_id))?;

        let url = info
            .acp_url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("Agent {} has no ACP URL", agent_id))?
            .to_string();

        let mut client = AcpClient::connect(&url).await?;
        let server_info = client.initialize().await?;
        let _session_id = client.new_session().await?;

        // Update kind from the server's own name
        self.status_message = Some(format!(
            "\u{1f517} Agent connected: {} ({} v{})",
            agent_id, server_info.kind, server_info.version
        ));

        self.agent_registry.update_status(agent_id, AgentStatus::Idle);
        self.acp_clients.insert(agent_id.to_string(), client);
        Ok(())
    }

    /// Poll all live ACP clients for pending events and forward them to
    /// Astation as `agentEvent` messages.  Called every TUI tick.
    pub async fn poll_acp_events(&mut self) {
        // Collect events per agent first (to avoid borrow issues)
        let agent_ids: Vec<String> = self.acp_clients.keys().cloned().collect();

        for agent_id in agent_ids {
            let events = {
                let client = self.acp_clients.get_mut(&agent_id).unwrap();
                client.drain_events()
            };
            if events.is_empty() {
                continue;
            }

            let session_id = self
                .acp_clients
                .get(&agent_id)
                .and_then(|c| c.session_id().map(|s| s.to_string()))
                .unwrap_or_default();

            let mut disconnected = false;
            for event in &events {
                // Update registry status
                match event {
                    AgentEvent::TextDelta(_) | AgentEvent::ToolCall { .. } => {
                        self.agent_registry
                            .update_status(&agent_id, AgentStatus::Thinking);
                    }
                    AgentEvent::Done => {
                        self.agent_registry
                            .update_status(&agent_id, AgentStatus::Idle);
                    }
                    AgentEvent::Disconnected => {
                        self.agent_registry
                            .update_status(&agent_id, AgentStatus::Disconnected);
                        disconnected = true;
                    }
                    _ => {}
                }
                // Forward to Astation
                let _ = self
                    .astation_client
                    .send_agent_event(&agent_id, &session_id, event)
                    .await;
            }

            if disconnected {
                self.acp_clients.remove(&agent_id);
            }
        }
    }

    pub fn record_claude_output(&mut self, data: impl AsRef<str>) {
        let text = data.as_ref();
        self.claude_raw_log.push_str(text);

        self.claude_terminal.process(text.as_bytes());
        self.update_claude_output_from_terminal();
    }

    pub fn update_claude_output_from_terminal(&mut self) {
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

    pub fn send_claude_data(&mut self, data: &str) {
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

    pub fn respond_claude_cursor_position(&mut self) {
        let (row, col) = self.claude_terminal.screen().cursor_position();
        let response = format!("\u{1b}[{};{}R", row + 1, col + 1);
        self.send_claude_data(&response);
    }

    pub fn handle_claude_control_sequences(&mut self, chunk: &str) {
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

    pub fn refresh_claude_view(&mut self) {
        if matches!(self.mode, AppMode::ClaudeChat) && !self.astation_connected {
            self.output_text = self.claude_output_log.clone();
        }
    }

    pub fn rebuild_claude_terminal(&mut self) {
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

    pub fn adjust_claude_terminal_size(&mut self, rows: u16, cols: u16) {
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

    pub fn process_claude_output(&mut self) {
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
            new_chunks.push("\u{26a0}\u{fe0f} Claude Code CLI session disconnected.\n".to_string());
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

    pub fn finalize_claude_session(&mut self) {
        if !matches!(self.mode, AppMode::ClaudeChat) || self.astation_connected {
            return;
        }

        // If there's an active mark task, flag it for async finalization
        self.dispatcher.set_main_needs_finalize();

        let had_activity_before_finalize = !self.claude_raw_log.trim().is_empty();

        self.record_claude_output("\u{2699}\u{fe0f} Claude Code CLI session ended.\n");

        let mut status_parts: Vec<String> = Vec::new();

        if had_activity_before_finalize {
            match self.persist_claude_log() {
                Ok(Some(path)) => {
                    let msg = format!("\u{1f4dd} Claude log saved to {}", path.display());
                    self.record_claude_output(format!("{}\n", msg));
                    status_parts.push(msg);
                }
                Ok(None) => {
                    status_parts
                        .push("Claude session ended with no output to save.".to_string());
                }
                Err(err) => {
                    let msg = format!("\u{26a0}\u{fe0f} Failed to save Claude log: {}", err);
                    self.record_claude_output(format!("{}\n", msg));
                    status_parts.push(msg);
                }
            }

            let summary = self.generate_claude_summary();
            match self.write_claude_summary_file(&summary) {
                Ok(path) => {
                    let msg = format!("\u{1f4c4} Summary saved to {}", path.display());
                    self.record_claude_output(format!("{}\n", msg));
                    status_parts.push(msg);
                }
                Err(err) => {
                    let msg = format!("\u{26a0}\u{fe0f} Failed to save Claude summary: {}", err);
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

    pub fn persist_claude_log(&mut self) -> Result<Option<PathBuf>> {
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

    pub fn generate_claude_summary(&self) -> String {
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
                summary.push_str("- \u{2026}\n");
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

    pub fn write_claude_summary_file(&mut self, summary: &str) -> Result<PathBuf> {
        let dir = PathBuf::from("claude_logs");
        fs::create_dir_all(&dir)?;
        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let path = dir.join(format!("claude-summary-{}.md", timestamp));
        fs::write(&path, summary)?;
        self.claude_summary_file = Some(path.clone());
        Ok(path)
    }

    pub async fn try_connect_astation(&mut self) -> Result<()> {
        if !self.astation_connected {
            match self.astation_client.connect_with_pairing(&self.config).await {
                Ok(code) => {
                    self.astation_connected = true;
                    self.pairing_code = Some(code);
                    self.status_message = Some("Connected to Astation".to_string());
                }
                Err(_) => {
                    // Fall back to direct URL connection
                    let url = self.config.astation_ws().to_string();
                    match self.astation_client.connect(&url).await {
                        Ok(_) => {
                            self.astation_connected = true;
                            self.status_message = Some("Connected to Astation".to_string());
                        }
                        Err(_) => {
                            // Continue in local mode (no Astation)
                        }
                    }
                }
            }
        }
        Ok(())
    }

    pub async fn handle_astation_message(&mut self, message: AstationMessage) {
        match message {
            AstationMessage::ProjectListResponse {
                projects,
                timestamp: _,
            } => {
                let projects_info = projects
                    .iter()
                    .map(|p| {
                        format!(
                            "\u{2022} {} (ID: {}) - {} [{}]",
                            p.name, p.id, p.description, p.status
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");

                self.output_text = format!(
                    "\u{1f4cb} Agora Projects List (from Astation)\n\n\
                    {}\n\n\
                    \u{1f4a1} To generate RTC tokens, use:\n\
                    \u{2022} Go to '\u{1f4bb} Execute Shell Command'\n\
                    \u{2022} Run: atem token rtc create --channel <name> --uid <id>\n\n\
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
                    "\u{1f511} RTC Token Generated (from Astation):\n\n\
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
                        "\u{2705} Claude Code launched from Astation: {}\n\nPress 'b' to go back to main menu",
                        message
                    );
                } else {
                    self.output_text = format!(
                        "\u{274c} Failed to launch Claude Code from Astation: {}\n\nPress 'b' to go back to main menu",
                        message
                    );
                }
            }
            AstationMessage::StatusUpdate { status: _, data: _ } => {
                // Status updates are informational; ignore in TUI
            }
            AstationMessage::CodexTaskResponse {
                output,
                success,
                timestamp: _,
            } => {
                if success {
                    self.record_codex_output(&format!("\u{1f9e0} [Astation] {}\n", output));
                } else {
                    self.record_codex_output(&format!("\u{274c} [Astation] {}\n", output));
                }

                if matches!(self.mode, AppMode::CodexChat) {
                    self.refresh_codex_view();
                } else if success {
                    self.output_text = format!("\u{1f9e0} Codex response (via Astation):\n\n{}", output);
                } else {
                    self.output_text = format!("\u{274c} Codex task failed (via Astation): {}", output);
                }
            }
            AstationMessage::VolumeUpdate { level } => {
                self.update_voice_volume(level);
            }
            AstationMessage::VoiceToggle { active } => {
                self.voice_active = active;
            }
            AstationMessage::VideoToggle { active } => {
                self.video_active = active;
            }
            AstationMessage::AtemInstanceList { instances } => {
                self.peer_atems = instances;
            }
            AstationMessage::VoiceCommand { text, is_final } => {
                self.handle_voice_command(&text, is_final).await;
            }
            AstationMessage::MarkTaskAssignment { task_id, received_at_ms } => {
                self.status_message = Some(format!("\u{1f4cc} Task received: {}", task_id));
                match self.load_and_build_work_item(&task_id, received_at_ms) {
                    Ok(item) => {
                        let main_busy = self.dispatcher.main_is_active();
                        self.work_items.insert(task_id.clone(), item.clone());
                        self.dispatcher.submit(item, main_busy);
                        self.try_dispatch_main().await;
                    }
                    Err(err) => {
                        self.status_message = Some(format!("\u{274c} Failed to load task {}: {}", task_id, err));
                        let _ = self
                            .astation_client
                            .send_mark_result(&task_id, false, &format!("Failed to load task: {}", err))
                            .await;
                    }
                }
            }
            AstationMessage::UserCommand { command, context } => {
                let action = context.get("action").map(|s| s.as_str()).unwrap_or("cli_input");
                match action {
                    "cli_input" => {
                        let target = self.pinned_cli.clone().unwrap_or(self.active_cli.clone());
                        match target {
                            ActiveCli::Claude => { self.send_claude_prompt(&command).await.ok(); }
                            ActiveCli::Codex => { self.send_codex_prompt(&command).await.ok(); }
                        }
                    }
                    "claude_input" => { self.send_claude_prompt(&command).await.ok(); }
                    "codex_input" => { self.send_codex_prompt(&command).await.ok(); }
                    "shell" => { self.execute_command(&command).await.ok(); }
                    _ => { self.send_claude_prompt(&command).await.ok(); }
                }
                self.status_message = Some(format!(
                    "Received command: {}",
                    &command[..command.len().min(50)]
                ));
            }
            AstationMessage::GenerateExplainer {
                topic,
                context,
                request_id,
            } => {
                self.status_message = Some(format!("\u{1f5bc} Generating explainer: {}", topic));
                match crate::visual_explainer::VisualExplainer::new() {
                    Ok(explainer) => {
                        match explainer.generate(&topic, context.as_deref()).await {
                            Ok(html) => {
                                let _ = self
                                    .astation_client
                                    .send_explainer_result(request_id, &topic, &html)
                                    .await;
                            }
                            Err(e) => {
                                self.status_message = Some(format!("\u{274c} Explainer failed: {}", e));
                                let _ = self
                                    .astation_client
                                    .send_explainer_error(request_id, &topic, &e.to_string())
                                    .await;
                            }
                        }
                    }
                    Err(e) => {
                        self.status_message = Some(format!("\u{274c} VisualExplainer init failed: {}", e));
                        let _ = self
                            .astation_client
                            .send_explainer_error(request_id, &topic, &e.to_string())
                            .await;
                    }
                }
            }
            AstationMessage::AgentListRequest => {
                let agents = self.agent_registry.all();
                let _ = self.astation_client.send_agent_list(agents).await;
            }
            AstationMessage::AgentPrompt {
                agent_id,
                session_id,
                text,
            } => {
                // Route to the appropriate backend.
                let agent = self.agent_registry.get(&agent_id);
                match agent {
                    None => {
                        self.status_message = Some(format!("\u{274c} Unknown agent: {}", agent_id));
                    }
                    Some(info) => match info.protocol {
                        AgentProtocol::Pty => {
                            // Route to the active PTY based on agent kind.
                            match info.kind {
                                AgentKind::ClaudeCode => {
                                    let _ = self.send_claude_prompt(&text).await;
                                }
                                AgentKind::Codex => {
                                    let _ = self.send_codex_prompt(&text).await;
                                }
                                AgentKind::Unknown(_) => {
                                    self.status_message = Some("\u{274c} No PTY route for unknown agent kind".to_string());
                                }
                            }
                        }
                        AgentProtocol::Acp => {
                            // Try the live client first; connect on demand if needed.
                            if !self.acp_clients.contains_key(&agent_id) {
                                if let Err(e) = self.connect_acp_agent(&agent_id).await {
                                    self.status_message = Some(format!("\u{274c} ACP connect failed for {}: {}", agent_id, e));
                                }
                            }
                            if let Some(acp) = self.acp_clients.get_mut(&agent_id) {
                                if let Err(e) = acp.send_prompt(&text) {
                                    self.status_message = Some(format!("\u{274c} ACP send failed: {}", e));
                                } else {
                                    self.agent_registry
                                        .update_status(&agent_id, AgentStatus::Thinking);
                                }
                            }
                        }
                    },
                }
            }
            AstationMessage::CredentialSync {
                customer_id,
                customer_secret,
            } => {
                let id_preview = customer_id[..4.min(customer_id.len())].to_string();

                // Store in memory for this session.
                self.synced_customer_id = Some(customer_id.clone());
                self.synced_customer_secret = Some(customer_secret.clone());

                // Persist to config file so CLI commands (e.g. `atem list project`) can use them.
                let mut cfg = crate::config::AtemConfig::load().unwrap_or_default();
                cfg.customer_id = Some(customer_id);
                cfg.customer_secret = Some(customer_secret);
                if let Err(e) = cfg.save_to_disk() {
                    self.status_message = Some(format!("\u{26a0}\u{fe0f} Could not save credentials: {}", e));
                } else {
                    self.status_message = Some(format!("\u{1f511} Credentials synced ({}...)", id_preview));
                }
            }
            _ => {
                // Unknown/unhandled message type — ignore silently
            }
        }
    }

    // MARK: - Mark Task Processing

    /// Load task JSON from disk and build a WorkItem with the assembled prompt.
    pub fn load_and_build_work_item(&self, task_id: &str, received_at_ms: u64) -> Result<WorkItem> {
        let task_path = PathBuf::from(".chisel/tasks").join(format!("{}.json", task_id));
        let task_json = fs::read_to_string(&task_path)
            .map_err(|e| anyhow::anyhow!("Failed to read task file: {}", e))?;
        let task: Value = serde_json::from_str(&task_json)
            .map_err(|e| anyhow::anyhow!("Failed to parse task JSON: {}", e))?;
        let prompt = self.build_mark_task_prompt(&task);
        Ok(WorkItem {
            task_id: task_id.to_string(),
            received_at_ms,
            kind: WorkKind::MarkTask,
            prompt,
        })
    }

    /// Pop the next task from the dispatcher's main queue and send it to the Claude PTY.
    pub async fn try_dispatch_main(&mut self) {
        if self.dispatcher.main_is_active() {
            return;
        }

        let task_id = match self.dispatcher.next_for_main() {
            Some(id) => id,
            None => return,
        };

        let item = match self.work_items.get(&task_id) {
            Some(item) => item.clone(),
            None => {
                self.status_message = Some(format!("\u{274c} Task item not found: {}", task_id));
                self.dispatcher.complete_main();
                return;
            }
        };

        // Ensure Claude session and send the prompt
        self.mode = AppMode::ClaudeChat;
        self.input_text.clear();
        self.claude_waiting_exit = false;
        if self.claude_output_log.is_empty() {
            self.claude_output_log = "\u{1f916} Claude Code CLI Session (Mark Task)\n\n".to_string();
        }

        match self.ensure_claude_session().await {
            Ok(new_session_started) => {
                if new_session_started {
                    self.record_claude_output("\u{1f50c} Claude Code CLI session started for mark task.\n");
                }
            }
            Err(err) => {
                eprintln!("\u{274c} Failed to start Claude session for task {}: {}", task_id, err);
                let _ = self
                    .astation_client
                    .send_mark_result(&task_id, false, &format!("Failed to start Claude: {}", err))
                    .await;
                self.dispatcher.complete_main();
                self.work_items.remove(&task_id);
                // Try next task
                Box::pin(self.try_dispatch_main()).await;
                return;
            }
        }

        // Send prompt to Claude via PTY
        self.record_claude_output(format!("> [Mark Task {}]\n", task_id));
        self.claude_user_actions.push(format!("[Mark Task {}]", task_id));

        if self.claude_sender.is_some() {
            self.send_claude_data(&item.prompt);
            if self.claude_sender.is_some() {
                self.send_claude_data("\n");
            }
            if self.claude_sender.is_some() {
                self.send_claude_data("\r");
            }
        }

        self.refresh_claude_view();
        self.status_message = Some(format!("\u{1f4cc} Task {} → Claude", task_id));
    }

    fn build_mark_task_prompt(&self, task: &Value) -> String {
        let mut prompt = String::new();

        prompt.push_str("You have a UI annotation task from Chisel Dev. ");
        prompt.push_str("A user drew annotations on a screenshot of their web app and wants you to implement the changes.\n\n");

        if let Some(url) = task.get("url").and_then(|v| v.as_str()) {
            prompt.push_str(&format!("Page URL: {}\n", url));
        }
        if let Some(title) = task.get("title").and_then(|v| v.as_str()) {
            prompt.push_str(&format!("Page title: {}\n", title));
        }

        // Screenshot path for vision
        if let Some(screenshot) = task.get("screenshot").and_then(|v| v.as_str()) {
            prompt.push_str(&format!("\nScreenshot (annotated): {}\n", screenshot));
            prompt.push_str("Please look at this screenshot to understand the visual context.\n");
        }

        // Annotations
        if let Some(annotations) = task.get("annotations").and_then(|v| v.as_array()) {
            prompt.push_str(&format!("\nAnnotations ({}):\n", annotations.len()));
            for (i, ann) in annotations.iter().enumerate() {
                let tool = ann.get("tool").and_then(|v| v.as_str()).unwrap_or("unknown");
                let text = ann.get("text").and_then(|v| v.as_str()).unwrap_or("");
                let x = ann.get("x").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let y = ann.get("y").and_then(|v| v.as_f64()).unwrap_or(0.0);
                prompt.push_str(&format!(
                    "  {}. [{}] at ({:.0}, {:.0})",
                    i + 1,
                    tool,
                    x,
                    y
                ));
                if !text.is_empty() {
                    prompt.push_str(&format!(" — \"{}\"", text));
                }
                prompt.push('\n');
            }
        }

        // Source files
        if let Some(files) = task.get("sourceFiles").and_then(|v| v.as_array()) {
            prompt.push_str(&format!("\nProject source files ({} files available):\n", files.len()));
            for f in files.iter().take(20) {
                if let Some(path) = f.as_str() {
                    prompt.push_str(&format!("  - {}\n", path));
                }
            }
            if files.len() > 20 {
                prompt.push_str(&format!("  ... and {} more\n", files.len() - 20));
            }
        }

        prompt.push_str("\nPlease implement the changes indicated by the annotations. ");
        prompt.push_str("Focus on the visual changes the user has marked up.");

        prompt
    }

    /// Called when a Claude session ends to report mark task result and dispatch next queued task.
    pub async fn finalize_mark_task(&mut self, success: bool) {
        if let Some(task_id) = self.dispatcher.complete_main() {
            let message = if success {
                "Task completed by Claude"
            } else {
                "Claude session ended before completing task"
            };
            let _ = self
                .astation_client
                .send_mark_result(&task_id, success, message)
                .await;
            self.work_items.remove(&task_id);

            // Dispatch next queued task
            self.try_dispatch_main().await;
        }
    }

    // MARK: - Voice Command Processing

    /// Handle an incoming voice command chunk from Astation.
    /// Buffers text until a trigger word is detected (or is_final is set),
    /// then sends the accumulated text to Claude Code via PTY.
    pub async fn handle_voice_command(&mut self, text: &str, is_final: bool) {
        self.voice_commands.push(text);

        let should_send = is_final || self.voice_commands.detect_trigger();

        if should_send && self.voice_commands.has_content() {
            let command = self.voice_commands.take();

            self.status_message = Some(format!("\u{1f3a4} Voice: {}", command));

            // Send to Claude Code
            if let Err(err) = self.send_claude_prompt(&command).await {
                self.status_message =
                    Some(format!("Failed to send voice command to Claude: {}", err));
            }
        }
    }

    pub async fn process_astation_messages(&mut self) {
        if let Some(message) = self.astation_client.recv_message().await {
            self.handle_astation_message(message).await;
        }
    }
}

pub fn current_timestamp_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_active_cli_default_is_claude() {
        let app = App::new();
        assert_eq!(app.active_cli, ActiveCli::Claude);
    }

    #[test]
    fn test_active_cli_equality() {
        assert_eq!(ActiveCli::Claude, ActiveCli::Claude);
        assert_eq!(ActiveCli::Codex, ActiveCli::Codex);
        assert_ne!(ActiveCli::Claude, ActiveCli::Codex);
        assert_ne!(ActiveCli::Codex, ActiveCli::Claude);
    }

    #[test]
    fn test_pinned_cli_default_is_none() {
        let app = App::new();
        assert!(app.pinned_cli.is_none());
    }

    #[test]
    fn test_pairing_code_default_is_none() {
        let app = App::new();
        assert!(app.pairing_code.is_none());
    }
}

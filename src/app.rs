mod terminal;

use anyhow::Result;
use crossterm::{
    execute,
    terminal::{
        EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode,
        enable_raw_mode,
    },
};
use serde_json::Value;
use std::{
    collections::{HashMap, VecDeque},
    fs,
    io,
    path::PathBuf,
    process::Command,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
use tokio::time::Duration;
use vt100::Parser as VtParser;

use crate::agora_api::{BffProject, format_projects};
use crate::claude_client::{ClaudeClient, ClaudeResizeHandle};
use crate::codex_client::{CodexClient, CodexResizeHandle};
use crate::command::StreamBuffer;
use crate::dispatch::{TaskDispatcher, WorkItem, WorkKind};
use crate::config::AtemConfig;
use crate::rtm_client::{RtmClient, RtmEvent};
use crate::websocket_client::{AstationClient, AstationMessage};
use crate::agent_client::{AgentEvent, AgentInfo, AgentKind, AgentOrigin, AgentProtocol, AgentStatus};
use crate::agent_registry::AgentRegistry;
use crate::acp_client::AcpClient;

#[derive(Debug, Clone)]
pub enum AppMode {
    MainMenu,
    TokenGeneration,
    ClaudeChat,
    CodexChat,
    CommandExecution,
    AgentPanel,
}

/// Actions available in the main menu. The menu is rebuilt dynamically
/// based on whether Atem is paired with Astation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MenuAction {
    ListProjects,
    LaunchClaude,
    LaunchCodex,
    ExecuteShell,
    AgentPanel,
    Help,
    Exit,
}

/// Which CLI backend is currently active for routing commands.
#[derive(Debug, Clone, PartialEq)]
pub enum ActiveCli {
    Claude,
    Codex,
}

pub struct App {
    pub last_session_refresh: Option<Instant>,
    pub terminal_outbox: VecDeque<crate::terminal_share::Message>,
    pub mode: AppMode,
    pub selected_index: usize,
    pub main_menu_items: Vec<String>,
    pub menu_actions: Vec<MenuAction>,
    pub output_text: String,
    pub input_text: String,
    pub show_popup: bool,
    pub popup_message: String,
    pub status_message: Option<String>,
    pub astation_client: AstationClient,
    pub astation_connected: bool,
    /// Astation instance ID when currently connected (from CredentialSync or auth flow).
    pub connected_astation_id: Option<String>,
    pub codex_client: CodexClient,
    pub codex_output_log: String,
    pub codex_raw_log: String,
    pub codex_raw_log_start: usize,
    pub codex_user_actions: Vec<String>,
    pub codex_log_file: Option<PathBuf>,
    pub codex_summary_file: Option<PathBuf>,
    pub codex_terminal: VtParser,
    pub codex_sender: Option<crate::pty_session::PtyInput>,
    pub codex_receiver: Option<tokio::sync::mpsc::Receiver<crate::pty_session::PtyEvent>>,
    pub codex_share: Option<crate::terminal_share::SharedTerminal>,
    pub codex_waiting_exit: bool,
    pub codex_resize_handle: Option<CodexResizeHandle>,
    pub codex_view_rows: u16,
    pub codex_view_cols: u16,
    pub claude_client: ClaudeClient,
    pub claude_output_log: String,
    pub claude_raw_log: String,
    pub claude_raw_log_start: usize,
    pub claude_user_actions: Vec<String>,
    pub claude_log_file: Option<PathBuf>,
    pub claude_summary_file: Option<PathBuf>,
    pub claude_terminal: VtParser,
    pub claude_sender: Option<crate::pty_session::PtyInput>,
    pub claude_receiver: Option<tokio::sync::mpsc::Receiver<crate::pty_session::PtyEvent>>,
    pub claude_share: Option<crate::terminal_share::SharedTerminal>,
    pub claude_waiting_exit: bool,
    pub claude_resize_handle: Option<ClaudeResizeHandle>,
    pub claude_view_rows: u16,
    pub claude_view_cols: u16,
    pub force_terminal_redraw: bool,
    pub terminal_ui: crate::tui::terminal_view::State,
    pub rtm_client: Option<RtmClient>,
    pub rtm_client_id: String,
    pub last_activity_ping: Option<Instant>,
    pub activity_ping_interval: Duration,
    pub pending_transcriptions: VecDeque<String>,
    pub rtm_token_expires_at: Option<Instant>,
    pub show_certificates: bool,
    pub cached_projects: Vec<BffProject>,
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
    /// Background Astation connection result channel (set up at startup).
    pub astation_connect_rx: Option<tokio::sync::oneshot::Receiver<
        Result<(crate::websocket_client::AstationClient, Option<String>)>
    >>,
    /// When to next retry the Astation connection.
    /// Uses `Instant` (monotonic clock — pauses during system sleep on both Linux and macOS),
    /// so retries only fire when the device is actively awake. No battery drain while sleeping.
    pub astation_reconnect_at: Option<Instant>,
    /// Pending command from Astation waiting for output relay.
    pub pending_astation_command: Option<PendingAstationCommand>,
    /// Pending voice coding request waiting for Claude to finish.
    pub pending_voice_request: Option<PendingVoiceRequest>,
    /// Pending visualize request waiting for agent to write HTML diagram.
    pub pending_visualize: Option<PendingVisualize>,
}

/// Tracks a command sent from Astation that needs output relayed back.
#[derive(Debug, Clone)]
pub struct PendingAstationCommand {
    pub target: ActiveCli,
    pub output_start_pos: usize, // Position in output_log where command output starts
    pub sent_at: Instant,
}

/// Tracks a visualize request waiting for the agent to write an HTML diagram.
#[derive(Debug, Clone)]
pub struct PendingVisualize {
    pub session_id: String,
    pub relay_url: Option<String>,
    pub sent_at: Instant,
    pub pre_snapshot: HashMap<PathBuf, SystemTime>,
    pub detected_file: Option<String>,
    pub output_snapshot_len: usize,
    pub last_output_at: Instant,
}

/// Map an `agentInput` control-key name (from Astation) to the raw byte
/// sequence written to the agent PTY. Returns None for an unknown key.
pub fn agent_key_to_bytes(key: &str) -> Option<&'static str> {
    match key {
        "enter" => Some("\r"),
        "esc" => Some("\x1b"),
        "ctrl-c" => Some("\x03"),
        "up" => Some("\x1b[A"),
        "down" => Some("\x1b[B"),
        "left" => Some("\x1b[D"),
        "right" => Some("\x1b[C"),
        "y" => Some("y"),
        "n" => Some("n"),
        _ => None,
    }
}

/// Tracks a voice coding request waiting for Claude to finish.
#[derive(Debug, Clone)]
pub struct PendingVoiceRequest {
    pub session_id: String,
    pub relay_url: String,
    pub sent_at: Instant,
    pub output_snapshot_len: usize,
    pub last_output_at: Instant,
}

impl App {
    pub fn new() -> Self {
        let config = crate::config::AtemConfig::load().unwrap_or_default();
        let rtm_client_id = config.rtm_account().to_string();
        let mut app = Self {
            last_session_refresh: None,
            terminal_outbox: VecDeque::new(),
            mode: AppMode::MainMenu,
            selected_index: 0,
            main_menu_items: Vec::new(),
            menu_actions: Vec::new(),
            output_text: String::new(),
            input_text: String::new(),
            show_popup: false,
            popup_message: String::new(),
            status_message: None,
            astation_client: AstationClient::new(),
            astation_connected: false,
            connected_astation_id: None,
            codex_client: CodexClient::new(),
            codex_output_log: String::new(),
            codex_raw_log: String::new(),
            codex_raw_log_start: 0,
            codex_user_actions: Vec::new(),
            codex_log_file: None,
            codex_summary_file: None,
            codex_terminal: VtParser::new(crate::pty_session::DEFAULT_ROWS, crate::pty_session::DEFAULT_COLS, crate::pty_session::SCROLLBACK_ROWS),
            codex_sender: None,
            codex_receiver: None,
            codex_share: None,
            codex_waiting_exit: false,
            codex_resize_handle: None,
            codex_view_rows: 0,
            codex_view_cols: 0,
            claude_client: ClaudeClient::new(),
            claude_output_log: String::new(),
            claude_raw_log: String::new(),
            claude_raw_log_start: 0,
            claude_user_actions: Vec::new(),
            claude_log_file: None,
            claude_summary_file: None,
            claude_terminal: VtParser::new(crate::pty_session::DEFAULT_ROWS, crate::pty_session::DEFAULT_COLS, crate::pty_session::SCROLLBACK_ROWS),
            claude_sender: None,
            claude_receiver: None,
            claude_share: None,
            claude_waiting_exit: false,
            claude_resize_handle: None,
            claude_view_rows: 0,
            claude_view_cols: 0,
            force_terminal_redraw: false,
            terminal_ui: crate::tui::terminal_view::State::new(),
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
            astation_connect_rx: None,
            astation_reconnect_at: None,
            pending_astation_command: None,
            pending_voice_request: None,
            pending_visualize: None,
        };
        app.rebuild_menu();
        app
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

    /// Local terminals remain available while Astation is disconnected.
    pub fn rebuild_menu(&mut self) {
        self.menu_actions.clear();
        self.main_menu_items.clear();

        // Always available
        self.menu_actions.push(MenuAction::ListProjects);
        self.main_menu_items.push("\u{1f4cb} List Agora Projects".to_string());

        self.menu_actions.push(MenuAction::LaunchClaude);
        self.main_menu_items.push(if self.claude_receiver.is_some() {
            "Resume Claude Code".into()
        } else {
            "Launch Claude Code".into()
        });
        self.menu_actions.push(MenuAction::LaunchCodex);
        self.main_menu_items.push(if self.codex_receiver.is_some() {
            "Resume Codex".into()
        } else {
            "Launch Codex".into()
        });

        self.menu_actions.push(MenuAction::ExecuteShell);
        self.main_menu_items.push("\u{1f4bb} Execute Shell Command".to_string());

        if self.astation_connected {
            self.menu_actions.push(MenuAction::AgentPanel);
            self.main_menu_items.push("\u{1f916} Agent Panel".to_string());
        }

        self.menu_actions.push(MenuAction::Help);
        self.main_menu_items.push("\u{2753} Help".to_string());

        self.menu_actions.push(MenuAction::Exit);
        self.main_menu_items.push("\u{1f6aa} Exit".to_string());

        // Clamp selected_index so it doesn't point past the new list
        if self.selected_index >= self.menu_actions.len() {
            self.selected_index = self.menu_actions.len().saturating_sub(1);
        }
    }

    pub async fn handle_selection(&mut self) -> Result<()> {
        self.status_message = None;
        let action = self.menu_actions.get(self.selected_index).copied();
        match action {
            Some(MenuAction::ListProjects) => {
                // List Agora Projects - Always fetch directly from Agora REST API
                self.mode = AppMode::TokenGeneration; // Reusing this mode for project listing
                self.output_text = "\u{1f4cb} Fetching Agora Projects...\n\n".to_string();

                // Fetch projects via SSO token (paired Astation takes priority when connected)
                let connected_aid = self.connected_astation_id.clone();
                let fetch_result = async {
                    let token = crate::sso_auth::valid_token(connected_aid.as_deref(), self.config.effective_sso_url()).await
                        .map_err(|e| anyhow::anyhow!("{}", e))?;
                    crate::agora_api::fetch_projects(&token, self.config.effective_bff_url()).await
                }.await;

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
                            Run `atem login` to authenticate via SSO.\n\n\
                            Press 'b' to go back to main menu",
                            e
                        );
                    }
                }
            }
            Some(MenuAction::LaunchClaude) => {
                // Launch Claude Code - always launch locally from Atem (like Codex)
                self.mode = AppMode::ClaudeChat;
                self.active_cli = ActiveCli::Claude;
                self.input_text.clear();
                self.claude_waiting_exit = false;
                match self.ensure_claude_session().await {
                    Ok(_) => self.refresh_claude_view(),
                    Err(err) => {
                        self.record_claude_output(format!(
                            "\u{274c} Unable to start Claude Code CLI: {}\n",
                            err
                        ));
                        self.refresh_claude_view();
                    }
                }
            }
            Some(MenuAction::LaunchCodex) => {
                // Launch Codex
                self.mode = AppMode::CodexChat;
                self.active_cli = ActiveCli::Codex;
                self.input_text.clear();
                self.codex_waiting_exit = false;
                match self.ensure_codex_session().await {
                    Ok(_) => self.refresh_codex_view(),
                    Err(err) => {
                        self.record_codex_output(&format!(
                            "\u{274c} Unable to start Codex CLI: {}\n",
                            err
                        ));
                        self.refresh_codex_view();
                    }
                }
            }
            Some(MenuAction::ExecuteShell) => {
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
            Some(MenuAction::AgentPanel) => {
                // Agent Panel
                self.mode = AppMode::AgentPanel;
                self.agent_panel_selected = 0;
            }
            Some(MenuAction::Help) => {
                // Help
                self.show_help_popup();
            }
            Some(MenuAction::Exit) | None => {
                // Exit - handled by caller
            }
        }
        Ok(())
    }

    pub fn show_help_popup(&mut self) {
        self.show_popup = true;
        self.popup_message = "\u{1f680} Atem - Agora.io AI CLI Tool\n\n\
            Navigation:\n\
            \u{2022} \u{2191}/\u{2193} or j/k: Navigate menu\n\
            \u{2022} Enter: Select item\n\
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
            self.force_terminal_redraw = true;

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
        if trimmed.is_empty() { return Ok(()); }
        if self.codex_waiting_exit { anyhow::bail!("Codex is shutting down"); }
        self.ensure_codex_session().await?;
        let sender = self.codex_sender.as_ref().ok_or_else(|| anyhow::anyhow!("Codex terminal unavailable"))?;
        sender.send(format!("{trimmed}\n\r"))?;
        self.codex_user_actions.push(trimmed.to_string());
        if trimmed.eq_ignore_ascii_case("quit") || trimmed.eq_ignore_ascii_case("exit") {
            self.codex_waiting_exit = true;
        }
        Ok(())
    }

    pub async fn ensure_codex_session(&mut self) -> Result<bool> {
        let needs_session = self.codex_sender.is_none() || self.codex_receiver.is_none();
        if !needs_session {
            return Ok(false);
        }

        let rows = if self.codex_view_rows == 0 { crate::pty_session::DEFAULT_ROWS } else { self.codex_view_rows };
        let cols = if self.codex_view_cols == 0 { crate::pty_session::DEFAULT_COLS } else { self.codex_view_cols };
        let session = self.codex_client.start_session_sized(rows, cols).await?;
        self.replace_terminal("codex");
        self.codex_sender = Some(session.sender);
        self.codex_receiver = Some(session.receiver);
        self.codex_resize_handle = Some(session.resize_handle);
        self.codex_raw_log.clear();
        self.codex_raw_log_start = 0;
        self.codex_output_log.clear();
        self.codex_user_actions.clear();
        self.codex_log_file = None;
        self.codex_summary_file = None;
        self.codex_view_rows = rows;
        self.codex_view_cols = cols;
        self.codex_terminal = VtParser::new(rows, cols, crate::pty_session::SCROLLBACK_ROWS);
        self.codex_waiting_exit = false;
        Ok(true)
    }

    pub fn record_codex_output(&mut self, data: impl AsRef<str>) {
        let text = data.as_ref();
        crate::app::terminal::append_log(&mut self.codex_raw_log, &mut self.codex_raw_log_start, text);

        if self.codex_receiver.is_some() {
            self.status_message = Some(text.trim().to_string());
        } else {
            self.codex_terminal.process(text.as_bytes());
            self.update_codex_output_from_terminal();
        }
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
        if self.codex_share.as_ref().is_some_and(|s| s.exit_status.is_some()) { return; }
        if let Some(sender) = &self.codex_sender {
            if let Err(error) = sender.send(data.to_string()) {
                self.status_message = Some(error.to_string());
            }
        }
    }

    pub fn refresh_codex_view(&mut self) {
        if matches!(self.mode, AppMode::CodexChat) {
            self.output_text = self.codex_output_log.clone();
        }
    }

    pub fn rebuild_codex_terminal(&mut self) {
        self.codex_terminal.set_size(self.codex_view_rows.max(2), self.codex_view_cols.max(2));
        self.update_codex_output_from_terminal();
    }

    pub fn adjust_codex_terminal_size(&mut self, rows: u16, cols: u16) {
        if self.codex_sender.as_ref().is_some_and(|s| s.remote_controlled()) { return; }
        let rows = rows.min(200);
        let cols = cols.min(400);
        if rows < 2 || cols < 2 {
            return;
        }
        if self.codex_view_rows == rows
            && self.codex_view_cols == cols
            && self.codex_terminal.screen().size() == (rows, cols)
        {
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
        self.process_terminal_output("codex");
    }

    pub async fn ensure_rtm_client(&mut self) -> Result<()> {
        // RTM DISABLED: Use WebSocket for all communication
        // TODO: Re-enable RTM for voice coding features in the future
        Ok(())
    }

    pub async fn send_activity_ping(&mut self, _focused: bool) -> Result<()> {
        // RTM DISABLED: Activity pings not needed without voice coding
        // TODO: Send activity via WebSocket when implementing voice coding
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
                Err(_err) => {
                    // Silently ignore activity ping errors (RTM not configured/no current project)
                    // This is expected in normal TUI usage without voice coding features
                }
            }
        }
    }

    pub async fn process_rtm_messages(&mut self) -> Result<()> {
        // RTM DISABLED: No RTM events to process
        // Still flush transcriptions if needed
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
        let was_focused = matches!(self.mode, AppMode::CodexChat);

        let had_activity_before_finalize = !self.codex_raw_log.trim().is_empty();

        crate::app::terminal::append_log(&mut self.codex_raw_log, &mut self.codex_raw_log_start, "\u{2699}\u{fe0f} Codex CLI session ended.\n");

        let mut status_parts: Vec<String> = Vec::new();

        if had_activity_before_finalize {
            match self.persist_codex_log() {
                Ok(Some(path)) => {
                    let msg = format!("\u{1f4dd} Codex log saved to {}", path.display());
                    crate::app::terminal::append_log(&mut self.codex_raw_log, &mut self.codex_raw_log_start, &format!("{}\n", msg));
                    status_parts.push(msg);
                }
                Ok(None) => {
                    status_parts.push("Codex session ended with no output to save.".to_string());
                }
                Err(err) => {
                    let msg = format!("\u{26a0}\u{fe0f} Failed to save Codex log: {}", err);
                    crate::app::terminal::append_log(&mut self.codex_raw_log, &mut self.codex_raw_log_start, &format!("{}\n", msg));
                    status_parts.push(msg);
                }
            }

            let summary = self.generate_codex_summary();
            match self.write_codex_summary_file(&summary) {
                Ok(path) => {
                    let msg = format!("\u{1f4c4} Summary saved to {}", path.display());
                    crate::app::terminal::append_log(&mut self.codex_raw_log, &mut self.codex_raw_log_start, &format!("{}\n", msg));
                    status_parts.push(msg);
                }
                Err(err) => {
                    let msg = format!("\u{26a0}\u{fe0f} Failed to save Codex summary: {}", err);
                    crate::app::terminal::append_log(&mut self.codex_raw_log, &mut self.codex_raw_log_start, &format!("{}\n", msg));
                    status_parts.push(msg);
                }
            }
        } else {
            status_parts.push("Codex session ended (no output captured).".to_string());
        }

        self.codex_receiver = None;
        self.rebuild_menu();

        if was_focused {
            self.mode = AppMode::MainMenu;
            self.show_popup = false;
            self.popup_message.clear();
            self.output_text.clear();
            self.input_text.clear();
        }
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
        if trimmed.is_empty() { return Ok(()); }
        if self.claude_waiting_exit { anyhow::bail!("Claude is shutting down"); }
        self.ensure_claude_session().await?;
        let sender = self.claude_sender.as_ref().ok_or_else(|| anyhow::anyhow!("Claude terminal unavailable"))?;
        sender.send(format!("{trimmed}\n\r"))?;
        self.claude_user_actions.push(trimmed.to_string());
        if trimmed.eq_ignore_ascii_case("quit") || trimmed.eq_ignore_ascii_case("exit") {
            self.claude_waiting_exit = true;
        }
        Ok(())
    }

    pub async fn ensure_claude_session(&mut self) -> Result<bool> {
        let needs_session = self.claude_sender.is_none() || self.claude_receiver.is_none();
        if !needs_session {
            return Ok(false);
        }

        let rows = if self.claude_view_rows == 0 { crate::pty_session::DEFAULT_ROWS } else { self.claude_view_rows };
        let cols = if self.claude_view_cols == 0 { crate::pty_session::DEFAULT_COLS } else { self.claude_view_cols };
        let session = self.claude_client.start_session_sized(rows, cols).await?;
        self.replace_terminal("claude");
        self.claude_sender = Some(session.sender);
        self.claude_receiver = Some(session.receiver);
        self.claude_resize_handle = Some(session.resize_handle);
        self.claude_raw_log.clear();
        self.claude_raw_log_start = 0;
        self.claude_output_log.clear();
        self.claude_user_actions.clear();
        self.claude_log_file = None;
        self.claude_summary_file = None;
        self.claude_view_rows = rows;
        self.claude_view_cols = cols;
        self.claude_terminal = VtParser::new(rows, cols, crate::pty_session::SCROLLBACK_ROWS);
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
        use crate::agent_detector::{scan_lockfiles, scan_default_ports};

        // First, scan for lockfiles (traditional detection)
        let mut detected = scan_lockfiles();

        // Then, scan common ACP ports (for agents without lockfiles)
        let port_detected = scan_default_ports().await;
        detected.extend(port_detected);

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
        crate::app::terminal::append_log(&mut self.claude_raw_log, &mut self.claude_raw_log_start, text);
        if self.claude_receiver.is_some() {
            self.status_message = Some(text.trim().to_string());
        } else {
            self.claude_terminal.process(text.as_bytes());
            self.update_claude_output_from_terminal();
        }
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
        if matches!(self.mode, AppMode::ClaudeChat) {
            self.output_text = self.claude_output_log.clone();
        }
    }

    pub fn send_claude_data(&mut self, data: &str) {
        if self.claude_share.as_ref().is_some_and(|s| s.exit_status.is_some()) { return; }
        if let Some(sender) = &self.claude_sender {
            if let Err(error) = sender.send(data.to_string()) {
                self.status_message = Some(error.to_string());
            }
        }
    }

    pub fn refresh_claude_view(&mut self) {
        if matches!(self.mode, AppMode::ClaudeChat) {
            self.output_text = self.claude_output_log.clone();
        }
    }

    pub fn rebuild_claude_terminal(&mut self) {
        self.claude_terminal.set_size(self.claude_view_rows.max(2), self.claude_view_cols.max(2));
        self.update_claude_output_from_terminal();
    }

    pub fn adjust_claude_terminal_size(&mut self, rows: u16, cols: u16) {
        if self.claude_sender.as_ref().is_some_and(|s| s.remote_controlled()) { return; }
        let rows = rows.min(200);
        let cols = cols.min(400);
        if rows < 2 || cols < 2 {
            return;
        }
        if self.claude_view_rows == rows
            && self.claude_view_cols == cols
            && self.claude_terminal.screen().size() == (rows, cols)
        {
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
        self.process_terminal_output("claude");
    }

    pub fn finalize_claude_session(&mut self) {
        let was_focused = matches!(self.mode, AppMode::ClaudeChat);

        // If there's an active mark task, flag it for async finalization
        self.dispatcher.set_main_needs_finalize();

        let had_activity_before_finalize = !self.claude_raw_log.trim().is_empty();

        crate::app::terminal::append_log(&mut self.claude_raw_log, &mut self.claude_raw_log_start, "\u{2699}\u{fe0f} Claude Code CLI session ended.\n");

        let mut status_parts: Vec<String> = Vec::new();

        if had_activity_before_finalize {
            match self.persist_claude_log() {
                Ok(Some(path)) => {
                    let msg = format!("\u{1f4dd} Claude log saved to {}", path.display());
                    crate::app::terminal::append_log(&mut self.claude_raw_log, &mut self.claude_raw_log_start, &format!("{}\n", msg));
                    status_parts.push(msg);
                }
                Ok(None) => {
                    status_parts
                        .push("Claude session ended with no output to save.".to_string());
                }
                Err(err) => {
                    let msg = format!("\u{26a0}\u{fe0f} Failed to save Claude log: {}", err);
                    crate::app::terminal::append_log(&mut self.claude_raw_log, &mut self.claude_raw_log_start, &format!("{}\n", msg));
                    status_parts.push(msg);
                }
            }

            let summary = self.generate_claude_summary();
            match self.write_claude_summary_file(&summary) {
                Ok(path) => {
                    let msg = format!("\u{1f4c4} Summary saved to {}", path.display());
                    crate::app::terminal::append_log(&mut self.claude_raw_log, &mut self.claude_raw_log_start, &format!("{}\n", msg));
                    status_parts.push(msg);
                }
                Err(err) => {
                    let msg = format!("\u{26a0}\u{fe0f} Failed to save Claude summary: {}", err);
                    crate::app::terminal::append_log(&mut self.claude_raw_log, &mut self.claude_raw_log_start, &format!("{}\n", msg));
                    status_parts.push(msg);
                }
            }
        } else {
            status_parts.push("Claude session ended (no output captured).".to_string());
        }

        self.claude_receiver = None;
        self.rebuild_menu();

        if was_focused {
            self.mode = AppMode::MainMenu;
            self.show_popup = false;
            self.popup_message.clear();
            self.output_text.clear();
            self.input_text.clear();
        }
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

    /// Spawn a background task that connects to Astation without blocking.
    /// Poll the result each loop tick with `poll_astation_connect()`.
    pub fn spawn_astation_connect(&mut self) {
        if self.astation_connected || self.astation_connect_rx.is_some() {
            return;
        }
        // Pairing can learn the relay identity while the TUI is already running.
        // Refresh before every attempt so the next reconnect can use it immediately.
        let config = AtemConfig::load().unwrap_or_else(|_| self.config.clone());
        self.config = config.clone();
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.astation_connect_rx = Some(rx);
        tokio::spawn(async move {
            // Connection priority:
            // 1. Local URL (from config or default ws://127.0.0.1:8080/ws)
            //    - Works for: same machine, LAN IP, VPN IP (Netbird, Tailscale, etc.)
            // 2. Relay (wss://station.agora.build) - remote connection

            let local_url = config.astation_ws();
            let session = crate::auth::AuthSession::load_saved();

            // Try local connection first
            let mut client = crate::websocket_client::AstationClient::new();

            // If we have a valid session, try local with session auth
            if let Some(ref sess) = session {
                if sess.is_valid() {
                    if let Ok(()) = client
                        .connect_with_session(local_url, &sess.session_id)
                        .await
                    {
                        let _ = tx.send(Ok((client, None)));
                        return;
                    }
                }
            }

            // No valid session - try local with fresh auth (5s timeout)
            let mut client = crate::websocket_client::AstationClient::new();
            let local_url = config.astation_ws().to_string();
            match client.connect_without_pairing(&local_url).await {
                Ok(()) => {
                    let _ = tx.send(Ok((client, Some("local".to_string()))));
                    return;
                }
                Err(_) => {}
            }

            // Local unavailable — try relay identity if configured
            if let Some(relay_code) = config.astation_relay_code.clone() {
                let relay_url = config.astation_relay_url().to_string();
                let mut relay_client = crate::websocket_client::AstationClient::new();
                match relay_client
                    .connect_relay_identity_without_pairing(&relay_url, &relay_code)
                    .await
                {
                    Ok(()) => {
                        let _ = tx.send(Ok((relay_client, Some(relay_code))));
                        return;
                    }
                    Err(_) => {}
                }
            }

            let _ = tx.send(Err(anyhow::anyhow!("Astation not reachable")));
        });
    }

    /// Check if the background Astation connection has completed, and if so apply it.
    pub fn poll_astation_connect(&mut self) {
        if let Some(rx) = &mut self.astation_connect_rx {
            match rx.try_recv() {
                Ok(Ok((client, code))) => {
                    self.astation_connect_rx = None;
                    self.astation_reconnect_at = None; // Clear any pending retry
                    self.astation_client = client;
                    self.astation_connected = true;
                    self.pairing_code = code;
                    self.rebuild_menu();
                    self.status_message = Some("Connected to Astation".to_string());

                    // Refresh session on successful connection
                    if let Some(session) = crate::auth::AuthSession::load_saved() {
                        let mut session = session;
                        session.refresh();
                        let _ = session.save();
                    }
                }
                Ok(Err(_)) => {
                    // Connection failed — schedule background retry every 30s.
                    // Instant is monotonic and pauses during system sleep, so the timer
                    // only counts awake time — no battery drain while the device sleeps.
                    self.astation_connect_rx = None;
                    self.astation_reconnect_at =
                        Some(Instant::now() + std::time::Duration::from_secs(30));
                    self.status_message = Some(
                        "Astation offline — retrying…".to_string()
                    );
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Empty) => {
                    // Still pending
                }
                Err(tokio::sync::oneshot::error::TryRecvError::Closed) => {
                    // Task dropped without sending — treat as failure, schedule retry
                    self.astation_connect_rx = None;
                    self.astation_reconnect_at =
                        Some(Instant::now() + std::time::Duration::from_secs(30));
                }
            }
        }
    }

    pub async fn handle_astation_message(&mut self, message: AstationMessage) {
        let shared = self.claude_share.as_ref().is_some_and(|s| s.has_viewer())
            || self.codex_share.as_ref().is_some_and(|s| s.has_viewer());
        if (shared || self.astation_client.is_ws_closed()) && matches!(&message, AstationMessage::AgentInput { .. } | AstationMessage::AgentPrompt { .. }
            | AstationMessage::VoiceRequest { .. } | AstationMessage::VoiceCommand { .. }
            | AstationMessage::VoiceToggle { .. } | AstationMessage::UserCommand { .. }) {
            self.handle_terminal_legacy_rejection();
            return;
        }
        match self.astation_client.handle_encryption_message(&message).await {
            Ok(Some(status)) => {
                self.status_message = Some(status);
                return;
            }
            Ok(None) => {}
            Err(error) => {
                self.status_message = Some(format!("Encryption setup failed: {error}"));
                return;
            }
        }
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
                // PTT flush: when mic is released, send any buffered voice text to Claude
                if !active && self.voice_commands.has_content() {
                    let command = self.voice_commands.take();
                    self.status_message = Some(format!("\u{1f3a4} PTT: {}", command));
                    if let Err(err) = self.send_claude_prompt(&command).await {
                        self.status_message =
                            Some(format!("Failed to send PTT voice to Claude: {}", err));
                    }
                }
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

                // Determine target CLI
                let target = match action {
                    "cli_input" => self.pinned_cli.clone().unwrap_or(self.active_cli.clone()),
                    "claude_input" => ActiveCli::Claude,
                    "codex_input" => ActiveCli::Codex,
                    _ => ActiveCli::Claude,
                };

                // Track output start position before sending command (use raw_log which accumulates)
                let output_start_pos = match target {
                    ActiveCli::Claude => self.claude_raw_log_start + self.claude_raw_log.len(),
                    ActiveCli::Codex => self.codex_raw_log_start + self.codex_raw_log.len(),
                };

                // Store pending command for output relay
                self.pending_astation_command = Some(PendingAstationCommand {
                    target: target.clone(),
                    output_start_pos,
                    sent_at: Instant::now(),
                });

                // Send command to appropriate CLI
                match action {
                    "cli_input" => {
                        match target {
                            ActiveCli::Claude => { self.send_claude_prompt(&command).await.ok(); }
                            ActiveCli::Codex => { self.send_codex_prompt(&command).await.ok(); }
                        }
                    }
                    "claude_input" => { self.send_claude_prompt(&command).await.ok(); }
                    "codex_input" => { self.send_codex_prompt(&command).await.ok(); }
                    "shell" => {
                        self.execute_command(&command).await.ok();
                        // For shell commands, clear pending since we don't track shell output relay yet
                        self.pending_astation_command = None;
                    }
                    _ => { self.send_claude_prompt(&command).await.ok(); }
                }

                self.status_message = Some(format!(
                    "Received command: {}",
                    &command[..command.len().min(50)]
                ));
            }
            AstationMessage::AgentListRequest => {
                let agents = self.agent_registry.all();
                let _ = self.astation_client.send_agent_list(agents).await;
            }
            AstationMessage::AgentPrompt {
                agent_id,
                session_id: _,
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
            AstationMessage::VoiceRequest {
                session_id,
                accumulated_text,
                relay_url,
            } => {
                self.handle_voice_request(session_id, accumulated_text, relay_url).await;
            }
            AstationMessage::Terminal(envelope) => {
                self.handle_terminal_message(envelope);
            }
            AstationMessage::AgentInput {
                agent_id,
                kind,
                text,
                key,
            } => {
                self.handle_agent_input(agent_id, kind, text, key);
            }
            AstationMessage::VisualizeRequest {
                session_id,
                topic,
                relay_url,
            } => {
                self.handle_visualize_request(session_id, topic, relay_url).await;
            }
            AstationMessage::CredentialSync {
                access_token,
                refresh_token,
                expires_at,
                login_id,
                astation_id,
                save_credentials,
            } => {
                let mut store = crate::credentials::CredentialStore::load();
                let now = crate::credentials::CredentialEntry::now_secs();
                store.upsert(crate::credentials::CredentialEntry::new_paired(
                    access_token,
                    refresh_token,
                    expires_at,
                    login_id.clone(),
                    astation_id.clone(),
                    save_credentials,
                    now,
                ));
                if let Err(e) = store.save() {
                    self.status_message = Some(format!("Failed to save paired credentials: {}", e));
                } else {
                    self.connected_astation_id = Some(astation_id.clone());
                    let preview = login_id.as_deref().unwrap_or("—");
                    self.status_message = Some(format!(
                        "\u{1f517} Paired SSO credentials received ({})",
                        preview
                    ));
                }
            }
            _ => {
                // Unknown/unhandled message type — ignore silently
            }
        }
    }

    /// Called when the Astation WebSocket connection drops.
    /// Marks any paired credential entries for that Astation with `disconnected_at`
    /// so the grace-period logic in `CredentialStore::resolve` can take effect.
    pub fn on_astation_disconnect(&mut self) {
        self.disconnect_terminals();
        if let Some(aid) = self.connected_astation_id.take() {
            let mut store = crate::credentials::CredentialStore::load();
            if let Some(entry) = store.find_paired_mut(&aid) {
                entry.disconnected_at = Some(crate::credentials::CredentialEntry::now_secs());
                let _ = store.save();
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
        if self.claude_sender.as_ref().is_some_and(|s| s.remote_controlled()) { return; }
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
                crate::diagnostics::warn(format!("Failed to start Claude session for task {}: {}", task_id, err));
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

        // One queued write prevents a rejected prompt from submitting an unrelated draft.
        let result = self.claude_sender.as_ref().unwrap().send(format!("{}\n\r", item.prompt));
        if let Err(error) = result {
            let _ = self.astation_client.send_mark_result(&task_id, false, &error.to_string()).await;
            self.dispatcher.complete_main();
            self.work_items.remove(&task_id);
            return;
        }
        self.claude_user_actions.push(format!("[Mark Task {}]", task_id));

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

    /// Handle a voice coding request from Astation: send to Claude and track for completion.
    /// Remote agent control (Astation → Atem): write text or a control key to
    /// the focused agent's PTY. `agent_id` is ignored in v1 (the focused/only
    /// agent = the current chat mode). `kind:"text"` types the line and submits
    /// it with Enter; `kind:"key"` writes the raw control bytes (see
    /// [`agent_key_to_bytes`]). Unknown kinds/keys are dropped with a status note.
    pub fn handle_agent_input(
        &mut self,
        agent_id: Option<String>,
        kind: String,
        text: Option<String>,
        key: Option<String>,
    ) {
        if self.claude_share.as_ref().is_some_and(|s| s.has_viewer()) || self.codex_share.as_ref().is_some_and(|s| s.has_viewer()) {
            self.status_message = Some("Use terminal-v1 control for an attached terminal".into());
            return;
        }
        if agent_id.is_some() {
            self.status_message = Some("Explicit terminal targeting requires terminal-v1".into());
            return;
        }
        // `kind` selects the input; the non-matching field is ignored (Astation
        // only ever populates one).
        let data: Option<String> = match kind.as_str() {
            // Type the line and submit it. Trims + skips empty like
            // send_claude_prompt, and matches its submit sequence (text, then
            // "\n", then "\r") which the Claude/Codex TUIs need to accept a line.
            "text" => text
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .map(|t| format!("{t}\n\r")),
            "key" => key
                .as_deref()
                .and_then(agent_key_to_bytes)
                .map(|s| s.to_string()),
            _ => None,
        };

        let Some(data) = data else {
            self.status_message = Some(format!(
                "Ignored agentInput (kind={}, key={:?})",
                kind, key
            ));
            return;
        };

        // Route to the focused agent's PTY. Codex when it's the active chat;
        // Claude otherwise (matches the voice path's default target). The
        // send_* helpers no-op if that agent has no live session.
        if matches!(self.mode, AppMode::CodexChat) && self.codex_sender.is_some() {
            self.send_codex_data(&data);
        } else {
            self.send_claude_data(&data);
        }
        self.status_message = Some(format!("\u{2328} agentInput: {}", kind));
    }

    pub async fn handle_voice_request(
        &mut self,
        session_id: String,
        accumulated_text: String,
        relay_url: String,
    ) {
        self.status_message = Some(format!("\u{1f3a4} Voice request: {}", &accumulated_text[..accumulated_text.len().min(50)]));

        // Send the transcribed text to Claude Code
        if let Err(err) = self.send_claude_prompt(&accumulated_text).await {
            self.status_message =
                Some(format!("Failed to send voice request to Claude: {}", err));
            // POST failure to relay so it unblocks
            let client = reqwest::Client::new();
            let _ = client
                .post(format!("{}/api/voice-sessions/response", relay_url))
                .json(&serde_json::json!({
                    "session_id": session_id,
                    "response": format!("Error: {}", err),
                }))
                .send()
                .await;
            let _ = self
                .astation_client
                .send_voice_response(&session_id, false, &format!("Failed to send to Claude: {}", err))
                .await;
            return;
        }

        // Track pending request — watch for Claude output completion
        let now = Instant::now();
        self.pending_voice_request = Some(PendingVoiceRequest {
            session_id,
            relay_url,
            sent_at: now,
            output_snapshot_len: self.claude_raw_log_start + self.claude_raw_log.len(),
            last_output_at: now,
        });
    }

    /// Check if a pending voice request's Claude output is complete (2s inactivity).
    /// When done, POST the response to the relay and notify Astation.
    pub async fn check_voice_request_completion(&mut self) {
        let pending = match self.pending_voice_request.clone() {
            Some(p) => p,
            None => return,
        };

        let current_len = self.claude_raw_log_start + self.claude_raw_log.len();

        // Output is still growing — update snapshot
        if current_len > pending.output_snapshot_len {
            if let Some(ref mut p) = self.pending_voice_request {
                p.output_snapshot_len = current_len;
                p.last_output_at = Instant::now();
            }
            return;
        }

        // No new output yet — wait at least 2 seconds of inactivity
        if pending.last_output_at.elapsed() < Duration::from_secs(2) {
            return;
        }

        // Also require at least 2s since the prompt was sent (avoid racing)
        if pending.sent_at.elapsed() < Duration::from_secs(2) {
            return;
        }

        // Claude is done — extract the response text.
        // At this point current_len <= pending.output_snapshot_len (output stopped growing).
        let output = crate::app::terminal::log_since(&self.claude_raw_log, self.claude_raw_log_start, pending.output_snapshot_len);
        let response_text = if !output.is_empty() {
            output.to_string()
        } else {
            "No output received from Claude.".to_string()
        };

        // POST response to relay server
        let client = reqwest::Client::new();
        let post_result = client
            .post(format!("{}/api/voice-sessions/response", pending.relay_url))
            .json(&serde_json::json!({
                "session_id": pending.session_id,
                "response": response_text,
            }))
            .send()
            .await;

        let success = post_result.is_ok();
        let msg = if success {
            "Response delivered to relay".to_string()
        } else {
            format!("Failed to POST to relay: {}", post_result.unwrap_err())
        };

        // Notify Astation
        let _ = self
            .astation_client
            .send_voice_response(&pending.session_id, success, &msg)
            .await;

        self.status_message = Some(format!("\u{1f3a4} Voice response: {}", msg));
        self.pending_voice_request = None;
    }

    // MARK: - Visualize Request Processing

    /// Handle a visualize request from Astation: send prompt to Claude and track for completion.
    pub async fn handle_visualize_request(
        &mut self,
        session_id: String,
        topic: String,
        relay_url: Option<String>,
    ) {
        use crate::agent_visualize::{build_visualize_prompt, snapshot_diagrams_dir};

        self.status_message = Some(format!(
            "\u{1f4ca} Visualize request: {}",
            &topic[..topic.len().min(50)]
        ));

        let prompt = build_visualize_prompt(&topic);
        let pre_snapshot = snapshot_diagrams_dir();

        // Send the prompt to Claude Code
        if let Err(err) = self.send_claude_prompt(&prompt).await {
            self.status_message =
                Some(format!("Failed to send visualize request to Claude: {}", err));
            let _ = self
                .astation_client
                .send_visualize_result(
                    &session_id,
                    false,
                    &format!("Failed to send to Claude: {}", err),
                    None,
                )
                .await;
            return;
        }

        // Track pending request — watch for Claude output completion
        let now = Instant::now();
        self.pending_visualize = Some(PendingVisualize {
            session_id,
            relay_url,
            sent_at: now,
            pre_snapshot,
            detected_file: None,
            output_snapshot_len: self.claude_raw_log_start + self.claude_raw_log.len(),
            last_output_at: now,
        });
    }

    /// Check if a pending visualize request's Claude output is complete (3s inactivity).
    /// When done, detect new HTML files and notify Astation.
    pub async fn check_visualize_completion(&mut self) {
        use crate::agent_visualize::detect_new_html_files;

        let pending = match self.pending_visualize.clone() {
            Some(p) => p,
            None => return,
        };

        let current_len = self.claude_raw_log_start + self.claude_raw_log.len();

        // Output is still growing — update snapshot
        if current_len > pending.output_snapshot_len {
            if let Some(ref mut p) = self.pending_visualize {
                p.output_snapshot_len = current_len;
                p.last_output_at = Instant::now();
            }
            return;
        }

        // No new output yet — wait at least 3 seconds of inactivity
        if pending.last_output_at.elapsed() < Duration::from_secs(3) {
            return;
        }

        // Also require at least 3s since the prompt was sent (avoid racing)
        if pending.sent_at.elapsed() < Duration::from_secs(3) {
            return;
        }

        // Agent is done — detect new HTML files
        let file_path = pending
            .detected_file
            .clone()
            .or_else(|| detect_new_html_files(&pending.pre_snapshot).into_iter().next());

        let (success, message) = match &file_path {
            Some(path) => {
                // Try to upload to diagram server
                let config = AtemConfig::load().unwrap_or_default();
                match crate::agent_visualize::resolve_diagram_server_url(&config) {
                    Ok(server_url) => {
                        match crate::agent_visualize::upload_diagram(path, "visualize", &server_url).await {
                            Ok(url) => (true, format!("Diagram: {} — View at: {}", path, url)),
                            Err(_) => (true, format!("Diagram generated: {}", path)),
                        }
                    }
                    Err(_) => (true, format!("Diagram generated: {}", path)),
                }
            }
            None => (false, "No HTML diagram file was detected".to_string()),
        };

        // Notify Astation
        let _ = self
            .astation_client
            .send_visualize_result(
                &pending.session_id,
                success,
                &message,
                file_path,
            )
            .await;

        self.status_message = Some(format!("\u{1f4ca} {}", message));
        self.pending_visualize = None;
    }

    /// Check if pending Astation command has output ready and relay it back.
    /// Sends output after 2 seconds of inactivity.
    pub async fn check_relay_output(&mut self) {
        if let Some(ref pending) = self.pending_astation_command.clone() {
            let elapsed = pending.sent_at.elapsed();

            // Wait at least 2 seconds for output to accumulate
            if elapsed < Duration::from_secs(2) {
                return;
            }

            // Extract output since command was sent (use raw_log which accumulates all output)
            let (output, success) = match pending.target {
                ActiveCli::Claude => {
                    let output = crate::app::terminal::log_since(&self.claude_raw_log, self.claude_raw_log_start, pending.output_start_pos);
                    if !output.is_empty() {
                        (output.to_string(), true)
                    } else {
                        ("No output received".to_string(), false)
                    }
                }
                ActiveCli::Codex => {
                    let output = crate::app::terminal::log_since(&self.codex_raw_log, self.codex_raw_log_start, pending.output_start_pos);
                    if !output.is_empty() {
                        (output.to_string(), true)
                    } else {
                        ("No output received".to_string(), false)
                    }
                }
            };

            // Send response back to Astation
            if let Err(e) = self.astation_client.send_command_response(&output, success).await {
                self.status_message = Some(format!("Failed to relay output to Astation: {}", e));
            } else {
                self.status_message = Some("Output relayed to Astation".to_string());
            }

            // Clear pending command
            self.pending_astation_command = None;
        }
    }

    pub async fn process_astation_messages(&mut self) {
        // Revoke before draining requests that were queued on a closed transport.
        if self.astation_connected && self.astation_client.is_ws_closed() {
            self.disconnect_terminals();
        }
        // Drain all pending messages (non-blocking try_recv loop)
        let mut message_count = 0;
        while message_count < 32 {
            let Some(message) = self.astation_client.recv_message() else { break; };
            self.handle_astation_message(message).await;
            message_count += 1;
        }

        // Detect WebSocket disconnect (channel closed after draining remaining messages)
        if self.astation_connected && self.astation_client.is_ws_closed() {
            self.astation_connected = false;
            self.on_astation_disconnect();
            self.astation_client = crate::websocket_client::AstationClient::new();
            self.rebuild_menu();
            // Schedule immediate reconnect attempt
            self.astation_reconnect_at = Some(Instant::now());
            self.status_message = Some("Astation disconnected — reconnecting…".to_string());
        }

        // Refresh session activity if we received any messages
        if message_count > 0 && self.last_session_refresh.is_none_or(|last| last.elapsed() >= Duration::from_secs(60)) {
            self.last_session_refresh = Some(Instant::now());
            if let Some(session) = crate::auth::AuthSession::load_saved() {
                let mut session = session;
                session.refresh();
                let _ = session.save();
            }
        }

        // Check if we should relay output back to Astation
        self.check_relay_output().await;

        // Check if pending voice request has completed
        self.check_voice_request_completion().await;

        // Check if pending visualize request has completed
        self.check_visualize_completion().await;
    }

    /// Check if it is time to retry the Astation connection.
    ///
    /// Uses `Instant` (monotonic clock) which pauses during system sleep on both
    /// Linux (CLOCK_MONOTONIC) and macOS (mach_absolute_time / CLOCK_UPTIME_RAW).
    /// This means the retry timer only counts awake time — no battery drain while
    /// the device is suspended, and no OS wake lock is held.
    pub fn check_astation_reconnect(&mut self) {
        if self.astation_connected || self.astation_connect_rx.is_some() {
            // Already connected or a connect attempt is already in flight — clear retry
            self.astation_reconnect_at = None;
            return;
        }
        if let Some(reconnect_at) = self.astation_reconnect_at {
            if Instant::now() >= reconnect_at {
                self.astation_reconnect_at = None;
                self.spawn_astation_connect();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_key_maps_control_keys_to_pty_bytes() {
        assert_eq!(agent_key_to_bytes("enter"), Some("\r"));
        assert_eq!(agent_key_to_bytes("esc"), Some("\x1b"));
        assert_eq!(agent_key_to_bytes("ctrl-c"), Some("\x03"));
        assert_eq!(agent_key_to_bytes("up"), Some("\x1b[A"));
        assert_eq!(agent_key_to_bytes("down"), Some("\x1b[B"));
        assert_eq!(agent_key_to_bytes("y"), Some("y"));
        assert_eq!(agent_key_to_bytes("n"), Some("n"));
    }

    #[test]
    fn agent_key_unknown_returns_none() {
        assert_eq!(agent_key_to_bytes("f13"), None);
        assert_eq!(agent_key_to_bytes(""), None);
        assert_eq!(agent_key_to_bytes("Enter"), None); // case-sensitive by design
    }

    #[test]
    fn handle_agent_input_text_types_line_and_submits_to_claude() {
        let mut app = App::new();
        let (tx, mut rx) = crate::pty_session::PtyInput::test_channel();
        app.claude_sender = Some(tx);
        app.mode = AppMode::ClaudeChat;
        app.handle_agent_input(None, "text".into(), Some("hello".into()), None);
        let got: String = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert_eq!(got, "hello\n\r");
    }

    #[test]
    fn handle_agent_input_key_writes_raw_control_bytes() {
        let mut app = App::new();
        let (tx, mut rx) = crate::pty_session::PtyInput::test_channel();
        app.claude_sender = Some(tx);
        app.mode = AppMode::ClaudeChat;
        app.handle_agent_input(None, "key".into(), None, Some("ctrl-c".into()));
        let got: String = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert_eq!(got, "\x03");
    }

    #[test]
    fn handle_agent_input_empty_text_sends_nothing() {
        let mut app = App::new();
        let (tx, mut rx) = crate::pty_session::PtyInput::test_channel();
        app.claude_sender = Some(tx);
        app.mode = AppMode::ClaudeChat;
        app.handle_agent_input(None, "text".into(), Some("   ".into()), None);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn handle_agent_input_unknown_key_sends_nothing() {
        let mut app = App::new();
        let (tx, mut rx) = crate::pty_session::PtyInput::test_channel();
        app.claude_sender = Some(tx);
        app.mode = AppMode::ClaudeChat;
        app.handle_agent_input(None, "key".into(), None, Some("f13".into()));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn handle_agent_input_routes_to_codex_when_focused() {
        let mut app = App::new();
        let (tx, mut rx) = crate::pty_session::PtyInput::test_channel();
        app.codex_sender = Some(tx);
        app.mode = AppMode::CodexChat;
        app.handle_agent_input(None, "key".into(), None, Some("esc".into()));
        let got: String = std::iter::from_fn(|| rx.try_recv().ok()).collect();
        assert_eq!(got, "\x1b");
    }

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

    #[test]
    fn test_pending_voice_request_default_is_none() {
        let app = App::new();
        assert!(app.pending_voice_request.is_none());
    }

    #[test]
    fn test_pending_voice_request_tracks_fields() {
        let now = Instant::now();
        let req = PendingVoiceRequest {
            session_id: "sess-123".to_string(),
            relay_url: "https://relay.example.com".to_string(),
            sent_at: now,
            output_snapshot_len: 42,
            last_output_at: now,
        };
        assert_eq!(req.session_id, "sess-123");
        assert_eq!(req.relay_url, "https://relay.example.com");
        assert_eq!(req.output_snapshot_len, 42);
    }

    #[test]
    fn test_pending_voice_request_clone() {
        let now = Instant::now();
        let req = PendingVoiceRequest {
            session_id: "sess-clone".to_string(),
            relay_url: "https://relay.test".to_string(),
            sent_at: now,
            output_snapshot_len: 100,
            last_output_at: now,
        };
        let cloned = req.clone();
        assert_eq!(cloned.session_id, "sess-clone");
        assert_eq!(cloned.output_snapshot_len, 100);
    }

    #[test]
    fn test_pending_visualize_default_is_none() {
        let app = App::new();
        assert!(app.pending_visualize.is_none());
    }

    #[test]
    fn test_pending_visualize_tracks_fields() {
        let now = Instant::now();
        let pv = PendingVisualize {
            session_id: "vis-1".to_string(),
            relay_url: Some("https://relay.test".to_string()),
            sent_at: now,
            pre_snapshot: HashMap::new(),
            detected_file: None,
            output_snapshot_len: 0,
            last_output_at: now,
        };
        assert_eq!(pv.session_id, "vis-1");
        assert_eq!(pv.relay_url.as_deref(), Some("https://relay.test"));
        assert!(pv.detected_file.is_none());
        assert!(pv.pre_snapshot.is_empty());
    }

    #[test]
    fn test_pending_visualize_clone() {
        let now = Instant::now();
        let pv = PendingVisualize {
            session_id: "vis-clone".to_string(),
            relay_url: None,
            sent_at: now,
            pre_snapshot: HashMap::new(),
            detected_file: Some("/tmp/test.html".to_string()),
            output_snapshot_len: 42,
            last_output_at: now,
        };
        let cloned = pv.clone();
        assert_eq!(cloned.session_id, "vis-clone");
        assert_eq!(cloned.detected_file.as_deref(), Some("/tmp/test.html"));
        assert_eq!(cloned.output_snapshot_len, 42);
    }

    #[test]
    fn test_pending_visualize_with_relay_url() {
        let now = Instant::now();
        let pv = PendingVisualize {
            session_id: "vis-relay".to_string(),
            relay_url: Some("https://relay.agora.build".to_string()),
            sent_at: now,
            pre_snapshot: HashMap::new(),
            detected_file: None,
            output_snapshot_len: 0,
            last_output_at: now,
        };
        assert_eq!(pv.relay_url.as_deref(), Some("https://relay.agora.build"));
    }

    #[test]
    fn test_pending_visualize_with_pre_snapshot() {
        let now = Instant::now();
        let mut snap = HashMap::new();
        snap.insert(
            PathBuf::from("/home/user/.agent/diagrams/existing.html"),
            SystemTime::now(),
        );
        let pv = PendingVisualize {
            session_id: "vis-snap".to_string(),
            relay_url: None,
            sent_at: now,
            pre_snapshot: snap,
            detected_file: None,
            output_snapshot_len: 0,
            last_output_at: now,
        };
        assert_eq!(pv.pre_snapshot.len(), 1);
        assert!(pv.pre_snapshot.contains_key(&PathBuf::from("/home/user/.agent/diagrams/existing.html")));
    }

    #[test]
    fn test_pending_visualize_detected_file_overrides_snapshot() {
        // When detected_file is Some, it should be used instead of snapshot diff
        let now = Instant::now();
        let pv = PendingVisualize {
            session_id: "vis-detect".to_string(),
            relay_url: None,
            sent_at: now,
            pre_snapshot: HashMap::new(),
            detected_file: Some("/home/user/.agent/diagrams/detected.html".to_string()),
            output_snapshot_len: 100,
            last_output_at: now,
        };
        // The detected_file should be preferred
        let file_path = pv.detected_file.clone().or_else(|| None);
        assert_eq!(file_path.as_deref(), Some("/home/user/.agent/diagrams/detected.html"));
    }

    #[test]
    fn test_pending_visualize_clone_preserves_snapshot() {
        let now = Instant::now();
        let mut snap = HashMap::new();
        snap.insert(PathBuf::from("/tmp/a.html"), SystemTime::now());
        snap.insert(PathBuf::from("/tmp/b.html"), SystemTime::now());
        let pv = PendingVisualize {
            session_id: "vis-snap-clone".to_string(),
            relay_url: None,
            sent_at: now,
            pre_snapshot: snap,
            detected_file: None,
            output_snapshot_len: 0,
            last_output_at: now,
        };
        let cloned = pv.clone();
        assert_eq!(cloned.pre_snapshot.len(), 2);
        assert!(cloned.pre_snapshot.contains_key(&PathBuf::from("/tmp/a.html")));
        assert!(cloned.pre_snapshot.contains_key(&PathBuf::from("/tmp/b.html")));
    }

    // ── Dynamic menu tests ──────────────────────────────────────────────

    #[test]
    fn test_menu_disconnected_keeps_local_terminals() {
        let app = App::new(); // astation_connected defaults to false
        assert!(!app.astation_connected);
        // Local terminals work offline; the connected agent panel requires Astation
        assert!(app.menu_actions.contains(&MenuAction::LaunchClaude));
        assert!(app.menu_actions.contains(&MenuAction::LaunchCodex));
        assert!(!app.menu_actions.contains(&MenuAction::AgentPanel));
        // Should contain Projects, Shell, Help, Exit
        assert!(app.menu_actions.contains(&MenuAction::ListProjects));
        assert!(app.menu_actions.contains(&MenuAction::ExecuteShell));
        assert!(app.menu_actions.contains(&MenuAction::Help));
        assert!(app.menu_actions.contains(&MenuAction::Exit));
        assert_eq!(app.menu_actions.len(), 6);
        assert_eq!(app.main_menu_items.len(), 6);
    }

    #[test]
    fn test_menu_connected_shows_all_items() {
        let mut app = App::new();
        app.astation_connected = true;
        app.rebuild_menu();
        assert!(app.menu_actions.contains(&MenuAction::LaunchClaude));
        assert!(app.menu_actions.contains(&MenuAction::LaunchCodex));
        assert!(app.menu_actions.contains(&MenuAction::AgentPanel));
        assert_eq!(app.menu_actions.len(), 7);
        assert_eq!(app.main_menu_items.len(), 7);
    }

    #[test]
    fn test_menu_rebuild_clamps_selected_index() {
        let mut app = App::new();
        app.astation_connected = true;
        app.rebuild_menu();
        // Select last item (Exit at index 6)
        app.selected_index = 6;
        // Disconnect and rebuild - only the connected agent panel disappears
        app.astation_connected = false;
        app.rebuild_menu();
        assert!(app.selected_index < app.menu_actions.len());
        assert_eq!(app.selected_index, 5); // clamped to last valid index
    }
}

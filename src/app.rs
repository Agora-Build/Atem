pub(crate) mod chat;
pub mod hosted;
mod reauth;
#[cfg(test)]
mod session_tests;
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
    collections::HashMap,
    fs,
    io,
    path::PathBuf,
    process::Command,
    time::Instant,
};
use tokio::time::Duration;

use crate::agora_api::{BffProject, format_projects};
use crate::claude_client::ClaudeClient;
use crate::codex_client::CodexClient;
use crate::pty_session::SpawnSpec;
use crate::session::{EXITED_KEEP, LaunchRequest, Provider, Session, SessionId, Sessions};
use crate::dispatch::{TaskDispatcher, WorkItem, WorkKind};
use crate::config::AtemConfig;
use crate::websocket_client::{AstationClient, AstationMessage};
use crate::agent_client::{AgentInfo, AgentOrigin, AgentProtocol, AgentStatus};
use crate::agent_registry::AgentRegistry;

/// The answer to every `visualizeRequest` from Astation.
pub const VISUALIZE_REMOVED: &str = "Diagram generation was removed from atem";
/// A mark task whose file no live Claude session's directory has.
pub const NO_PROJECT_SESSION: &str =
    "no Claude session for this project; run `atem agent launch claude` there";

#[derive(Debug, Clone)]
pub enum AppMode {
    MainMenu,
    TokenGeneration,
    /// The focused session's terminal (`App::focused`).
    Terminal,
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

pub struct App {
    pub last_session_refresh: Option<Instant>,
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
    /// Counts the times the Astation link became authenticated (a connect or
    /// a re-authentication): the session host gives each one its own attachment.
    pub astation_link_gen: u64,
    /// Inside `atem runtime`: the broker's sessions and the session-family
    /// messages for its session host (see `app/hosted.rs`). `None` in the TUI,
    /// which refuses remote session, terminal and chat messages.
    pub hosted: Option<hosted::Hosted>,
    /// Astation instance ID when currently connected (from CredentialSync or auth flow).
    pub connected_astation_id: Option<String>,
    /// Launch configuration for Codex sessions.
    pub codex_client: CodexClient,
    /// Launch configuration for Claude Code sessions.
    pub claude_client: ClaudeClient,
    /// The agent sessions launched in Atem.
    pub sessions: Sessions,
    /// The session the TUI shows in `AppMode::Terminal` (kept after leaving the view).
    pub focused: Option<SessionId>,
    pub force_terminal_redraw: bool,
    pub terminal_ui: crate::tui::terminal_view::State,
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
    pub pairing_code: Option<String>,
    /// Registry of the PTY agents Atem launched (Claude Code, Codex).
    pub agent_registry: AgentRegistry,
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
    /// Deadline of a re-authentication proof sent over the open socket that
    /// Astation has not accepted yet (see `app/reauth.rs`).
    pub astation_reauth: Option<Instant>,
    /// Where per-session chat directories are created (`chat-<uuid>`).
    pub chat_root: PathBuf,
    /// Stale chat directories under `chat_root` were swept (once per App).
    pub chat_swept: bool,
    /// Session logs: `<logs_dir>/<session_id>/{session.ansi,summary.md}`.
    pub logs_dir: PathBuf,
    /// The session the active main mark task was sent to.
    pub main_task_session: Option<SessionId>,
}

impl App {
    pub fn new() -> Self {
        let config = crate::config::AtemConfig::load().unwrap_or_default();
        let mut app = Self {
            last_session_refresh: None,
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
            astation_link_gen: 0,
            hosted: None,
            connected_astation_id: None,
            codex_client: CodexClient::new(),
            claude_client: ClaudeClient::new(),
            sessions: Sessions::default(),
            focused: None,
            force_terminal_redraw: false,
            terminal_ui: crate::tui::terminal_view::State::new(config.terminal_prefix.as_deref()),
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
            pairing_code: None,
            agent_registry: AgentRegistry::new(),
            active_agent_id: None,
            agent_panel_selected: 0,
            astation_connect_rx: None,
            astation_reconnect_at: None,
            astation_reauth: None,
            chat_root: crate::chat::claude::hooks::session_dir_root(),
            chat_swept: false,
            logs_dir: Self::default_logs_dir(),
            main_task_session: None,
        };
        app.rebuild_menu();
        app
    }

    /// `<config dir>/logs`. Tests get none (logs off) unless they set a temp dir.
    fn default_logs_dir() -> PathBuf {
        if cfg!(test) {
            PathBuf::new()
        } else {
            AtemConfig::config_dir().join("logs")
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

    /// Local terminals remain available while Astation is disconnected.
    pub fn rebuild_menu(&mut self) {
        self.menu_actions.clear();
        self.main_menu_items.clear();

        // Always available
        self.menu_actions.push(MenuAction::ListProjects);
        self.main_menu_items.push("\u{1f4cb} List Agora Projects".to_string());

        self.menu_actions.push(MenuAction::LaunchClaude);
        let running = |p| self.sessions.latest(p).is_some();
        let (claude_running, codex_running) = (running(Provider::Claude), running(Provider::Codex));
        self.main_menu_items.push(if claude_running {
            "Resume Claude Code".into()
        } else {
            "Launch Claude Code".into()
        });
        self.menu_actions.push(MenuAction::LaunchCodex);
        self.main_menu_items.push(if codex_running {
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
                self.launch_from_menu(Provider::Claude).await;
            }
            Some(MenuAction::LaunchCodex) => {
                // Launch Codex
                self.launch_from_menu(Provider::Codex).await;
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

    // MARK: - Sessions

    /// The size of a new session: the local viewport, else the default.
    pub(crate) fn launch_size(&self) -> (u16, u16) {
        match self.terminal_ui.viewport {
            (0, _) | (_, 0) => (crate::pty_session::DEFAULT_ROWS, crate::pty_session::DEFAULT_COLS),
            (rows, cols) => (rows.max(2), cols.max(2)),
        }
    }

    /// Start a new session (Claude gets its chat adapter). Registers it (id =
    /// session id) in the local registry. A failed launch
    /// returns its error and leaves nothing behind.
    pub async fn launch_session(&mut self, req: LaunchRequest) -> Result<SessionId> {
        if let Some(env) = &req.env {
            crate::session::check_env(env).map_err(|e| anyhow::anyhow!(e))?;
        }
        self.sessions.check_room()?;
        let LaunchRequest { provider, args, cwd, env, rows, cols } = req;
        let mut session = Session::new(provider, rows.clamp(2, 200), cols.clamp(2, 400));
        session.cwd = cwd.clone();
        let id = session.id.clone();
        // CLAUDE_CLI_*/CODEX_CLI_* from the launch environment when given.
        let (binary, spawn_args, chat) = match provider {
            Provider::Claude => {
                let client = match &env {
                    Some(env) => ClaudeClient::from_env(env),
                    None => self.claude_client.clone(),
                };
                let launch_args = [client.launch_args(), &args[..]].concat();
                // Chat hooks for this process; empty when chat could not be prepared.
                // On failure the prepared chat is dropped (removing its directory).
                let (chat, chat_args) = self.prepare_claude_chat(id.as_str(), &launch_args);
                (client.binary().to_string(), [chat_args, launch_args].concat(), chat)
            }
            Provider::Codex => {
                let client = match &env {
                    Some(env) => CodexClient::from_env(env),
                    None => self.codex_client.clone(),
                };
                (client.binary().to_string(), [client.launch_args(), &args[..]].concat(), None)
            }
        };
        let pty = crate::pty_session::spawn_spec(SpawnSpec {
            binary,
            args: spawn_args,
            cwd,
            env,
            rows,
            cols,
        })?;
        session.attach(pty);
        session.view = (rows, cols);
        session.chat = chat;
        self.sessions.insert(session)?;

        // Status stays Unknown and chat-v1 unadvertised until Claude's hooks report
        // the session (`poll_chat`); Codex has no chat adapter yet: its activity
        // can't be detected (Unknown) and it advertises no chat capability.
        self.agent_registry.register(AgentInfo {
            id: id.to_string(),
            name: match provider {
                Provider::Claude => "claude-code",
                Provider::Codex => "codex",
            }
            .to_string(),
            kind: provider.kind(),
            protocol: AgentProtocol::Pty,
            origin: AgentOrigin::Launched,
            status: AgentStatus::Unknown,
            session_ids: vec![],
            acp_url: None,
            pty_pid: None,
            capabilities: vec![],
        });
        self.rebuild_menu();
        Ok(id)
    }

    /// Stop a session's process; its exit is handled like any other.
    pub fn stop_session(&mut self, id: &SessionId) {
        if let Some(handle) = self.sessions.get(id).and_then(|s| s.handle.as_ref())
            && let Err(error) = handle.stop()
        {
            self.status_message = Some(error.to_string());
        }
    }

    /// Remove sessions that exited `EXITED_KEEP` (10 min) before `now`, with
    /// their registry entries.
    pub fn reap_exited_sessions(&mut self, now: Instant) {
        let due: Vec<SessionId> = self
            .sessions
            .iter()
            .filter(|s| s.exited_at.is_some_and(|at| now.saturating_duration_since(at) >= EXITED_KEEP))
            .map(|s| s.id.clone())
            .collect();
        if due.is_empty() {
            return;
        }
        for id in due {
            if self.sessions.remove(&id).is_none() { continue; }
            self.agent_registry.remove(id.as_str());
            if self.focused.as_ref() == Some(&id) {
                self.focused = None;
                if matches!(self.mode, AppMode::Terminal) {
                    self.mode = AppMode::MainMenu;
                    self.output_text.clear();
                }
            }
        }
        self.rebuild_menu();
    }

    /// Tests: the newest session of `provider`, live or exited.
    #[cfg(test)]
    pub(crate) fn last_session(&self, provider: Provider) -> Option<&Session> {
        self.sessions.iter().filter(|s| s.provider == provider).last()
    }

    /// The session shown by the terminal view, while it is open.
    pub fn focused_session(&self) -> Option<&Session> {
        if !matches!(self.mode, AppMode::Terminal) {
            return None;
        }
        self.sessions.get(self.focused.as_ref()?)
    }

    pub fn focused_session_mut(&mut self) -> Option<&mut Session> {
        if !matches!(self.mode, AppMode::Terminal) {
            return None;
        }
        self.sessions.get_mut(self.focused.as_ref()?)
    }

    /// The terminal view is open on `id`.
    pub fn is_focused(&self, id: &SessionId) -> bool {
        matches!(self.mode, AppMode::Terminal) && self.focused.as_ref() == Some(id)
    }

    /// Open the terminal view on `id`.
    pub fn focus_session(&mut self, id: &SessionId) {
        self.focused = Some(id.clone());
        self.mode = AppMode::Terminal;
        self.refresh_view(id);
    }

    /// Resume: the latest live session of `provider`. Launch: a new one when
    /// there is none (a failure is shown as a status message).
    async fn launch_from_menu(&mut self, provider: Provider) {
        self.input_text.clear();
        if let Some(id) = self.sessions.latest(provider) {
            self.focus_session(&id);
            return;
        }
        let (rows, cols) = self.launch_size();
        match self.launch_session(LaunchRequest::here(provider, Vec::new(), rows, cols)).await {
            Ok(id) => self.focus_session(&id),
            Err(err) => {
                self.status_message = Some(format!(
                    "\u{274c} Unable to start {} CLI: {}",
                    provider.product(),
                    err
                ));
            }
        }
    }

    pub fn update_output_from_terminal(&mut self, id: &SessionId) {
        let focused = self.is_focused(id);
        let Some(session) = self.sessions.get_mut(id) else { return; };
        let screen = session.terminal.screen();
        let (_rows, cols) = screen.size();

        let mut lines: Vec<String> = screen
            .rows(0, cols)
            .map(|line| line.replace('\u{0000}', ""))
            .collect();

        while lines.last().is_some_and(|line| line.trim().is_empty()) {
            lines.pop();
        }

        session.output_log = lines.join("\n");
        if focused {
            self.output_text = session.output_log.clone();
        }
    }

    pub fn send_data(&mut self, id: &SessionId, data: &str) {
        let Some(session) = self.sessions.get_mut(id) else { return; };
        if session.share.exit_status.is_some() { return; }
        if let Some(sender) = &session.input {
            match sender.send(data.to_string()) {
                Ok(()) => session.last_used = Instant::now(),
                Err(error) => self.status_message = Some(error.to_string()),
            }
        }
    }

    pub fn refresh_view(&mut self, id: &SessionId) {
        if self.is_focused(id)
            && let Some(session) = self.sessions.get(id)
        {
            self.output_text = session.output_log.clone();
        }
    }

    pub fn rebuild_terminal(&mut self, id: &SessionId) {
        let Some(session) = self.sessions.get_mut(id) else { return; };
        session.terminal.set_size(session.view.0.max(2), session.view.1.max(2));
        self.update_output_from_terminal(id);
    }

    pub fn adjust_terminal_size(&mut self, id: &SessionId, rows: u16, cols: u16) {
        let Some(session) = self.sessions.get_mut(id) else { return; };
        if session.input.as_ref().is_some_and(|s| s.remote_controlled()) { return; }
        let rows = rows.min(200);
        let cols = cols.min(400);
        if rows < 2 || cols < 2 {
            return;
        }
        if session.view == (rows, cols) && session.terminal.screen().size() == (rows, cols) {
            return;
        }

        session.view = (rows, cols);
        self.rebuild_terminal(id);

        let Some(session) = self.sessions.get(id) else { return; };
        if let Some(handle) = &session.handle
            && let Err(err) = handle.resize(rows, cols)
        {
            self.status_message = Some(format!(
                "Failed to resize {} terminal: {}",
                session.provider.label(),
                err
            ));
        }
    }

    /// Drain every session's PTY output. A panic while processing one session
    /// ends that session (its process is stopped), not the others.
    pub fn process_sessions_output(&mut self) {
        for id in self.sessions.ids() {
            let processed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                self.process_terminal_output(&id)
            }));
            if processed.is_err() {
                self.end_failed_session(&id);
            }
        }
    }

    /// Stop session `id` after an internal error and mark it exited.
    fn end_failed_session(&mut self, id: &SessionId) {
        eprintln!("atem: session {id} failed while processing its output; stopping it");
        let Some(session) = self.sessions.get_mut(id) else { return; };
        if let Some(handle) = &session.handle {
            let _ = handle.stop();
        }
        session.events = None;
        session.exited_at.get_or_insert_with(Instant::now);
        session.share.exit_status.get_or_insert_with(|| "ended after an internal error".into());
        if let Some(input) = &session.input {
            input.set_remote(false);
        }
        self.rebuild_menu();
    }

    /// The host part of the terminal UI's loop, run by the TUI and by `atem
    /// runtime` every tick: the Astation connection and its messages, every
    /// session's output, exited-session reaping, chat state and mark tasks.
    pub async fn tick_host(&mut self) {
        // Check if background Astation connection has completed
        self.poll_astation_connect();

        // Check if a reconnect retry timer has elapsed (fires only while awake)
        self.check_astation_reconnect();

        // Process any pending Astation messages (also detects WS disconnect)
        self.process_astation_messages().await;
        self.process_sessions_output();
        self.reap_exited_sessions(Instant::now());
        self.poll_chat();

        // Dispatcher: drain triage verdicts and try to send next task to main
        self.dispatcher.poll_triage_results();
        self.try_dispatch_main().await;

        // Dispatcher: collect completed background task results
        for result in self.dispatcher.poll_background_results() {
            let _ = self
                .astation_client
                .send_mark_result(&result.task_id, result.success, &result.output)
                .await;
            self.work_items.remove(&result.task_id);
        }

        // Dispatcher: deferred finalize flag (set when Claude session ends mid-task)
        if self.dispatcher.take_main_needs_finalize() {
            self.finalize_mark_task(true).await;
        }
    }

    pub fn finalize_session(&mut self, id: &SessionId) {
        let was_focused = self.is_focused(id);
        let Some(provider) = self.sessions.get(id).map(|s| s.provider) else { return; };
        let label = provider.label();

        if self.main_task_session.as_ref() == Some(id) {
            // The active mark task's session ended: finalize it (async).
            self.dispatcher.set_main_needs_finalize();
        }

        let Some(session) = self.sessions.get_mut(id) else { return; };
        let had_activity_before_finalize = !session.raw_log.trim().is_empty();

        crate::app::terminal::append_log(&mut session.raw_log, &mut session.raw_log_start, &format!("\u{2699}\u{fe0f} {} CLI session ended.\n", provider.product()));

        let mut status_parts: Vec<String> = Vec::new();

        if had_activity_before_finalize {
            match Self::persist_log(session, &self.logs_dir) {
                Ok(Some(path)) => {
                    let msg = format!("\u{1f4dd} {} log saved to {}", label, path.display());
                    crate::app::terminal::append_log(&mut session.raw_log, &mut session.raw_log_start, &format!("{}\n", msg));
                    status_parts.push(msg);
                }
                Ok(None) => {
                    status_parts
                        .push(format!("{} session ended with no output to save.", label));
                }
                Err(err) => {
                    let msg = format!("\u{26a0}\u{fe0f} Failed to save {} log: {}", label, err);
                    crate::app::terminal::append_log(&mut session.raw_log, &mut session.raw_log_start, &format!("{}\n", msg));
                    status_parts.push(msg);
                }
            }

            let summary = Self::generate_summary(session);
            match Self::write_summary_file(session, &self.logs_dir, &summary) {
                Ok(path) => {
                    let msg = format!("\u{1f4c4} Summary saved to {}", path.display());
                    crate::app::terminal::append_log(&mut session.raw_log, &mut session.raw_log_start, &format!("{}\n", msg));
                    status_parts.push(msg);
                }
                Err(err) => {
                    let msg = format!("\u{26a0}\u{fe0f} Failed to save {} summary: {}", label, err);
                    crate::app::terminal::append_log(&mut session.raw_log, &mut session.raw_log_start, &format!("{}\n", msg));
                    status_parts.push(msg);
                }
            }
        } else {
            status_parts.push(format!("{} session ended (no output captured).", label));
        }

        // The PTY receiver is dropped: the session has exited.
        session.events = None;
        session.exited_at = Some(Instant::now());
        session.waiting_exit = false;
        self.rebuild_menu();

        if was_focused {
            self.mode = AppMode::MainMenu;
            self.show_popup = false;
            self.popup_message.clear();
            self.output_text.clear();
            self.input_text.clear();
        }
        self.status_message = if status_parts.is_empty() {
            Some(format!("{} session ended.", label))
        } else {
            Some(status_parts.join(" | "))
        };
    }

    /// `<logs_dir>/<session_id>/`, created on first use. Both directories are
    /// private (0700): logs hold whatever the agent printed.
    fn session_log_dir(session: &Session, logs_dir: &std::path::Path) -> Result<PathBuf> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        if logs_dir.as_os_str().is_empty() {
            anyhow::bail!("session logs are off");
        }
        let dir = logs_dir.join(session.id.as_str());
        fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
        for path in [logs_dir, dir.as_path()] {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
        }
        Ok(dir)
    }

    /// Write a private (0600) log file.
    fn write_private(path: &std::path::Path, contents: &[u8]) -> Result<()> {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(contents)?;
        Ok(())
    }

    /// Saves the raw log as `<logs_dir>/<session_id>/session.ansi` (once per session).
    pub fn persist_log(session: &mut Session, logs_dir: &std::path::Path) -> Result<Option<PathBuf>> {
        if session.raw_log.trim().is_empty() {
            return Ok(None);
        }
        if let Some(path) = &session.log_file {
            return Ok(Some(path.clone()));
        }

        let path = Self::session_log_dir(session, logs_dir)?.join("session.ansi");
        Self::write_private(&path, session.raw_log.as_bytes())?;
        session.log_file = Some(path.clone());
        Ok(Some(path))
    }

    pub fn generate_summary(session: &Session) -> String {
        let mut summary = String::new();
        summary.push_str(&format!("# {} Session Summary\n\n", session.provider.product()));
        summary.push_str(&format!(
            "Commands executed: {}\n",
            session.user_actions.len()
        ));
        if !session.user_actions.is_empty() {
            summary.push_str("\n## Commands\n");
            let max_commands = 10;
            for cmd in session.user_actions.iter().take(max_commands) {
                summary.push_str("- ");
                summary.push_str(cmd);
                summary.push('\n');
            }
            if session.user_actions.len() > max_commands {
                summary.push_str("- \u{2026}\n");
            }
        }
        summary.push('\n');
        summary.push_str(&format!(
            "Total output lines captured: {}\n",
            session.output_log.lines().count()
        ));
        if let Some(path) = &session.log_file {
            summary.push_str(&format!("Full log saved at: {}\n", path.display()));
        } else {
            summary.push_str("Full log has not been saved yet.\n");
        }
        summary
    }

    /// `<logs_dir>/<session_id>/summary.md`.
    pub fn write_summary_file(session: &mut Session, logs_dir: &std::path::Path, summary: &str) -> Result<PathBuf> {
        let path = Self::session_log_dir(session, logs_dir)?.join("summary.md");
        Self::write_private(&path, summary.as_bytes())?;
        session.summary_file = Some(path.clone());
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

            // No valid session: try local without pairing (loopback bootstrap proof)
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
                    self.astation_link_gen += 1;
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
        if self.intercept_astation_reauth(&message).await {
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
                // `auth_required` and auth replies were handled by
                // `intercept_astation_reauth`; other status updates need nothing.
            }
            AstationMessage::VolumeUpdate { level } => {
                self.update_voice_volume(level);
            }
            AstationMessage::VideoToggle { active } => {
                self.video_active = active;
            }
            AstationMessage::AtemInstanceList { instances } => {
                self.peer_atems = instances;
            }
            AstationMessage::MarkTaskAssignment { task_id, received_at_ms } => {
                self.status_message = Some(format!("\u{1f4cc} Task received: {}", task_id));
                let Some(target) = self.mark_task_session(&task_id) else {
                    self.status_message = Some(format!("\u{274c} Task {}: {}", task_id, NO_PROJECT_SESSION));
                    let _ = self
                        .astation_client
                        .send_mark_result(&task_id, false, NO_PROJECT_SESSION)
                        .await;
                    return;
                };
                match self.load_and_build_work_item(&task_id, received_at_ms, &target) {
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
            AstationMessage::SessionWire(text) => {
                self.session_wire(text);
            }
            AstationMessage::VisualizeRequest { session_id, .. } => {
                // Diagram generation was removed; answer so Astation stops waiting.
                let _ = self
                    .astation_client
                    .send_visualize_result(&session_id, false, VISUALIZE_REMOVED, None)
                    .await;
            }
            AstationMessage::CredentialSync {
                access_token,
                refresh_token,
                expires_at,
                login_id,
                astation_id,
                save_credentials,
            } => {
                // Only for the pairing this connection authenticated under:
                // never re-creates a pairing removed (or replaced) meanwhile.
                let saved = self.astation_client.apply_bound(&astation_id, || {
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
                    store.save()
                });
                if let Err(e) = saved {
                    self.status_message = Some(format!("Paired credentials not saved: {e:#}"));
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
        if let Some(aid) = self.connected_astation_id.take() {
            let mut store = crate::credentials::CredentialStore::load();
            if let Some(entry) = store.find_paired_mut(&aid) {
                entry.disconnected_at = Some(crate::credentials::CredentialEntry::now_secs());
                let _ = store.save();
            }
        }
    }

    // MARK: - Mark Task Processing

    /// `<cwd>/.chisel/tasks/<task_id>.json` (a task id is a file name, never a path).
    pub(crate) fn mark_task_path(cwd: &std::path::Path, task_id: &str) -> Option<PathBuf> {
        let name = std::path::Path::new(task_id);
        let mut parts = name.components();
        let plain = matches!(
            (parts.next(), parts.next()),
            (Some(std::path::Component::Normal(_)), None)
        );
        plain.then(|| cwd.join(".chisel/tasks").join(format!("{task_id}.json")))
    }

    /// The live Claude session whose directory has the task (most recently used first).
    pub fn mark_task_session(&self, task_id: &str) -> Option<SessionId> {
        if let Some(hosted) = &self.hosted {
            return hosted.mark_task_session(task_id);
        }
        let mut sessions: Vec<&Session> = self
            .sessions
            .iter()
            .filter(|s| s.provider == Provider::Claude && s.is_live() && s.input.is_some())
            .collect();
        sessions.sort_by_key(|s| std::cmp::Reverse(s.last_used));
        sessions
            .into_iter()
            .find(|s| Self::mark_task_path(&s.cwd, task_id).is_some_and(|p| p.is_file()))
            .map(|s| s.id.clone())
    }

    /// Load the task JSON from `session`'s directory and build a WorkItem for it.
    pub fn load_and_build_work_item(&self, task_id: &str, received_at_ms: u64, session: &SessionId) -> Result<WorkItem> {
        let cwd = match &self.hosted {
            Some(hosted) => hosted.session(session).map(|s| s.cwd.clone()),
            None => self.sessions.get(session).map(|s| s.cwd.clone()),
        };
        let cwd = cwd
            .ok_or_else(|| anyhow::anyhow!("The session has ended"))?;
        let task_path = Self::mark_task_path(&cwd, task_id)
            .ok_or_else(|| anyhow::anyhow!("Invalid task id"))?;
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
            session: session.clone(),
            cwd,
        })
    }

    /// Pop the next task from the dispatcher's main queue and send it to the
    /// Claude session it was routed to. Waits while a viewer controls that session.
    pub async fn try_dispatch_main(&mut self) {
        if self.dispatcher.main_is_active() {
            return;
        }
        let Some(next) = self.dispatcher.peek_main() else { return; };
        let target = self.work_items.get(next).map(|item| item.session.clone());
        let controlled = match (&self.hosted, &target) {
            // Inside the runtime: a remote lease holder exists.
            (Some(hosted), Some(id)) => hosted.session(id).is_some_and(|s| s.live && s.remote_controlled),
            _ => target
                .as_ref()
                .and_then(|id| self.sessions.get(id))
                .filter(|s| s.is_live())
                .and_then(|s| s.input.as_ref())
                .is_some_and(|input| input.remote_controlled()),
        };
        if controlled {
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

        let id = item.session.clone();
        let live = match &self.hosted {
            Some(hosted) => hosted.session(&id).is_some_and(|s| s.live),
            None => self.sessions.get(&id).is_some_and(|s| s.is_live() && s.input.is_some()),
        };
        if !live {
            let _ = self
                .astation_client
                .send_mark_result(&task_id, false, NO_PROJECT_SESSION)
                .await;
            self.dispatcher.complete_main();
            self.work_items.remove(&task_id);
            // Try the next task.
            Box::pin(self.try_dispatch_main()).await;
            return;
        }

        if let Some(hosted) = self.hosted.as_mut() {
            // The broker writes it through the session's worker (local-origin
            // input: no remote lease exists, and none is revoked).
            hosted.writes.push((task_id.clone(), id.clone(), format!("{}\n\r", item.prompt)));
            self.main_task_session = Some(id);
            self.status_message = Some(format!("\u{1f4cc} Task {} → Claude", task_id));
            return;
        }
        self.focused = Some(id.clone());
        self.mode = AppMode::Terminal;
        self.input_text.clear();
        let session = self.sessions.get_mut(&id).expect("checked above");
        session.waiting_exit = false;
        if session.output_log.is_empty() {
            session.output_log = "\u{1f916} Claude Code CLI Session (Mark Task)\n\n".to_string();
        }
        // One queued write prevents a rejected prompt from submitting an unrelated draft.
        let result = session.input.as_ref().unwrap().send(format!("{}\n\r", item.prompt));
        if let Err(error) = result {
            let _ = self.astation_client.send_mark_result(&task_id, false, &error.to_string()).await;
            self.dispatcher.complete_main();
            self.work_items.remove(&task_id);
            return;
        }
        session.last_used = Instant::now();
        session.user_actions.push(format!("[Mark Task {}]", task_id));
        self.main_task_session = Some(id.clone());

        self.refresh_view(&id);
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
        self.main_task_session = None;
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

    pub async fn process_astation_messages(&mut self) {
        // Drain all pending messages (non-blocking try_recv loop)
        let mut message_count = 0;
        while message_count < 32 {
            let Some(message) = self.astation_client.recv_message() else { break; };
            self.handle_astation_message(message).await;
            message_count += 1;
        }
        self.check_astation_reauth_deadline();

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
    fn test_pairing_code_default_is_none() {
        let app = App::new();
        assert!(app.pairing_code.is_none());
    }

    /// Diagram generation was removed: every `visualizeRequest` is answered
    /// at once with an unsupported `visualizeResult`, and nothing is sent to
    /// an agent.
    #[tokio::test]
    async fn visualize_request_is_answered_as_unsupported() {
        use futures_util::StreamExt;
        use tokio_tungstenite::tungstenite::Message as WsMessage;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut socket = tokio_tungstenite::accept_async(stream).await.unwrap();
            loop {
                match socket.next().await {
                    Some(Ok(WsMessage::Text(text))) => {
                        return serde_json::from_str::<AstationMessage>(&text).unwrap();
                    }
                    Some(Ok(_)) => {}
                    other => panic!("socket ended before a reply: {other:?}"),
                }
            }
        });

        let mut app = App::new();
        app.astation_client.connect_raw(&format!("ws://{address}")).await.unwrap();
        app.handle_astation_message(AstationMessage::VisualizeRequest {
            session_id: "vis-1".into(),
            topic: "WebRTC flow".into(),
            relay_url: Some("https://relay.test".into()),
        })
        .await;

        let reply = tokio::time::timeout(Duration::from_secs(3), peer)
            .await
            .expect("no visualizeResult reached Astation")
            .unwrap();
        match reply {
            AstationMessage::VisualizeResult { session_id, success, message, file_path } => {
                assert_eq!(session_id, "vis-1");
                assert!(!success);
                assert_eq!(message, "Diagram generation was removed from atem");
                assert!(file_path.is_none());
            }
            other => panic!("expected VisualizeResult, got {other:?}"),
        }
        assert_eq!(app.sessions.iter().count(), 0, "no agent session was started");
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

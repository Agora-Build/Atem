pub mod hosted;
pub mod op_route;
mod reauth;
#[cfg(test)]
mod session_tests;

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
use crate::session::SessionId;
use crate::dispatch::{TaskDispatcher, WorkItem, WorkKind};
use crate::config::AtemConfig;
use crate::runtime::protocol::SessionSummary;
use crate::websocket_client::{AstationClient, AstationMessage};

/// The answer to every `visualizeRequest` from Astation.
pub const VISUALIZE_REMOVED: &str = "Diagram generation was removed from atem";
/// A mark task whose file no live Claude session's directory has.
pub const NO_PROJECT_SESSION: &str =
    "no Claude session for this project; run `atem agent launch claude` there";

#[derive(Debug, Clone)]
pub enum AppMode {
    MainMenu,
    TokenGeneration,
    CommandExecution,
    AgentPanel,
}

/// Actions available in the main menu. Agent entries launch and attach
/// sessions through `atem runtime`, which owns them and the Astation link.
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
    /// Reconnect after the link drops (tests turn it off: they never reach a real Astation).
    pub astation_reconnect: bool,
    /// Inside `atem runtime`: the broker's sessions and the session-family
    /// messages for its session host (see `app/hosted.rs`). `None` in the TUI,
    /// which refuses remote session, terminal and chat messages.
    pub hosted: Option<hosted::Hosted>,
    /// Astation instance ID when currently connected (from CredentialSync or auth flow).
    pub connected_astation_id: Option<String>,
    pub force_terminal_redraw: bool,
    pub show_certificates: bool,
    pub cached_projects: Vec<BffProject>,
    pub config: AtemConfig,
    pub dispatcher: TaskDispatcher,
    pub work_items: HashMap<String, WorkItem>,
    pub pairing_code: Option<String>,
    /// The menu: the runtime's sessions as its last `list` gave them (the
    /// agent panel), or why it couldn't be asked.
    pub runtime_sessions: Vec<SessionSummary>,
    pub runtime_note: Option<String>,
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
    /// The session the active main mark task was sent to.
    pub main_task_session: Option<SessionId>,
    /// Mark-task notices for `atem runtime`: those naming a session go to
    /// that session's frontend only, the others to the runtime's log.
    pub task_notices: Vec<(Option<SessionId>, String)>,
    /// The running Astation operation's replies (`atem runtime`; see
    /// `app/op_route.rs`).
    pub op_route: Option<op_route::OpRoute>,
    /// Why the last background connect failed, when the saved session was
    /// the problem (shown to a pairing or unlock waiting for the link).
    pub astation_connect_error: Option<String>,
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
            astation_reconnect: true,
            hosted: None,
            connected_astation_id: None,
            force_terminal_redraw: false,
            show_certificates: false,
            cached_projects: Vec::new(),
            config,
            dispatcher: TaskDispatcher::new(),
            work_items: HashMap::new(),
            pairing_code: None,
            runtime_sessions: Vec::new(),
            runtime_note: None,
            agent_panel_selected: 0,
            astation_connect_rx: None,
            astation_reconnect_at: None,
            astation_reauth: None,
            main_task_session: None,
            task_notices: Vec::new(),
            op_route: None,
            astation_connect_error: None,
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

    /// The menu: projects, the agent entries (through the runtime), the
    /// shell, help. The agent panel lists the runtime's sessions.
    pub fn rebuild_menu(&mut self) {
        self.menu_actions.clear();
        self.main_menu_items.clear();

        self.menu_actions.push(MenuAction::ListProjects);
        self.main_menu_items.push("\u{1f4cb} List Agora Projects".to_string());

        self.menu_actions.push(MenuAction::LaunchClaude);
        self.main_menu_items.push("Launch Claude Code".into());
        self.menu_actions.push(MenuAction::LaunchCodex);
        self.main_menu_items.push("Launch Codex".into());

        self.menu_actions.push(MenuAction::AgentPanel);
        let running = self.runtime_sessions.iter().filter(|s| s.state == "running").count();
        self.main_menu_items.push(format!("\u{1f916} Agent Sessions ({running} running)"));

        self.menu_actions.push(MenuAction::ExecuteShell);
        self.main_menu_items.push("\u{1f4bb} Execute Shell Command".to_string());

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
            Some(MenuAction::LaunchClaude | MenuAction::LaunchCodex) => {
                // The TUI loop launches through the runtime (it owns the terminal).
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
            \u{2022} \u{1f916} Launch Claude Code or Codex (sessions run in the atem runtime)\n\
            \u{2022} \u{1f916} Agent Sessions: open a running session\n\
            \u{2022} \u{1f4bb} Execute shell commands\n\
            \u{2022} \u{1f3af} Generate RTC tokens (via shell)\n\
            \u{2022} In a session, the prefix then h detaches; it keeps running\n\n\
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

    /// A mark-task notice about session `sid` (`None`: no session's).
    fn task_notice(&mut self, sid: Option<SessionId>, text: String) {
        self.task_notices.push((sid, text));
    }

    /// The host part of `atem runtime`'s loop, every tick: the Astation
    /// connection and its messages, and mark tasks (the sessions are the
    /// broker's).
    pub async fn tick_host(&mut self) {
        // Check if background Astation connection has completed
        self.poll_astation_connect();

        // Check if a reconnect retry timer has elapsed (fires only while awake)
        self.check_astation_reconnect();

        // Process any pending Astation messages (also detects WS disconnect)
        self.process_astation_messages().await;

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

            // A refused or missing saved session is worth telling a
            // pairing or unlock that waits for this link.
            let mut session_problem = None;
            let mut note = |error: anyhow::Error| {
                if error.downcast_ref::<crate::websocket_client::SessionError>().is_some() {
                    session_problem = Some(error);
                }
            };

            // If we have a valid session, try local with session auth
            if let Some(ref sess) = session {
                if sess.is_valid() {
                    match client
                        .connect_with_session(local_url, &sess.session_id)
                        .await
                    {
                        Ok(()) => {
                            let _ = tx.send(Ok((client, None)));
                            return;
                        }
                        Err(error) => note(error),
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
                Err(error) => note(error),
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
                    Err(error) => note(error),
                }
            }

            let _ = tx.send(Err(match session_problem {
                Some(error) => crate::runtime::ops::session_advice(error),
                None => anyhow::anyhow!("Astation not reachable"),
            }));
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
                    self.astation_connect_error = None;
                    self.pairing_code = code;
                    self.rebuild_menu();
                    self.status_message = Some("Connected to Astation".to_string());

                    // Refresh session on successful connection
                    self.refresh_saved_session();
                }
                Ok(Err(error)) => {
                    self.astation_connect_error = error
                        .downcast_ref::<crate::runtime::ops::SessionAdvice>()
                        .map(|advice| advice.0.clone());
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
        // A running pairing or unlock's replies are its own.
        let Some(message) = self.route_to_op(message) else {
            return;
        };
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
            AstationMessage::MarkTaskAssignment { task_id, received_at_ms } => {
                self.task_notice(None, format!("\u{1f4cc} Task received: {}", task_id));
                let Some(target) = self.mark_task_session(&task_id) else {
                    self.task_notice(None, format!("\u{274c} Task {}: {}", task_id, NO_PROJECT_SESSION));
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
                        self.task_notice(Some(target.clone()), format!("\u{274c} Failed to load task {}: {}", task_id, err));
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
            AstationMessage::SessionOversize { id } => {
                self.session_refusal(id, crate::session_protocol::wire::ErrorCode::UnsupportedVersion, None);
            }
            AstationMessage::RemovedOp => {
                // r6 §0: refused, with no effect.
                self.session_refusal(
                    None,
                    crate::session_protocol::wire::ErrorCode::UnsupportedVersion,
                    Some(hosted::REMOVED_OP),
                );
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
                // In the link's own profile (never another one).
                let profile = self.astation_client.profile();
                let saved = self.astation_client.apply_bound(&astation_id, || {
                    let path = profile?.credentials;
                    let mut store = crate::credentials::CredentialStore::load_from(&path);
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
                    store.save_to(&path)
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
        // The link's own profile (never another one).
        if let Some(aid) = self.connected_astation_id.take()
            && let Ok(profile) = self.astation_client.profile()
        {
            let mut store = crate::credentials::CredentialStore::load_from(&profile.credentials);
            if let Some(entry) = store.find_paired_mut(&aid) {
                entry.disconnected_at = Some(crate::credentials::CredentialEntry::now_secs());
                let _ = store.save_to(&profile.credentials);
            }
        }
    }

    /// Keeps the link profile's saved session (`session.json`) fresh.
    fn refresh_saved_session(&self) {
        if let Ok(path) = self.astation_client.saved_session_file()
            && let Some(mut session) = crate::auth::AuthSession::load_saved_from(&path)
        {
            session.refresh();
            let _ = session.save_to(&path);
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
    /// Only inside the runtime (`hosted`): the menu TUI runs no sessions.
    pub fn mark_task_session(&self, task_id: &str) -> Option<SessionId> {
        self.hosted.as_ref()?.mark_task_session(task_id)
    }

    /// Load the task JSON from `session`'s directory and build a WorkItem for it.
    pub fn load_and_build_work_item(&self, task_id: &str, received_at_ms: u64, session: &SessionId) -> Result<WorkItem> {
        let cwd = self
            .hosted
            .as_ref()
            .and_then(|hosted| hosted.session(session))
            .map(|s| s.cwd.clone())
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
    /// Claude session it was routed to (the broker writes it). Waits while a
    /// remote lease holder controls that session.
    pub async fn try_dispatch_main(&mut self) {
        if self.dispatcher.main_is_active() {
            return;
        }
        let Some(next) = self.dispatcher.peek_main() else { return; };
        let target = self.work_items.get(next).map(|item| item.session.clone());
        let controlled = match (&self.hosted, &target) {
            (Some(hosted), Some(id)) => hosted.session(id).is_some_and(|s| s.live && s.remote_controlled),
            _ => false,
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
                self.task_notice(None, format!("\u{274c} Task item not found: {}", task_id));
                self.dispatcher.complete_main();
                return;
            }
        };

        let id = item.session.clone();
        let live = self.hosted.as_ref().and_then(|h| h.session(&id)).is_some_and(|s| s.live);
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
            self.main_task_session = Some(id.clone());
            self.task_notice(Some(id), format!("\u{1f4cc} Task {} \u{2192} Claude", task_id));
        }
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
            self.refresh_saved_session();
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
        if !self.astation_reconnect {
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
        let _profile = crate::test_profile::temp();
        let app = App::new();
        assert!(app.pairing_code.is_none());
    }

    /// Diagram generation was removed: every `visualizeRequest` is answered
    /// at once with an unsupported `visualizeResult`, and nothing is sent to
    /// an agent.
    #[tokio::test]
    async fn visualize_request_is_answered_as_unsupported() {
        let _profile = crate::test_profile::temp();
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
    }

    // ── Menu tests ──────────────────────────────────────────────────────

    #[test]
    fn the_menu_launches_and_lists_agents_through_the_runtime() {
        let _profile = crate::test_profile::temp();
        let app = App::new();
        // The menu never opens its own Astation connection.
        assert!(!app.astation_connected && app.astation_connect_rx.is_none());
        assert_eq!(
            app.menu_actions,
            [
                MenuAction::ListProjects,
                MenuAction::LaunchClaude,
                MenuAction::LaunchCodex,
                MenuAction::AgentPanel,
                MenuAction::ExecuteShell,
                MenuAction::Help,
                MenuAction::Exit,
            ]
        );
        assert_eq!(app.main_menu_items.len(), 7);
        assert_eq!(app.main_menu_items[3], "\u{1f916} Agent Sessions (0 running)");
    }

    #[test]
    fn the_agent_entry_counts_the_runtime_sessions() {
        let _profile = crate::test_profile::temp();
        let mut app = App::new();
        let session = |id: &str, state: &str| SessionSummary {
            id: id.into(),
            provider: "codex".into(),
            cwd: "/tmp".into(),
            created_at_ms: 1,
            state: state.into(),
            status: "unknown".into(),
            attached: false,
            remote_controlled: false,
            exited: None,
            rows: 24,
            cols: 80,
            generation: "g".into(),
        };
        app.runtime_sessions = vec![
            session("ses-aaaaaaaaaaaa", "running"),
            session("ses-bbbbbbbbbbbb", "exited"),
            session("ses-cccccccccccc", "running"),
        ];
        app.selected_index = 99;
        app.rebuild_menu();
        assert_eq!(app.main_menu_items[3], "\u{1f916} Agent Sessions (2 running)");
        assert_eq!(app.selected_index, 6); // clamped to last valid index
    }
}

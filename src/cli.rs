use anyhow::Result;
use clap::{Parser, Subcommand};

/// Resolve Agora REST credentials following the canonical priority:
///   runtime-synced (via WS) > env vars > config file
///
/// For CLI commands there is no in-memory synced state, so the effective
/// priority here is: env vars > config file > Astation WS fallback.
///
/// Callers inside the TUI that already have synced credentials should use
/// them directly and not call this function.
async fn resolve_credentials(
    config: &crate::config::AtemConfig,
) -> Result<(String, String)> {
    // 1. env vars override config — AtemConfig::load() already applied env vars,
    //    so customer_id / customer_secret already reflect env > config file.
    if let (Some(cid), Some(csecret)) =
        (config.customer_id.clone(), config.customer_secret.clone())
    {
        return Ok((cid, csecret));
    }

    // 2. No local credentials — try Astation WS (receives credentialSync on connect).
    let ws_url = config.astation_ws().to_string();
    let mut client = crate::websocket_client::AstationClient::new();

    // Try session-based connection first if we have a valid saved session
    let connected = if let Some(session) = crate::auth::AuthSession::load_saved() {
        if session.is_valid() {
            client.connect_with_session(&ws_url, &session.session_id).await.is_ok()
        } else {
            false
        }
    } else {
        false
    };

    // Fall back to direct connection if session auth failed
    if !connected {
        client.connect(&ws_url).await.map_err(|e| {
            anyhow::anyhow!(
                "No credentials found locally and could not connect to Astation ({ws_url}): {e}\n\
                Fix options:\n\
                1. Run `atem login` to authenticate with Astation\n\
                2. Set AGORA_CUSTOMER_ID and AGORA_CUSTOMER_SECRET env vars"
            )
        })?;
    }

    let timeout = tokio::time::Duration::from_secs(5);
    let result = tokio::time::timeout(timeout, async {
        loop {
            match client.recv_message_async().await {
                Some(crate::websocket_client::AstationMessage::CredentialSync {
                    customer_id,
                    customer_secret,
                }) => return Some((customer_id, customer_secret)),
                Some(_) => continue,
                None => return None,
            }
        }
    })
    .await;

    let (cid, csecret) = result
        .map_err(|_| anyhow::anyhow!("Timed out waiting for credentials from Astation"))?
        .ok_or_else(|| anyhow::anyhow!("Astation disconnected before sending credentials"))?;

    // Ask whether to persist to config.toml
    let id_preview = &cid[..4.min(cid.len())];
    print!("Save credentials ({}...) to config? [Y/n] ", id_preview);
    use std::io::Write;
    std::io::stdout().flush().ok();
    let mut input = String::new();
    std::io::stdin().read_line(&mut input).unwrap_or(0);
    if !matches!(input.trim().to_lowercase().as_str(), "n" | "no") {
        let mut cfg = crate::config::AtemConfig::load().unwrap_or_default();
        cfg.customer_id = Some(cid.clone());
        cfg.customer_secret = Some(csecret.clone());
        if let Err(e) = cfg.save_to_disk() {
            eprintln!("Warning: could not persist credentials to config: {e}");
        } else {
            println!(
                "Credentials saved to {}",
                crate::config::AtemConfig::config_path().display()
            );
        }
    } else {
        println!("Credentials available for this session only.");
    }

    Ok((cid, csecret))
}

#[derive(Parser)]
#[command(name = "atem")]
#[command(version)]
#[command(about = "Agora.io CLI tool with AI integration")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    Token {
        #[command(subcommand)]
        token_command: TokenCommands,
    },
    /// Show resolved configuration
    Config {
        #[command(subcommand)]
        config_command: ConfigCommands,
    },
    /// Manage active project
    Project {
        #[command(subcommand)]
        project_command: ProjectCommands,
    },
    /// List Agora resources
    List {
        #[command(subcommand)]
        list_command: ListCommands,
    },
    /// Interactive REPL with AI-powered command interpretation
    Repl,
    /// Authenticate with Astation (OTP + deep link pairing)
    Login {
        /// Astation server URL (defaults to https://station.agora.build)
        #[arg(long)]
        server: Option<String>,
        /// After pairing, connect to Astation and save Agora credentials to config
        #[arg(long)]
        save_credentials: bool,
    },
    /// Clear saved authentication session
    Logout,
    /// Manage and communicate with AI agents (Claude Code, Codex, etc.)
    Agent {
        #[command(subcommand)]
        agent_command: AgentCommands,
    },
    /// Manage Agora dev servers
    Serv {
        #[command(subcommand)]
        serv_command: ServCommands,
    },
}

#[derive(Subcommand)]
pub enum TokenCommands {
    Rtc {
        #[command(subcommand)]
        rtc_command: RtcCommands,
    },
    Rtm {
        #[command(subcommand)]
        rtm_command: RtmCommands,
    },
}

#[derive(Subcommand)]
pub enum RtcCommands {
    /// Create an RTC token
    Create {
        /// Channel name
        #[arg(long)]
        channel: Option<String>,
        /// User ID
        #[arg(long)]
        uid: Option<String>,
        /// Role: publisher or subscriber
        #[arg(long, default_value = "publisher")]
        role: String,
        /// Expiry in seconds
        #[arg(long, default_value = "3600")]
        expire: u32,
    },
    /// Decode an existing token
    Decode {
        /// The token string to decode
        token: String,
    },
}

#[derive(Subcommand)]
pub enum RtmCommands {
    /// Create an RTM token
    Create {
        /// User ID
        #[arg(long)]
        user_id: Option<String>,
        /// Expiry in seconds
        #[arg(long, default_value = "3600")]
        expire: u32,
    },
}

#[derive(Subcommand)]
pub enum ConfigCommands {
    /// Show resolved configuration with secrets masked
    Show,
    /// Set a configuration value
    Set {
        /// Config key (astation_ws, astation_relay_url)
        key: String,
        /// Config value
        value: String,
    },
    /// Clear the active project
    Clear,
}

#[derive(Subcommand)]
pub enum ProjectCommands {
    /// Set active project by App ID or index from `atem list project`
    Use {
        /// App ID or 1-based index from `atem list project`
        app_id_or_index: String,
    },
    /// Show current active project
    Show {
        /// Show full app certificate (unmasked)
        #[arg(long)]
        with_certificate: bool,
    },
}

#[derive(Subcommand)]
pub enum ListCommands {
    /// List all Agora projects in your account
    Project {
        /// Show app certificates in output
        #[arg(long)]
        show_certificates: bool,
    },
}


#[derive(Subcommand)]
pub enum AgentCommands {
    /// Scan lockfiles and list all detected agents
    List,
    /// Launch Claude Code as a PTY agent
    Launch {
        /// Agent type to launch (claude-code or codex)
        #[arg(default_value = "claude-code")]
        agent_type: String,
    },
    /// Connect to an ACP agent at a WebSocket URL and show its server info
    Connect {
        /// WebSocket URL of the ACP server (e.g. ws://localhost:8765)
        url: String,
        /// Timeout for the ACP probe in milliseconds
        #[arg(long, default_value = "3000")]
        timeout: u64,
    },
    /// Send a text prompt to a running ACP agent and stream the response
    Prompt {
        /// WebSocket URL of the ACP server
        url: String,
        /// The prompt text to send
        text: String,
        /// Timeout per response event in milliseconds
        #[arg(long, default_value = "30000")]
        timeout: u64,
    },
    /// Probe a WebSocket URL to check for ACP support
    Probe {
        /// WebSocket URL to probe
        url: String,
        /// Timeout in milliseconds
        #[arg(long, default_value = "2000")]
        timeout: u64,
    },
    /// Generate a visual HTML diagram via an active ACP agent
    Visualize {
        /// Topic or system to visualize
        topic: String,
        /// WebSocket URL of the ACP server (auto-detected if omitted)
        #[arg(long)]
        url: Option<String>,
        /// Timeout in milliseconds
        #[arg(long, default_value = "120000")]
        timeout: u64,
        /// Skip opening the result in a browser
        #[arg(long)]
        no_browser: bool,
    },
}

#[derive(Subcommand)]
pub enum ServCommands {
    /// Launch a browser-based RTC audio/video test page (HTTPS)
    Rtc {
        /// Channel name
        #[arg(long, default_value = "test")]
        channel: String,
        /// HTTPS port (0 = auto-assign)
        #[arg(long, default_value = "0")]
        port: u16,
        /// Token expiry in seconds
        #[arg(long, default_value = "3600")]
        expire: u32,
        /// Don't auto-open the browser
        #[arg(long)]
        no_browser: bool,
        /// Run as a background daemon
        #[arg(long)]
        background: bool,
        /// Internal: marks this process as the detached daemon (hidden)
        #[arg(long, hide = true)]
        _serv_daemon: bool,
    },
    /// Host diagrams from SQLite — serves HTML at /d/{id}
    Diagrams {
        /// HTTP port (default: 8787)
        #[arg(long, default_value = "8787")]
        port: u16,
        /// Run as a background daemon
        #[arg(long)]
        background: bool,
        /// Internal: marks this process as the detached daemon (hidden)
        #[arg(long, hide = true)]
        _serv_daemon: bool,
    },
    /// List running background servers
    List,
    /// Kill a background server by ID
    Kill {
        /// Server ID (e.g. rtc-demo-8443)
        id: String,
    },
    /// Kill all background servers
    Killall,
}

pub async fn handle_cli_command(command: Commands) -> Result<()> {
    match command {
        Commands::Token { token_command } => match token_command {
            TokenCommands::Rtc { rtc_command } => match rtc_command {
                RtcCommands::Create {
                    channel,
                    uid,
                    role,
                    expire,
                } => {
                    let app_id = crate::config::ActiveProject::resolve_app_id(None)?;
                    let app_certificate =
                        crate::config::ActiveProject::resolve_app_certificate(None)?;

                    let channel_name = channel.as_deref().unwrap_or("test-channel");
                    let uid_str = uid.as_deref().unwrap_or("0");
                    let token_role = match role.as_str() {
                        "subscriber" | "sub" => crate::token::Role::Subscriber,
                        _ => crate::token::Role::Publisher,
                    };

                    // Use time sync for accurate issued_at
                    let mut time_sync = crate::time_sync::TimeSync::new();
                    let now = time_sync.now().await? as u32;

                    let token = crate::token::build_token_rtc(
                        &app_id,
                        &app_certificate,
                        channel_name,
                        uid_str,
                        token_role,
                        expire,
                        now,
                    )?;

                    if token.is_empty() {
                        println!("Error: App certificate is empty. Cannot generate token.");
                        return Ok(());
                    }

                    println!("RTC Token created successfully:");
                    println!("{}", token);
                    println!("\nToken Details:");
                    println!("  Channel: {}", channel_name);
                    println!("  UID: {}", uid_str);
                    println!("  Role: {:?}", token_role);
                    println!("  Valid for: {}s", expire);

                    let offset = time_sync.offset();
                    if offset != 0 {
                        println!("  Clock offset: {}s", offset);
                    }

                    Ok(())
                }
                RtcCommands::Decode { token } => {
                    let info = crate::token::decode_token(&token)?;
                    println!("Decoded Token:");
                    println!("{}", info.display());
                    Ok(())
                }
            },
            TokenCommands::Rtm { rtm_command } => match rtm_command {
                RtmCommands::Create { user_id, expire } => {
                    let app_id = crate::config::ActiveProject::resolve_app_id(None)?;
                    let app_certificate =
                        crate::config::ActiveProject::resolve_app_certificate(None)?;

                    let uid = user_id.as_deref().unwrap_or("atem01");

                    // Use time sync for accurate issued_at
                    let mut time_sync = crate::time_sync::TimeSync::new();
                    let now = time_sync.now().await? as u32;

                    let token = crate::token::build_token_rtm(
                        &app_id,
                        &app_certificate,
                        uid,
                        expire,
                        now,
                    )?;

                    if token.is_empty() {
                        println!("Error: App certificate is empty. Cannot generate token.");
                        return Ok(());
                    }

                    println!("RTM Token created successfully:");
                    println!("{}", token);
                    println!("\nToken Details:");
                    println!("  User ID: {}", uid);
                    println!("  Valid for: {}s", expire);

                    let offset = time_sync.offset();
                    if offset != 0 {
                        println!("  Clock offset: {}s", offset);
                    }

                    Ok(())
                }
            },
        },
        Commands::Config { config_command } => match config_command {
            ConfigCommands::Show => {
                let config = crate::config::AtemConfig::load()?;
                println!("{}", config.display_masked());
                Ok(())
            }
            ConfigCommands::Set { key, value } => {
                let mut config = crate::config::AtemConfig::load()?;
                match key.as_str() {
                    "astation_ws" => {
                        config.astation_ws = Some(value.clone());
                        config.save_to_disk()?;
                        println!("astation_ws = {}", value);
                    }
                    "astation_relay_url" => {
                        config.astation_relay_url = Some(value.clone());
                        config.save_to_disk()?;
                        println!("astation_relay_url = {}", value);
                    }
                    _ => {
                        anyhow::bail!(
                            "Unknown config key '{}'. Available keys: astation_ws, astation_relay_url",
                            key
                        );
                    }
                }
                Ok(())
            }
            ConfigCommands::Clear => {
                crate::config::ActiveProject::clear()?;
                println!("Active project cleared.");
                Ok(())
            }
        },
        Commands::Project { project_command } => match project_command {
            ProjectCommands::Use { app_id_or_index } => {
                // If it parses as a number, treat as index into cached project list
                if let Ok(idx) = app_id_or_index.parse::<usize>() {
                    let project = crate::config::ProjectCache::get(idx).ok_or_else(|| {
                        let hint = match crate::config::ProjectCache::load() {
                            Some(projects) => format!(
                                "Valid range: 1-{}. Run `atem list project` to refresh.",
                                projects.len()
                            ),
                            None => "No cached projects. Run `atem list project` first.".to_string(),
                        };
                        anyhow::anyhow!("Invalid project index {}. {}", idx, hint)
                    })?;
                    let active = crate::config::ActiveProject {
                        app_id: project.vendor_key.clone(),
                        app_certificate: project.sign_key.clone(),
                        name: project.name.clone(),
                    };
                    active.save()?;
                    println!("Active project set: {} ({})", project.name, project.vendor_key);
                } else {
                    // Treat as App ID — fetch from API to resolve name + certificate
                    let config = crate::config::AtemConfig::load()?;
                    let (cid, csecret) = resolve_credentials(&config).await?;
                    let projects =
                        crate::agora_api::fetch_agora_projects_with_credentials(&cid, &csecret).await?;
                    if let Err(e) = crate::config::ProjectCache::save(&projects) {
                        eprintln!("Warning: could not cache projects: {}", e);
                    }
                    let project = projects
                        .iter()
                        .find(|p| p.vendor_key == app_id_or_index)
                        .ok_or_else(|| {
                            anyhow::anyhow!("Project with App ID '{}' not found", app_id_or_index)
                        })?;
                    let active = crate::config::ActiveProject {
                        app_id: project.vendor_key.clone(),
                        app_certificate: project.sign_key.clone(),
                        name: project.name.clone(),
                    };
                    active.save()?;
                    println!("Active project set: {} ({})", active.name, active.app_id);
                }
                Ok(())
            }
            ProjectCommands::Show { with_certificate } => {
                match crate::config::ActiveProject::load() {
                    Some(proj) => {
                        println!("Active project: {}", proj.name);
                        println!("App ID: {}", proj.app_id);
                        let cert_display = if with_certificate {
                            proj.app_certificate.clone()
                        } else if proj.app_certificate.len() > 4 {
                            format!(
                                "{}...{}",
                                &proj.app_certificate[..2],
                                &proj.app_certificate[proj.app_certificate.len() - 2..]
                            )
                        } else if !proj.app_certificate.is_empty() {
                            "****".to_string()
                        } else {
                            "(empty)".to_string()
                        };
                        println!("Certificate: {}", cert_display);
                    }
                    None => {
                        println!("No active project set. Run `atem project use <APP_ID>`");
                    }
                }
                Ok(())
            }
        },
        Commands::List { list_command } => match list_command {
            ListCommands::Project { show_certificates } => {
                let config = crate::config::AtemConfig::load()?;
                let (cid, csecret) = resolve_credentials(&config).await?;
                let projects =
                    crate::agora_api::fetch_agora_projects_with_credentials(&cid, &csecret)
                        .await?;
                // Cache for offline use (atem project use <N>)
                if let Err(e) = crate::config::ProjectCache::save(&projects) {
                    eprintln!("Warning: could not cache projects: {}", e);
                }
                print!("{}", crate::agora_api::format_projects(&projects, show_certificates));
                Ok(())
            }
        },
        Commands::Repl => crate::repl::run_repl().await,
        Commands::Login { server: _, save_credentials } => {
            use std::io::Write;
            use crate::websocket_client::AstationClient;

            println!("Authenticating with Astation...");

            let config = crate::config::AtemConfig::load().unwrap_or_default();

            let mut client = AstationClient::new();
            let pairing_code = client.connect_with_pairing(&config).await?;

            if pairing_code == "local" {
                println!("Connected to local Astation!");
                println!("Waiting for pairing approval...");
            } else {
                println!("Connected via relay (code: {})", pairing_code);
                println!("Check your Mac for pairing approval dialog");
            }

            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
            println!("Authenticated successfully!");

            // Sync credentials from Astation
            println!("Syncing Agora credentials from Astation...");

            let timeout = tokio::time::Duration::from_secs(5);
            let result = tokio::time::timeout(timeout, async {
                loop {
                    match client.recv_message_async().await {
                        Some(crate::websocket_client::AstationMessage::CredentialSync {
                            customer_id,
                            customer_secret,
                        }) => return Some((customer_id, customer_secret)),
                        Some(_) => continue,
                        None => return None,
                    }
                }
            })
            .await;

            match result {
                Ok(Some((cid, csecret))) => {
                    let id_preview = &cid[..4.min(cid.len())];
                    println!("Credentials received ({}...)", id_preview);

                    // --save-credentials skips the prompt
                    let should_save = if save_credentials {
                        true
                    } else {
                        print!("Save credentials to encrypted store? [Y/n] ");
                        std::io::stdout().flush().ok();
                        let mut input = String::new();
                        std::io::stdin().read_line(&mut input).unwrap_or(0);
                        !matches!(input.trim().to_lowercase().as_str(), "n" | "no")
                    };

                    if should_save {
                        let mut cfg = crate::config::AtemConfig::load().unwrap_or_default();
                        cfg.customer_id = Some(cid);
                        cfg.customer_secret = Some(csecret);
                        if let Err(e) = cfg.save_to_disk() {
                            eprintln!("Warning: could not persist credentials: {e}");
                        } else {
                            println!(
                                "Credentials saved to {}",
                                crate::config::CredentialStore::path().display()
                            );
                        }
                    } else {
                        println!("Credentials not saved.");
                    }
                }
                Ok(None) => eprintln!("Warning: Astation disconnected before sending credentials"),
                Err(_) => eprintln!("Warning: Timed out waiting for credentials from Astation"),
            }
            Ok(())
        }
        Commands::Logout => {
            crate::auth::AuthSession::clear_saved()?;
            println!("Logged out. Session cleared.");
            Ok(())
        }
        Commands::Agent { agent_command } => match agent_command {
            AgentCommands::Launch { agent_type } => {
                println!("Launching {} as PTY agent...", agent_type);
                println!("Note: This will be implemented in the TUI mode");
                println!("For now, use: atem (enter TUI)");
                // TODO: Implement CLI agent launch with interactive session
                Ok(())
            }
            AgentCommands::List => {
                use crate::agent_detector::{scan_lockfiles, scan_default_ports};
                use crate::agent_client::AgentProtocol;

                // Scan both lockfiles and default ports
                let mut agents = scan_lockfiles();
                let port_agents = scan_default_ports().await;
                agents.extend(port_agents);

                if agents.is_empty() {
                    println!("No agents detected.");
                    println!("Tip: start Claude Code in ACP mode or Codex and re-run.");
                    println!("Example: npx -y @rebornix/stdio-to-ws --persist --grace-period 604800 \\");
                    println!("         \"npx @zed-industries/claude-code-acp\" --port 8765");
                } else {
                    println!("Detected agents ({})\n", agents.len());
                    for (i, agent) in agents.iter().enumerate() {
                        let proto = match agent.protocol {
                            AgentProtocol::Acp => "ACP",
                            AgentProtocol::Pty => "PTY",
                        };
                        let pid_str = agent
                            .pid
                            .map(|p| format!("pid={p}"))
                            .unwrap_or_else(|| "pid=?".to_string());
                        println!(
                            "  {}. {} [{}] {} — {}",
                            i + 1,
                            agent.kind,
                            proto,
                            pid_str,
                            agent.acp_url
                        );
                    }
                }
                Ok(())
            }

            AgentCommands::Connect { url, timeout } => {
                use crate::acp_client::AcpClient;
                use crate::agent_detector::probe_acp;

                println!("Probing {} …", url);
                let result = probe_acp(&url, timeout).await;
                match &result {
                    crate::agent_detector::ProbeResult::AcpAvailable { kind, version } => {
                        println!("ACP server detected: {} v{}", kind, version);
                    }
                    crate::agent_detector::ProbeResult::NotAcp => {
                        anyhow::bail!("Port is open but did not respond with a valid ACP handshake");
                    }
                    crate::agent_detector::ProbeResult::Unreachable => {
                        anyhow::bail!("Could not connect to {}", url);
                    }
                }

                println!("Running initialize + new_session …");
                let mut client = AcpClient::connect(&url).await?;
                let info = client.initialize().await?;
                let session_id = client.new_session().await?;

                println!("\nConnected successfully:");
                println!("  Agent   : {}", info.kind);
                println!("  Version : {}", info.version);
                println!("  Session : {}", session_id);
                Ok(())
            }

            AgentCommands::Prompt { url, text, timeout } => {
                use crate::acp_client::AcpClient;
                use crate::agent_client::AgentEvent;
                use std::time::Duration;

                println!("Connecting to {} …", url);
                let mut client = AcpClient::connect(&url).await?;
                let info = client.initialize().await?;
                let _session_id = client.new_session().await?;

                println!("Agent: {} — sending prompt …\n", info.kind);
                client.send_prompt(&text)?;

                // Poll for events until Done or timeout
                let deadline =
                    std::time::Instant::now() + Duration::from_millis(timeout);
                loop {
                    if std::time::Instant::now() >= deadline {
                        eprintln!("\nTimeout waiting for agent response.");
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    let events = client.drain_events();
                    for event in events {
                        match event {
                            AgentEvent::TextDelta(t) => print!("{}", t),
                            AgentEvent::ToolCall { name, .. } => {
                                print!("\n[tool: {}] ", name)
                            }
                            AgentEvent::ToolResult { .. } => print!("[result] "),
                            AgentEvent::Done => {
                                println!();
                                return Ok(());
                            }
                            AgentEvent::Error(e) => {
                                anyhow::bail!("Agent error: {}", e);
                            }
                            AgentEvent::Disconnected => {
                                anyhow::bail!("Agent disconnected");
                            }
                        }
                    }
                }
                Ok(())
            }

            AgentCommands::Probe { url, timeout } => {
                use crate::agent_detector::{probe_acp, ProbeResult};

                print!("Probing {} … ", url);
                let result = probe_acp(&url, timeout).await;
                match result {
                    ProbeResult::AcpAvailable { kind, version } => {
                        println!("ACP ({} v{})", kind, version);
                    }
                    ProbeResult::NotAcp => {
                        println!("open but not ACP");
                    }
                    ProbeResult::Unreachable => {
                        println!("unreachable");
                    }
                }
                Ok(())
            }

            AgentCommands::Visualize { topic, url, timeout, no_browser } => {
                use crate::acp_client::AcpClient;
                use crate::agent_client::AgentEvent;
                use crate::agent_visualize::{
                    build_visualize_prompt, detect_new_html_files,
                    open_html_in_browser, resolve_agent_url, snapshot_diagrams_dir,
                };
                use std::time::Duration;

                let agent_url = resolve_agent_url(url).await?;
                println!("Connecting to {} …", agent_url);

                let mut client = AcpClient::connect(&agent_url).await?;
                let info = client.initialize().await?;
                let _session_id = client.new_session().await?;
                println!("Agent: {} — generating diagram …\n", info.kind);

                // Snapshot diagrams dir before sending prompt
                let pre_snapshot = snapshot_diagrams_dir();

                let prompt = build_visualize_prompt(&topic);
                client.send_prompt(&prompt)?;

                // Poll for events; watch for Write tool calls targeting .html
                let deadline = std::time::Instant::now() + Duration::from_millis(timeout);
                let mut detected_file: Option<String> = None;

                loop {
                    if std::time::Instant::now() >= deadline {
                        eprintln!("\nTimeout waiting for agent.");
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    let events = client.drain_events();
                    for event in events {
                        match event {
                            AgentEvent::TextDelta(t) => print!("{}", t),
                            AgentEvent::ToolCall { name, input, .. } => {
                                print!("\n[tool: {}] ", name);
                                // Detect Write tool targeting an .html file
                                if name == "Write" {
                                    if let Some(fp) = input.get("file_path").and_then(|v| v.as_str()) {
                                        if fp.ends_with(".html") {
                                            detected_file = Some(fp.to_string());
                                        }
                                    }
                                }
                            }
                            AgentEvent::ToolResult { .. } => print!("[done] "),
                            AgentEvent::Done => {
                                println!();

                                // Determine which file to open
                                let file_path = detected_file.or_else(|| {
                                    detect_new_html_files(&pre_snapshot).into_iter().next()
                                });

                                match file_path {
                                    Some(path) => {
                                        println!("\nDiagram saved: {}", path);

                                        // Upload to diagram server
                                        let config = crate::config::AtemConfig::load().unwrap_or_default();
                                        match crate::agent_visualize::resolve_diagram_server_url(&config) {
                                            Ok(server_url) => {
                                                match crate::agent_visualize::upload_diagram(&path, &topic, &server_url).await {
                                                    Ok(url) => {
                                                        println!("View at: {}", url);
                                                        if !no_browser {
                                                            open_html_in_browser(&url);
                                                        }
                                                    }
                                                    Err(e) => {
                                                        eprintln!("Upload failed: {}", e);
                                                        if !no_browser {
                                                            open_html_in_browser(&path);
                                                            println!("Opened local file in browser.");
                                                        }
                                                    }
                                                }
                                            }
                                            Err(e) => {
                                                eprintln!("Could not resolve diagram server: {}", e);
                                                if !no_browser {
                                                    open_html_in_browser(&path);
                                                    println!("Opened local file in browser.");
                                                }
                                            }
                                        }
                                    }
                                    None => {
                                        eprintln!("No HTML diagram file was detected.");
                                    }
                                }
                                return Ok(());
                            }
                            AgentEvent::Error(e) => {
                                anyhow::bail!("Agent error: {}", e);
                            }
                            AgentEvent::Disconnected => {
                                anyhow::bail!("Agent disconnected");
                            }
                        }
                    }
                }
                Ok(())
            }
        },
        Commands::Serv { serv_command } => match serv_command {
            ServCommands::Rtc {
                channel,
                port,
                expire,
                no_browser,
                background,
                _serv_daemon,
            } => {
                let config = crate::rtc_test_server::RtcTestConfig {
                    channel,
                    port,
                    expire_secs: expire,
                    no_browser,
                    background,
                    _daemon: _serv_daemon,
                };
                crate::rtc_test_server::run_server(config).await
            }
            ServCommands::Diagrams {
                port,
                background,
                _serv_daemon,
            } => {
                let config = crate::diagram_server::DiagramServerConfig {
                    port,
                    background,
                    _daemon: _serv_daemon,
                };
                crate::diagram_server::run_server(config).await
            }
            ServCommands::List => crate::rtc_test_server::cmd_list_servers(),
            ServCommands::Kill { id } => crate::rtc_test_server::cmd_kill_server(&id),
            ServCommands::Killall => crate::rtc_test_server::cmd_kill_all_servers(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn cli_no_args_returns_none_command() {
        let cli = Cli::try_parse_from(["atem"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn cli_list_project_parses() {
        let cli = Cli::try_parse_from(["atem", "list", "project"]).unwrap();
        match cli.command {
            Some(Commands::List {
                list_command: ListCommands::Project { show_certificates },
            }) => {
                assert!(!show_certificates);
            }
            _ => panic!("Expected List Project command"),
        }
    }

    #[test]
    fn cli_list_project_with_show_certificates() {
        let cli =
            Cli::try_parse_from(["atem", "list", "project", "--show-certificates"]).unwrap();
        match cli.command {
            Some(Commands::List {
                list_command: ListCommands::Project { show_certificates },
            }) => {
                assert!(show_certificates);
            }
            _ => panic!("Expected List Project command with show_certificates"),
        }
    }

    #[test]
    fn cli_config_show_parses() {
        let cli = Cli::try_parse_from(["atem", "config", "show"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Config {
                config_command: ConfigCommands::Show
            })
        ));
    }

    #[test]
    fn cli_project_use_parses() {
        let cli = Cli::try_parse_from(["atem", "project", "use", "my_app_id"]).unwrap();
        match cli.command {
            Some(Commands::Project {
                project_command: ProjectCommands::Use { app_id_or_index },
            }) => {
                assert_eq!(app_id_or_index, "my_app_id");
            }
            _ => panic!("Expected Project Use command"),
        }
    }

    #[test]
    fn cli_project_show_parses() {
        let cli = Cli::try_parse_from(["atem", "project", "show"]).unwrap();
        match cli.command {
            Some(Commands::Project {
                project_command: ProjectCommands::Show { with_certificate },
            }) => {
                assert!(!with_certificate);
            }
            _ => panic!("Expected Project Show command"),
        }
    }

    #[test]
    fn cli_project_show_with_certificate() {
        let cli =
            Cli::try_parse_from(["atem", "project", "show", "--with-certificate"]).unwrap();
        match cli.command {
            Some(Commands::Project {
                project_command: ProjectCommands::Show { with_certificate },
            }) => {
                assert!(with_certificate);
            }
            _ => panic!("Expected Project Show command"),
        }
    }

    #[test]
    fn cli_token_rtc_create_defaults() {
        let cli = Cli::try_parse_from(["atem", "token", "rtc", "create"]).unwrap();
        match cli.command {
            Some(Commands::Token {
                token_command:
                    TokenCommands::Rtc {
                        rtc_command:
                            RtcCommands::Create {
                                channel,
                                uid,
                                role,
                                expire,
                            },
                    },
            }) => {
                assert!(channel.is_none());
                assert!(uid.is_none());
                assert_eq!(role, "publisher");
                assert_eq!(expire, 3600);
            }
            _ => panic!("Expected Token Rtc Create command"),
        }
    }

    #[test]
    fn cli_token_rtc_decode_parses() {
        let cli =
            Cli::try_parse_from(["atem", "token", "rtc", "decode", "007sometoken"]).unwrap();
        match cli.command {
            Some(Commands::Token {
                token_command:
                    TokenCommands::Rtc {
                        rtc_command: RtcCommands::Decode { token },
                    },
            }) => {
                assert_eq!(token, "007sometoken");
            }
            _ => panic!("Expected Token Rtc Decode command"),
        }
    }

    #[test]
    fn cli_token_rtm_create_defaults() {
        let cli = Cli::try_parse_from(["atem", "token", "rtm", "create"]).unwrap();
        match cli.command {
            Some(Commands::Token {
                token_command:
                    TokenCommands::Rtm {
                        rtm_command: RtmCommands::Create { user_id, expire },
                    },
            }) => {
                assert!(user_id.is_none());
                assert_eq!(expire, 3600);
            }
            _ => panic!("Expected Token Rtm Create command"),
        }
    }

    #[test]
    fn cli_repl_parses() {
        let cli = Cli::try_parse_from(["atem", "repl"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Repl)));
    }

    #[test]
    fn cli_login_parses() {
        let cli = Cli::try_parse_from(["atem", "login"]).unwrap();
        match cli.command {
            Some(Commands::Login { server, save_credentials }) => {
                assert!(server.is_none());
                assert!(!save_credentials);
            }
            _ => panic!("Expected Login command"),
        }
    }

    #[test]
    fn cli_login_with_server_parses() {
        let cli =
            Cli::try_parse_from(["atem", "login", "--server", "http://localhost:3000"]).unwrap();
        match cli.command {
            Some(Commands::Login { server, .. }) => {
                assert_eq!(server.as_deref(), Some("http://localhost:3000"));
            }
            _ => panic!("Expected Login command with server"),
        }
    }

    #[test]
    fn cli_login_save_credentials_flag() {
        let cli =
            Cli::try_parse_from(["atem", "login", "--save-credentials"]).unwrap();
        match cli.command {
            Some(Commands::Login { save_credentials, .. }) => {
                assert!(save_credentials);
            }
            _ => panic!("Expected Login command with save_credentials"),
        }
    }

    fn cli_logout_parses() {
        let cli = Cli::try_parse_from(["atem", "logout"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Logout)));
    }

    // ── agent command ─────────────────────────────────────────────────────

    #[test]
    fn cli_agent_list_parses() {
        let cli = Cli::try_parse_from(["atem", "agent", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Agent {
                agent_command: AgentCommands::List
            })
        ));
    }

    #[test]
    fn cli_agent_connect_parses() {
        let cli =
            Cli::try_parse_from(["atem", "agent", "connect", "ws://localhost:8765"]).unwrap();
        match cli.command {
            Some(Commands::Agent {
                agent_command: AgentCommands::Connect { url, timeout },
            }) => {
                assert_eq!(url, "ws://localhost:8765");
                assert_eq!(timeout, 3000);
            }
            _ => panic!("expected Agent Connect"),
        }
    }

    #[test]
    fn cli_agent_connect_custom_timeout() {
        let cli = Cli::try_parse_from([
            "atem",
            "agent",
            "connect",
            "ws://localhost:9000",
            "--timeout",
            "5000",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Agent {
                agent_command: AgentCommands::Connect { timeout, .. },
            }) => {
                assert_eq!(timeout, 5000);
            }
            _ => panic!("expected Agent Connect"),
        }
    }

    #[test]
    fn cli_agent_prompt_parses() {
        let cli = Cli::try_parse_from([
            "atem",
            "agent",
            "prompt",
            "ws://localhost:8765",
            "write a hello world in Rust",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Agent {
                agent_command: AgentCommands::Prompt { url, text, timeout },
            }) => {
                assert_eq!(url, "ws://localhost:8765");
                assert_eq!(text, "write a hello world in Rust");
                assert_eq!(timeout, 30000);
            }
            _ => panic!("expected Agent Prompt"),
        }
    }

    #[test]
    fn cli_agent_probe_parses() {
        let cli =
            Cli::try_parse_from(["atem", "agent", "probe", "ws://127.0.0.1:8765"]).unwrap();
        match cli.command {
            Some(Commands::Agent {
                agent_command: AgentCommands::Probe { url, timeout },
            }) => {
                assert_eq!(url, "ws://127.0.0.1:8765");
                assert_eq!(timeout, 2000);
            }
            _ => panic!("expected Agent Probe"),
        }
    }

    #[test]
    fn cli_agent_probe_custom_timeout() {
        let cli = Cli::try_parse_from([
            "atem", "agent", "probe", "ws://localhost:9999", "--timeout", "500",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Agent {
                agent_command: AgentCommands::Probe { timeout, .. },
            }) => {
                assert_eq!(timeout, 500);
            }
            _ => panic!("expected Agent Probe"),
        }
    }

    // ── agent visualize ──────────────────────────────────────────────────

    #[test]
    fn cli_agent_visualize_parses() {
        let cli = Cli::try_parse_from([
            "atem", "agent", "visualize", "WebRTC data flow",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Agent {
                agent_command: AgentCommands::Visualize { topic, url, timeout, no_browser },
            }) => {
                assert_eq!(topic, "WebRTC data flow");
                assert!(url.is_none());
                assert_eq!(timeout, 120000);
                assert!(!no_browser);
            }
            _ => panic!("expected Agent Visualize"),
        }
    }

    #[test]
    fn cli_agent_visualize_with_url() {
        let cli = Cli::try_parse_from([
            "atem", "agent", "visualize", "auth system",
            "--url", "ws://localhost:8765",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Agent {
                agent_command: AgentCommands::Visualize { topic, url, .. },
            }) => {
                assert_eq!(topic, "auth system");
                assert_eq!(url.as_deref(), Some("ws://localhost:8765"));
            }
            _ => panic!("expected Agent Visualize"),
        }
    }

    #[test]
    fn cli_agent_visualize_no_browser_flag() {
        let cli = Cli::try_parse_from([
            "atem", "agent", "visualize", "pipeline", "--no-browser",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Agent {
                agent_command: AgentCommands::Visualize { no_browser, .. },
            }) => {
                assert!(no_browser);
            }
            _ => panic!("expected Agent Visualize"),
        }
    }

    #[test]
    fn cli_agent_visualize_custom_timeout() {
        let cli = Cli::try_parse_from([
            "atem", "agent", "visualize", "data flow", "--timeout", "60000",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Agent {
                agent_command: AgentCommands::Visualize { timeout, .. },
            }) => {
                assert_eq!(timeout, 60000);
            }
            _ => panic!("expected Agent Visualize"),
        }
    }

    #[test]
    fn cli_agent_visualize_all_flags() {
        let cli = Cli::try_parse_from([
            "atem", "agent", "visualize", "Atem architecture",
            "--url", "ws://10.0.0.1:9000",
            "--timeout", "30000",
            "--no-browser",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Agent {
                agent_command: AgentCommands::Visualize { topic, url, timeout, no_browser },
            }) => {
                assert_eq!(topic, "Atem architecture");
                assert_eq!(url.as_deref(), Some("ws://10.0.0.1:9000"));
                assert_eq!(timeout, 30000);
                assert!(no_browser);
            }
            _ => panic!("expected Agent Visualize"),
        }
    }

    #[test]
    fn cli_agent_visualize_topic_with_spaces() {
        let cli = Cli::try_parse_from([
            "atem", "agent", "visualize", "multi word topic with spaces",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Agent {
                agent_command: AgentCommands::Visualize { topic, .. },
            }) => {
                assert_eq!(topic, "multi word topic with spaces");
            }
            _ => panic!("expected Agent Visualize"),
        }
    }

    #[test]
    fn cli_agent_visualize_missing_topic_fails() {
        let result = Cli::try_parse_from(["atem", "agent", "visualize"]);
        assert!(result.is_err(), "visualize without topic should fail");
    }

    // ── config set / clear ────────────────────────────────────────────────

    #[test]
    fn cli_project_use_with_app_id() {
        let cli = Cli::try_parse_from(["atem", "project", "use", "abc123def456"]).unwrap();
        match cli.command {
            Some(Commands::Project {
                project_command: ProjectCommands::Use { app_id_or_index },
            }) => {
                assert_eq!(app_id_or_index, "abc123def456");
            }
            _ => panic!("Expected Project Use command"),
        }
    }

    #[test]
    fn cli_project_use_with_index() {
        let cli = Cli::try_parse_from(["atem", "project", "use", "3"]).unwrap();
        match cli.command {
            Some(Commands::Project {
                project_command: ProjectCommands::Use { app_id_or_index },
            }) => {
                assert_eq!(app_id_or_index, "3");
                assert!(app_id_or_index.parse::<usize>().is_ok());
            }
            _ => panic!("Expected Project Use with index"),
        }
    }

    #[test]
    fn cli_config_set_astation_ws() {
        let cli = Cli::try_parse_from([
            "atem", "config", "set", "astation_ws", "ws://10.0.0.5:8080/ws",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Config {
                config_command: ConfigCommands::Set { key, value },
            }) => {
                assert_eq!(key, "astation_ws");
                assert_eq!(value, "ws://10.0.0.5:8080/ws");
            }
            _ => panic!("Expected Config Set command"),
        }
    }

    #[test]
    fn cli_config_set_astation_relay_url() {
        let cli = Cli::try_parse_from([
            "atem", "config", "set", "astation_relay_url", "https://custom.relay.example.com",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Config {
                config_command: ConfigCommands::Set { key, value },
            }) => {
                assert_eq!(key, "astation_relay_url");
                assert_eq!(value, "https://custom.relay.example.com");
            }
            _ => panic!("Expected Config Set command"),
        }
    }

    #[test]
    fn cli_config_clear_parses() {
        let cli = Cli::try_parse_from(["atem", "config", "clear"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Config {
                config_command: ConfigCommands::Clear
            })
        ));
    }

    // ── serv command ─────────────────────────────────────────────────────

    #[test]
    fn cli_serv_rtc_defaults() {
        let cli = Cli::try_parse_from(["atem", "serv", "rtc"]).unwrap();
        match cli.command {
            Some(Commands::Serv {
                serv_command:
                    ServCommands::Rtc {
                        channel,
                        port,
                        expire,
                        no_browser,
                        background,
                        ..
                    },
            }) => {
                assert_eq!(channel, "test");
                assert_eq!(port, 0);
                assert_eq!(expire, 3600);
                assert!(!no_browser);
                assert!(!background);
            }
            _ => panic!("expected Serv Rtc command"),
        }
    }

    #[test]
    fn cli_serv_rtc_with_options() {
        let cli = Cli::try_parse_from([
            "atem",
            "serv",
            "rtc",
            "--channel",
            "demo",
            "--port",
            "8443",
            "--expire",
            "7200",
            "--no-browser",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Serv {
                serv_command:
                    ServCommands::Rtc {
                        channel,
                        port,
                        expire,
                        no_browser,
                        ..
                    },
            }) => {
                assert_eq!(channel, "demo");
                assert_eq!(port, 8443);
                assert_eq!(expire, 7200);
                assert!(no_browser);
            }
            _ => panic!("expected Serv Rtc command"),
        }
    }

    #[test]
    fn cli_serv_rtc_background_flag() {
        let cli =
            Cli::try_parse_from(["atem", "serv", "rtc", "--background"]).unwrap();
        match cli.command {
            Some(Commands::Serv {
                serv_command: ServCommands::Rtc { background, .. },
            }) => {
                assert!(background);
            }
            _ => panic!("expected Serv Rtc command"),
        }
    }

    #[test]
    fn cli_serv_list_parses() {
        let cli = Cli::try_parse_from(["atem", "serv", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Serv {
                serv_command: ServCommands::List
            })
        ));
    }

    #[test]
    fn cli_serv_kill_parses() {
        let cli = Cli::try_parse_from(["atem", "serv", "kill", "rtc-demo-8443"]).unwrap();
        match cli.command {
            Some(Commands::Serv {
                serv_command: ServCommands::Kill { id },
            }) => {
                assert_eq!(id, "rtc-demo-8443");
            }
            _ => panic!("expected Serv Kill command"),
        }
    }

    #[test]
    fn cli_serv_killall_parses() {
        let cli = Cli::try_parse_from(["atem", "serv", "killall"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Serv {
                serv_command: ServCommands::Killall
            })
        ));
    }

    // ── serv diagrams command ───────────────────────────────────────────

    #[test]
    fn cli_serv_diagrams_defaults() {
        let cli = Cli::try_parse_from(["atem", "serv", "diagrams"]).unwrap();
        match cli.command {
            Some(Commands::Serv {
                serv_command: ServCommands::Diagrams { port, background, _serv_daemon },
            }) => {
                assert_eq!(port, 8787);
                assert!(!background);
                assert!(!_serv_daemon);
            }
            _ => panic!("expected Serv Diagrams command"),
        }
    }

    #[test]
    fn cli_serv_diagrams_with_port() {
        let cli = Cli::try_parse_from(["atem", "serv", "diagrams", "--port", "9000"]).unwrap();
        match cli.command {
            Some(Commands::Serv {
                serv_command: ServCommands::Diagrams { port, .. },
            }) => {
                assert_eq!(port, 9000);
            }
            _ => panic!("expected Serv Diagrams command"),
        }
    }

    #[test]
    fn cli_serv_diagrams_background_flag() {
        let cli = Cli::try_parse_from(["atem", "serv", "diagrams", "--background"]).unwrap();
        match cli.command {
            Some(Commands::Serv {
                serv_command: ServCommands::Diagrams { background, .. },
            }) => {
                assert!(background);
            }
            _ => panic!("expected Serv Diagrams command"),
        }
    }
}

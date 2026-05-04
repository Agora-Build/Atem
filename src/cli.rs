use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "atem")]
#[command(version)]
#[command(about = "A terminal that connects builders, Agora platform, and AI agents.")]
#[command(long_about = "A terminal that connects builders, Agora platform, and AI agents.

Open source. Some functions built on official Agora APIs — your credentials stay on your machine.

Disclaimer: This is an unofficial community tool that contains some experimental
functions, provided AS-IS, with no SLA or guarantees. Contributions welcome.
For official products and support, visit https://www.agora.io/")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Generate Agora RTC/RTM tokens
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
    /// Log in with Agora Console (opens browser)
    Login,
    /// Log out from SSO
    Logout,
    /// Pair with Astation
    Pair {
        /// Save credentials for offline use
        #[arg(long)]
        save: bool,
    },
    /// Unpair from Astation
    Unpair,
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
        /// RTC user identifier.
        ///
        /// - All-digit value → int uid (SDK `joinChannel(uid:)`).
        /// - Non-digit value → string account (SDK `joinChannelWithUserAccount(:)`).
        /// - Leading `s/` → force string account mode. Use this for all-digit
        ///   string accounts, e.g. `--rtc-user-id s/1232`. (`/` is not a legal
        ///   RTC/RTM account character, so the prefix is unambiguous.)
        #[arg(long = "rtc-user-id")]
        rtc_user_id: Option<String>,
        /// Role: publisher or subscriber
        #[arg(long, default_value = "publisher")]
        role: String,
        /// Expiry in seconds
        #[arg(long, default_value = "3600")]
        expire: u32,
        /// Also embed an RTM (Signaling) login privilege. Defaults to using
        /// --rtc-user-id as the RTM account; pass --rtm-user-id to override.
        #[arg(long)]
        with_rtm: bool,
        /// RTM user account to embed (only used with --with-rtm). If omitted,
        /// --rtc-user-id is reused.
        #[arg(long)]
        rtm_user_id: Option<String>,
    },
    /// Decode an existing token
    Decode {
        /// The token string to decode
        token: String,
    },
}

#[derive(Subcommand)]
pub enum RtmCommands {
    /// Create a Signaling (RTM) token
    Create {
        /// RTM user id (string account)
        #[arg(long = "rtm-user-id")]
        rtm_user_id: Option<String>,
        /// Expiry in seconds
        #[arg(long, default_value = "3600")]
        expire: u32,
    },
    /// Decode an existing Signaling (RTM) token
    Decode {
        /// Token to decode
        token: String,
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
    /// Interactive wizard to configure ConvoAI agent
    Convo {
        /// Config file path (default: ~/.config/atem/convo.toml)
        #[arg(long)]
        config: Option<std::path::PathBuf>,
        /// Validate config without modifying it
        #[arg(long)]
        validate: bool,
    },
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
        /// Channel name. If omitted, atem auto-generates one in the shape
        /// `atem-rtc-<app_id[..12]>-<unix_ts>-<rand4>`. Supports `{appid}`
        /// and `{ts}` placeholders, e.g. `--channel atem-rtc-{appid}-{ts}-001`.
        #[arg(long)]
        channel: Option<String>,
        /// HTTPS port (0 = auto-assign)
        #[arg(long, default_value = "0")]
        port: u16,
        /// Token expiry in seconds
        #[arg(long, default_value = "3600")]
        expire: u32,
        /// RTC user identifier. All-digit → int uid. Non-digit → string account.
        /// Leading `s/` forces string mode (e.g. `s/1232`).
        #[arg(long = "rtc-user-id")]
        rtc_user_id: Option<String>,
        /// Also embed an RTM (Signaling) login privilege in the token.
        /// Defaults to using --rtc-user-id as the RTM account.
        #[arg(long)]
        with_rtm: bool,
        /// RTM user account to embed (only used with --with-rtm).
        /// If omitted, the RTC user id is reused.
        #[arg(long)]
        rtm_user_id: Option<String>,
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
    /// Launch a browser-based Conversational AI agent test page (HTTPS).
    #[command(after_help = "EXAMPLES:
  # Launch a single agent with the test page
  atem serv convo

  # Run as a background daemon (headless, survives terminal close)
  atem serv convo --background

  # Launch 40 background agents. {appid} and {ts} are expanded by atem,
  # so the channels look like atem-convo-2655d20a82fc-1777574763-0001..0040.
  # `sleep 0.5` between spawns avoids hitting Agora's /join rate limit;
  # without it, ~5-10% of the agents fail to start in a tight burst.
  for i in $(seq -f '%04g' 1 40); do \\
    atem serv convo --background --channel 'atem-convo-{appid}-{ts}-'$i; \\
    sleep 0.5; \\
  done
  atem serv list                # inspect them
  atem serv killall             # stop all of them
")]
    Convo {
        /// Channel to join. Supports `{appid}` (first 12 chars of the
        /// active app id) and `{ts}` (unix timestamp) placeholders, e.g.
        /// `--channel atem-convo-{appid}-{ts}-001`.
        #[arg(long)]
        channel: Option<String>,
        /// Human's RTC uid. Defaults to "0" (server-assigned).
        #[arg(long = "rtc-user-id")]
        rtc_user_id: Option<String>,
        /// Agent's RTC uid. Required via CLI or TOML.
        #[arg(long = "agent-user-id")]
        agent_user_id: Option<String>,
        /// Config TOML path. Default: ~/.config/atem/convo.toml
        #[arg(long)]
        config: Option<std::path::PathBuf>,
        /// HTTPS port (0 = auto). Ignored with --background.
        #[arg(long, default_value = "0")]
        port: u16,
        /// Don't auto-open the browser
        #[arg(long)]
        no_browser: bool,
        /// Daemon mode: re-execs as a detached daemon process. Parent
        /// exits immediately after the agent is created and registered.
        /// Use `atem serv list` / `kill` / `killall` to manage running
        /// agents — `kill` sends SIGTERM to the daemon which POSTs
        /// `/leave` before exiting.
        #[arg(long)]
        background: bool,
        /// Internal: daemon marker (hidden)
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
    /// Receive Agora webhooks locally; tunnels via ngrok by default.
    /// Prints each event to stdout and serves a live console at /.
    Webhooks {
        /// webhooks.toml path. Default: ~/.config/atem/webhooks.toml
        #[arg(long)]
        config: Option<std::path::PathBuf>,
        /// Local HTTP port (0 = use TOML or 9090 default)
        #[arg(long, default_value = "0")]
        port: u16,
        /// Skip ngrok tunnel — POSTs must reach the local port directly.
        #[arg(long)]
        no_tunnel: bool,
        /// Don't auto-open the local console in a browser.
        #[arg(long)]
        no_browser: bool,
        /// Daemon mode: re-execs as a detached daemon process.
        #[arg(long)]
        background: bool,
        /// Internal: daemon marker (hidden)
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
    /// Open a UI to talk to a running convo agent (kind=convo). Spawns
    /// a foreground HTTPS page bound to the daemon's channel/uids; the
    /// page hides "Start Agent" since the agent is already alive.
    Attach {
        /// Server ID from `atem serv list` (kind=convo only)
        id: String,
        /// HTTPS port (0 = auto-assign)
        #[arg(long, default_value = "0")]
        port: u16,
        /// Don't auto-open the browser
        #[arg(long)]
        no_browser: bool,
    },
}

pub async fn handle_cli_command(command: Commands) -> Result<()> {
    match command {
        Commands::Token { token_command } => match token_command {
            TokenCommands::Rtc { rtc_command } => match rtc_command {
                RtcCommands::Create {
                    channel,
                    rtc_user_id,
                    role,
                    expire,
                    with_rtm,
                    rtm_user_id,
                } => {
                    let app_id = crate::config::ProjectCache::resolve_app_id(None)?;
                    let app_certificate =
                        crate::config::ProjectCache::resolve_app_certificate(None)?;

                    let channel_name = channel.as_deref().unwrap_or("test-channel");
                    let uid_str = rtc_user_id.as_deref().unwrap_or("0");
                    let token_role = match role.as_str() {
                        "subscriber" | "sub" => crate::token::Role::Subscriber,
                        _ => crate::token::Role::Publisher,
                    };

                    // Use time sync for accurate issued_at
                    let mut time_sync = crate::time_sync::TimeSync::new();
                    let now = time_sync.now().await? as u32;

                    let rtc_account = crate::token::RtcAccount::parse(uid_str);
                    // Reject --rtm-user-id without --with-rtm — otherwise it would
                    // silently do nothing.
                    if rtm_user_id.is_some() && !with_rtm {
                        anyhow::bail!(
                            "--rtm-user-id requires --with-rtm; add --with-rtm to embed an RTM login privilege"
                        );
                    }

                    let token = if with_rtm {
                        crate::token::build_token_rtc_with_rtm(
                            &app_id,
                            &app_certificate,
                            channel_name,
                            rtc_account,
                            token_role,
                            expire,
                            expire,
                            rtm_user_id.as_deref(),
                        )?
                    } else {
                        crate::token::build_token_rtc(
                            &app_id,
                            &app_certificate,
                            channel_name,
                            rtc_account,
                            token_role,
                            expire,
                            now,
                        )?
                    };

                    if token.is_empty() {
                        println!("Error: App certificate is empty. Cannot generate token.");
                        return Ok(());
                    }

                    let label = if with_rtm { "RTC+RTM Token" } else { "RTC Token" };
                    println!("{} created successfully:", label);
                    println!("{}", token);
                    println!("\nToken Details:");
                    println!("  Channel: {}", channel_name);
                    // Show the account that actually went into the token (quote-stripped
                    // if the user passed `"..."`), not the raw CLI arg.
                    println!(
                        "  RTC User: {} ({})",
                        rtc_account.as_str(),
                        rtc_account.mode_label()
                    );
                    println!("  Role: {:?}", token_role);
                    println!("  Valid for: {}s", expire);
                    if with_rtm {
                        let rtm_account = rtm_user_id.as_deref().unwrap_or(uid_str);
                        println!("  RTM login: enabled (User = {})", rtm_account);
                    }

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
                RtmCommands::Create { rtm_user_id, expire } => {
                    let app_id = crate::config::ProjectCache::resolve_app_id(None)?;
                    let app_certificate =
                        crate::config::ProjectCache::resolve_app_certificate(None)?;

                    let uid = rtm_user_id.as_deref().unwrap_or("atem01");

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
                    println!("  RTM User: {}", uid);
                    println!("  Valid for: {}s", expire);

                    let offset = time_sync.offset();
                    if offset != 0 {
                        println!("  Clock offset: {}s", offset);
                    }

                    Ok(())
                }
                RtmCommands::Decode { token } => {
                    let info = crate::token::decode_token(&token)?;
                    println!("Decoded Token:");
                    println!("{}", info.display());
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
                crate::config::ProjectCache::clear_active()?;
                println!("Active project cleared.");
                Ok(())
            }
            ConfigCommands::Convo { config, validate } => {
                let path = config.unwrap_or_else(||
                    crate::config::AtemConfig::config_dir().join("convo.toml"));
                if validate {
                    crate::convo_wizard::run_validate(&path)
                } else {
                    crate::convo_wizard::run_wizard(&path)
                }
            }
        },
        Commands::Project { project_command } => match project_command {
            ProjectCommands::Use { app_id_or_index } => {
                // Index path reads from local ProjectCache — no network call needed.
                // App ID path fetches from the BFF API to resolve name + certificate.
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
                    crate::config::ProjectCache::set_active(&project.app_id, None)?;
                    println!("Active project set: {} ({})", project.name, project.app_id);
                } else {
                    let config = crate::config::AtemConfig::load()?;
                    let token = crate::sso_auth::valid_token(None, config.effective_sso_url()).await
                        .map_err(|e| anyhow::anyhow!("{}", e))?;
                    let projects = crate::agora_api::fetch_projects(&token, config.effective_bff_url()).await?;
                    if let Err(e) = crate::config::ProjectCache::save(&projects) {
                        eprintln!("Warning: could not cache projects: {}", e);
                    }
                    let project = projects
                        .iter()
                        .find(|p| p.app_id == app_id_or_index)
                        .ok_or_else(|| {
                            anyhow::anyhow!("Project with App ID '{}' not found", app_id_or_index)
                        })?;
                    crate::config::ProjectCache::set_active(&project.app_id, None)?;
                    println!("Active project set: {} ({})", project.name, project.app_id);
                }
                Ok(())
            }
            ProjectCommands::Show { with_certificate } => {
                match crate::config::ProjectCache::get_active() {
                    Some(proj) => {
                        println!("Active project: {}", proj.name);
                        println!("App ID: {}", proj.app_id);
                        let vid_suffix = proj.vid.map(|v| format!("  |  vid: {}", v)).unwrap_or_default();
                        println!("Project ID: {}{}", proj.project_id, vid_suffix);
                        let cert = proj.sign_key.as_deref().unwrap_or("");
                        let cert_display = if with_certificate {
                            cert.to_string()
                        } else if cert.len() > 4 {
                            format!("{}...{}", &cert[..2], &cert[cert.len() - 2..])
                        } else if !cert.is_empty() {
                            "****".to_string()
                        } else {
                            "(empty)".to_string()
                        };
                        println!("Certificate: {}", cert_display);
                        if !proj.created_at.is_empty() {
                            println!("Created: {}", proj.created_at);
                        }
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
                let token = crate::sso_auth::valid_token(None, config.effective_sso_url()).await
                    .map_err(|e| anyhow::anyhow!("{}", e))?;
                let projects = crate::agora_api::fetch_projects(&token, config.effective_bff_url()).await?;
                if let Err(e) = crate::config::ProjectCache::save(&projects) {
                    eprintln!("Warning: could not cache projects: {}", e);
                }
                print!("{}", crate::agora_api::format_projects(&projects, show_certificates));
                Ok(())
            }
        },
        Commands::Repl => crate::repl::run_repl().await,
        Commands::Login => {
            let config = crate::config::AtemConfig::load()?;
            let session = crate::sso_auth::run_login_flow(config.effective_sso_url()).await?;
            let mut store = crate::credentials::CredentialStore::load();
            store.upsert(crate::credentials::CredentialEntry::new_sso(
                session.access_token.clone(),
                session.refresh_token.clone(),
                session.expires_at,
                session.login_id.clone(),
            ));
            store.save()?;
            match &session.login_id {
                Some(id) => println!("Logged in. (SSO: {})", id),
                None => println!("Logged in. (SSO)"),
            }
            Ok(())
        }
        Commands::Logout => {
            let mut store = crate::credentials::CredentialStore::load();
            store.remove_sso();
            store.save()?;
            println!("Logged out.");
            Ok(())
        }
        Commands::Pair { save } => run_pair(save).await,
        Commands::Unpair => {
            let mut store = crate::credentials::CredentialStore::load();
            let count = store
                .entries
                .iter()
                .filter(|e| e.source == crate::credentials::CredentialSource::AstationPaired)
                .count();
            if count == 0 {
                println!("No paired sessions to remove.");
                return Ok(());
            }
            store
                .entries
                .retain(|e| e.source != crate::credentials::CredentialSource::AstationPaired);
            store.save()?;
            let plural = if count == 1 { "" } else { "s" };
            println!("Unpaired ({count} session{plural} removed).");
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
                rtc_user_id,
                with_rtm,
                rtm_user_id,
                no_browser,
                background,
                _serv_daemon,
            } => {
                if rtm_user_id.is_some() && !with_rtm {
                    anyhow::bail!(
                        "--rtm-user-id requires --with-rtm; add --with-rtm to enable RTM on the test page"
                    );
                }
                let config = crate::rtc_test_server::RtcTestConfig {
                    channel,
                    port,
                    expire_secs: expire,
                    rtc_user_id,
                    with_rtm,
                    rtm_user_id,
                    no_browser,
                    background,
                    _daemon: _serv_daemon,
                };
                crate::rtc_test_server::run_server(config).await
            }
            ServCommands::Convo {
                channel, rtc_user_id, agent_user_id, config, port,
                no_browser, background, _serv_daemon,
            } => {
                crate::convo_test_server::run_server(crate::convo_test_server::ServeConvoConfig {
                    channel, rtc_user_id, agent_user_id,
                    config_path: config,
                    port, no_browser, background,
                    _daemon: _serv_daemon,
                    attach: false,
                }).await
            }
            ServCommands::Webhooks {
                config, port, no_tunnel, no_browser, background, _serv_daemon,
            } => {
                crate::webhook_server::run_server(crate::webhook_server::ServeWebhooksConfig {
                    config_path: config,
                    port, no_tunnel, no_browser, background,
                    _daemon: _serv_daemon,
                }).await
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
            ServCommands::Attach { id, port, no_browser } => {
                // Look up the running daemon by id (or 1-based index from
                // `atem serv list`), validate it's a convo agent, then
                // spawn a foreground UI bound to its channel.
                let id = crate::rtc_test_server::resolve_id_or_index(&id)?;
                let entry_path = crate::rtc_test_server::servers_dir()
                    .join(format!("{}.json", id));
                if !entry_path.exists() {
                    anyhow::bail!("No server with id '{}'. Run `atem serv list`.", id);
                }
                let data = std::fs::read_to_string(&entry_path)?;
                let entry: crate::rtc_test_server::ServerEntry = serde_json::from_str(&data)?;
                if entry.kind != "convo" {
                    anyhow::bail!(
                        "Server '{}' is kind='{}'; attach only works for kind='convo'.",
                        id, entry.kind
                    );
                }
                crate::convo_test_server::run_server(crate::convo_test_server::ServeConvoConfig {
                    channel: Some(entry.channel.clone()),
                    rtc_user_id: None,    // resolves from convo.toml
                    agent_user_id: None,  // resolves from convo.toml
                    config_path: None,
                    port,
                    no_browser,
                    background: false,
                    _daemon: false,
                    attach: true,
                }).await
            }
        },
    }
}

/// Prompt "Save credentials? ... [y/N]" on stdin. Defaults to false on empty / non-tty.
fn prompt_save_credentials() -> bool {
    use std::io::{self, BufRead, Write};

    print!("Save credentials so they keep working when Astation disconnects? [y/N]: ");
    let _ = io::stdout().flush();

    let stdin = io::stdin();
    let mut line = String::new();
    if stdin.lock().read_line(&mut line).is_err() {
        return false;
    }
    matches!(
        line.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    )
}

/// `atem pair [--save]` — connect to Astation, send PairSavePreference, wait for SsoTokenSync.
async fn run_pair(save: bool) -> Result<()> {
    use tokio::time::{Duration, timeout};
    let config = crate::config::AtemConfig::load()?;

    println!("Connecting to Astation...");
    let mut client = crate::websocket_client::AstationClient::new();

    // Try local-first-then-relay pairing flow. Returns pairing code (or "local").
    let result = client.connect_with_pairing(&config).await?;
    if result == "local" {
        println!("Connected to local Astation.");
    } else {
        println!("Pairing code: {}", result);
        println!("Approve the pairing in your Astation app.");
    }

    // Resolve save preference: --save skips the prompt; otherwise ask interactively.
    let save_credentials = if save {
        true
    } else {
        prompt_save_credentials()
    };

    // Send save preference. Astation uses this to decide what to put in
    // the subsequent SsoTokenSync message.
    client
        .send_message(crate::websocket_client::AstationMessage::PairSavePreference {
            save_credentials,
        })
        .await?;

    println!("Waiting for Astation to send SSO credentials...");

    // Wait up to 60s for SsoTokenSync.
    let received = timeout(Duration::from_secs(60), async {
        loop {
            match client.recv_message_async().await {
                Some(crate::websocket_client::AstationMessage::SsoTokenSync {
                    access_token,
                    refresh_token,
                    expires_at,
                    login_id,
                    astation_id,
                    save_credentials,
                }) => {
                    return Ok::<_, anyhow::Error>((
                        access_token,
                        refresh_token,
                        expires_at,
                        login_id,
                        astation_id,
                        save_credentials,
                    ));
                }
                Some(_) => continue,
                None => anyhow::bail!("Astation connection closed before sending credentials."),
            }
        }
    })
    .await;

    match received {
        Ok(Ok((access_token, refresh_token, expires_at, login_id, astation_id, save_credentials))) => {
            let mut store = crate::credentials::CredentialStore::load();
            let now = crate::credentials::CredentialEntry::now_secs();
            store.upsert(crate::credentials::CredentialEntry::new_paired(
                access_token,
                refresh_token,
                expires_at,
                login_id.clone(),
                astation_id,
                save_credentials,
                now,
            ));
            store.save()?;
            match login_id {
                Some(id) => println!("Paired with Astation. (SSO: {})", id),
                None => println!("Paired with Astation."),
            }
            if save_credentials {
                println!("Credentials saved — will work offline.");
            } else {
                println!("Credentials are session-only (5 min grace period after disconnect).");
            }
            Ok(())
        }
        Ok(Err(e)) => Err(e),
        Err(_) => anyhow::bail!(
            "Pairing timed out waiting for credentials. \
             (Astation may not yet support SSO token sync — check Astation version.)"
        ),
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
                                rtc_user_id,
                                role,
                                expire,
                                with_rtm,
                                rtm_user_id,
                            },
                    },
            }) => {
                assert!(channel.is_none());
                assert!(rtc_user_id.is_none());
                assert_eq!(role, "publisher");
                assert_eq!(expire, 3600);
                assert!(!with_rtm);
                assert!(rtm_user_id.is_none());
            }
            _ => panic!("Expected Token Rtc Create command"),
        }
    }

    #[test]
    fn cli_token_rtc_create_with_rtm_flag() {
        let cli = Cli::try_parse_from(["atem", "token", "rtc", "create", "--with-rtm"]).unwrap();
        match cli.command {
            Some(Commands::Token {
                token_command:
                    TokenCommands::Rtc {
                        rtc_command: RtcCommands::Create { with_rtm, rtm_user_id, .. },
                    },
            }) => {
                assert!(with_rtm);
                assert!(rtm_user_id.is_none());
            }
            _ => panic!("Expected RtcCommands::Create with with_rtm=true"),
        }
    }

    #[test]
    fn cli_token_rtc_create_with_separate_rtm_user() {
        let cli = Cli::try_parse_from([
            "atem", "token", "rtc", "create",
            "--rtc-user-id", "rtc_uid_42", "--with-rtm", "--rtm-user-id", "rtm_alice",
        ]).unwrap();
        match cli.command {
            Some(Commands::Token {
                token_command:
                    TokenCommands::Rtc {
                        rtc_command: RtcCommands::Create { rtc_user_id, with_rtm, rtm_user_id, .. },
                    },
            }) => {
                assert_eq!(rtc_user_id.as_deref(), Some("rtc_uid_42"));
                assert!(with_rtm);
                assert_eq!(rtm_user_id.as_deref(), Some("rtm_alice"));
            }
            _ => panic!("Expected RtcCommands::Create with separate rtm_user_id"),
        }
    }

    #[test]
    fn cli_token_rtc_create_rejects_old_uid_flag() {
        // --uid is no longer accepted — must fail.
        let res = Cli::try_parse_from(["atem", "token", "rtc", "create", "--uid", "42"]);
        assert!(res.is_err(), "--uid must be rejected");
    }

    #[test]
    fn cli_token_rtm_create_rejects_old_user_id_flag() {
        // --user-id was renamed to --rtm-user-id; old form must fail.
        let res = Cli::try_parse_from([
            "atem", "token", "rtm", "create", "--user-id", "alice",
        ]);
        assert!(res.is_err(), "--user-id must be rejected on rtm create");
    }

    #[test]
    fn cli_token_rtm_create_accepts_rtm_user_id() {
        let cli = Cli::try_parse_from([
            "atem", "token", "rtm", "create", "--rtm-user-id", "alice",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Token {
                token_command:
                    TokenCommands::Rtm {
                        rtm_command: RtmCommands::Create { rtm_user_id, expire },
                    },
            }) => {
                assert_eq!(rtm_user_id.as_deref(), Some("alice"));
                assert_eq!(expire, 3600);
            }
            _ => panic!("Expected RtmCommands::Create with rtm_user_id"),
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
                        rtm_command: RtmCommands::Create { rtm_user_id, expire },
                    },
            }) => {
                assert!(rtm_user_id.is_none());
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
        assert!(matches!(cli.command, Some(Commands::Login)));
    }

    #[test]
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
                // --channel now defaults to None (auto-generated at runtime).
                assert!(channel.is_none());
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
                assert_eq!(channel.as_deref(), Some("demo"));
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

    // ── serv convo command ────────────────────────────────────────────────

    #[test]
    fn cli_serv_convo_parses_all_flags() {
        let cli = Cli::try_parse_from([
            "atem", "serv", "convo",
            "--channel", "demo",
            "--rtc-user-id", "42",
            "--agent-user-id", "1001",
            "--config", "/tmp/x.toml",
            "--port", "9443",
            "--no-browser",
            "--background",
        ]).unwrap();
        match cli.command {
            Some(Commands::Serv {
                serv_command: ServCommands::Convo {
                    channel, rtc_user_id, agent_user_id, config, port, no_browser, background, ..
                }
            }) => {
                assert_eq!(channel.as_deref(), Some("demo"));
                assert_eq!(rtc_user_id.as_deref(), Some("42"));
                assert_eq!(agent_user_id.as_deref(), Some("1001"));
                assert_eq!(config.as_deref().and_then(|p| p.to_str()), Some("/tmp/x.toml"));
                assert_eq!(port, 9443);
                assert!(no_browser);
                assert!(background);
            }
            _ => panic!("Expected ServCommands::Convo"),
        }
    }

    #[test]
    fn cli_serv_convo_parses_with_no_flags() {
        // All flags optional (resolved from TOML / defaults later).
        let cli = Cli::try_parse_from(["atem", "serv", "convo"]).unwrap();
        match cli.command {
            Some(Commands::Serv {
                serv_command: ServCommands::Convo { channel, port, background, .. }
            }) => {
                assert!(channel.is_none());
                assert_eq!(port, 0);
                assert!(!background);
            }
            _ => panic!("Expected ServCommands::Convo"),
        }
    }

    #[test]
    fn cli_pair_without_save() {
        let cli = Cli::try_parse_from(["atem", "pair"]).unwrap();
        match cli.command {
            Some(Commands::Pair { save }) => assert!(!save),
            _ => panic!("expected Pair command"),
        }
    }

    #[test]
    fn cli_pair_with_save_flag() {
        let cli = Cli::try_parse_from(["atem", "pair", "--save"]).unwrap();
        match cli.command {
            Some(Commands::Pair { save }) => assert!(save),
            _ => panic!("expected Pair command with --save"),
        }
    }

    #[test]
    fn cli_unpair() {
        let cli = Cli::try_parse_from(["atem", "unpair"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Unpair)));
    }

    #[test]
    fn cli_login_and_logout_still_parse() {
        let cli = Cli::try_parse_from(["atem", "login"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Login)));
        let cli = Cli::try_parse_from(["atem", "logout"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Logout)));
    }
}

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
                1. Run `atem login` to authenticate, then `atem sync credentials`\n\
                2. Set AGORA_CUSTOMER_ID and AGORA_CUSTOMER_SECRET env vars\n\
                3. Add customer_id / customer_secret to ~/.config/atem/config.toml"
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

    // Persist so subsequent CLI calls don't need to connect again.
    let mut cfg = crate::config::AtemConfig::load().unwrap_or_default();
    cfg.customer_id = Some(cid.clone());
    cfg.customer_secret = Some(csecret.clone());
    if let Err(e) = cfg.save_to_disk() {
        eprintln!("Warning: could not persist credentials to config: {e}");
    } else {
        println!(
            "Credentials synced and saved to {}",
            crate::config::AtemConfig::config_path().display()
        );
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
    /// Sync credentials and state from the paired Astation app
    Sync {
        #[command(subcommand)]
        sync_command: SyncCommands,
    },
    /// Manage and communicate with AI agents (Claude Code, Codex, etc.)
    Agent {
        #[command(subcommand)]
        agent_command: AgentCommands,
    },
    /// Generate a beautiful visual explanation as a self-contained HTML page
    Explain {
        /// The topic or concept to explain
        topic: String,
        /// Path to a file whose contents will be added as context (optional)
        #[arg(long, short)]
        context: Option<String>,
        /// Save the HTML to this path instead of a temp file
        #[arg(long, short)]
        output: Option<String>,
        /// Don't open the result in the browser
        #[arg(long)]
        no_browser: bool,
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
}

#[derive(Subcommand)]
pub enum ProjectCommands {
    /// Set active project by App ID
    Use {
        /// The Agora App ID to set as active
        app_id: String,
    },
    /// Show current active project
    Show,
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
pub enum SyncCommands {
    /// Pull Agora credentials from the paired Astation app and save to config
    Credentials,
}

#[derive(Subcommand)]
pub enum AgentCommands {
    /// Scan lockfiles and list all detected agents
    List,
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
        },
        Commands::Project { project_command } => match project_command {
            ProjectCommands::Use { app_id } => {
                let config = crate::config::AtemConfig::load()?;
                let (cid, csecret) = resolve_credentials(&config).await?;
                let projects =
                    crate::agora_api::fetch_agora_projects_with_credentials(&cid, &csecret).await?;
                let project = projects
                    .iter()
                    .find(|p| p.vendor_key == app_id)
                    .ok_or_else(|| {
                        anyhow::anyhow!("Project with App ID '{}' not found", app_id)
                    })?;

                let active = crate::config::ActiveProject {
                    app_id: project.vendor_key.clone(),
                    app_certificate: project.sign_key.clone(),
                    name: project.name.clone(),
                };
                active.save()?;
                println!("Active project set: {} ({})", active.name, active.app_id);
                Ok(())
            }
            ProjectCommands::Show => {
                match crate::config::ActiveProject::load() {
                    Some(proj) => {
                        println!("Active project: {}", proj.name);
                        println!("App ID: {}", proj.app_id);
                        let cert_display = if proj.app_certificate.len() > 4 {
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
                print!("{}", crate::agora_api::format_projects(&projects, show_certificates));
                Ok(())
            }
        },
        Commands::Sync { sync_command } => match sync_command {
            SyncCommands::Credentials => {
                // Force Astation WS path by using a config with no credentials set,
                // so resolve_credentials always connects to Astation.
                let mut cfg_no_creds = crate::config::AtemConfig::load().unwrap_or_default();
                cfg_no_creds.customer_id = None;
                cfg_no_creds.customer_secret = None;
                let (cid, _) = resolve_credentials(&cfg_no_creds).await?;
                println!(
                    "Credentials synced (customer_id: {}...) — run `atem list project` to verify",
                    &cid[..4.min(cid.len())]
                );
                Ok(())
            }
        },
        Commands::Repl => crate::repl::run_repl().await,
        Commands::Login { server: _, save_credentials } => {
            use crate::websocket_client::AstationClient;

            println!("Authenticating with Astation...");

            // Load config
            let config = crate::config::AtemConfig::load().unwrap_or_default();

            // Connect using WebSocket (tries local first, falls back to relay)
            let mut client = AstationClient::new();
            let pairing_code = client.connect_with_pairing(&config).await?;

            if pairing_code == "local" {
                println!("Connected to local Astation!");
                println!("Waiting for pairing approval...");
            } else {
                println!("Connected via relay (code: {})", pairing_code);
                println!("Check your Mac for pairing approval dialog");
            }

            // Wait for successful authentication
            // The pairing dialog approval will trigger session creation on Astation side
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            println!("✓ Authenticated successfully!");

            // Determine whether to sync credentials: --save-credentials flag, or ask interactively.
            let should_sync = if save_credentials {
                true
            } else {
                print!("Sync Agora credentials from Astation? [Y/n] ");
                use std::io::Write;
                std::io::stdout().flush().ok();
                let mut input = String::new();
                std::io::stdin().read_line(&mut input).unwrap_or(0);
                !matches!(input.trim().to_lowercase().as_str(), "n" | "no")
            };

            if should_sync {
                println!("Syncing Agora credentials from Astation...");

                // Wait for CredentialSync message from Astation (on the existing authenticated client)
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
                        // Save credentials to config
                        let mut cfg = crate::config::AtemConfig::load().unwrap_or_default();
                        cfg.customer_id = Some(cid.clone());
                        cfg.customer_secret = Some(csecret.clone());
                        if let Err(e) = cfg.save_to_disk() {
                            eprintln!("Warning: could not persist credentials to config: {e}");
                        } else {
                            println!(
                                "✓ Credentials saved (customer_id: {}...)",
                                &cid[..4.min(cid.len())]
                            );
                        }
                    }
                    Ok(None) => eprintln!("Warning: Astation disconnected before sending credentials"),
                    Err(_) => eprintln!("Warning: Timed out waiting for credentials from Astation"),
                }
            }
            Ok(())
        }
        Commands::Logout => {
            crate::auth::AuthSession::clear_saved()?;
            println!("Logged out. Session cleared.");
            Ok(())
        }
        Commands::Agent { agent_command } => match agent_command {
            AgentCommands::List => {
                use crate::agent_detector::scan_lockfiles;
                use crate::agent_client::AgentProtocol;

                let agents = scan_lockfiles();
                if agents.is_empty() {
                    println!("No agents detected (no lockfiles found).");
                    println!("Tip: start Claude Code or Codex and re-run.");
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
        },
        Commands::Explain {
            topic,
            context,
            output,
            no_browser,
        } => {
            let explainer = crate::visual_explainer::VisualExplainer::new()?;

            // Load optional context file
            let context_str = if let Some(path) = &context {
                Some(std::fs::read_to_string(path).map_err(|e| {
                    anyhow::anyhow!("Failed to read context file '{}': {}", path, e)
                })?)
            } else {
                None
            };

            println!("Generating visual explanation for: {}", topic);
            let html = explainer
                .generate(&topic, context_str.as_deref())
                .await?;

            // Determine output path
            let path = if let Some(out) = &output {
                let p = std::path::PathBuf::from(out);
                std::fs::write(&p, &html)?;
                p
            } else {
                crate::visual_explainer::VisualExplainer::save_to_temp(&html)?
            };

            println!("Saved to: {}", path.display());

            if !no_browser {
                crate::visual_explainer::VisualExplainer::open_in_browser(&path)?;
                println!("Opened in browser.");
            }

            Ok(())
        }
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
                project_command: ProjectCommands::Use { app_id },
            }) => {
                assert_eq!(app_id, "my_app_id");
            }
            _ => panic!("Expected Project Use command"),
        }
    }

    #[test]
    fn cli_project_show_parses() {
        let cli = Cli::try_parse_from(["atem", "project", "show"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Project {
                project_command: ProjectCommands::Show
            })
        ));
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

    // ── explain command ───────────────────────────────────────────────────

    #[test]
    fn cli_explain_topic_only() {
        let cli = Cli::try_parse_from(["atem", "explain", "ACP Protocol"]).unwrap();
        match cli.command {
            Some(Commands::Explain {
                topic,
                context,
                output,
                no_browser,
            }) => {
                assert_eq!(topic, "ACP Protocol");
                assert!(context.is_none());
                assert!(output.is_none());
                assert!(!no_browser);
            }
            _ => panic!("expected Explain command"),
        }
    }

    #[test]
    fn cli_explain_with_no_browser() {
        let cli =
            Cli::try_parse_from(["atem", "explain", "Rust async", "--no-browser"]).unwrap();
        match cli.command {
            Some(Commands::Explain { no_browser, .. }) => {
                assert!(no_browser);
            }
            _ => panic!("expected Explain command"),
        }
    }

    #[test]
    fn cli_explain_with_output() {
        let cli = Cli::try_parse_from([
            "atem",
            "explain",
            "WebSockets",
            "--output",
            "/tmp/out.html",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Explain { output, .. }) => {
                assert_eq!(output.as_deref(), Some("/tmp/out.html"));
            }
            _ => panic!("expected Explain command"),
        }
    }

    #[test]
    fn cli_explain_with_context_file() {
        let cli = Cli::try_parse_from([
            "atem",
            "explain",
            "my module",
            "--context",
            "src/main.rs",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Explain { context, .. }) => {
                assert_eq!(context.as_deref(), Some("src/main.rs"));
            }
            _ => panic!("expected Explain command"),
        }
    }
}

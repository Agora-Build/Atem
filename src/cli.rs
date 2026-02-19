use anyhow::Result;
use clap::{Parser, Subcommand};

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
    },
    /// Clear saved authentication session
    Logout,
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
                let cid = config.customer_id.as_deref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "AGORA_CUSTOMER_ID not configured. Set it in ~/.config/atem/config.toml or as env var."
                    )
                })?;
                let csecret = config.customer_secret.as_deref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "AGORA_CUSTOMER_SECRET not configured. Set it in ~/.config/atem/config.toml or as env var."
                    )
                })?;

                let projects =
                    crate::agora_api::fetch_agora_projects_with_credentials(cid, csecret).await?;
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

                // Priority 1: local credentials (env > config file)
                if let (Some(cid), Some(csecret)) =
                    (config.customer_id.as_deref(), config.customer_secret.as_deref())
                {
                    let projects =
                        crate::agora_api::fetch_agora_projects_with_credentials(cid, csecret)
                            .await?;
                    print!("{}", crate::agora_api::format_projects(&projects, show_certificates));
                    return Ok(());
                }

                // Priority 2: request projects from local Astation over WebSocket
                println!("No local credentials — connecting to Astation...");
                let ws_url = config.astation_ws();
                let mut client = crate::websocket_client::AstationClient::new();
                match client.connect(ws_url).await {
                    Ok(()) => {
                        client.request_projects().await?;
                        // Wait up to 5 seconds for response
                        let timeout = tokio::time::Duration::from_secs(5);
                        let result = tokio::time::timeout(timeout, async {
                            loop {
                                match client.recv_message().await {
                                    Some(crate::websocket_client::AstationMessage::ProjectListResponse {
                                        projects,
                                        ..
                                    }) => return Some(projects),
                                    Some(_) => continue,
                                    None => return None,
                                }
                            }
                        })
                        .await;

                        match result {
                            Ok(Some(projects)) => {
                                if projects.is_empty() {
                                    println!("No projects found in your Agora account.");
                                } else {
                                    for (i, p) in projects.iter().enumerate() {
                                        println!("{}. {} (ID: {})", i + 1, p.name, p.id);
                                    }
                                }
                            }
                            Ok(None) | Err(_) => {
                                anyhow::bail!(
                                    "Timed out waiting for projects from Astation.\n\
                                    Configure credentials in ~/.config/atem/config.toml or run `atem` \
                                    to sync them automatically after pairing."
                                );
                            }
                        }
                    }
                    Err(e) => {
                        anyhow::bail!(
                            "No credentials found and could not connect to Astation ({}): {}\n\
                            Options:\n\
                            1. Run `atem` (TUI) — credentials auto-sync from Astation on connect\n\
                            2. Set AGORA_CUSTOMER_ID and AGORA_CUSTOMER_SECRET env vars\n\
                            3. Add to ~/.config/atem/config.toml",
                            ws_url, e
                        );
                    }
                }
                Ok(())
            }
        },
        Commands::Repl => crate::repl::run_repl().await,
        Commands::Login { server } => {
            let relay = if let Some(s) = server.as_deref() {
                s.to_string()
            } else {
                let cfg = crate::config::AtemConfig::load().unwrap_or_default();
                cfg.astation_relay_url().to_string()
            };
            let session = crate::auth::run_login_flow(Some(&relay)).await?;
            session.save()?;
            println!("Session saved. You are now authenticated.");
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
            Some(Commands::Login { server }) => {
                assert!(server.is_none());
            }
            _ => panic!("Expected Login command"),
        }
    }

    #[test]
    fn cli_login_with_server_parses() {
        let cli =
            Cli::try_parse_from(["atem", "login", "--server", "http://localhost:3000"]).unwrap();
        match cli.command {
            Some(Commands::Login { server }) => {
                assert_eq!(server.as_deref(), Some("http://localhost:3000"));
            }
            _ => panic!("Expected Login command with server"),
        }
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

use anyhow::Result;
use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "atem")]
#[command(disable_version_flag = true)]
#[command(about = "A terminal that connects builders, Agora platform, and AI agents.")]
#[command(long_about = "A terminal that connects builders, Agora platform, and AI agents.

Open source. Some functions built on official Agora APIs — your credentials stay on your machine.

Disclaimer: This is an unofficial community tool that contains some experimental
functions, provided AS-IS, with no SLA or guarantees. Contributions welcome.
For official products and support, visit https://www.agora.io/")]
pub struct Cli {
    /// Print the version, and those of Atem's background processes while they run
    #[arg(short = 'V', long = "version")]
    pub version: bool,
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
    /// Manage current project
    Project {
        #[command(subcommand)]
        project_command: ProjectCommands,
    },
    /// Interactive REPL with AI-powered command interpretation
    Repl,
    /// Log in with Agora Console (opens browser)
    Login,
    /// Log out from SSO
    Logout,
    /// Show account, pairing, verification and credential status (read-only, offline)
    Status,
    /// Pair with Astation (shows the status when already paired)
    #[command(args_conflicts_with_subcommands = true)]
    Pair {
        /// Save credentials for offline use
        #[arg(long)]
        save: bool,
        #[command(subcommand)]
        command: Option<PairCommands>,
    },
    /// Unpair from Astation
    Unpair {
        /// Don't ask for confirmation (needed when input isn't a terminal)
        #[arg(short, long)]
        yes: bool,
    },
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
    /// Shared cross-agent context store (see designs/vault.md)
    Vault {
        #[command(subcommand)]
        command: VaultCommands,
    },
    /// Sync memory and skills across agents and machines (see designs/atem-memory.md)
    Sync {
        /// Don't harvest Claude's saved memories this run
        #[arg(long)]
        no_harvest: bool,
        /// Allow writing into files tracked by git
        #[arg(long)]
        allow_tracked: bool,
    },
    /// Shared memory for coding agents (see designs/atem-memory.md)
    Memory {
        #[command(subcommand)]
        command: MemoryCommands,
    },
    /// Shared skills for coding agents (see designs/atem-memory.md)
    Skill {
        #[command(subcommand)]
        command: SkillCommands,
    },
    /// This device's keys: unlock with Touch ID on your Mac, lock (status: `atem status`; see designs/e2e-encryption.md)
    Cred {
        #[command(subcommand)]
        command: CredCommands,
    },
    /// Runs the cred agent (started automatically when keys are needed)
    #[command(hide = true)]
    CredAgent,
    /// Atem's background runtime (agent sessions, the Astation link): `atem runtime restart`
    Runtime {
        #[command(subcommand)]
        command: Option<RuntimeCommands>,
    },
    /// Runs one agent session for the runtime (started by it; outlives it)
    #[command(hide = true)]
    Worker {
        /// The runtime's state directory
        #[arg(long)]
        state: std::path::PathBuf,
        /// The session id (`ses-…`)
        #[arg(long)]
        session: String,
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
    /// Clear the current project
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
    /// List all Agora projects in your account
    List {
        /// Show app certificates in output
        #[arg(long)]
        show_certificates: bool,
    },
    /// Set current project by App ID or index from `atem project list`
    Use {
        /// App ID or 1-based index from `atem project list`
        app_id_or_index: String,
    },
    /// Show current project
    Show {
        /// Show full app certificate (unmasked)
        #[arg(long)]
        with_certificate: bool,
    },
}


#[derive(Subcommand)]
pub enum AgentCommands {
    /// Start the original interactive CLI as a runtime session and open it
    /// here; detaching (prefix, then h) leaves it running
    Launch {
        /// Agent type to launch (claude, claude-code or codex)
        #[arg(default_value = "claude-code")]
        agent_type: String,
        /// Arguments passed to the original agent CLI (e.g. --continue for claude, resume --last for codex)
        #[arg(
            trailing_var_arg = true,
            allow_hyphen_values = true,
            value_name = "AGENT_ARGS"
        )]
        agent_args: Vec<String>,
    },
    /// Open a running session (`atem agent list` shows them)
    Attach {
        /// Session id (ses-…)
        session_id: String,
    },
    /// List the runtime's sessions
    List,
    /// Stop a session's agent (or remove one that can't run any more)
    Stop {
        /// Session id (ses-…)
        session_id: String,
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
  for i in $(seq -f '%04g' 1 40); do \\
    atem serv convo --background --channel 'atem-convo-{appid}-{ts}-'$i; \\
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
    /// Serve a directory (or single file) over HTTPS. Markdown is
    /// rendered to HTML by default; append `?raw=1` to any URL for
    /// raw bytes. Useful for browsing AI-generated docs on a remote
    /// machine.
    #[command(after_help = "EXAMPLES:
  # Foreground — print Local/Network/Custom URLs, open browser
  atem serv files /home/me/docs

  # Single file — serves the parent dir, URL points at the file
  atem serv files /home/me/docs/spec.md

  # Background daemon (port auto-picked when not given)
  atem serv files /home/me/docs --background
  atem serv list
  atem serv kill files-<port>
")]
    Files {
        /// Directory or single file to serve. A file path serves the
        /// parent directory with the URL pointing at the file.
        dir: std::path::PathBuf,
        /// HTTPS port (0 = auto-pick — works for both foreground and --background).
        #[arg(long, default_value = "0")]
        port: u16,
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

#[derive(clap::Subcommand, Debug)]
pub enum PairCommands {
    /// Verify this device with the paired Astation (safety code + Touch ID); no re-pairing
    Verify,
}

#[derive(clap::Subcommand, Debug)]
pub enum RuntimeCommands {
    /// Restart the runtime as this build; sessions keep running
    Restart,
}

#[derive(clap::Subcommand, Debug)]
pub enum CredCommands {
    /// Send known Git projects to Astation's credential picker (keys must be unlocked)
    Projects,
    /// Unlock this device's keys (approve with Touch ID on your Mac)
    Unlock,
    /// Wipe the unlocked keys from memory and stop the cred agent
    Lock,
}

#[derive(clap::Subcommand, Debug)]
pub enum VaultCommands {
    /// Create a new vault in the current work session
    New {
        /// Human/agent description of the vault
        #[arg(long)]
        summary: String,
    },
    /// List vaults you can read
    List,
    /// Read a vault's current contents (or history)
    Read {
        /// Vault id (from 'vault new' / 'vault list')
        #[arg(long = "vault-id")]
        vault_id: String,
        /// Only entries newer than this seq cursor
        #[arg(long)]
        since: Option<u64>,
        /// Show every version, not just the current view
        #[arg(long)]
        history: bool,
        /// Output format: human (default) or plain
        #[arg(long, default_value = "human")]
        format: String,
    },
    /// Append an entry, or override one with --entry-id
    Write {
        /// Vault id to write to
        #[arg(long = "vault-id")]
        vault_id: String,
        /// Override this entry id instead of appending
        #[arg(long = "entry-id")]
        entry_id: Option<u32>,
        /// Entry text
        #[arg(long)]
        text: String,
    },
    /// Update the mutable summary
    SetSummary {
        /// Vault id whose summary to update
        #[arg(long = "vault-id")]
        vault_id: String,
        /// New summary text
        #[arg(long)]
        text: String,
    },
}

#[derive(clap::Subcommand, Debug)]
pub enum MemoryCommands {
    /// Add a memory (a short, durable fact)
    Add {
        /// The fact to remember
        content: String,
        /// global | project | machine (default: project inside a git repo, else global)
        #[arg(long)]
        scope: Option<String>,
        /// Project key (default: the current repo's normalized git remote)
        #[arg(long)]
        project: Option<String>,
        /// high | medium | low
        #[arg(long, default_value = "medium")]
        confidence: String,
        /// Which agent is saving this: cli (default) or codex
        #[arg(long, default_value = "cli", value_parser = ["cli", "codex"])]
        agent: String,
        /// Store even though it looks like a credential (only if it is not one)
        #[arg(long)]
        force: bool,
        /// When the fact became true: YYYY-MM-DD (UTC) or unix seconds (default: now)
        #[arg(long)]
        valid_at: Option<String>,
    },
    /// List valid memories (global, this machine, and the current project unless --all)
    List {
        #[arg(long)]
        scope: Option<String>,
        #[arg(long)]
        project: Option<String>,
        /// List memories from every project and machine, not just this one
        #[arg(long)]
        all: bool,
        /// Include outdated facts and show replacement chains, oldest first
        /// (with an id: just the chain containing it)
        #[arg(long, value_name = "ID", num_args = 0..=1)]
        history: Option<Option<String>>,
        /// Show everything about each memory: full id, status, timestamps, source, whole content
        #[arg(long)]
        full: bool,
    },
    /// Search memories on this machine (FTS5 + BM25; works for CJK; offline)
    Search {
        text: String,
        /// global | project | machine (default: any)
        #[arg(long)]
        scope: Option<String>,
        /// Only this project key
        #[arg(long)]
        project: Option<String>,
        /// Include outdated facts
        #[arg(long)]
        history: bool,
        #[arg(long, default_value_t = 20)]
        limit: usize,
        /// Show everything about each memory: full id, status, timestamps, source, whole content
        #[arg(long)]
        full: bool,
    },
    /// Remove a memory everywhere
    Rm {
        id: String,
    },
    /// Replace an outdated fact: adds the new one and invalidates the old one
    Replace {
        /// Memory id (a unique prefix, or the short id shown in the Codex block)
        id: String,
        /// The fact as it is now
        content: String,
        /// When the new fact became true: YYYY-MM-DD (UTC) or unix seconds (default: now)
        #[arg(long)]
        valid_at: Option<String>,
    },
    /// Mark a fact outdated without a replacement (kept as history, no longer injected)
    Invalidate {
        /// Memory id (a unique prefix, or the short id shown in the Codex block)
        id: String,
        /// When it stopped being true: YYYY-MM-DD (UTC) or unix seconds (default: now)
        #[arg(long)]
        at: Option<String>,
    },
    /// Remove a memory that contained a credential, everywhere, and stop re-harvesting it
    Purge {
        id: String,
        /// Don't ask for confirmation (needed when input isn't a terminal)
        #[arg(short, long)]
        yes: bool,
    },
    /// Rewrite the managed memory blocks and skills from the local store
    Apply {
        #[arg(long)]
        allow_tracked: bool,
    },
    /// Account, machine, pending changes, held-back memories, credential findings
    Status,
}

#[derive(clap::Subcommand, Debug)]
pub enum SkillCommands {
    /// Add (or update) a skill from a directory containing SKILL.md
    Add {
        dir: String,
        /// global (default) | project
        #[arg(long)]
        scope: Option<String>,
        /// Skill name (default: the directory name)
        #[arg(long)]
        name: Option<String>,
    },
    /// List skills
    List,
    /// Remove a skill everywhere
    Rm {
        name: String,
        #[arg(long, default_value = "global")]
        scope: String,
    },
    /// Every version of a skill, newest first (asks the relay)
    History {
        name: String,
        #[arg(long, default_value = "global")]
        scope: String,
    },
    /// Re-push an old version's files as a new version (history is kept)
    Restore {
        name: String,
        #[arg(long)]
        version: i64,
        #[arg(long, default_value = "global")]
        scope: String,
    },
    /// Erase skill versions that contained a credential
    Purge {
        name: String,
        #[arg(long, default_value = "global")]
        scope: String,
        #[arg(long)]
        version: Option<i64>,
        #[arg(long)]
        all_versions: bool,
        /// Don't ask for confirmation (needed when input isn't a terminal)
        #[arg(short, long)]
        yes: bool,
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
                crate::config::ProjectCache::clear_current()?;
                println!("Current project cleared.");
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
            ProjectCommands::List { show_certificates } => {
                crate::auth::require_login("atem project")?;
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
            ProjectCommands::Use { app_id_or_index } => {
                // Index path reads from local ProjectCache — no network call needed.
                // App ID path fetches from the BFF API to resolve name + certificate.
                if let Ok(idx) = app_id_or_index.parse::<usize>() {
                    let project = crate::config::ProjectCache::get(idx).ok_or_else(|| {
                        let hint = match crate::config::ProjectCache::load() {
                            Some(projects) => format!(
                                "Valid range: 1-{}. Run `atem project list` to refresh.",
                                projects.len()
                            ),
                            None => "No cached projects. Run `atem project list` first.".to_string(),
                        };
                        anyhow::anyhow!("Invalid project index {}. {}", idx, hint)
                    })?;
                    crate::config::ProjectCache::set_current(&project.app_id, None)?;
                    println!("Current project set: {} ({})", project.name, project.app_id);
                } else {
                    crate::auth::require_login("atem project")?;
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
                    crate::config::ProjectCache::set_current(&project.app_id, None)?;
                    println!("Current project set: {} ({})", project.name, project.app_id);
                }
                Ok(())
            }
            ProjectCommands::Show { with_certificate } => {
                match crate::config::ProjectCache::get_current() {
                    Some(proj) => {
                        println!("Current project: {}", proj.name);
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
                        println!("No current project set. Run `atem project use <APP_ID>`");
                    }
                }
                Ok(())
            }
        },
        Commands::Repl => crate::repl::run_repl().await,
        Commands::Login => {
            let config = crate::config::AtemConfig::load()?;
            let session = crate::sso_auth::run_login_flow(config.effective_sso_url()).await?;
            crate::records::Login::from_sso(
                config.effective_sso_url(),
                session.login_id.clone(),
                session.tokens(),
            )
            .save(&crate::paths::ProfilePaths::default_paths().login)?;
            match &session.login_id {
                Some(id) => println!("Logged in. (SSO: {})", id),
                None => println!("Logged in. (SSO)"),
            }
            Ok(())
        }
        Commands::Logout => {
            crate::records::Login::remove(&crate::paths::ProfilePaths::default_paths().login)?;
            println!("Logged out.");
            reload_runtime().await;
            Ok(())
        }
        Commands::Status => {
            let src = crate::profile::Sources::current()?;
            print!("{}", crate::memory::cred_agent::blocking(move || Ok(crate::status::text(&src))).await?);
            Ok(())
        }
        Commands::Pair { save, command: None } => run_pair(&crate::profile::Sources::current()?, save).await,
        Commands::Pair { command: Some(PairCommands::Verify), .. } => {
            run_pair_verify(&crate::profile::Sources::current()?).await
        }
        Commands::Unpair { yes } => {
            let src = crate::profile::Sources::current()?;
            if !crate::status::profile_paired(&src) && !revocation_recorded(&src) {
                // r9: an unpair that stopped midway left device-list files.
                if crate::pairing::remove_device_list_leftovers(&src)? {
                    println!("Removed the leftover device-list files.");
                    reload_runtime().await;
                } else {
                    println!("No pairing to remove.");
                }
                return Ok(());
            }
            let what = match crate::status::pairing(&src) {
                Some(pairing) => format!("the pairing with Astation {}", pairing.astation_id),
                None => "this profile's pairing".to_string(),
            };
            if !confirm_destructive(
                &format!(
                    "Remove {what}? This machine loses vault, memory sync and `atem cred` until you run `atem pair` again."
                ),
                yes,
            )? {
                println!("Cancelled; nothing was removed.");
                return Ok(());
            }
            let notices = {
                let src = src.clone();
                crate::memory::cred_agent::blocking(move || {
                    let agent = crate::memory::cred_agent::running_agent();
                    unpair_profile(&src, agent.as_deref())
                })
                .await?
            };
            println!("Unpaired.");
            for notice in notices {
                println!("{notice}");
            }
            reload_runtime().await;
            Ok(())
        }
        Commands::Agent { agent_command } => match agent_command {
            AgentCommands::Launch {
                agent_type,
                agent_args,
            } => crate::runtime::commands::launch(&agent_type, agent_args).await,
            AgentCommands::Attach { session_id } => {
                crate::runtime::commands::attach(&session_id).await
            }
            AgentCommands::List => crate::runtime::commands::list().await,
            AgentCommands::Stop { session_id } => crate::runtime::commands::stop(&session_id).await,
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
            ServCommands::Files {
                dir,
                port,
                no_browser,
                background,
                _serv_daemon,
            } => {
                let config = crate::files_server::ServeFilesConfig {
                    dir,
                    port,
                    no_browser,
                    background,
                    _daemon: _serv_daemon,
                };
                crate::files_server::run_server(config).await
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
        Commands::Vault { command } => handle_vault_command(command).await,
        Commands::Sync { no_harvest, allow_tracked } => crate::memory::cmd::handle_sync(no_harvest, allow_tracked).await,
        Commands::Memory { command } => crate::memory::cmd::handle_memory(command).await,
        Commands::Skill { command } => crate::memory::cmd::handle_skill(command).await,
        Commands::Cred { command } => crate::memory::unlock::handle_cred(command).await,
        Commands::CredAgent => {
            #[cfg(unix)]
            {
                crate::memory::agent_socket::run_cred_agent().await
            }
            #[cfg(not(unix))]
            {
                anyhow::bail!("the cred agent needs a Unix system")
            }
        }
        // Bare `atem runtime` is the runtime itself (started detached by the
        // commands that need it).
        Commands::Runtime { command: None } => {
            crate::runtime::run_runtime(crate::config::AtemConfig::config_dir()).await
        }
        Commands::Runtime {
            command: Some(RuntimeCommands::Restart),
        } => crate::runtime::client::restart().await,
        Commands::Worker { state, session } => crate::runtime::worker::run_worker(state, session).await,
    }
}

async fn handle_vault_command(command: VaultCommands) -> Result<()> {
    use crate::vault_client::{self, VaultClient};

    // Tier-2 gate: Astation is the control plane, so vault needs an active
    // pairing session. Also resolves relay base + client id + session.
    let paired = crate::auth::require_pairing("Atem Vault")?;
    let client_id = crate::config::AtemConfig::ensure_instance_id();
    let client = VaultClient::new(
        paired.relay_base,
        client_id,
        paired.session_id,
        paired.astation_id,
    );

    match command {
        VaultCommands::New { summary } => {
            let v = client.create(&summary).await?;
            println!("Created vault {}", v.vault_id);
        }
        VaultCommands::List => {
            for item in client.list().await? {
                println!("{}  {}", item.vault_id, item.summary);
            }
        }
        VaultCommands::Read { vault_id, since, history, format } => {
            let entries = client.read(&vault_id, since, history).await?;
            let fmt = vault_client::parse_format(&format);
            let out = if history {
                vault_client::render_history(&entries, fmt)
            } else {
                // Summary lives on the vaults row, not in the entries list; v1
                // renders an empty summary header here. A follow-up can have the
                // read endpoint return {summary, entries} and thread it through.
                vault_client::render_current("", &entries, fmt)
            };
            print!("{}", out);
        }
        VaultCommands::Write { vault_id, entry_id, text } => {
            let r = client.write(&vault_id, &text, entry_id).await?;
            println!("Wrote e{} v{} (seq {})", r.entry_no, r.version, r.seq);
        }
        VaultCommands::SetSummary { vault_id, text } => {
            client.set_summary(&vault_id, &text).await?;
            println!("Summary updated.");
        }
    }
    Ok(())
}

/// Prompt a yes/no question on stdin. Defaults to false on empty / non-tty.
/// Confirms an irreversible command. `--yes` skips the question; without a
/// terminal and without `--yes` it refuses rather than guess, so scripts must
/// say `--yes`. A typo asks again; Enter means no.
pub(crate) fn confirm_destructive(question: &str, yes: bool) -> Result<bool> {
    use std::io::IsTerminal;
    destructive_decision(yes, std::io::stdin().is_terminal(), || {
        prompt_yes_no(&format!("{question} [y/N]: "))
    })
}

fn destructive_decision(yes: bool, is_terminal: bool, ask: impl FnOnce() -> bool) -> Result<bool> {
    if yes {
        return Ok(true);
    }
    if !is_terminal {
        anyhow::bail!("This can't be undone, and input isn't a terminal to confirm it: pass --yes to go ahead.");
    }
    Ok(ask())
}

fn prompt_yes_no(question: &str) -> bool {
    use std::io::{self, BufRead, Write};

    print!("{question}");
    let _ = io::stdout().flush();

    let stdin = io::stdin();
    loop {
        let mut line = String::new();
        match stdin.lock().read_line(&mut line) {
            Ok(0) | Err(_) => return false,
            Ok(_) => {}
        }
        match line.trim().to_ascii_lowercase().as_str() {
            "y" | "yes" => return true,
            // Empty takes the default ("[y/N]").
            "" | "n" | "no" => return false,
            // A typo ("yn") asks again instead of meaning "no".
            _ => {
                print!("Type y or n: ");
                let _ = io::stdout().flush();
            }
        }
    }
}

/// Whether an Astation revoked this device (`atem unpair` sets its keys aside).
fn revocation_recorded(src: &crate::profile::Sources) -> bool {
    crate::memory::trust::TrustStore::load_from(&src.paths.cred.trust)
        .is_ok_and(|trust| trust.revoked().is_some())
}

/// `atem unpair` after the confirmation: first durably commits the next host
/// trust generation (so work started under the old pairing can't apply
/// anything, even if what follows is interrupted), then removes the pairing
/// record and the r9 device list (the user's own login, memory, vault data,
/// trust pins and keys stay: `pairing::unpair_with_notices`), and, when an
/// Astation revoked this device and `agent` (the running cred agent, if any)
/// doesn't hold its keys unlocked, sets the revoked keys aside so the next
/// `atem pair` verifies with new ones. Returns the notices to print: keys set
/// aside, a revocation left recorded, or a failure to set them aside (the
/// pairing is removed regardless). Blocking.
fn unpair_profile(
    src: &crate::profile::Sources,
    agent: Option<&dyn crate::memory::cred_agent::CredAgentApi>,
) -> Result<Vec<String>> {
    let (_, mut notices) = crate::pairing::unpair_with_notices(src)?;
    // Unpaired from here on: what happens to revoked keys is only reported.
    match crate::memory::verification::set_aside_revoked_keys(&src.paths.cred, agent) {
        Ok(Some(notice)) => notices.push(notice),
        Ok(None) => {}
        Err(error) => notices.push(format!("Couldn't set the revoked keys aside: {error:#}")),
    }
    if let Ok(trust) = crate::memory::trust::TrustStore::load_from(&src.paths.cred.trust)
        && let Some(revoked) = trust.revoked()
    {
        let why = if trust.recorded_home() != Some(revoked.astation_id.as_str()) {
            "it isn't this device's home Astation"
        } else {
            "the cred agent holds them unlocked; run `atem cred lock`, then `atem unpair` again"
        };
        notices.push(format!(
            "Astation {}'s revocation of this device is still recorded and its keys were not set aside ({why}).",
            revoked.astation_id
        ));
    }
    Ok(notices)
}

/// `atem pair [--save]` — when the profile is already paired, prints its
/// status and changes nothing (no runtime, no connection). Otherwise the
/// runtime pairs (pairing code or local), stores the credentials and the
/// binding, makes the new connection its link and verifies this device on it.
async fn run_pair(src: &crate::profile::Sources, save: bool) -> Result<()> {
    run_pair_with(src, save, |options| {
        crate::runtime::op_client::run(crate::runtime::protocol::OpKind::Pair, options)
    })
    .await
}

async fn run_pair_with<F: std::future::Future<Output = Result<()>>>(
    src: &crate::profile::Sources,
    save: bool,
    op: impl FnOnce(crate::runtime::protocol::OpOptions) -> F,
) -> Result<()> {
    let already = {
        let src = src.clone();
        crate::memory::cred_agent::blocking(move || Ok(crate::status::already_paired(&src))).await?
    };
    if let Some(text) = already {
        print!("{text}");
        return Ok(());
    }
    op(crate::runtime::protocol::OpOptions { save, ..Default::default() }).await
}

/// `atem pair verify` — verifies this device with the paired Astation on the
/// runtime's authenticated link (sessions, viewers and chats stay
/// connected). Does nothing when that Astation already verified it, and
/// refuses after a revocation, offline. A cancelled or failed verification
/// keeps the pairing.
async fn run_pair_verify(src: &crate::profile::Sources) -> Result<()> {
    run_pair_verify_with(src, || {
        crate::runtime::op_client::run(
            crate::runtime::protocol::OpKind::PairVerify,
            Default::default(),
        )
    })
    .await
}

async fn run_pair_verify_with<F: std::future::Future<Output = Result<()>>>(
    src: &crate::profile::Sources,
    op: impl FnOnce() -> F,
) -> Result<()> {
    match crate::status::verify_start(src)? {
        crate::status::VerifyStart::AlreadyVerified(message) => {
            println!("{message}");
            Ok(())
        }
        crate::status::VerifyStart::Verify(_) => op().await,
    }
}

/// `atem unpair` and `atem logout` tell a running runtime to re-read the
/// profile (dropping the link and attachments of a removed pairing); they
/// never start one.
async fn reload_runtime() {
    let locator = crate::runtime::client::Locator::default_paths();
    if let Ok(Some(mut client)) =
        crate::runtime::client::RuntimeClient::existing_at(&locator, true).await
    {
        let _ = client.send(&crate::runtime::protocol::ClientMsg::Reload).await;
        // Wait for its answer, so the link is gone when unpair returns.
        let _ = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while let Ok(Some(message)) = client.recv().await {
                if matches!(message, crate::runtime::protocol::RuntimeMsg::Notice { ref text } if text == "Reloaded") {
                    break;
                }
            }
        })
        .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn destructive_commands_confirm_or_need_yes() {
        // --yes goes ahead without asking, terminal or not.
        assert!(destructive_decision(true, false, || panic!("asked")).unwrap());
        assert!(destructive_decision(true, true, || panic!("asked")).unwrap());
        // No terminal and no --yes: refuse, never guess.
        let error = destructive_decision(false, false, || panic!("asked")).unwrap_err();
        assert!(error.to_string().contains("--yes"), "{error}");
        // A terminal: the answer decides.
        assert!(destructive_decision(false, true, || true).unwrap());
        assert!(!destructive_decision(false, true, || false).unwrap());
    }

    #[test]
    fn purge_and_unpair_accept_yes() {
        let cli = Cli::try_parse_from(["atem", "unpair", "--yes"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Unpair { yes: true })));
        let cli = Cli::try_parse_from(["atem", "memory", "purge", "mem_1a2b", "-y"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Memory { command: MemoryCommands::Purge { yes: true, .. } })
        ));
        let cli = Cli::try_parse_from(["atem", "skill", "purge", "demo", "--all-versions", "--yes"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Skill { command: SkillCommands::Purge { yes: true, all_versions: true, .. } })
        ));
        let cli = Cli::try_parse_from(["atem", "memory", "purge", "mem_1a2b"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Memory { command: MemoryCommands::Purge { yes: false, .. } })
        ));
    }

    #[test]
    fn cli_no_args_returns_none_command() {
        let cli = Cli::try_parse_from(["atem"]).unwrap();
        assert!(cli.command.is_none());
    }

    #[test]
    fn cli_project_list_parses() {
        let cli = Cli::try_parse_from(["atem", "project", "list"]).unwrap();
        match cli.command {
            Some(Commands::Project {
                project_command: ProjectCommands::List { show_certificates },
            }) => {
                assert!(!show_certificates);
            }
            _ => panic!("Expected Project List command"),
        }
    }

    #[test]
    fn cli_project_list_with_show_certificates() {
        let cli =
            Cli::try_parse_from(["atem", "project", "list", "--show-certificates"]).unwrap();
        match cli.command {
            Some(Commands::Project {
                project_command: ProjectCommands::List { show_certificates },
            }) => {
                assert!(show_certificates);
            }
            _ => panic!("Expected Project List command with show_certificates"),
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
    fn cli_agent_launch_defaults_to_claude_without_extra_args() {
        let cli = Cli::try_parse_from(["atem", "agent", "launch"]).unwrap();
        let Some(Commands::Agent {
            agent_command: AgentCommands::Launch {
                agent_type,
                agent_args,
            },
        }) = cli.command
        else {
            panic!("expected agent launch")
        };
        assert_eq!(agent_type, "claude-code");
        assert!(agent_args.is_empty());
    }

    #[test]
    fn cli_agent_launch_forwards_codex_profile_with_or_without_separator() {
        for arguments in [
            vec!["atem", "agent", "launch", "codex", "--profile", "oss"],
            vec!["atem", "agent", "launch", "codex", "--", "--profile", "oss"],
        ] {
            let cli = Cli::try_parse_from(arguments).unwrap();
            let Some(Commands::Agent {
                agent_command: AgentCommands::Launch {
                    agent_type,
                    agent_args,
                },
            }) = cli.command
            else {
                panic!("expected agent launch")
            };
            assert_eq!(agent_type, "codex");
            assert_eq!(agent_args, ["--profile", "oss"]);
        }
    }

    #[test]
    fn cli_agent_launch_preserves_quoted_values_and_literal_separator() {
        let cli = Cli::try_parse_from([
            "atem",
            "agent",
            "launch",
            "claude",
            "--append-system-prompt",
            "a prompt with spaces\nand a newline",
            "--",
            "--literal",
        ])
        .unwrap();
        let Some(Commands::Agent {
            agent_command: AgentCommands::Launch {
                agent_type,
                agent_args,
            },
        }) = cli.command
        else {
            panic!("expected agent launch")
        };
        assert_eq!(agent_type, "claude");
        assert_eq!(
            agent_args,
            [
                "--append-system-prompt",
                "a prompt with spaces\nand a newline",
                "--",
                "--literal"
            ]
        );
    }

    #[test]
    fn cli_agent_launch_forwards_agent_help_after_separator() {
        let cli =
            Cli::try_parse_from(["atem", "agent", "launch", "codex", "--", "--help"]).unwrap();
        let Some(Commands::Agent {
            agent_command: AgentCommands::Launch { agent_args, .. },
        }) = cli.command
        else {
            panic!("expected agent launch")
        };
        assert_eq!(agent_args, ["--help"]);
    }

    #[test]
    fn cli_agent_attach_list_and_stop_parse() {
        let cli = Cli::try_parse_from(["atem", "agent", "attach", "ses-abcdefghijkl"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Agent { agent_command: AgentCommands::Attach { ref session_id } })
                if session_id == "ses-abcdefghijkl"
        ));
        let cli = Cli::try_parse_from(["atem", "agent", "list"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Agent { agent_command: AgentCommands::List })
        ));
        let cli = Cli::try_parse_from(["atem", "agent", "stop", "ses-abcdefghijkl"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Agent { agent_command: AgentCommands::Stop { ref session_id } })
                if session_id == "ses-abcdefghijkl"
        ));
        assert!(Cli::try_parse_from(["atem", "agent", "attach"]).is_err());
    }

    #[test]
    fn cli_removed_acp_and_diagram_subcommands_are_rejected() {
        for args in [
            &["atem", "agent", "connect", "ws://localhost:8765"][..],
            &["atem", "agent", "prompt", "ws://localhost:8765", "hi"],
            &["atem", "agent", "probe", "ws://localhost:8765"],
            &["atem", "agent", "visualize", "topic"],
            &["atem", "serv", "diagrams"],
        ] {
            let err = match Cli::try_parse_from(args) {
                Ok(_) => panic!("{args:?} should be rejected"),
                Err(e) => e,
            };
            assert_eq!(
                err.kind(),
                clap::error::ErrorKind::InvalidSubcommand,
                "{args:?}"
            );
        }
        // `atem agent launch` still parses.
        assert!(Cli::try_parse_from(["atem", "agent", "launch"]).is_ok());
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
            Some(Commands::Pair { save, .. }) => assert!(!save),
            _ => panic!("expected Pair command"),
        }
    }

    #[test]
    fn cli_pair_with_save_flag() {
        let cli = Cli::try_parse_from(["atem", "pair", "--save"]).unwrap();
        match cli.command {
            Some(Commands::Pair { save, .. }) => assert!(save),
            _ => panic!("expected Pair command with --save"),
        }
    }

    #[test]
    fn cred_agent_is_a_hidden_subcommand() {
        use clap::CommandFactory;
        let cli = Cli::try_parse_from(["atem", "cred-agent"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::CredAgent)));
        let help = Cli::command().render_help().to_string();
        assert!(!help.contains("cred-agent"), "{help}");
    }

    #[test]
    fn runtime_runs_bare_and_restarts_visibly() {
        use clap::CommandFactory;
        let cli = Cli::try_parse_from(["atem", "runtime"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Runtime { command: None })));
        let cli = Cli::try_parse_from(["atem", "runtime", "restart"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Runtime { command: Some(RuntimeCommands::Restart) })
        ));
        let help = Cli::command().render_help().to_string();
        assert!(help.contains("runtime restart"), "{help}");
        let mut command = Cli::command();
        let runtime = command.find_subcommand_mut("runtime").unwrap();
        let help = runtime.render_help().to_string();
        assert!(
            help.contains("Restart the runtime as this build; sessions keep running"),
            "{help}"
        );
    }

    #[test]
    fn worker_is_a_hidden_subcommand_with_state_and_session() {
        use clap::CommandFactory;
        let cli = Cli::try_parse_from(["atem", "worker", "--state", "/tmp/s", "--session", "ses-abcdefgh2345"]).unwrap();
        match cli.command {
            Some(Commands::Worker { state, session }) => {
                assert_eq!(state, std::path::PathBuf::from("/tmp/s"));
                assert_eq!(session, "ses-abcdefgh2345");
            }
            _ => panic!("not a worker command"),
        }
        assert!(Cli::try_parse_from(["atem", "worker"]).is_err());
        let help = Cli::command().render_help().to_string();
        assert!(!help.contains("worker"), "{help}");
    }

    #[test]
    fn cred_commands_parse() {
        for (arg, expected) in [("unlock", "Unlock"), ("lock", "Lock")] {
            let cli = Cli::try_parse_from(["atem", "cred", arg]).unwrap();
            match cli.command {
                Some(Commands::Cred { command }) => assert_eq!(format!("{command:?}"), expected),
                _ => panic!("expected atem cred {arg}"),
            }
        }
    }

    #[test]
    fn cli_unpair() {
        let cli = Cli::try_parse_from(["atem", "unpair"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Unpair { yes: false })));
    }

    #[test]
    fn cli_login_and_logout_still_parse() {
        let cli = Cli::try_parse_from(["atem", "login"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Login)));
        let cli = Cli::try_parse_from(["atem", "logout"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Logout)));
    }

    // ── vault command ────────────────────────────────────────────────────

    #[test]
    fn cli_vault_new_parses() {
        let cli = Cli::try_parse_from(["atem", "vault", "new", "--summary", "ctx"]).unwrap();
        match cli.command {
            Some(Commands::Vault { command: VaultCommands::New { summary } }) => {
                assert_eq!(summary, "ctx");
            }
            _ => panic!("expected vault new"),
        }
    }

    #[test]
    fn cli_vault_write_with_entry_id_parses() {
        let cli = Cli::try_parse_from([
            "atem", "vault", "write", "--vault-id", "v-1", "--entry-id", "3", "--text", "edit",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Vault {
                command: VaultCommands::Write { vault_id, entry_id, text },
            }) => {
                assert_eq!(vault_id, "v-1");
                assert_eq!(entry_id, Some(3));
                assert_eq!(text, "edit");
            }
            _ => panic!("expected vault write"),
        }
    }

    #[test]
    fn cli_vault_read_history_flag_parses() {
        let cli = Cli::try_parse_from([
            "atem", "vault", "read", "--vault-id", "v-1", "--history",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Vault { command: VaultCommands::Read { vault_id, history, .. } }) => {
                assert_eq!(vault_id, "v-1");
                assert!(history);
            }
            _ => panic!("expected vault read"),
        }
    }

    #[test]
    fn cli_vault_read_since_and_format_parse() {
        let cli = Cli::try_parse_from([
            "atem", "vault", "read", "--vault-id", "v-1", "--since", "5", "--format", "plain",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Vault { command: VaultCommands::Read { since, format, .. } }) => {
                assert_eq!(since, Some(5));
                assert_eq!(format, "plain");
            }
            _ => panic!("expected vault read"),
        }
        // Default format when omitted.
        let cli = Cli::try_parse_from(["atem", "vault", "read", "--vault-id", "v-1"]).unwrap();
        match cli.command {
            Some(Commands::Vault { command: VaultCommands::Read { format, .. } }) => {
                assert_eq!(format, "human");
            }
            _ => panic!("expected vault read"),
        }
    }

    // ── status, pair, pair verify, cred unlock (offline decisions) ───────

    #[test]
    fn cli_status_and_pair_verify_parse() {
        let cli = Cli::try_parse_from(["atem", "status"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Status)));
        let cli = Cli::try_parse_from(["atem", "pair", "verify"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Pair { save: false, command: Some(PairCommands::Verify) })
        ));
        let cli = Cli::try_parse_from(["atem", "pair"]).unwrap();
        assert!(matches!(cli.command, Some(Commands::Pair { save: false, command: None })));
    }

    /// A local listener every Astation URL of the profile points at: a test
    /// fails if anything connects to it (`assert_never_dialed`).
    fn trap(src: &mut crate::profile::Sources) -> std::net::TcpListener {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let port = listener.local_addr().unwrap().port();
        src.config.astation_ws = Some(format!("ws://127.0.0.1:{port}/ws"));
        src.config.astation_relay_url = Some(format!("http://127.0.0.1:{port}"));
        listener
    }

    fn assert_never_dialed(listener: &std::net::TcpListener) {
        match listener.accept() {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Ok(_) => panic!("atem connected to Astation"),
            Err(error) => panic!("listener failed: {error}"),
        }
    }

    /// Paired and bound with astation-1 (generation 1).
    fn paired_profile(dir: &std::path::Path) {
        crate::pairing::tests::bound_profile(dir, "astation-1");
    }

    /// cred/state.json: verified with astation-1, revoked by it when `revoked`.
    fn trust_file(dir: &std::path::Path, revoked: bool) {
        let pin = crate::memory::trust::AstationTrust {
            device_id: "device".into(),
            data_account: "account".into(),
            sign_gen: 1,
            astation_sign_pub: "s".into(),
            astation_enc_pub: "e".into(),
            recovery_sign_pub: "r".into(),
            device_pub: "d".into(),
            device_sign_pub: "ds".into(),
            unlock_auth_pub: "u".into(),
            safety_code: "MN3H-A74N-FJE4".into(),
            transcript: String::new(),
            epoch_floor: 0,
            account_state: None,
            account_epoch: 0,
        };
        let mut store = serde_json::json!({
            "version": 1,
            "home_astation": "astation-1",
            "astations": {"astation-1": pin},
        });
        if revoked {
            store["revoked"] = serde_json::json!({"astation_id": "astation-1", "at": 1_700_000_000u64});
        }
        crate::paths::write_test_file(&crate::paths::CredPaths::in_dir(dir).trust, store.to_string());
        crate::paths::write_test_file(&crate::paths::CredPaths::in_dir(dir).device_keys_sealed, b"{}");
    }

    use crate::status::tests::snapshot as files;

    #[tokio::test]
    async fn pair_on_a_paired_profile_changes_nothing_and_never_connects() {
        let dir = tempfile::tempdir().unwrap();
        paired_profile(dir.path());
        let mut src = crate::profile::Sources::in_dir(dir.path());
        let listener = trap(&mut src);
        let before = files(dir.path());
        // The runtime isn't asked either: the status is local.
        let never = |_| async { panic!("asked the runtime to pair") };
        run_pair_with(&src, false, never).await.unwrap();
        assert_never_dialed(&listener);
        assert_eq!(files(dir.path()), before);
        // Also while verification is incomplete or after a revocation.
        trust_file(dir.path(), true);
        let before = files(dir.path());
        run_pair_with(&src, true, never).await.unwrap();
        assert_never_dialed(&listener);
        assert_eq!(files(dir.path()), before);
    }

    #[tokio::test]
    async fn pair_verify_without_a_pairing_says_to_pair() {
        let dir = tempfile::tempdir().unwrap();
        let mut src = crate::profile::Sources::in_dir(dir.path());
        let listener = trap(&mut src);
        let never = || async { panic!("asked the runtime to verify") };
        let error = run_pair_verify_with(&src, never).await.unwrap_err();
        assert_eq!(error.to_string(), "Not paired. Run atem pair first.");
        assert_never_dialed(&listener);
    }

    #[tokio::test]
    async fn pair_verify_when_verified_does_nothing_offline() {
        let dir = tempfile::tempdir().unwrap();
        paired_profile(dir.path());
        trust_file(dir.path(), false);
        let mut src = crate::profile::Sources::in_dir(dir.path());
        let listener = trap(&mut src);
        let before = files(dir.path());
        let never = || async { panic!("asked the runtime to verify") };
        run_pair_verify_with(&src, never).await.unwrap();
        assert_never_dialed(&listener);
        assert_eq!(files(dir.path()), before);
    }

    #[tokio::test]
    async fn pair_verify_on_a_revoked_device_moves_nothing() {
        let dir = tempfile::tempdir().unwrap();
        paired_profile(dir.path());
        trust_file(dir.path(), true);
        let mut src = crate::profile::Sources::in_dir(dir.path());
        let listener = trap(&mut src);
        let before = files(dir.path());
        let never = || async { panic!("asked the runtime to verify") };
        let error = run_pair_verify_with(&src, never).await.unwrap_err();
        assert_eq!(
            error.to_string(),
            "This device was revoked by Astation astation-1. Run atem unpair, then atem pair, to set it up again."
        );
        assert_never_dialed(&listener);
        assert_eq!(files(dir.path()), before);
    }

    #[tokio::test]
    async fn cred_unlock_on_an_unverified_device_says_to_verify_and_never_connects() {
        let dir = tempfile::tempdir().unwrap();
        paired_profile(dir.path());
        let mut src = crate::profile::Sources::in_dir(dir.path());
        let listener = trap(&mut src);
        let error = crate::memory::unlock::unlock_command(&src)
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "This device isn't verified. Run atem pair verify first.");
        assert_never_dialed(&listener);
    }

    #[test]
    fn unpair_removes_the_pairing_but_keeps_the_login() {
        let dir = tempfile::tempdir().unwrap();
        paired_profile(dir.path());
        let src = crate::profile::Sources::in_dir(dir.path());
        let login = crate::records::Login::from_sso(
            "https://sso2.agora.io",
            Some("me".into()),
            crate::records::Tokens {
                access_token: "a".into(),
                refresh_token: "r".into(),
                expires_at: crate::credentials::now_secs() + 3600,
            },
        );
        login.save(&src.paths.login).unwrap();
        assert!(crate::status::profile_paired(&src));
        assert!(unpair_profile(&src, None).unwrap().is_empty());
        assert_eq!(crate::status::pairing(&src), None);
        assert!(!crate::status::profile_paired(&src));
        assert_eq!(crate::records::Login::load(&src.paths.login).unwrap(), Some(login));
    }

    #[test]
    fn unpair_sets_revoked_keys_aside_so_pair_starts_with_new_ones() {
        let dir = tempfile::tempdir().unwrap();
        paired_profile(dir.path());
        trust_file(dir.path(), true);
        let src = crate::profile::Sources::in_dir(dir.path());
        let notices = unpair_profile(&src, None).unwrap();
        assert_eq!(notices.len(), 1, "{notices:?}");
        assert!(notices[0].contains("old keys were moved aside"), "{notices:?}");
        assert!(!crate::paths::CredPaths::in_dir(dir.path()).device_keys_sealed.exists());
        let trust = crate::memory::trust::TrustStore::load_from(&src.paths.cred.trust).unwrap();
        assert!(trust.revoked().is_none());
        assert!(trust.verified("astation-1").is_none());
    }

    #[test]
    fn unpair_says_when_a_revocation_stays_recorded() {
        let dir = tempfile::tempdir().unwrap();
        paired_profile(dir.path());
        trust_file(dir.path(), false);
        let src = crate::profile::Sources::in_dir(dir.path());
        crate::memory::trust::TrustStore::update(&src.paths.cred.trust, |trust| {
            trust.record_revoked("astation-9", 1_700_000_000);
            Ok(())
        })
        .unwrap();
        let notices = unpair_profile(&src, None).unwrap();
        assert_eq!(notices.len(), 1, "{notices:?}");
        assert!(notices[0].contains("Astation astation-9's revocation of this device is still recorded"), "{notices:?}");
        assert!(crate::paths::CredPaths::in_dir(dir.path()).device_keys_sealed.exists());
        assert_eq!(crate::status::pairing(&src), None);
    }

    #[test]
    fn unpair_still_unpairs_when_the_keys_cant_be_set_aside() {
        let dir = tempfile::tempdir().unwrap();
        paired_profile(dir.path());
        crate::paths::write_test_file(&crate::paths::CredPaths::in_dir(dir.path()).trust, b"not json");
        let src = crate::profile::Sources::in_dir(dir.path());
        let notices = unpair_profile(&src, None).unwrap();
        assert_eq!(notices.len(), 1, "{notices:?}");
        assert!(notices[0].starts_with("Couldn't set the revoked keys aside:"), "{notices:?}");
        assert_eq!(crate::status::pairing(&src), None);
    }

    #[test]
    fn unpair_commits_the_next_generation_before_removing_anything() {
        let dir = tempfile::tempdir().unwrap();
        let old = crate::pairing::tests::bound_profile(dir.path(), "astation-1");
        let src = crate::profile::Sources::in_dir(dir.path());
        // Removing the record fails (a directory is in its place): the
        // unpair is interrupted after its commit.
        let record = &src.paths.pairing.record;
        std::fs::remove_file(record).unwrap();
        std::fs::create_dir_all(record.join("occupied")).unwrap();
        assert!(unpair_profile(&src, None).is_err());
        let trust_gen = std::fs::read_to_string(&src.paths.pairing.trust_gen).unwrap();
        assert_eq!(trust_gen.trim(), "2");
        assert!(old.check().is_err(), "the old binding is invalidated");
        // Retried: the next generation again, never a repeat.
        std::fs::remove_dir_all(record).unwrap();
        unpair_profile(&src, None).unwrap();
        assert_eq!(crate::pairing::load(&src).unwrap().host_trust_gen, 3);
        assert_eq!(crate::status::pairing(&src), None);
    }

    #[test]
    fn unpair_keeps_keys_trust_and_memory_data() {
        let dir = tempfile::tempdir().unwrap();
        paired_profile(dir.path());
        trust_file(dir.path(), false);
        std::fs::write(dir.path().join("knowledge.db"), b"memories").unwrap();
        crate::paths::write_test_file(&crate::paths::CredPaths::in_dir(dir.path()).project_names, b"{}");
        let src = crate::profile::Sources::in_dir(dir.path());
        let cred = crate::paths::CredPaths::in_dir(dir.path());
        let kept = [cred.trust, cred.device_keys_sealed, dir.path().join("knowledge.db"), cred.project_names]
            .map(|path| { let contents = std::fs::read(&path).unwrap(); (path, contents) });
        assert!(unpair_profile(&src, None).unwrap().is_empty());
        for (path, contents) in kept {
            assert_eq!(std::fs::read(&path).unwrap(), contents, "{}", path.display());
        }
        // The pairing was generation 1.
        assert_eq!(crate::pairing::load(&src).unwrap().host_trust_gen, 2);
    }

    #[test]
    fn cred_status_is_gone() {
        assert!(Cli::try_parse_from(["atem", "cred", "status"]).is_err());
    }
}

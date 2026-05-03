//! atem serv convo — ConvoAI agent test server.
//!
//! Runs an HTTPS server that serves a browser UI for Agora Conversational AI
//! v2, plus a small API for starting/stopping agents against api.agora.io.
//! In --background mode, the HTTPS server is not started; the agent runs
//! headless until the process is killed.

use anyhow::Result;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;

use crate::convo_config::{CliOverrides, ConvoConfig, ResolvedConfig};

/// Agora Conversational AI v2 REST base URL. Overridable via `ATEM_CONVOAI_API_URL`
/// for integration tests that point at a local mock.
fn convoai_base_url() -> String {
    std::env::var("ATEM_CONVOAI_API_URL")
        .unwrap_or_else(|_| "https://api.agora.io".to_string())
}

/// Build a ConvoAI REST URL. `hipaa` switches the path prefix from
/// `/api/conversational-ai-agent/...` to `/hipaa/api/conversational-ai-agent/...`.
/// `suffix` is everything after the prefix (e.g. `v2/projects/<app_id>/join`).
fn convoai_url(hipaa: bool, suffix: &str) -> String {
    let prefix = if hipaa { "hipaa/api" } else { "api" };
    format!("{}/{}/conversational-ai-agent/{}", convoai_base_url(), prefix, suffix)
}

/// Generate a unique agent name for this session.
/// Build the session name sent as `name` in /join.
/// Format: `atem-agent-<app_id[..12]>-<unix_ts>-<rand4>`
/// The `agent` prefix keeps this visually distinct from the auto-
/// generated channel (`atem-convo-...`); they would otherwise share
/// the same shape and be hard to tell apart in logs.
fn gen_agent_name(app_id: &str) -> String {
    use rand::RngCore;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let rand = rand::thread_rng().next_u32();
    let prefix: String = app_id.chars().take(12).collect();
    format!("atem-agent-{prefix}-{ts}-{:04x}", rand & 0xffff)
}

/// Generate a random RTC uid (as a short decimal string) for the
/// avatar's video stream. Range [10000, 99999] — 5 digits, matching
/// the upstream demo's `avatar_rtc_uid` shape (e.g. "33830"). Short
/// enough to be readable in logs, large enough to avoid common
/// collisions with the human's uid (typically small) or the agent's
/// uid (typically "1001").
fn gen_avatar_uid() -> String {
    use rand::RngCore;
    let n = (rand::thread_rng().next_u32() % 90000) + 10000;
    n.to_string()
}

/// Mint an RTC token for the avatar's video uid on the SAME channel
/// the voice agent is running in. The avatar needs to publish into
/// the user's channel for the browser to receive the remote video —
/// putting it in a separate channel means the video never reaches us.
///
/// Credential resolution:
///   1. User pre-supplied `agora_token` in [agent.avatar.params] →
///      return (None, None); build_join_payload emits the user's
///      token + whatever `agora_channel` they set verbatim.
///   2. [agent.avatar.params] has agora_appid + agora_app_cert → mint
///      with those (avatar lives in a different Agora project).
///   3. Fall back to the active project's appid + cert (avatar shares
///      the voice channel in the main project — the typical case).
///
/// Returns (Some(channel), Some(token)) where `channel` is the voice
/// channel itself, or (None, None) when no cert is available.
fn mint_avatar_channel_and_token(
    convo: &crate::convo_config::ConvoConfig,
    voice_channel: &str,
    fallback_app_id: &str,
    fallback_app_cert: &str,
    avatar_uid: &str,
) -> (Option<String>, Option<String>) {
    if convo.avatar_has_preset_token() {
        return (None, None);
    }
    let (appid, cert) = convo
        .avatar_mint_credentials()
        .unwrap_or_else(|| (fallback_app_id.to_string(), fallback_app_cert.to_string()));
    if cert.is_empty() {
        return (None, None);
    }
    // Reuse the voice channel so avatar video lands in the browser's
    // already-joined channel.
    let channel = voice_channel.to_string();
    // 1 h expiry — avatar is torn down with /leave when the user stops.
    let token = crate::token::build_token_rtc(
        &appid,
        &cert,
        &channel,
        crate::token::RtcAccount::parse(avatar_uid),
        crate::token::Role::Publisher,
        3600,
        0,
    )
    .ok()
    .filter(|s| !s.is_empty());
    match token {
        Some(t) => (Some(channel), Some(t)),
        None => (None, None),
    }
}

pub struct ServeConvoConfig {
    pub channel:       Option<String>,
    pub rtc_user_id:   Option<String>,
    pub agent_user_id: Option<String>,
    pub config_path:   Option<PathBuf>,
    pub port:          u16,
    pub no_browser:    bool,
    pub background:    bool,
    pub _daemon:       bool,
    /// Attach mode — page hides "Start Agent". Used by
    /// `atem serv attach <id>` so the user can join a channel that
    /// already has a daemon-owned agent in it.
    pub attach:        bool,
}

/// Process-local state. One agent at a time.
#[derive(Default, Debug, Clone)]
pub struct AgentState {
    pub running:    bool,
    pub agent_id:   Option<String>,
    pub name:       Option<String>,
    pub started_at: Option<u64>,
    /// Whether the active agent was started in HIPAA mode. Controls
    /// which URL `/leave` and `/stop` use — must match `/start`'s URL.
    pub hipaa:      bool,
}

/// One entry in the ConvoAI REST history log. Captures exactly what
/// atem sent to / received from `api.agora.io` for this process's
/// lifetime. Bounded capacity (oldest evicted) so it can't grow unbounded.
#[derive(Clone, serde::Serialize)]
pub struct HistoryEntry {
    /// Unix epoch milliseconds. Milliseconds give enough precision to
    /// tell request and response apart when they're close together.
    pub ts_ms:    u64,
    /// `"request"` or `"response"`.
    pub kind:     String,
    /// HTTP method (request entries only).
    pub method:   Option<String>,
    pub url:      String,
    /// HTTP status (response entries only).
    pub status:   Option<u16>,
    /// Raw body. JSON-shaped where applicable, otherwise the text.
    pub body:     String,
}

const HISTORY_CAPACITY: usize = 200;

/// Append to the history log, evicting oldest entries past CAPACITY.
async fn history_push(
    log: &Arc<Mutex<std::collections::VecDeque<HistoryEntry>>>,
    entry: HistoryEntry,
) {
    let mut g = log.lock().await;
    if g.len() >= HISTORY_CAPACITY {
        g.pop_front();
    }
    g.push_back(entry);
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

pub async fn run_server(cfg: ServeConvoConfig) -> Result<()> {
    let toml_path = cfg.config_path.clone().unwrap_or_else(default_config_path);
    let convo = if toml_path.exists() {
        ConvoConfig::from_file(&toml_path)?
    } else {
        anyhow::bail!(
            "No config at {}. Pass --config or create one (wizard coming soon).",
            toml_path.display()
        )
    };
    // Get app_id + app_certificate from active project.
    let app_id   = crate::config::ProjectCache::resolve_app_id(None)?;
    let app_cert = crate::config::ProjectCache::resolve_app_certificate(None)?;

    // Auto-generate channel when neither CLI nor TOML provides one.
    // User-provided channels may use `{appid}`/`{ts}` placeholders so the
    // same template can be reused across many for-loop invocations
    // without needing to compute prefix/timestamp in the shell.
    let cli_channel = cfg.channel.clone()
        .or_else(|| convo.channel.clone())
        .map(|s| crate::web_server::net::expand_channel_template(&s, &app_id))
        .unwrap_or_else(|| crate::web_server::net::gen_channel(&app_id, "convo"));

    let resolved = convo.resolve(&CliOverrides {
        channel:       Some(cli_channel),
        rtc_user_id:   cfg.rtc_user_id.clone(),
        agent_user_id: cfg.agent_user_id.clone(),
    })?;

    // ── Background mode: re-exec as detached daemon ─────────────────────
    // Parent prints info, spawns a child with --_serv-daemon, registers
    // the child's PID, exits. Child runs run_background which holds the
    // agent and posts /leave on SIGTERM.
    if cfg.background && !cfg._daemon {
        let exe = std::env::current_exe()?;
        let log_dir = crate::rtc_test_server::servers_dir();
        std::fs::create_dir_all(&log_dir)?;
        // For convo, the channel name is unique per agent (auto-gen has
        // ts+rand4, user-provided is deliberate). Use it as the registry
        // id directly — `kind="convo"` already distinguishes it from rtc
        // entries that share the prefixed-with-port `server_id` shape.
        let sid = resolved.channel.clone();
        let log_path = log_dir.join(format!("{}.log", sid));
        let log_file = std::fs::File::create(&log_path)?;

        let mut daemon_args: Vec<String> = vec![
            "serv".into(), "convo".into(),
            "--channel".into(), resolved.channel.clone(),
            "--rtc-user-id".into(), resolved.rtc_user_id.clone(),
            "--agent-user-id".into(), resolved.agent_user_id.clone(),
        ];
        if let Some(p) = &cfg.config_path {
            daemon_args.push("--config".into());
            daemon_args.push(p.display().to_string());
        }
        daemon_args.push("--background".into());
        daemon_args.push("--no-browser".into());
        // Hidden flag — tells the spawned process it's the daemon.
        daemon_args.push("--serv-daemon".into());

        let child = std::process::Command::new(exe)
            .args(&daemon_args)
            .stdin(std::process::Stdio::null())
            .stdout(log_file.try_clone()?)
            .stderr(log_file)
            .spawn()?;

        let entry = crate::rtc_test_server::ServerEntry {
            id: sid.clone(),
            pid: child.id(),
            kind: "convo".to_string(),
            port: 0,
            channel: resolved.channel.clone(),
            local_url: String::new(),
            network_url: String::new(),
            started_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            last_status: None,
            last_checked_at: None,
        };
        crate::rtc_test_server::register_server(&entry)?;

        println!("atem serv convo");
        println!("  config:    {}", toml_path.display());
        println!("  channel:   {}", resolved.channel);
        println!("  rtc uid:   {}", resolved.rtc_user_id);
        println!("  agent uid: {}", resolved.agent_user_id);
        println!(
            "  avatar:    {}",
            if resolved.avatar_configured { "configured" } else { "not configured" }
        );
        println!("  ID:        {}", sid);
        println!("  PID:       {}", child.id());
        println!("  Log:       {}", log_path.display());
        println!();
        println!("Use `atem serv list` to see running agents.");
        println!("Use `atem serv kill {}` (or `killall`) to /leave + stop.", sid);
        return Ok(());
    }

    // ── Daemon mode: this IS the spawned child ──────────────────────────
    if cfg._daemon {
        println!("atem serv convo (daemon)");
        println!("  config:    {}", toml_path.display());
        println!("  channel:   {}", resolved.channel);
        println!("  rtc uid:   {}", resolved.rtc_user_id);
        println!("  agent uid: {}", resolved.agent_user_id);
        println!(
            "  avatar:    {}",
            if resolved.avatar_configured { "configured" } else { "not configured" }
        );
        return run_background(&app_id, &app_cert, &resolved, &convo).await;
    }

    // Bind and set up TLS. Bind on 0.0.0.0 so the page is reachable from
    // phones/other devices on the LAN — same pattern as `serv rtc`. The
    // self-signed cert covers both loopback and the detected LAN IP
    // (via sslip.io) so browsers on either hostname trust it.
    let lan_ip = crate::web_server::net::get_lan_ip();
    let sslip  = crate::web_server::net::sslip_host(&lan_ip);
    let extra_hostnames = crate::config::AtemConfig::load()
        .map(|c| c.extra_hostnames())
        .unwrap_or_default();
    let (certs, key) =
        crate::web_server::cert::generate_self_signed_cert(&lan_ip, &extra_hostnames)?;

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let bind_addr = std::net::SocketAddr::from(([0, 0, 0, 0], cfg.port));
    let listener = TcpListener::bind(bind_addr).await?;
    let bound_port = listener.local_addr()?.port();

    let local_url   = format!("https://localhost:{}/", bound_port);
    let network_url = format!("https://{}:{}/", sslip, bound_port);
    let custom_urls: Vec<String> = extra_hostnames
        .iter()
        .map(|h| format!("https://{}:{}/", h.trim(), bound_port))
        .collect();

    let project_name = crate::config::ProjectCache::name_for_app_id(&app_id);

    println!("Convo AI Engine running:");
    println!("  Local:   {}", local_url);
    println!("  Network: {}", network_url);
    for u in &custom_urls {
        println!("  Custom:  {}", u);
    }
    println!();
    println!(
        "  App ID:  {}...{}",
        &app_id[..4.min(app_id.len())],
        if app_id.len() > 8 { &app_id[app_id.len() - 4..] } else { "" }
    );
    if let Some(ref name) = project_name {
        println!("  Project: {}", name);
    }
    println!("  Channel: {}", resolved.channel);
    println!("  Config:  {}", toml_path.display());
    println!("  RTC UID: {}", resolved.rtc_user_id);
    println!("  Agent:   {} (avatar {})",
             resolved.agent_user_id,
             if resolved.avatar_configured { "configured" } else { "off" });
    println!();
    println!("Press Ctrl+C to stop.");
    println!();

    if !cfg.no_browser {
        let _ = crate::web_server::browser::open_browser(&local_url);
    }

    let state: Arc<Mutex<AgentState>> = Arc::new(Mutex::new(AgentState::default()));
    let history: Arc<Mutex<std::collections::VecDeque<HistoryEntry>>> =
        Arc::new(Mutex::new(std::collections::VecDeque::new()));
    let app_id    = Arc::new(app_id);
    let app_cert  = Arc::new(app_cert);
    let resolved  = Arc::new(resolved);
    let convo_cfg = Arc::new(convo);

    let attach_mode = cfg.attach;
    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor  = acceptor.clone();
        let app_id    = app_id.clone();
        let app_cert  = app_cert.clone();
        let resolved  = resolved.clone();
        let convo_cfg = convo_cfg.clone();
        let state     = state.clone();
        let history   = history.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(_) => return,
            };
            let _ = handle_connection(tls, &app_id, &app_cert, &resolved, &convo_cfg, state, history, attach_mode).await;
        });
    }
}

fn default_config_path() -> PathBuf {
    crate::config::AtemConfig::config_dir().join("convo.toml")
}

/// Headless mode: no HTTPS server, no browser, no local RTC. atem just
/// POSTs /join to the ConvoAI REST API, prints the agent id, and waits
/// for SIGINT/SIGTERM to POST /leave. Useful when an external device
/// (phone, ConvoAI-capable hardware) joins the channel on its own and
/// atem's only role is to keep the agent alive on the other side.
/// Walk a JSON value recursively and mask any field whose key suggests
/// it carries a secret (contains "key", "token", "secret", "cert",
/// "password", or "credential"). The value is replaced with a short
/// "***<N chars>" string so the operator can still tell whether a
/// field was set without exposing its contents in the log file.
fn mask_secrets(v: &mut serde_json::Value) {
    fn looks_secret(name: &str) -> bool {
        let n = name.to_ascii_lowercase();
        n.contains("key")
            || n.contains("token")
            || n.contains("secret")
            || n.contains("cert")
            || n.contains("password")
            || n.contains("credential")
    }
    match v {
        serde_json::Value::Object(m) => {
            for (k, val) in m.iter_mut() {
                if looks_secret(k) {
                    let len = match val {
                        serde_json::Value::String(s) => s.len(),
                        _ => 0,
                    };
                    *val = serde_json::Value::String(format!("***<{} chars>", len));
                } else {
                    mask_secrets(val);
                }
            }
        }
        serde_json::Value::Array(a) => {
            for x in a.iter_mut() { mask_secrets(x); }
        }
        _ => {}
    }
}

/// Spawn a tokio task that polls Agora's GET /agents/{id} every 60s
/// and writes the result back into the daemon's registry entry. Each
/// successful poll updates `last_status` + `last_checked_at` so
/// `atem serv list` can show STATUS without making any network calls.
/// On error, status becomes "ERR" so the operator notices.
fn spawn_status_poller(
    channel: String,
    app_id: String,
    agent_id: String,
    agent_token: String,
    hipaa: bool,
) {
    tokio::spawn(async move {
        let url = convoai_url(hipaa, &format!("v2/projects/{}/agents/{}", app_id, agent_id));
        let client = reqwest::Client::new();
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let status = match client
                .get(&url)
                .header("Authorization", format!("agora token={}", agent_token))
                .send()
                .await
            {
                Ok(r) if r.status().is_success() => {
                    r.json::<serde_json::Value>().await
                        .ok()
                        .and_then(|v| v["status"].as_str().map(str::to_string))
                        .unwrap_or_else(|| "?".into())
                }
                Ok(r) => format!("HTTP_{}", r.status().as_u16()),
                Err(_) => "ERR".into(),
            };
            // Read-modify-write the registry JSON. We're the only writer
            // for this id so there's no contention.
            let path = crate::rtc_test_server::servers_dir().join(format!("{}.json", channel));
            if let Ok(data) = std::fs::read_to_string(&path) {
                if let Ok(mut entry) = serde_json::from_str::<crate::rtc_test_server::ServerEntry>(&data) {
                    entry.last_status = Some(status);
                    entry.last_checked_at = Some(
                        std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .map(|d| d.as_secs())
                            .unwrap_or(0)
                    );
                    if let Ok(json) = serde_json::to_string_pretty(&entry) {
                        let _ = std::fs::write(&path, json);
                    }
                }
            }
        }
    });
}

async fn run_background(
    app_id:   &str,
    app_cert: &str,
    resolved: &ResolvedConfig,
    convo:    &ConvoConfig,
) -> Result<()> {
    println!("  mode:      background (no HTTPS server)");

    let name = gen_agent_name(app_id);
    // Token expiry: at least 2h, or 2× idle_timeout — whichever is longer.
    let expire = resolved
        .idle_timeout_secs
        .unwrap_or(3600)
        .max(3600)
        .saturating_mul(2);

    let agent_token = crate::token::build_token_rtc_with_rtm(
        app_id,
        app_cert,
        &resolved.channel,
        crate::token::RtcAccount::parse(&resolved.agent_user_id),
        crate::token::Role::Publisher,
        expire,
        expire,
        Some(resolved.agent_user_id.as_str()),
    )?;

    let avatar_user_id = gen_avatar_uid();
    // Avatar video runs in the vendor's OWN Agora project (akool etc.).
    // Mint a fresh channel + token for the avatar. Uses [agent.avatar
    // .params].agora_appid/agora_app_cert if set, otherwise falls back
    // to the active project's appid+cert.
    let (avatar_channel, avatar_token) =
        mint_avatar_channel_and_token(convo, &resolved.channel, app_id, app_cert, &avatar_user_id);
    let payload = convo.build_join_payload(crate::convo_config::JoinArgs {
        name: &name,
        channel: &resolved.channel,
        token: &agent_token,
        agent_rtc_uid: &resolved.agent_user_id,
        remote_uids: &[resolved.rtc_user_id.clone()],
        include_avatar: resolved.avatar_configured,
        avatar_user_id: &avatar_user_id,
        avatar_channel: avatar_channel.as_deref(),
        avatar_token:   avatar_token.as_deref(),
        // Background mode: no UI, use config-level preset as-is.
        preset: None,
        // Encryption / geofence: read from convo.toml. mode=0 → no
        // encryption block emitted. geofence empty/"GLOBAL" → no fence.
        encryption_mode: if resolved.encryption_mode > 0 { Some(resolved.encryption_mode) } else { None },
        encryption_key:  if resolved.encryption_mode > 0 { Some(resolved.encryption_key.as_str()) } else { None },
        encryption_salt: if !resolved.encryption_salt.is_empty() { Some(resolved.encryption_salt.as_str()) } else { None },
        geofence_area:   if !resolved.geofence.is_empty() { Some(resolved.geofence.as_str()) } else { None },
        enable_dump: false,
    });

    // Use HIPAA endpoint when convo.toml says so. Both /join and /leave
    // must use the same prefix or the agent gets stranded on the wrong
    // SD-RTN.
    let url = convoai_url(resolved.hipaa, &format!("v2/projects/{}/join", app_id));
    println!("  /join URL: {}", url);
    // Log the request body with secrets masked. Useful for diagnosing
    // mismatches (encryption_key present? geofence area? avatar shape?).
    {
        let mut masked = payload.clone();
        mask_secrets(&mut masked);
        match serde_json::to_string_pretty(&masked) {
            Ok(s)  => println!("  /join body (masked):\n{}", s),
            Err(_) => println!("  /join body: <serialization failed>"),
        }
    }
    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .header("Authorization", format!("agora token={}", agent_token))
        .header("Content-Type", "application/json")
        .json(&payload)
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("agora /join failed: {} {}", status, body);
    }

    let body: serde_json::Value = resp.json().await?;
    let agent_id = body["agent_id"].as_str().unwrap_or("").to_string();
    println!("  agent_id:  {}", agent_id);
    println!("  name:      {}", name);
    println!("\nAgent running. SIGTERM (atem serv kill) or Ctrl+C to stop.");

    // Spawn a 60s status poller that updates the registry JSON. Lets
    // `atem serv list` show whether each agent is RUNNING/IDLE/STOPPED
    // without each list call having to make a network round-trip.
    spawn_status_poller(
        resolved.channel.clone(),
        app_id.to_string(),
        agent_id.clone(),
        agent_token.clone(),
        resolved.hipaa,
    );

    // Block until SIGINT or SIGTERM. The daemon process is reaped via
    // SIGTERM by `atem serv kill`/`killall`; tokio::signal::ctrl_c only
    // catches SIGINT on Unix, so listen for both.
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate())?;
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    println!("\nStopping agent...");

    // Mint a fresh short-lived token for the /leave call.
    let leave_token = crate::token::build_token_rtc_with_rtm(
        app_id,
        app_cert,
        &resolved.channel,
        crate::token::RtcAccount::parse(&resolved.agent_user_id),
        crate::token::Role::Publisher,
        3600,
        3600,
        Some(resolved.agent_user_id.as_str()),
    )?;
    let leave_url = convoai_url(
        resolved.hipaa,
        &format!("v2/projects/{}/agents/{}/leave", app_id, agent_id),
    );
    println!("/leave URL: {}", leave_url);
    let _ = client
        .post(&leave_url)
        .header("Authorization", format!("agora token={}", leave_token))
        .send()
        .await;

    // Best-effort cleanup of the registry entry so `atem serv list`
    // doesn't show a dead daemon. Id matches what the parent registered
    // (the channel name itself).
    let _ = crate::rtc_test_server::unregister_server(&resolved.channel);

    println!("Stopped.");
    Ok(())
}

async fn handle_connection(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    app_id:     &str,
    app_cert:   &str,
    resolved:   &Arc<ResolvedConfig>,
    convo_cfg:  &Arc<ConvoConfig>,
    state:      Arc<Mutex<AgentState>>,
    history:    Arc<Mutex<std::collections::VecDeque<HistoryEntry>>>,
    attach_mode: bool,
) -> Result<()> {
    use crate::web_server::request::{read_full_http_request, send_response};
    let buf = match read_full_http_request(&mut stream).await {
        Ok(Some(b)) => b,
        _ => return Ok(()),
    };
    let request = String::from_utf8_lossy(&buf);
    let first = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first.split_whitespace().collect();
    if parts.len() < 2 {
        send_response(&mut stream, 400, "text/plain", b"Bad Request").await?;
        return Ok(());
    }
    let (method, path) = (parts[0], parts[1]);
    match (method, path) {
        ("GET", "/") => {
            let html = build_html_page(app_id, resolved, attach_mode);
            send_response(&mut stream, 200, "text/html; charset=utf-8", html.as_bytes()).await?;
        }
        ("GET", "/favicon.ico") => {
            // No icon yet — return 204 so the browser stops logging 404s.
            send_response(&mut stream, 204, "image/x-icon", b"").await?;
        }
        ("GET", "/vendor/agora-rtm-sdk.js") => {
            const RTM: &str = include_str!("../assets/agora-rtm-sdk.js");
            send_response(&mut stream, 200, "application/javascript; charset=utf-8", RTM.as_bytes()).await?;
        }
        ("GET", "/vendor/conversational-ai-api.js") => {
            const TOOLKIT: &str = include_str!("../assets/convo/conversational-ai-api.js");
            send_response(&mut stream, 200, "application/javascript; charset=utf-8", TOOLKIT.as_bytes()).await?;
        }
        ("POST", "/api/token") => {
            use crate::web_server::{request::extract_body, token_endpoint::handle_token_api};
            let body = extract_body(&request);
            // serv convo always issues RTC+RTM tokens — the ConvoAI toolkit
            // needs RTM for word-by-word transcription.
            handle_token_api(
                &mut stream, &body, app_id, app_cert,
                3600,                                // 1h expiry
                true,                                // with_rtm
                Some(resolved.agent_user_id.as_str()),
            ).await?;
        }
        ("POST", "/api/convo/start") => {
            let body = crate::web_server::request::extract_body(&request);
            let req: serde_json::Value =
                serde_json::from_str(&body).unwrap_or(serde_json::json!({}));
            let include_avatar = req["avatar"].as_bool().unwrap_or(false);
            // Optional preset selected by the browser dropdown. Empty
            // string / missing key falls back to config-level preset.
            let preset_override: Option<String> = req["preset"]
                .as_str()
                .map(|s| s.to_string())
                .filter(|s| !s.is_empty());
            // Optional RTC encryption from the page. Browser sends mode (1..=8),
            // key, and salt (base64 32 bytes for gcm2 modes). Empty key →
            // unencrypted (no `properties.rtc` block emitted).
            let enc_key: Option<String> = req["encryption_key"]
                .as_str()
                .map(|s| s.to_string())
                .filter(|s| !s.is_empty());
            let enc_mode: Option<u8> = req["encryption_mode"]
                .as_u64()
                .and_then(|n| u8::try_from(n).ok());
            let enc_salt: Option<String> = req["encryption_salt"]
                .as_str()
                .map(|s| s.to_string())
                .filter(|s| !s.is_empty());
            // Geofence — restrict media routing region. "GLOBAL" / empty
            // → no `properties.geofence` emitted (Agora's default).
            let geo_area: Option<String> = req["geofence_area"]
                .as_str()
                .map(|s| s.to_string())
                .filter(|s| !s.is_empty() && !s.eq_ignore_ascii_case("GLOBAL"));
            // HIPAA mode — routes the call through Agora's US-HIPAA
            // endpoint. Browser also enforces NORTH_AMERICA + AES_256_GCM2
            // before sending; we trust those flags arrived correctly.
            let hipaa = req["hipaa"].as_bool().unwrap_or(false);
            // Audio dump — opt-in debug knob, surfaces as
            // properties.parameters.enable_dump=true. Server-side capture;
            // retrieve via Agora support.
            let enable_dump = req["enable_dump"].as_bool().unwrap_or(false);

            // Only one agent at a time per process.
            {
                let st = state.lock().await;
                if st.running {
                    let err = serde_json::json!({
                        "error": "agent already running",
                        "agent_id": st.agent_id,
                    });
                    crate::web_server::request::send_response(
                        &mut stream, 409, "application/json", err.to_string().as_bytes()
                    ).await?;
                    return Ok(());
                }
            }

            // Mint an RTC+RTM token for the agent's uid, same channel.
            let expire = resolved.idle_timeout_secs
                .unwrap_or(3600)
                .max(3600)
                .saturating_mul(2);
            let agent_token = crate::token::build_token_rtc_with_rtm(
                app_id,
                app_cert,
                &resolved.channel,
                crate::token::RtcAccount::parse(&resolved.agent_user_id),
                crate::token::Role::Publisher,
                expire,
                expire,
                Some(resolved.agent_user_id.as_str()),
            )?;

            let name = gen_agent_name(app_id);
            let avatar_user_id = gen_avatar_uid();
            let (avatar_channel, avatar_token) =
                mint_avatar_channel_and_token(convo_cfg, &resolved.channel, app_id, app_cert, &avatar_user_id);
            let payload = convo_cfg.build_join_payload(crate::convo_config::JoinArgs {
                name: &name,
                channel: &resolved.channel,
                token: &agent_token,
                agent_rtc_uid: &resolved.agent_user_id,
                remote_uids: &[resolved.rtc_user_id.clone()],
                include_avatar,
                avatar_user_id: &avatar_user_id,
                avatar_channel: avatar_channel.as_deref(),
                avatar_token:   avatar_token.as_deref(),
                preset: preset_override.as_deref(),
                encryption_mode: enc_mode,
                encryption_key:  enc_key.as_deref(),
                encryption_salt: enc_salt.as_deref(),
                geofence_area:   geo_area.as_deref(),
                enable_dump,
            });

            let url = convoai_url(hipaa, &format!("v2/projects/{}/join", app_id));
            history_push(&history, HistoryEntry {
                ts_ms: unix_ms(), kind: "request".into(),
                method: Some("POST".into()), url: url.clone(), status: None,
                body: serde_json::to_string_pretty(&payload)
                    .unwrap_or_else(|_| payload.to_string()),
            }).await;
            let client = reqwest::Client::new();
            let resp = client
                .post(&url)
                .header("Authorization", format!("agora token={}", agent_token))
                .header("Content-Type", "application/json")
                .json(&payload)
                .send()
                .await;

            match resp {
                Ok(r) if r.status().is_success() => {
                    let status_u16 = r.status().as_u16();
                    let raw = r.text().await.unwrap_or_default();
                    history_push(&history, HistoryEntry {
                        ts_ms: unix_ms(), kind: "response".into(),
                        method: None, url: url.clone(), status: Some(status_u16),
                        body: raw.clone(),
                    }).await;
                    let body_json: serde_json::Value =
                        serde_json::from_str(&raw).unwrap_or_else(|_| serde_json::json!({}));
                    let agent_id = body_json["agent_id"].as_str().unwrap_or("").to_string();
                    let started = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0);
                    {
                        let mut st = state.lock().await;
                        st.running    = true;
                        st.agent_id   = Some(agent_id.clone());
                        st.name       = Some(name.clone());
                        st.started_at = Some(started);
                        st.hipaa      = hipaa;
                    }
                    let out = serde_json::json!({
                        "agent_id":   agent_id,
                        "name":       name,
                        "started_at": started,
                    });
                    crate::web_server::request::send_response(
                        &mut stream, 200, "application/json", out.to_string().as_bytes()
                    ).await?;
                }
                Ok(r) => {
                    let status = r.status().as_u16();
                    let body = r.text().await.unwrap_or_default();
                    history_push(&history, HistoryEntry {
                        ts_ms: unix_ms(), kind: "response".into(),
                        method: None, url: url.clone(), status: Some(status),
                        body: body.clone(),
                    }).await;
                    let err = serde_json::json!({
                        "error": format!("agora /join failed: {} {}", status, body),
                    });
                    crate::web_server::request::send_response(
                        &mut stream, status, "application/json", err.to_string().as_bytes()
                    ).await?;
                }
                Err(e) => {
                    let err = serde_json::json!({ "error": format!("request failed: {}", e) });
                    crate::web_server::request::send_response(
                        &mut stream, 502, "application/json", err.to_string().as_bytes()
                    ).await?;
                }
            }
        }

        ("POST", "/api/convo/stop") => {
            // Both fields read under one lock — keep them consistent.
            let (agent_id, hipaa) = {
                let st = state.lock().await;
                (st.agent_id.clone(), st.hipaa)
            };
            let agent_id = match agent_id {
                Some(id) => id,
                None => {
                    crate::web_server::request::send_response(
                        &mut stream, 200, "application/json",
                        b"{\"stopped\":true,\"note\":\"no agent\"}"
                    ).await?;
                    return Ok(());
                }
            };

            let token = crate::token::build_token_rtc_with_rtm(
                app_id,
                app_cert,
                &resolved.channel,
                crate::token::RtcAccount::parse(&resolved.agent_user_id),
                crate::token::Role::Publisher,
                3600,
                3600,
                Some(resolved.agent_user_id.as_str()),
            )?;
            // Re-use hipaa from /start so the URL matches the agent's
            // origin endpoint.
            let url = convoai_url(hipaa, &format!("v2/projects/{}/agents/{}/leave", app_id, agent_id));
            history_push(&history, HistoryEntry {
                ts_ms: unix_ms(), kind: "request".into(),
                method: Some("POST".into()), url: url.clone(), status: None,
                body: "".into(),
            }).await;
            let client = reqwest::Client::new();
            let resp = client
                .post(&url)
                .header("Authorization", format!("agora token={}", token))
                .send()
                .await;
            if let Ok(r) = resp {
                let status_u16 = r.status().as_u16();
                let raw = r.text().await.unwrap_or_default();
                history_push(&history, HistoryEntry {
                    ts_ms: unix_ms(), kind: "response".into(),
                    method: None, url: url.clone(), status: Some(status_u16),
                    body: raw,
                }).await;
            }

            {
                let mut st = state.lock().await;
                *st = AgentState::default();
            }
            crate::web_server::request::send_response(
                &mut stream, 200, "application/json", b"{\"stopped\":true}"
            ).await?;
        }

        ("GET", "/api/convo/status") => {
            let st = state.lock().await.clone();
            let body = serde_json::json!({
                "running":           st.running,
                "agent_id":          st.agent_id,
                "name":              st.name,
                "started_at":        st.started_at,
                "avatar_configured": resolved.avatar_configured,
            });
            crate::web_server::request::send_response(
                &mut stream, 200, "application/json", body.to_string().as_bytes()
            ).await?;
        }

        ("GET", "/api/convo/history") => {
            // Process-lifetime log of every request/response atem has made
            // against Agora's ConvoAI REST endpoints. Bounded at
            // HISTORY_CAPACITY entries (oldest evicted). Consumed by the
            // "Show History" button on the page.
            let entries: Vec<HistoryEntry> = history.lock().await.iter().cloned().collect();
            let body = serde_json::json!({ "entries": entries, "capacity": HISTORY_CAPACITY });
            crate::web_server::request::send_response(
                &mut stream, 200, "application/json", body.to_string().as_bytes()
            ).await?;
        }

        _ => {
            send_response(&mut stream, 404, "text/plain", b"Not Found").await?;
        }
    }
    Ok(())
}

/// Build the HTML for the root `/` page.
///
/// 3 blocks: General / RTC / ConvoAI. The visual style mirrors
/// `rtc_test_server::build_html_page` (same CSS, same slogan list, same
/// status-dot classes), but the RTC+RTM wiring and ConvoAI toolkit init
/// live in Task 14. This function only produces the static structure,
/// inline CSS, and the JS constants + input-seeding the page needs to
/// display correctly.
fn build_html_page(app_id: &str, resolved: &ResolvedConfig, attach_mode: bool) -> String {
    let app_id_display = if app_id.len() > 12 {
        format!("{}...{}", &app_id[..6], &app_id[app_id.len() - 4..])
    } else {
        app_id.to_string()
    };
    // "App ID" or "App ID (Project Name)" — project name comes from the
    // project cache when the active app_id matches a known project. The
    // parenthetical is omitted when app_id came from --app-id / env var.
    let app_id_label = match crate::config::ProjectCache::name_for_app_id(app_id) {
        Some(name) => format!("App ID ({})", crate::web_server::html::escape(&name)),
        None => "App ID".to_string(),
    };

    let channel   = resolved.channel.as_str();
    let rtc_uid   = resolved.rtc_user_id.as_str();
    let agent_uid = resolved.agent_user_id.as_str();
    let preset    = resolved.preset.clone().unwrap_or_default();
    let avatar_ok = if resolved.avatar_configured { "true" } else { "false" };
    // JSON-encode the preset list so it embeds safely as a JS array
    // literal regardless of quotes / odd chars in preset names.
    let presets_js = serde_json::to_string(&resolved.presets)
        .unwrap_or_else(|_| "[]".to_string());
    // JSON-encode the avatar summary as a JS object (or null). Only
    // non-secret fields from [agent.avatar] — never `params`.
    let avatar_info_js = match &resolved.avatar_summary {
        Some(s) => serde_json::to_string(&serde_json::json!({
            "vendor":    s.vendor,
            "avatar_id": s.avatar_id,
        })).unwrap_or_else(|_| "null".to_string()),
        None => "null".to_string(),
    };

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>atem serv convo</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #e6edf3; min-height: 100vh; }}
.header {{ background: #161b22; border-bottom: 1px solid #30363d; padding: 12px 20px; display: flex; align-items: center; gap: 12px; }}
.header h1 {{ font-size: 16px; font-weight: 600; }}
.header .app-id {{ font-size: 12px; color: #7d8590; font-family: monospace; }}
.controls {{ background: #161b22; border-bottom: 1px solid #30363d; padding: 12px 20px; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
.controls input {{ background: #0d1117; border: 1px solid #30363d; color: #e6edf3; padding: 6px 10px; border-radius: 6px; font-size: 14px; width: 180px; }}
#channelInput {{ width: 360px; }}
.controls input:focus {{ border-color: #58a6ff; outline: none; }}
.controls label {{ font-size: 12px; color: #7d8590; }}
.btn {{ padding: 6px 14px; border: 1px solid #30363d; border-radius: 6px; font-size: 13px; cursor: pointer; font-weight: 500; transition: 0.15s; }}
.btn-join {{ background: #238636; border-color: #238636; color: #fff; }}
.btn-join:hover {{ background: #2ea043; }}
.btn-leave {{ background: #da3633; border-color: #da3633; color: #fff; }}
.btn-leave:hover {{ background: #f85149; }}
.btn-mute {{ background: #21262d; color: #e6edf3; }}
.btn-mute:hover {{ background: #30363d; }}
.btn-mute.active {{ background: #da3633; border-color: #da3633; }}
.btn-stats {{ background: #1f6feb; border-color: #1f6feb; color: #fff; }}
.btn-stats:hover {{ background: #388bfd; }}
.btn-stats.active {{ background: #0969da; }}
.stats-panel, .history-panel {{ display: none; background: #0d1117; border: 1px solid #30363d; border-radius: 6px; padding: 10px 14px; margin: 8px 16px; font-size: 11px; font-family: monospace; color: #c9d1d9; line-height: 1.5; max-height: 260px; overflow-y: auto; white-space: pre-wrap; }}
.stats-panel.visible, .history-panel.visible {{ display: block; }}
.token-row {{ background: #161b22; border-bottom: 1px solid #30363d; padding: 8px 20px; display: flex; align-items: center; gap: 10px; }}
.token-row label {{ font-size: 12px; color: #7d8590; white-space: nowrap; }}
.token-row textarea {{ background: #0d1117; border: 1px solid #30363d; color: #e6edf3; padding: 6px 10px; border-radius: 6px; font-size: 12px; font-family: monospace; flex: 1; resize: vertical; min-height: 32px; max-height: 120px; line-height: 1.4; }}
.token-row textarea:focus {{ border-color: #58a6ff; outline: none; }}
.token-row .btn {{ flex-shrink: 0; }}
.video-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 12px; padding: 16px; }}
.video-cell {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; position: relative; aspect-ratio: 16/9; }}
.video-cell > div {{ position: absolute; inset: 0; }}
.video-cell video {{ width: 100%; height: 100%; object-fit: cover; }}
.video-label {{ position: absolute; bottom: 8px; left: 8px; background: rgba(0,0,0,0.7); padding: 3px 8px; border-radius: 4px; font-size: 12px; color: #e6edf3; }}
.status-dot {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; vertical-align: middle; }}
.status-dot.disconnected {{ background: #7d8590; }}
.status-dot.connected {{ background: #3fb950; }}
.status-dot.connecting {{ background: #d29922; }}
.status-dot.idle {{ background: #7d8590; }}
.status-dot.transitioning {{ background: #d29922; }}
.copy-btn {{ background: none; border: 1px solid #555; color: #8b949e; padding: 2px 8px; border-radius: 4px; cursor: pointer; font-size: 12px; margin-left: 6px; }}
.copy-btn:hover {{ border-color: #58a6ff; color: #c9d1d9; }}
/* Block sections — General / RTC / ConvoAI */
.block {{ margin: 16px 20px; border: 1px solid #30363d; border-radius: 8px; background: #161b22; overflow: hidden; }}
.block-title {{ padding: 10px 16px; background: #1c2128; border-bottom: 1px solid #30363d; font-size: 14px; font-weight: 600; color: #c9d1d9; }}
.block .controls, .block .token-row {{ border-bottom: 1px solid #30363d; background: transparent; }}
.block .controls:last-child, .block .token-row:last-child {{ border-bottom: none; }}
.app-id-value {{ font-family: monospace; font-size: 13px; color: #c9d1d9; }}
.read-only-value {{ font-family: monospace; font-size: 13px; color: #c9d1d9; padding: 6px 0; }}
.btn:disabled {{ opacity: 0.5; cursor: not-allowed; }}
#slogan {{ font-size: 13px; font-weight: 400; color: #7d8590; }}
/* ConvoAI transcription + events */
.convo-sub-title {{ padding: 8px 16px; background: #1c2128; border-top: 1px solid #30363d; border-bottom: 1px solid #30363d; font-size: 12px; font-weight: 500; color: #7d8590; text-transform: uppercase; letter-spacing: 0.5px; }}
#transcript {{ max-height: 400px; overflow-y: auto; padding: 8px 16px; font-size: 13px; line-height: 1.5; color: #e6edf3; scroll-behavior: smooth; }}
#transcript div {{ padding: 2px 0; }}
#transcript .user  {{ color: #79c0ff; }}
#transcript .agent {{ color: #3fb950; }}
#events {{ max-height: 160px; overflow-y: auto; padding: 8px 16px; font-size: 11px; font-family: monospace; color: #7d8590; }}
#events div {{ padding: 1px 0; }}
#events .info    {{ color: #7d8590; }}
#events .success {{ color: #3fb950; }}
#events .warning {{ color: #d29922; }}
#events .error   {{ color: #f85149; }}
.avatar-row {{ display: flex; align-items: center; gap: 8px; }}
.avatar-row input[type=checkbox]:disabled + label {{ color: #555; cursor: not-allowed; }}
</style>
<script src="https://download.agora.io/sdk/release/AgoraRTC_N-4.23.4.js"></script>
<script src="/vendor/agora-rtm-sdk.js"></script>
<script src="/vendor/conversational-ai-api.js"></script>
</head>
<body>

<div class="header">
  <h1>Welcome to Agora, <span id="slogan">real-time is the only time</span></h1>
</div>

<!-- ── General ─────────────────────────────────────────────────── -->
<section class="block">
  <h2 class="block-title">General</h2>
  <div class="controls">
    <label>{app_id_label}</label>
    <span class="app-id-value">{app_id_display}</span>
    <button class="copy-btn" onclick="copyText('{app_id}')">Copy</button>
  </div>
  <div class="controls">
    <label>Channel</label>
    <input id="channelInput" type="text" value="{channel}" placeholder="channel name">
  </div>
  <div class="token-row">
    <label>Access Token</label>
    <textarea id="tokenInput" rows="1" placeholder="Click Fetch to mint a token"></textarea>
    <button id="fetchBtn" class="btn btn-mute" onclick="fetchToken()">Fetch</button>
    <button class="copy-btn" onclick="copyText(document.getElementById('tokenInput').value)">Copy</button>
  </div>
  <div class="controls">
    <label>Encryption</label>
    <select id="encModeSelect" style="width:200px">
      <option value="0">None</option>
      <option value="8" selected>AES_256_GCM2</option>
      <option value="7">AES_128_GCM2</option>
      <option value="6">AES_256_GCM</option>
      <option value="5">AES_128_GCM</option>
      <option value="3">AES_256_XTS</option>
      <option value="1">AES_128_XTS</option>
      <option value="2">AES_128_ECB</option>
      <option value="4">SM4_128_ECB</option>
    </select>
    <input id="encKeyInput" type="text" placeholder="Encryption key (empty = unencrypted; same key used for local SDK + agent)" style="flex:1">
  </div>
  <div class="token-row" id="encSaltRow">
    <label>Salt</label>
    <textarea id="encSaltInput" rows="1" placeholder="Base64 32-byte salt (auto-generated; same value sent to agent)"></textarea>
    <button class="btn btn-mute" onclick="regenSalt()">Regen</button>
    <button class="copy-btn" onclick="copyText(document.getElementById('encSaltInput').value)">Copy</button>
  </div>
  <div class="controls">
    <label>Geofence</label>
    <select id="geoAreaSelect" style="width:200px">
      <option value="GLOBAL" selected>Global (no fence)</option>
      <option value="NORTH_AMERICA">North America</option>
      <option value="EUROPE">Europe</option>
      <option value="ASIA">Asia</option>
      <option value="JAPAN">Japan</option>
      <option value="INDIA">India</option>
    </select>
  </div>
</section>

<!-- ── RTC ─────────────────────────────────────────────────────── -->
<section class="block">
  <h2 class="block-title"><span class="status-dot disconnected" id="rtcDot"></span>RTC — <span id="rtcState" style="font-weight:400;color:#7d8590">Disconnected</span></h2>
  <div class="controls">
    <label>UID</label>
    <input id="uidInput" type="text" placeholder="auto" value="{rtc_uid}" style="width:100px">
    <button id="joinBtn"    class="btn btn-join"  onclick="doJoin()">Join</button>
    <button id="leaveBtn"   class="btn btn-leave" onclick="doLeave()" style="display:none">Leave</button>
    <button id="muteBtn"    class="btn btn-mute"  onclick="toggleMute()">Mute Mic</button>
    <button id="cameraBtn"  class="btn btn-mute"  onclick="toggleCamera()">Camera Off</button>
    <button id="statsBtn"   class="btn btn-stats" onclick="toggleStats()">Stats</button>
  </div>
  <div id="statsPanel" class="stats-panel"></div>
  <div class="video-grid">
    <!-- Both cells start hidden. #localCell becomes visible when the
         Camera button is ON; #agentCell becomes visible when the agent
         publishes a remote video track (e.g. avatar). -->
    <div class="video-cell" id="localCell" style="display:none">
      <div id="localVideo"></div>
      <span class="video-label">Local</span>
    </div>
    <div class="video-cell" id="agentCell" style="display:none">
      <div id="agentVideo"></div>
      <span class="video-label">Agent (avatar)</span>
    </div>
  </div>
</section>

<!-- ── ConvoAI ─────────────────────────────────────────────────── -->
<section class="block">
  <h2 class="block-title"><span class="status-dot idle" id="agentDot"></span>ConvoAI — <span id="agentState" style="font-weight:400;color:#7d8590">idle</span></h2>
  <div class="controls">
    <label>Agent UID</label>
    <span id="agentUidDisplay" class="read-only-value">—</span>
  </div>
  <div class="controls">
    <label>Presets</label>
    <div id="presetCheckboxes"
         style="display:inline-flex;flex-wrap:wrap;gap:10px 14px;align-items:center;font-size:13px;width:fit-content"></div>
  </div>
  <div class="controls avatar-row">
    <label for="avatarCheckbox">Enable Avatar</label>
    <input type="checkbox" id="avatarCheckbox">
  </div>
  <div class="controls avatar-row">
    <label for="hipaaCheckbox">HIPAA Mode</label>
    <input type="checkbox" id="hipaaCheckbox">
    <span id="hipaaHint" style="font-size:12px;color:#7d8590">
      Routes via /hipaa endpoint, forces NORTH_AMERICA + AES_256_GCM2 with a generated key.
      Contact Agora Support to enable this function for your project first.
    </span>
  </div>
  <div class="controls avatar-row">
    <label for="audioDumpCheckbox">Audio Dump</label>
    <input type="checkbox" id="audioDumpCheckbox">
    <span style="font-size:12px;color:#7d8590">
      Sends `parameters.enable_dump=true` so Agora captures agent-side audio for debugging.
      Retrieve via Agora Support.
    </span>
  </div>
  <div class="controls" id="avatarInfo"
       style="flex-direction:column;align-items:flex-start;gap:4px;padding-left:16px;color:#7d8590;font-family:monospace;font-size:12px">
    <!-- Filled by JS from AVATAR_INFO. Shows non-secret fields from
         [agent.avatar], or a note when the block is absent. -->
  </div>
  <div class="controls">
    <button id="startAgentBtn" class="btn btn-join" onclick="startAgent()">Start Agent</button>
    <button id="stopAgentBtn"  class="btn btn-leave" onclick="stopAgent()"  style="display:none">Stop Agent</button>
    <button id="historyBtn"    class="btn btn-stats" onclick="toggleHistory()">API History</button>
  </div>
  <div id="historyPanel" class="history-panel"></div>
  <div class="convo-sub-title">Live transcription</div>
  <div id="transcript"></div>
  <div class="convo-sub-title">Events</div>
  <div id="events"></div>
</section>

<script>
// Constants populated from the server's ResolvedConfig.
const APP_ID      = "{app_id}";
const CHANNEL     = "{channel}";
const RTC_UID     = "{rtc_uid}";
const AGENT_UID   = "{agent_uid}";
const PRESET      = "{preset}";
const PRESETS     = {presets_js};    // e.g. ["expertise_ai_poc", ...] or []
const AVATAR_OK   = {avatar_ok};     // [agent.avatar] block present in TOML
const AVATAR_INFO = {avatar_info_js};  // {{vendor, avatar_id}} or null

// Defaults from convo.toml. Pre-fill the form fields on load; user
// can still override via the browser controls.
const DEFAULT_HIPAA    = {default_hipaa};
const DEFAULT_GEOFENCE = "{default_geofence}";
const DEFAULT_ENC_MODE = {default_enc_mode};
const DEFAULT_ENC_KEY  = "{default_enc_key}";
const DEFAULT_ENC_SALT = "{default_enc_salt}";
const ATTACH_MODE      = {attach_mode};   // True → daemon owns the agent; UI hides Start/Stop.

// ── Encryption helpers ───────────────────────────────────────────
// Mode IDs match the Agora ConvoAI REST API integer table; the strings
// are what AgoraRTC.setEncryptionConfig expects. The same key+salt is
// sent to /api/convo/start so the agent joins encrypted with matching
// params; otherwise audio comes back as noise / silence.
const ENC_MODE_NAMES = {{
  1: 'aes-128-xts', 2: 'aes-128-ecb', 3: 'aes-256-xts', 4: 'sm4-128-ecb',
  5: 'aes-128-gcm', 6: 'aes-256-gcm', 7: 'aes-128-gcm2', 8: 'aes-256-gcm2',
}};
function randSalt32() {{
  const a = new Uint8Array(32);
  crypto.getRandomValues(a);
  return a;
}}
function saltBase64(arr) {{
  let s = '';
  for (const b of arr) s += String.fromCharCode(b);
  return btoa(s);
}}
function saltFromBase64(b64) {{
  const bin = atob(b64);
  const a = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
  return a;
}}
function regenSalt() {{
  document.getElementById('encSaltInput').value = saltBase64(randSalt32());
}}
// Salt only matters for gcm2 modes (7, 8). Hide the row + clear the
// value for any other mode so the UI shows only what's actually used.
function syncSaltRow() {{
  const id = parseInt(document.getElementById('encModeSelect').value, 10);
  const isGcm2 = id === 7 || id === 8;
  const row = document.getElementById('encSaltRow');
  const input = document.getElementById('encSaltInput');
  if (!row || !input) return;
  if (isGcm2) {{
    row.style.display = '';
    if (!input.value) input.value = saltBase64(randSalt32());
  }} else {{
    row.style.display = 'none';
    input.value = '';
  }}
}}
// Pre-fill HIPAA / geofence / encryption controls from convo.toml
// defaults emitted by the server. User can still override.
function applyTomlDefaults() {{
  if (DEFAULT_HIPAA) document.getElementById('hipaaCheckbox').checked = true;
  if (DEFAULT_GEOFENCE) document.getElementById('geoAreaSelect').value = DEFAULT_GEOFENCE;
  if (DEFAULT_ENC_MODE > 0) {{
    document.getElementById('encModeSelect').value = String(DEFAULT_ENC_MODE);
    document.getElementById('encKeyInput').value   = DEFAULT_ENC_KEY;
    document.getElementById('encSaltInput').value  = DEFAULT_ENC_SALT;
  }} else {{
    // No encryption configured in TOML — leave the page-default mode 8
    // selected but clear any auto-generated salt so the row stays empty
    // until the user picks a key.
    if (!DEFAULT_ENC_KEY) document.getElementById('encKeyInput').value = '';
  }}
}}

// Attach mode: a background daemon already owns the agent on this
// channel. Hide Start/Stop because /api/convo/start would create a
// SECOND agent on the same channel, which Agora rejects.
function applyAttachMode() {{
  if (!ATTACH_MODE) return;
  const startBtn = document.getElementById('startAgentBtn');
  const stopBtn  = document.getElementById('stopAgentBtn');
  if (startBtn) startBtn.style.display = 'none';
  if (stopBtn)  stopBtn.style.display  = 'none';
  setAgentDot('connected', 'attached (daemon owns agent)');
  logEvent('Attach mode: agent is owned by a background daemon. Use `atem serv kill` to /leave.', 'info');
}}
window.addEventListener('DOMContentLoaded', () => {{
  applyTomlDefaults();
  applyAttachMode();
  document.getElementById('encModeSelect').addEventListener('change', syncSaltRow);
  syncSaltRow();
  document.getElementById('hipaaCheckbox').addEventListener('change', syncHipaa);
  syncHipaa();
}});

// Generate a short random encryption key (8 decimal digits) for
// HIPAA mode. Easy to read/share for testing; not cryptographically
// strong — for production use, replace with a 32-byte key.
function genHipaaKey() {{
  const a = new Uint32Array(1);
  crypto.getRandomValues(a);
  return String(a[0] % 100000000).padStart(8, '0');
}}

// Force the related controls when HIPAA mode is on:
//   geofence = NORTH_AMERICA, encryption = AES_256_GCM2 (mode 8)
// Generated key + fresh salt are populated. All four fields are
// locked while HIPAA is checked so the values that get sent to the
// server can't drift from what the UI claims is in effect.
function syncHipaa() {{
  const on = document.getElementById('hipaaCheckbox').checked;
  const geo = document.getElementById('geoAreaSelect');
  const mode = document.getElementById('encModeSelect');
  const key = document.getElementById('encKeyInput');
  const salt = document.getElementById('encSaltInput');
  if (on) {{
    geo.value  = 'NORTH_AMERICA';
    mode.value = '8';
    if (!key.value) key.value = genHipaaKey();
    syncSaltRow();
    if (!salt.value) salt.value = saltBase64(randSalt32());
    geo.disabled = mode.disabled = key.readOnly = salt.readOnly = true;
  }} else {{
    geo.disabled = mode.disabled = false;
    key.readOnly = salt.readOnly = false;
  }}
}}

function copyText(text) {{
  if (!text) return;
  navigator.clipboard.writeText(text).catch(() => {{}});
}}

function logEvent(msg, cls) {{
  const el = document.getElementById('events');
  const d  = document.createElement('div');
  const now = new Date();
  const hh = String(now.getHours()).padStart(2, '0');
  const mm = String(now.getMinutes()).padStart(2, '0');
  const ss = String(now.getSeconds()).padStart(2, '0');
  const ms = String(now.getMilliseconds()).padStart(3, '0');
  d.textContent = hh + ':' + mm + ':' + ss + '.' + ms + '  ' + msg;
  if (cls) d.className = cls;
  el.appendChild(d);
  // Cap at ~200 entries — oldest first.
  while (el.childElementCount > 200) el.removeChild(el.firstChild);
  requestAnimationFrame(() => {{ el.scrollTop = el.scrollHeight; }});
}}

// ── Session state ────────────────────────────────────────────────
let rtcClient  = null;   // AgoraRTC client
let localAudio = null;
let localVideo = null;
let audioMuted = false;
let rtm        = null;   // AgoraRTM.RTM instance
let convoApi   = null;   // ConversationalAIAPI singleton
let rtcJoined  = false;
let agentRunning = false;
let avatarWatchdog = null;   // setTimeout handle; fires if no remote video

// Mirror the server-side RtcAccount::parse rules exactly:
//   - all digits (within u32) → int uid
//   - `s/` prefix             → string account (prefix stripped)
//   - anything else           → string account
// Never silently coerces "423dd" to 423 like parseInt does.
function classifyUid(raw) {{
  if (!raw) return {{ kind: 'int', num: 0, account: '',  tokenArg: '0',   joinArg: null,  label: 'int (auto)' }};
  if (raw.startsWith('s/')) {{
    const stripped = raw.slice(2);
    return {{ kind: 'str', num: 0, account: stripped, tokenArg: raw, joinArg: stripped, label: 'string account' }};
  }}
  if (/^\d+$/.test(raw)) {{
    const n = Number(raw);
    if (Number.isFinite(n) && n >= 0 && n <= 4294967295) {{
      return {{ kind: 'int', num: n, account: '', tokenArg: String(n), joinArg: n, label: 'int' }};
    }}
  }}
  return {{ kind: 'str', num: 0, account: raw, tokenArg: raw, joinArg: raw, label: 'string account' }};
}}

// Return the string form of the local uid used for RTM login. The RTM user
// must match the `rtm_user_id` baked into the token, so we pass this value
// to the /api/token endpoint AND to `new AgoraRTM.RTM(appId, uid)`.
function rtmUserIdForLocal() {{
  const k = classifyUid(document.getElementById('uidInput').value.trim() || RTC_UID);
  return k.kind === 'int' ? String(k.num) : k.account;
}}

function setRtcDot(cls, label) {{
  const dot = document.getElementById('rtcDot');
  dot.className = 'status-dot ' + cls;
  document.getElementById('rtcState').textContent = label;
}}
function setAgentDot(cls, label) {{
  const dot = document.getElementById('agentDot');
  dot.className = 'status-dot ' + cls;
  document.getElementById('agentState').textContent = label;
}}

// Toolkit state string → dot class.
function mapState(s) {{
  if (!s || s === 'idle') return 'idle';
  // listening / thinking / speaking / silent → active (connected)
  return 'connected';
}}

async function fetchToken() {{
  const channel  = document.getElementById('channelInput').value.trim() || CHANNEL;
  const uidInput = document.getElementById('uidInput').value.trim();
  const uidKind  = classifyUid(uidInput);

  // We MUST send our own rtm_user_id so the minted token's RTM pin matches
  // the (uid) we'll use to log into RTM from this browser. The server's
  // default_rtm_user is the agent's uid — if we omitted this field, the
  // token would be pinned to the agent, and our RTM login would fail.
  const body = {{
    channel: channel,
    uid: uidKind.tokenArg,
    rtm_user_id: rtmUserIdForLocal(),
  }};

  try {{
    const resp = await fetch('/api/token', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify(body),
    }});
    const data = await resp.json();
    if (data.error) throw new Error(data.error);
    document.getElementById('tokenInput').value = data.token;
    logEvent('Token fetched (RTC + RTM, rtm_user_id=' + (data.rtm_user_id || '?') + ')', 'success');
  }} catch (err) {{
    logEvent('Fetch token error: ' + err.message, 'error');
  }}
}}

async function doJoin() {{
  if (rtcJoined) {{ logEvent('Already joined', 'warning'); return; }}

  if (!document.getElementById('tokenInput').value.trim()) {{
    await fetchToken();
  }}
  const token = document.getElementById('tokenInput').value.trim();
  if (!token) {{ logEvent('No token — aborting join', 'error'); return; }}

  const channel  = document.getElementById('channelInput').value.trim() || CHANNEL;
  const uidInput = document.getElementById('uidInput').value.trim();
  const uidKind  = classifyUid(uidInput);
  const joinUid  = uidKind.joinArg;

  setRtcDot('connecting', 'Connecting...');
  logEvent('Joining channel ' + channel + ' uid=' + (joinUid === null ? 'auto' : joinUid)
      + ' (' + uidKind.label + ')');

  try {{
    // Toolkit requirement: enable audio-PTS metadata BEFORE creating the client.
    // Old SDKs may not have this parameter — log a warning and keep going.
    try {{
      if (typeof AgoraRTC.setParameter === 'function') {{
        AgoraRTC.setParameter('ENABLE_AUDIO_PTS_METADATA', true);
      }} else {{
        logEvent('AgoraRTC.setParameter not available — ENABLE_AUDIO_PTS_METADATA skipped', 'warning');
      }}
    }} catch (e) {{
      logEvent('setParameter ENABLE_AUDIO_PTS_METADATA failed: ' + e.message, 'warning');
    }}

    // Geofence — restrict local SDK media routing. Must be set BEFORE
    // createClient. The same area is forwarded to /api/convo/start so
    // the agent stays in the same region.
    const geoArea = document.getElementById('geoAreaSelect').value;
    if (geoArea && geoArea !== 'GLOBAL') {{
      AgoraRTC.setArea({{ areaCode: geoArea }});
      logEvent('Geofence: ' + geoArea);
    }}

    rtcClient = AgoraRTC.createClient({{ mode: 'rtc', codec: 'vp8' }});

    rtcClient.on('user-published', async (user, mediaType) => {{
      try {{
        await rtcClient.subscribe(user, mediaType);
      }} catch (e) {{
        logEvent('Subscribe failed for ' + user.uid + ' (' + mediaType + '): ' + e.message, 'error');
        return;
      }}
      logEvent('Subscribed to ' + user.uid + ' (' + mediaType + ')', 'success');
      if (mediaType === 'audio') {{
        user.audioTrack && user.audioTrack.play();
      }}
      if (mediaType === 'video') {{
        const cell = document.getElementById('agentCell');
        cell.style.display = '';
        if (user.videoTrack) user.videoTrack.play('agentVideo');
        if (avatarWatchdog) {{ clearTimeout(avatarWatchdog); avatarWatchdog = null; }}
        logEvent('Avatar video playing', 'success');
      }}
    }});
    rtcClient.on('user-unpublished', (user, mediaType) => {{
      if (mediaType === 'video') {{
        document.getElementById('agentCell').style.display = 'none';
      }}
    }});
    rtcClient.on('user-joined', (user) => {{
      logEvent('Remote uid=' + user.uid + ' joined');
    }});
    rtcClient.on('user-left', (user) => {{
      logEvent('Remote uid=' + user.uid + ' left');
    }});
    // audio-pts counter — the ConversationalAIAPI toolkit relies on
    // this event for word-by-word timing. If the counter stays at 0,
    // PTS metadata isn't flowing from the agent's audio stream and
    // word mode can't reveal words progressively.
    window.__ptsCount = 0;
    rtcClient.on('audio-pts', (pts) => {{
      window.__ptsCount += 1;
      if (window.__ptsCount === 1) {{
        logEvent('audio-pts: first PTS=' + pts + ' — word-by-word sync active', 'success');
      }}
      if (window.__ptsCount % 100 === 0) {{
        logEvent('audio-pts: count=' + window.__ptsCount + ' latest=' + pts);
      }}
    }});
    rtcClient.on('connection-state-change', (cur, prev) => {{
      logEvent('RTC: ' + prev + ' -> ' + cur);
      if (cur === 'CONNECTED') setRtcDot('connected', 'Connected');
      else if (cur === 'RECONNECTING') setRtcDot('connecting', 'Reconnecting...');
      else if (cur === 'DISCONNECTED') setRtcDot('disconnected', 'Disconnected');
    }});

    // Encryption (must be configured BEFORE rtcClient.join). Empty key →
    // no encryption. The same key+salt is sent to /api/convo/start so
    // the agent joins encrypted with matching params.
    const encModeId = parseInt(document.getElementById('encModeSelect').value, 10);
    const encKey    = document.getElementById('encKeyInput').value;
    if (encModeId !== 0 && encKey) {{
      const modeStr = ENC_MODE_NAMES[encModeId];
      const isGcm2  = encModeId === 7 || encModeId === 8;
      if (isGcm2) {{
        const saltB64 = document.getElementById('encSaltInput').value.trim();
        let salt;
        try {{ salt = saltFromBase64(saltB64); }}
        catch (e) {{ logEvent('Salt is not valid base64', 'error'); return; }}
        if (salt.length !== 32) {{
          logEvent('Salt must decode to 32 bytes (got ' + salt.length + ')', 'error');
          return;
        }}
        rtcClient.setEncryptionConfig(modeStr, encKey, salt);
        logEvent('Encryption: ' + modeStr + ' (salt: ' + saltB64.slice(0, 12) + '…)');
      }} else {{
        rtcClient.setEncryptionConfig(modeStr, encKey);
        logEvent('Encryption: ' + modeStr);
      }}
    }}

    const joinedUid = await rtcClient.join(APP_ID, channel, token, joinUid);
    logEvent('Joined as uid ' + joinedUid, 'success');

    // Local mic — best effort. Voice agent doesn't need local video.
    try {{
      localAudio = await AgoraRTC.createMicrophoneAudioTrack();
      await rtcClient.publish([localAudio]);
      logEvent('Published local audio', 'success');
    }} catch (e) {{
      logEvent('No microphone — joined as listener: ' + e.message, 'warning');
    }}

    // RTM v2 login, using OUR stringified uid so it matches the token's RTM pin.
    try {{
      if (!window.AgoraRTM) throw new Error('RTM SDK not loaded');
      const rtmUser = rtmUserIdForLocal();
      // useStringUserId:true matches the working Agora ConvoAI coding-assistant
      // demo. Without it the SDK treats the uid as numeric and message/
      // presence routing misbehaves when our uid doesn't parse as an int.
      rtm = new AgoraRTM.RTM(APP_ID, rtmUser, {{ useStringUserId: true }});
      rtm.addEventListener('status', (evt) => {{
        logEvent('RTM status: ' + evt.state + (evt.reason ? ' (' + evt.reason + ')' : ''));
      }});
      await rtm.login({{ token }});
      logEvent('RTM logged in as ' + rtmUser, 'success');
      // Subscribe to the RTM channel. The ConvoAI toolkit only LISTENS
      // for MESSAGE events; it does NOT issue the subscribe itself.
      // Match the upstream Conversational-AI-Demo's default call
      // (withMessage + withPresence). Projects without Presence enabled
      // log a non-fatal -13001 warning but the subscribe still succeeds.
      try {{
        await rtm.subscribe(channel, {{
          withMessage:  true,
          withPresence: true,
        }});
        logEvent('RTM subscribed to channel ' + channel, 'success');
      }} catch (subErr) {{
        logEvent('RTM subscribe failed: ' + subErr.message, 'error');
      }}
    }} catch (e) {{
      logEvent('RTM login failed: ' + e.message, 'error');
    }}

    rtcJoined = true;
    setRtcDot('connected', 'Connected');
    document.getElementById('joinBtn').style.display  = 'none';
    document.getElementById('leaveBtn').style.display = '';
  }} catch (err) {{
    logEvent('Join error: ' + err.message, 'error');
    setRtcDot('disconnected', 'Error');
  }}
}}

async function doLeave() {{
  if (avatarWatchdog) {{ clearTimeout(avatarWatchdog); avatarWatchdog = null; }}
  try {{
    if (agentRunning) {{
      try {{ await stopAgent(); }} catch (_) {{}}
    }}
    if (convoApi) {{
      try {{ convoApi.destroy(); }} catch (_) {{}}
      convoApi = null;
    }}
    if (rtm) {{
      try {{ await rtm.unsubscribe(CHANNEL); }} catch (_) {{}}
      try {{ await rtm.logout(); }} catch (_) {{}}
      rtm = null;
    }}
    if (localAudio) {{ localAudio.close(); localAudio = null; }}
    if (localVideo) {{ localVideo.close(); localVideo = null; }}
    if (rtcClient) {{
      try {{ await rtcClient.leave(); }} catch (_) {{}}
      rtcClient = null;
    }}
    rtcJoined = false;
    audioMuted = false;
    const muteBtn = document.getElementById('muteBtn');
    muteBtn.classList.remove('active');
    muteBtn.textContent = 'Mute Mic';
    const camBtn = document.getElementById('cameraBtn');
    if (camBtn) {{
      camBtn.classList.remove('active');
      camBtn.textContent = 'Camera Off';
    }}
    const localDiv = document.getElementById('localVideo');
    if (localDiv) localDiv.innerHTML = '';
    document.getElementById('localCell').style.display = 'none';
    document.getElementById('agentCell').style.display = 'none';

    setRtcDot('disconnected', 'Disconnected');
    setAgentDot('idle', 'idle');
    document.getElementById('joinBtn').style.display  = '';
    document.getElementById('leaveBtn').style.display = 'none';
    logEvent('Left channel');
  }} catch (err) {{
    logEvent('Leave error: ' + err.message, 'error');
  }}
}}

async function toggleMute() {{
  if (!rtcClient) return;
  const btn = document.getElementById('muteBtn');
  if (!localAudio) {{
    try {{
      localAudio = await AgoraRTC.createMicrophoneAudioTrack();
      await rtcClient.publish([localAudio]);
      audioMuted = false;
      btn.classList.remove('active');
      btn.textContent = 'Mute Mic';
      logEvent('Microphone enabled', 'success');
    }} catch (e) {{
      logEvent('Cannot access microphone: ' + e.message, 'error');
    }}
    return;
  }}
  audioMuted = !audioMuted;
  await localAudio.setEnabled(!audioMuted);
  btn.classList.toggle('active', audioMuted);
  btn.textContent = audioMuted ? 'Unmute Mic' : 'Mute Mic';
}}

// Local camera toggle. OFF by default — avatar agents publish remote
// video on their side; the user only needs a local camera if they
// want to show themselves (optional). Click to start; click again
// to stop and close the track.
async function toggleCamera() {{
  if (!rtcClient) {{
    logEvent('Join RTC first, then toggle Camera.', 'warning');
    return;
  }}
  const btn = document.getElementById('cameraBtn');
  if (!localVideo) {{
    try {{
      localVideo = await AgoraRTC.createCameraVideoTrack();
      await rtcClient.publish([localVideo]);
      document.getElementById('localCell').style.display = '';
      localVideo.play('localVideo');
      btn.classList.add('active');
      btn.textContent = 'Camera On';
      logEvent('Local camera enabled', 'success');
    }} catch (e) {{
      logEvent('Cannot access camera: ' + e.message, 'error');
      localVideo = null;
    }}
    return;
  }}
  try {{
    await rtcClient.unpublish([localVideo]);
    localVideo.close();
    localVideo = null;
    const inner = document.getElementById('localVideo');
    if (inner) inner.innerHTML = '';
    document.getElementById('localCell').style.display = 'none';
    btn.classList.remove('active');
    btn.textContent = 'Camera Off';
    logEvent('Local camera disabled');
  }} catch (e) {{
    logEvent('Camera toggle error: ' + e.message, 'error');
  }}
}}

// ── Stats panel (RTC side) ──────────────────────────────────────
// Mirrors `serv rtc`'s Stats button: every 1s, pulls rtcClient's
// RTC stats and renders them. Click again to stop + collapse.
let statsInterval = null;
function toggleStats() {{
  const panel = document.getElementById('statsPanel');
  const btn   = document.getElementById('statsBtn');
  const visible = panel.classList.toggle('visible');
  btn.classList.toggle('active', visible);
  if (visible) {{
    updateStats();
    statsInterval = setInterval(updateStats, 1000);
  }} else {{
    clearInterval(statsInterval);
    statsInterval = null;
  }}
}}
async function updateStats() {{
  const panel = document.getElementById('statsPanel');
  if (!rtcClient) {{ panel.textContent = 'Not joined — click Join first.'; return; }}
  try {{
    const r = rtcClient.getRTCStats();
    const la = localAudio ? rtcClient.getLocalAudioStats() : null;
    const lv = localVideo ? rtcClient.getLocalVideoStats() : null;
    let text = '';
    text += 'Duration:      ' + (r.Duration || 0) + ' s\n';
    text += 'Users in room: ' + (r.UserCount || 0) + '\n';
    text += 'Send bitrate:  ' + (((r.SendBitrate || 0) / 1000).toFixed(0)) + ' kbps\n';
    text += 'Recv bitrate:  ' + (((r.RecvBitrate || 0) / 1000).toFixed(0)) + ' kbps\n';
    text += 'RTT:           ' + (r.RTT || 0) + ' ms\n';
    text += 'Packet loss:   tx=' + (r.OutgoingAvailableBandwidth || 0) + ' rx=' + (r.RecvType || '') + '\n';
    if (la) {{
      text += '\n[local audio]\n';
      text += 'codec=' + (la.codecType || '?') + '  sendBitrate=' + ((la.sendBitrate || 0) / 1000).toFixed(0) + ' kbps\n';
      text += 'sendVolumeLevel=' + (la.sendVolumeLevel || 0) + '\n';
    }}
    if (lv) {{
      text += '\n[local video]\n';
      text += (lv.sendResolutionWidth || '?') + 'x' + (lv.sendResolutionHeight || '?')
           + ' @ ' + (lv.sendFrameRate || 0) + 'fps, '
           + ((lv.sendBitrate || 0) / 1000).toFixed(0) + ' kbps\n';
    }}
    panel.textContent = text;
  }} catch (e) {{
    panel.textContent = 'Stats error: ' + e.message;
  }}
}}

// ── API history panel (ConvoAI REST calls) ──────────────────────
// Fetches /api/convo/history (process-lifetime ring buffer) and
// renders each entry. Click again to collapse.
async function toggleHistory() {{
  const panel = document.getElementById('historyPanel');
  const btn   = document.getElementById('historyBtn');
  const visible = panel.classList.toggle('visible');
  btn.classList.toggle('active', visible);
  if (visible) await refreshHistory();
}}
async function refreshHistory() {{
  const panel = document.getElementById('historyPanel');
  try {{
    const r = await fetch('/api/convo/history');
    const data = await r.json();
    const entries = data.entries || [];
    if (entries.length === 0) {{
      panel.textContent = '(no ConvoAI API calls yet — click Start Agent to see /join + /leave request/response bodies)';
      return;
    }}
    const fmt = (e) => {{
      const ts = new Date(e.ts_ms).toISOString().slice(11, 23);
      const head = e.kind === 'request'
        ? '→ ' + (e.method || 'POST') + ' ' + e.url
        : '← ' + (e.status || '') + ' ' + e.url;
      let body = e.body || '';
      // Pretty-print JSON bodies that came back as raw strings.
      try {{
        if (body && (body.trim().startsWith('{{') || body.trim().startsWith('['))) {{
          body = JSON.stringify(JSON.parse(body), null, 2);
        }}
      }} catch (_) {{}}
      return '[' + ts + '] ' + head + (body ? '\n' + body : '');
    }};
    panel.textContent = entries.map(fmt).join('\n\n');
    panel.scrollTop = panel.scrollHeight;
  }} catch (e) {{
    panel.textContent = 'Could not fetch history: ' + e.message;
  }}
}}

// Extract display text from a toolkit transcript item. Agora's item
// shape varies by render mode and turn status — `text` is the
// accumulated turn text in word/text mode, but in some flows the
// useful field is on `metadata` (partial transcription) or in a
// `words` array. Try the common locations in order.
function extractItemText(item) {{
  if (!item) return '';
  if (typeof item.text === 'string' && item.text) return item.text;
  const md = item.metadata;
  if (md && typeof md === 'object') {{
    if (typeof md.text === 'string' && md.text) return md.text;
    if (typeof md.transcription === 'string' && md.transcription) return md.transcription;
    if (Array.isArray(md.words)) {{
      const joined = md.words.map(w => (w && (w.word ?? w.text ?? '')) || '').join('').trim();
      if (joined) return joined;
    }}
  }}
  if (Array.isArray(item.words)) {{
    const joined = item.words.map(w => (w && (w.word ?? w.text ?? '')) || '').join('').trim();
    if (joined) return joined;
  }}
  return '';
}}

// Status-to-suffix mapping — helps make in-progress vs final visually
// distinct.  0 = IN_PROGRESS, 1 = END, 2 = INTERRUPTED
function turnStatusSuffix(s) {{
  if (s === 1) return '';         // finalised — plain text
  if (s === 2) return ' ⟂';       // interrupted
  return ' …';                    // in progress
}}

function renderTranscript(list) {{
  if (!Array.isArray(list)) return;
  const el = document.getElementById('transcript');
  const agentUidStr = String(AGENT_UID);
  const rows = list.map((item) => {{
    const who   = String(item.userId ?? item.uid ?? '') === agentUidStr ? 'agent' : 'user';
    const text  = extractItemText(item);
    const label = who === 'agent' ? 'agent' : 'user';
    const suffix = turnStatusSuffix(item.status);
    const div   = document.createElement('div');
    div.className = who;
    div.textContent = label + ': ' + text + suffix;
    return div;
  }});
  el.innerHTML = '';
  rows.forEach((r) => el.appendChild(r));
  requestAnimationFrame(() => {{ el.scrollTop = el.scrollHeight; }});
}}

async function startAgent() {{
  if (!rtcJoined) {{ logEvent('Join RTC before starting the agent', 'warning'); return; }}
  if (agentRunning) {{ logEvent('Agent already running', 'warning'); return; }}

  const includeAvatar = document.getElementById('avatarCheckbox').checked;
  // Checked presets, comma-joined (e.g. "expertise_ai_poc,_akool_test_expertise").
  // Empty string → fall back to whatever preset/presets is set in convo.toml.
  const presetName = selectedPresetString();
  setAgentDot('transitioning', 'starting...');

  // STEP 1: Initialize the ConvoAI toolkit and wire all listeners
  // BEFORE firing /api/convo/start. The upstream demo does this same
  // order — if we wire listeners after the agent is already speaking
  // its greeting, we miss the first batch of transcripts.
  const ToolkitClass =
    (ConversationalAIAPI && ConversationalAIAPI.ConversationalAIAPI)
    || ConversationalAIAPI;
  if (ToolkitClass && typeof ToolkitClass.init === 'function') {{
    try {{
      if (!convoApi) {{
        convoApi = ToolkitClass.init({{
          rtcEngine:  rtcClient,
          rtmEngine:  rtm,
          renderMode: 'text',
          enableRenderModeFallback: true,
          enableLog:  true,
        }});
        convoApi.on('transcript-updated', (list) => {{
          // Word-by-word streaming sanity check. For each (uid, turn_id)
          // pair, count how many times the toolkit has emitted an update
          // and remember the longest text length we saw. On turn END
          // (status === 1) we log:
          //   "turn <who>:<turn_id> final: N updates (max text=L chars)"
          // Expected with word mode + "enable_words":true: N should be
          // many (one per word — typically 10-80). If N == 1 the text
          // arrived all at once → word streaming isn't active.
          if (Array.isArray(list)) {{
            const agentUidStr = String(AGENT_UID);
            for (const it of list) {{
              const who = String(it.uid || '') === agentUidStr ? 'agent' : 'user';
              const key = who + ':' + (it.turn_id ?? '?');
              window.__turnUpdates = window.__turnUpdates || {{}};
              const prev = window.__turnUpdates[key] || {{count: 0, maxLen: 0}};
              const txt = extractItemText(it);
              prev.count += 1;
              if (txt.length > prev.maxLen) prev.maxLen = txt.length;
              window.__turnUpdates[key] = prev;
              if (it.status === 1 && !prev.logged) {{
                prev.logged = true;
                const kind = prev.count >= 10 ? 'streamed' : 'single-shot';
                logEvent('turn ' + key + ' final [' + kind + ']: '
                  + prev.count + ' updates, max text=' + prev.maxLen + ' chars');
              }}
            }}
          }}
          renderTranscript(list);
        }});
        convoApi.on('agent-state-changed', (uid, payload) => {{
          // Toolkit emits TWO args: (agent_uid, state_payload). The
          // state lives in the 2nd arg — either a bare string like
          // "listening" or an object with a `.state` field. We accept
          // both, and fall back to the 1st arg only if the 2nd is
          // missing entirely.
          const looksLikeState = s =>
            typeof s === 'string' && s.length > 0 && !/^\d+$/.test(s);
          let state = null;
          if (looksLikeState(payload)) {{
            state = payload;
          }} else if (payload && typeof payload === 'object') {{
            const candidates = [payload.state, payload.newState,
                                payload.agent_state, payload.current,
                                payload.status, payload.name, payload.type];
            for (const c of candidates) {{
              if (looksLikeState(c)) {{ state = c; break; }}
            }}
          }} else if (looksLikeState(uid)) {{
            // Rare shim: some versions emit only one arg (the state).
            state = uid;
          }}
          if (state) {{
            setAgentDot(mapState(state), state);
            logEvent('agent: ' + state + ' (uid=' + uid + ')');
          }} else {{
            let dump;
            try {{ dump = JSON.stringify(payload).slice(0, 200); }}
            catch (_) {{ dump = String(payload); }}
            logEvent('agent-state-changed (uid=' + uid + ', payload=' + dump + ')');
          }}
        }});
        // Keep these event handlers lean — noisy toolkit internals go
        // to the browser console via enableLog:true. Here we surface
        // only the events the user cares about in the #events panel.
        convoApi.on('agent-interrupted', (ev) => {{
          logEvent('agent-interrupted', 'warning');
        }});
        convoApi.on('agent-error', (err) => {{
          logEvent('agent-error: ' + (err?.message || JSON.stringify(err || {{}}).slice(0, 120)), 'error');
        }});
        const ch = document.getElementById('channelInput').value.trim() || CHANNEL;
        await convoApi.subscribeMessage(ch);
        logEvent('Toolkit listeners ready, subscribed to channel ' + ch, 'success');
      }}
    }} catch (e) {{
      logEvent('Toolkit init failed: ' + e.message, 'error');
    }}
  }} else {{
    logEvent('ConversationalAIAPI not loaded — transcripts disabled', 'warning');
  }}

  // STEP 2: Now that the toolkit is listening, fire /api/convo/start
  // (which does the Agora /join). First transcripts from the agent's
  // greeting will land in the already-attached listeners.
  try {{
    const startBody = {{ avatar: includeAvatar }};
    if (presetName) startBody.preset = presetName;
    // Forward encryption to the agent so it joins with matching params.
    // Empty key → no encryption fields sent → unencrypted call. Salt
    // comes from the page's editable Salt field, NOT a per-tab random
    // value, so the agent's salt matches whatever the local SDK used.
    const startEncModeId = parseInt(document.getElementById('encModeSelect').value, 10);
    const startEncKey    = document.getElementById('encKeyInput').value;
    if (startEncModeId !== 0 && startEncKey) {{
      startBody.encryption_mode = startEncModeId;
      startBody.encryption_key  = startEncKey;
      if (startEncModeId === 7 || startEncModeId === 8) {{
        startBody.encryption_salt = document.getElementById('encSaltInput').value.trim();
      }}
    }}
    // Forward geofence area. GLOBAL = default = no field sent.
    const startGeoArea = document.getElementById('geoAreaSelect').value;
    if (startGeoArea && startGeoArea !== 'GLOBAL') {{
      startBody.geofence_area = startGeoArea;
    }}
    // HIPAA mode flag — server uses it to pick /hipaa/api/... URL.
    if (document.getElementById('hipaaCheckbox').checked) {{
      startBody.hipaa = true;
    }}
    // Audio dump flag — debug knob; server adds parameters.enable_dump.
    if (document.getElementById('audioDumpCheckbox').checked) {{
      startBody.enable_dump = true;
    }}
    const resp = await fetch('/api/convo/start', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify(startBody),
    }});
    const data = await resp.json().catch(() => ({{}}));
    if (!resp.ok || data.error) {{
      logEvent('Start failed: ' + (data.error || ('HTTP ' + resp.status)), 'error');
      setAgentDot('idle', 'idle');
      return;
    }}
    const startedChannel = document.getElementById('channelInput').value.trim() || CHANNEL;
    logEvent(
      'Agent started: ' + (data.agent_id || '?')
        + ' (name: ' + (data.name || '?') + ', channel: ' + startedChannel + ')',
      'success'
    );

    agentRunning = true;
    setAgentDot('connected', 'connected');
    document.getElementById('startAgentBtn').style.display = 'none';
    document.getElementById('stopAgentBtn').style.display  = '';
    document.getElementById('stopAgentBtn').disabled       = false;

    // Avatar watchdog: if the user ticked Enable Avatar but no remote
    // video shows up within 10s, tell them plainly so they can debug
    // their preset or [agent.avatar] block instead of staring at an
    // empty agent cell.
    if (includeAvatar) {{
      avatarWatchdog = setTimeout(() => {{
        const agentCellVisible = document.getElementById('agentCell').style.display !== 'none';
        if (!agentCellVisible) {{
          logEvent(
            'Avatar enabled but no remote video received within 10s. '
            + 'Check that [agent.avatar] in convo.toml has a supported '
            + 'vendor + avatar_id + api_key combination that your Agora '
            + 'project actually provisions.',
            'warning'
          );
        }}
      }}, 10000);
    }}
  }} catch (err) {{
    logEvent('Start error: ' + err.message, 'error');
    setAgentDot('idle', 'idle');
  }}
}}

async function stopAgent() {{
  setAgentDot('transitioning', 'stopping...');
  if (avatarWatchdog) {{ clearTimeout(avatarWatchdog); avatarWatchdog = null; }}
  try {{
    const resp = await fetch('/api/convo/stop', {{ method: 'POST' }});
    const data = await resp.json().catch(() => ({{}}));
    if (data.error) logEvent('Stop error: ' + data.error, 'error');
    else logEvent('Agent stopped', 'success');
  }} catch (err) {{
    logEvent('Stop request failed: ' + err.message, 'error');
  }}
  if (convoApi) {{
    try {{ convoApi.destroy(); }} catch (_) {{}}
    convoApi = null;
  }}
  agentRunning = false;
  setAgentDot('idle', 'idle');
  document.getElementById('agentCell').style.display = 'none';
  document.getElementById('startAgentBtn').style.display = '';
  document.getElementById('startAgentBtn').disabled     = !rtcJoined;
  document.getElementById('stopAgentBtn').style.display  = 'none';
}}

// ── Slogan: random per page load, fixed for the session ─────────
const SLOGANS = [
  // real-time / networking
  "real-time is the only time",
  "latency is a suggestion, not a law",
  "every millisecond matters",
  "speed of thought, speed of sound",
  "bits in motion, minds in sync",
  "zero delay, all play",
  "the network is now",
  "ping travels at the speed of light",
  "if it's not real-time, it's history",
  "packets fly, conversations thrive",
  // voice / natural conversation
  "your true voice, heard",
  "nature's voice, zero friction",
  "real conversations, at the speed of speech",
  "voice is better, always",
  "speak naturally, be understood",
  "no keyboards, no clicks — just talk",
  "the fastest interface is your voice",
  "from thought to speech to action",
  "say it once, mean it always",
  "talk like you mean it",
  "conversations that flow",
  "every word in its moment",
  "audio is the new UI",
  "speech was the first API",
  "presence over pixels",
];
document.getElementById('slogan').textContent = SLOGANS[Math.floor(Math.random() * SLOGANS.length)];

// Seed inputs / read-only displays from the constants above.
document.getElementById('channelInput').value = CHANNEL;
document.getElementById('uidInput').value     = RTC_UID;
document.getElementById('agentUidDisplay').textContent = AGENT_UID;

// Avatar checkbox is ALWAYS clickable. An avatar can come from either
// an explicit [agent.avatar] TOML block OR from a selected preset
// (atem can't know which presets imply avatar). If the user checks the
// box without a TOML block we log an informational warning at click
// time but still let Start Agent run.
(function renderAvatarInfo() {{
  const info = document.getElementById('avatarInfo');
  info.innerHTML = '';
  if (AVATAR_INFO && (AVATAR_INFO.vendor || AVATAR_INFO.avatar_id)) {{
    if (AVATAR_INFO.vendor) {{
      const d = document.createElement('div');
      d.textContent = 'vendor:    ' + AVATAR_INFO.vendor;
      info.appendChild(d);
    }}
    if (AVATAR_INFO.avatar_id) {{
      const d = document.createElement('div');
      d.textContent = 'avatar_id: ' + AVATAR_INFO.avatar_id;
      info.appendChild(d);
    }}
  }} else {{
    const d = document.createElement('div');
    d.textContent = '(no [agent.avatar] in convo.toml — only enable if your preset includes avatar)';
    info.appendChild(d);
  }}
}})();

// Warn when user ticks the box with no [agent.avatar] block in TOML.
// Agora's /join requires a concrete `vendor` — the preset alone does
// NOT back-fill it (returns 400 "unsupported avatar vendor"). atem
// will silently skip the avatar block rather than let the /join fail.
document.getElementById('avatarCheckbox').addEventListener('change', (ev) => {{
  if (ev.target.checked && !AVATAR_OK) {{
    logEvent('Enable Avatar is checked but no [agent.avatar] block in convo.toml. '
      + 'Agora requires vendor + avatar_id + api_key to activate avatar — '
      + 'the avatar block will be skipped.', 'warning');
  }}
}});

// Populate the Presets checkboxes from the `presets` list in convo.toml.
// All boxes are CHECKED by default. When Start Agent fires, the checked
// values are joined with commas into a single `preset` string (Agora's
// /join expects `properties.preset` = "id1,id2,…"). Empty list renders
// a placeholder — config-level `preset` (singular) still applies
// server-side in that case.
(function populatePresets() {{
  const box = document.getElementById('presetCheckboxes');
  box.innerHTML = '';
  if (!Array.isArray(PRESETS) || PRESETS.length === 0) {{
    const span = document.createElement('span');
    span.style.color = '#7d8590';
    span.textContent = PRESET ? PRESET + '  (single, config-level)' : '—';
    box.appendChild(span);
    return;
  }}
  for (const p of PRESETS) {{
    const id = 'preset_cb_' + p.replace(/[^a-zA-Z0-9_]/g, '_');
    const wrap = document.createElement('label');
    wrap.style.display       = 'inline-flex';
    wrap.style.alignItems    = 'center';
    wrap.style.gap           = '4px';
    wrap.style.cursor        = 'pointer';
    wrap.style.color         = '#c9d1d9';
    wrap.style.fontFamily    = 'monospace';
    wrap.style.whiteSpace    = 'nowrap';   // each preset stays one line
    wrap.style.flex          = '0 0 auto'; // hug content; don't grow/shrink
    const cb = document.createElement('input');
    cb.type    = 'checkbox';
    cb.value   = p;
    cb.checked = true;                    // all checked by default
    cb.className = 'preset-checkbox';
    cb.id      = id;
    const txt = document.createElement('span');
    txt.textContent = p;
    wrap.appendChild(cb);
    wrap.appendChild(txt);
    box.appendChild(wrap);
  }}
}})();

// Helper: comma-joined list of currently-checked preset names (may be empty).
function selectedPresetString() {{
  return Array.from(document.querySelectorAll('.preset-checkbox'))
    .filter(cb => cb.checked)
    .map(cb => cb.value)
    .join(',');
}}

// On page load:
//   1. Auto-fetch an Access Token so the user doesn't have to click Fetch
//      before Join. (Same UX as `serv rtc`.)
//   2. Query the server for any already-running agent so the UI reflects
//      reality if the user reloads mid-session.
window.addEventListener('load', async () => {{
  try {{ await fetchToken(); }} catch (_) {{ /* ignored — user can click Fetch */ }}

  try {{
    const resp = await fetch('/api/convo/status');
    const st = await resp.json();
    if (st && st.running) {{
      setAgentDot('connected', 'connected (existing)');
      agentRunning = true;
      document.getElementById('startAgentBtn').style.display = 'none';
      document.getElementById('stopAgentBtn').style.display  = '';
      document.getElementById('stopAgentBtn').disabled       = false;
      const existingChannel = document.getElementById('channelInput').value.trim() || CHANNEL;
      logEvent(
        'Existing agent detected: ' + (st.agent_id || '?')
          + ' (name: ' + (st.name || '?') + ', channel: ' + existingChannel + ')',
        'info'
      );
    }}
  }} catch (_) {{ /* ignore */ }}
}});
</script>
</body>
</html>"##,
        app_id_display = app_id_display,
        app_id_label   = app_id_label,
        app_id         = app_id,
        channel        = channel,
        rtc_uid        = rtc_uid,
        agent_uid      = agent_uid,
        preset         = preset,
        presets_js     = presets_js,
        avatar_ok      = avatar_ok,
        avatar_info_js = avatar_info_js,
        default_hipaa    = if resolved.hipaa { "true" } else { "false" },
        default_geofence = resolved.geofence,
        default_enc_mode = resolved.encryption_mode,
        default_enc_key  = resolved.encryption_key,
        default_enc_salt = resolved.encryption_salt,
        attach_mode      = if attach_mode { "true" } else { "false" },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mask_secrets_replaces_sensitive_keys_keeps_others() {
        let mut v = serde_json::json!({
            "channel": "test",
            "token":   "super_secret_token_value",
            "agent_user_id": "1001",
            "rtc": {
                "encryption_key":  "shhhh",
                "encryption_salt": "saltydata=",   // not masked
                "encryption_mode": 8,
            },
            "agent": {
                "llm": {
                    "url":     "https://api.example.com",
                    "api_key": "sk-xxxxx",
                },
                "avatar": {
                    "params": {
                        "agora_app_cert": "private",
                    },
                },
            },
        });
        mask_secrets(&mut v);
        assert!(v["token"].as_str().unwrap().starts_with("***"));
        assert!(v["rtc"]["encryption_key"].as_str().unwrap().starts_with("***"));
        assert!(v["agent"]["llm"]["api_key"].as_str().unwrap().starts_with("***"));
        assert!(v["agent"]["avatar"]["params"]["agora_app_cert"].as_str().unwrap().starts_with("***"));
        // Non-sensitive fields are untouched.
        assert_eq!(v["channel"], "test");
        assert_eq!(v["agent_user_id"], "1001");
        assert_eq!(v["rtc"]["encryption_salt"], "saltydata=");
        assert_eq!(v["rtc"]["encryption_mode"], 8);
        assert_eq!(v["agent"]["llm"]["url"], "https://api.example.com");
    }

    #[test]
    fn default_config_path_ends_with_convo_toml() {
        let p = default_config_path();
        assert!(p.ends_with("convo.toml"));
    }

    // Real /api/token behaviour is exercised in scripts/run-local-dev-tests.sh
    // via a running server. This unit test just checks that the route constant
    // text is present in the source (cheap guard against accidental removal).
    #[test]
    fn source_contains_api_token_route() {
        let src = include_str!("convo_test_server.rs");
        assert!(src.contains("\"/api/token\""), "missing /api/token route");
    }

    #[test]
    fn convoai_base_url_defaults_to_agora() {
        // Unset to guarantee default.
        unsafe { std::env::remove_var("ATEM_CONVOAI_API_URL"); }
        assert_eq!(convoai_base_url(), "https://api.agora.io");
    }

    #[test]
    fn convoai_base_url_honours_env_override() {
        unsafe { std::env::set_var("ATEM_CONVOAI_API_URL", "http://127.0.0.1:9999"); }
        assert_eq!(convoai_base_url(), "http://127.0.0.1:9999");
        unsafe { std::env::remove_var("ATEM_CONVOAI_API_URL"); }
    }

    #[test]
    fn convoai_url_default_uses_api_prefix() {
        unsafe { std::env::remove_var("ATEM_CONVOAI_API_URL"); }
        let u = convoai_url(false, "v2/projects/abc/join");
        assert_eq!(u, "https://api.agora.io/api/conversational-ai-agent/v2/projects/abc/join");
    }

    #[test]
    fn convoai_url_hipaa_uses_hipaa_prefix() {
        unsafe { std::env::remove_var("ATEM_CONVOAI_API_URL"); }
        let u = convoai_url(true, "v2/projects/abc/join");
        assert_eq!(u, "https://api.agora.io/hipaa/api/conversational-ai-agent/v2/projects/abc/join");
    }

    #[test]
    fn html_has_expected_ids_and_scripts() {
        let resolved = ResolvedConfig {
            channel:           "chan".into(),
            rtc_user_id:       "42".into(),
            agent_user_id:     "9".into(),
            idle_timeout_secs: Some(120),
            avatar_configured: true,
            avatar_summary:    Some(crate::convo_config::AvatarSummary {
                vendor: Some("heygen".into()), avatar_id: Some("abc".into()),
            }),
            preset:            None,
            presets:           vec![],
            hipaa:             false,
            geofence:          String::new(),
            encryption_mode:   0,
            encryption_key:    String::new(),
            encryption_salt:   String::new(),
        };
        let html = build_html_page("app-xx", &resolved, false);
        assert!(html.contains("/vendor/conversational-ai-api.js"));
        assert!(html.contains("id=\"agentUidDisplay\""));
        assert!(html.contains("id=\"avatarCheckbox\""));
        assert!(html.contains("Welcome to Agora"));
        assert!(html.contains("id=\"presetCheckboxes\""));
        assert!(html.contains("id=\"avatarInfo\""));
        // Avatar info block should render the non-secret fields
        assert!(html.contains("heygen"));
        assert!(html.contains("abc"));
    }

    #[test]
    fn html_embeds_preset_list_as_js_array() {
        let resolved = ResolvedConfig {
            channel:           "c".into(),
            rtc_user_id:       "1".into(),
            agent_user_id:     "2".into(),
            idle_timeout_secs: None,
            avatar_configured: false,
            avatar_summary:    None,
            preset:            None,
            presets:           vec!["expertise_ai_poc".into(), "_akool_test_expertise".into()],
            hipaa:             false,
            geofence:          String::new(),
            encryption_mode:   0,
            encryption_key:    String::new(),
            encryption_salt:   String::new(),
        };
        let html = build_html_page("app", &resolved, false);
        // JSON-encoded array literal must appear in the page.
        assert!(html.contains(r#"["expertise_ai_poc","_akool_test_expertise"]"#),
            "preset list not embedded — got: {}",
            html.lines().find(|l| l.contains("PRESETS")).unwrap_or(""));
    }

    #[test]
    fn gen_agent_name_has_expected_shape() {
        let n = gen_agent_name("7dcc42cab6404f7b9ea0a36b1500d1f1");
        assert!(n.starts_with("atem-agent-7dcc42cab640-"), "got: {n}");
        // 4-hex suffix after the last dash
        let last = n.rsplit('-').next().unwrap();
        assert_eq!(last.len(), 4);
        assert!(last.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

use anyhow::Result;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Configuration for the RTC test server.
pub struct RtcTestConfig {
    pub channel: String,
    pub port: u16,
    pub expire_secs: u32,
    /// Optional RTC user id / account. None → server default ("0" / auto-assign).
    /// Honours the same `s/` prefix convention as `atem token rtc create`.
    pub rtc_user_id: Option<String>,
    /// When true, issue an RTC+RTM combined token and render the RTM UI.
    pub with_rtm: bool,
    /// RTM user account to embed. Only used when `with_rtm` is true.
    /// If None, falls back to `rtc_user_id`.
    pub rtm_user_id: Option<String>,
    pub no_browser: bool,
    pub background: bool,
    pub _daemon: bool,
}

/// A registered background server tracked via a JSON file.
#[derive(serde::Serialize, serde::Deserialize, Debug)]
pub struct ServerEntry {
    pub id: String,
    pub pid: u32,
    pub kind: String,
    pub port: u16,
    pub channel: String,
    pub local_url: String,
    pub network_url: String,
    pub started_at: u64,
}

// ── Server registry ─────────────────────────────────────────────────────

/// Directory where server JSON files are stored.
pub fn servers_dir() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join("atem")
        .join("servers")
}

/// Build a deterministic server ID.
pub fn server_id(kind: &str, channel: &str, port: u16) -> String {
    format!("{}-{}-{}", kind, channel, port)
}

/// Write a server entry JSON file.
fn register_server(entry: &ServerEntry) -> Result<()> {
    let dir = servers_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}.json", entry.id));
    let json = serde_json::to_string_pretty(entry)?;
    std::fs::write(path, json)?;
    Ok(())
}

/// Remove a server entry JSON file.
fn unregister_server(id: &str) -> Result<()> {
    let path = servers_dir().join(format!("{}.json", id));
    if path.exists() {
        std::fs::remove_file(path)?;
    }
    Ok(())
}

/// Check if a PID is still alive using kill(pid, 0).
fn is_pid_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as i32, 0) == 0 }
}

/// List all registered servers, filtering out dead PIDs.
fn list_servers() -> Vec<ServerEntry> {
    let dir = servers_dir();
    let entries = match std::fs::read_dir(&dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(),
    };
    let mut servers = Vec::new();
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        let data = match std::fs::read_to_string(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let server: ServerEntry = match serde_json::from_str(&data) {
            Ok(s) => s,
            Err(_) => continue,
        };
        if is_pid_alive(server.pid) {
            servers.push(server);
        } else {
            // Stale entry — clean up
            let _ = std::fs::remove_file(&path);
        }
    }
    servers.sort_by(|a, b| a.started_at.cmp(&b.started_at));
    servers
}

/// Kill a single server by ID.
fn kill_server(id: &str) -> Result<()> {
    let path = servers_dir().join(format!("{}.json", id));
    if !path.exists() {
        anyhow::bail!("No server with id '{}'", id);
    }
    let data = std::fs::read_to_string(&path)?;
    let server: ServerEntry = serde_json::from_str(&data)?;
    if is_pid_alive(server.pid) {
        unsafe { libc::kill(server.pid as i32, libc::SIGTERM); }
    }
    std::fs::remove_file(&path)?;
    Ok(())
}

/// Kill all registered servers.
fn kill_all_servers() -> Result<()> {
    let servers = list_servers();
    for s in &servers {
        unsafe { libc::kill(s.pid as i32, libc::SIGTERM); }
        let _ = unregister_server(&s.id);
    }
    Ok(())
}

// ── CLI command handlers ────────────────────────────────────────────────

pub fn cmd_list_servers() -> Result<()> {
    let servers = list_servers();
    if servers.is_empty() {
        println!("No running servers.");
        return Ok(());
    }
    println!("{:<24} {:>6} {:>8}  {}", "ID", "PID", "PORT", "URL");
    for s in &servers {
        println!("{:<24} {:>6} {:>8}  {}", s.id, s.pid, s.port, s.network_url);
    }
    Ok(())
}

pub fn cmd_kill_server(id: &str) -> Result<()> {
    kill_server(id)?;
    println!("Killed server '{}'", id);
    Ok(())
}

pub fn cmd_kill_all_servers() -> Result<()> {
    let servers = list_servers();
    if servers.is_empty() {
        println!("No running servers.");
        return Ok(());
    }
    let count = servers.len();
    kill_all_servers()?;
    println!("Killed {} server(s).", count);
    Ok(())
}

/// Detect the LAN IP address by connecting a UDP socket to an external address.
/// This doesn't actually send any data — it just causes the OS to pick the
/// outbound interface, from which we read back the local address.
pub fn get_lan_ip() -> IpAddr {
    let socket = UdpSocket::bind("0.0.0.0:0").ok();
    let ip = socket
        .and_then(|s| {
            s.connect("8.8.8.8:80").ok()?;
            s.local_addr().ok()
        })
        .map(|a| a.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    ip
}

/// Format an IP address for sslip.io: dots become dashes.
fn sslip_host(ip: &IpAddr) -> String {
    format!("{}.sslip.io", ip.to_string().replace('.', "-"))
}

/// Run the HTTPS server for RTC testing.
pub async fn run_server(config: RtcTestConfig) -> Result<()> {
    let app_id = crate::config::ProjectCache::resolve_app_id(None)?;
    let app_certificate = crate::config::ProjectCache::resolve_app_certificate(None)?;

    let lan_ip = get_lan_ip();
    let sslip = sslip_host(&lan_ip);

    // Generate self-signed cert
    let (certs, key) = crate::web_server::cert::generate_self_signed_cert(&lan_ip)?;

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    // Bind listener
    let bind_addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let listener = TcpListener::bind(bind_addr).await?;
    let local_addr = listener.local_addr()?;
    let port = local_addr.port();

    let local_url = format!("https://localhost:{}/", port);
    let network_url = format!("https://{}:{}/", sslip, port);

    // ── Background mode: re-exec as daemon ──────────────────────────────
    if config.background && !config._daemon {
        let exe = std::env::current_exe()?;
        let log_dir = servers_dir();
        std::fs::create_dir_all(&log_dir)?;
        let sid = server_id("rtc", &config.channel, port);
        let log_path = log_dir.join(format!("{}.log", sid));
        let log_file = std::fs::File::create(&log_path)?;

        let mut daemon_args: Vec<String> = vec![
            "serv".into(),
            "rtc".into(),
            "--channel".into(),
            config.channel.clone(),
            "--port".into(),
            port.to_string(),
            "--expire".into(),
            config.expire_secs.to_string(),
        ];
        if let Some(uid) = &config.rtc_user_id {
            daemon_args.push("--rtc-user-id".into());
            daemon_args.push(uid.clone());
        }
        if config.with_rtm {
            daemon_args.push("--with-rtm".into());
        }
        if let Some(rtm_uid) = &config.rtm_user_id {
            daemon_args.push("--rtm-user-id".into());
            daemon_args.push(rtm_uid.clone());
        }
        daemon_args.push("--no-browser".into());
        daemon_args.push("--serv-daemon".into());

        let child = std::process::Command::new(exe)
            .args(&daemon_args)
            .stdin(std::process::Stdio::null())
            .stdout(log_file.try_clone()?)
            .stderr(log_file)
            .spawn()?;

        let entry = ServerEntry {
            id: sid.clone(),
            pid: child.id(),
            kind: "rtc".to_string(),
            port,
            channel: config.channel.clone(),
            local_url: local_url.clone(),
            network_url: network_url.clone(),
            started_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        register_server(&entry)?;

        println!("RTC server started in background:");
        println!("  ID:      {}", sid);
        println!("  PID:     {}", child.id());
        println!("  Local:   {}", local_url);
        println!("  Network: {}", network_url);
        println!("  Log:     {}", log_path.display());
        println!();
        println!("Use `atem serv list` to see running servers.");
        println!("Use `atem serv kill {}` to stop it.", sid);
        return Ok(());
    }

    // ── Daemon mode: register self and set up cleanup ───────────────────
    if config._daemon {
        let sid = server_id("rtc", &config.channel, port);
        let entry = ServerEntry {
            id: sid.clone(),
            pid: std::process::id(),
            kind: "rtc".to_string(),
            port,
            channel: config.channel.clone(),
            local_url: local_url.clone(),
            network_url: network_url.clone(),
            started_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };
        register_server(&entry)?;

        // Clean up on Ctrl+C
        let cleanup_id = sid.clone();
        ctrlc::set_handler(move || {
            let _ = unregister_server(&cleanup_id);
            std::process::exit(0);
        })
        .ok();
    }

    // ── Foreground output ───────────────────────────────────────────────
    println!("RTC Test Server running:");
    println!("  Local:   {}", local_url);
    println!("  Network: {}", network_url);
    println!();
    println!(
        "  App ID:  {}...{}",
        &app_id[..4.min(app_id.len())],
        if app_id.len() > 8 {
            &app_id[app_id.len() - 4..]
        } else {
            ""
        }
    );
    println!("  Channel: {}", config.channel);
    println!();
    println!("Press Ctrl+C to stop.");
    println!();

    // Open browser
    if !config.no_browser {
        if let Err(e) = open_browser(&local_url) {
            eprintln!("Could not open browser: {}", e);
        }
    }

    let app_id = Arc::new(app_id);
    let app_certificate = Arc::new(app_certificate);
    let channel = Arc::new(config.channel);
    let expire_secs = config.expire_secs;
    let rtc_user_id = Arc::new(config.rtc_user_id);
    let with_rtm = config.with_rtm;
    let rtm_user_id = Arc::new(config.rtm_user_id);

    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app_id = app_id.clone();
        let app_certificate = app_certificate.clone();
        let channel = channel.clone();
        let rtc_user_id = rtc_user_id.clone();
        let rtm_user_id = rtm_user_id.clone();

        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    // TLS handshake failures are expected (cert warnings, probes)
                    let _ = e;
                    return;
                }
            };

            if let Err(e) = handle_connection(
                tls_stream,
                peer,
                &app_id,
                &app_certificate,
                &channel,
                expire_secs,
                rtc_user_id.as_deref(),
                with_rtm,
                rtm_user_id.as_deref(),
            )
            .await
            {
                eprintln!("[{}] Error: {}", peer, e);
            }
        });
    }
}

/// Handle a single TLS connection — parse the HTTP request and route.
#[allow(clippy::too_many_arguments)]
async fn handle_connection(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    _peer: SocketAddr,
    app_id: &str,
    app_certificate: &str,
    default_channel: &str,
    expire_secs: u32,
    rtc_user_id: Option<&str>,
    with_rtm: bool,
    rtm_user_id: Option<&str>,
) -> Result<()> {
    // Read until we have the full request (headers + Content-Length bytes of body).
    // A single .read() can return only the headers if the browser splits the POST
    // across TLS records — that previously caused intermittent 400s on /api/token.
    let buf = match crate::web_server::request::read_full_http_request(&mut stream).await {
        Ok(Some(b)) => b,
        Ok(None) => return Ok(()),
        Err(e) => {
            eprintln!("[rtc_test_server] read error: {e}");
            return Ok(());
        }
    };
    let request = String::from_utf8_lossy(&buf);

    // Parse first line: METHOD PATH HTTP/1.x
    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        crate::web_server::request::send_response(&mut stream, 400, "text/plain", b"Bad Request").await?;
        return Ok(());
    }
    let method = parts[0];
    let path = parts[1];

    match (method, path) {
        ("GET", "/") => {
            let default_uid = rtc_user_id.unwrap_or("0");
            let default_rtm_uid = rtm_user_id.unwrap_or(default_uid);
            let html = build_html_page(
                app_id, default_channel, default_uid, with_rtm, default_rtm_uid,
            );
            crate::web_server::request::send_response(&mut stream, 200, "text/html; charset=utf-8", html.as_bytes()).await?;
        }
        ("GET", "/favicon.ico") => {
            crate::web_server::request::send_response(&mut stream, 204, "text/plain", b"").await?;
        }
        ("GET", "/vendor/agora-rtm-sdk.js") => {
            // Vendored SDK embedded at compile time — no CDN dependency.
            const RTM_SDK: &str = include_str!("../assets/agora-rtm-sdk.js");
            crate::web_server::request::send_response(
                &mut stream,
                200,
                "application/javascript; charset=utf-8",
                RTM_SDK.as_bytes(),
            )
            .await?;
        }
        ("POST", "/api/token") => {
            let body = crate::web_server::request::extract_body(&request);
            handle_token_api(
                &mut stream, &body, app_id, app_certificate, expire_secs, with_rtm, rtm_user_id,
            )
            .await?;
        }
        _ => {
            crate::web_server::request::send_response(&mut stream, 404, "text/plain", b"Not Found").await?;
        }
    }

    Ok(())
}

/// Handle POST /api/token — generate an RTC (or RTC+RTM) token.
async fn handle_token_api(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    body: &str,
    app_id: &str,
    app_certificate: &str,
    expire_secs: u32,
    with_rtm: bool,
    default_rtm_user: Option<&str>,
) -> Result<()> {
    // Parse body as JSON: { "channel": "...", "uid": "...", "rtm_user_id"?: "..." }
    let parsed: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            let err = r#"{"error":"Invalid JSON body"}"#;
            crate::web_server::request::send_response(stream, 400, "application/json", err.as_bytes()).await?;
            return Ok(());
        }
    };

    let channel = parsed["channel"].as_str().unwrap_or("test");
    let uid = parsed["uid"].as_str().unwrap_or("0");
    // Only honoured when the server was launched with --with-rtm.
    let rtm_user_id_req = parsed["rtm_user_id"].as_str();

    // Use time sync for accurate issued_at
    let mut time_sync = crate::time_sync::TimeSync::new();
    let now = match time_sync.now().await {
        Ok(t) => t as u32,
        Err(_) => {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as u32
        }
    };

    let rtc_account = crate::token::RtcAccount::parse(uid);

    let token = if with_rtm {
        // Resolve RTM account: request body > CLI default > fallback to RTC uid.
        // The client is trusted — if it sends a mismatched rtm_user_id, login
        // with a stale token will simply fail, which is the desired behaviour.
        let rtm_uid = rtm_user_id_req
            .or(default_rtm_user)
            .map(str::to_string)
            .unwrap_or_else(|| rtc_account.as_str());
        match crate::token::build_token_rtc_with_rtm(
            app_id,
            app_certificate,
            channel,
            rtc_account,
            crate::token::Role::Publisher,
            expire_secs,
            expire_secs,
            Some(&rtm_uid),
        ) {
            Ok(t) => t,
            Err(e) => {
                let err = serde_json::json!({"error": format!("Token generation failed: {}", e)});
                crate::web_server::request::send_response(stream, 500, "application/json", err.to_string().as_bytes()).await?;
                return Ok(());
            }
        }
    } else {
        match crate::token::build_token_rtc(
            app_id,
            app_certificate,
            channel,
            rtc_account,
            crate::token::Role::Publisher,
            expire_secs,
            now,
        ) {
            Ok(t) => t,
            Err(e) => {
                let err = serde_json::json!({"error": format!("Token generation failed: {}", e)});
                crate::web_server::request::send_response(stream, 500, "application/json", err.to_string().as_bytes()).await?;
                return Ok(());
            }
        }
    };

    // Echo which RTM user this token was issued for (for client UX).
    let actual_rtm_user = if with_rtm {
        rtm_user_id_req
            .or(default_rtm_user)
            .map(str::to_string)
            .unwrap_or_else(|| rtc_account.as_str())
    } else {
        String::new()
    };
    let resp = serde_json::json!({
        "token": token,
        "app_id": app_id,
        "channel": channel,
        "uid": uid,
        "with_rtm": with_rtm,
        "rtm_user_id": actual_rtm_user,
    });

    crate::web_server::request::send_response(stream, 200, "application/json", resp.to_string().as_bytes()).await?;
    Ok(())
}

/// Open a URL in the default browser.
pub(crate) fn open_browser(url: &str) -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(url).spawn()?;
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open").arg(url).spawn()?;
    }
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", url])
            .spawn()?;
    }
    Ok(())
}

/// Build the self-contained HTML page for RTC testing.
fn build_html_page(
    app_id: &str,
    default_channel: &str,
    default_uid: &str,
    with_rtm: bool,
    default_rtm_uid: &str,
) -> String {
    let app_id_display = if app_id.len() > 12 {
        format!("{}...{}", &app_id[..6], &app_id[app_id.len() - 4..])
    } else {
        app_id.to_string()
    };

    // Fragments that are only rendered when --with-rtm is active.
    let rtm_css = if with_rtm {
        // RTM-only styles. The two input rows reuse `.controls` and the log
        // reuses `#log`'s visual treatment (inherits block background), so
        // RTC and RTM blocks look identical. Only dot state + line colours
        // live here.
        r##"#rtmLog { max-height:200px; overflow-y:auto; padding:8px 16px; font-size:11px; font-family:monospace; color:#7d8590; }
#rtmLog div { padding:1px 0; }
#rtmLog .inbound  { color:#79c0ff; }
#rtmLog .outbound { color:#3fb950; }
#rtmLog .info     { color:#7d8590; }
#rtmLog .error    { color:#f85149; }
#rtmDot.ok  { background:#3fb950 !important; }
#rtmDot.err { background:#f85149 !important; }"##
    } else {
        ""
    };

    let rtm_section = if with_rtm {
        format!(r##"
<section class="block">
  <h2 class="block-title"><span class="status-dot disconnected" id="rtmDot"></span>Signaling (RTM) — <span id="rtmStatusText" style="font-weight:400;color:#7d8590">not logged in</span></h2>
  <div class="controls">
    <label>RTM User</label>
    <input id="rtmUserInput" type="text" value="{default_rtm_uid}" placeholder="user id" oninput="updateFetchState()">
    <button id="rtmLoginBtn" class="btn btn-mute" onclick="rtmLogin()">Login</button>
    <button id="rtmLogoutBtn" class="btn btn-leave" onclick="rtmLogout()" style="display:none">Logout</button>
  </div>
  <div class="controls">
    <label>Send to</label>
    <input id="rtmPeerInput" type="text" placeholder="peer user id (leave blank = channel)" style="width:360px">
  </div>
  <div class="controls">
    <label>Message</label>
    <input id="rtmMsgInput" type="text" placeholder="message" style="flex:1;min-width:200px">
    <button id="rtmSendBtn" class="btn btn-mute" onclick="rtmSend()" disabled>Send</button>
  </div>
  <div id="rtmLog"></div>
</section>"##,
            default_rtm_uid = default_rtm_uid)
    } else {
        String::new()
    };

    // RTM SDK v2 served from atem itself (vendored at build time from
    // agora-rtm-sdk@2.2.4). Avoids CDN flakiness / 404s and works offline.
    let rtm_sdk_script = if with_rtm {
        r#"<script src="/vendor/agora-rtm-sdk.js"></script>"#
    } else {
        ""
    };

    let rtm_js = if with_rtm {
        r##"
// ── Signaling (RTM v2) ────────────────────────────────────────────
let rtm = null;
let rtmChannelName = null;
function rtmLog(msg, cls) {
  const el = document.getElementById('rtmLog');
  const d = document.createElement('div');
  d.textContent = '[' + new Date().toLocaleTimeString() + '] ' + msg;
  if (cls) d.className = cls;
  el.appendChild(d);
  el.scrollTop = el.scrollHeight;
}
function rtmSetStatus(state, text) {
  // Preserve `status-dot` base class; state ∈ {'', 'ok', 'err'}
  const dot = document.getElementById('rtmDot');
  dot.className = 'status-dot' + (state ? ' ' + state : ' disconnected');
  document.getElementById('rtmStatusText').textContent = text;
}
async function rtmLogin() {
  const actualUser = document.getElementById('rtmUserInput').value.trim();
  if (!actualUser) { rtmLog('Enter an RTM user id first', 'error'); return; }
  if (!window.AgoraRTM) { rtmLog('RTM SDK not loaded', 'error'); return; }

  // Use the token that's already in the textbox. If the user changed the RTM
  // user id but didn't click Fetch, the existing token won't match and RTM
  // will reject the login — which is the correct behaviour.
  const token = document.getElementById('tokenInput').value.trim();
  if (!token) {
    rtmLog('No token — click Fetch first', 'error');
    return;
  }

  try {
    rtm = new AgoraRTM.RTM(APP_ID, actualUser);
    rtm.addEventListener('message', (evt) => {
      const from = evt.publisher || '?';
      const chan = evt.channelName ? ' [' + evt.channelName + ']' : '';
      rtmLog('← ' + from + chan + ': ' + evt.message, 'inbound');
    });
    rtm.addEventListener('status', (evt) => {
      rtmLog('RTM status: ' + evt.state + (evt.reason ? ' (' + evt.reason + ')' : ''), 'info');
    });
    await rtm.login({ token });

    // Subscribe to the RTC channel so channel messages arrive here too.
    rtmChannelName = document.getElementById('channelInput').value.trim() || 'test';
    try {
      await rtm.subscribe(rtmChannelName);
      rtmLog('Subscribed to channel ' + rtmChannelName, 'info');
    } catch (e) {
      rtmLog('Subscribe failed (non-fatal): ' + e.message, 'info');
    }

    rtmSetStatus('ok', 'logged in as ' + actualUser);
    document.getElementById('rtmLoginBtn').style.display = 'none';
    document.getElementById('rtmLogoutBtn').style.display = '';
    document.getElementById('rtmSendBtn').disabled = false;
    rtmLog('Logged in as ' + actualUser, 'info');
  } catch (e) {
    rtmLog('Login failed: ' + e.message, 'error');
    rtmSetStatus('err', 'login failed');
  }
}
async function rtmLogout() {
  if (!rtm) return;
  try {
    if (rtmChannelName) {
      try { await rtm.unsubscribe(rtmChannelName); } catch (_) {}
      rtmChannelName = null;
    }
    await rtm.logout();
  } catch (e) {
    rtmLog('Logout error: ' + e.message, 'error');
  }
  rtm = null;
  rtmSetStatus('', 'not logged in');
  document.getElementById('rtmLoginBtn').style.display = '';
  document.getElementById('rtmLogoutBtn').style.display = 'none';
  document.getElementById('rtmSendBtn').disabled = true;
  rtmLog('Logged out', 'info');
}
async function rtmSend() {
  if (!rtm) { rtmLog('Not logged in', 'error'); return; }
  const peer = document.getElementById('rtmPeerInput').value.trim();
  const msg  = document.getElementById('rtmMsgInput').value;
  if (!msg) { rtmLog('Enter a message', 'error'); return; }
  try {
    if (peer) {
      await rtm.publish(peer, msg, { channelType: 'USER' });
      rtmLog('→ ' + peer + ': ' + msg, 'outbound');
    } else {
      const chan = rtmChannelName || (document.getElementById('channelInput').value.trim() || 'test');
      await rtm.publish(chan, msg);
      rtmLog('→ [' + chan + ']: ' + msg, 'outbound');
    }
    document.getElementById('rtmMsgInput').value = '';
  } catch (e) {
    rtmLog('Send failed: ' + e.message, 'error');
  }
}
"##
    } else {
        ""
    };

    format!(
        r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Hello, Agora RTC</title>
<style>
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #e6edf3; min-height: 100vh; }}
.header {{ background: #161b22; border-bottom: 1px solid #30363d; padding: 12px 20px; display: flex; align-items: center; gap: 12px; }}
.header h1 {{ font-size: 16px; font-weight: 600; }}
.header .app-id {{ font-size: 12px; color: #7d8590; font-family: monospace; }}
.controls {{ background: #161b22; border-bottom: 1px solid #30363d; padding: 12px 20px; display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }}
.controls input {{ background: #0d1117; border: 1px solid #30363d; color: #e6edf3; padding: 6px 10px; border-radius: 6px; font-size: 14px; width: 180px; }}
.controls input:focus {{ border-color: #58a6ff; outline: none; }}
.controls label {{ font-size: 12px; color: #7d8590; }}
.btn {{ padding: 6px 14px; border: 1px solid #30363d; border-radius: 6px; font-size: 13px; cursor: pointer; font-weight: 500; transition: 0.15s; }}
.btn-join {{ background: #238636; border-color: #238636; color: #fff; }}
.btn-join:hover {{ background: #2ea043; }}
.btn-leave {{ background: #da3633; border-color: #da3633; color: #fff; display: none; }}
.btn-leave:hover {{ background: #f85149; }}
.btn-mute {{ background: #21262d; color: #e6edf3; }}
.btn-mute:hover {{ background: #30363d; }}
.btn-mute.active {{ background: #da3633; border-color: #da3633; }}
.btn-stats {{ background: #21262d; color: #e6edf3; }}
.btn-stats:hover {{ background: #30363d; }}
.btn-stats.active {{ background: #1f6feb; border-color: #1f6feb; }}
.token-row {{ background: #161b22; border-bottom: 1px solid #30363d; padding: 8px 20px; display: flex; align-items: center; gap: 10px; }}
.token-row label {{ font-size: 12px; color: #7d8590; white-space: nowrap; }}
.token-row textarea {{ background: #0d1117; border: 1px solid #30363d; color: #e6edf3; padding: 6px 10px; border-radius: 6px; font-size: 12px; font-family: monospace; flex: 1; resize: vertical; min-height: 32px; max-height: 120px; line-height: 1.4; }}
.token-row textarea:focus {{ border-color: #58a6ff; outline: none; }}
.token-row .btn {{ flex-shrink: 0; }}
.video-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 12px; padding: 16px; flex: 1; }}
.video-cell {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; position: relative; aspect-ratio: 16/9; }}
/* The Agora SDK injects <video> inside a wrapper div; make the wrapper fill the cell. */
.video-cell > div {{ position: absolute; inset: 0; }}
.video-cell video {{ width: 100%; height: 100%; object-fit: cover; }}
.video-label {{ position: absolute; bottom: 8px; left: 8px; background: rgba(0,0,0,0.7); padding: 3px 8px; border-radius: 4px; font-size: 12px; color: #e6edf3; }}
.status-bar {{ background: #161b22; border-top: 1px solid #30363d; padding: 8px 20px; font-size: 12px; color: #7d8590; display: flex; justify-content: space-between; }}
.status-dot {{ display: inline-block; width: 8px; height: 8px; border-radius: 50%; margin-right: 6px; vertical-align: middle; }}
.status-dot.disconnected {{ background: #7d8590; }}
.status-dot.connected {{ background: #3fb950; }}
.status-dot.connecting {{ background: #d29922; }}
.stats-panel {{ display: none; background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 12px 16px; margin: 0 16px; font-size: 12px; font-family: monospace; color: #7d8590; line-height: 1.6; }}
.stats-panel.visible {{ display: block; }}
#log {{ max-height: 200px; overflow-y: auto; padding: 8px 16px; font-size: 11px; font-family: monospace; color: #7d8590; }}
#log div {{ padding: 1px 0; }}
#log .error   {{ color: #f85149; }}
#log .warning {{ color: #d29922; }}
#log .success {{ color: #3fb950; }}
.copy-btn {{ background: none; border: 1px solid #555; color: #8b949e; padding: 2px 8px; border-radius: 4px; cursor: pointer; font-size: 12px; margin-left: 6px; }}
.copy-btn:hover {{ border-color: #58a6ff; color: #c9d1d9; }}
.device-banner {{ margin: 8px 16px; padding: 10px 14px; border-radius: 6px; font-size: 13px; line-height: 1.5; }}
.device-banner.warning {{ background: #2d1f00; border: 1px solid #d29922; color: #e3b341; }}
.device-banner.info {{ background: #0d1f2d; border: 1px solid #388bfd; color: #79c0ff; }}
.device-banner.success {{ background: #0d2818; border: 1px solid #3fb950; color: #56d364; }}
.device-banner .grant-btn {{ background: #388bfd; color: #fff; border: none; padding: 4px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; margin-left: 8px; }}
.device-banner .grant-btn:hover {{ background: #58a6ff; }}
/* Block sections — General / RTC / RTM */
.block {{ margin: 16px 20px; border: 1px solid #30363d; border-radius: 8px; background: #161b22; overflow: hidden; }}
.block-title {{ padding: 10px 16px; background: #1c2128; border-bottom: 1px solid #30363d; font-size: 14px; font-weight: 600; color: #c9d1d9; }}
.block .controls, .block .token-row {{ border-bottom: 1px solid #30363d; background: transparent; }}
.block .controls:last-child, .block .token-row:last-child, .block .status-bar {{ border-bottom: none; }}
.app-id-value {{ font-family: monospace; font-size: 13px; color: #c9d1d9; }}
.btn:disabled {{ opacity: 0.5; cursor: not-allowed; }}
#slogan {{ font-size: 13px; font-weight: 400; color: #7d8590; }}
{rtm_css}
</style>
</head>
<body>

<div class="header">
  <h1>Welcome to Agora, <span id="slogan">real-time is the only time</span></h1>
</div>

<!-- ── General ─────────────────────────────────────────────────── -->
<section class="block">
  <h2 class="block-title">General</h2>
  <div class="controls">
    <label>App ID</label>
    <span class="app-id-value">{app_id_display}</span>
    <button class="copy-btn" onclick="copyText('{app_id}')">Copy</button>
  </div>
  <div class="controls">
    <label>Channel</label>
    <input id="channelInput" type="text" value="{default_channel}" placeholder="channel name" oninput="updateFetchState()">
  </div>
  <div class="token-row">
    <label>Access Token</label>
    <textarea id="tokenInput" rows="1" placeholder="Auto-generated on Join — or paste your own token here"></textarea>
    <button id="fetchBtn" class="btn btn-mute" onclick="fetchToken()" disabled>Fetch</button>
    <button class="copy-btn" onclick="copyText(document.getElementById('tokenInput').value)">Copy</button>
  </div>
</section>

<!-- ── RTC ─────────────────────────────────────────────────────── -->
<section class="block">
  <h2 class="block-title"><span class="status-dot disconnected" id="statusDot"></span>RTC — <span id="statusText" style="font-weight:400;color:#7d8590">Disconnected</span></h2>
  <div class="controls">
    <label>UID</label>
    <input id="uidInput" type="text" placeholder="auto" value="{default_uid}" style="width:100px" oninput="updateFetchState()">
    <button id="joinBtn" class="btn btn-join" onclick="doJoin()">Join</button>
    <button id="leaveBtn" class="btn btn-leave" onclick="doLeave()">Leave</button>
    <button id="muteAudioBtn" class="btn btn-mute" onclick="toggleMuteAudio()">Mute Mic</button>
    <button id="muteVideoBtn" class="btn btn-mute" onclick="toggleMuteVideo()">Mute Cam</button>
    <button id="statsBtn" class="btn btn-stats" onclick="toggleStats()">Stats</button>
    <span id="networkQuality" style="margin-left:auto;font-size:12px;color:#7d8590"></span>
  </div>
  <div id="deviceBanner" class="device-banner" style="display:none"></div>
  <div id="statsPanel" class="stats-panel"></div>
  <div class="video-grid" id="videoGrid">
    <div class="video-cell" id="localCell" style="display:none">
      <div id="localVideo"></div>
      <span class="video-label" id="localLabel">Local</span>
    </div>
  </div>
  <div id="log"></div>
</section>

{rtm_section}

<script src="https://download.agora.io/sdk/release/AgoraRTC_N-4.23.0.js"></script>
{rtm_sdk_script}
<script>
const APP_ID = "{app_id}";
function copyText(text) {{
  if (!text) return;
  navigator.clipboard.writeText(text).then(() => {{
    log('Copied to clipboard', 'success');
  }});
}}
let client = null;
let localAudio = null;
let localVideo = null;
let audioMuted = false;
let videoMuted = false;
let creatingAudio = false;
let creatingVideo = false;
let hasMic = false;
let hasCam = false;
let permissionGranted = false;

async function checkDevices() {{
  const banner = document.getElementById('deviceBanner');
  try {{
    const devices = await navigator.mediaDevices.enumerateDevices();
    hasMic = devices.some(d => d.kind === 'audioinput' && d.deviceId);
    hasCam = devices.some(d => d.kind === 'videoinput' && d.deviceId);
    // If labels are empty, permission not yet granted
    const hasLabels = devices.some(d => d.label);

    if (!hasMic && !hasCam) {{
      banner.className = 'device-banner warning';
      banner.innerHTML = 'No microphone or camera detected. You can still join as a viewer.';
      banner.style.display = '';
    }} else if (!hasLabels) {{
      banner.className = 'device-banner info';
      banner.innerHTML = 'Microphone and camera access needed for audio/video. <button class="grant-btn" onclick="requestPermission()">Grant Access</button>';
      banner.style.display = '';
    }} else {{
      const parts = [];
      if (hasMic) parts.push('Mic');
      if (hasCam) parts.push('Camera');
      banner.className = 'device-banner success';
      banner.innerHTML = parts.join(' + ') + ' ready';
      banner.style.display = '';
      permissionGranted = true;
    }}
  }} catch (e) {{
    banner.className = 'device-banner warning';
    banner.innerHTML = 'Cannot detect devices: ' + e.message;
    banner.style.display = '';
  }}
}}

async function requestPermission() {{
  const banner = document.getElementById('deviceBanner');
  try {{
    const stream = await navigator.mediaDevices.getUserMedia({{ audio: true, video: true }});
    stream.getTracks().forEach(t => t.stop());
    permissionGranted = true;
    await checkDevices();
    log('Device access granted', 'success');
  }} catch (e) {{
    if (e.name === 'NotAllowedError') {{
      banner.className = 'device-banner warning';
      banner.innerHTML = 'Permission denied. Check browser settings to allow microphone/camera access.';
      log('Device permission denied', 'error');
    }} else if (e.name === 'NotFoundError') {{
      // Try audio only
      try {{
        const stream = await navigator.mediaDevices.getUserMedia({{ audio: true }});
        stream.getTracks().forEach(t => t.stop());
        permissionGranted = true;
        await checkDevices();
        log('Microphone access granted (no camera)', 'success');
      }} catch (e2) {{
        banner.className = 'device-banner warning';
        banner.innerHTML = 'No devices available. You can join as a viewer.';
        log('No media devices found', 'warning');
      }}
    }} else {{
      banner.className = 'device-banner warning';
      banner.innerHTML = 'Device error: ' + e.message;
      log('Device error: ' + e.message, 'error');
    }}
  }}
}}

checkDevices();
let statsInterval = null;

function log(msg, cls) {{
  const el = document.getElementById('log');
  const d = document.createElement('div');
  d.textContent = '[' + new Date().toLocaleTimeString() + '] ' + msg;
  if (cls) d.className = cls;
  el.appendChild(d);
  el.scrollTop = el.scrollHeight;
}}

function setStatus(state, text) {{
  const dot = document.getElementById('statusDot');
  const txt = document.getElementById('statusText');
  dot.className = 'status-dot ' + state;
  txt.textContent = text;
}}

// Mirror the server-side RtcAccount::parse rules exactly:
//   - all digits         → int uid (uint32)
//   - non-digits         → string account
//   - `s/` prefix        → string account (prefix stripped — so s/1232 means "1232" as string)
// Never silently coerces "423dd" to 423 like parseInt does.
//
// Returns:
//   kind       : 'int' | 'str'
//   num        : Number when kind==='int'
//   account    : String when kind==='str' (stripped of s/ prefix)
//   tokenArg   : what to send in the /api/token "uid" field (raw input is fine;
//                server understands s/ prefix). We just send the unmodified raw.
//   joinArg    : what to pass to AgoraRTC client.join (number or string)
//   label      : human-readable mode tag for logs
function classifyUid(raw) {{
  if (!raw) return {{ kind: 'int', num: 0, account: '',  tokenArg: '0',   joinArg: null,  label: 'int (auto)' }};

  // Rule 3 first — "s/" prefix forces string even for all-digit payloads
  if (raw.startsWith('s/')) {{
    const stripped = raw.slice(2);
    return {{ kind: 'str', num: 0, account: stripped, tokenArg: raw, joinArg: stripped, label: 'string account' }};
  }}
  // Rule 1 — all digits within u32 range
  if (/^\d+$/.test(raw)) {{
    const n = Number(raw);
    if (Number.isFinite(n) && n >= 0 && n <= 4294967295) {{
      return {{ kind: 'int', num: n, account: '', tokenArg: String(n), joinArg: n, label: 'int' }};
    }}
  }}
  // Rule 2 — fallback: everything else is a string account
  return {{ kind: 'str', num: 0, account: raw, tokenArg: raw, joinArg: raw, label: 'string account' }};
}}

async function fetchToken() {{
  const channel = document.getElementById('channelInput').value.trim() || 'test';
  const uidInput = document.getElementById('uidInput').value.trim();
  const uidKind = classifyUid(uidInput);

  // When the RTM panel is present, include the requested RTM user so the
  // fetched token covers both RTC + RTM for a consistent (uid, rtm_user) pair.
  // The server may override rtm_user_id when --rtm-user-id was pinned; we
  // reflect the authoritative value back into the input below.
  // Send the raw uid as typed. The server's RtcAccount::parse mirrors the
  // client rules: "423" → int, "423dd" → string, "s/1232" → string "1232".
  const body = {{ channel: channel, uid: uidKind.tokenArg }};
  const rtmInput = document.getElementById('rtmUserInput');
  if (rtmInput) {{
    const requested = rtmInput.value.trim();
    if (requested) body.rtm_user_id = requested;
  }}

  try {{
    const resp = await fetch('/api/token', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify(body)
    }});
    const data = await resp.json();
    if (data.error) throw new Error(data.error);
    document.getElementById('tokenInput').value = data.token;

    log('Token fetched' + (data.with_rtm ? ' (RTC + RTM)' : ''), 'success');
  }} catch (err) {{
    log('Fetch token error: ' + err.message, 'error');
  }}
}}

async function doJoin() {{
  const channel = document.getElementById('channelInput').value.trim() || 'test';
  const uidInput = document.getElementById('uidInput').value.trim();
  const uidKind = classifyUid(uidInput);
  // Agora RTC Web SDK accepts either a number (int uid) or a string (user
  // account). classifyUid gives us the correctly-typed value — never
  // coerced. `joinArg` is null when uid=0 (auto-assign by server).
  const joinUid = uidKind.joinArg;

  setStatus('connecting', 'Connecting...');
  log('Joining channel: ' + channel + ' uid: ' + (joinUid === null ? 'auto' : joinUid)
      + ' (' + uidKind.label + ')');

  // Use the token that's already in the textbox. If the user edited
  // channel/UID without clicking Fetch, the token won't match and the
  // RTC server rejects with invalid-token — which is what we want.
  const token = document.getElementById('tokenInput').value.trim();
  if (!token) {{
    log('No token — click Fetch first', 'error');
    setStatus('disconnected', 'No token');
    return;
  }}
  try {{
    log('Using token from textbox', 'success');
    console.log('App ID:', APP_ID);
    console.log('Channel:', channel);
    console.log('Token:', token);

    // Create client
    client = AgoraRTC.createClient({{ mode: 'rtc', codec: 'vp8' }});

    client.on('user-published', async (user, mediaType) => {{
      await client.subscribe(user, mediaType);
      log('Subscribed to user ' + user.uid + ' (' + mediaType + ')', 'success');
      if (mediaType === 'video') {{
        addRemoteVideo(user);
      }}
      if (mediaType === 'audio') {{
        user.audioTrack.play();
      }}
    }});

    client.on('user-unpublished', (user, mediaType) => {{
      log('User ' + user.uid + ' unpublished ' + mediaType);
      if (mediaType === 'video') {{
        removeRemoteVideo(user.uid);
      }}
    }});

    client.on('user-left', (user) => {{
      log('User ' + user.uid + ' left');
      removeRemoteVideo(user.uid);
    }});

    client.on('network-quality', (stats) => {{
      const q = ['', 'Excellent', 'Good', 'Poor', 'Bad', 'Very Bad', 'Down'];
      const up = q[stats.uplinkNetworkQuality] || 'Unknown';
      const down = q[stats.downlinkNetworkQuality] || 'Unknown';
      document.getElementById('networkQuality').textContent = 'Up: ' + up + ' / Down: ' + down;
    }});

    client.on('connection-state-change', (curState, prevState) => {{
      log('Connection: ' + prevState + ' -> ' + curState);
      if (curState === 'CONNECTED') {{
        setStatus('connected', 'Connected - ' + channel);
      }} else if (curState === 'RECONNECTING') {{
        setStatus('connecting', 'Reconnecting...');
      }} else if (curState === 'DISCONNECTED') {{
        setStatus('disconnected', 'Disconnected');
      }}
    }});

    // Join
    const joinedUid = await client.join(APP_ID, channel, token, joinUid);
    log('Joined as uid: ' + joinedUid, 'success');
    document.getElementById('joinBtn').style.display = 'none';
    document.getElementById('leaveBtn').style.display = '';

    // Create local tracks (skip gracefully if no devices)
    const tracks = [];
    try {{
      localAudio = await AgoraRTC.createMicrophoneAudioTrack();
      tracks.push(localAudio);
    }} catch (e) {{
      log('No microphone found, joining without audio', 'warning');
    }}
    try {{
      localVideo = await AgoraRTC.createCameraVideoTrack();
      tracks.push(localVideo);
      const localCell = document.getElementById('localCell');
      localCell.style.display = '';
      localVideo.play('localVideo');
    }} catch (e) {{
      log('No camera found, joining without video', 'warning');
    }}
    document.getElementById('localLabel').textContent = 'Local (uid: ' + joinedUid + ')';

    if (tracks.length > 0) {{
      await client.publish(tracks);
      log('Published local tracks (' + tracks.length + ')', 'success');
    }} else {{
      log('No media devices, joined as viewer only', 'warning');
    }}

  }} catch (err) {{
    log('Error: ' + err.message, 'error');
    setStatus('disconnected', 'Error');
  }}
}}

async function doLeave() {{
  try {{
    if (localAudio) {{ localAudio.close(); localAudio = null; }}
    if (localVideo) {{ localVideo.close(); localVideo = null; }}
    if (client) {{ await client.leave(); client = null; }}

    document.getElementById('localCell').style.display = 'none';
    // Remove all remote cells
    document.querySelectorAll('.remote-cell').forEach(el => el.remove());

    audioMuted = false;
    videoMuted = false;
    document.getElementById('muteAudioBtn').classList.remove('active');
    document.getElementById('muteAudioBtn').textContent = 'Mute Mic';
    document.getElementById('muteVideoBtn').classList.remove('active');
    document.getElementById('muteVideoBtn').textContent = 'Mute Cam';

    setStatus('disconnected', 'Disconnected');
    document.getElementById('joinBtn').style.display = '';
    document.getElementById('leaveBtn').style.display = 'none';
    document.getElementById('networkQuality').textContent = '';
    log('Left channel');
  }} catch (err) {{
    log('Leave error: ' + err.message, 'error');
  }}
}}

function addRemoteVideo(user) {{
  let cell = document.getElementById('remote-' + user.uid);
  if (!cell) {{
    cell = document.createElement('div');
    cell.className = 'video-cell remote-cell';
    cell.id = 'remote-' + user.uid;
    cell.innerHTML = '<div id="player-' + user.uid + '"></div><span class="video-label">Remote (uid: ' + user.uid + ')</span>';
    document.getElementById('videoGrid').appendChild(cell);
  }}
  user.videoTrack.play('player-' + user.uid);
}}

function removeRemoteVideo(uid) {{
  const cell = document.getElementById('remote-' + uid);
  if (cell) cell.remove();
}}

async function toggleMuteAudio() {{
  if (!client) return;
  if (creatingAudio) return;
  const btn = document.getElementById('muteAudioBtn');
  if (!localAudio) {{
    creatingAudio = true;
    try {{
      localAudio = await AgoraRTC.createMicrophoneAudioTrack();
      await client.publish([localAudio]);
      audioMuted = false;
      btn.classList.remove('active');
      btn.textContent = 'Mute Mic';
      log('Microphone enabled', 'success');
    }} catch (e) {{
      log('Cannot access microphone: ' + e.message, 'error');
    }} finally {{
      creatingAudio = false;
    }}
    return;
  }}
  audioMuted = !audioMuted;
  await localAudio.setEnabled(!audioMuted);
  btn.classList.toggle('active', audioMuted);
  btn.textContent = audioMuted ? 'Unmute Mic' : 'Mute Mic';
}}

async function toggleMuteVideo() {{
  if (!client) return;
  if (creatingVideo) return;
  const btn = document.getElementById('muteVideoBtn');
  if (!localVideo) {{
    creatingVideo = true;
    try {{
      localVideo = await AgoraRTC.createCameraVideoTrack();
      await client.publish([localVideo]);
      const localCell = document.getElementById('localCell');
      localCell.style.display = '';
      localVideo.play('localVideo');
      videoMuted = false;
      btn.classList.remove('active');
      btn.textContent = 'Mute Cam';
      log('Camera enabled', 'success');
    }} catch (e) {{
      log('Cannot access camera: ' + e.message, 'error');
    }} finally {{
      creatingVideo = false;
    }}
    return;
  }}
  videoMuted = !videoMuted;
  await localVideo.setEnabled(!videoMuted);
  btn.classList.toggle('active', videoMuted);
  btn.textContent = videoMuted ? 'Unmute Cam' : 'Mute Cam';
}}

function toggleStats() {{
  const panel = document.getElementById('statsPanel');
  const btn = document.getElementById('statsBtn');
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
  if (!client) {{ document.getElementById('statsPanel').textContent = 'Not connected'; return; }}
  try {{
    const rtcStats = client.getRTCStats();
    const localStats = localVideo ? client.getLocalVideoStats() : {{}};
    let text = 'Duration: ' + rtcStats.Duration + 's\n';
    text += 'Users: ' + rtcStats.UserCount + '\n';
    text += 'Send bitrate: ' + ((rtcStats.SendBitrate || 0) / 1000).toFixed(0) + ' kbps\n';
    text += 'Recv bitrate: ' + ((rtcStats.RecvBitrate || 0) / 1000).toFixed(0) + ' kbps\n';
    if (localStats.sendResolutionWidth) {{
      text += 'Video: ' + localStats.sendResolutionWidth + 'x' + localStats.sendResolutionHeight + ' @ ' + localStats.sendFrameRate + 'fps\n';
    }}
    document.getElementById('statsPanel').textContent = text;
  }} catch(e) {{
    document.getElementById('statsPanel').textContent = 'Error: ' + e.message;
  }}
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

// ── Fetch button enable/disable ─────────────────────────────────
// Enabled only when all required user-id fields are filled. The token
// is NOT auto-cleared when inputs change — the user drives it: if they
// edit without clicking Fetch, Join/Login will use the stale token and
// the server will reject with an invalid-token error, which is
// intentional and informative.
function updateFetchState() {{
  const channel = document.getElementById('channelInput').value.trim();
  const uid     = document.getElementById('uidInput').value.trim();
  const rtmIn   = document.getElementById('rtmUserInput');
  const rtmVal  = rtmIn ? rtmIn.value.trim() : 'n/a';
  const ok = channel && uid && rtmVal;
  const btn = document.getElementById('fetchBtn');
  if (btn) btn.disabled = !ok;
}}
updateFetchState();

// Auto-fetch on load only if all inputs are ready.
if (!document.getElementById('fetchBtn').disabled) {{
  fetchToken();
}}

{rtm_js}
</script>
</body>
</html>"##,
        app_id_display = app_id_display,
        default_channel = default_channel,
        default_uid = default_uid,
        app_id = app_id,
        rtm_css = rtm_css,
        rtm_section = rtm_section,
        rtm_sdk_script = rtm_sdk_script,
        rtm_js = rtm_js,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_lan_ip_returns_non_unspecified() {
        let ip = get_lan_ip();
        // Should be a real IP or localhost, never 0.0.0.0
        assert!(!ip.is_unspecified());
    }

    #[test]
    fn sslip_host_formats_correctly() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42));
        assert_eq!(sslip_host(&ip), "192-168-1-42.sslip.io");
    }

    #[test]
    fn html_page_contains_app_id_and_channel() {
        let html = build_html_page(
            "abc123def456ghij", "my-test-channel", "0", false, "0",
        );
        assert!(html.contains("abc123...ghij")); // truncated display
        assert!(html.contains("my-test-channel"));
        assert!(html.contains("abc123def456ghij")); // full ID in JS config
    }

    #[test]
    fn html_page_has_rtm_section_when_enabled() {
        let html = build_html_page(
            "abc123def456ghij", "chan", "42", true, "alice",
        );
        // RTM SDK loaded
        assert!(html.contains("agora-rtm"), "RTM SDK script missing");
        // RTM UI region visible
        assert!(html.contains("Signaling"),      "RTM UI header missing");
        assert!(html.contains("rtmLoginBtn"),    "RTM login button missing");
        assert!(html.contains("rtmSendBtn"),     "RTM send button missing");
        // Default RTM user is embedded
        assert!(html.contains("alice"),          "default RTM user missing");
    }

    #[test]
    fn html_page_has_no_rtm_section_when_disabled() {
        let html = build_html_page(
            "abc123def456ghij", "chan", "42", false, "0",
        );
        assert!(!html.contains("Signaling"),   "RTM UI should not render without --with-rtm");
        assert!(!html.contains("rtmLoginBtn"), "RTM button should not render");
    }

    #[test]
    fn server_id_format() {
        assert_eq!(server_id("rtc", "demo", 8443), "rtc-demo-8443");
        assert_eq!(server_id("rtc", "test", 0), "rtc-test-0");
    }

    #[test]
    fn servers_dir_under_config() {
        let dir = servers_dir();
        let dir_str = dir.to_string_lossy();
        assert!(dir_str.contains("atem"));
        assert!(dir_str.ends_with("servers"));
    }
}

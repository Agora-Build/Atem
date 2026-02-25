use anyhow::Result;
use rcgen::{CertificateParams, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

/// Configuration for the RTC test server.
pub struct RtcTestConfig {
    pub channel: String,
    pub port: u16,
    pub expire_secs: u32,
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

/// Generate a self-signed TLS certificate for the given IP address,
/// its sslip.io hostname, and localhost.
pub fn generate_self_signed_cert(
    ip: &IpAddr,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let sslip = sslip_host(ip);

    let mut params = CertificateParams::new(vec![sslip.clone(), "localhost".to_string()])?;
    params
        .subject_alt_names
        .push(SanType::IpAddress((*ip).into()));

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der().to_vec()));

    Ok((vec![cert_der], key_der))
}

/// Run the HTTPS server for RTC testing.
pub async fn run_server(config: RtcTestConfig) -> Result<()> {
    let app_id = crate::config::ActiveProject::resolve_app_id(None)?;
    let app_certificate = crate::config::ActiveProject::resolve_app_certificate(None)?;

    let lan_ip = get_lan_ip();
    let sslip = sslip_host(&lan_ip);

    // Generate self-signed cert
    let (certs, key) = generate_self_signed_cert(&lan_ip)?;

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

        let child = std::process::Command::new(exe)
            .args([
                "serv",
                "rtc",
                "--channel",
                &config.channel,
                "--port",
                &port.to_string(),
                "--expire",
                &config.expire_secs.to_string(),
                "--no-browser",
                "--serv-daemon",
            ])
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

    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let app_id = app_id.clone();
        let app_certificate = app_certificate.clone();
        let channel = channel.clone();

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
            )
            .await
            {
                eprintln!("[{}] Error: {}", peer, e);
            }
        });
    }
}

/// Handle a single TLS connection — parse the HTTP request and route.
async fn handle_connection(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    _peer: SocketAddr,
    app_id: &str,
    app_certificate: &str,
    default_channel: &str,
    expire_secs: u32,
) -> Result<()> {
    let mut buf = vec![0u8; 8192];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let request = String::from_utf8_lossy(&buf[..n]);

    // Parse first line: METHOD PATH HTTP/1.x
    let first_line = request.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        send_response(&mut stream, 400, "text/plain", b"Bad Request").await?;
        return Ok(());
    }
    let method = parts[0];
    let path = parts[1];

    match (method, path) {
        ("GET", "/") => {
            let html = build_html_page(app_id, default_channel);
            send_response(&mut stream, 200, "text/html; charset=utf-8", html.as_bytes()).await?;
        }
        ("GET", "/favicon.ico") => {
            send_response(&mut stream, 204, "text/plain", b"").await?;
        }
        ("POST", "/api/token") => {
            // Extract JSON body
            let body = extract_body(&request);
            handle_token_api(&mut stream, &body, app_id, app_certificate, expire_secs).await?;
        }
        _ => {
            send_response(&mut stream, 404, "text/plain", b"Not Found").await?;
        }
    }

    Ok(())
}

/// Extract the HTTP body (after the blank line).
fn extract_body(request: &str) -> String {
    if let Some(idx) = request.find("\r\n\r\n") {
        request[idx + 4..].to_string()
    } else if let Some(idx) = request.find("\n\n") {
        request[idx + 2..].to_string()
    } else {
        String::new()
    }
}

/// Handle POST /api/token — generate an RTC token.
async fn handle_token_api(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    body: &str,
    app_id: &str,
    app_certificate: &str,
    expire_secs: u32,
) -> Result<()> {
    // Parse body as JSON: { "channel": "...", "uid": "..." }
    let parsed: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            let err = r#"{"error":"Invalid JSON body"}"#;
            send_response(stream, 400, "application/json", err.as_bytes()).await?;
            return Ok(());
        }
    };

    let channel = parsed["channel"].as_str().unwrap_or("test");
    let uid = parsed["uid"].as_str().unwrap_or("0");

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

    let token = match crate::token::build_token_rtc(
        app_id,
        app_certificate,
        channel,
        uid,
        crate::token::Role::Publisher,
        expire_secs,
        now,
    ) {
        Ok(t) => t,
        Err(e) => {
            let err = serde_json::json!({"error": format!("Token generation failed: {}", e)});
            send_response(stream, 500, "application/json", err.to_string().as_bytes()).await?;
            return Ok(());
        }
    };

    let resp = serde_json::json!({
        "token": token,
        "app_id": app_id,
        "channel": channel,
        "uid": uid,
    });

    send_response(stream, 200, "application/json", resp.to_string().as_bytes()).await?;
    Ok(())
}

/// Write an HTTP response.
async fn send_response(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let status_text = match status {
        200 => "OK",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Unknown",
    };

    let header = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
        status, status_text, content_type, body.len()
    );

    stream.write_all(header.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

/// Open a URL in the default browser.
fn open_browser(url: &str) -> Result<()> {
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
fn build_html_page(app_id: &str, default_channel: &str) -> String {
    let app_id_display = if app_id.len() > 12 {
        format!("{}...{}", &app_id[..6], &app_id[app_id.len() - 4..])
    } else {
        app_id.to_string()
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
#log .error {{ color: #f85149; }}
#log .success {{ color: #3fb950; }}
.copy-btn {{ background: none; border: 1px solid #555; color: #8b949e; padding: 2px 8px; border-radius: 4px; cursor: pointer; font-size: 12px; margin-left: 6px; }}
.copy-btn:hover {{ border-color: #58a6ff; color: #c9d1d9; }}
</style>
</head>
<body>

<div class="header">
  <h1>Hello, Agora RTC</h1>
  <span class="app-id">App ID: {app_id_display} <button class="copy-btn" onclick="copyText('{app_id}')">Copy</button></span>
</div>

<div class="controls">
  <label>Channel</label>
  <input id="channelInput" type="text" value="{default_channel}" placeholder="channel name">
  <label>UID</label>
  <input id="uidInput" type="text" placeholder="auto" style="width:100px">
  <button id="joinBtn" class="btn btn-join" onclick="doJoin()">Join</button>
  <button id="leaveBtn" class="btn btn-leave" onclick="doLeave()">Leave</button>
  <button id="muteAudioBtn" class="btn btn-mute" onclick="toggleMuteAudio()">Mute Mic</button>
  <button id="muteVideoBtn" class="btn btn-mute" onclick="toggleMuteVideo()">Mute Cam</button>
  <button id="statsBtn" class="btn btn-stats" onclick="toggleStats()">Stats</button>
</div>

<div class="token-row">
  <label>Access Token</label>
  <textarea id="tokenInput" rows="1" placeholder="Auto-generated on Join — or paste your own token here"></textarea>
  <button class="btn btn-mute" onclick="fetchToken()">Fetch</button>
  <button class="copy-btn" onclick="copyText(document.getElementById('tokenInput').value)">Copy</button>
</div>

<div id="statsPanel" class="stats-panel"></div>

<div class="video-grid" id="videoGrid">
  <div class="video-cell" id="localCell" style="display:none">
    <div id="localVideo"></div>
    <span class="video-label" id="localLabel">Local</span>
  </div>
</div>

<div id="log"></div>

<div class="status-bar">
  <span><span class="status-dot disconnected" id="statusDot"></span><span id="statusText">Disconnected</span></span>
  <span id="networkQuality"></span>
</div>

<script src="https://download.agora.io/sdk/release/AgoraRTC_N-4.22.0.js"></script>
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

async function fetchToken() {{
  const channel = document.getElementById('channelInput').value.trim() || 'test';
  const uidInput = document.getElementById('uidInput').value.trim();
  const uid = uidInput ? parseInt(uidInput) || 0 : 0;

  try {{
    const resp = await fetch('/api/token', {{
      method: 'POST',
      headers: {{ 'Content-Type': 'application/json' }},
      body: JSON.stringify({{ channel: channel, uid: String(uid) }})
    }});
    const data = await resp.json();
    if (data.error) throw new Error(data.error);
    document.getElementById('tokenInput').value = data.token;
    log('Token fetched', 'success');
  }} catch (err) {{
    log('Fetch token error: ' + err.message, 'error');
  }}
}}

async function doJoin() {{
  const channel = document.getElementById('channelInput').value.trim() || 'test';
  const uidInput = document.getElementById('uidInput').value.trim();
  const uid = uidInput ? parseInt(uidInput) || 0 : 0;

  setStatus('connecting', 'Connecting...');
  log('Joining channel: ' + channel + ' uid: ' + (uid || 'auto'));

  try {{
    // Use token from textarea, or fetch one if empty
    let token = document.getElementById('tokenInput').value.trim();
    if (!token) {{
      const resp = await fetch('/api/token', {{
        method: 'POST',
        headers: {{ 'Content-Type': 'application/json' }},
        body: JSON.stringify({{ channel: channel, uid: String(uid) }})
      }});
      const data = await resp.json();
      if (data.error) throw new Error(data.error);
      token = data.token;
      document.getElementById('tokenInput').value = token;
    }}
    log('Token received', 'success');
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

    // Join
    const joinedUid = await client.join(APP_ID, channel, token, uid || null);
    log('Joined as uid: ' + joinedUid, 'success');

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

    setStatus('connected', 'Connected - ' + channel);
    document.getElementById('joinBtn').style.display = 'none';
    document.getElementById('leaveBtn').style.display = '';

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
  const btn = document.getElementById('muteAudioBtn');
  if (!localAudio) {{
    try {{
      localAudio = await AgoraRTC.createMicrophoneAudioTrack();
      await client.publish([localAudio]);
      audioMuted = false;
      btn.classList.remove('active');
      btn.textContent = 'Mute Mic';
      log('Microphone enabled', 'success');
    }} catch (e) {{
      log('Cannot access microphone: ' + e.message, 'error');
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
  const btn = document.getElementById('muteVideoBtn');
  if (!localVideo) {{
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

// Pre-fill token on page load
fetchToken();
</script>
</body>
</html>"##,
        app_id_display = app_id_display,
        default_channel = default_channel,
        app_id = app_id,
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
    fn generate_cert_succeeds() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let result = generate_self_signed_cert(&ip);
        assert!(result.is_ok());
        let (certs, _key) = result.unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn html_page_contains_app_id_and_channel() {
        let html = build_html_page("abc123def456ghij", "my-test-channel");
        assert!(html.contains("abc123...ghij")); // truncated display
        assert!(html.contains("my-test-channel"));
        assert!(html.contains("abc123def456ghij")); // full ID in JS config
    }

    #[test]
    fn extract_body_from_http_request() {
        let req = "POST /api/token HTTP/1.1\r\nHost: localhost\r\nContent-Length: 37\r\n\r\n{\"channel\":\"test\",\"uid\":\"123\"}";
        let body = extract_body(req);
        assert_eq!(body, "{\"channel\":\"test\",\"uid\":\"123\"}");
    }

    #[test]
    fn extract_body_empty_when_no_blank_line() {
        let req = "GET / HTTP/1.1\r\nHost: localhost";
        let body = extract_body(req);
        assert!(body.is_empty());
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

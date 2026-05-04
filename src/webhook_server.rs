//! `atem serv webhooks` — local server for receiving Agora webhook events
//! (ConvoAI events 101/102/103/110/111, RTC channel events, etc.).
//!
//! Default flow:
//!   1. Bind a plain HTTP listener on `--port` (default 9090).
//!   2. Optionally spawn `ngrok http <port>` as a child process to
//!      get a public HTTPS URL Agora can POST to.
//!   3. Print local + public URLs so the operator can paste the
//!      public URL into Agora Console → NCS / ConvoAI webhook settings.
//!   4. POST /webhook handler validates Agora-Signature-V2 (skipped
//!      when no secret is configured), responds 200 immediately, and
//!      broadcasts the event to web console clients via SSE.
//!   5. GET / serves a live event console (auto-scrolling list).
//!   6. Each event is also printed as a one-line summary to stdout —
//!      `--background` redirects this to `<id>.log` in the registry.

use anyhow::Result;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::broadcast;

const DEFAULT_PORT: u16 = 9090;
/// SSE keepalive — browsers drop idle connections after ~30s.
const SSE_KEEPALIVE_SECS: u64 = 15;

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
pub struct WebhooksFile {
    /// Local HTTP port. Default 9090.
    pub port: Option<u16>,
    /// HMAC secret used to validate `Agora-Signature-V2`. Empty / unset
    /// → skip signature validation (events accepted unsigned, with a
    /// banner warning so the operator notices in dev).
    pub secret: Option<String>,
    /// Spawn a tunnel to get a public URL. Default true.
    pub tunnel: Option<bool>,
    /// Tunnel provider: "ngrok" (default) or "cloudflared".
    /// - "ngrok"        — uses your authtoken (set via `ngrok config add-authtoken`).
    ///                    Free tier: 1 random URL, changes per launch.
    /// - "cloudflared"  — quick tunnel; no account / authtoken needed.
    ///                    Always random `*.trycloudflare.com` URL.
    pub tunnel_provider: Option<String>,
    /// Optional ngrok reserved domain (paid feature). When unset,
    /// ngrok assigns a random `*.ngrok-free.app` host. Ignored for
    /// non-ngrok providers.
    pub ngrok_domain: Option<String>,
}

pub struct ServeWebhooksConfig {
    pub config_path: Option<PathBuf>,
    pub port:        u16,
    pub no_tunnel:   bool,
    pub no_browser:  bool,
    pub background:  bool,
    pub _daemon:     bool,
}

/// One event captured by the server. Sent to SSE clients verbatim
/// and printed as a one-line summary to stdout.
#[derive(Clone, serde::Serialize)]
struct WebhookEvent {
    /// Unix epoch milliseconds when atem received the POST.
    received_ms: u64,
    /// Whether the signature passed (or was skipped when no secret set).
    signature_ok: bool,
    /// `eventType` field from the body, if it was a numeric int.
    event_type: Option<u64>,
    /// Friendly label for known event types ("agent_joined", etc.).
    label: String,
    /// Full JSON body verbatim.
    body: serde_json::Value,
    /// Raw remote address that sent the request (informational).
    remote: String,
}

/// Static mapping of `eventType` → friendly label. Adding a new event
/// is one row here. Unknown codes fall back to `unknown`.
const KNOWN_EVENTS: &[(u64, &str)] = &[
    // ConvoAI agent events
    (101, "agent_joined"),
    (102, "agent_left"),
    (103, "agent_history"),
    (110, "agent_error"),
    (111, "agent_metrics"),
    (201, "inbound_call_state"),
    (202, "outbound_call_state"),
    // RTC channel events (NCS — productId differs but eventType
    // codes are non-overlapping with ConvoAI's). Add as needed.
    (103, "user_joined"),       // collision warning: agent_history vs user_joined
    (104, "user_left"),
    (105, "broadcaster_joined"),
    (106, "broadcaster_left"),
];

fn label_for(event_type: u64) -> String {
    // First-match-wins; if we ever need product-specific dispatch we'll
    // key on (productId, eventType) instead.
    KNOWN_EVENTS
        .iter()
        .find(|(c, _)| *c == event_type)
        .map(|(_, l)| (*l).to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Default config path: `~/.config/atem/webhooks.toml`.
fn default_config_path() -> PathBuf {
    crate::config::AtemConfig::config_dir().join("webhooks.toml")
}

fn load_file(path: &Path) -> Result<WebhooksFile> {
    if !path.exists() {
        return Ok(WebhooksFile::default());
    }
    let s = std::fs::read_to_string(path)?;
    Ok(toml::from_str(&s)?)
}

/// Validate `Agora-Signature-V2` against `secret`. Per Agora docs,
/// the signature is HMAC-SHA256(secret, raw_body) hex-encoded.
fn verify_signature(body: &[u8], secret: &str, sig_v2: Option<&str>) -> bool {
    let Some(sig) = sig_v2 else { return false };
    let mut mac = match Hmac::<Sha256>::new_from_slice(secret.as_bytes()) {
        Ok(m) => m,
        Err(_) => return false,
    };
    mac.update(body);
    let expected_bytes = mac.finalize().into_bytes();
    let expected_hex = expected_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    // constant-time comparison to avoid timing leaks
    constant_time_eq(expected_hex.as_bytes(), sig.as_bytes())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Tunnel providers atem knows how to spawn. Each variant has its
/// own quirks — see the spawn_* functions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TunnelProvider {
    Ngrok,
    Cloudflared,
}

impl TunnelProvider {
    fn parse(s: &str) -> Result<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "" | "ngrok" => Ok(Self::Ngrok),
            "cloudflared" | "cf" => Ok(Self::Cloudflared),
            other => anyhow::bail!(
                "Unknown tunnel_provider '{}' — valid: ngrok, cloudflared",
                other
            ),
        }
    }
    fn name(self) -> &'static str {
        match self {
            Self::Ngrok => "ngrok",
            Self::Cloudflared => "cloudflared",
        }
    }
}

/// Dispatch to the right spawn_* helper. Returns the tunnel process
/// + the public URL it announced.
async fn spawn_tunnel(
    provider: TunnelProvider,
    port:     u16,
    domain:   Option<&str>,
) -> Result<(std::process::Child, String)> {
    match provider {
        TunnelProvider::Ngrok       => spawn_ngrok(port, domain).await,
        TunnelProvider::Cloudflared => spawn_cloudflared(port).await,
    }
}

/// Spawn `cloudflared tunnel --url http://localhost:<port>` (quick
/// tunnel, no auth required) and parse the public `*.trycloudflare.com`
/// URL out of cloudflared's stderr. Returns the child process + URL.
///
/// Why we don't poll a local API like with ngrok: cloudflared has no
/// agent API. The URL is announced once on stderr at startup.
async fn spawn_cloudflared(port: u16) -> Result<(std::process::Child, String)> {
    let mut cmd = std::process::Command::new("cloudflared");
    cmd.arg("tunnel")
        .arg("--url")
        .arg(format!("http://localhost:{}", port))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| anyhow::anyhow!(
        "Failed to spawn cloudflared ({}). Install from https://github.com/cloudflare/cloudflared/releases or pass --no-tunnel.",
        e
    ))?;

    let stderr = child.stderr.take().expect("piped");
    let stdout = child.stdout.take().expect("piped");
    let (tx, rx) = tokio::sync::oneshot::channel::<String>();
    // Tail of stderr lines — when cloudflared fails to acquire a
    // tunnel (Cloudflare API outage, network error, etc.) atem needs
    // to surface the underlying message. Otherwise the user sees a
    // generic "no URL" error and has nothing actionable.
    let stderr_buf = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let stderr_buf_writer = stderr_buf.clone();

    // Drain stderr looking for the URL line. Continue draining after
    // the URL is found so the OS pipe doesn't fill up and back-pressure
    // cloudflared. Runs on a blocking thread because BufRead::lines()
    // is sync.
    std::thread::spawn(move || {
        use std::io::{BufRead, BufReader};
        let reader = BufReader::new(stderr);
        let mut tx = Some(tx);
        for line in reader.lines().map_while(|r| r.ok()) {
            // Keep last 30 lines for diagnostic on failure.
            if let Ok(mut v) = stderr_buf_writer.lock() {
                v.push(line.clone());
                if v.len() > 30 { let _ = v.remove(0); }
            }
            if let Some(t) = tx.take() {
                if let Some(url) = extract_trycloudflare_url(&line) {
                    let _ = t.send(url);
                } else {
                    tx = Some(t);
                }
            }
        }
    });
    // Drain stdout too — cloudflared mostly logs to stderr but sends
    // an occasional line to stdout.
    std::thread::spawn(move || {
        use std::io::{BufRead, BufReader};
        for _ in BufReader::new(stdout).lines() {}
    });

    let print_stderr_tail = |buf: &Arc<std::sync::Mutex<Vec<String>>>| {
        if let Ok(v) = buf.lock() {
            if v.is_empty() { return; }
            eprintln!("cloudflared stderr (last {} lines):", v.len());
            for line in v.iter() {
                eprintln!("  | {}", line);
            }
        }
    };

    match tokio::time::timeout(std::time::Duration::from_secs(15), rx).await {
        Ok(Ok(url)) => Ok((child, url)),
        Ok(Err(_)) => {
            let _ = child.kill();
            print_stderr_tail(&stderr_buf);
            anyhow::bail!("cloudflared exited before printing a tunnel URL — see stderr above")
        }
        Err(_) => {
            let _ = child.kill();
            print_stderr_tail(&stderr_buf);
            anyhow::bail!("cloudflared started but no `*.trycloudflare.com` URL appeared in stderr within 15s — see stderr above")
        }
    }
}

/// Pull a `https://<words>.trycloudflare.com` URL out of a cloudflared
/// stderr line. Returns None if the line doesn't carry one.
fn extract_trycloudflare_url(line: &str) -> Option<String> {
    let start = line.find("https://")?;
    let tail = &line[start..];
    let end = tail.find(|c: char| c.is_whitespace() || c == '|' || c == '"').unwrap_or(tail.len());
    let url = &tail[..end];
    if url.contains(".trycloudflare.com") {
        Some(url.to_string())
    } else {
        None
    }
}

/// Check if another ngrok process already owns the local agent API
/// at `127.0.0.1:4040`. Returns Ok(Some(addr)) when a foreign ngrok
/// is running with a tunnel forwarding to `addr`, Ok(None) when 4040
/// is free.
///
/// Why this matters: ngrok agents grab port 4040 for their local API,
/// and only one process can bind it. If we naively spawn `ngrok http
/// <port>` while another ngrok is already running, our child silently
/// fails to start its tunnel — but we'd still successfully *read*
/// tunnel info from :4040, which belongs to the other ngrok. The
/// caller would then print a "Public" URL that points at someone
/// else's local app. Surface the collision before spawning instead.
async fn detect_existing_ngrok() -> Option<String> {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(500))
        .build()
    {
        Ok(c) => c,
        Err(_) => return None,
    };
    let resp = client.get("http://127.0.0.1:4040/api/tunnels").send().await.ok()?;
    if !resp.status().is_success() { return None; }
    let body: serde_json::Value = resp.json().await.ok()?;
    body["tunnels"]
        .as_array()?
        .first()
        .and_then(|t| t["config"]["addr"].as_str().map(str::to_string))
}

/// Spawn `ngrok http <port>` and read the resulting public URL from
/// ngrok's local API at http://127.0.0.1:4040/api/tunnels. Returns
/// the child process handle so the caller can kill it on shutdown.
///
/// Refuses to start if another ngrok already owns :4040 — see
/// `detect_existing_ngrok` for the rationale.
///
/// Auth handling: if ngrok exits early (typical cause: authtoken not
/// set), we capture stderr, surface it, and open the ngrok dashboard
/// in the browser so the user can grab their token.
async fn spawn_ngrok(port: u16, domain: Option<&str>) -> Result<(std::process::Child, String)> {
    if let Some(existing_addr) = detect_existing_ngrok().await {
        eprintln!();
        eprintln!("Another ngrok is already running on 127.0.0.1:4040");
        eprintln!("  forwarding to: {}", existing_addr);
        eprintln!();
        eprintln!("Atem can't start its own tunnel because ngrok's agent API port (:4040)");
        eprintln!("is single-instance, and ngrok free-tier accounts allow only one tunnel");
        eprintln!("at a time per account.");
        eprintln!();
        eprintln!("Options:");
        eprintln!("  1. Stop the other ngrok:   pkill ngrok");
        eprintln!("  2. Skip the tunnel:        atem serv webhooks --no-tunnel");
        eprintln!("  3. Multi-tunnel workflow:  upgrade to a paid ngrok plan");
        eprintln!("                             https://ngrok.com/pricing");
        eprintln!();
        anyhow::bail!("ngrok :4040 already in use");
    }

    let mut cmd = std::process::Command::new("ngrok");
    let mut cmd = std::process::Command::new("ngrok");
    cmd.arg("http").arg(port.to_string());
    if let Some(d) = domain {
        cmd.arg("--domain").arg(d);
    }
    cmd.stdout(std::process::Stdio::null());
    // Capture stderr so we can detect auth errors and surface them.
    cmd.stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().map_err(|e| anyhow::anyhow!(
        "Failed to spawn ngrok ({}). Install from https://ngrok.com or pass --no-tunnel.",
        e
    ))?;

    // Poll ngrok's local API for the tunnel URL. The first request
    // usually fails because ngrok hasn't bound 4040 yet.
    let client = reqwest::Client::new();
    for _ in 0..30 {
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        // If ngrok died early, surface its stderr so the user sees
        // why (authtoken missing is the most common cause).
        if let Ok(Some(_status)) = child.try_wait() {
            let stderr_text = child.stderr.take()
                .and_then(|mut s| {
                    use std::io::Read;
                    let mut buf = String::new();
                    s.read_to_string(&mut buf).ok().map(|_| buf)
                })
                .unwrap_or_default();
            let auth_dashboard = "https://dashboard.ngrok.com/get-started/your-authtoken";
            let needs_auth = stderr_text.contains("authtoken")
                || stderr_text.to_ascii_lowercase().contains("auth");
            if needs_auth {
                eprintln!();
                eprintln!("ngrok exited — auth token not configured.");
                eprintln!();
                eprintln!("To fix:");
                eprintln!("  1. Open {} (browser opening now)", auth_dashboard);
                eprintln!("  2. Copy your authtoken");
                eprintln!("  3. Run: ngrok config add-authtoken <YOUR_TOKEN>");
                eprintln!("  4. Re-run `atem serv webhooks`");
                eprintln!();
                if !stderr_text.is_empty() {
                    eprintln!("ngrok stderr:");
                    for line in stderr_text.lines().take(5) {
                        eprintln!("  | {}", line);
                    }
                }
                let _ = crate::web_server::browser::open_browser(auth_dashboard);
            } else if !stderr_text.is_empty() {
                eprintln!("ngrok exited unexpectedly. stderr:");
                for line in stderr_text.lines().take(10) {
                    eprintln!("  | {}", line);
                }
            }
            anyhow::bail!("ngrok did not start a tunnel");
        }
        let r = client
            .get("http://127.0.0.1:4040/api/tunnels")
            .send()
            .await;
        if let Ok(resp) = r {
            if let Ok(body) = resp.json::<serde_json::Value>().await {
                if let Some(tunnels) = body["tunnels"].as_array() {
                    for t in tunnels {
                        // Prefer https public_url; fall back to first.
                        if let Some(url) = t["public_url"].as_str() {
                            if url.starts_with("https://") {
                                return Ok((child, url.to_string()));
                            }
                        }
                    }
                }
            }
        }
    }
    let _ = child.kill();
    anyhow::bail!("ngrok started but no tunnel URL appeared after 6s on http://127.0.0.1:4040")
}

pub async fn run_server(cfg: ServeWebhooksConfig) -> Result<()> {
    let toml_path = cfg.config_path.clone().unwrap_or_else(default_config_path);
    let file = load_file(&toml_path)?;
    let port = if cfg.port != 0 { cfg.port } else { file.port.unwrap_or(DEFAULT_PORT) };
    let secret = file.secret.unwrap_or_default();
    let tunnel = !cfg.no_tunnel && file.tunnel.unwrap_or(true);
    let provider = TunnelProvider::parse(file.tunnel_provider.as_deref().unwrap_or("ngrok"))?;
    let ngrok_domain = file.ngrok_domain.clone();

    // ── Background mode: re-exec as detached daemon ─────────────────────
    if cfg.background && !cfg._daemon {
        let exe = std::env::current_exe()?;
        let log_dir = crate::rtc_test_server::servers_dir();
        std::fs::create_dir_all(&log_dir)?;
        let sid = format!("webhooks-{}", port);
        let log_path = log_dir.join(format!("{}.log", sid));
        let log_file = std::fs::File::create(&log_path)?;

        let mut daemon_args: Vec<String> = vec![
            "serv".into(), "webhooks".into(),
            "--port".into(), port.to_string(),
        ];
        if let Some(p) = &cfg.config_path {
            daemon_args.push("--config".into());
            daemon_args.push(p.display().to_string());
        }
        if cfg.no_tunnel { daemon_args.push("--no-tunnel".into()); }
        daemon_args.push("--no-browser".into());
        daemon_args.push("--background".into());
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
            kind: "webhooks".to_string(),
            port,
            channel: String::new(),
            local_url: format!("http://127.0.0.1:{}", port),
            network_url: String::new(),
            started_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            last_status: None,
            last_checked_at: None,
        };
        crate::rtc_test_server::register_server(&entry)?;
        println!("atem serv webhooks");
        println!("  config:  {}", toml_path.display());
        println!("  port:    {}", port);
        println!("  ID:      {}", sid);
        println!("  PID:     {}", child.id());
        println!("  Log:     {}", log_path.display());
        println!();
        println!("Use `atem serv list` / `kill {} ` / `killall` to manage.", sid);
        return Ok(());
    }

    // Bind first so `ngrok http <port>` doesn't race us for the port.
    let listener = TcpListener::bind(("0.0.0.0", port)).await
        .map_err(|e| anyhow::anyhow!("Bind 0.0.0.0:{} failed: {}", port, e))?;
    let actual_port = listener.local_addr()?.port();
    let local_url = format!("http://127.0.0.1:{}", actual_port);

    // Optionally bring up ngrok tunnel.
    let mut ngrok_child: Option<std::process::Child> = None;
    let public_url = if tunnel {
        match spawn_tunnel(provider, actual_port, ngrok_domain.as_deref()).await {
            Ok((c, u)) => { ngrok_child = Some(c); Some(u) }
            Err(e) => {
                eprintln!("warning: tunnel disabled — {}", e);
                None
            }
        }
    } else { None };

    println!("atem serv webhooks");
    println!("  config:  {}", toml_path.display());
    println!("  Local:   {}", local_url);
    if let Some(u) = &public_url {
        println!("  Public:  {}/webhook", u);
    } else {
        println!("  Public:  (tunnel disabled — POSTs must reach {} directly)", local_url);
    }
    if secret.is_empty() {
        println!("  Secret:  not set — signature validation SKIPPED (set `secret` in webhooks.toml to enable)");
    } else {
        println!("  Secret:  set ({} chars) — Agora-Signature-V2 will be validated", secret.len());
    }
    println!();
    println!("Configure the webhook URL in Agora Console (NCS / ConvoAI) to the Public URL above.");
    if !cfg.no_browser {
        let _ = crate::web_server::browser::open_browser(&local_url);
    }

    // Broadcast channel — every accepted POST is fanned out to all
    // connected SSE clients. Capacity bounded so a slow client can't
    // OOM us; old events drop on overflow.
    let (tx, _) = broadcast::channel::<WebhookEvent>(256);
    let secret = Arc::new(secret);
    let tx = Arc::new(tx);

    // Print a single-line summary of every event to stdout so the
    // daemon log is grep-able.
    let mut log_rx = tx.subscribe();
    tokio::spawn(async move {
        loop {
            match log_rx.recv().await {
                Ok(ev) => {
                    let ts = format_ms(ev.received_ms);
                    let sig = if ev.signature_ok { "ok" } else { "skip" };
                    let body_summary = ev.body["payload"].get("agent_id")
                        .and_then(|v| v.as_str())
                        .map(|a| format!(" agent_id={}", a))
                        .unwrap_or_default();
                    println!(
                        "[{}] {} {}  sig={}{} from {}",
                        ts,
                        ev.event_type.map(|c| c.to_string()).unwrap_or_else(|| "?".into()),
                        ev.label,
                        sig,
                        body_summary,
                        ev.remote,
                    );
                }
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(_) => break,
            }
        }
    });

    // Wrap the ngrok child in a struct so it gets killed when this
    // function returns (Ctrl+C path through tokio::select!). Without
    // this, ngrok lingers after atem exits.
    struct NgrokGuard(Option<std::process::Child>);
    impl Drop for NgrokGuard {
        fn drop(&mut self) {
            if let Some(mut c) = self.0.take() { let _ = c.kill(); }
        }
    }
    let _guard = NgrokGuard(ngrok_child);

    let accept_loop = async {
        loop {
            let (mut stream, peer) = listener.accept().await?;
            let secret  = secret.clone();
            let tx      = tx.clone();
            tokio::spawn(async move {
                let _ = handle_connection(&mut stream, peer.to_string(), &secret, &tx).await;
            });
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };

    // Catch Ctrl+C so the NgrokGuard's Drop fires and kills the tunnel.
    tokio::select! {
        r = accept_loop => { r?; }
        _ = tokio::signal::ctrl_c() => {
            println!("\nShutting down — killing ngrok tunnel.");
        }
    }
    Ok(())
}

fn format_ms(ms: u64) -> String {
    use std::time::{Duration, UNIX_EPOCH};
    let dt = UNIX_EPOCH + Duration::from_millis(ms);
    let secs = dt.duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let h = (secs / 3600) % 24;
    let m = (secs / 60) % 60;
    let s = secs % 60;
    let mss = ms % 1000;
    format!("{:02}:{:02}:{:02}.{:03}", h, m, s, mss)
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

async fn handle_connection(
    stream: &mut tokio::net::TcpStream,
    peer:   String,
    secret: &Arc<String>,
    tx:     &Arc<broadcast::Sender<WebhookEvent>>,
) -> Result<()> {
    // Minimal HTTP/1.1 reader — read until \r\n\r\n, parse, route.
    let mut buf = Vec::with_capacity(4096);
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 { break; }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            // Header complete; check Content-Length and read remainder.
            let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n").unwrap() + 4;
            let header_str = std::str::from_utf8(&buf[..header_end]).unwrap_or("");
            let content_length: usize = header_str
                .lines()
                .find_map(|l| {
                    let l = l.trim();
                    let lc = l.to_ascii_lowercase();
                    if let Some(rest) = lc.strip_prefix("content-length:") {
                        rest.trim().parse().ok()
                    } else { None }
                })
                .unwrap_or(0);
            let already_have = buf.len() - header_end;
            while buf.len() - header_end < content_length {
                let n = stream.read(&mut tmp).await?;
                if n == 0 { break; }
                buf.extend_from_slice(&tmp[..n]);
            }
            let _ = already_have;
            break;
        }
        if buf.len() > 1024 * 1024 { break; }
    }
    let header_end = buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4).unwrap_or(buf.len());
    let header_str = std::str::from_utf8(&buf[..header_end]).unwrap_or("");
    let body_bytes = &buf[header_end..];

    let first_line = header_str.lines().next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path   = parts.next().unwrap_or("");

    match (method, path) {
        ("GET", "/") => {
            let html = build_console_html();
            send_response(stream, 200, "text/html; charset=utf-8", html.as_bytes()).await
        }
        ("GET", "/events") => sse_stream(stream, tx).await,
        ("POST", "/webhook") => {
            let sig_v2 = header_value(header_str, "agora-signature-v2");
            let signature_ok = if secret.is_empty() {
                true   // skipped, not validated — log/stream still happen
            } else {
                verify_signature(body_bytes, secret, sig_v2.as_deref())
            };
            let body: serde_json::Value = serde_json::from_slice(body_bytes)
                .unwrap_or(serde_json::json!({"_unparsed": String::from_utf8_lossy(body_bytes).to_string()}));
            let event_type = body["eventType"].as_u64();
            let label = event_type.map(label_for).unwrap_or_else(|| "no eventType".into());
            let ev = WebhookEvent {
                received_ms: unix_ms(),
                signature_ok,
                event_type,
                label,
                body,
                remote: peer,
            };
            let _ = tx.send(ev);
            send_response(stream, 200, "application/json", b"{\"ok\":true}").await
        }
        _ => send_response(stream, 404, "text/plain", b"Not Found").await,
    }
}

fn header_value(header_str: &str, name_lower: &str) -> Option<String> {
    for line in header_str.lines() {
        let mut parts = line.splitn(2, ':');
        if let (Some(k), Some(v)) = (parts.next(), parts.next()) {
            if k.trim().eq_ignore_ascii_case(name_lower) {
                return Some(v.trim().to_string());
            }
        }
    }
    None
}

async fn send_response(
    stream: &mut tokio::net::TcpStream,
    status: u16,
    content_type: &str,
    body: &[u8],
) -> Result<()> {
    let status_text = match status {
        200 => "OK", 404 => "Not Found", 500 => "Internal Server Error",
        _ => "OK",
    };
    let head = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        status, status_text, content_type, body.len()
    );
    stream.write_all(head.as_bytes()).await?;
    stream.write_all(body).await?;
    stream.flush().await?;
    Ok(())
}

/// Server-Sent Events stream. Sends each broadcast event as `data:
/// <json>\n\n`; sends a comment heartbeat every SSE_KEEPALIVE_SECS so
/// proxies don't kill an idle connection.
async fn sse_stream(
    stream: &mut tokio::net::TcpStream,
    tx:     &Arc<broadcast::Sender<WebhookEvent>>,
) -> Result<()> {
    let head = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n";
    stream.write_all(head.as_bytes()).await?;
    stream.flush().await?;
    let mut rx = tx.subscribe();
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(SSE_KEEPALIVE_SECS));
    loop {
        tokio::select! {
            ev = rx.recv() => {
                match ev {
                    Ok(e) => {
                        let json = serde_json::to_string(&e).unwrap_or_default();
                        let frame = format!("data: {}\n\n", json);
                        if stream.write_all(frame.as_bytes()).await.is_err() { break; }
                        if stream.flush().await.is_err() { break; }
                    }
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    Err(_) => break,
                }
            }
            _ = tick.tick() => {
                if stream.write_all(b": keepalive\n\n").await.is_err() { break; }
                if stream.flush().await.is_err() { break; }
            }
        }
    }
    Ok(())
}

fn build_console_html() -> String {
    // Minimal single-page console. Subscribes to /events SSE, prepends
    // each event to a scrolling list. Click a row to toggle the JSON.
    r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>atem serv webhooks</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; background: #0d1117; color: #e6edf3; min-height: 100vh; }
header { padding: 12px 20px; border-bottom: 1px solid #30363d; background: #161b22; display: flex; gap: 12px; align-items: center; }
header h1 { font-size: 16px; font-weight: 600; }
header .pill { font-size: 12px; padding: 2px 8px; border-radius: 10px; background: #21262d; color: #7d8590; }
header .pill.ok { background: #196c2e; color: #fff; }
#events { padding: 12px 20px; }
.ev { border: 1px solid #30363d; border-radius: 6px; margin-bottom: 8px; overflow: hidden; }
.ev .head { padding: 8px 12px; display: flex; gap: 12px; align-items: baseline; cursor: pointer; background: #161b22; }
.ev .ts { font-family: monospace; color: #7d8590; font-size: 12px; }
.ev .code { font-family: monospace; color: #58a6ff; }
.ev .label { font-weight: 600; }
.ev .sig-ok { color: #3fb950; font-size: 12px; }
.ev .sig-skip { color: #d29922; font-size: 12px; }
.ev .sig-bad { color: #f85149; font-size: 12px; font-weight: 600; }
.ev .body { display: none; padding: 12px; background: #0d1117; font-family: monospace; font-size: 12px; white-space: pre-wrap; overflow-x: auto; }
.ev.expanded .body { display: block; }
.empty { padding: 30px 20px; color: #7d8590; font-style: italic; }
</style>
</head>
<body>
<header>
  <h1>atem serv webhooks</h1>
  <span id="status" class="pill">connecting…</span>
  <span class="pill" id="count">0 events</span>
</header>
<div id="events">
  <div class="empty">Waiting for the first webhook POST.</div>
</div>
<script>
const KNOWN = {
  101: 'agent_joined', 102: 'agent_left', 103: 'agent_history',
  110: 'agent_error', 111: 'agent_metrics',
  201: 'inbound_call_state', 202: 'outbound_call_state',
};
let count = 0;
const events = document.getElementById('events');
const status = document.getElementById('status');
const counter = document.getElementById('count');
const empty = events.querySelector('.empty');

function fmt(ms) {
  const d = new Date(ms);
  return d.toLocaleTimeString('en-US', { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3,'0');
}

function addEvent(e) {
  if (empty) empty.remove();
  count += 1;
  counter.textContent = count + (count === 1 ? ' event' : ' events');
  const div = document.createElement('div');
  div.className = 'ev';
  const head = document.createElement('div');
  head.className = 'head';
  const sigCls = e.signature_ok ? 'sig-ok' : (e.body && e.body._unparsed ? 'sig-bad' : 'sig-skip');
  const sigText = e.signature_ok ? 'sig ok' : 'sig skip/bad';
  head.innerHTML =
    '<span class="ts">' + fmt(e.received_ms) + '</span>' +
    '<span class="code">' + (e.event_type ?? '?') + '</span>' +
    '<span class="label">' + e.label + '</span>' +
    '<span class="' + sigCls + '">' + sigText + '</span>';
  head.onclick = () => div.classList.toggle('expanded');
  const body = document.createElement('div');
  body.className = 'body';
  body.textContent = JSON.stringify(e.body, null, 2);
  div.appendChild(head);
  div.appendChild(body);
  events.prepend(div);
  // Cap at 500 to avoid runaway memory.
  while (events.children.length > 500) events.removeChild(events.lastChild);
}

const es = new EventSource('/events');
es.onopen  = () => { status.textContent = 'live'; status.classList.add('ok'); };
es.onerror = () => { status.textContent = 'disconnected'; status.classList.remove('ok'); };
es.onmessage = (m) => {
  try { addEvent(JSON.parse(m.data)); }
  catch (err) { console.warn('bad SSE payload', err); }
};
</script>
</body>
</html>
"##.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn label_for_known_codes() {
        assert_eq!(label_for(101), "agent_joined");
        assert_eq!(label_for(102), "agent_left");
        assert_eq!(label_for(110), "agent_error");
        assert_eq!(label_for(202), "outbound_call_state");
        assert_eq!(label_for(9999), "unknown");
    }

    #[test]
    fn verify_signature_matches_known_hmac() {
        // HMAC-SHA256("secret", "hello") = 88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b
        let body = b"hello";
        let sig = "88aab3ede8d3adf94d26ab90d3bafd4a2083070c3bcce9c014ee04a443847c0b";
        assert!(verify_signature(body, "secret", Some(sig)));
    }

    #[test]
    fn verify_signature_rejects_wrong_sig() {
        assert!(!verify_signature(b"hello", "secret", Some("00".repeat(32).as_str())));
    }

    #[test]
    fn verify_signature_returns_false_when_header_missing() {
        assert!(!verify_signature(b"hello", "secret", None));
    }

    #[test]
    fn tunnel_provider_parse_accepts_known_aliases() {
        assert_eq!(TunnelProvider::parse("ngrok").unwrap(), TunnelProvider::Ngrok);
        assert_eq!(TunnelProvider::parse("NGROK").unwrap(), TunnelProvider::Ngrok);
        assert_eq!(TunnelProvider::parse("").unwrap(), TunnelProvider::Ngrok); // default
        assert_eq!(TunnelProvider::parse("cloudflared").unwrap(), TunnelProvider::Cloudflared);
        assert_eq!(TunnelProvider::parse("cf").unwrap(), TunnelProvider::Cloudflared);
        assert!(TunnelProvider::parse("frp").is_err());
    }

    #[test]
    fn extract_trycloudflare_url_from_typical_log_line() {
        // Real cloudflared stderr line shape (border characters stripped to ASCII).
        let line = "2026-05-04T12:00:00Z INF |  https://random-words-here.trycloudflare.com  |";
        assert_eq!(
            extract_trycloudflare_url(line).as_deref(),
            Some("https://random-words-here.trycloudflare.com")
        );
    }

    #[test]
    fn extract_trycloudflare_url_ignores_non_cloudflare_https() {
        assert_eq!(extract_trycloudflare_url("see https://example.com for docs"), None);
    }

    #[test]
    fn extract_trycloudflare_url_returns_none_when_no_https() {
        assert_eq!(extract_trycloudflare_url("INF Starting tunnel"), None);
    }

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"abcd"));
    }

    #[test]
    fn header_value_is_case_insensitive() {
        let header = "POST /webhook HTTP/1.1\r\n\
            Host: example.com\r\n\
            Content-Type: application/json\r\n\
            Agora-Signature-V2: abc123\r\n\
            \r\n";
        assert_eq!(header_value(header, "agora-signature-v2"), Some("abc123".into()));
        assert_eq!(header_value(header, "content-type"),       Some("application/json".into()));
        assert_eq!(header_value(header, "host"),               Some("example.com".into()));
        assert_eq!(header_value(header, "missing"),            None);
    }

    #[test]
    fn webhooks_file_parses_full_example() {
        let toml = r#"
            port = 9090
            secret = "shh"
            tunnel = true
            tunnel_provider = "cloudflared"
            ngrok_domain = "atem-webhooks.ngrok-free.app"
        "#;
        let f: WebhooksFile = toml::from_str(toml).unwrap();
        assert_eq!(f.port, Some(9090));
        assert_eq!(f.secret.as_deref(), Some("shh"));
        assert_eq!(f.tunnel, Some(true));
        assert_eq!(f.tunnel_provider.as_deref(), Some("cloudflared"));
        assert_eq!(f.ngrok_domain.as_deref(), Some("atem-webhooks.ngrok-free.app"));
    }

    #[test]
    fn webhooks_file_parses_empty_with_defaults() {
        // Operator may leave fields out; serde defaults to None.
        let f: WebhooksFile = toml::from_str("").unwrap();
        assert_eq!(f.port, None);
        assert_eq!(f.secret, None);
        assert_eq!(f.tunnel, None);
        assert_eq!(f.tunnel_provider, None);
    }

    #[test]
    fn webhooks_example_toml_is_valid() {
        // Guard against the example file going stale or syntactically
        // broken — it gets copied into ~/.config/atem/webhooks.toml as-is.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("configs/webhooks.example.toml");
        let s = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
        let f: WebhooksFile = toml::from_str(&s)
            .unwrap_or_else(|e| panic!("parse {}: {}", path.display(), e));
        // Sanity: at minimum, `port` is present in the example.
        assert!(f.port.is_some());
        // `tunnel_provider` documented as ngrok | cloudflared — sanity-check
        // whatever the example sets is a value the parser accepts.
        if let Some(tp) = f.tunnel_provider.as_deref() {
            TunnelProvider::parse(tp).expect("example tunnel_provider should parse");
        }
    }

    /// End-to-end: bring up the server in --no-tunnel mode, POST a real
    /// webhook payload, assert the response shape and that an SSE client
    /// receives the event.
    #[tokio::test]
    async fn end_to_end_post_webhook_returns_200_and_broadcasts_sse() {
        // Pick a port unlikely to clash with `cargo test` parallelism.
        let port: u16 = 19090 + (rand::random::<u16>() % 500);
        let cfg = ServeWebhooksConfig {
            config_path: Some(std::path::PathBuf::from("/dev/null")),
            port,
            no_tunnel: true,
            no_browser: true,
            background: false,
            _daemon: false,
        };
        let server = tokio::spawn(async move {
            let _ = run_server(cfg).await;
        });
        // Wait for bind.
        let base = format!("http://127.0.0.1:{}", port);
        let client = reqwest::Client::new();
        for _ in 0..40 {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            if client.get(&base).send().await.is_ok() { break; }
        }

        // SSE subscriber via raw TCP — `reqwest` without the `stream`
        // feature can't tail an open SSE response, and the integration
        // test only needs to read the first `data:` frame.
        let sse_handle = tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut s = tokio::net::TcpStream::connect(("127.0.0.1", port))
                .await.expect("sse connect");
            let req = format!(
                "GET /events HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\n\r\n",
            );
            s.write_all(req.as_bytes()).await.unwrap();
            let mut buf = String::new();
            let mut tmp = [0u8; 4096];
            for _ in 0..50 {
                let n = match s.read(&mut tmp).await { Ok(n) => n, Err(_) => break };
                if n == 0 { break; }
                buf.push_str(&String::from_utf8_lossy(&tmp[..n]));
                if buf.contains("data:") && buf.contains("\n\n") { break; }
            }
            buf
        });

        // Give the SSE client a moment to subscribe.
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // POST a webhook payload.
        let post = reqwest::Client::new();
        let body = serde_json::json!({
            "noticeId": "e2e-1",
            "productId": 1,
            "eventType": 101,
            "notifyMs": 1700000000000u64,
            "payload": { "agent_id": "agent-x", "channel": "chan" },
        });
        let resp = post
            .post(format!("{}/webhook", base))
            .json(&body)
            .send()
            .await
            .expect("POST /webhook");
        assert_eq!(resp.status().as_u16(), 200);
        let resp_body: serde_json::Value = resp.json().await.unwrap();
        assert_eq!(resp_body["ok"], true);

        // The SSE client should have received the event.
        let sse_buf = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            sse_handle,
        ).await.expect("sse timeout").expect("sse panic");
        assert!(sse_buf.contains("\"event_type\":101"), "SSE buf: {}", sse_buf);
        assert!(sse_buf.contains("\"label\":\"agent_joined\""), "SSE buf: {}", sse_buf);
        assert!(sse_buf.contains("\"agent_id\":\"agent-x\""), "SSE buf: {}", sse_buf);

        // 404 path
        let resp404 = reqwest::Client::new()
            .get(format!("{}/no-such-route", base))
            .send().await.unwrap();
        assert_eq!(resp404.status().as_u16(), 404);

        server.abort();
    }

    #[test]
    fn label_for_collisions_first_match_wins() {
        // The static table has two entries for code 103 (ConvoAI's
        // agent_history and a hypothetical RTC user_joined). First one
        // wins by design; this test makes the choice explicit so a
        // future re-ordering doesn't silently flip behaviour.
        assert_eq!(label_for(103), "agent_history");
    }
}

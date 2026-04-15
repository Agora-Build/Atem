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

/// Generate a unique agent name for this session.
fn gen_agent_name() -> String {
    use rand::RngCore;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let rand = rand::thread_rng().next_u32();
    format!("atem-convo-{ts}-{:04x}", rand & 0xffff)
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
}

/// Process-local state. One agent at a time.
#[derive(Default, Debug, Clone)]
pub struct AgentState {
    pub running:    bool,
    pub agent_id:   Option<String>,
    pub name:       Option<String>,
    pub started_at: Option<u64>,
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
    let resolved = convo.resolve(&CliOverrides {
        channel:       cfg.channel.clone(),
        rtc_user_id:   cfg.rtc_user_id.clone(),
        agent_user_id: cfg.agent_user_id.clone(),
    })?;

    println!("atem serv convo");
    println!("  config:    {}", toml_path.display());
    println!("  channel:   {}", resolved.channel);
    println!("  rtc uid:   {}", resolved.rtc_user_id);
    println!("  agent uid: {}", resolved.agent_user_id);
    println!(
        "  avatar:    {}",
        if resolved.avatar_configured { "configured" } else { "not configured" }
    );

    if cfg.background {
        anyhow::bail!("background mode not implemented yet");
    }

    // Get app_id + app_certificate from active project.
    let app_id   = crate::config::ProjectCache::resolve_app_id(None)?;
    let app_cert = crate::config::ProjectCache::resolve_app_certificate(None)?;

    // Bind and set up TLS. We use loopback-only cert (127.0.0.1) because
    // serv convo is developer-local by design.
    let listener = TcpListener::bind(("127.0.0.1", cfg.port)).await?;
    let bound_port = listener.local_addr()?.port();
    let lan_ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));
    let (certs, key) = crate::web_server::cert::generate_self_signed_cert(&lan_ip)?;

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    let acceptor = TlsAcceptor::from(Arc::new(tls_config));

    let url = format!("https://127.0.0.1:{}/", bound_port);
    println!("\nServing on {}", url);
    if !cfg.no_browser {
        let _ = crate::rtc_test_server::open_browser(&url);
    }

    let state: Arc<Mutex<AgentState>> = Arc::new(Mutex::new(AgentState::default()));
    let app_id    = Arc::new(app_id);
    let app_cert  = Arc::new(app_cert);
    let resolved  = Arc::new(resolved);
    let convo_cfg = Arc::new(convo);

    loop {
        let (stream, _) = listener.accept().await?;
        let acceptor  = acceptor.clone();
        let app_id    = app_id.clone();
        let app_cert  = app_cert.clone();
        let resolved  = resolved.clone();
        let convo_cfg = convo_cfg.clone();
        let state     = state.clone();
        tokio::spawn(async move {
            let tls = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(_) => return,
            };
            let _ = handle_connection(tls, &app_id, &app_cert, &resolved, &convo_cfg, state).await;
        });
    }
}

fn default_config_path() -> PathBuf {
    crate::config::AtemConfig::config_dir().join("convo.toml")
}

async fn handle_connection(
    mut stream: tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    app_id:     &str,
    app_cert:   &str,
    resolved:   &Arc<ResolvedConfig>,
    convo_cfg:  &Arc<ConvoConfig>,
    state:      Arc<Mutex<AgentState>>,
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
            let html = build_html_page(app_id, resolved);
            send_response(&mut stream, 200, "text/html; charset=utf-8", html.as_bytes()).await?;
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

            let name = gen_agent_name();
            let payload = convo_cfg.build_join_payload(crate::convo_config::JoinArgs {
                name: &name,
                channel: &resolved.channel,
                token: &agent_token,
                agent_rtc_uid: &resolved.agent_user_id,
                remote_uids: &[resolved.rtc_user_id.clone()],
                include_avatar,
            });

            let url = format!(
                "{}/api/conversational-ai-agent/v2/projects/{}/join",
                convoai_base_url(), app_id
            );
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
                    let body_json: serde_json::Value =
                        r.json().await.unwrap_or_else(|_| serde_json::json!({}));
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
            let agent_id = {
                let st = state.lock().await;
                st.agent_id.clone()
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
            let url = format!(
                "{}/api/conversational-ai-agent/v2/projects/{}/agents/{}/leave",
                convoai_base_url(), app_id, agent_id
            );
            let client = reqwest::Client::new();
            let _ = client
                .post(&url)
                .header("Authorization", format!("agora token={}", token))
                .send()
                .await;

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
fn build_html_page(app_id: &str, resolved: &ResolvedConfig) -> String {
    let app_id_display = if app_id.len() > 12 {
        format!("{}...{}", &app_id[..6], &app_id[app_id.len() - 4..])
    } else {
        app_id.to_string()
    };

    let channel   = resolved.channel.as_str();
    let rtc_uid   = resolved.rtc_user_id.as_str();
    let agent_uid = resolved.agent_user_id.as_str();
    let preset    = resolved.preset.clone().unwrap_or_default();
    let avatar_ok = if resolved.avatar_configured { "true" } else { "false" };

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
#transcript {{ max-height: 180px; overflow-y: auto; padding: 8px 16px; font-size: 13px; line-height: 1.5; color: #e6edf3; }}
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
    <label>App ID</label>
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
</section>

<!-- ── RTC ─────────────────────────────────────────────────────── -->
<section class="block">
  <h2 class="block-title"><span class="status-dot disconnected" id="rtcDot"></span>RTC — <span id="rtcState" style="font-weight:400;color:#7d8590">Disconnected</span></h2>
  <div class="controls">
    <label>UID</label>
    <input id="uidInput" type="text" placeholder="auto" value="{rtc_uid}" style="width:100px">
    <button id="joinBtn"  class="btn btn-join"  onclick="doJoin()">Join</button>
    <button id="leaveBtn" class="btn btn-leave" onclick="doLeave()">Leave</button>
    <button id="muteBtn"  class="btn btn-mute"  onclick="toggleMute()">Mute Mic</button>
  </div>
  <div class="video-grid">
    <div class="video-cell" id="localCell">
      <div id="localVideo"></div>
      <span class="video-label">Local</span>
    </div>
    <div class="video-cell" id="agentCell" style="display:none">
      <div id="agentVideo"></div>
      <span class="video-label">Agent</span>
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
    <label>Preset</label>
    <span id="presetDisplay" class="read-only-value">—</span>
  </div>
  <div class="controls avatar-row">
    <input type="checkbox" id="avatarCheckbox" title="No avatar configured in TOML">
    <label for="avatarCheckbox">Enable avatar</label>
  </div>
  <div class="controls">
    <button id="startAgentBtn" class="btn btn-join" onclick="startAgent()" disabled>Start Agent</button>
    <button id="stopAgentBtn"  class="btn btn-leave" onclick="stopAgent()"  style="display:none">Stop Agent</button>
  </div>
  <div class="convo-sub-title">Live transcription</div>
  <div id="transcript"></div>
  <div class="convo-sub-title">Events</div>
  <div id="events"></div>
</section>

<script>
// Constants populated from the server's ResolvedConfig.
const APP_ID    = "{app_id}";
const CHANNEL   = "{channel}";
const RTC_UID   = "{rtc_uid}";
const AGENT_UID = "{agent_uid}";
const PRESET    = "{preset}";
const AVATAR_OK = {avatar_ok};

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
  el.scrollTop = el.scrollHeight;
}}

// Placeholder handlers — Task 14 wires these to RTC / ConvoAI toolkit.
async function fetchToken()  {{ logEvent('fetchToken: not implemented yet',  'warning'); }}
async function doJoin()      {{ logEvent('doJoin: not implemented yet',      'warning'); }}
async function doLeave()     {{ logEvent('doLeave: not implemented yet',     'warning'); }}
async function toggleMute()  {{ logEvent('toggleMute: not implemented yet',  'warning'); }}
async function startAgent()  {{ logEvent('startAgent: not implemented yet',  'warning'); }}
async function stopAgent()   {{ logEvent('stopAgent: not implemented yet',   'warning'); }}

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
document.getElementById('presetDisplay').textContent   = PRESET || "—";
document.getElementById('avatarCheckbox').disabled = !AVATAR_OK;
</script>
</body>
</html>"##,
        app_id_display = app_id_display,
        app_id         = app_id,
        channel        = channel,
        rtc_uid        = rtc_uid,
        agent_uid      = agent_uid,
        preset         = preset,
        avatar_ok      = avatar_ok,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn html_has_expected_ids_and_scripts() {
        let resolved = ResolvedConfig {
            channel:           "chan".into(),
            rtc_user_id:       "42".into(),
            agent_user_id:     "9".into(),
            idle_timeout_secs: Some(120),
            avatar_configured: true,
            preset:            None,
        };
        let html = build_html_page("app-xx", &resolved);
        assert!(html.contains("/vendor/conversational-ai-api.js"));
        assert!(html.contains("id=\"agentUidDisplay\""));
        assert!(html.contains("id=\"avatarCheckbox\""));
        assert!(html.contains("Welcome to Agora"));
    }

    #[test]
    fn gen_agent_name_has_expected_shape() {
        let n = gen_agent_name();
        assert!(n.starts_with("atem-convo-"), "got: {n}");
        // 4-hex suffix after the last dash
        let last = n.rsplit('-').next().unwrap();
        assert_eq!(last.len(), 4);
        assert!(last.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

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

    // Get app_id + app_certificate from active project.
    let app_id   = crate::config::ProjectCache::resolve_app_id(None)?;
    let app_cert = crate::config::ProjectCache::resolve_app_certificate(None)?;

    if cfg.background {
        println!("atem serv convo");
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

/// Headless mode: no HTTPS server, no browser, no local RTC. atem just
/// POSTs /join to the ConvoAI REST API, prints the agent id, and waits
/// for SIGINT/SIGTERM to POST /leave. Useful when an external device
/// (phone, ConvoAI-capable hardware) joins the channel on its own and
/// atem's only role is to keep the agent alive on the other side.
async fn run_background(
    app_id:   &str,
    app_cert: &str,
    resolved: &ResolvedConfig,
    convo:    &ConvoConfig,
) -> Result<()> {
    println!("  mode:      background (no HTTPS server)");

    let name = gen_agent_name();
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

    let payload = convo.build_join_payload(crate::convo_config::JoinArgs {
        name: &name,
        channel: &resolved.channel,
        token: &agent_token,
        agent_rtc_uid: &resolved.agent_user_id,
        remote_uids: &[resolved.rtc_user_id.clone()],
        include_avatar: resolved.avatar_configured,
        // Background mode: no UI, use config-level preset as-is.
        preset: None,
    });

    let url = format!(
        "{}/api/conversational-ai-agent/v2/projects/{}/join",
        convoai_base_url(),
        app_id
    );
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
    println!("\nAgent running. Ctrl+C to stop.");

    // Block until SIGINT/SIGTERM, then POST /leave.
    tokio::signal::ctrl_c().await?;
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
    let leave_url = format!(
        "{}/api/conversational-ai-agent/v2/projects/{}/agents/{}/leave",
        convoai_base_url(),
        app_id,
        agent_id
    );
    let _ = client
        .post(&leave_url)
        .header("Authorization", format!("agora token={}", leave_token))
        .send()
        .await;
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
                preset: preset_override.as_deref(),
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
.btn-leave {{ background: #da3633; border-color: #da3633; color: #fff; }}
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
</section>

<!-- ── RTC ─────────────────────────────────────────────────────── -->
<section class="block">
  <h2 class="block-title"><span class="status-dot disconnected" id="rtcDot"></span>RTC — <span id="rtcState" style="font-weight:400;color:#7d8590">Disconnected</span></h2>
  <div class="controls">
    <label>UID</label>
    <input id="uidInput" type="text" placeholder="auto" value="{rtc_uid}" style="width:100px">
    <button id="joinBtn"  class="btn btn-join"  onclick="doJoin()">Join</button>
    <button id="leaveBtn" class="btn btn-leave" onclick="doLeave()" style="display:none">Leave</button>
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
    <label>Presets</label>
    <div id="presetCheckboxes"
         style="display:flex;flex-wrap:wrap;gap:12px;align-items:center;font-size:13px"></div>
  </div>
  <div class="controls avatar-row">
    <input type="checkbox" id="avatarCheckbox" title="No avatar configured in TOML">
    <label for="avatarCheckbox">Enable avatar</label>
  </div>
  <div class="controls">
    <button id="startAgentBtn" class="btn btn-join" onclick="startAgent()">Start Agent</button>
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
const PRESETS   = {presets_js};    // e.g. ["expertise_ai_poc", ...] or []
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
  // Cap at ~200 entries — oldest first.
  while (el.childElementCount > 200) el.removeChild(el.firstChild);
  el.scrollTop = el.scrollHeight;
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

    rtcClient = AgoraRTC.createClient({{ mode: 'rtc', codec: 'vp8' }});

    rtcClient.on('user-published', async (user, mediaType) => {{
      await rtcClient.subscribe(user, mediaType);
      logEvent('Subscribed to ' + user.uid + ' (' + mediaType + ')', 'success');
      if (mediaType === 'audio') {{
        user.audioTrack && user.audioTrack.play();
      }}
      if (mediaType === 'video') {{
        const cell = document.getElementById('agentCell');
        cell.style.display = '';
        user.videoTrack && user.videoTrack.play('agentVideo');
      }}
    }});
    rtcClient.on('user-unpublished', (user, mediaType) => {{
      logEvent('User ' + user.uid + ' unpublished ' + mediaType);
      if (mediaType === 'video') {{
        document.getElementById('agentCell').style.display = 'none';
      }}
    }});
    rtcClient.on('connection-state-change', (cur, prev) => {{
      logEvent('RTC: ' + prev + ' -> ' + cur);
      if (cur === 'CONNECTED') setRtcDot('connected', 'Connected');
      else if (cur === 'RECONNECTING') setRtcDot('connecting', 'Reconnecting...');
      else if (cur === 'DISCONNECTED') setRtcDot('disconnected', 'Disconnected');
    }});

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
      rtm = new AgoraRTM.RTM(APP_ID, rtmUser);
      rtm.addEventListener('status', (evt) => {{
        logEvent('RTM status: ' + evt.state + (evt.reason ? ' (' + evt.reason + ')' : ''));
      }});
      await rtm.login({{ token }});
      logEvent('RTM logged in as ' + rtmUser, 'success');
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
  try {{
    if (agentRunning) {{
      try {{ await stopAgent(); }} catch (_) {{}}
    }}
    if (convoApi) {{
      try {{ convoApi.destroy(); }} catch (_) {{}}
      convoApi = null;
    }}
    if (rtm) {{
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

function renderTranscript(list) {{
  if (!Array.isArray(list)) return;
  const el = document.getElementById('transcript');
  const agentUidStr = String(AGENT_UID);
  const rows = list.map((item) => {{
    const who = String(item.userId ?? item.uid ?? '') === agentUidStr ? 'agent' : 'user';
    const label = who === 'agent' ? 'agent' : 'user';
    const text = (item.text ?? '') + '';
    const div = document.createElement('div');
    div.className = who;
    div.textContent = label + ': ' + text;
    return div;
  }});
  el.innerHTML = '';
  rows.forEach((r) => el.appendChild(r));
  el.scrollTop = el.scrollHeight;
}}

async function startAgent() {{
  if (!rtcJoined) {{ logEvent('Join RTC before starting the agent', 'warning'); return; }}
  if (agentRunning) {{ logEvent('Agent already running', 'warning'); return; }}

  const includeAvatar = document.getElementById('avatarCheckbox').checked;
  // Checked presets, comma-joined (e.g. "expertise_ai_poc,_akool_test_expertise").
  // Empty string → fall back to whatever preset/presets is set in convo.toml.
  const presetName = selectedPresetString();
  setAgentDot('transitioning', 'starting...');
  try {{
    const startBody = {{ avatar: includeAvatar }};
    if (presetName) startBody.preset = presetName;
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
    logEvent('Agent started: ' + (data.agent_id || '?') + ' (' + (data.name || '?') + ')', 'success');

    // Initialize the ConvoAI toolkit. It wires RTC + RTM events to provide
    // word-by-word transcription and agent state signals.
    //
    // The esbuild IIFE bundle wraps the module exports under the
    // `ConversationalAIAPI` global, so the class sits at
    // `ConversationalAIAPI.ConversationalAIAPI`. Fall back to the global
    // itself in case a future bundle config inlines the class.
    const ToolkitClass =
      (ConversationalAIAPI && ConversationalAIAPI.ConversationalAIAPI)
      || ConversationalAIAPI;
    if (!ToolkitClass || typeof ToolkitClass.init !== 'function') {{
      logEvent('ConversationalAIAPI not loaded — skipping toolkit init', 'warning');
    }} else {{
      try {{
        convoApi = ToolkitClass.init({{
          rtcEngine:  rtcClient,
          rtmEngine:  rtm,
          renderMode: 'word',
          enableLog:  false,
        }});

        convoApi.on('transcript-updated', (list) => {{
          renderTranscript(list);
        }});
        convoApi.on('agent-state-changed', (ev) => {{
          const state = (ev && (ev.state || ev.newState)) || 'unknown';
          setAgentDot(mapState(state), state);
          logEvent('agent-state-changed: ' + state);
        }});
        convoApi.on('agent-metrics', (m) => {{
          logEvent('agent-metrics: ' + JSON.stringify(m));
        }});
        convoApi.on('agent-interrupted', (ev) => {{
          logEvent('agent-interrupted: ' + JSON.stringify(ev || {{}}), 'warning');
        }});
        convoApi.on('agent-error', (err) => {{
          logEvent('agent-error: ' + JSON.stringify(err || {{}}), 'error');
        }});

        // Subscribe to the toolkit messaging for this channel. The toolkit
        // internally pairs channel + agent uid via the RTM presence data.
        const channel = document.getElementById('channelInput').value.trim() || CHANNEL;
        await convoApi.subscribeMessage(channel);
        logEvent('Toolkit subscribed to channel ' + channel, 'success');
      }} catch (e) {{
        logEvent('Toolkit init failed: ' + e.message, 'error');
      }}
    }}

    agentRunning = true;
    setAgentDot('connected', 'connected');
    document.getElementById('startAgentBtn').style.display = 'none';
    document.getElementById('stopAgentBtn').style.display  = '';
    document.getElementById('stopAgentBtn').disabled       = false;
  }} catch (err) {{
    logEvent('Start error: ' + err.message, 'error');
    setAgentDot('idle', 'idle');
  }}
}}

async function stopAgent() {{
  setAgentDot('transitioning', 'stopping...');
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
document.getElementById('avatarCheckbox').disabled = !AVATAR_OK;

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
    wrap.style.gap           = '6px';
    wrap.style.cursor        = 'pointer';
    wrap.style.color         = '#c9d1d9';
    wrap.style.fontFamily    = 'monospace';
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
      logEvent('Existing agent detected: ' + (st.agent_id || '?') + ' (' + (st.name || '?') + ')', 'info');
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
            presets:           vec![],
        };
        let html = build_html_page("app-xx", &resolved);
        assert!(html.contains("/vendor/conversational-ai-api.js"));
        assert!(html.contains("id=\"agentUidDisplay\""));
        assert!(html.contains("id=\"avatarCheckbox\""));
        assert!(html.contains("Welcome to Agora"));
        assert!(html.contains("id=\"presetCheckboxes\""));
    }

    #[test]
    fn html_embeds_preset_list_as_js_array() {
        let resolved = ResolvedConfig {
            channel:           "c".into(),
            rtc_user_id:       "1".into(),
            agent_user_id:     "2".into(),
            idle_timeout_secs: None,
            avatar_configured: false,
            preset:            None,
            presets:           vec!["expertise_ai_poc".into(), "_akool_test_expertise".into()],
        };
        let html = build_html_page("app", &resolved);
        // JSON-encoded array literal must appear in the page.
        assert!(html.contains(r#"["expertise_ai_poc","_akool_test_expertise"]"#),
            "preset list not embedded — got: {}",
            html.lines().find(|l| l.contains("PRESETS")).unwrap_or(""));
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

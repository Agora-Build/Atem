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
            let html = format!(
                "<!doctype html><html><body><h1>atem serv convo</h1><p>channel: {}</p></body></html>",
                resolved.channel
            );
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
    fn gen_agent_name_has_expected_shape() {
        let n = gen_agent_name();
        assert!(n.starts_with("atem-convo-"), "got: {n}");
        // 4-hex suffix after the last dash
        let last = n.rsplit('-').next().unwrap();
        assert_eq!(last.len(), 4);
        assert!(last.chars().all(|c| c.is_ascii_hexdigit()));
    }
}

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoSession {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: u64, // Unix seconds
    #[serde(default)]
    pub login_id: Option<String>,
}

impl SsoSession {
    pub(crate) fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

/// OAuth 2.0 client_id registered in the Agora SSO server for CLI applications.
const CLIENT_ID: &str = "atem";

/// Generate a PKCE (code_verifier, code_challenge) pair.
/// verifier: 32 random bytes → base64url
/// challenge: SHA-256(verifier) → base64url
pub fn generate_pkce() -> (String, String) {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    let verifier = URL_SAFE_NO_PAD.encode(bytes);
    let hash = Sha256::digest(verifier.as_bytes());
    let challenge = URL_SAFE_NO_PAD.encode(hash);
    (verifier, challenge)
}

/// Generate a random state token for CSRF protection.
pub fn generate_state() -> String {
    let mut bytes = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Load best credential entry, refresh if near-expiry, return access token.
/// `connected_astation_id`: Some if Atem is currently connected to that Astation.
pub async fn valid_token(connected_astation_id: Option<&str>, sso_url: &str) -> Result<String> {
    valid_token_from(
        &crate::credentials::CredentialStore::path(),
        connected_astation_id,
        sso_url,
    )
    .await
}

/// Path-injectable version used in tests.
pub async fn valid_token_from(
    path: &std::path::Path,
    connected_astation_id: Option<&str>,
    sso_url: &str,
) -> Result<String> {
    use crate::credentials::{CredentialEntry, CredentialSource, CredentialStore};
    let mut store = CredentialStore::load_from(path);
    let now = CredentialEntry::now_secs();

    let (source, astation_id, refresh, needs) = {
        let entry = store.resolve(connected_astation_id, now)?;
        (
            entry.source,
            entry.astation_id.clone(),
            entry.refresh_token.clone(),
            entry.needs_refresh(),
        )
    };

    if !needs {
        // Re-borrow to return access_token
        let entry = store.resolve(connected_astation_id, now)?;
        return Ok(entry.access_token.clone());
    }

    let refreshed = refresh_token(&refresh, sso_url)
        .await
        .map_err(|e| anyhow::anyhow!("Session expired. Run 'atem login' or re-pair. ({e})"))?;

    match source {
        CredentialSource::Sso => {
            if let Some(sso) = store.find_sso_mut() {
                sso.access_token = refreshed.access_token.clone();
                sso.refresh_token = refreshed.refresh_token.clone();
                sso.expires_at = refreshed.expires_at;
            }
        }
        CredentialSource::AstationPaired => {
            if let Some(aid) = astation_id.as_deref() {
                if let Some(p) = store.find_paired_mut(aid) {
                    p.access_token = refreshed.access_token.clone();
                    p.refresh_token = refreshed.refresh_token.clone();
                    p.expires_at = refreshed.expires_at;
                }
            }
        }
    }
    store.save_to(path)?;
    Ok(refreshed.access_token)
}

/// Exchange a refresh_token for a new SsoSession.
pub async fn refresh_token(refresh_token: &str, sso_url: &str) -> Result<SsoSession> {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v0/oauth/token", sso_url))
        .form(&[
            ("grant_type", "refresh_token"),
            ("client_id", CLIENT_ID),
            ("refresh_token", refresh_token),
        ])
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Token refresh failed ({status}): {body}");
    }

    parse_token_response(resp).await
}

/// Parse `code`, `state`, and `loginId` from an OAuth callback query string.
/// Input: the raw query string after `?` (e.g. "code=abc&state=xyz&loginId=...")
/// Returns: (code, state, login_id) — all URL-decoded, empty string if not present
fn parse_callback_query(query: &str) -> (String, String, String) {
    let mut code = String::new();
    let mut state = String::new();
    let mut login_id = String::new();
    for pair in query.split('&') {
        if let Some(v) = pair.strip_prefix("code=") {
            code = urlencoding::decode(v).unwrap_or_default().into_owned();
        } else if let Some(v) = pair.strip_prefix("state=") {
            state = urlencoding::decode(v).unwrap_or_default().into_owned();
        } else if let Some(v) = pair.strip_prefix("loginId=") {
            login_id = urlencoding::decode(v).unwrap_or_default().into_owned();
        }
    }
    (code, state, login_id)
}

/// OAuth 2.0 + PKCE login flow.
///
/// Opens the browser and waits for the loopback redirect callback.
/// If no callback arrives within 5 seconds, prints a hint asking the user to
/// paste the callback URL from the browser address bar — both paths then race;
/// whichever arrives first completes the login.
pub async fn run_login_flow(sso_url: &str) -> Result<SsoSession> {
    let (verifier, challenge) = generate_pkce();
    let state = generate_state();

    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let redirect_uri = format!("http://127.0.0.1:{}/oauth/callback", port);

    let auth_url = format!(
        "{}/api/v0/oauth/authorize?response_type=code&client_id={}\
         &redirect_uri={}&scope=basic_info,console&state={}\
         &code_challenge={}&code_challenge_method=S256",
        sso_url,
        CLIENT_ID,
        urlencoding::encode(&redirect_uri),
        state,
        challenge,
    );

    println!("Opening browser for Agora Console login...");
    println!("  {}", auth_url);
    let _ = crate::web_server::browser::open_browser(&auth_url);
    println!("Waiting for browser callback...");

    // Channel: loopback callback OR stdin paste both send (code, state, login_id) here
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<(String, String, String)>>(2);

    // Spawn loopback listener task
    let tx_loopback = tx.clone();
    let state_for_loopback = state.clone();
    tokio::spawn(async move {
        let result: Result<(String, String, String)> = async {
            let (mut stream, _) = tokio::time::timeout(
                std::time::Duration::from_secs(300),
                listener.accept(),
            )
            .await
            .map_err(|_| anyhow::anyhow!("Loopback timed out"))?
            .map_err(|e| anyhow::anyhow!("Accept failed: {}", e))?;

            let mut buf = Vec::new();
            let mut tmp = [0u8; 4096];
            loop {
                let n = stream.read(&mut tmp).await?;
                if n == 0 { break; }
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") { break; }
            }
            let request = String::from_utf8_lossy(&buf);
            let query = request
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|p| p.split_once('?').map(|(_, q)| q))
                .unwrap_or("");
            let (code, ret_state, login_id) = parse_callback_query(query);

            // Always respond to the browser
            let html = r##"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Login successful</title>
<style>
  *{margin:0;padding:0;box-sizing:border-box}
  body{
    min-height:100vh;display:flex;align-items:center;justify-content:center;
    background:#0f0f11;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;
  }
  .card{
    text-align:center;padding:48px 56px;max-width:560px;width:100%;
    background:#18181b;border:1px solid #2a2a2e;border-radius:16px;
    box-shadow:0 8px 32px rgba(0,0,0,.4);
  }
  .icon{font-size:36px;color:#22c55e;margin-bottom:20px}
  .url-row{
    display:flex;align-items:center;gap:8px;
    background:#09090b;border:1px solid #27272a;border-radius:8px;
    padding:10px 12px;margin-bottom:24px;text-align:left;
  }
  .url-text{
    flex:1;font-family:ui-monospace,monospace;font-size:11px;
    color:#71717a;word-break:break-all;
  }
  .copy-btn{
    flex-shrink:0;background:none;border:none;cursor:pointer;
    color:#52525b;padding:2px;line-height:1;transition:color .15s;
  }
  .copy-btn:hover{color:#a1a1aa}
  .copy-btn svg{display:block}
  h1{font-size:20px;font-weight:600;color:#f4f4f5;margin-bottom:8px}
  p{font-size:14px;color:#71717a;margin-bottom:28px}
  .close-btn{
    padding:9px 22px;border:none;border-radius:8px;
    background:#3f3f46;color:#d4d4d8;font-size:14px;font-weight:500;
    cursor:pointer;transition:background .15s;
  }
  .close-btn:hover{background:#52525b}
</style>
</head>
<body>
<div class="card">
  <div class="icon">✓</div>
  <div class="url-row">
    <span class="url-text" id="url"></span>
    <button class="copy-btn" onclick="copyUrl()" title="Copy">
      <svg id="icon-copy" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>
      </svg>
      <svg id="icon-check" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#22c55e" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" style="display:none">
        <polyline points="20 6 9 17 4 12"/>
      </svg>
    </button>
  </div>
  <h1>Login successful</h1>
  <p>Return to the terminal to continue.</p>
  <button class="close-btn" onclick="window.close()">Close</button>
</div>
<script>
  document.getElementById('url').textContent = window.location.href;
  function copyUrl() {
    navigator.clipboard.writeText(window.location.href).then(function() {
      document.getElementById('icon-copy').style.display = 'none';
      document.getElementById('icon-check').style.display = 'block';
      setTimeout(function() {
        document.getElementById('icon-copy').style.display = 'block';
        document.getElementById('icon-check').style.display = 'none';
      }, 1500);
    });
  }
</script>
</body>
</html>"##;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                html.len(), html,
            );
            let _ = stream.write_all(response.as_bytes()).await;

            if ret_state != state_for_loopback {
                anyhow::bail!("OAuth state mismatch — possible CSRF. Try 'atem login' again.");
            }
            if code.is_empty() {
                anyhow::bail!("No authorization code received from OAuth server.");
            }
            Ok((code, ret_state, login_id))
        }.await;
        let _ = tx_loopback.send(result).await;
    });

    // Wait 5s for the browser callback. If it doesn't arrive, show
    // a paste-URL fallback. Both paths (loopback + stdin) race via
    // the same channel — whichever delivers a valid code first wins.
    let first = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        rx.recv(),
    ).await;

    let (code, _, login_id) = match first {
        Ok(Some(result)) => {
            // Callback arrived within 5s
            println!("Login successful.");
            result?
        }
        _ => {
            // No callback yet — show paste hint and also accept stdin.
            // The loopback listener is still running, so a late callback
            // will also arrive via the same channel.
            let paste_prompt_lines = 3; // lines we'll clear on success
            println!("\nIf the browser redirect didn't complete, copy the callback URL");
            println!("from your browser's address bar and paste it here:");
            print!("> ");
            use std::io::Write;
            std::io::stdout().flush().ok();

            // Spawn stdin reader
            let tx_stdin = tx.clone();
            tokio::spawn(async move {
                let result = tokio::task::spawn_blocking(|| {
                    let mut s = String::new();
                    std::io::stdin().read_line(&mut s).map(|_| s)
                }).await;
                let outcome: Result<(String, String, String)> = match result {
                    Ok(Ok(s)) => {
                        let pasted = s.trim();
                        if pasted.is_empty() {
                            // User pressed Enter without pasting — ignore
                            // silently so the loopback can still win.
                            return;
                        }
                        let query = pasted
                            .split_once('?')
                            .map(|(_, q)| q.split('#').next().unwrap_or(q))
                            .unwrap_or("");
                        let (code, state, login_id) = parse_callback_query(query);
                        if code.is_empty() {
                            Err(anyhow::anyhow!("No authorization code found in the pasted URL."))
                        } else {
                            Ok((code, state, login_id))
                        }
                    }
                    _ => Err(anyhow::anyhow!("Failed to read input.")),
                };
                let _ = tx_stdin.send(outcome).await;
            });

            // Wait for whichever arrives first: loopback or stdin
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(285),
                rx.recv(),
            )
            .await
            .map_err(|_| anyhow::anyhow!("Login timed out."))?
            .ok_or_else(|| anyhow::anyhow!("Login failed."))??;

            // Clear the paste prompt so the terminal looks clean
            // regardless of which path won (loopback vs stdin).
            // Move cursor up N lines, clear each, move back down.
            for _ in 0..paste_prompt_lines {
                eprint!("\x1b[A\x1b[2K"); // up one line + clear line
            }
            eprintln!("Login successful.");
            result
        }
    };

    // Exchange code for tokens
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{}/api/v0/oauth/token", sso_url))
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", CLIENT_ID),
            ("code", code.as_str()),
            ("code_verifier", verifier.as_str()),
            ("redirect_uri", redirect_uri.as_str()),
        ])
        .send()
        .await?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        anyhow::bail!("Token exchange failed ({status}): {body}");
    }

    let mut session = parse_token_response(resp).await?;
    if !login_id.is_empty() {
        session.login_id = Some(login_id);
    }
    Ok(session)
}


/// Parse the JSON token response into an SsoSession.
async fn parse_token_response(resp: reqwest::Response) -> Result<SsoSession> {
    #[derive(Deserialize)]
    struct TokenResp {
        access_token: String,
        refresh_token: String,
        expires_in: u64,
    }
    let tr: TokenResp = resp.json().await?;
    let expires_at = SsoSession::now_secs() + tr.expires_in;
    Ok(SsoSession {
        access_token: tr.access_token,
        refresh_token: tr.refresh_token,
        expires_at,
        login_id: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn now() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
    }

    #[test]
    fn pkce_challenge_is_base64url_of_sha256_verifier() {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        use sha2::{Digest, Sha256};

        let (v, c) = generate_pkce();
        // Verify the challenge is SHA256(verifier) base64url
        let computed = {
            let hash = Sha256::digest(v.as_bytes());
            URL_SAFE_NO_PAD.encode(hash)
        };
        assert_eq!(c, computed, "challenge must be base64url(SHA256(verifier))");
        assert!(v.len() >= 40, "verifier must be at least 40 chars");
    }

    #[test]
    fn valid_token_returns_error_when_no_session() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("no_session.enc");
        // No file written — should error
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(valid_token_from(&path, None, "https://sso.agora.io"));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("Not logged in"), "got: {}", msg);
    }

    #[test]
    fn parse_callback_query_extracts_code_and_state() {
        let (code, state, login_id) = parse_callback_query("code=mycode123&state=mystate456");
        assert_eq!(code, "mycode123");
        assert_eq!(state, "mystate456");
        assert_eq!(login_id, "");
    }

    #[test]
    fn parse_callback_query_extracts_login_id() {
        let (code, state, login_id) = parse_callback_query("code=abc&loginId=52a4f560&state=xyz");
        assert_eq!(code, "abc");
        assert_eq!(state, "xyz");
        assert_eq!(login_id, "52a4f560");
    }

    #[test]
    fn parse_callback_query_url_decodes_values() {
        // Spaces encoded as %20, plus other percent-encoded chars
        let (code, state, _) = parse_callback_query("code=hello%20world&state=foo%2Bbar");
        assert_eq!(code, "hello world");
        assert_eq!(state, "foo+bar");
    }

    #[test]
    fn parse_callback_query_handles_missing_params() {
        let (code, state, login_id) = parse_callback_query("code=only_code");
        assert_eq!(code, "only_code");
        assert_eq!(state, "");
        assert_eq!(login_id, "");

        let (code2, state2, login_id2) = parse_callback_query("");
        assert_eq!(code2, "");
        assert_eq!(state2, "");
        assert_eq!(login_id2, "");
    }

    #[test]
    fn parse_callback_query_handles_extra_params() {
        let (code, state, login_id) = parse_callback_query("session_state=ignored&code=abc&state=xyz&loginId=user123&extra=irrelevant");
        assert_eq!(code, "abc");
        assert_eq!(state, "xyz");
        assert_eq!(login_id, "user123");
    }

    #[test]
    fn generate_state_produces_unique_values() {
        let s1 = generate_state();
        let s2 = generate_state();
        assert_ne!(s1, s2, "two states should not be identical");
        assert!(!s1.is_empty());
    }

    #[test]
    fn generate_pkce_produces_unique_pairs() {
        let (v1, c1) = generate_pkce();
        let (v2, c2) = generate_pkce();
        assert_ne!(v1, v2, "verifiers should not be identical");
        assert_ne!(c1, c2, "challenges should not be identical");
    }
}

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::credentials::Tokens;

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

    /// Its tokens.
    pub fn tokens(&self) -> Tokens {
        Tokens {
            access_token: self.access_token.clone(),
            refresh_token: self.refresh_token.clone(),
            expires_at: self.expires_at,
        }
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

/// A valid Agora access token for API calls (`connected`: the Astation
/// atem's link is connected to, if any).
///
/// Which login: the one Astation shares with the pairing while the pairing
/// allows it (`PairingRecord::usable_shared`: connected, saved for offline
/// use, or within the grace period after the link dropped), else the user's
/// own `atem login`. Its Agora tokens (`Login::agora_tokens`) are used
/// as they are until a minute before they expire. Then the own login
/// refreshes at `sso_url` (Agora SSO); a shared one is never refreshed here
/// (Agora rotates refresh tokens, which would invalidate Astation's copy):
/// Astation sends fresh ones (`credentialSync`), asked through the runtime.
pub async fn valid_token(connected: Option<&str>, sso_url: &str) -> Result<String> {
    valid_token_in(&crate::paths::ProfilePaths::default_paths(), connected, sso_url).await
}

/// `valid_token` for the profile `paths`.
pub async fn valid_token_in(
    paths: &crate::paths::ProfilePaths,
    connected: Option<&str>,
    sso_url: &str,
) -> Result<String> {
    let pairing = paths.pairing.clone();
    valid_token_with(paths, connected, sso_url, move |aid, save| {
        fetch_from_astation(pairing, aid, save)
    })
    .await
}

/// Saves fresh shared tokens into the pairing, only while it still exists.
pub type SavePaired = Box<dyn FnOnce(&Tokens) -> Result<()> + Send>;

async fn valid_token_with<F, Fut>(
    paths: &crate::paths::ProfilePaths,
    connected: Option<&str>,
    sso_url: &str,
    fetch_paired: F,
) -> Result<String>
where
    F: FnOnce(String, SavePaired) -> Fut,
    Fut: std::future::Future<Output = Result<Tokens>>,
{
    use crate::credentials::{Login, NOT_LOGGED_IN};
    use crate::pairing::PairingRecord;
    // Only for choosing the login: every save below reloads the file, so a
    // change made while atem waited (e.g. `atem unpair`) is never undone.
    let record = PairingRecord::load(&paths.pairing).ok().flatten();
    if let Some(record) = &record
        && let Some(shared) = record.usable_shared(connected, crate::credentials::now_secs())
    {
        let tokens = shared.agora_tokens()?;
        if !tokens.needs_refresh() {
            return Ok(tokens.access_token.clone());
        }
        // Updates only the pairing still on disk; never re-adds one.
        let (save_paths, save_aid) = (paths.pairing.clone(), record.astation_id.clone());
        let save: SavePaired = Box::new(move |fresh| {
            let saved = PairingRecord::update(&save_paths, &save_aid, |record| {
                if let Some(shared) = record.shared.as_mut() {
                    shared.tokens = fresh.clone();
                }
            })?;
            if !saved {
                anyhow::bail!("the pairing with Astation {save_aid} was removed meanwhile; nothing was saved");
            }
            Ok(())
        });
        let fresh = fetch_paired(record.astation_id.clone(), save).await.map_err(|e| {
            anyhow::anyhow!(
                "The session from Astation has expired, and Astation couldn't send a new one ({e}). \
                 Open Astation and try again, or run 'atem login'."
            )
        })?;
        return Ok(fresh.access_token);
    }
    let login = Login::load(&paths.login).ok_or_else(|| anyhow::anyhow!(NOT_LOGGED_IN))?;
    let tokens = login.agora_tokens()?;
    if !tokens.needs_refresh() {
        return Ok(tokens.access_token.clone());
    }
    if !login.agora_tokens_are_identity() {
        anyhow::bail!("The Agora connection of this login expired. Run 'atem login'.");
    }
    let refreshed = refresh_token(&tokens.refresh_token, sso_url)
        .await
        .map_err(|e| anyhow::anyhow!("Session expired. Run 'atem login' or re-pair. ({e})"))?;
    let Some(mut current) = Login::load(&paths.login) else {
        anyhow::bail!("Logged out while the session was refreshed. Run 'atem login'.");
    };
    current.tokens = refreshed.tokens();
    current.save(&paths.login)?;
    Ok(refreshed.access_token)
}

/// Fresh shared tokens for `astation_id`. Only `atem runtime` talks to
/// Astation: a CLI asks it (`token` operation; it never opens its own
/// connection), and the runtime itself reads what its link received
/// (Astation sends `credentialSync` on connect and whenever it refreshes;
/// the runtime saves them in the pairing).
async fn fetch_from_astation(
    paths: crate::paths::PairingPaths,
    astation_id: String,
    _save: SavePaired,
) -> Result<Tokens> {
    if !crate::runtime::in_runtime() {
        // Quiet: the menu's TUI may own the screen.
        crate::runtime::op_client::run_quiet(
            crate::runtime::protocol::OpKind::Token,
            crate::runtime::protocol::OpOptions {
                astation_id: Some(astation_id.clone()),
                ..Default::default()
            },
        )
        .await?;
    }
    fresh_shared(&paths, &astation_id)
        .ok_or_else(|| anyhow::anyhow!("Astation hasn't sent fresh credentials yet"))
}

/// The tokens Astation shared for `astation_id`, when they have time left.
pub(crate) fn fresh_shared(paths: &crate::paths::PairingPaths, astation_id: &str) -> Option<Tokens> {
    let record = crate::pairing::PairingRecord::load(paths).ok()??;
    if record.astation_id != astation_id {
        return None;
    }
    let tokens = record.shared?.agora_tokens().ok()?.clone();
    (!tokens.needs_refresh()).then_some(tokens)
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

    // Channel: loopback callback OR stdin paste both send here.
    // The 4th field is the source tag ("loopback" or "stdin") for debugging.
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Result<(String, String, String, String)>>(2);

    // Spawn loopback listener task
    let tx_loopback = tx.clone();
    let state_for_loopback = state.clone();
    tokio::spawn(async move {
        let result: Result<(String, String, String, String)> = async {
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
            Ok((code, ret_state, login_id, "loopback".to_string()))
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

    let (code, _, login_id, _source) = match first {
        Ok(Some(result)) => {
            // Callback arrived within 5s
            print!("Validating...");
            use std::io::Write;
            std::io::stdout().flush().ok();
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

            // Spawn stdin reader — loops until it gets a non-empty line
            // with a valid authorization code + matching state. Empty
            // lines (accidental Enter) and stale URLs from previous
            // login attempts (state mismatch) are rejected with a hint.
            let tx_stdin = tx.clone();
            let expected_state = state.clone();
            tokio::spawn(async move {
                loop {
                    let line = tokio::task::spawn_blocking(|| {
                        let mut s = String::new();
                        std::io::stdin().read_line(&mut s).map(|_| s)
                    }).await;
                    match line {
                        Ok(Ok(s)) => {
                            let pasted = s.trim();
                            if pasted.is_empty() {
                                continue;
                            }
                            let query = pasted
                                .split_once('?')
                                .map(|(_, q)| q.split('#').next().unwrap_or(q))
                                .unwrap_or("");
                            let (code, ret_state, login_id) = parse_callback_query(query);
                            if code.is_empty() {
                                eprintln!("No authorization code found — paste the full callback URL.");
                                continue;
                            }
                            if ret_state != expected_state {
                                eprintln!("Stale URL from a previous login attempt — paste the URL from the CURRENT browser tab.");
                                continue;
                            }
                            let _ = tx_stdin.send(Ok((code, ret_state, login_id, "stdin".to_string()))).await;
                            break;
                        }
                        _ => {
                            let _ = tx_stdin.send(Err(anyhow::anyhow!("Failed to read input."))).await;
                            break;
                        }
                    }
                }
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
            eprint!("Validating...");
            std::io::Write::flush(&mut std::io::stderr()).ok();
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
        eprintln!(" failed.");
        eprintln!("  source:       {}", _source);
        eprintln!("  redirect_uri: {}", redirect_uri);
        eprintln!("  code prefix:  {}...", &code[..code.len().min(12)]);
        anyhow::bail!("Token exchange failed ({status}): {body}");
    }
    eprintln!(" ok.");

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

    use crate::paths::ProfilePaths;
    use crate::pairing::PairingRecord;

    fn tokens(access: &str, expires_at: u64) -> Tokens {
        Tokens {
            access_token: access.into(),
            refresh_token: format!("{access}-refresh"),
            expires_at,
        }
    }

    /// A pairing with `astation-A` whose shared login expires at
    /// `expires_at`; `save`: kept for offline use.
    fn paired(paths: &ProfilePaths, expires_at: u64, save: bool) {
        let mut record = crate::pairing::tests::paired_record("astation-A");
        record.shared.as_mut().unwrap().tokens = tokens("old-access", expires_at);
        record.save_credentials = save;
        record.save(&paths.pairing).unwrap();
    }

    fn own_login(paths: &ProfilePaths, expires_at: u64) {
        crate::credentials::Login::from_sso(
            "https://sso2.agora.io",
            Some("me".into()),
            tokens("sso-access", expires_at),
        )
        .save(&paths.login)
        .unwrap();
    }

    fn shared_access(paths: &ProfilePaths) -> Option<String> {
        let record = PairingRecord::load(&paths.pairing).unwrap()?;
        Some(record.shared?.tokens.access_token)
    }

    fn profile() -> (tempfile::TempDir, ProfilePaths) {
        let dir = tempfile::tempdir().unwrap();
        let paths = ProfilePaths::in_dir(dir.path());
        (dir, paths)
    }

    /// Fails the test if Astation is asked.
    async fn never_astation(_: String, _: SavePaired) -> Result<Tokens> {
        panic!("must not contact Astation")
    }

    #[test]
    fn valid_token_returns_error_when_no_session() {
        let (_dir, paths) = profile();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(valid_token_in(&paths, None, "https://sso.agora.io"));
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("Not logged in"), "got: {}", msg);
    }

    #[test]
    fn paired_token_near_expiry_comes_from_astation_not_sso_refresh() {
        let (_dir, paths) = profile();
        paired(&paths, now() + 10, true);
        let rt = tokio::runtime::Runtime::new().unwrap();
        // An unreachable SSO URL: a refresh attempt would fail the test.
        let token = rt.block_on(valid_token_with(&paths, None, "http://127.0.0.1:1", |aid, save| async move {
            assert_eq!(aid, "astation-A");
            let fresh = tokens("new-access", now() + 7200);
            save(&fresh)?;
            Ok(fresh)
        })).unwrap();
        assert_eq!(token, "new-access");
        assert_eq!(shared_access(&paths).as_deref(), Some("new-access"));
    }

    #[test]
    fn paired_token_with_time_left_does_not_contact_astation() {
        let (_dir, paths) = profile();
        paired(&paths, now() + 3600, true);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let token = rt.block_on(valid_token_with(&paths, None, "http://127.0.0.1:1", never_astation)).unwrap();
        assert_eq!(token, "old-access");
    }

    #[test]
    fn paired_token_says_to_open_astation_when_it_cannot_renew() {
        let (_dir, paths) = profile();
        paired(&paths, now() + 10, true);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt.block_on(valid_token_with(&paths, None, "http://127.0.0.1:1", |_, _| async {
            Err(anyhow::anyhow!("timed out waiting for Astation"))
        })).unwrap_err().to_string();
        assert!(err.contains("Open Astation") && err.contains("timed out"), "{}", err);
        // The stored tokens are left alone.
        assert_eq!(shared_access(&paths).as_deref(), Some("old-access"));
    }

    #[test]
    fn the_shared_login_wins_while_usable_then_the_own_login() {
        let (_dir, paths) = profile();
        own_login(&paths, now() + 3600);
        paired(&paths, now() + 3600, false);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let token = |connected: Option<&'static str>| {
            rt.block_on(valid_token_with(&paths, connected, "http://127.0.0.1:1", never_astation))
                .unwrap()
        };
        // Never disconnected (or connected): the pairing's.
        assert_eq!(token(None), "old-access");
        // Disconnected beyond the grace period, not saved: the own login.
        PairingRecord::update(&paths.pairing, "astation-A", |record| {
            record.disconnected_at = Some(now() - crate::pairing::GRACE_PERIOD_SECS - 1);
        })
        .unwrap();
        assert_eq!(token(None), "sso-access");
        // Connected to that Astation again: the pairing's.
        assert_eq!(token(Some("astation-A")), "old-access");
    }

    #[test]
    fn a_login_without_an_agora_connection_says_so() {
        let (_dir, paths) = profile();
        crate::credentials::Login {
            issuer: "auth.agora.build".into(),
            subject: Some("me".into()),
            tokens: tokens("identity", now() + 3600),
            connections: Default::default(),
        }
        .save(&paths.login)
        .unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let err = rt
            .block_on(valid_token_with(&paths, None, "http://127.0.0.1:1", never_astation))
            .unwrap_err()
            .to_string();
        assert_eq!(err, crate::credentials::NO_AGORA_CONNECTION);
    }

    #[test]
    fn an_unpair_during_the_paired_refresh_is_not_undone() {
        let (_dir, paths) = profile();
        paired(&paths, now() + 10, true);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let src_dir = paths.dir.clone();
        let result = rt.block_on(valid_token_with(&paths, None, "http://127.0.0.1:1", |_, save| async move {
            // `atem unpair` runs while atem waits for Astation.
            crate::pairing::unpair(&crate::status::Sources::in_dir(&src_dir)).unwrap();
            let fresh = tokens("new-access", now() + 7200);
            save(&fresh)?;
            Ok(fresh)
        }));
        assert!(result.is_err(), "a removed pairing yields no token");
        assert!(!paths.pairing.record.exists(), "the stale copy re-added the pairing");
    }

    #[test]
    fn a_logout_during_the_sso_refresh_is_not_undone() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (_dir, paths) = profile();
        own_login(&paths, now() + 10);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let login = paths.login.clone();
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 8192];
                let _ = socket.read(&mut buf).await.unwrap();
                // `atem logout` runs while the SSO refresh is in flight.
                crate::credentials::Login::remove(&login).unwrap();
                let body = r#"{"access_token":"fresh","refresh_token":"fresh-refresh","expires_in":3600}"#;
                let reply = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(reply.as_bytes()).await.unwrap();
                socket.shutdown().await.unwrap();
            });
            let result = valid_token_with(&paths, None, &url, never_astation).await;
            server.await.unwrap();
            result
        });
        assert!(result.unwrap_err().to_string().contains("Logged out"));
        assert!(!paths.login.exists(), "the stale copy re-added the login");
    }

    #[test]
    fn the_own_login_refreshes_at_its_sso() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (_dir, paths) = profile();
        own_login(&paths, now() + 10);
        let rt = tokio::runtime::Runtime::new().unwrap();
        let token = rt.block_on(async {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut buf = vec![0u8; 8192];
                let _ = socket.read(&mut buf).await.unwrap();
                let body = r#"{"access_token":"fresh","refresh_token":"fresh-refresh","expires_in":3600}"#;
                let reply = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                socket.write_all(reply.as_bytes()).await.unwrap();
                socket.shutdown().await.unwrap();
            });
            let token = valid_token_with(&paths, None, &url, never_astation).await.unwrap();
            server.await.unwrap();
            token
        });
        assert_eq!(token, "fresh");
        let login = crate::credentials::Login::load(&paths.login).unwrap();
        assert_eq!(login.tokens.access_token, "fresh");
        assert_eq!(login.issuer, "sso2.agora.io", "the issuer stays");
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

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use tokio::net::TcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SsoSession {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: u64, // Unix seconds
}

impl SsoSession {
    // ── canonical path ──────────────────────────────────────────────

    pub fn session_path() -> PathBuf {
        crate::config::AtemConfig::config_dir().join("sso_session.json")
    }

    // ── persistence (public path) ────────────────────────────────────

    pub fn load() -> Option<Self> {
        Self::load_from(&Self::session_path())
    }

    pub fn save(&self) -> Result<()> {
        self.save_to(&Self::session_path())
    }

    pub fn delete() -> Result<()> {
        Self::delete_at(&Self::session_path())
    }

    // ── persistence (path-injectable, for tests) ─────────────────────

    pub fn load_from(path: &std::path::Path) -> Option<Self> {
        let content = fs::read_to_string(path).ok()?;
        serde_json::from_str(&content).ok()
    }

    pub fn save_to(&self, path: &std::path::Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, &json)?;
        // chmod 0600
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        Ok(())
    }

    pub fn delete_at(path: &std::path::Path) -> Result<()> {
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    // ── token access ─────────────────────────────────────────────────

    pub(crate) fn now_secs() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }

    pub fn needs_refresh(&self) -> bool {
        self.expires_at < Self::now_secs() + 60
    }
}

/// OAuth 2.0 client_id registered in the Agora SSO server for CLI applications.
const CLIENT_ID: &str = "agora_web_cli";

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

/// Load session from canonical path, refresh if near-expiry, return access token.
/// Returns Err if no session file exists.
pub async fn valid_token(sso_url: &str) -> Result<String> {
    valid_token_from(&SsoSession::session_path(), sso_url).await
}

/// Path-injectable version used in tests.
pub async fn valid_token_from(path: &std::path::Path, sso_url: &str) -> Result<String> {
    let mut session = SsoSession::load_from(path)
        .ok_or_else(|| anyhow::anyhow!("Not logged in. Run 'atem login' first."))?;

    if session.needs_refresh() {
        session = refresh_token(&session.refresh_token, sso_url)
            .await
            .map_err(|e| anyhow::anyhow!("Session expired. Run 'atem login' to re-authenticate. ({e})"))?;
        session.save_to(path)?;
    }

    Ok(session.access_token.clone())
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

/// Parse `code` and `state` from an OAuth callback query string.
/// Input: the raw query string after `?` (e.g. "code=abc&state=xyz")
/// Returns: (code, state) — both URL-decoded, empty string if not present
fn parse_callback_query(query: &str) -> (String, String) {
    let mut code = String::new();
    let mut state = String::new();
    for pair in query.split('&') {
        if let Some(v) = pair.strip_prefix("code=") {
            code = urlencoding::decode(v).unwrap_or_default().into_owned();
        } else if let Some(v) = pair.strip_prefix("state=") {
            state = urlencoding::decode(v).unwrap_or_default().into_owned();
        }
    }
    (code, state)
}

/// Full OAuth 2.0 + PKCE browser login flow.
/// Opens the browser (falls back to printing URL), waits for the loopback callback,
/// exchanges the code for tokens, saves the session, and returns it.
pub async fn run_login_flow(sso_url: &str) -> Result<SsoSession> {
    let (verifier, challenge) = generate_pkce();
    let state = generate_state();

    // Bind on a random port
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
    let _ = crate::rtc_test_server::open_browser(&auth_url);
    println!("Waiting for login to complete...");

    // Accept exactly one connection on the loopback
    let (mut stream, _) = tokio::time::timeout(
        std::time::Duration::from_secs(300),
        listener.accept(),
    )
    .await
    .map_err(|_| anyhow::anyhow!("Login timed out after 5 minutes."))?
    .map_err(|e| anyhow::anyhow!("Loopback accept failed: {}", e))?;

    let mut buf = Vec::new();
    let mut tmp = [0u8; 4096];
    loop {
        let n = stream.read(&mut tmp).await?;
        if n == 0 { break; }
        buf.extend_from_slice(&tmp[..n]);
        if buf.windows(4).any(|w| w == b"\r\n\r\n") { break; }
    }
    let request = String::from_utf8_lossy(&buf);

    // Parse the request line: "GET /oauth/callback?code=xxx&state=yyy HTTP/1.1"
    let query = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|path| path.split_once('?').map(|(_, q)| q))
        .unwrap_or("");

    let (code, returned_state) = parse_callback_query(query);

    // Validate before responding to browser
    let (html_body, error) = if returned_state != state {
        (
            "<html><body><h2>Login failed — state mismatch. Try again.</h2></body></html>",
            Some("OAuth state mismatch — possible CSRF. Try 'atem login' again."),
        )
    } else if code.is_empty() {
        (
            "<html><body><h2>Login failed — no code received. Try again.</h2></body></html>",
            Some("No authorization code received from OAuth server."),
        )
    } else {
        (
            "<html><body><h2>Login successful — return to the terminal.</h2></body></html>",
            None,
        )
    };

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        html_body.len(),
        html_body,
    );
    stream.write_all(response.as_bytes()).await?;
    drop(stream);

    if let Some(err) = error {
        anyhow::bail!("{}", err);
    }

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

    let session = parse_token_response(resp).await?;
    session.save()?;
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
    fn sso_session_save_and_load_round_trip() {
        // Use a temp path so we don't touch real config
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sso_session.json");

        let session = SsoSession {
            access_token: "access_abc".to_string(),
            refresh_token: "refresh_xyz".to_string(),
            expires_at: now() + 3600,
        };
        session.save_to(&path).unwrap();

        let loaded = SsoSession::load_from(&path).unwrap();
        assert_eq!(loaded.access_token, "access_abc");
        assert_eq!(loaded.refresh_token, "refresh_xyz");
        assert_eq!(loaded.expires_at, session.expires_at);
    }

    #[test]
    fn sso_session_delete_removes_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sso_session.json");

        let session = SsoSession {
            access_token: "tok".to_string(),
            refresh_token: "ref".to_string(),
            expires_at: now() + 3600,
        };
        session.save_to(&path).unwrap();
        assert!(path.exists());
        SsoSession::delete_at(&path).unwrap();
        assert!(!path.exists());
    }

    #[test]
    fn load_returns_none_when_file_missing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("no_such_file.json");
        assert!(SsoSession::load_from(&path).is_none());
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
        let path = dir.path().join("no_session.json");
        // No file written — should error
        let rt = tokio::runtime::Runtime::new().unwrap();
        let result = rt.block_on(valid_token_from(&path, "https://sso.agora.io"));
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("Not logged in"), "got: {}", msg);
    }

    #[test]
    fn parse_callback_query_extracts_code_and_state() {
        let (code, state) = parse_callback_query("code=mycode123&state=mystate456");
        assert_eq!(code, "mycode123");
        assert_eq!(state, "mystate456");
    }

    #[test]
    fn parse_callback_query_url_decodes_values() {
        // Spaces encoded as %20, plus other percent-encoded chars
        let (code, state) = parse_callback_query("code=hello%20world&state=foo%2Bbar");
        assert_eq!(code, "hello world");
        assert_eq!(state, "foo+bar");
    }

    #[test]
    fn parse_callback_query_handles_missing_params() {
        let (code, state) = parse_callback_query("code=only_code");
        assert_eq!(code, "only_code");
        assert_eq!(state, "");

        let (code2, state2) = parse_callback_query("");
        assert_eq!(code2, "");
        assert_eq!(state2, "");
    }

    #[test]
    fn parse_callback_query_handles_extra_params() {
        let (code, state) = parse_callback_query("session_state=ignored&code=abc&state=xyz&extra=irrelevant");
        assert_eq!(code, "abc");
        assert_eq!(state, "xyz");
    }

    #[test]
    fn needs_refresh_true_when_near_expiry() {
        let session = SsoSession {
            access_token: "tok".to_string(),
            refresh_token: "ref".to_string(),
            expires_at: SsoSession::now_secs() + 30, // expires in 30s, buffer is 60s
        };
        assert!(session.needs_refresh(), "should need refresh when < 60s remaining");
    }

    #[test]
    fn needs_refresh_false_when_plenty_of_time() {
        let session = SsoSession {
            access_token: "tok".to_string(),
            refresh_token: "ref".to_string(),
            expires_at: SsoSession::now_secs() + 3600, // 1 hour remaining
        };
        assert!(!session.needs_refresh(), "should not need refresh with 1h remaining");
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

use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
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
}

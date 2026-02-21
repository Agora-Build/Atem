use anyhow::{Result, anyhow};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_SERVER_URL: &str = "https://station.agora.build";

/// Stored session after successful pairing.
/// Sessions expire after 7 days of inactivity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    pub session_id: String,
    pub token: String,
    pub astation_id: String,  // Unique ID of the Astation instance
    pub hostname: String,
    pub last_activity: u64,  // Unix timestamp of last connection/message
}

impl AuthSession {
    /// Check if this session is still valid (not expired).
    /// Sessions expire after 7 days of inactivity.
    pub fn is_valid(&self) -> bool {
        let now = now_timestamp();
        let age = now.saturating_sub(self.last_activity);
        age < 7 * 24 * 60 * 60 // 7 days in seconds
    }

    /// Refresh the session activity timestamp to current time.
    /// Call this on every connection or message to keep session alive.
    pub fn refresh(&mut self) {
        self.last_activity = now_timestamp();
    }

    /// Create a new session with current timestamp.
    pub fn new(session_id: String, token: String, astation_id: String, hostname: String) -> Self {
        Self {
            session_id,
            token,
            astation_id,
            hostname,
            last_activity: now_timestamp(),
        }
    }

    /// Get age in seconds since last activity.
    pub fn age_seconds(&self) -> u64 {
        now_timestamp().saturating_sub(self.last_activity)
    }
}

/// Get current Unix timestamp in seconds.
fn now_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs()
}

/// Manages multiple sessions, one per Astation instance.
/// Sessions are keyed by astation_id, allowing seamless endpoint switching.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SessionManager {
    sessions: std::collections::HashMap<String, AuthSession>,
}

impl SessionManager {
    /// Load sessions from disk (~/.config/atem/sessions.json).
    /// Returns empty SessionManager if file doesn't exist.
    pub fn load() -> Result<Self> {
        let path = Self::sessions_path()?;

        if !path.exists() {
            return Ok(Self::default());
        }

        let content = std::fs::read_to_string(&path)
            .map_err(|e| anyhow!("Failed to read sessions file: {}", e))?;

        let manager: SessionManager = serde_json::from_str(&content)
            .map_err(|e| anyhow!("Failed to parse sessions file: {}", e))?;

        Ok(manager)
    }

    /// Save all sessions to disk.
    pub fn save(&self) -> Result<()> {
        let path = Self::sessions_path()?;

        // Ensure parent directory exists
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| anyhow!("Failed to create config directory: {}", e))?;
        }

        let json = serde_json::to_string_pretty(self)
            .map_err(|e| anyhow!("Failed to serialize sessions: {}", e))?;

        std::fs::write(&path, json)
            .map_err(|e| anyhow!("Failed to write sessions file: {}", e))?;

        Ok(())
    }

    /// Get session for a specific Astation (if valid).
    pub fn get(&self, astation_id: &str) -> Option<&AuthSession> {
        self.sessions.get(astation_id).filter(|s| s.is_valid())
    }

    /// Get mutable session for a specific Astation (if valid).
    pub fn get_mut(&mut self, astation_id: &str) -> Option<&mut AuthSession> {
        self.sessions.get_mut(astation_id).filter(|s| s.is_valid())
    }

    /// Save or update a session for a specific Astation.
    pub fn save_session(&mut self, session: AuthSession) -> Result<()> {
        let astation_id = session.astation_id.clone();
        self.sessions.insert(astation_id, session);
        self.save()
    }

    /// Remove a session for a specific Astation.
    pub fn remove(&mut self, astation_id: &str) -> Result<()> {
        self.sessions.remove(astation_id);
        self.save()
    }

    /// Get all active (valid) sessions.
    pub fn active_sessions(&self) -> Vec<&AuthSession> {
        self.sessions.values().filter(|s| s.is_valid()).collect()
    }

    /// Clean up expired sessions and save.
    pub fn cleanup_expired(&mut self) -> Result<()> {
        self.sessions.retain(|_, session| session.is_valid());
        self.save()
    }

    /// Get the path to the sessions file.
    fn sessions_path() -> Result<std::path::PathBuf> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| anyhow!("Could not determine config directory"))?;
        Ok(config_dir.join("atem").join("sessions.json"))
    }
}

/// Generate a random 8-digit OTP code.
pub fn generate_otp() -> String {
    let mut rng = rand::thread_rng();
    let code: u32 = rng.gen_range(10_000_000..100_000_000);
    code.to_string()
}

/// Build the deep link URL that activates the local Astation app.
pub fn build_deep_link(session_id: &str, hostname: &str, otp: &str) -> String {
    format!(
        "astation://auth?id={}&tag={}&otp={}",
        session_id, hostname, otp
    )
}

/// Build the web fallback URL for when Astation is not installed locally.
pub fn build_web_fallback_url(server_url: &str, session_id: &str, hostname: &str) -> String {
    format!(
        "{}/auth?id={}&tag={}",
        server_url.trim_end_matches('/'),
        session_id,
        hostname
    )
}

/// Get the local machine hostname.
pub fn get_hostname() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Try to open a URL (deep link or web page) on the local system.
pub fn open_url(url: &str) -> Result<()> {
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
            .args(["/c", "start", url])
            .spawn()?;
    }
    Ok(())
}

/// Create a new auth session on the Astation server.
pub async fn create_server_session(
    server_url: &str,
    hostname: &str,
) -> Result<(String, String, String)> {
    let url = format!("{}/api/sessions", server_url.trim_end_matches('/'));

    let client = reqwest::Client::new();
    let resp = client
        .post(&url)
        .json(&serde_json::json!({ "hostname": hostname }))
        .send()
        .await
        .map_err(|e| anyhow!("Failed to create session: {}", e))?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        return Err(anyhow!("Server returned {}: {}", status, body));
    }

    #[derive(Deserialize)]
    struct CreateResp {
        id: String,
        otp: String,
    }

    let data: CreateResp = resp
        .json()
        .await
        .map_err(|e| anyhow!("Failed to parse server response: {}", e))?;

    Ok((data.id, data.otp, server_url.to_string()))
}

/// Poll the server for session status until granted, denied, or timeout.
pub async fn poll_session_status(
    server_url: &str,
    session_id: &str,
    astation_id: &str,
    timeout: Duration,
) -> Result<AuthSession> {
    let url = format!(
        "{}/api/sessions/{}/status",
        server_url.trim_end_matches('/'),
        session_id
    );
    let client = reqwest::Client::new();
    let start = std::time::Instant::now();

    loop {
        if start.elapsed() > timeout {
            return Err(anyhow!("Authentication timed out"));
        }

        let resp = client
            .get(&url)
            .send()
            .await
            .map_err(|e| anyhow!("Failed to check session status: {}", e))?;

        if resp.status().is_success() {
            #[derive(Deserialize)]
            struct StatusResp {
                id: String,
                status: String,
                token: Option<String>,
            }

            let data: StatusResp = resp.json().await?;

            match data.status.as_str() {
                "granted" => {
                    let token = data
                        .token
                        .ok_or_else(|| anyhow!("Granted but no token received"))?;
                    return Ok(AuthSession::new(
                        data.id,
                        token,
                        astation_id.to_string(),
                        get_hostname(),
                    ));
                }
                "denied" => {
                    return Err(anyhow!("Authentication was denied"));
                }
                "expired" => {
                    return Err(anyhow!("Session expired"));
                }
                _ => {
                    // Still pending, wait and retry
                    tokio::time::sleep(Duration::from_secs(2)).await;
                }
            }
        } else if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(anyhow!("Session not found or expired"));
        } else {
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
    }
}

/// Run the full login flow.
/// Note: This is for the old HTTP-based auth flow. For WebSocket-based auth,
/// the astation_id is received in the auth_required message.
pub async fn run_login_flow(server_url: Option<&str>, astation_id: &str) -> Result<AuthSession> {
    let server = server_url.unwrap_or(DEFAULT_SERVER_URL);
    let hostname = get_hostname();

    println!("Authenticating with Astation...");
    println!();

    // Step 1: Create session on server
    let (session_id, otp, _server) = create_server_session(server, &hostname).await?;

    // Step 2: Try deep link to local Astation
    let deep_link = build_deep_link(&session_id, &hostname, &otp);
    let web_url = build_web_fallback_url(server, &session_id, &hostname);

    println!("OTP Code: {}", otp);
    println!();

    let _ = open_url(&deep_link);

    println!("If Astation didn't open automatically, visit:");
    println!("  {}", web_url);
    println!();
    println!("Waiting for authorization...");

    // Step 3: Poll for grant
    let timeout = Duration::from_secs(300); // 5 minutes
    let session = poll_session_status(server, &session_id, astation_id, timeout).await?;

    println!("Authenticated successfully!");
    Ok(session)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn otp_is_8_digits() {
        let otp = generate_otp();
        assert_eq!(otp.len(), 8);
        assert!(otp.chars().all(|c| c.is_ascii_digit()));
    }

    #[test]
    fn otp_is_random() {
        let a = generate_otp();
        let b = generate_otp();
        assert_ne!(a, b);
    }

    #[test]
    fn deep_link_format() {
        let link = build_deep_link("sess123", "my-host", "12345678");
        assert_eq!(link, "astation://auth?id=sess123&tag=my-host&otp=12345678");
    }

    #[test]
    fn web_fallback_url_format() {
        let url = build_web_fallback_url("https://station.agora.build", "sess123", "my-host");
        assert_eq!(
            url,
            "https://station.agora.build/auth?id=sess123&tag=my-host"
        );
    }

    #[test]
    fn web_fallback_url_strips_trailing_slash() {
        let url = build_web_fallback_url("https://station.agora.build/", "s1", "h1");
        assert_eq!(url, "https://station.agora.build/auth?id=s1&tag=h1");
    }

    #[test]
    fn auth_session_serialization_roundtrip() {
        let session = AuthSession::new(
            "test-id".to_string(),
            "test-token".to_string(),
            "astation-123".to_string(),
            "test-host".to_string(),
        );
        let json = serde_json::to_string(&session).unwrap();
        let parsed: AuthSession = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.session_id, "test-id");
        assert_eq!(parsed.token, "test-token");
        assert_eq!(parsed.astation_id, "astation-123");
        assert_eq!(parsed.hostname, "test-host");
        assert!(parsed.last_activity > 0);
    }

    #[test]
    fn hostname_returns_non_empty() {
        let h = get_hostname();
        assert!(!h.is_empty());
    }

    // --- Mock server helpers ---

    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Spin up a one-shot HTTP server that returns the given body for any request.
    async fn mock_http_server(response_body: &'static str, status: u16) -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let status_line = match status {
            200 => "200 OK",
            404 => "404 Not Found",
            _ => "500 Internal Server Error",
        };
        tokio::spawn(async move {
            // Accept multiple connections (poll loops retry)
            loop {
                if let Ok((mut stream, _)) = listener.accept().await {
                    let body = response_body;
                    let resp = format!(
                        "HTTP/1.1 {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        status_line,
                        body.len(),
                        body
                    );
                    let mut buf = [0u8; 4096];
                    let _ = stream.read(&mut buf).await;
                    let _ = stream.write_all(resp.as_bytes()).await;
                }
            }
        });
        addr
    }

    #[tokio::test]
    async fn create_server_session_parses_id_field() {
        let body = r#"{"id":"abc-123","otp":"12345678","hostname":"host","status":"pending","created_at":"2024-01-01T00:00:00Z","expires_at":"2024-01-01T04:00:00Z"}"#;
        let addr = mock_http_server(body, 200).await;
        let url = format!("http://{}", addr);
        let (session_id, otp, _) = create_server_session(&url, "test-host").await.unwrap();
        assert_eq!(session_id, "abc-123");
        assert_eq!(otp, "12345678");
    }

    #[tokio::test]
    async fn poll_session_status_parses_granted() {
        let body = r#"{"id":"abc-123","status":"granted","token":"tok-xyz"}"#;
        let addr = mock_http_server(body, 200).await;
        let url = format!("http://{}", addr);
        let session = poll_session_status(&url, "abc-123", "astation-test", Duration::from_secs(5))
            .await
            .unwrap();
        assert_eq!(session.session_id, "abc-123");
        assert_eq!(session.token, "tok-xyz");
        assert_eq!(session.astation_id, "astation-test");
    }

    #[tokio::test]
    async fn poll_session_status_returns_error_on_denied() {
        let body = r#"{"id":"abc-123","status":"denied"}"#;
        let addr = mock_http_server(body, 200).await;
        let url = format!("http://{}", addr);
        let err = poll_session_status(&url, "abc-123", "astation-test", Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("denied"));
    }

    #[tokio::test]
    async fn poll_session_status_returns_error_on_404() {
        let body = r#"{"error":"not found"}"#;
        let addr = mock_http_server(body, 404).await;
        let url = format!("http://{}", addr);
        let err = poll_session_status(&url, "no-such-id", "astation-test", Duration::from_secs(5))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("not found") || err.to_string().contains("expired"));
    }

    // ===== Session Expiry & Refresh Tests =====

    #[test]
    fn session_is_valid_when_fresh() {
        let session = AuthSession::new(
            "sess-123".to_string(),
            "token-abc".to_string(),
            "astation-home".to_string(),
            "test-host".to_string(),
        );
        assert!(session.is_valid(), "Fresh session should be valid");
        assert_eq!(session.age_seconds(), 0, "Fresh session age should be 0");
    }

    #[test]
    fn session_expires_after_7_days() {
        let mut session = AuthSession::new(
            "sess-123".to_string(),
            "token-abc".to_string(),
            "astation-home".to_string(),
            "test-host".to_string(),
        );

        // Simulate 7 days + 1 second of inactivity
        let seven_days_ago = now_timestamp() - (7 * 24 * 60 * 60 + 1);
        session.last_activity = seven_days_ago;

        assert!(!session.is_valid(), "Session should expire after 7 days");
        assert!(session.age_seconds() > 7 * 24 * 60 * 60, "Age should be over 7 days");
    }

    #[test]
    fn session_valid_just_before_expiry() {
        let mut session = AuthSession::new(
            "sess-123".to_string(),
            "token-abc".to_string(),
            "astation-home".to_string(),
            "test-host".to_string(),
        );

        // Simulate 7 days - 1 second of inactivity (just before expiry)
        let almost_seven_days_ago = now_timestamp() - (7 * 24 * 60 * 60 - 1);
        session.last_activity = almost_seven_days_ago;

        assert!(session.is_valid(), "Session should be valid just before 7 days");
    }

    #[test]
    fn session_refresh_extends_validity() {
        let mut session = AuthSession::new(
            "sess-123".to_string(),
            "token-abc".to_string(),
            "astation-home".to_string(),
            "test-host".to_string(),
        );

        // Simulate 6 days of inactivity
        let six_days_ago = now_timestamp() - (6 * 24 * 60 * 60);
        session.last_activity = six_days_ago;

        assert!(session.is_valid(), "6-day-old session should still be valid");

        // Refresh the session (simulates new connection/message)
        session.refresh();

        // Now it should be fresh again
        assert!(session.is_valid(), "Refreshed session should be valid");
        assert!(session.age_seconds() < 5, "Refreshed session should have age near 0");
    }

    #[test]
    fn session_refresh_prevents_expiry() {
        let mut session = AuthSession::new(
            "sess-123".to_string(),
            "token-abc".to_string(),
            "astation-home".to_string(),
            "test-host".to_string(),
        );

        // Simulate expired session (8 days old)
        let eight_days_ago = now_timestamp() - (8 * 24 * 60 * 60);
        session.last_activity = eight_days_ago;

        assert!(!session.is_valid(), "8-day-old session should be expired");

        // Refresh won't help - expired is expired (need new pairing)
        session.refresh();

        // But now it's fresh again (this simulates creating a new session after re-pairing)
        assert!(session.is_valid(), "After refresh, session is valid");
    }

    #[test]
    fn session_age_calculation() {
        let mut session = AuthSession::new(
            "sess-123".to_string(),
            "token-abc".to_string(),
            "astation-home".to_string(),
            "test-host".to_string(),
        );

        // Test various ages
        let test_cases = vec![
            (1 * 60 * 60, "1 hour"),              // 1 hour
            (24 * 60 * 60, "1 day"),              // 1 day
            (3 * 24 * 60 * 60, "3 days"),         // 3 days
            (6 * 24 * 60 * 60, "6 days"),         // 6 days
        ];

        for (age_seconds, label) in test_cases {
            session.last_activity = now_timestamp() - age_seconds;
            let actual_age = session.age_seconds();

            // Allow 1 second tolerance for test execution time
            assert!(
                (actual_age as i64 - age_seconds as i64).abs() <= 1,
                "{}: expected age {}, got {}",
                label,
                age_seconds,
                actual_age
            );
        }
    }

    #[test]
    fn session_save_and_load_preserves_activity() {
        // Create a temp session file
        let temp_dir = std::env::temp_dir();
        let session_path = temp_dir.join("test_session_activity.json");

        // Clean up any existing file
        let _ = std::fs::remove_file(&session_path);

        let original = AuthSession::new(
            "sess-456".to_string(),
            "token-xyz".to_string(),
            "astation-office".to_string(),
            "test-machine".to_string(),
        );

        // Save to file
        let json = serde_json::to_string_pretty(&original).unwrap();
        std::fs::write(&session_path, &json).unwrap();

        // Load from file
        let content = std::fs::read_to_string(&session_path).unwrap();
        let loaded: AuthSession = serde_json::from_str(&content).unwrap();

        // Verify all fields match
        assert_eq!(loaded.session_id, original.session_id);
        assert_eq!(loaded.token, original.token);
        assert_eq!(loaded.astation_id, original.astation_id);
        assert_eq!(loaded.hostname, original.hostname);
        assert_eq!(loaded.last_activity, original.last_activity);
        assert!(loaded.is_valid());

        // Clean up
        let _ = std::fs::remove_file(&session_path);
    }

    #[test]
    fn multiple_sessions_independent() {
        // Simulate multiple Astation instances with different sessions
        let session_b = AuthSession::new(
            "sess-machine-b".to_string(),
            "token-b".to_string(),
            "astation-home".to_string(),
            "machine-b".to_string(),
        );

        let mut session_c = AuthSession::new(
            "sess-machine-c".to_string(),
            "token-c".to_string(),
            "astation-office".to_string(),
            "machine-c".to_string(),
        );

        // Machine C is old (5 days)
        session_c.last_activity = now_timestamp() - (5 * 24 * 60 * 60);

        // Both should be valid
        assert!(session_b.is_valid(), "Machine B session should be valid");
        assert!(session_c.is_valid(), "Machine C session (5 days) should be valid");

        // Refresh machine C
        session_c.refresh();

        // Machine B should be unaffected
        assert!(session_b.age_seconds() < 5, "Machine B should still be fresh");
        assert!(session_c.age_seconds() < 5, "Machine C should now be fresh");
    }

    // ===== SessionManager Tests =====

    #[test]
    fn session_manager_starts_empty() {
        let manager = SessionManager::default();
        assert_eq!(manager.active_sessions().len(), 0);
    }

    #[test]
    fn session_manager_save_and_load() {
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join("test_session_manager.json");
        let _ = std::fs::remove_file(&temp_path);

        // Create manager with sessions
        let mut manager = SessionManager::default();
        let session1 = AuthSession::new(
            "sess-1".to_string(),
            "token-1".to_string(),
            "astation-home".to_string(),
            "laptop".to_string(),
        );
        let session2 = AuthSession::new(
            "sess-2".to_string(),
            "token-2".to_string(),
            "astation-office".to_string(),
            "desktop".to_string(),
        );

        manager.sessions.insert("astation-home".to_string(), session1.clone());
        manager.sessions.insert("astation-office".to_string(), session2.clone());

        // Serialize and save
        let json = serde_json::to_string_pretty(&manager).unwrap();
        std::fs::write(&temp_path, json).unwrap();

        // Load from file
        let content = std::fs::read_to_string(&temp_path).unwrap();
        let loaded: SessionManager = serde_json::from_str(&content).unwrap();

        // Verify sessions loaded correctly
        assert_eq!(loaded.sessions.len(), 2);
        assert!(loaded.get("astation-home").is_some());
        assert!(loaded.get("astation-office").is_some());
        assert_eq!(loaded.get("astation-home").unwrap().session_id, "sess-1");
        assert_eq!(loaded.get("astation-office").unwrap().session_id, "sess-2");

        // Clean up
        let _ = std::fs::remove_file(&temp_path);
    }

    #[test]
    fn session_manager_get_valid_session() {
        let mut manager = SessionManager::default();
        let session = AuthSession::new(
            "sess-abc".to_string(),
            "token-abc".to_string(),
            "astation-home".to_string(),
            "my-laptop".to_string(),
        );

        manager.sessions.insert("astation-home".to_string(), session);

        // Should return the session
        let retrieved = manager.get("astation-home");
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().session_id, "sess-abc");
    }

    #[test]
    fn session_manager_get_expired_session_returns_none() {
        let mut manager = SessionManager::default();
        let mut session = AuthSession::new(
            "sess-old".to_string(),
            "token-old".to_string(),
            "astation-home".to_string(),
            "my-laptop".to_string(),
        );

        // Make session expired (8 days old)
        session.last_activity = now_timestamp() - (8 * 24 * 60 * 60);
        manager.sessions.insert("astation-home".to_string(), session);

        // Should return None for expired session
        assert!(manager.get("astation-home").is_none());
    }

    #[test]
    fn session_manager_get_nonexistent() {
        let manager = SessionManager::default();
        assert!(manager.get("nonexistent-astation").is_none());
    }

    #[test]
    fn session_manager_multiple_astations() {
        let mut manager = SessionManager::default();

        // Add sessions for 3 different Astation instances
        let session_home = AuthSession::new(
            "sess-home".to_string(),
            "token-home".to_string(),
            "astation-home".to_string(),
            "laptop".to_string(),
        );
        let session_office = AuthSession::new(
            "sess-office".to_string(),
            "token-office".to_string(),
            "astation-office".to_string(),
            "desktop".to_string(),
        );
        let session_lab = AuthSession::new(
            "sess-lab".to_string(),
            "token-lab".to_string(),
            "astation-lab".to_string(),
            "workstation".to_string(),
        );

        manager.sessions.insert("astation-home".to_string(), session_home);
        manager.sessions.insert("astation-office".to_string(), session_office);
        manager.sessions.insert("astation-lab".to_string(), session_lab);

        // All sessions should be accessible
        assert_eq!(manager.sessions.len(), 3);
        assert!(manager.get("astation-home").is_some());
        assert!(manager.get("astation-office").is_some());
        assert!(manager.get("astation-lab").is_some());
        assert_eq!(manager.active_sessions().len(), 3);
    }

    #[test]
    fn session_manager_cleanup_expired() {
        let mut manager = SessionManager::default();

        // Add 2 valid sessions and 2 expired sessions
        let valid1 = AuthSession::new(
            "sess-valid1".to_string(),
            "token-valid1".to_string(),
            "astation-home".to_string(),
            "laptop".to_string(),
        );
        let valid2 = AuthSession::new(
            "sess-valid2".to_string(),
            "token-valid2".to_string(),
            "astation-office".to_string(),
            "desktop".to_string(),
        );

        let mut expired1 = AuthSession::new(
            "sess-expired1".to_string(),
            "token-expired1".to_string(),
            "astation-old1".to_string(),
            "old-laptop".to_string(),
        );
        expired1.last_activity = now_timestamp() - (8 * 24 * 60 * 60);

        let mut expired2 = AuthSession::new(
            "sess-expired2".to_string(),
            "token-expired2".to_string(),
            "astation-old2".to_string(),
            "old-desktop".to_string(),
        );
        expired2.last_activity = now_timestamp() - (10 * 24 * 60 * 60);

        manager.sessions.insert("astation-home".to_string(), valid1);
        manager.sessions.insert("astation-office".to_string(), valid2);
        manager.sessions.insert("astation-old1".to_string(), expired1);
        manager.sessions.insert("astation-old2".to_string(), expired2);

        assert_eq!(manager.sessions.len(), 4);
        assert_eq!(manager.active_sessions().len(), 2); // Only valid ones

        // Cleanup should remove expired sessions
        manager.sessions.retain(|_, session| session.is_valid());

        assert_eq!(manager.sessions.len(), 2);
        assert!(manager.get("astation-home").is_some());
        assert!(manager.get("astation-office").is_some());
        assert!(manager.get("astation-old1").is_none());
        assert!(manager.get("astation-old2").is_none());
    }

    #[test]
    fn session_manager_same_atem_different_endpoints() {
        // This tests the core feature: one session works for both local and relay
        let mut manager = SessionManager::default();

        let session = AuthSession::new(
            "sess-universal".to_string(),
            "token-universal".to_string(),
            "astation-home-abc123".to_string(), // Unique Astation ID
            "my-laptop".to_string(),
        );

        manager.sessions.insert("astation-home-abc123".to_string(), session.clone());

        // Connection 1: Local WebSocket (ws://127.0.0.1:8080/ws)
        // Uses astation_id from auth_required → finds session
        assert!(manager.get("astation-home-abc123").is_some());

        // Connection 2: Relay server (https://station.agora.build)
        // Uses same astation_id from auth_required → finds SAME session
        assert!(manager.get("astation-home-abc123").is_some());

        // Both connections share one session!
        assert_eq!(manager.sessions.len(), 1);
    }

    #[test]
    fn session_manager_get_mut_allows_refresh() {
        let mut manager = SessionManager::default();

        let mut session = AuthSession::new(
            "sess-abc".to_string(),
            "token-abc".to_string(),
            "astation-home".to_string(),
            "laptop".to_string(),
        );

        // Make session 5 days old
        session.last_activity = now_timestamp() - (5 * 24 * 60 * 60);
        manager.sessions.insert("astation-home".to_string(), session);

        // Get mutable reference and refresh
        if let Some(session) = manager.get_mut("astation-home") {
            session.refresh();
        }

        // Session should now be fresh
        let refreshed = manager.get("astation-home").unwrap();
        assert!(refreshed.age_seconds() < 5);
    }
}

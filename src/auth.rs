use anyhow::{Result, anyhow};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::time::Duration;

const DEFAULT_SERVER_URL: &str = "https://station.agora.build";

/// Stored session after successful authentication.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSession {
    pub session_id: String,
    pub token: String,
    pub hostname: String,
    pub authenticated_at: u64,
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
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    return Ok(AuthSession {
                        session_id: data.id,
                        token,
                        hostname: get_hostname(),
                        authenticated_at: now,
                    });
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
pub async fn run_login_flow(server_url: Option<&str>) -> Result<AuthSession> {
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
    let session = poll_session_status(server, &session_id, timeout).await?;

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
        let session = AuthSession {
            session_id: "test-id".to_string(),
            token: "test-token".to_string(),
            hostname: "test-host".to_string(),
            authenticated_at: 1700000000,
        };
        let json = serde_json::to_string(&session).unwrap();
        let parsed: AuthSession = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.session_id, "test-id");
        assert_eq!(parsed.token, "test-token");
        assert_eq!(parsed.hostname, "test-host");
        assert_eq!(parsed.authenticated_at, 1700000000);
    }

    #[test]
    fn hostname_returns_non_empty() {
        let h = get_hostname();
        assert!(!h.is_empty());
    }
}

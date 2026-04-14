//! `POST /api/token` handler. Shared by `atem serv rtc` and `atem serv convo`.
//! Caller decides whether the minted token includes RTM by passing `with_rtm`.

use anyhow::Result;

/// Handle POST /api/token — generate an RTC (or RTC+RTM) token.
pub async fn handle_token_api(
    stream: &mut tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    body: &str,
    app_id: &str,
    app_certificate: &str,
    expire_secs: u32,
    with_rtm: bool,
    default_rtm_user: Option<&str>,
) -> Result<()> {
    // Parse body as JSON: { "channel": "...", "uid": "...", "rtm_user_id"?: "..." }
    let parsed: serde_json::Value = match serde_json::from_str(body) {
        Ok(v) => v,
        Err(_) => {
            let err = r#"{"error":"Invalid JSON body"}"#;
            crate::web_server::request::send_response(stream, 400, "application/json", err.as_bytes()).await?;
            return Ok(());
        }
    };

    let channel = parsed["channel"].as_str().unwrap_or("test");
    let uid = parsed["uid"].as_str().unwrap_or("0");
    // Only honoured when the server was launched with --with-rtm.
    let rtm_user_id_req = parsed["rtm_user_id"].as_str();

    // Use time sync for accurate issued_at
    let mut time_sync = crate::time_sync::TimeSync::new();
    let now = match time_sync.now().await {
        Ok(t) => t as u32,
        Err(_) => {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as u32
        }
    };

    let rtc_account = crate::token::RtcAccount::parse(uid);

    let token = if with_rtm {
        // Resolve RTM account: request body > CLI default > fallback to RTC uid.
        // The client is trusted — if it sends a mismatched rtm_user_id, login
        // with a stale token will simply fail, which is the desired behaviour.
        let rtm_uid = rtm_user_id_req
            .or(default_rtm_user)
            .map(str::to_string)
            .unwrap_or_else(|| rtc_account.as_str());
        match crate::token::build_token_rtc_with_rtm(
            app_id,
            app_certificate,
            channel,
            rtc_account,
            crate::token::Role::Publisher,
            expire_secs,
            expire_secs,
            Some(&rtm_uid),
        ) {
            Ok(t) => t,
            Err(e) => {
                let err = serde_json::json!({"error": format!("Token generation failed: {}", e)});
                crate::web_server::request::send_response(stream, 500, "application/json", err.to_string().as_bytes()).await?;
                return Ok(());
            }
        }
    } else {
        match crate::token::build_token_rtc(
            app_id,
            app_certificate,
            channel,
            rtc_account,
            crate::token::Role::Publisher,
            expire_secs,
            now,
        ) {
            Ok(t) => t,
            Err(e) => {
                let err = serde_json::json!({"error": format!("Token generation failed: {}", e)});
                crate::web_server::request::send_response(stream, 500, "application/json", err.to_string().as_bytes()).await?;
                return Ok(());
            }
        }
    };

    // Echo which RTM user this token was issued for (for client UX).
    let actual_rtm_user = if with_rtm {
        rtm_user_id_req
            .or(default_rtm_user)
            .map(str::to_string)
            .unwrap_or_else(|| rtc_account.as_str())
    } else {
        String::new()
    };
    let resp = serde_json::json!({
        "token": token,
        "app_id": app_id,
        "channel": channel,
        "uid": uid,
        "with_rtm": with_rtm,
        "rtm_user_id": actual_rtm_user,
    });

    crate::web_server::request::send_response(stream, 200, "application/json", resp.to_string().as_bytes()).await?;
    Ok(())
}

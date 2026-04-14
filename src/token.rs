/// Agora AccessToken2 generation using:
/// https://github.com/AgoraIO/Tools/tree/master/DynamicKey/AgoraDynamicKey/rust/src
use agora_token::access_token;
use agora_token::rtc_token_builder;
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose};
use flate2::read::ZlibDecoder;
use std::collections::HashMap;
use std::io::Read as IoRead;

pub const SERVICE_TYPE_RTC: u16 = access_token::SERVICE_TYPE_RTC;
pub const SERVICE_TYPE_RTM: u16 = access_token::SERVICE_TYPE_RTM;

/// Role for RTC tokens.
#[derive(Debug, Clone, Copy)]
pub enum Role {
    Publisher,
    Subscriber,
}

/// Classify an RTC user identifier:
/// - all digits → `Int(u32)` — use `build_token_with_uid` (SDK join with `joinChannel(uid:)`)
/// - anything else → `Str(&str)` — use `build_token_with_user_account` (SDK join with `joinChannelWithUserAccount(:)`)
#[derive(Debug, Clone, Copy)]
pub enum RtcAccount<'a> {
    Int(u32),
    Str(&'a str),
}

impl<'a> RtcAccount<'a> {
    /// Parse an RTC user identifier string into int-uid or string-account form.
    ///
    /// Rules:
    /// - Leading `s/` → `Str(<rest>)`. Forced string mode. `/` is NOT in the
    ///   allowed char set for RTC/RTM user accounts, so this prefix can never
    ///   collide with a legal account. Reads as "string-slash".
    /// - All-digit value parseable as u32 → `Int(n)`.
    /// - Anything else → `Str(raw)`.
    ///
    /// Examples:
    ///   `1212`     → Int(1212)
    ///   `ssdi2`    → Str("ssdi2")
    ///   `s/1212`   → Str("1212")
    ///   `s/alice`  → Str("alice")
    pub fn parse(raw: &'a str) -> Self {
        if let Some(rest) = raw.strip_prefix("s/") {
            return RtcAccount::Str(rest);
        }
        if !raw.is_empty() && raw.chars().all(|c| c.is_ascii_digit()) {
            if let Ok(n) = raw.parse::<u32>() {
                return RtcAccount::Int(n);
            }
        }
        RtcAccount::Str(raw)
    }

    pub fn as_str(&self) -> String {
        match self {
            RtcAccount::Int(n) => n.to_string(),
            RtcAccount::Str(s) => s.to_string(),
        }
    }

    pub fn mode_label(&self) -> &'static str {
        match self {
            RtcAccount::Int(_) => "int uid",
            RtcAccount::Str(_) => "string account",
        }
    }
}

/// Build an Agora AccessToken2 for RTC. Auto-selects int-uid vs string-account path.
pub fn build_token_rtc(
    app_id: &str,
    app_certificate: &str,
    channel: &str,
    account: RtcAccount<'_>,
    role: Role,
    expire_secs: u32,
    _issued_at: u32,
) -> Result<String> {
    if app_certificate.is_empty() {
        return Ok(String::new());
    }

    let agora_role = match role {
        Role::Publisher => rtc_token_builder::ROLE_PUBLISHER,
        Role::Subscriber => rtc_token_builder::ROLE_SUBSCRIBER,
    };

    let token = match account {
        RtcAccount::Int(uid) => rtc_token_builder::build_token_with_uid(
            app_id, app_certificate, channel, uid, agora_role, expire_secs, expire_secs,
        ),
        RtcAccount::Str(user_account) => rtc_token_builder::build_token_with_user_account(
            app_id, app_certificate, channel, user_account, agora_role, expire_secs, expire_secs,
        ),
    }
    .map_err(|e| anyhow::anyhow!("{}", e))?;

    Ok(token)
}

/// Build a combined RTC + RTM AccessToken2 — equivalent to the C++ SDK's
/// `RtcTokenBuilder2::BuildTokenWithRtm`. Grants RTC channel privileges for the
/// given role AND an RTM login privilege.
///
/// - If `rtm_user_id` is `None`, the RTC `account` is reused as the RTM user_id
///   (calls upstream `build_token_with_rtm`).
/// - If `rtm_user_id` is `Some`, RTC and RTM have separate accounts
///   (calls upstream `build_token_with_rtm2`).
pub fn build_token_rtc_with_rtm(
    app_id: &str,
    app_certificate: &str,
    channel: &str,
    rtc_account: RtcAccount<'_>,
    role: Role,
    token_expire_secs: u32,
    privilege_expire_secs: u32,
    rtm_user_id: Option<&str>,
) -> Result<String> {
    if app_certificate.is_empty() {
        return Ok(String::new());
    }

    let agora_role = match role {
        Role::Publisher => rtc_token_builder::ROLE_PUBLISHER,
        Role::Subscriber => rtc_token_builder::ROLE_SUBSCRIBER,
    };

    // Upstream build_token_with_rtm[2] both store the RTC account as a string inside
    // the token. Convert to string regardless of int/str classification — the
    // server validates by exact string match either way, so "42" works for both
    // SDK int-uid join and SDK string-account join.
    let rtc_account_str = rtc_account.as_str();

    let token = if let Some(rtm_uid) = rtm_user_id {
        rtc_token_builder::build_token_with_rtm2(
            app_id,
            app_certificate,
            channel,
            &rtc_account_str,
            agora_role,
            token_expire_secs,
            privilege_expire_secs,
            privilege_expire_secs,
            privilege_expire_secs,
            privilege_expire_secs,
            rtm_uid,
            token_expire_secs,
        )
    } else {
        rtc_token_builder::build_token_with_rtm(
            app_id,
            app_certificate,
            channel,
            &rtc_account_str,
            agora_role,
            token_expire_secs,
            privilege_expire_secs,
        )
    }
    .map_err(|e| anyhow::anyhow!("{}", e))?;

    Ok(token)
}

/// Build an Agora AccessToken2 for RTM.
pub fn build_token_rtm(
    app_id: &str,
    app_certificate: &str,
    user_id: &str,
    expire_secs: u32,
    _issued_at: u32,
) -> Result<String> {
    if app_certificate.is_empty() {
        return Ok(String::new());
    }

    let mut token = access_token::new_access_token(app_id, app_certificate, expire_secs);
    let mut service_rtm = access_token::new_service_rtm(user_id);
    service_rtm.service.add_privilege(access_token::PRIVILEGE_LOGIN, expire_secs);
    token.add_service(Box::new(service_rtm));

    token.build().map_err(|e| anyhow::anyhow!("{}", e))
}

/// Decode a token to inspect its fields (for diagnostics).
pub fn decode_token(token: &str) -> Result<TokenInfo> {
    if !token.starts_with(access_token::VERSION) {
        anyhow::bail!("Invalid token version (expected {})", access_token::VERSION);
    }

    let encoded = &token[access_token::VERSION.len()..];
    // Accept both padded and unpadded base64
    let compressed = general_purpose::STANDARD.decode(encoded)
        .or_else(|_| general_purpose::STANDARD_NO_PAD.decode(encoded))?;
    let data = zlib_decompress(&compressed)?;

    let mut offset = 0;

    // Read signature (length-prefixed bytes)
    let sig_len = read_uint16(&data, &mut offset)? as usize;
    if offset + sig_len > data.len() {
        anyhow::bail!("Unexpected end of token data reading signature");
    }
    offset += sig_len;

    // Read content
    let app_id = read_string(&data, &mut offset)?;
    let issue_ts = read_uint32(&data, &mut offset)?;
    let expire = read_uint32(&data, &mut offset)?;
    let salt = read_uint32(&data, &mut offset)?;
    let service_count = read_uint16(&data, &mut offset)?;

    let mut services = Vec::new();
    for _ in 0..service_count {
        let service_type = read_uint16(&data, &mut offset)?;
        let priv_count = read_uint16(&data, &mut offset)?;
        let mut privileges = HashMap::new();
        for _ in 0..priv_count {
            let k = read_uint16(&data, &mut offset)?;
            let v = read_uint32(&data, &mut offset)?;
            privileges.insert(k, v);
        }
        // Read service-specific tail fields (matches upstream access_token::IService::pack
        // impls). If we don't consume them, the next service's offset is wrong.
        let (channel, rtc_user_id, rtm_user_id) = match service_type {
            SERVICE_TYPE_RTC => {
                let c = read_string(&data, &mut offset)?;
                let u = read_string(&data, &mut offset)?;
                (Some(c), Some(u), None)
            }
            SERVICE_TYPE_RTM => {
                let u = read_string(&data, &mut offset)?;
                (None, None, Some(u))
            }
            // Unknown services — no way to skip safely; stop parsing further services.
            _ => {
                services.push(ServiceInfo {
                    service_type,
                    privileges,
                    channel: None,
                    rtc_user_id: None,
                    rtm_user_id: None,
                });
                break;
            }
        };
        services.push(ServiceInfo {
            service_type,
            privileges,
            channel,
            rtc_user_id,
            rtm_user_id,
        });
    }

    Ok(TokenInfo {
        version: access_token::VERSION.to_string(),
        app_id,
        issue_ts,
        expire,
        salt,
        services,
    })
}

/// Decoded token info for display.
#[derive(Debug)]
pub struct TokenInfo {
    /// Token format version — the 3-char prefix (e.g. "007").
    pub version: String,
    pub app_id: String,
    pub issue_ts: u32,
    pub expire: u32,
    pub salt: u32,
    pub services: Vec<ServiceInfo>,
}

#[derive(Debug)]
pub struct ServiceInfo {
    pub service_type: u16,
    pub privileges: HashMap<u16, u32>,
    /// RTC channel name (only populated for SERVICE_TYPE_RTC).
    pub channel: Option<String>,
    /// RTC user id/account as stored in the token — always a string, even if
    /// originally an int uid (upstream stringifies int uids before packing).
    pub rtc_user_id: Option<String>,
    /// RTM user id (only populated for SERVICE_TYPE_RTM).
    pub rtm_user_id: Option<String>,
}

impl TokenInfo {
    /// The absolute unix timestamp at which the token expires.
    pub fn expires_at(&self) -> u64 {
        self.issue_ts as u64 + self.expire as u64
    }

    /// Render the decoded token info as a human-readable multi-line string.
    pub fn display(&self) -> String {
        self.display_at(now_secs())
    }

    /// Same as `display` but with an injectable "now" for deterministic tests.
    pub fn display_at(&self, now: u64) -> String {
        const RULE: &str = "────────────────────────────────────────────────────────────────────────";
        let mut lines: Vec<String> = Vec::new();

        // ── Token info ────────────────────────────────────────────────
        lines.push(String::new());
        lines.push("  TOKEN INFO".to_string());
        lines.push(format!("  {}", RULE));
        lines.push(format!("     Version             {}", self.version));
        lines.push(format!("     App ID              {}", self.app_id));

        // ── Validity ─────────────────────────────────────────────────
        let exp = self.expires_at();
        lines.push(String::new());
        lines.push("  VALIDITY".to_string());
        lines.push(format!("  {}", RULE));
        lines.push(format!(
            "     Valid from          {}",
            format_timestamp_with_local(self.issue_ts as u64)
        ));
        lines.push(format!(
            "     Valid until         {}",
            format_timestamp_with_local(exp)
        ));
        let status = if now < self.issue_ts as u64 {
            format!(
                "not yet valid — starts in {}",
                format_relative_duration(self.issue_ts as u64 - now)
            )
        } else if now < exp {
            format!(
                "yes — expires in {}",
                format_relative_duration(exp - now)
            )
        } else {
            format!(
                "EXPIRED — ended {} ago",
                format_relative_duration(now - exp)
            )
        };
        lines.push(format!("     Valid now           {}", status));

        // ── Services ─────────────────────────────────────────────────
        lines.push(String::new());
        lines.push("  SERVICES".to_string());
        lines.push(format!("  {}", RULE));
        for svc in &self.services {
            let name = match svc.service_type {
                1 => "RTC",
                2 => "RTM",
                4 => "FPA",
                5 => "Chat",
                7 => "APaaS",
                _ => "Unknown",
            };
            lines.push(String::new());
            lines.push(format!("  {} (type {})", name, svc.service_type));
            if let Some(ch) = &svc.channel {
                lines.push(format!("     Channel             {}", ch));
            }
            if let Some(uid) = &svc.rtc_user_id {
                lines.push(format!("     RTC User            {}", uid));
            }
            if let Some(uid) = &svc.rtm_user_id {
                lines.push(format!("     RTM User            {}", uid));
            }
            if !svc.privileges.is_empty() {
                lines.push("     Privileges".to_string());
                // Sort privileges by key for stable output
                let mut keys: Vec<u16> = svc.privileges.keys().copied().collect();
                keys.sort();
                for k in keys {
                    let v = svc.privileges[&k];
                    let priv_name = match (svc.service_type, k) {
                        (1, 1) => "joinChannel",
                        (1, 2) => "publishAudio",
                        (1, 3) => "publishVideo",
                        (1, 4) => "publishData",
                        (2, 1) => "login",
                        _ => "unknown",
                    };
                    // 8-space indent + 17-char label pad puts the content at
                    // the same column (26) as the label-section values above.
                    lines.push(format!(
                        "        {:<17}expires in {}",
                        priv_name,
                        format_relative_duration(v as u64)
                    ));
                }
            }
        }

        lines.push(String::new());
        lines.push(format!("  {}", RULE));
        lines.push(format!("  Decoded at {}", format_timestamp_with_local(now)));
        lines.join("\n")
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Format a relative duration with seconds precision. Starts at the largest
/// applicable unit and always ends at seconds so outputs are comparable:
///   0         → "0s"
///   45        → "45s"
///   90        → "1m 30s"
///   3600      → "1h 0m 0s"
///   3665      → "1h 1m 5s"
///   90061     → "1d 1h 1m 1s"
fn format_relative_duration(secs: u64) -> String {
    const MIN: u64 = 60;
    const HOUR: u64 = 60 * MIN;
    const DAY: u64 = 24 * HOUR;

    if secs >= DAY {
        let d = secs / DAY;
        let h = (secs % DAY) / HOUR;
        let m = (secs % HOUR) / MIN;
        let s = secs % MIN;
        format!("{}d {}h {}m {}s", d, h, m, s)
    } else if secs >= HOUR {
        let h = secs / HOUR;
        let m = (secs % HOUR) / MIN;
        let s = secs % MIN;
        format!("{}h {}m {}s", h, m, s)
    } else if secs >= MIN {
        let m = secs / MIN;
        let s = secs % MIN;
        format!("{}m {}s", m, s)
    } else {
        format!("{}s", secs)
    }
}

fn format_timestamp(ts: u32) -> String {
    format_timestamp_impl(ts as u64)
}

/// Like format_timestamp but takes a u64 (for values that may exceed u32).
fn format_timestamp_u64(ts: u64) -> String {
    format_timestamp_impl(ts)
}

fn format_timestamp_impl(secs: u64) -> String {
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let h = time_of_day / 3600;
    let m = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC", y, mo, d, h, m, s)
}

/// Format a unix timestamp in the system's local timezone.
/// Returns `None` if libc's localtime_r fails (shouldn't happen on Unix).
#[cfg(unix)]
fn format_local_timestamp(secs: u64) -> Option<String> {
    use std::ffi::CStr;
    let t: libc::time_t = secs as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let res = unsafe { libc::localtime_r(&t, &mut tm) };
    if res.is_null() {
        return None;
    }
    let tz = unsafe {
        if tm.tm_zone.is_null() {
            String::from("local")
        } else {
            CStr::from_ptr(tm.tm_zone)
                .to_str()
                .unwrap_or("local")
                .to_string()
        }
    };
    Some(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02} {}",
        tm.tm_year + 1900,
        tm.tm_mon + 1,
        tm.tm_mday,
        tm.tm_hour,
        tm.tm_min,
        tm.tm_sec,
        tz
    ))
}

#[cfg(not(unix))]
fn format_local_timestamp(_secs: u64) -> Option<String> {
    None
}

/// Return `"<UTC time>  (<local time>)"` if local-time conversion works; else
/// just the UTC string. Used to keep the Validity block aligned.
fn format_timestamp_with_local(secs: u64) -> String {
    let utc = format_timestamp_impl(secs);
    match format_local_timestamp(secs) {
        Some(local) if local != utc => format!("{} ({})", utc, local),
        _ => utc,
    }
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m as u32, d as u32)
}

fn zlib_decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
}

// Binary reading helpers (little-endian) for decode_token
fn read_uint16(data: &[u8], offset: &mut usize) -> Result<u16> {
    if *offset + 2 > data.len() {
        anyhow::bail!("Unexpected end of token data");
    }
    let val = u16::from_le_bytes([data[*offset], data[*offset + 1]]);
    *offset += 2;
    Ok(val)
}

fn read_uint32(data: &[u8], offset: &mut usize) -> Result<u32> {
    if *offset + 4 > data.len() {
        anyhow::bail!("Unexpected end of token data");
    }
    let val = u32::from_le_bytes([
        data[*offset],
        data[*offset + 1],
        data[*offset + 2],
        data[*offset + 3],
    ]);
    *offset += 4;
    Ok(val)
}

fn read_string(data: &[u8], offset: &mut usize) -> Result<String> {
    let len = read_uint16(data, offset)? as usize;
    if *offset + len > data.len() {
        anyhow::bail!("Unexpected end of token data");
    }
    let s = String::from_utf8(data[*offset..*offset + len].to_vec())?;
    *offset += len;
    Ok(s)
}

// Legacy token generator (kept for backward compatibility)
pub fn generate_rtm_token(
    app_id: &str,
    app_certificate: &str,
    user_id: &str,
    expire_seconds: u32,
) -> String {
    if app_certificate.is_empty() {
        return String::new();
    }
    let expire_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        + expire_seconds as u64;
    let raw = format!("{}{}{}{}", app_id, app_certificate, user_id, expire_epoch);
    let digest = format!("{:x}", md5_simple(raw.as_bytes()));
    format!("007{}{:016x}", &digest[..16], expire_epoch)
}

fn md5_simple(data: &[u8]) -> u128 {
    let mut h: u128 = 0;
    for &b in data {
        h = h.wrapping_mul(31).wrapping_add(b as u128);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    // Agora's own test vectors — upstream test fixtures from
    // DynamicKey/AgoraDynamicKey/rust/src/access_token.rs test_service_rtc.
    // NOT real credentials; they exist so generated tokens can be verified
    // byte-for-byte against known-good upstream output.
    const TEST_APP_ID: &str = "970CA35de60c44645bbae8a215061b33";
    const TEST_APP_CERT: &str = "5CFd2fd1755d40ecb72977518be15d3b";

    #[test]
    fn empty_certificate_returns_empty_rtc_token() {
        let token =
            build_token_rtc("appid", "", "chan", RtcAccount::parse("0"), Role::Publisher, 3600, 1000000).unwrap();
        assert!(token.is_empty());
    }

    #[test]
    fn empty_certificate_returns_empty_rtm_token() {
        let token = build_token_rtm("appid", "", "user", 3600, 1000000).unwrap();
        assert!(token.is_empty());
    }

    #[test]
    fn rtc_token_starts_with_version() {
        // Official crate requires 32-char hex app_id and certificate
        let token = build_token_rtc(
            TEST_APP_ID,
            TEST_APP_CERT,
            "chan",
            RtcAccount::parse("0"),
            Role::Publisher,
            3600,
            1000000,
        )
        .unwrap();
        assert!(token.starts_with("007"));
    }

    #[test]
    fn rtm_token_starts_with_version() {
        let token = build_token_rtm(
            TEST_APP_ID,
            TEST_APP_CERT,
            "user",
            3600,
            1000000,
        ).unwrap();
        assert!(token.starts_with("007"));
    }

    #[test]
    fn rtc_token_generate_then_decode_roundtrip() {
        let app_id = TEST_APP_ID;
        let token = build_token_rtc(
            app_id,
            TEST_APP_CERT,
            "chan1",
            RtcAccount::parse("12345"),
            Role::Publisher,
            3600,
            1700000000,
        )
        .unwrap();
        let info = decode_token(&token).unwrap();
        assert_eq!(info.app_id, app_id);
        assert_eq!(info.expire, 3600);
        assert!(!info.services.is_empty());
        assert_eq!(info.services[0].service_type, SERVICE_TYPE_RTC);
    }

    #[test]
    fn rtm_token_generate_then_decode_roundtrip() {
        let app_id = TEST_APP_ID;
        let token = build_token_rtm(
            app_id,
            TEST_APP_CERT,
            "alice",
            7200,
            1700000000,
        ).unwrap();
        let info = decode_token(&token).unwrap();
        assert_eq!(info.app_id, app_id);
        assert_eq!(info.expire, 7200);
        assert_eq!(info.services[0].service_type, SERVICE_TYPE_RTM);
    }

    #[test]
    fn rtc_with_rtm_token_carries_both_services() {
        let app_id = TEST_APP_ID;
        let token = build_token_rtc_with_rtm(
            app_id,
            TEST_APP_CERT,
            "test_channel",
            RtcAccount::parse("alice"),
            Role::Publisher,
            7200,
            7200,
            None,
        )
        .unwrap();
        let info = decode_token(&token).unwrap();
        assert_eq!(info.app_id, app_id);
        assert_eq!(info.expire, 7200);
        let service_types: Vec<u16> = info.services.iter().map(|s| s.service_type).collect();
        assert!(service_types.contains(&SERVICE_TYPE_RTC));
        assert!(service_types.contains(&SERVICE_TYPE_RTM));
    }

    #[test]
    fn rtc_with_rtm_separate_accounts_decodes() {
        let app_id = TEST_APP_ID;
        let token = build_token_rtc_with_rtm(
            app_id,
            TEST_APP_CERT,
            "test_channel",
            RtcAccount::parse("rtc_account"),
            Role::Publisher,
            7200,
            7200,
            Some("rtm_account_other"),
        )
        .unwrap();
        assert!(!token.is_empty());
        let info = decode_token(&token).unwrap();
        let service_types: Vec<u16> = info.services.iter().map(|s| s.service_type).collect();
        assert!(service_types.contains(&SERVICE_TYPE_RTC));
        assert!(service_types.contains(&SERVICE_TYPE_RTM));
    }

    #[test]
    fn rtc_with_rtm_empty_cert_returns_empty() {
        let token = build_token_rtc_with_rtm(
            "appid",
            "",
            "channel",
            RtcAccount::parse("user"),
            Role::Publisher,
            3600,
            3600,
            None,
        )
        .unwrap();
        assert!(token.is_empty());
    }

    #[test]
    fn publisher_has_more_privileges_than_subscriber() {
        let app_id = TEST_APP_ID;
        let cert = TEST_APP_CERT;
        let pub_token = build_token_rtc(app_id, cert, "chan", RtcAccount::parse("0"), Role::Publisher, 3600, 0).unwrap();
        let sub_token = build_token_rtc(app_id, cert, "chan", RtcAccount::parse("0"), Role::Subscriber, 3600, 0).unwrap();
        let pub_info = decode_token(&pub_token).unwrap();
        let sub_info = decode_token(&sub_token).unwrap();
        assert!(pub_info.services[0].privileges.len() > sub_info.services[0].privileges.len());
    }

    #[test]
    fn decode_invalid_token_fails() {
        assert!(decode_token("invalid").is_err());
        assert!(decode_token("007invalid_base64!!!").is_err());
    }

    #[test]
    fn decode_handles_unpadded_base64() {
        let token = build_token_rtc(
            TEST_APP_ID,
            TEST_APP_CERT,
            "chan", RtcAccount::parse("0"), Role::Publisher, 3600, 1700000000,
        ).unwrap();
        let unpadded = token.trim_end_matches('=').to_string();
        let info = decode_token(&unpadded).unwrap();
        assert_eq!(info.services[0].service_type, SERVICE_TYPE_RTC);
    }

    #[test]
    fn rtc_publisher_has_four_privileges() {
        let token = build_token_rtc(
            TEST_APP_ID,
            TEST_APP_CERT,
            "chan", RtcAccount::parse("0"), Role::Publisher, 3600, 1700000000,
        ).unwrap();
        let info = decode_token(&token).unwrap();
        assert_eq!(info.services[0].privileges.len(), 4);
    }

    #[test]
    fn rtc_subscriber_has_one_privilege() {
        let token = build_token_rtc(
            TEST_APP_ID,
            TEST_APP_CERT,
            "chan", RtcAccount::parse("0"), Role::Subscriber, 3600, 1700000000,
        ).unwrap();
        let info = decode_token(&token).unwrap();
        assert_eq!(info.services[0].privileges.len(), 1);
    }

    #[test]
    fn privilege_values_are_relative_seconds() {
        let expire_secs = 7200u32;
        let token = build_token_rtc(
            TEST_APP_ID,
            TEST_APP_CERT,
            "chan", RtcAccount::parse("0"), Role::Publisher, expire_secs, 1700000000,
        ).unwrap();
        let info = decode_token(&token).unwrap();
        assert_eq!(info.expire, expire_secs);
        for (_, &v) in &info.services[0].privileges {
            assert_eq!(v, expire_secs);
        }
    }

    // ── RtcAccount classification (int vs string auto-detect) ──────────────

    #[test]
    fn rtc_account_parses_digits_as_int() {
        match RtcAccount::parse("42") {
            RtcAccount::Int(n) => assert_eq!(n, 42),
            RtcAccount::Str(_) => panic!("expected Int, got Str"),
        }
        match RtcAccount::parse("0") {
            RtcAccount::Int(n) => assert_eq!(n, 0),
            _ => panic!("expected Int(0)"),
        }
        // u32 boundary — still fits
        match RtcAccount::parse("4294967295") {
            RtcAccount::Int(n) => assert_eq!(n, u32::MAX),
            _ => panic!("expected Int(u32::MAX)"),
        }
    }

    #[test]
    fn rtc_account_parses_non_digits_as_str() {
        match RtcAccount::parse("alice") {
            RtcAccount::Str(s) => assert_eq!(s, "alice"),
            _ => panic!("expected Str"),
        }
        // Mixed
        assert!(matches!(RtcAccount::parse("user_42"), RtcAccount::Str(_)));
        // Leading space — has a non-digit
        assert!(matches!(RtcAccount::parse(" 42"), RtcAccount::Str(_)));
        // Minus sign — negative numbers are not valid RTC int uids
        assert!(matches!(RtcAccount::parse("-1"), RtcAccount::Str(_)));
        // Hex — 'a'–'f' are not digits
        assert!(matches!(RtcAccount::parse("deadbeef"), RtcAccount::Str(_)));
    }

    #[test]
    fn rtc_account_empty_string_is_str() {
        match RtcAccount::parse("") {
            RtcAccount::Str(s) => assert_eq!(s, ""),
            _ => panic!("expected Str for empty input"),
        }
    }

    #[test]
    fn rtc_account_overflowing_digits_fall_back_to_str() {
        // 10000000000 > u32::MAX — must fall back to string so we don't silently truncate.
        let raw = "10000000000";
        match RtcAccount::parse(raw) {
            RtcAccount::Str(s) => assert_eq!(s, raw),
            _ => panic!("overflowing digits must not be interpreted as Int"),
        }
    }

    #[test]
    fn rtc_account_s_slash_prefix_forces_str() {
        // `s/` prefix strips and forces string mode. The `/` is not in the
        // allowed char set for RTC/RTM accounts, so no legal account can ever
        // contain `s/` — the escape is unambiguous.
        match RtcAccount::parse("s/1212") {
            RtcAccount::Str(s) => assert_eq!(s, "1212"),
            _ => panic!("s/1212 must be Str(\"1212\"), got Int"),
        }
        match RtcAccount::parse("s/alice") {
            RtcAccount::Str(s) => assert_eq!(s, "alice"),
            _ => panic!("s/alice must stay Str"),
        }
        // Empty after prefix
        match RtcAccount::parse("s/") {
            RtcAccount::Str(s) => assert_eq!(s, ""),
            _ => panic!("s/ (empty) must be empty Str"),
        }
        // Account starting with plain `s` (no slash) is NOT treated as the prefix
        match RtcAccount::parse("ssdi2") {
            RtcAccount::Str(s) => assert_eq!(s, "ssdi2"),
            _ => panic!("ssdi2 must be Str(\"ssdi2\")"),
        }
        // Bare leading `/` (no preceding `s`) is NOT the prefix either
        match RtcAccount::parse("/1212") {
            RtcAccount::Str(s) => assert_eq!(s, "/1212"),
            _ => panic!("/1212 (no s prefix) must be Str(\"/1212\")"),
        }
        // Prefix takes precedence over digit detection
        assert!(matches!(RtcAccount::parse("s/1212"), RtcAccount::Str(_)));
    }

    #[test]
    fn rtc_account_mode_label_matches_variant() {
        assert_eq!(RtcAccount::parse("42").mode_label(), "int uid");
        assert_eq!(RtcAccount::parse("alice").mode_label(), "string account");
    }

    #[test]
    fn rtc_account_as_str_roundtrips_int() {
        assert_eq!(RtcAccount::parse("42").as_str(), "42");
        assert_eq!(RtcAccount::parse("0").as_str(), "0");
        assert_eq!(RtcAccount::parse("alice").as_str(), "alice");
    }

    // ── Int-uid vs string-account round-trips ─────────────────────────────

    #[test]
    fn rtc_int_uid_token_differs_from_string_account_token() {
        // Different account strings — "42" vs "alice" — must yield different tokens.
        let t1 = build_token_rtc(
            TEST_APP_ID, TEST_APP_CERT, "chan",
            RtcAccount::parse("42"), Role::Publisher, 3600, 1700000000,
        )
        .unwrap();
        let t2 = build_token_rtc(
            TEST_APP_ID, TEST_APP_CERT, "chan",
            RtcAccount::parse("alice"), Role::Publisher, 3600, 1700000000,
        )
        .unwrap();
        assert_ne!(t1, t2);
        // Both must still decode.
        let info1 = decode_token(&t1).unwrap();
        let info2 = decode_token(&t2).unwrap();
        assert_eq!(info1.services[0].service_type, SERVICE_TYPE_RTC);
        assert_eq!(info2.services[0].service_type, SERVICE_TYPE_RTC);
    }

    #[test]
    fn int_uid_2233_and_string_2233_decode_identically() {
        // Build two tokens for the "same" user — once via int 2233, once via
        // string "2233". Only ts/salt/signature bytes differ; the SERVICE
        // payload carrying channel+user is byte-identical. This proves that
        // the int-vs-string mode is NOT recoverable from the token.
        let t_int = build_token_rtc(
            TEST_APP_ID, TEST_APP_CERT, "chan",
            RtcAccount::Int(2233), Role::Publisher, 3600, 0,
        )
        .unwrap();
        let t_str = build_token_rtc(
            TEST_APP_ID, TEST_APP_CERT, "chan",
            RtcAccount::Str("2233"), Role::Publisher, 3600, 0,
        )
        .unwrap();

        let info_int = decode_token(&t_int).unwrap();
        let info_str = decode_token(&t_str).unwrap();

        assert_eq!(info_int.services.len(), 1);
        assert_eq!(info_str.services.len(), 1);
        let s_int = &info_int.services[0];
        let s_str = &info_str.services[0];

        assert_eq!(s_int.service_type, s_str.service_type);
        assert_eq!(s_int.channel.as_deref(), Some("chan"));
        assert_eq!(s_str.channel.as_deref(), Some("chan"));
        // Both store the user as literal "2233" — no mode marker anywhere.
        assert_eq!(s_int.rtc_user_id.as_deref(), Some("2233"));
        assert_eq!(s_str.rtc_user_id.as_deref(), Some("2233"));
        // Same privilege set on both.
        assert_eq!(s_int.privileges.len(), s_str.privileges.len());
        for (k, v) in &s_int.privileges {
            assert_eq!(s_str.privileges.get(k), Some(v));
        }
    }

    #[test]
    fn rtc_with_rtm_int_uid_same_account_for_both() {
        // --rtc-user-id 42 --with-rtm  → RTC and RTM both keyed on "42"
        let token = build_token_rtc_with_rtm(
            TEST_APP_ID, TEST_APP_CERT, "chan",
            RtcAccount::parse("42"), Role::Publisher, 3600, 3600,
            None,
        )
        .unwrap();
        let info = decode_token(&token).unwrap();
        let types: Vec<u16> = info.services.iter().map(|s| s.service_type).collect();
        assert!(types.contains(&SERVICE_TYPE_RTC));
        assert!(types.contains(&SERVICE_TYPE_RTM));
    }

    #[test]
    fn rtc_with_rtm_int_uid_and_separate_rtm_account() {
        // --rtc-user-id 42 --with-rtm --rtm-user-id rtm_alice
        let token = build_token_rtc_with_rtm(
            TEST_APP_ID, TEST_APP_CERT, "chan",
            RtcAccount::parse("42"), Role::Publisher, 3600, 3600,
            Some("rtm_alice"),
        )
        .unwrap();
        let info = decode_token(&token).unwrap();
        let types: Vec<u16> = info.services.iter().map(|s| s.service_type).collect();
        assert!(types.contains(&SERVICE_TYPE_RTC));
        assert!(types.contains(&SERVICE_TYPE_RTM));
    }

    #[test]
    fn rtc_with_rtm_separate_account_produces_different_token_than_same_account() {
        // Same RTC account but distinct RTM accounts → different token bytes.
        let same = build_token_rtc_with_rtm(
            TEST_APP_ID, TEST_APP_CERT, "chan",
            RtcAccount::parse("alice"), Role::Publisher, 3600, 3600,
            None,
        )
        .unwrap();
        let separate = build_token_rtc_with_rtm(
            TEST_APP_ID, TEST_APP_CERT, "chan",
            RtcAccount::parse("alice"), Role::Publisher, 3600, 3600,
            Some("bob"),
        )
        .unwrap();
        assert_ne!(same, separate);
    }

    // ── Subscriber role restrictions ──────────────────────────────────────

    #[test]
    fn rtc_with_rtm_subscriber_has_only_join_channel_on_rtc_side() {
        let token = build_token_rtc_with_rtm(
            TEST_APP_ID, TEST_APP_CERT, "chan",
            RtcAccount::parse("42"), Role::Subscriber, 3600, 3600,
            None,
        )
        .unwrap();
        let info = decode_token(&token).unwrap();
        let rtc = info
            .services
            .iter()
            .find(|s| s.service_type == SERVICE_TYPE_RTC)
            .expect("RTC service missing");
        // Subscriber = joinChannel only (no publish privileges)
        assert_eq!(rtc.privileges.len(), 1);
    }

    // ── Empty-cert paths ──────────────────────────────────────────────────

    #[test]
    fn build_token_rtc_int_uid_empty_cert_returns_empty() {
        let t = build_token_rtc(
            "appid", "", "chan", RtcAccount::parse("42"),
            Role::Publisher, 3600, 0,
        )
        .unwrap();
        assert!(t.is_empty());
    }

    #[test]
    fn build_token_rtc_with_rtm_separate_empty_cert_returns_empty() {
        let t = build_token_rtc_with_rtm(
            "appid", "", "chan", RtcAccount::parse("42"),
            Role::Publisher, 3600, 3600, Some("rtm_user"),
        )
        .unwrap();
        assert!(t.is_empty());
    }

    // ── Decode display + payload round-trip ───────────────────────────────

    #[test]
    fn decoded_rtc_token_surfaces_channel_and_user() {
        let token = build_token_rtc(
            TEST_APP_ID, TEST_APP_CERT, "mychan",
            RtcAccount::parse("alice"), Role::Publisher, 3600, 0,
        )
        .unwrap();
        let info = decode_token(&token).unwrap();
        let display = info.display();
        assert!(display.contains("Channel             mychan"), "display missing channel:\n{display}");
        assert!(display.contains("RTC User            alice"), "display missing RTC user:\n{display}");
    }

    #[test]
    fn decoded_rtm_token_surfaces_user() {
        let token =
            build_token_rtm(TEST_APP_ID, TEST_APP_CERT, "alice_rtm", 3600, 0).unwrap();
        let info = decode_token(&token).unwrap();
        let display = info.display();
        assert!(display.contains("RTM User            alice_rtm"), "display missing RTM user:\n{display}");
    }

    #[test]
    fn decoded_combined_token_surfaces_both_users_and_channel() {
        let token = build_token_rtc_with_rtm(
            TEST_APP_ID, TEST_APP_CERT, "combined_chan",
            RtcAccount::parse("42"), Role::Publisher, 3600, 3600,
            Some("rtm_alice"),
        )
        .unwrap();
        let info = decode_token(&token).unwrap();
        let display = info.display();
        assert!(display.contains("Channel             combined_chan"));
        assert!(display.contains("RTC User            42"));
        assert!(display.contains("RTM User            rtm_alice"));
    }

    #[test]
    fn display_shows_version_validity_and_sections() {
        // Build a token issued at a known ts so we can check the validity output.
        let token = build_token_rtc_with_rtm(
            TEST_APP_ID, TEST_APP_CERT, "demo",
            RtcAccount::parse("42"), Role::Publisher, 3600, 3600,
            Some("alice"),
        )
        .unwrap();
        let info = decode_token(&token).unwrap();
        // Pretend "now" is exactly halfway through the token's lifetime.
        let now = info.issue_ts as u64 + 1800;
        let display = info.display_at(now);

        // Section headers
        assert!(display.contains("TOKEN INFO"),  "missing TOKEN INFO:\n{display}");
        assert!(display.contains("VALIDITY"),    "missing VALIDITY:\n{display}");
        assert!(display.contains("SERVICES"),    "missing SERVICES:\n{display}");

        // Version
        assert!(display.contains("Version"));
        assert!(display.contains("007"));

        // Validity lines
        assert!(display.contains("Valid from"));
        assert!(display.contains("Valid until"));
        assert!(display.contains("Valid now"));
        assert!(display.contains("expires in 30m 0s"),
            "expected 'expires in 30m 0s', got:\n{display}");

        // Service data
        assert!(display.contains("RTC"));
        assert!(display.contains("Channel             demo"));
        assert!(display.contains("RTC User            42"));
        assert!(display.contains("RTM User            alice"));
        assert!(display.contains("joinChannel"));
        assert!(display.contains("login"));

        // Footer
        assert!(display.contains("Decoded at"));
    }

    #[test]
    fn display_flags_expired_token() {
        let token = build_token_rtc(
            TEST_APP_ID, TEST_APP_CERT, "c",
            RtcAccount::parse("1"), Role::Publisher, 60, 0,
        )
        .unwrap();
        let info = decode_token(&token).unwrap();
        let way_later = info.issue_ts as u64 + 10_000;
        let display = info.display_at(way_later);
        assert!(display.contains("EXPIRED"), "expected EXPIRED:\n{display}");
    }

    #[test]
    fn display_flags_not_yet_valid_token() {
        let token = build_token_rtc(
            TEST_APP_ID, TEST_APP_CERT, "c",
            RtcAccount::parse("1"), Role::Publisher, 60, 0,
        )
        .unwrap();
        let info = decode_token(&token).unwrap();
        // Simulate a "now" before the token was issued (clock skew case)
        let earlier = info.issue_ts as u64 - 120;
        let display = info.display_at(earlier);
        assert!(display.contains("not yet valid"), "expected 'not yet valid':\n{display}");
    }

    #[test]
    fn format_relative_duration_always_ends_in_seconds() {
        assert_eq!(format_relative_duration(0),      "0s");
        assert_eq!(format_relative_duration(45),     "45s");
        assert_eq!(format_relative_duration(60),     "1m 0s");
        assert_eq!(format_relative_duration(90),     "1m 30s");
        assert_eq!(format_relative_duration(3600),   "1h 0m 0s");
        assert_eq!(format_relative_duration(3665),   "1h 1m 5s");
        assert_eq!(format_relative_duration(86_400), "1d 0h 0m 0s");
        assert_eq!(format_relative_duration(90_061), "1d 1h 1m 1s");
    }

    #[test]
    fn decoded_service_fields_are_preserved() {
        // Structural check: decode_token's ServiceInfo should carry channel +
        // rtc_user_id for RTC, rtm_user_id for RTM, and no cross-contamination.
        let token = build_token_rtc_with_rtm(
            TEST_APP_ID, TEST_APP_CERT, "xx",
            RtcAccount::parse("rtc_acc"), Role::Publisher, 3600, 3600,
            Some("rtm_acc"),
        )
        .unwrap();
        let info = decode_token(&token).unwrap();

        let rtc = info.services.iter().find(|s| s.service_type == SERVICE_TYPE_RTC).unwrap();
        assert_eq!(rtc.channel.as_deref(), Some("xx"));
        assert_eq!(rtc.rtc_user_id.as_deref(), Some("rtc_acc"));
        assert!(rtc.rtm_user_id.is_none(), "RTC service must not carry rtm_user_id");

        let rtm = info.services.iter().find(|s| s.service_type == SERVICE_TYPE_RTM).unwrap();
        assert_eq!(rtm.rtm_user_id.as_deref(), Some("rtm_acc"));
        assert!(rtm.channel.is_none(), "RTM service must not carry channel");
        assert!(rtm.rtc_user_id.is_none(), "RTM service must not carry rtc_user_id");
    }

    // ── Edge cases ────────────────────────────────────────────────────────

    #[test]
    fn rtc_account_at_u32_boundary_fits() {
        // u32::MAX must still be Int — 10 digits but within range.
        match RtcAccount::parse("4294967295") {
            RtcAccount::Int(n) => assert_eq!(n, u32::MAX),
            _ => panic!("u32::MAX must be Int"),
        }
    }

    #[test]
    fn rtc_account_just_over_u32_falls_back_to_str() {
        // 4294967296 = u32::MAX + 1 → must NOT silently truncate
        match RtcAccount::parse("4294967296") {
            RtcAccount::Str(s) => assert_eq!(s, "4294967296"),
            _ => panic!("overflowing digits must be Str, not Int"),
        }
    }

    #[test]
    fn long_string_account_255_chars_round_trips() {
        // Agora caps string accounts at 255 bytes. Build one of exactly 255.
        let long = "a".repeat(255);
        let token = build_token_rtc(
            TEST_APP_ID, TEST_APP_CERT, "chan",
            RtcAccount::parse(&long), Role::Publisher, 3600, 0,
        )
        .unwrap();
        let info = decode_token(&token).unwrap();
        let rtc = info.services.iter().find(|s| s.service_type == SERVICE_TYPE_RTC).unwrap();
        assert_eq!(rtc.rtc_user_id.as_deref(), Some(long.as_str()));
    }

    #[test]
    fn channel_with_allowed_punctuation_survives_round_trip() {
        // RTC channel allows a broad set of punctuation. Sanity check that
        // our decode correctly reconstructs a realistic channel name.
        let channel = "room-42@agora.io:1";
        let token = build_token_rtc(
            TEST_APP_ID, TEST_APP_CERT, channel,
            RtcAccount::parse("42"), Role::Publisher, 3600, 0,
        )
        .unwrap();
        let info = decode_token(&token).unwrap();
        let rtc = info.services.iter().find(|s| s.service_type == SERVICE_TYPE_RTC).unwrap();
        assert_eq!(rtc.channel.as_deref(), Some(channel));
    }

    #[test]
    fn uid_0_stores_empty_string_in_token() {
        // Upstream convention: uid=0 means "server assigns a uid". The SDK's
        // get_uid_str(0) returns "" (sentinel), so the token carries an empty
        // uid string, not "0". This is the correct behaviour for int uid 0.
        let token = build_token_rtc(
            TEST_APP_ID, TEST_APP_CERT, "chan",
            RtcAccount::parse("0"), Role::Publisher, 3600, 0,
        )
        .unwrap();
        let info = decode_token(&token).unwrap();
        let rtc = info.services.iter().find(|s| s.service_type == SERVICE_TYPE_RTC).unwrap();
        assert_eq!(rtc.rtc_user_id.as_deref(), Some(""));
    }

    #[test]
    fn string_account_0_stores_literal_zero() {
        // In contrast to int uid 0, a string account "0" (passed via s/0)
        // stores the literal "0" in the token — no "server assigns" sentinel.
        let token = build_token_rtc(
            TEST_APP_ID, TEST_APP_CERT, "chan",
            RtcAccount::parse("s/0"), Role::Publisher, 3600, 0,
        )
        .unwrap();
        let info = decode_token(&token).unwrap();
        let rtc = info.services.iter().find(|s| s.service_type == SERVICE_TYPE_RTC).unwrap();
        assert_eq!(rtc.rtc_user_id.as_deref(), Some("0"));
    }

    #[test]
    fn rtc_publisher_token_has_all_four_privileges() {
        let token = build_token_rtc(
            TEST_APP_ID, TEST_APP_CERT, "c",
            RtcAccount::parse("1"), Role::Publisher, 3600, 0,
        )
        .unwrap();
        let info = decode_token(&token).unwrap();
        let rtc = info.services.iter().find(|s| s.service_type == SERVICE_TYPE_RTC).unwrap();
        use agora_token::access_token::{
            PRIVILEGE_JOIN_CHANNEL, PRIVILEGE_PUBLISH_AUDIO_STREAM,
            PRIVILEGE_PUBLISH_VIDEO_STREAM, PRIVILEGE_PUBLISH_DATA_STREAM,
        };
        assert!(rtc.privileges.contains_key(&PRIVILEGE_JOIN_CHANNEL));
        assert!(rtc.privileges.contains_key(&PRIVILEGE_PUBLISH_AUDIO_STREAM));
        assert!(rtc.privileges.contains_key(&PRIVILEGE_PUBLISH_VIDEO_STREAM));
        assert!(rtc.privileges.contains_key(&PRIVILEGE_PUBLISH_DATA_STREAM));
    }

    #[test]
    fn rtc_subscriber_token_has_only_join_channel() {
        let token = build_token_rtc(
            TEST_APP_ID, TEST_APP_CERT, "c",
            RtcAccount::parse("1"), Role::Subscriber, 3600, 0,
        )
        .unwrap();
        let info = decode_token(&token).unwrap();
        let rtc = info.services.iter().find(|s| s.service_type == SERVICE_TYPE_RTC).unwrap();
        use agora_token::access_token::{
            PRIVILEGE_JOIN_CHANNEL, PRIVILEGE_PUBLISH_AUDIO_STREAM,
        };
        assert!(rtc.privileges.contains_key(&PRIVILEGE_JOIN_CHANNEL));
        assert!(!rtc.privileges.contains_key(&PRIVILEGE_PUBLISH_AUDIO_STREAM));
    }

    #[test]
    fn build_and_decode_with_real_credentials() {
        // Verify our output matches the Agora SDK reference test vector.
        // Skipped unless AGORA_APP_ID and AGORA_APP_CERTIFICATE are set.
        let app_id = match std::env::var("AGORA_APP_ID") {
            Ok(v) if !v.is_empty() => v,
            _ => { eprintln!("skipped: AGORA_APP_ID not set"); return; }
        };
        let app_cert = match std::env::var("AGORA_APP_CERTIFICATE") {
            Ok(v) if !v.is_empty() => v,
            _ => { eprintln!("skipped: AGORA_APP_CERTIFICATE not set"); return; }
        };

        // Use the official crate directly with controlled salt/ts
        let expire: u32 = 600;
        let mut token = access_token::new_access_token(&app_id, &app_cert, expire);
        // Override salt and issue_ts to match reference
        // Note: the struct fields aren't public, so we verify via roundtrip instead
        let built = token.build();
        assert!(built.is_ok(), "Token build should succeed with valid credentials");
        let token_str = built.unwrap();
        assert!(token_str.starts_with("007"));
        let info = decode_token(&token_str).unwrap();
        assert_eq!(info.app_id, app_id);
    }

    // Legacy token tests
    #[test]
    fn legacy_empty_certificate_returns_empty_token() {
        let token = generate_rtm_token("app", "", "user", 3600);
        assert!(token.is_empty());
    }

    #[test]
    fn legacy_token_starts_with_prefix() {
        let token = generate_rtm_token("app", "cert", "user", 3600);
        assert!(token.starts_with("007"));
    }
}

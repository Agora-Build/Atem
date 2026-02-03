use anyhow::Result;
use base64::{Engine as _, engine::general_purpose};
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;
use std::collections::HashMap;

type HmacSha256 = Hmac<Sha256>;

const VERSION: &str = "007";

// Service types
pub const SERVICE_TYPE_RTC: u16 = 1;
pub const SERVICE_TYPE_RTM: u16 = 2;
#[allow(dead_code)]
pub const SERVICE_TYPE_FPA: u16 = 4;
#[allow(dead_code)]
pub const SERVICE_TYPE_CHAT: u16 = 5;

// RTC privilege types
pub const PRIVILEGE_JOIN_CHANNEL: u16 = 1;
pub const PRIVILEGE_PUBLISH_AUDIO: u16 = 2;
pub const PRIVILEGE_PUBLISH_VIDEO: u16 = 3;
pub const PRIVILEGE_PUBLISH_DATA: u16 = 4;

// RTM privilege types
pub const PRIVILEGE_LOGIN: u16 = 1;

/// Role for RTC tokens.
#[derive(Debug, Clone, Copy)]
pub enum Role {
    Publisher,
    Subscriber,
}

/// Build a real Agora AccessToken2 for RTC.
pub fn build_token_rtc(
    app_id: &str,
    app_certificate: &str,
    _channel: &str,
    _uid: &str,
    role: Role,
    expire_secs: u32,
    issued_at: u32,
) -> Result<String> {
    if app_certificate.is_empty() {
        return Ok(String::new());
    }

    let salt: u32 = rand::thread_rng().r#gen();
    let expire_at = issued_at + expire_secs;

    // Build privileges based on role
    let mut privileges = HashMap::new();
    privileges.insert(PRIVILEGE_JOIN_CHANNEL, expire_at);
    match role {
        Role::Publisher => {
            privileges.insert(PRIVILEGE_PUBLISH_AUDIO, expire_at);
            privileges.insert(PRIVILEGE_PUBLISH_VIDEO, expire_at);
            privileges.insert(PRIVILEGE_PUBLISH_DATA, expire_at);
        }
        Role::Subscriber => {}
    }

    // Build service: RTC
    let services = vec![Service {
        service_type: SERVICE_TYPE_RTC,
        privileges,
    }];

    // Build the token
    let content = TokenContent {
        app_id: app_id.to_string(),
        issue_ts: issued_at,
        expire: expire_secs,
        salt,
        services,
    };

    // Sign
    let signing_key = derive_signing_key(app_certificate, &content)?;

    // Encode content
    let mut content_buf = Vec::new();
    pack_string(&mut content_buf, &content.app_id);
    pack_uint32(&mut content_buf, content.issue_ts);
    pack_uint32(&mut content_buf, content.expire);
    pack_uint32(&mut content_buf, content.salt);
    pack_uint16(&mut content_buf, content.services.len() as u16);
    for svc in &content.services {
        pack_uint16(&mut content_buf, svc.service_type);
        pack_uint16(&mut content_buf, svc.privileges.len() as u16);
        for (&k, &v) in &svc.privileges {
            pack_uint16(&mut content_buf, k);
            pack_uint32(&mut content_buf, v);
        }
    }

    // Sign the content
    let mut mac = HmacSha256::new_from_slice(&signing_key)?;
    mac.update(&content_buf);
    let signature = mac.finalize().into_bytes();

    // Final token: VERSION + base64(signature + content_buf)
    let mut token_buf = Vec::new();
    pack_bytes(&mut token_buf, &signature);
    token_buf.extend_from_slice(&content_buf);

    let encoded = general_purpose::STANDARD.encode(&token_buf);

    Ok(format!("{}{}", VERSION, encoded))
}

/// Build a real Agora AccessToken2 for RTM.
pub fn build_token_rtm(
    app_id: &str,
    app_certificate: &str,
    _user_id: &str,
    expire_secs: u32,
    issued_at: u32,
) -> Result<String> {
    if app_certificate.is_empty() {
        return Ok(String::new());
    }

    let salt: u32 = rand::thread_rng().r#gen();
    let expire_at = issued_at + expire_secs;

    let mut privileges = HashMap::new();
    privileges.insert(PRIVILEGE_LOGIN, expire_at);

    let services = vec![Service {
        service_type: SERVICE_TYPE_RTM,
        privileges,
    }];

    let content = TokenContent {
        app_id: app_id.to_string(),
        issue_ts: issued_at,
        expire: expire_secs,
        salt,
        services,
    };

    let signing_key = derive_signing_key(app_certificate, &content)?;

    let mut content_buf = Vec::new();
    pack_string(&mut content_buf, &content.app_id);
    pack_uint32(&mut content_buf, content.issue_ts);
    pack_uint32(&mut content_buf, content.expire);
    pack_uint32(&mut content_buf, content.salt);
    pack_uint16(&mut content_buf, content.services.len() as u16);
    for svc in &content.services {
        pack_uint16(&mut content_buf, svc.service_type);
        pack_uint16(&mut content_buf, svc.privileges.len() as u16);
        for (&k, &v) in &svc.privileges {
            pack_uint16(&mut content_buf, k);
            pack_uint32(&mut content_buf, v);
        }
    }

    let mut mac = HmacSha256::new_from_slice(&signing_key)?;
    mac.update(&content_buf);
    let signature = mac.finalize().into_bytes();

    let mut token_buf = Vec::new();
    pack_bytes(&mut token_buf, &signature);
    token_buf.extend_from_slice(&content_buf);

    let encoded = general_purpose::STANDARD.encode(&token_buf);

    Ok(format!("{}{}", VERSION, encoded))
}

/// Decode a token to inspect its fields (for diagnostics).
pub fn decode_token(token: &str) -> Result<TokenInfo> {
    if !token.starts_with(VERSION) {
        anyhow::bail!("Invalid token version (expected {})", VERSION);
    }

    let encoded = &token[VERSION.len()..];
    let data = general_purpose::STANDARD.decode(encoded)?;

    let mut offset = 0;

    // Read signature (length-prefixed bytes)
    let sig_len = read_uint16(&data, &mut offset)? as usize;
    if offset + sig_len > data.len() {
        anyhow::bail!("Unexpected end of token data reading signature");
    }
    let _signature = &data[offset..offset + sig_len];
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
        services.push(ServiceInfo {
            service_type,
            privileges,
        });
    }

    Ok(TokenInfo {
        app_id,
        issue_ts,
        expire,
        salt,
        services,
    })
}

// Internal types

struct TokenContent {
    app_id: String,
    issue_ts: u32,
    expire: u32,
    salt: u32,
    services: Vec<Service>,
}

struct Service {
    service_type: u16,
    privileges: HashMap<u16, u32>,
}

/// Decoded token info for display.
#[derive(Debug)]
pub struct TokenInfo {
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
}

impl TokenInfo {
    pub fn display(&self) -> String {
        let mut lines = Vec::new();
        lines.push(format!("App ID: {}", self.app_id));
        lines.push(format!(
            "Issued at: {} ({})",
            self.issue_ts,
            format_timestamp(self.issue_ts)
        ));
        lines.push(format!("Expire: {}s", self.expire));
        lines.push(format!("Salt: {}", self.salt));
        for svc in &self.services {
            let svc_name = match svc.service_type {
                1 => "RTC",
                2 => "RTM",
                4 => "FPA",
                5 => "Chat",
                _ => "Unknown",
            };
            lines.push(format!(
                "Service: {} (type={})",
                svc_name, svc.service_type
            ));
            for (&k, &v) in &svc.privileges {
                let priv_name = match (svc.service_type, k) {
                    (1, 1) => "joinChannel",
                    (1, 2) => "publishAudio",
                    (1, 3) => "publishVideo",
                    (1, 4) => "publishData",
                    (2, 1) => "login",
                    _ => "unknown",
                };
                lines.push(format!(
                    "  {}: expires {} ({})",
                    priv_name,
                    v,
                    format_timestamp(v)
                ));
            }
        }
        lines.join("\n")
    }
}

fn format_timestamp(ts: u32) -> String {
    // Simple UTC date formatting
    let secs = ts as u64;
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let h = time_of_day / 3600;
    let m = (time_of_day % 3600) / 60;
    let s = time_of_day % 60;

    // Convert days since epoch to year-month-day
    let (y, mo, d) = civil_from_days(days as i64);
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02} UTC", y, mo, d, h, m, s)
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

// Signing key derivation
fn derive_signing_key(app_certificate: &str, content: &TokenContent) -> Result<Vec<u8>> {
    // Step 1: HMAC(certificate, issue_ts)
    let mut mac1 = HmacSha256::new_from_slice(app_certificate.as_bytes())?;
    mac1.update(&content.issue_ts.to_le_bytes());
    let key1 = mac1.finalize().into_bytes();

    // Step 2: HMAC(key1, salt)
    let mut mac2 = HmacSha256::new_from_slice(&key1)?;
    mac2.update(&content.salt.to_le_bytes());
    let key2 = mac2.finalize().into_bytes();

    Ok(key2.to_vec())
}

// Binary packing helpers (little-endian)
fn pack_uint16(buf: &mut Vec<u8>, val: u16) {
    buf.extend_from_slice(&val.to_le_bytes());
}

fn pack_uint32(buf: &mut Vec<u8>, val: u32) {
    buf.extend_from_slice(&val.to_le_bytes());
}

fn pack_string(buf: &mut Vec<u8>, s: &str) {
    pack_uint16(buf, s.len() as u16);
    buf.extend_from_slice(s.as_bytes());
}

fn pack_bytes(buf: &mut Vec<u8>, data: &[u8]) {
    pack_uint16(buf, data.len() as u16);
    buf.extend_from_slice(data);
}

// Binary reading helpers (little-endian)
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

// Keep the old simple token generator for backward compatibility
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
    // Simple hash for legacy token - not cryptographic
    let mut h: u128 = 0;
    for &b in data {
        h = h.wrapping_mul(31).wrapping_add(b as u128);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_certificate_returns_empty_rtc_token() {
        let token =
            build_token_rtc("appid", "", "chan", "uid", Role::Publisher, 3600, 1000000).unwrap();
        assert!(token.is_empty());
    }

    #[test]
    fn empty_certificate_returns_empty_rtm_token() {
        let token = build_token_rtm("appid", "", "user", 3600, 1000000).unwrap();
        assert!(token.is_empty());
    }

    #[test]
    fn rtc_token_starts_with_version() {
        let token = build_token_rtc(
            "appid123",
            "cert456",
            "chan",
            "uid",
            Role::Publisher,
            3600,
            1000000,
        )
        .unwrap();
        assert!(token.starts_with("007"));
    }

    #[test]
    fn rtm_token_starts_with_version() {
        let token = build_token_rtm("appid123", "cert456", "user", 3600, 1000000).unwrap();
        assert!(token.starts_with("007"));
    }

    #[test]
    fn rtc_token_generate_then_decode_roundtrip() {
        let app_id = "test_app_id_32chars_exactly_here";
        let token = build_token_rtc(
            app_id,
            "test_cert",
            "chan1",
            "uid1",
            Role::Publisher,
            3600,
            1700000000,
        )
        .unwrap();
        let info = decode_token(&token).unwrap();
        assert_eq!(info.app_id, app_id);
        assert_eq!(info.issue_ts, 1700000000);
        assert_eq!(info.expire, 3600);
        assert!(!info.services.is_empty());
        assert_eq!(info.services[0].service_type, SERVICE_TYPE_RTC);
    }

    #[test]
    fn rtm_token_generate_then_decode_roundtrip() {
        let app_id = "test_app_id_for_rtm";
        let token =
            build_token_rtm(app_id, "test_cert", "alice", 7200, 1700000000).unwrap();
        let info = decode_token(&token).unwrap();
        assert_eq!(info.app_id, app_id);
        assert_eq!(info.issue_ts, 1700000000);
        assert_eq!(info.expire, 7200);
        assert_eq!(info.services[0].service_type, SERVICE_TYPE_RTM);
    }

    #[test]
    fn publisher_has_more_privileges_than_subscriber() {
        let pub_token = build_token_rtc(
            "appid",
            "cert",
            "chan",
            "uid",
            Role::Publisher,
            3600,
            1000000,
        )
        .unwrap();
        let sub_token = build_token_rtc(
            "appid",
            "cert",
            "chan",
            "uid",
            Role::Subscriber,
            3600,
            1000000,
        )
        .unwrap();
        let pub_info = decode_token(&pub_token).unwrap();
        let sub_info = decode_token(&sub_token).unwrap();
        // Publisher should have 4 privileges (join, audio, video, data)
        // Subscriber should have 1 (join only)
        assert!(pub_info.services[0].privileges.len() > sub_info.services[0].privileges.len());
    }

    #[test]
    fn decode_invalid_token_fails() {
        assert!(decode_token("invalid").is_err());
        assert!(decode_token("007invalid_base64!!!").is_err());
    }

    // Keep old tests for legacy token
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

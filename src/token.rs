use anyhow::Result;
use base64::{Engine as _, engine::general_purpose};
use flate2::write::ZlibEncoder;
use flate2::read::ZlibDecoder;
use flate2::Compression;
use hmac::{Hmac, Mac};
use rand::Rng;
use sha2::Sha256;
use std::io::{Read as IoRead, Write as IoWrite};
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
///
/// AccessToken2 format encodes channel_name and uid as part of each service's
/// content (after privileges). Without these, the token fails RTC validation.
pub fn build_token_rtc(
    app_id: &str,
    app_certificate: &str,
    channel: &str,
    uid: &str,
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

    // Build service: RTC (includes channel_name and uid per AccessToken2 spec)
    let services = vec![ServiceWithExtra {
        service_type: SERVICE_TYPE_RTC,
        privileges,
        extra_strings: vec![channel.to_string(), uid.to_string()],
    }];

    // Build the token
    let content = TokenContent {
        app_id: app_id.to_string(),
        issue_ts: issued_at,
        expire: expire_secs,
        salt,
    };

    // Sign
    let signing_key = derive_signing_key(app_certificate, &content)?;

    // Encode content
    let mut content_buf = Vec::new();
    pack_string(&mut content_buf, &content.app_id);
    pack_uint32(&mut content_buf, content.issue_ts);
    pack_uint32(&mut content_buf, content.expire);
    pack_uint32(&mut content_buf, content.salt);
    pack_uint16(&mut content_buf, services.len() as u16);
    for svc in &services {
        pack_uint16(&mut content_buf, svc.service_type);
        pack_uint16(&mut content_buf, svc.privileges.len() as u16);
        for (&k, &v) in &svc.privileges {
            pack_uint16(&mut content_buf, k);
            pack_uint32(&mut content_buf, v);
        }
        // Pack extra strings (channel_name, uid) per AccessToken2 spec
        for s in &svc.extra_strings {
            pack_string(&mut content_buf, s);
        }
    }

    // Sign the content
    let mut mac = HmacSha256::new_from_slice(&signing_key)?;
    mac.update(&content_buf);
    let signature = mac.finalize().into_bytes();

    // Final token: VERSION + base64(zlib(pack_string(signature) + content_buf))
    let mut token_buf = Vec::new();
    pack_bytes(&mut token_buf, &signature);
    token_buf.extend_from_slice(&content_buf);

    let compressed = zlib_compress(&token_buf)?;
    let encoded = general_purpose::STANDARD.encode(&compressed);

    Ok(format!("{}{}", VERSION, encoded))
}

/// Build a real Agora AccessToken2 for RTM.
///
/// RTM service includes user_id as extra string after privileges.
pub fn build_token_rtm(
    app_id: &str,
    app_certificate: &str,
    user_id: &str,
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

    let services = vec![ServiceWithExtra {
        service_type: SERVICE_TYPE_RTM,
        privileges,
        extra_strings: vec![user_id.to_string()],
    }];

    let content = TokenContent {
        app_id: app_id.to_string(),
        issue_ts: issued_at,
        expire: expire_secs,
        salt,
    };

    let signing_key = derive_signing_key(app_certificate, &content)?;

    let mut content_buf = Vec::new();
    pack_string(&mut content_buf, &content.app_id);
    pack_uint32(&mut content_buf, content.issue_ts);
    pack_uint32(&mut content_buf, content.expire);
    pack_uint32(&mut content_buf, content.salt);
    pack_uint16(&mut content_buf, services.len() as u16);
    for svc in &services {
        pack_uint16(&mut content_buf, svc.service_type);
        pack_uint16(&mut content_buf, svc.privileges.len() as u16);
        for (&k, &v) in &svc.privileges {
            pack_uint16(&mut content_buf, k);
            pack_uint32(&mut content_buf, v);
        }
        // Pack extra strings (user_id) per AccessToken2 spec
        for s in &svc.extra_strings {
            pack_string(&mut content_buf, s);
        }
    }

    let mut mac = HmacSha256::new_from_slice(&signing_key)?;
    mac.update(&content_buf);
    let signature = mac.finalize().into_bytes();

    // Final token: VERSION + base64(zlib(pack_string(signature) + content_buf))
    let mut token_buf = Vec::new();
    pack_bytes(&mut token_buf, &signature);
    token_buf.extend_from_slice(&content_buf);

    let compressed = zlib_compress(&token_buf)?;
    let encoded = general_purpose::STANDARD.encode(&compressed);

    Ok(format!("{}{}", VERSION, encoded))
}

/// Decode a token to inspect its fields (for diagnostics).
pub fn decode_token(token: &str) -> Result<TokenInfo> {
    if !token.starts_with(VERSION) {
        anyhow::bail!("Invalid token version (expected {})", VERSION);
    }

    let encoded = &token[VERSION.len()..];
    let compressed = general_purpose::STANDARD.decode(encoded)?;
    let data = zlib_decompress(&compressed)?;

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
}

/// Service with extra strings packed after privileges (AccessToken2 spec).
/// RTC: extra_strings = [channel_name, uid]
/// RTM: extra_strings = [user_id]
struct ServiceWithExtra {
    service_type: u16,
    privileges: HashMap<u16, u32>,
    extra_strings: Vec<String>,
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
// Official format: HMAC(key=issue_ts_bytes, data=app_certificate), then HMAC(key=salt_bytes, data=result)
fn derive_signing_key(app_certificate: &str, content: &TokenContent) -> Result<Vec<u8>> {
    // Step 1: HMAC(key=issue_ts, data=app_certificate)
    let mut mac1 = HmacSha256::new_from_slice(&content.issue_ts.to_le_bytes())?;
    mac1.update(app_certificate.as_bytes());
    let key1 = mac1.finalize().into_bytes();

    // Step 2: HMAC(key=salt, data=key1)
    let mut mac2 = HmacSha256::new_from_slice(&content.salt.to_le_bytes())?;
    mac2.update(&key1);
    let key2 = mac2.finalize().into_bytes();

    Ok(key2.to_vec())
}

// Zlib compression/decompression (required by AccessToken2 format)
fn zlib_compress(data: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)?;
    Ok(encoder.finish()?)
}

fn zlib_decompress(data: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(data);
    let mut decompressed = Vec::new();
    decoder.read_to_end(&mut decompressed)?;
    Ok(decompressed)
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

    #[test]
    fn rtc_token_contains_channel_and_uid() {
        // Verify channel_name and uid are packed into the token
        let token = build_token_rtc(
            "appid_for_channel_test",
            "cert_for_channel_test",
            "my-channel",
            "12345",
            Role::Publisher,
            3600,
            1700000000,
        )
        .unwrap();

        // Decode and verify - the raw token data should contain channel+uid
        let encoded = &token[VERSION.len()..];
        let compressed = general_purpose::STANDARD.decode(encoded).unwrap();
        let data = zlib_decompress(&compressed).unwrap();
        let raw = String::from_utf8_lossy(&data);
        assert!(raw.contains("my-channel"), "Token should contain channel name");
        assert!(raw.contains("12345"), "Token should contain uid");
    }

    #[test]
    fn rtm_token_contains_user_id() {
        let token = build_token_rtm(
            "appid_for_rtm_test",
            "cert_for_rtm_test",
            "alice_user",
            3600,
            1700000000,
        )
        .unwrap();

        let encoded = &token[VERSION.len()..];
        let compressed = general_purpose::STANDARD.decode(encoded).unwrap();
        let data = zlib_decompress(&compressed).unwrap();
        let raw = String::from_utf8_lossy(&data);
        assert!(raw.contains("alice_user"), "Token should contain user_id");
    }

    #[test]
    fn different_channels_produce_different_tokens() {
        let token1 = build_token_rtc(
            "appid", "cert", "channel-A", "1001", Role::Publisher, 3600, 1700000000,
        )
        .unwrap();
        let token2 = build_token_rtc(
            "appid", "cert", "channel-B", "1001", Role::Publisher, 3600, 1700000000,
        )
        .unwrap();
        assert_ne!(token1, token2);
    }

    #[test]
    fn different_uids_produce_different_tokens() {
        let token1 = build_token_rtc(
            "appid", "cert", "channel", "1001", Role::Publisher, 3600, 1700000000,
        )
        .unwrap();
        let token2 = build_token_rtc(
            "appid", "cert", "channel", "2002", Role::Publisher, 3600, 1700000000,
        )
        .unwrap();
        assert_ne!(token1, token2);
    }

    #[test]
    fn token_is_zlib_compressed() {
        let token = build_token_rtc(
            "appid", "cert", "channel", "uid", Role::Publisher, 3600, 1700000000,
        )
        .unwrap();

        let encoded = &token[VERSION.len()..];
        let compressed = general_purpose::STANDARD.decode(encoded).unwrap();

        // Zlib data starts with 0x78 (default compression)
        assert!(
            compressed[0] == 0x78,
            "Token payload should be zlib compressed (expected 0x78 header, got 0x{:02x})",
            compressed[0]
        );
    }

    #[test]
    fn signing_key_uses_correct_hmac_order() {
        // Verify the signing key derivation matches official:
        // Step 1: HMAC(key=issue_ts, data=app_certificate)
        // Step 2: HMAC(key=salt, data=step1_result)
        let content = TokenContent {
            app_id: "test".to_string(),
            issue_ts: 1700000000,
            expire: 3600,
            salt: 12345,
        };

        let key = derive_signing_key("test_certificate", &content).unwrap();

        // Manually compute expected key
        let mut mac1 = HmacSha256::new_from_slice(&1700000000u32.to_le_bytes()).unwrap();
        mac1.update(b"test_certificate");
        let step1 = mac1.finalize().into_bytes();

        let mut mac2 = HmacSha256::new_from_slice(&12345u32.to_le_bytes()).unwrap();
        mac2.update(&step1);
        let expected = mac2.finalize().into_bytes();

        assert_eq!(key, expected.to_vec());
    }

    #[test]
    fn rtc_publisher_has_four_privileges() {
        let token = build_token_rtc(
            "appid", "cert", "chan", "uid", Role::Publisher, 3600, 1700000000,
        )
        .unwrap();
        let info = decode_token(&token).unwrap();
        assert_eq!(info.services[0].privileges.len(), 4); // join, audio, video, data
    }

    #[test]
    fn rtc_subscriber_has_one_privilege() {
        let token = build_token_rtc(
            "appid", "cert", "chan", "uid", Role::Subscriber, 3600, 1700000000,
        )
        .unwrap();
        let info = decode_token(&token).unwrap();
        assert_eq!(info.services[0].privileges.len(), 1); // join only
    }

    #[test]
    fn expire_timestamps_are_correct() {
        let issued_at = 1700000000u32;
        let expire_secs = 7200u32;
        let token = build_token_rtc(
            "appid", "cert", "chan", "uid", Role::Publisher, expire_secs, issued_at,
        )
        .unwrap();
        let info = decode_token(&token).unwrap();
        assert_eq!(info.issue_ts, issued_at);
        assert_eq!(info.expire, expire_secs);

        let expected_expire_at = issued_at + expire_secs;
        for (_, &v) in &info.services[0].privileges {
            assert_eq!(v, expected_expire_at);
        }
    }

    #[test]
    fn zlib_compress_decompress_roundtrip() {
        let data = b"Hello, Agora AccessToken2!";
        let compressed = zlib_compress(data).unwrap();
        let decompressed = zlib_decompress(&compressed).unwrap();
        assert_eq!(decompressed, data);
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

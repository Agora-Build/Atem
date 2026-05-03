//! LAN IP detection and sslip.io URL formatting.
//!
//! Used by every local-HTTPS server (`serv rtc`, `serv convo`, …) to
//! figure out the outbound LAN address so the self-signed cert can
//! cover it and the "Network" URL shown to the user resolves from
//! phones/other devices on the same network.

use std::net::{IpAddr, Ipv4Addr, UdpSocket};

/// Detect the LAN IP address by connecting a UDP socket to an external
/// address. This doesn't actually send any data — it just causes the OS
/// to pick the outbound interface, from which we read back the local
/// address.
pub fn get_lan_ip() -> IpAddr {
    UdpSocket::bind("0.0.0.0:0")
        .ok()
        .and_then(|s| {
            s.connect("8.8.8.8:80").ok()?;
            s.local_addr().ok()
        })
        .map(|a| a.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

/// Format an IP address for sslip.io (dots become dashes): `192.168.1.42`
/// → `192-168-1-42.sslip.io`. sslip.io is a public wildcard-DNS service
/// that resolves any `1-2-3-4.sslip.io` to `1.2.3.4`, which lets
/// browsers on other devices trust our self-signed cert without
/// fighting certificate hostname validation on a raw IP.
pub fn sslip_host(ip: &IpAddr) -> String {
    format!("{}.sslip.io", ip.to_string().replace('.', "-"))
}

/// Generate a channel name when the user didn't provide `--channel`.
/// Format: `atem-<scenario>-<app_id[..12]>-<ts>-<rand4>`.
/// `scenario` distinguishes the server type (e.g. "rtc", "convo").
pub fn gen_channel(app_id: &str, scenario: &str) -> String {
    use rand::RngCore;
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let rand = rand::thread_rng().next_u32();
    let prefix: String = app_id.chars().take(12).collect();
    format!("atem-{scenario}-{prefix}-{ts}-{:04x}", rand & 0xffff)
}

/// Expand placeholders in a user-provided `--channel` template:
///   `{appid}` → first 12 chars of `app_id`
///   `{ts}`    → unix epoch seconds at expansion time
/// Other characters pass through verbatim. Idempotent on strings with
/// no placeholders, so callers can always run it through the expander.
pub fn expand_channel_template(template: &str, app_id: &str) -> String {
    if !template.contains("{appid}") && !template.contains("{ts}") {
        return template.to_string();
    }
    let appid12: String = app_id.chars().take(12).collect();
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    template
        .replace("{appid}", &appid12)
        .replace("{ts}", &ts.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_lan_ip_returns_non_unspecified() {
        let ip = get_lan_ip();
        assert!(!ip.is_unspecified());
    }

    #[test]
    fn sslip_host_formats_correctly() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 42));
        assert_eq!(sslip_host(&ip), "192-168-1-42.sslip.io");
    }

    #[test]
    fn expand_channel_template_passes_through_when_no_placeholders() {
        // No `{appid}` / `{ts}` → string returned verbatim.
        assert_eq!(
            expand_channel_template("test-001", "abcdef0123456789abcd"),
            "test-001"
        );
    }

    #[test]
    fn expand_channel_template_substitutes_appid() {
        let out = expand_channel_template(
            "atem-convo-{appid}-fixed-0001",
            "2655d20a82fc47cebcff82d5bd5d53ef",
        );
        assert_eq!(out, "atem-convo-2655d20a82fc-fixed-0001");
    }

    #[test]
    fn expand_channel_template_substitutes_ts_with_digits() {
        let out = expand_channel_template(
            "atem-convo-{appid}-{ts}-0001",
            "2655d20a82fc47cebcff82d5bd5d53ef",
        );
        // Format: atem-convo-<12chars>-<unix_secs>-0001 — verify the
        // ts segment is all digits and reasonable (≥ 1700000000 = 2023).
        let parts: Vec<&str> = out.split('-').collect();
        assert_eq!(parts.len(), 5);
        assert_eq!(parts[3].parse::<u64>().unwrap_or(0) > 1_700_000_000, true);
    }
}

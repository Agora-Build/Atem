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
}

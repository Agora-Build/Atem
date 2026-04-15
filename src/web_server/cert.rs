use anyhow::Result;
use rcgen::{CertificateParams, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::IpAddr;

/// Generate a self-signed TLS certificate for the given IP address,
/// its sslip.io hostname, localhost, and any additional DNS names
/// (e.g. tunnel hostnames from `config.toml`'s `extra_hostnames`).
pub fn generate_self_signed_cert(
    ip: &IpAddr,
    extra_hostnames: &[String],
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let sslip = format!("{}.sslip.io", ip.to_string().replace('.', "-"));

    let mut names = vec![sslip, "localhost".to_string()];
    for h in extra_hostnames {
        let trimmed = h.trim();
        if !trimmed.is_empty() {
            names.push(trimmed.to_string());
        }
    }

    let mut params = CertificateParams::new(names)?;
    params
        .subject_alt_names
        .push(SanType::IpAddress((*ip).into()));

    let key_pair = KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    let cert_der = CertificateDer::from(cert.der().to_vec());
    let key_der =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der().to_vec()));

    Ok((vec![cert_der], key_der))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn generate_cert_succeeds() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let result = generate_self_signed_cert(&ip, &[]);
        assert!(result.is_ok());
        let (certs, _key) = result.unwrap();
        assert_eq!(certs.len(), 1);
    }

    #[test]
    fn generate_cert_accepts_extra_hostnames() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let extras = vec![
            "genie.netbird.cloud".to_string(),
            "dev.mytailnet.ts.net".to_string(),
        ];
        let result = generate_self_signed_cert(&ip, &extras);
        assert!(result.is_ok());
    }

    #[test]
    fn generate_cert_ignores_empty_and_whitespace_entries() {
        let ip = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let extras = vec!["".to_string(), "   ".to_string(), "ok.example.com".to_string()];
        let result = generate_self_signed_cert(&ip, &extras);
        assert!(result.is_ok());
    }
}

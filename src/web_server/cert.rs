use anyhow::Result;
use rcgen::{CertificateParams, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::net::IpAddr;

/// Generate a self-signed TLS certificate for the given IP address,
/// its sslip.io hostname, and localhost.
pub fn generate_self_signed_cert(
    ip: &IpAddr,
) -> Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
    let sslip = format!("{}.sslip.io", ip.to_string().replace('.', "-"));

    let mut params = CertificateParams::new(vec![sslip.clone(), "localhost".to_string()])?;
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
        let result = generate_self_signed_cert(&ip);
        assert!(result.is_ok());
        let (certs, _key) = result.unwrap();
        assert_eq!(certs.len(), 1);
    }
}

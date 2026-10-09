//! Device verification: commit-then-reveal, a 12-character safety code both
//! sides show, then applying what a verified Astation sends.
//! See designs/e2e-encryption.md "Devices → Verification".
use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD};
use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::memory::device_keys::DeviceKeys;
use crate::memory::encoding::{base32_prefix, enc};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AstationKeys {
    /// SEC1-encoded P-256 public key of Astation's Secure Enclave signing key.
    pub sign_pub: Vec<u8>,
    pub enc_pub: [u8; 32],
    pub recovery_sign_pub: [u8; 32],
    pub nonce_s: [u8; 32],
}

fn decode_exact<const N: usize>(value: &str, what: &str) -> Result<[u8; N]> {
    STANDARD
        .decode(value)
        .with_context(|| format!("{what} is not base64"))?
        .try_into()
        .map_err(|_| anyhow!("{what} has the wrong length"))
}

impl AstationKeys {
    pub fn from_wire(
        sign_pub: &str,
        enc_pub: &str,
        recovery_sign_pub: &str,
        nonce: &str,
    ) -> Result<Self> {
        let sign_pub = STANDARD
            .decode(sign_pub)
            .context("Astation signing key is not base64")?;
        if sign_pub.len() != 65 {
            return Err(anyhow!("Astation signing key must be a 65-byte SEC1 point"));
        }
        Ok(Self {
            sign_pub,
            enc_pub: decode_exact(enc_pub, "Astation encryption key")?,
            recovery_sign_pub: decode_exact(recovery_sign_pub, "recovery signing key")?,
            nonce_s: decode_exact(nonce, "Astation nonce")?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reveal {
    pub device_pub: [u8; 32],
    pub device_sign_pub: [u8; 32],
    pub unlock_auth_pub: [u8; 32],
    pub nonce_a: [u8; 32],
}

pub fn commitment_for(reveal: &Reveal) -> [u8; 32] {
    Sha256::digest(enc(&[
        b"atem-verify-commit-v1",
        &reveal.device_pub,
        &reveal.device_sign_pub,
        &reveal.unlock_auth_pub,
        &reveal.nonce_a,
    ]))
    .into()
}

pub fn safety_code(reveal: &Reveal, astation: &AstationKeys) -> String {
    let digest = Sha256::digest(enc(&[
        b"atem-safety-code-v1",
        &reveal.device_pub,
        &reveal.device_sign_pub,
        &reveal.unlock_auth_pub,
        &astation.sign_pub,
        &astation.enc_pub,
        &astation.recovery_sign_pub,
        &reveal.nonce_a,
        &astation.nonce_s,
    ]));
    let raw = base32_prefix(&digest, 12);
    format!("{}-{}-{}", &raw[..4], &raw[4..8], &raw[8..])
}

pub struct Handshake {
    keys: DeviceKeys,
    nonce_a: [u8; 32],
}

impl Handshake {
    pub fn start(keys: DeviceKeys) -> Self {
        let mut nonce_a = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut nonce_a);
        Self { keys, nonce_a }
    }

    pub fn reveal(&self) -> Reveal {
        Reveal {
            device_pub: self.keys.device_pub(),
            device_sign_pub: self.keys.device_sign_pub(),
            unlock_auth_pub: self.keys.unlock_auth_pub(),
            nonce_a: self.nonce_a,
        }
    }

    pub fn commitment(&self) -> [u8; 32] {
        commitment_for(&self.reveal())
    }

    pub fn safety_code(&self, astation: &AstationKeys) -> String {
        safety_code(&self.reveal(), astation)
    }

    pub fn keys(&self) -> &DeviceKeys {
        &self.keys
    }

    pub fn into_keys(self) -> DeviceKeys {
        self.keys
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn astation() -> AstationKeys {
        AstationKeys {
            sign_pub: vec![4; 65],
            enc_pub: [5; 32],
            recovery_sign_pub: [6; 32],
            nonce_s: [7; 32],
        }
    }

    #[test]
    fn commitment_matches_the_reveal_and_hides_the_nonce() {
        let first = Handshake::start(DeviceKeys::generate());
        assert_eq!(commitment_for(&first.reveal()), first.commitment());
        let mut changed = first.reveal();
        changed.nonce_a[0] ^= 1;
        assert_ne!(commitment_for(&changed), first.commitment());
    }

    #[test]
    fn safety_code_is_stable_formatted_and_covers_every_key() {
        let handshake = Handshake::start(DeviceKeys::generate());
        let code = handshake.safety_code(&astation());
        assert_eq!(code, handshake.safety_code(&astation()));
        assert_eq!(code.len(), 14);
        assert!(code.chars().enumerate().all(|(i, c)| if i == 4 || i == 9 {
            c == '-'
        } else {
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".contains(c)
        }));

        let mut swapped = astation();
        swapped.recovery_sign_pub = [9; 32];
        assert_ne!(code, handshake.safety_code(&swapped));
        let mut nonce = astation();
        nonce.nonce_s = [8; 32];
        assert_ne!(code, handshake.safety_code(&nonce));
    }

    #[test]
    fn astation_keys_parse_from_base64() {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let keys = AstationKeys::from_wire(
            &STANDARD.encode([4u8; 65]),
            &STANDARD.encode([5u8; 32]),
            &STANDARD.encode([6u8; 32]),
            &STANDARD.encode([7u8; 32]),
        )
        .unwrap();
        assert_eq!(keys.enc_pub, [5; 32]);
        assert!(AstationKeys::from_wire("", &STANDARD.encode([5u8; 31]), "", "").is_err());
    }
}

//! Statements Astation signs with its Secure Enclave P-256 key. atem trusts a
//! mode, key or device only when it arrives inside one of these.
//! See designs/e2e-encryption.md "Signed statements".
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::memory::crypto::EncryptionMode;
#[cfg(test)]
use crate::memory::encoding::u64_field;
use crate::memory::encoding::{dec, enc, read_u64};

/// A statement as it travels: its exact encoded bytes and a 64-byte `r ‖ s`
/// signature, both base64.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedWire {
    pub statement: String,
    pub signature: String,
}

/// Checks `signed` against Astation's SEC1 public key and returns its fields.
pub fn verify_astation(sign_pub: &[u8], signed: &SignedWire) -> Result<Vec<Vec<u8>>> {
    let key = VerifyingKey::from_sec1_bytes(sign_pub)
        .map_err(|_| anyhow!("Astation signing key is malformed"))?;
    let statement = STANDARD
        .decode(&signed.statement)
        .context("statement is not base64")?;
    let raw = STANDARD
        .decode(&signed.signature)
        .context("signature is not base64")?;
    let signature =
        Signature::from_slice(&raw).map_err(|_| anyhow!("signature must be 64 bytes r‖s"))?;
    if signature.normalize_s().is_some() {
        bail!("signature is not in low-S form");
    }
    key.verify(&statement, &signature)
        .map_err(|_| anyhow!("Astation signature check failed"))?;
    dec(&statement)
}

fn text(field: &[u8]) -> Result<String> {
    String::from_utf8(field.to_vec()).context("statement field is not UTF-8")
}

fn key32(field: &[u8]) -> Result<[u8; 32]> {
    field
        .try_into()
        .map_err(|_| anyhow!("expected a 32-byte key"))
}

fn expect(fields: &[Vec<u8>], label: &str, count: usize) -> Result<()> {
    if fields.first().map(Vec::as_slice) != Some(label.as_bytes()) {
        bail!("expected a {label} statement");
    }
    if fields.len() != count {
        bail!(
            "{label} statement has {} fields, expected {count}",
            fields.len()
        );
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountState {
    pub account: String,
    pub sign_gen: u64,
    pub mode: EncryptionMode,
    pub kid: Option<String>,
    pub epoch: u64,
}

impl AccountState {
    pub const LABEL: &'static str = "atem-account-state-v1";

    /// Astation's side of the encoding: atem only parses, so tests alone encode.
    #[cfg(test)]
    pub fn encode(&self) -> Vec<u8> {
        enc(&[
            Self::LABEL.as_bytes(),
            self.account.as_bytes(),
            &u64_field(self.sign_gen),
            self.mode.as_str().as_bytes(),
            self.kid.as_deref().unwrap_or("").as_bytes(),
            &u64_field(self.epoch),
        ])
    }

    pub fn parse(fields: &[Vec<u8>]) -> Result<Self> {
        expect(fields, Self::LABEL, 6)?;
        let kid = text(&fields[4])?;
        Ok(Self {
            account: text(&fields[1])?,
            sign_gen: read_u64(&fields[2])?,
            mode: EncryptionMode::parse(&text(&fields[3])?)?,
            kid: (!kid.is_empty()).then_some(kid),
            epoch: read_u64(&fields[5])?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceVerified {
    pub account: String,
    pub sign_gen: u64,
    pub device_id: String,
    pub device_pub: [u8; 32],
    pub device_sign_pub: [u8; 32],
    pub unlock_auth_pub: [u8; 32],
    /// `transcript_for(commitment, nonce_a, nonce_s)` of the ceremony this
    /// certificate answers, so a recorded certificate can't be replayed into
    /// a later ceremony that reuses the same device keys.
    pub transcript: [u8; 32],
    pub epoch: u64,
}

impl DeviceVerified {
    pub const LABEL: &'static str = "atem-device-verified-v1";

    /// Astation's side of the encoding: atem only parses, so tests alone encode.
    #[cfg(test)]
    pub fn encode(&self) -> Vec<u8> {
        enc(&[
            Self::LABEL.as_bytes(),
            self.account.as_bytes(),
            &u64_field(self.sign_gen),
            self.device_id.as_bytes(),
            &self.device_pub,
            &self.device_sign_pub,
            &self.unlock_auth_pub,
            &self.transcript,
            &u64_field(self.epoch),
        ])
    }

    pub fn parse(fields: &[Vec<u8>]) -> Result<Self> {
        expect(fields, Self::LABEL, 9)?;
        Ok(Self {
            account: text(&fields[1])?,
            sign_gen: read_u64(&fields[2])?,
            device_id: text(&fields[3])?,
            device_pub: key32(&fields[4])?,
            device_sign_pub: key32(&fields[5])?,
            unlock_auth_pub: key32(&fields[6])?,
            transcript: key32(&fields[7])?,
            epoch: read_u64(&fields[8])?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantStatement {
    pub account: String,
    pub sign_gen: u64,
    /// `K` in this step; `index` and `scope` arrive with credentials.
    pub kind: String,
    pub device_id: String,
    pub device_pub: [u8; 32],
    pub kid: String,
    /// Empty except for scope grants.
    pub scope_hmac: String,
    /// `sealed_hash(encapped_key, ciphertext)` of the HPKE output.
    pub sealed_hash: [u8; 32],
}

impl GrantStatement {
    pub const LABEL: &'static str = "atem-grant-v1";

    /// Astation's side of the encoding: atem only parses, so tests alone encode.
    #[cfg(test)]
    pub fn encode(&self) -> Vec<u8> {
        enc(&[
            Self::LABEL.as_bytes(),
            self.account.as_bytes(),
            &u64_field(self.sign_gen),
            self.kind.as_bytes(),
            self.device_id.as_bytes(),
            &self.device_pub,
            self.kid.as_bytes(),
            self.scope_hmac.as_bytes(),
            &self.sealed_hash,
        ])
    }

    pub fn parse(fields: &[Vec<u8>]) -> Result<Self> {
        expect(fields, Self::LABEL, 9)?;
        Ok(Self {
            account: text(&fields[1])?,
            sign_gen: read_u64(&fields[2])?,
            kind: text(&fields[3])?,
            device_id: text(&fields[4])?,
            device_pub: key32(&fields[5])?,
            kid: text(&fields[6])?,
            scope_hmac: text(&fields[7])?,
            sealed_hash: key32(&fields[8])?,
        })
    }

    /// HPKE `info`: everything the seal is for, without the hash of its own output.
    pub fn info(&self) -> Vec<u8> {
        enc(&[
            b"atem-grant-info-v1",
            self.account.as_bytes(),
            self.kind.as_bytes(),
            self.device_id.as_bytes(),
            &self.device_pub,
            self.kid.as_bytes(),
            self.scope_hmac.as_bytes(),
        ])
    }
}

pub fn sealed_hash(encapped: &[u8], ciphertext: &[u8]) -> [u8; 32] {
    Sha256::digest(enc(&[encapped, ciphertext])).into()
}

/// Test stand-in for Astation: a P-256 key that signs statements the way
/// Astation's Secure Enclave key does (64-byte r‖s, low-S).
#[cfg(test)]
pub(crate) struct FakeAstation {
    key: p256::ecdsa::SigningKey,
}

#[cfg(test)]
impl FakeAstation {
    pub fn new() -> Self {
        Self {
            key: p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng),
        }
    }

    pub fn sign_pub(&self) -> Vec<u8> {
        self.key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    pub fn sign(&self, statement: &[u8]) -> SignedWire {
        use p256::ecdsa::signature::Signer;
        let signature: Signature = self.key.sign(statement);
        let signature = signature.normalize_s().unwrap_or(signature);
        SignedWire {
            statement: STANDARD.encode(statement),
            signature: STANDARD.encode(signature.to_bytes()),
        }
    }

    /// Like `sign`, but with a fresh random nonce per call, as CryptoKit's
    /// signatures are: same statement, different signature bytes.
    pub fn sign_randomized(&self, statement: &[u8]) -> SignedWire {
        use p256::ecdsa::signature::RandomizedSigner;
        let signature: Signature = self
            .key
            .try_sign_with_rng(&mut rand::rngs::OsRng, statement)
            .expect("OsRng signing");
        let signature = signature.normalize_s().unwrap_or(signature);
        SignedWire {
            statement: STANDARD.encode(statement),
            signature: STANDARD.encode(signature.to_bytes()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn state(epoch: u64) -> AccountState {
        AccountState {
            account: "acct".into(),
            sign_gen: 1,
            mode: EncryptionMode::On,
            kid: Some("0123abcd".into()),
            epoch,
        }
    }

    #[test]
    fn signed_account_state_verifies_and_parses() {
        let astation = FakeAstation::new();
        let signed = astation.sign(&state(3).encode());
        let fields = verify_astation(&astation.sign_pub(), &signed).unwrap();
        assert_eq!(AccountState::parse(&fields).unwrap(), state(3));
    }

    #[test]
    fn other_signer_and_tampering_are_rejected() {
        let astation = FakeAstation::new();
        let relay = FakeAstation::new();
        let forged = relay.sign(&state(3).encode());
        assert!(verify_astation(&astation.sign_pub(), &forged).is_err());

        let mut signed = astation.sign(&state(3).encode());
        signed.statement = STANDARD.encode(state(4).encode());
        assert!(verify_astation(&astation.sign_pub(), &signed).is_err());
    }

    #[test]
    fn high_s_signature_is_rejected() {
        let astation = FakeAstation::new();
        let signed = astation.sign(&state(3).encode());
        let raw = STANDARD.decode(&signed.signature).unwrap();
        let low = Signature::from_slice(&raw).unwrap();
        let (r, s) = low.split_scalars();
        let high = Signature::from_scalars(r, -s).unwrap();
        let tampered = SignedWire {
            statement: signed.statement.clone(),
            signature: STANDARD.encode(high.to_bytes()),
        };
        assert!(
            verify_astation(&astation.sign_pub(), &tampered)
                .unwrap_err()
                .to_string()
                .contains("low-S")
        );
    }

    #[test]
    fn wrong_label_or_field_count_is_rejected() {
        let verified = DeviceVerified {
            account: "acct".into(),
            sign_gen: 1,
            device_id: "dev".into(),
            device_pub: [1; 32],
            device_sign_pub: [2; 32],
            unlock_auth_pub: [3; 32],
            transcript: [4; 32],
            epoch: 9,
        };
        let fields = dec(&verified.encode()).unwrap();
        assert_eq!(fields.len(), 9);
        assert_eq!(fields[7], vec![4; 32]);
        assert!(AccountState::parse(&fields).is_err());
        assert_eq!(DeviceVerified::parse(&fields).unwrap(), verified);
        assert!(DeviceVerified::parse(&fields[..8]).is_err());
    }

    #[test]
    fn grant_statement_round_trips_and_info_excludes_the_hash() {
        let grant = GrantStatement {
            account: "acct".into(),
            sign_gen: 1,
            kind: "K".into(),
            device_id: "dev".into(),
            device_pub: [4; 32],
            kid: "0123abcd".into(),
            scope_hmac: String::new(),
            sealed_hash: sealed_hash(b"enc", b"ct"),
        };
        assert_eq!(
            GrantStatement::parse(&dec(&grant.encode()).unwrap()).unwrap(),
            grant
        );
        let mut other = grant.clone();
        other.sealed_hash = [0; 32];
        assert_eq!(grant.info(), other.info());
        assert_ne!(sealed_hash(b"enc", b"ct"), sealed_hash(b"en", b"cct"));
    }
}

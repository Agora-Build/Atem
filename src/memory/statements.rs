//! Statements Astation signs with its Secure Enclave P-256 key, and the
//! unlock/rotation statements this device signs (Ed25519). atem trusts a
//! mode, key or device only when it arrives inside one of these.
//! See designs/e2e-encryption.md "Signed statements".
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use p256::ecdsa::{Signature, VerifyingKey, signature::Verifier};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::memory::crypto::EncryptionMode;
use crate::memory::encoding::{dec, enc, read_u64, u64_field};

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

/// Asks the home Astation to release this device's storage key. Signed by
/// the unlock-auth key; `e_pub` is a single-use X25519 key the release is
/// sealed to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockRequest {
    pub account: String,
    pub device_id: String,
    /// `/proc/sys/kernel/random/boot_id`, empty where there is none.
    pub boot_id: String,
    /// Empty until auto-unlock tickets (build step 7).
    pub ticket: String,
    pub e_pub: [u8; 32],
    pub nonce: [u8; 32],
    /// Unix seconds.
    pub time: u64,
    /// The storage key the device asks for: `device_keys.sealed`'s header.
    pub storage_kid: String,
}

impl UnlockRequest {
    pub const LABEL: &'static str = "atem-unlock-request-v1";

    pub fn encode(&self) -> Vec<u8> {
        enc(&[
            Self::LABEL.as_bytes(),
            self.account.as_bytes(),
            self.device_id.as_bytes(),
            self.boot_id.as_bytes(),
            self.ticket.as_bytes(),
            &self.e_pub,
            &self.nonce,
            &u64_field(self.time),
            self.storage_kid.as_bytes(),
        ])
    }

    pub fn parse(fields: &[Vec<u8>]) -> Result<Self> {
        expect(fields, Self::LABEL, 9)?;
        Ok(Self {
            account: text(&fields[1])?,
            device_id: text(&fields[2])?,
            boot_id: text(&fields[3])?,
            ticket: text(&fields[4])?,
            e_pub: key32(&fields[5])?,
            nonce: key32(&fields[6])?,
            time: read_u64(&fields[7])?,
            storage_kid: text(&fields[8])?,
        })
    }
}

/// SHA-256 of the exact request bytes: what the grant and the HPKE info bind to.
pub fn unlock_request_hash(statement: &[u8]) -> [u8; 32] {
    Sha256::digest(statement).into()
}

/// HPKE `info` for a storage key released to an unlock request's `e_pub`.
pub fn unlock_info(
    account: &str,
    device_id: &str,
    storage_kid: &str,
    request_hash: &[u8; 32],
) -> Vec<u8> {
    enc(&[
        b"atem-unlock-info-v1",
        account.as_bytes(),
        device_id.as_bytes(),
        storage_kid.as_bytes(),
        request_hash,
    ])
}

/// Astation's answer to one unlock request: which storage key it released.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnlockGrant {
    pub account: String,
    pub sign_gen: u64,
    pub device_id: String,
    pub storage_kid: String,
    pub request_hash: [u8; 32],
    /// `sealed_hash(encapped_key, ciphertext)` of the HPKE output.
    pub sealed_hash: [u8; 32],
}

impl UnlockGrant {
    pub const LABEL: &'static str = "atem-unlock-grant-v1";

    /// Astation's side of the encoding: atem only parses, so tests alone encode.
    #[cfg(test)]
    pub fn encode(&self) -> Vec<u8> {
        enc(&[
            Self::LABEL.as_bytes(),
            self.account.as_bytes(),
            &u64_field(self.sign_gen),
            self.device_id.as_bytes(),
            self.storage_kid.as_bytes(),
            &self.request_hash,
            &self.sealed_hash,
        ])
    }

    pub fn parse(fields: &[Vec<u8>]) -> Result<Self> {
        expect(fields, Self::LABEL, 7)?;
        Ok(Self {
            account: text(&fields[1])?,
            sign_gen: read_u64(&fields[2])?,
            device_id: text(&fields[3])?,
            storage_kid: text(&fields[4])?,
            request_hash: key32(&fields[5])?,
            sealed_hash: key32(&fields[6])?,
        })
    }
}

/// HPKE `info` for a storage key sealed to Astation's encryption key.
pub fn storage_key_info(account: &str, device_id: &str, storage_kid: &str) -> Vec<u8> {
    enc(&[
        b"atem-storage-key-info-v1",
        account.as_bytes(),
        device_id.as_bytes(),
        storage_kid.as_bytes(),
    ])
}

/// A new storage key for Astation to hold. Signed by the device signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageRotate {
    pub account: String,
    pub device_id: String,
    /// Empty at the first sealing, when Astation holds no storage key yet.
    pub old_storage_kid: String,
    pub new_storage_kid: String,
    pub sealed_hash: [u8; 32],
}

impl StorageRotate {
    pub const LABEL: &'static str = "atem-storage-rotate-v1";

    pub fn encode(&self) -> Vec<u8> {
        enc(&[
            Self::LABEL.as_bytes(),
            self.account.as_bytes(),
            self.device_id.as_bytes(),
            self.old_storage_kid.as_bytes(),
            self.new_storage_kid.as_bytes(),
            &self.sealed_hash,
        ])
    }

    /// Astation parses it; atem reads its own rotate back to learn which
    /// storage key Astation's ack must name.
    pub fn parse(fields: &[Vec<u8>]) -> Result<Self> {
        expect(fields, Self::LABEL, 6)?;
        Ok(Self {
            account: text(&fields[1])?,
            device_id: text(&fields[2])?,
            old_storage_kid: text(&fields[3])?,
            new_storage_kid: text(&fields[4])?,
            sealed_hash: key32(&fields[5])?,
        })
    }
}

/// Astation stored the new storage key as pending (and kept the old one).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageAck {
    pub account: String,
    pub sign_gen: u64,
    pub device_id: String,
    pub storage_kid: String,
}

impl StorageAck {
    pub const LABEL: &'static str = "atem-storage-ack-v1";

    /// Astation's side of the encoding: atem only parses, so tests alone encode.
    #[cfg(test)]
    pub fn encode(&self) -> Vec<u8> {
        enc(&[
            Self::LABEL.as_bytes(),
            self.account.as_bytes(),
            &u64_field(self.sign_gen),
            self.device_id.as_bytes(),
            self.storage_kid.as_bytes(),
        ])
    }

    pub fn parse(fields: &[Vec<u8>]) -> Result<Self> {
        expect(fields, Self::LABEL, 5)?;
        Ok(Self {
            account: text(&fields[1])?,
            sign_gen: read_u64(&fields[2])?,
            device_id: text(&fields[3])?,
            storage_kid: text(&fields[4])?,
        })
    }
}

/// The device switched to the new storage key; Astation may drop the old one.
/// Signed by the device signing key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageConfirm {
    pub account: String,
    pub device_id: String,
    pub storage_kid: String,
}

impl StorageConfirm {
    pub const LABEL: &'static str = "atem-storage-confirm-v1";

    pub fn encode(&self) -> Vec<u8> {
        enc(&[
            Self::LABEL.as_bytes(),
            self.account.as_bytes(),
            self.device_id.as_bytes(),
            self.storage_kid.as_bytes(),
        ])
    }

    /// Astation's side: atem only encodes, so tests alone parse.
    #[cfg(test)]
    pub fn parse(fields: &[Vec<u8>]) -> Result<Self> {
        expect(fields, Self::LABEL, 4)?;
        Ok(Self {
            account: text(&fields[1])?,
            device_id: text(&fields[2])?,
            storage_kid: text(&fields[3])?,
        })
    }
}

/// The device gives up a storage key Astation holds as pending (its sealed
/// file is gone). Signed by the device signing key; Astation drops a pending
/// key only if it equals `storage_kid` exactly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageAbandon {
    pub account: String,
    pub device_id: String,
    pub storage_kid: String,
}

impl StorageAbandon {
    pub const LABEL: &'static str = "atem-storage-abandon-v1";

    pub fn encode(&self) -> Vec<u8> {
        enc(&[
            Self::LABEL.as_bytes(),
            self.account.as_bytes(),
            self.device_id.as_bytes(),
            self.storage_kid.as_bytes(),
        ])
    }

    /// Astation's side: atem only encodes, so tests alone parse.
    #[cfg(test)]
    pub fn parse(fields: &[Vec<u8>]) -> Result<Self> {
        expect(fields, Self::LABEL, 4)?;
        Ok(Self {
            account: text(&fields[1])?,
            device_id: text(&fields[2])?,
            storage_kid: text(&fields[3])?,
        })
    }
}

/// Astation's check of a device (or unlock-auth) Ed25519 signature.
#[cfg(test)]
pub(crate) fn verify_device(sign_pub: &[u8; 32], signed: &SignedWire) -> Result<Vec<Vec<u8>>> {
    let key = ed25519_dalek::VerifyingKey::from_bytes(sign_pub)
        .map_err(|_| anyhow!("device signing key is malformed"))?;
    let statement = STANDARD
        .decode(&signed.statement)
        .context("statement is not base64")?;
    let raw: [u8; 64] = STANDARD
        .decode(&signed.signature)
        .context("signature is not base64")?
        .try_into()
        .map_err(|_| anyhow!("signature must be 64 bytes"))?;
    key.verify_strict(&statement, &ed25519_dalek::Signature::from_bytes(&raw))
        .map_err(|_| anyhow!("device signature check failed"))?;
    dec(&statement)
}

/// Test stand-in for Astation: a P-256 key that signs statements the way
/// Astation's Secure Enclave key does (64-byte r‖s, low-S).
#[cfg(test)]
pub(crate) struct FakeAstation {
    key: p256::ecdsa::SigningKey,
    enc: x25519_dalek::StaticSecret,
}

#[cfg(test)]
impl FakeAstation {
    pub fn new() -> Self {
        Self {
            key: p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng),
            enc: x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng),
        }
    }

    /// Astation's X25519 encryption public key (receives storage keys).
    pub fn enc_pub(&self) -> [u8; 32] {
        x25519_dalek::PublicKey::from(&self.enc).to_bytes()
    }

    pub fn enc_secret_bytes(&self) -> [u8; 32] {
        self.enc.to_bytes()
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

    #[test]
    fn unlock_statements_round_trip() {
        let request = UnlockRequest {
            account: "acct".into(),
            device_id: "dev".into(),
            boot_id: "boot".into(),
            ticket: String::new(),
            e_pub: [1; 32],
            nonce: [2; 32],
            time: 1_760_000_000,
            storage_kid: "0a1b2c3d".into(),
        };
        let bytes = request.encode();
        assert_eq!(
            UnlockRequest::parse(&dec(&bytes).unwrap()).unwrap(),
            request
        );
        assert_eq!(
            unlock_request_hash(&bytes),
            <[u8; 32]>::from(Sha256::digest(&bytes))
        );
        let grant = UnlockGrant {
            account: "acct".into(),
            sign_gen: 1,
            device_id: "dev".into(),
            storage_kid: "0a1b2c3d".into(),
            request_hash: unlock_request_hash(&bytes),
            sealed_hash: [3; 32],
        };
        assert_eq!(
            UnlockGrant::parse(&dec(&grant.encode()).unwrap()).unwrap(),
            grant
        );
        assert!(
            UnlockGrant::parse(&dec(&bytes).unwrap()).is_err(),
            "a request is not a grant"
        );
        assert_ne!(
            unlock_info("acct", "dev", "0a1b2c3d", &[4; 32]),
            unlock_info("acct", "dev", "0a1b2c3d", &[5; 32])
        );
    }

    #[test]
    fn storage_statements_round_trip() {
        let rotate = StorageRotate {
            account: "acct".into(),
            device_id: "dev".into(),
            old_storage_kid: String::new(),
            new_storage_kid: "0a1b2c3d".into(),
            sealed_hash: [6; 32],
        };
        assert_eq!(
            StorageRotate::parse(&dec(&rotate.encode()).unwrap()).unwrap(),
            rotate
        );
        let ack = StorageAck {
            account: "acct".into(),
            sign_gen: 1,
            device_id: "dev".into(),
            storage_kid: "0a1b2c3d".into(),
        };
        assert_eq!(
            StorageAck::parse(&dec(&ack.encode()).unwrap()).unwrap(),
            ack
        );
        let confirm = StorageConfirm {
            account: "acct".into(),
            device_id: "dev".into(),
            storage_kid: "0a1b2c3d".into(),
        };
        assert_eq!(
            StorageConfirm::parse(&dec(&confirm.encode()).unwrap()).unwrap(),
            confirm
        );
        assert!(StorageAck::parse(&dec(&confirm.encode()).unwrap()).is_err());
        let abandon = StorageAbandon {
            account: "acct".into(),
            device_id: "dev".into(),
            storage_kid: "0a1b2c3d".into(),
        };
        assert_eq!(
            StorageAbandon::parse(&dec(&abandon.encode()).unwrap()).unwrap(),
            abandon
        );
        assert!(StorageConfirm::parse(&dec(&abandon.encode()).unwrap()).is_err());
        assert_ne!(
            storage_key_info("acct", "dev", "0a1b2c3d"),
            storage_key_info("acct", "dev", "4e5f6a7b")
        );
    }

    #[test]
    fn device_signatures_verify_only_with_the_signing_key() {
        let keys = crate::memory::device_keys::DeviceKeys::generate();
        let signed = keys.sign_statement(&enc(&[b"label", b"x"]));
        assert_eq!(
            verify_device(&keys.device_sign_pub(), &signed).unwrap(),
            vec![b"label".to_vec(), b"x".to_vec()]
        );
        assert!(verify_device(&keys.unlock_auth_pub(), &signed).is_err());
    }

    #[test]
    fn fake_astation_has_an_encryption_key() {
        let fake = FakeAstation::new();
        let derived = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(
            fake.enc_secret_bytes(),
        ));
        assert_eq!(derived.to_bytes(), fake.enc_pub());
        assert_ne!(fake.enc_pub(), FakeAstation::new().enc_pub());
    }
}

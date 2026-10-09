//! The storage key and the sealed device-keys file. The storage key's only
//! job is to protect `device_keys.sealed`; Astation holds it, the key agent
//! holds it while unlocked, and it is replaced at every unlock.
//! See designs/e2e-encryption.md "Keys on disk (atem)".
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use chacha20poly1305::{
    Key, XChaCha20Poly1305, XNonce,
    aead::{Aead, AeadCore, KeyInit, Payload},
};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::path::Path;
use zeroize::Zeroizing;

use crate::memory::device_keys::{DeviceKeys, UnlockAuthKey};
use crate::memory::encoding::{dec, enc};
use crate::memory::statements::{
    SignedWire, StorageAck, UnlockGrant, UnlockRequest, sealed_hash, unlock_request_hash,
    verify_astation,
};
use crate::memory::trust::AstationTrust;

pub type StorageKey = Zeroizing<[u8; 32]>;

pub fn new_storage_key() -> StorageKey {
    let mut key = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(key.as_mut());
    key
}

/// 8 lowercase hex characters, like a `kid`.
pub fn new_storage_kid() -> String {
    let mut bytes = [0u8; 4];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Associated data of the sealed file: which device and which storage key.
pub fn device_keys_aad(device_id: &str, storage_kid: &str) -> Vec<u8> {
    enc(&[
        b"atem-device-keys-v1",
        device_id.as_bytes(),
        storage_kid.as_bytes(),
    ])
}

/// `device_keys.sealed` (and `.next` during a rotation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedDeviceKeys {
    pub version: u8,
    pub device_id: String,
    pub storage_kid: String,
    /// Base64 24-byte XChaCha20 nonce.
    pub nonce: String,
    pub ciphertext: String,
}

impl SealedDeviceKeys {
    pub fn seal(
        keys: &DeviceKeys,
        device_id: &str,
        storage_kid: &str,
        storage_key: &[u8; 32],
    ) -> Result<Self> {
        if !crate::memory::crypto::valid_kid(storage_kid) {
            bail!("storage key id must be 8 lowercase hex characters");
        }
        let cipher = XChaCha20Poly1305::new(Key::from_slice(storage_key));
        let nonce = XChaCha20Poly1305::generate_nonce(&mut OsRng);
        let plain = keys.sealed_plaintext()?;
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: &plain,
                    aad: &device_keys_aad(device_id, storage_kid),
                },
            )
            .map_err(|_| anyhow!("could not seal the device keys"))?;
        Ok(Self {
            version: 1,
            device_id: device_id.into(),
            storage_kid: storage_kid.into(),
            nonce: STANDARD.encode(nonce),
            ciphertext: STANDARD.encode(ciphertext),
        })
    }

    pub fn open(&self, storage_key: &[u8; 32], unlock_auth: UnlockAuthKey) -> Result<DeviceKeys> {
        if self.version != 1 {
            bail!("unsupported device_keys.sealed version {}", self.version);
        }
        let nonce = STANDARD
            .decode(&self.nonce)
            .context("device_keys.sealed nonce is not base64")?;
        if nonce.len() != 24 {
            bail!("device_keys.sealed nonce has the wrong length");
        }
        let ciphertext = STANDARD
            .decode(&self.ciphertext)
            .context("device_keys.sealed ciphertext is not base64")?;
        let cipher = XChaCha20Poly1305::new(Key::from_slice(storage_key));
        let plain = Zeroizing::new(
            cipher
                .decrypt(
                    XNonce::from_slice(&nonce),
                    Payload {
                        msg: &ciphertext,
                        aad: &device_keys_aad(&self.device_id, &self.storage_kid),
                    },
                )
                .map_err(|_| {
                    anyhow!(
                        "the storage key doesn't open device_keys.sealed (wrong key, or the file was changed)"
                    )
                })?,
        );
        DeviceKeys::from_sealed_plaintext(&plain, unlock_auth)
    }

    pub fn load_from(path: &Path) -> Result<Option<Self>> {
        let raw = match std::fs::read(path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        Ok(Some(serde_json::from_slice(&raw).with_context(|| {
            format!("{} is unreadable", path.display())
        })?))
    }

    pub fn save_to(&self, path: &Path) -> Result<()> {
        crate::memory::crypto::write_private(path, &serde_json::to_vec_pretty(self)?)
    }
}

/// Moves `device_keys.sealed.next` over `device_keys.sealed` and syncs the
/// directory, so the rename survives a crash.
pub fn promote_next(next: &Path, sealed: &Path) -> Result<()> {
    std::fs::rename(next, sealed)?;
    #[cfg(unix)]
    if let Some(parent) = sealed
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

/// Astation's reply to an unlock request: the storage key sealed to the
/// request's `e_pub`, and the signed `atem-unlock-grant-v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnlockGrantWire {
    pub grant: SignedWire,
    pub encapped_key: String,
    pub ciphertext: String,
}

/// An unlock grant that checked out against the pins: the signed
/// statement, the request hash it answers, and the decoded HPKE seal.
pub struct CheckedGrant {
    pub grant: UnlockGrant,
    pub request_hash: [u8; 32],
    pub encapped: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Checks an `atem-unlock-grant-v1` against the home Astation's `pins` and
/// the request statement bytes it must answer. The one check both the key
/// agent (before it opens the seal) and the CLI (before it spends the
/// agent's single-use key on a reply) run.
pub fn check_unlock_grant(
    pins: &AstationTrust,
    request_bytes: &[u8],
    grant: &UnlockGrantWire,
) -> Result<CheckedGrant> {
    let request_hash = unlock_request_hash(request_bytes);
    let sign_pub = STANDARD.decode(&pins.astation_sign_pub)?;
    let granted = UnlockGrant::parse(&verify_astation(&sign_pub, &grant.grant)?)?;
    if granted.account != pins.data_account {
        bail!("unlock grant is for a different account");
    }
    if granted.sign_gen != pins.sign_gen {
        bail!("unlock grant is signed by a different signing-key generation");
    }
    if granted.device_id != pins.device_id {
        bail!("unlock grant is for a different device");
    }
    if granted.request_hash != request_hash {
        bail!("unlock grant answers a different request");
    }
    if !crate::memory::crypto::valid_kid(&granted.storage_kid) {
        bail!("unlock grant has an invalid storage key id");
    }
    // Astation releases the key the request names, nothing else.
    let requested = UnlockRequest::parse(&dec(request_bytes)?)?;
    if granted.storage_kid != requested.storage_kid {
        bail!(
            "unlock grant releases a different storage key ({}) than the request names ({})",
            granted.storage_kid,
            requested.storage_kid
        );
    }
    let encapped = STANDARD
        .decode(&grant.encapped_key)
        .context("unlock grant key encapsulation is not base64")?;
    let ciphertext = STANDARD
        .decode(&grant.ciphertext)
        .context("unlock grant ciphertext is not base64")?;
    if sealed_hash(&encapped, &ciphertext) != granted.sealed_hash {
        bail!("unlock grant does not match what Astation signed");
    }
    Ok(CheckedGrant {
        grant: granted,
        request_hash,
        encapped,
        ciphertext,
    })
}

/// Checks an `atem-storage-ack-v1` against the home Astation's `pins`: it
/// must acknowledge exactly `storage_kid`. Shared by the agent and the CLI.
pub fn check_storage_ack(pins: &AstationTrust, storage_kid: &str, ack: &SignedWire) -> Result<()> {
    let sign_pub = STANDARD.decode(&pins.astation_sign_pub)?;
    let acked = StorageAck::parse(&verify_astation(&sign_pub, ack)?)?;
    if acked.account != pins.data_account
        || acked.sign_gen != pins.sign_gen
        || acked.device_id != pins.device_id
        || acked.storage_kid != storage_kid
    {
        bail!("Astation's acknowledgement is for a different storage key");
    }
    Ok(())
}

/// A storage key for Astation: sealed to its encryption key, with the
/// device-signed `atem-storage-rotate-v1`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StorageRotation {
    pub rotate: SignedWire,
    pub encapped_key: String,
    pub ciphertext: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::crypto::valid_kid;

    fn sealed(keys: &DeviceKeys, key: &[u8; 32]) -> SealedDeviceKeys {
        SealedDeviceKeys::seal(keys, "dev-1", "0a1b2c3d", key).unwrap()
    }

    #[test]
    fn sealed_keys_open_with_the_storage_key_only() {
        let keys = DeviceKeys::generate();
        let storage_key = new_storage_key();
        let file = sealed(&keys, &storage_key);
        assert_eq!(
            (
                file.version,
                file.device_id.as_str(),
                file.storage_kid.as_str()
            ),
            (1, "dev-1", "0a1b2c3d")
        );
        let opened = file.open(&storage_key, keys.unlock_auth_key()).unwrap();
        assert_eq!(opened.device_pub(), keys.device_pub());
        assert_eq!(opened.device_sign_pub(), keys.device_sign_pub());
        assert_eq!(opened.unlock_auth_pub(), keys.unlock_auth_pub());
        assert!(
            file.open(&new_storage_key(), keys.unlock_auth_key())
                .is_err()
        );
    }

    #[test]
    fn header_and_ciphertext_are_bound() {
        let keys = DeviceKeys::generate();
        let storage_key = new_storage_key();
        let file = sealed(&keys, &storage_key);
        let mut other_kid = file.clone();
        other_kid.storage_kid = "4e5f6a7b".into();
        assert!(
            other_kid
                .open(&storage_key, keys.unlock_auth_key())
                .is_err()
        );
        let mut other_device = file.clone();
        other_device.device_id = "dev-2".into();
        assert!(
            other_device
                .open(&storage_key, keys.unlock_auth_key())
                .is_err()
        );
        let mut tampered = file.clone();
        let mut bytes = STANDARD.decode(&tampered.ciphertext).unwrap();
        bytes[0] ^= 1;
        tampered.ciphertext = STANDARD.encode(bytes);
        assert!(tampered.open(&storage_key, keys.unlock_auth_key()).is_err());
    }

    #[test]
    fn file_round_trips_0600_and_promotes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device_keys.sealed");
        let next = dir.path().join("device_keys.sealed.next");
        assert!(SealedDeviceKeys::load_from(&path).unwrap().is_none());
        let file = sealed(&DeviceKeys::generate(), &new_storage_key());
        file.save_to(&next).unwrap();
        promote_next(&next, &path).unwrap();
        assert!(!next.exists());
        assert_eq!(SealedDeviceKeys::load_from(&path).unwrap().unwrap(), file);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn storage_kids_and_keys_are_fresh() {
        let (first, second) = (new_storage_kid(), new_storage_kid());
        assert!(valid_kid(&first) && valid_kid(&second));
        assert_ne!(first, second);
        assert_ne!(*new_storage_key(), *new_storage_key());
        let bad =
            SealedDeviceKeys::seal(&DeviceKeys::generate(), "dev-1", "XYZ", &new_storage_key());
        assert!(bad.is_err());
    }

    #[test]
    fn aad_binds_label_device_and_kid() {
        assert_eq!(
            device_keys_aad("dev-1", "0a1b2c3d"),
            crate::memory::encoding::enc(&[b"atem-device-keys-v1", b"dev-1", b"0a1b2c3d"])
        );
    }
}

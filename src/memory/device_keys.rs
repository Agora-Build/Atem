//! The device's own keys, created fresh at verification: X25519 to open keys
//! sealed to this device, Ed25519 to sign its writes, Ed25519 to sign unlock
//! requests. The first two are sealed in `device_keys.sealed` (see
//! storage_key.rs); the unlock-auth key sits in its own 0600 file because it
//! must work while the others are locked.
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::Path;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

use crate::memory::statements::SignedWire;

pub struct DeviceKeys {
    device: StaticSecret,
    device_sign: SigningKey,
    unlock_auth: SigningKey,
}

#[derive(Serialize, Deserialize)]
struct StoredDeviceKeys {
    version: u8,
    device: String,
    device_sign: String,
    unlock_auth: String,
}

fn decode32(value: &str, what: &str) -> Result<[u8; 32]> {
    STANDARD
        .decode(value)
        .with_context(|| format!("{what} is not base64"))?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what} has the wrong length"))
}

impl DeviceKeys {
    pub fn generate() -> Self {
        Self {
            device: StaticSecret::random_from_rng(OsRng),
            device_sign: SigningKey::generate(&mut OsRng),
            unlock_auth: SigningKey::generate(&mut OsRng),
        }
    }

    /// Keys from raw secrets: known-answer tests, and the key agent taking
    /// keys handed over at verification.
    pub(crate) fn from_secrets(
        device: [u8; 32],
        device_sign: [u8; 32],
        unlock_auth: [u8; 32],
    ) -> Self {
        Self {
            device: StaticSecret::from(device),
            device_sign: SigningKey::from_bytes(&device_sign),
            unlock_auth: SigningKey::from_bytes(&unlock_auth),
        }
    }

    pub fn device_pub(&self) -> [u8; 32] {
        PublicKey::from(&self.device).to_bytes()
    }

    pub fn device_sign_pub(&self) -> [u8; 32] {
        self.device_sign.verifying_key().to_bytes()
    }

    pub fn unlock_auth_pub(&self) -> [u8; 32] {
        self.unlock_auth.verifying_key().to_bytes()
    }

    pub fn device_secret_bytes(&self) -> [u8; 32] {
        self.device.to_bytes()
    }

    pub fn unlock_auth_key(&self) -> UnlockAuthKey {
        UnlockAuthKey {
            key: self.unlock_auth.clone(),
        }
    }

    /// Signs `statement` with the device signing key.
    pub fn sign_statement(&self, statement: &[u8]) -> SignedWire {
        signed_wire(&self.device_sign, statement)
    }

    /// The three secrets, for handing unlocked keys to the key agent.
    pub(crate) fn secret_parts(
        &self,
    ) -> (
        Zeroizing<[u8; 32]>,
        Zeroizing<[u8; 32]>,
        Zeroizing<[u8; 32]>,
    ) {
        (
            Zeroizing::new(self.device.to_bytes()),
            Zeroizing::new(self.device_sign.to_bytes()),
            Zeroizing::new(self.unlock_auth.to_bytes()),
        )
    }

    /// The device key and device signing key, serialized for
    /// `device_keys.sealed`. The unlock-auth key is not included.
    pub fn sealed_plaintext(&self) -> Result<Zeroizing<Vec<u8>>> {
        let device = Zeroizing::new(STANDARD.encode(self.device.to_bytes()));
        let device_sign = Zeroizing::new(STANDARD.encode(self.device_sign.to_bytes()));
        Ok(Zeroizing::new(serde_json::to_vec(&SealedPlainRef {
            version: 1,
            device: &device,
            device_sign: &device_sign,
        })?))
    }

    pub fn from_sealed_plaintext(plain: &[u8], unlock_auth: UnlockAuthKey) -> Result<Self> {
        let SealedPlain {
            version,
            device,
            device_sign,
        } = serde_json::from_slice(plain).context("sealed device keys are unreadable")?;
        let (device, device_sign) = (Zeroizing::new(device), Zeroizing::new(device_sign));
        if version != 1 {
            bail!("unsupported sealed device keys version {version}");
        }
        Ok(Self {
            device: StaticSecret::from(decode32(&device, "device key")?),
            device_sign: SigningKey::from_bytes(&decode32(&device_sign, "device signing key")?),
            unlock_auth: unlock_auth.key,
        })
    }

    pub fn load_from(path: &Path) -> Result<Option<Self>> {
        let raw = match std::fs::read(path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let stored: StoredDeviceKeys =
            serde_json::from_slice(&raw).context("device_keys is unreadable")?;
        if stored.version != 1 {
            bail!("unsupported device_keys version {}", stored.version);
        }
        Ok(Some(Self {
            device: StaticSecret::from(decode32(&stored.device, "device key")?),
            device_sign: SigningKey::from_bytes(&decode32(
                &stored.device_sign,
                "device signing key",
            )?),
            unlock_auth: SigningKey::from_bytes(&decode32(&stored.unlock_auth, "unlock-auth key")?),
        }))
    }

    pub fn save_to(&self, path: &Path) -> Result<()> {
        let stored = StoredDeviceKeys {
            version: 1,
            device: STANDARD.encode(self.device.to_bytes()),
            device_sign: STANDARD.encode(self.device_sign.to_bytes()),
            unlock_auth: STANDARD.encode(self.unlock_auth.to_bytes()),
        };
        crate::memory::crypto::write_private(path, &serde_json::to_vec(&stored)?)
    }
}

#[derive(Serialize)]
struct SealedPlainRef<'a> {
    version: u8,
    device: &'a str,
    device_sign: &'a str,
}

#[derive(Deserialize)]
struct SealedPlain {
    version: u8,
    device: String,
    device_sign: String,
}

/// Signs `statement` with an Ed25519 key; carried like Astation's statements.
fn signed_wire(key: &SigningKey, statement: &[u8]) -> SignedWire {
    use ed25519_dalek::Signer;
    SignedWire {
        statement: STANDARD.encode(statement),
        signature: STANDARD.encode(key.sign(statement).to_bytes()),
    }
}

/// Signs unlock requests while the other two keys are sealed. Unsealed on
/// disk (0600): it can only ask Astation for an unlock; Astation decides.
pub struct UnlockAuthKey {
    key: SigningKey,
}

#[derive(Serialize, Deserialize)]
struct StoredUnlockAuth {
    version: u8,
    unlock_auth: String,
}

impl UnlockAuthKey {
    pub fn public(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }

    pub fn sign_statement(&self, statement: &[u8]) -> SignedWire {
        signed_wire(&self.key, statement)
    }

    pub fn load_from(path: &Path) -> Result<Option<Self>> {
        let raw = match std::fs::read(path) {
            Ok(raw) => Zeroizing::new(raw),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let stored: StoredUnlockAuth =
            serde_json::from_slice(&raw).context("unlock_auth_key is unreadable")?;
        let encoded = Zeroizing::new(stored.unlock_auth);
        if stored.version != 1 {
            bail!("unsupported unlock_auth_key version {}", stored.version);
        }
        let secret = Zeroizing::new(decode32(&encoded, "unlock-auth key")?);
        Ok(Some(Self {
            key: SigningKey::from_bytes(&secret),
        }))
    }

    pub fn save_to(&self, path: &Path) -> Result<()> {
        let stored = StoredUnlockAuth {
            version: 1,
            unlock_auth: STANDARD.encode(self.key.to_bytes()),
        };
        let bytes = Zeroizing::new(serde_json::to_vec(&stored)?);
        let _wipe = Zeroizing::new(stored.unlock_auth);
        crate::memory::crypto::write_private(path, &bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_distinct_and_survive_a_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("device_keys");
        assert!(DeviceKeys::load_from(&path).unwrap().is_none());
        let keys = DeviceKeys::generate();
        assert_ne!(keys.device_sign_pub(), keys.unlock_auth_pub());
        keys.save_to(&path).unwrap();
        let loaded = DeviceKeys::load_from(&path).unwrap().unwrap();
        assert_eq!(loaded.device_pub(), keys.device_pub());
        assert_eq!(loaded.device_sign_pub(), keys.device_sign_pub());
        assert_eq!(loaded.unlock_auth_pub(), keys.unlock_auth_pub());
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
    fn two_generations_differ() {
        assert_ne!(
            DeviceKeys::generate().device_pub(),
            DeviceKeys::generate().device_pub()
        );
    }

    #[test]
    fn sealed_plaintext_holds_only_the_two_sealed_keys() {
        let keys = DeviceKeys::generate();
        let plain = keys.sealed_plaintext().unwrap();
        let json: serde_json::Value = serde_json::from_slice(&plain).unwrap();
        let mut fields: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        fields.sort();
        assert_eq!(fields, ["device", "device_sign", "version"]);
        let back = DeviceKeys::from_sealed_plaintext(&plain, keys.unlock_auth_key()).unwrap();
        assert_eq!(back.device_pub(), keys.device_pub());
        assert_eq!(back.device_sign_pub(), keys.device_sign_pub());
        assert_eq!(back.unlock_auth_pub(), keys.unlock_auth_pub());
        assert!(DeviceKeys::from_sealed_plaintext(b"{}", keys.unlock_auth_key()).is_err());
    }

    #[test]
    fn unlock_auth_key_round_trips_as_its_own_0600_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unlock_auth_key");
        assert!(UnlockAuthKey::load_from(&path).unwrap().is_none());
        let keys = DeviceKeys::generate();
        keys.unlock_auth_key().save_to(&path).unwrap();
        let loaded = UnlockAuthKey::load_from(&path).unwrap().unwrap();
        assert_eq!(loaded.public(), keys.unlock_auth_pub());
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
    fn statements_are_signed_with_the_right_key() {
        use ed25519_dalek::{Signature, VerifyingKey};
        let keys = DeviceKeys::generate();
        let check = |public: [u8; 32], signed: &SignedWire| {
            let raw: [u8; 64] = STANDARD
                .decode(&signed.signature)
                .unwrap()
                .try_into()
                .unwrap();
            VerifyingKey::from_bytes(&public)
                .unwrap()
                .verify_strict(b"statement", &Signature::from_bytes(&raw))
                .is_ok()
        };
        let by_device = keys.sign_statement(b"statement");
        assert_eq!(STANDARD.decode(&by_device.statement).unwrap(), b"statement");
        assert!(check(keys.device_sign_pub(), &by_device));
        assert!(!check(keys.unlock_auth_pub(), &by_device));
        let by_unlock_auth = keys.unlock_auth_key().sign_statement(b"statement");
        assert!(check(keys.unlock_auth_pub(), &by_unlock_auth));
    }
}

//! The device's own keys, created fresh at verification: X25519 to open keys
//! sealed to this device, Ed25519 to sign its writes, Ed25519 to sign unlock
//! requests. Build step 2 seals the first two behind the storage key; until
//! then the file is plain and 0600.
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use x25519_dalek::{PublicKey, StaticSecret};

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

pub fn device_keys_path() -> PathBuf {
    crate::config::AtemConfig::config_dir().join("device_keys")
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
}

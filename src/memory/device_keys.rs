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

use crate::memory::account_keys::{AccountKeys, AccountKeysWire};
use crate::memory::statements::SignedWire;

pub struct DeviceKeys {
    device: StaticSecret,
    device_sign: SigningKey,
    unlock_auth: SigningKey,
}

/// The three public keys a device reveals at verification.
pub trait PublicKeys {
    fn device_pub(&self) -> [u8; 32];
    fn device_sign_pub(&self) -> [u8; 32];
    fn unlock_auth_pub(&self) -> [u8; 32];
}

/// Public keys of a device whose secrets stay sealed (or in the key agent).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DevicePublics {
    pub device_pub: [u8; 32],
    pub device_sign_pub: [u8; 32],
    pub unlock_auth_pub: [u8; 32],
}

impl PublicKeys for DevicePublics {
    fn device_pub(&self) -> [u8; 32] {
        self.device_pub
    }
    fn device_sign_pub(&self) -> [u8; 32] {
        self.device_sign_pub
    }
    fn unlock_auth_pub(&self) -> [u8; 32] {
        self.unlock_auth_pub
    }
}

impl PublicKeys for DeviceKeys {
    fn device_pub(&self) -> [u8; 32] {
        DeviceKeys::device_pub(self)
    }
    fn device_sign_pub(&self) -> [u8; 32] {
        DeviceKeys::device_sign_pub(self)
    }
    fn unlock_auth_pub(&self) -> [u8; 32] {
        DeviceKeys::unlock_auth_pub(self)
    }
}

/// The device key, device signing key and unlock-auth key secrets, wiped
/// when dropped.
pub(crate) type SecretParts = (
    Zeroizing<[u8; 32]>,
    Zeroizing<[u8; 32]>,
    Zeroizing<[u8; 32]>,
);

#[derive(Deserialize)]
struct StoredDeviceKeys {
    version: u8,
    device: Zeroizing<String>,
    device_sign: Zeroizing<String>,
    unlock_auth: Zeroizing<String>,
}

#[derive(Serialize)]
struct StoredDeviceKeysRef<'a> {
    version: u8,
    device: &'a str,
    device_sign: &'a str,
    unlock_auth: &'a str,
}

/// Decodes a base64 32-byte secret; the buffers are wiped when dropped.
pub(crate) fn decode32(value: &str, what: &str) -> Result<Zeroizing<[u8; 32]>> {
    let raw = Zeroizing::new(
        STANDARD
            .decode(value)
            .with_context(|| format!("{what} is not base64"))?,
    );
    let bytes: [u8; 32] = raw
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("{what} has the wrong length"))?;
    Ok(Zeroizing::new(bytes))
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
    pub(crate) fn secret_parts(&self) -> SecretParts {
        (
            Zeroizing::new(self.device.to_bytes()),
            Zeroizing::new(self.device_sign.to_bytes()),
            Zeroizing::new(self.unlock_auth.to_bytes()),
        )
    }

    /// The device key and device signing key, serialized for
    /// `device_keys.sealed`. The unlock-auth key is not included.
    #[cfg(test)]
    pub fn sealed_plaintext(&self) -> Result<Zeroizing<Vec<u8>>> {
        self.sealed_plaintext_with(&AccountKeys::default())
    }

    /// Like `sealed_plaintext`, plus the account keys (`K` and the keys it
    /// replaced, build step 2b). With none the bytes are exactly step 2a's
    /// (version 1); with keys the payload is version 2, so a step-2a binary
    /// refuses the file instead of silently dropping the keys.
    pub fn sealed_plaintext_with(&self, accounts: &AccountKeys) -> Result<Zeroizing<Vec<u8>>> {
        let device = Zeroizing::new(STANDARD.encode(self.device.to_bytes()));
        let device_sign = Zeroizing::new(STANDARD.encode(self.device_sign.to_bytes()));
        let account_keys = (!accounts.is_empty()).then(|| accounts.to_wire());
        Ok(Zeroizing::new(serde_json::to_vec(&SealedPlainRef {
            version: if account_keys.is_some() { 2 } else { 1 },
            device: &device,
            device_sign: &device_sign,
            account_keys: account_keys.as_ref(),
        })?))
    }

    #[cfg(test)]
    pub fn from_sealed_plaintext(plain: &[u8], unlock_auth: UnlockAuthKey) -> Result<Self> {
        Self::from_sealed_plaintext_with(plain, unlock_auth).map(|(keys, _)| keys)
    }

    /// The device keys and the account keys of a sealed payload (none in a
    /// step-2a file).
    pub fn from_sealed_plaintext_with(
        plain: &[u8],
        unlock_auth: UnlockAuthKey,
    ) -> Result<(Self, AccountKeys)> {
        let SealedPlain {
            version,
            device,
            device_sign,
            account_keys,
        } = serde_json::from_slice(plain).context("sealed device keys are unreadable")?;
        let (device, device_sign) = (Zeroizing::new(device), Zeroizing::new(device_sign));
        if version != 1 && version != 2 {
            bail!("unsupported sealed device keys version {version}");
        }
        let accounts = AccountKeys::from_wire(account_keys)?;
        Ok((
            Self {
                device: StaticSecret::from(*decode32(&device, "device key")?),
                device_sign: SigningKey::from_bytes(&*decode32(
                    &device_sign,
                    "device signing key",
                )?),
                unlock_auth: unlock_auth.key,
            },
            accounts,
        ))
    }

    pub fn load_from(path: &Path) -> Result<Option<Self>> {
        let raw = match std::fs::read(path) {
            Ok(raw) => Zeroizing::new(raw),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        let stored: StoredDeviceKeys =
            serde_json::from_slice(&raw).context("device_keys is unreadable")?;
        if stored.version != 1 {
            bail!("unsupported device_keys version {}", stored.version);
        }
        Ok(Some(Self {
            device: StaticSecret::from(*decode32(&stored.device, "device key")?),
            device_sign: SigningKey::from_bytes(&*decode32(
                &stored.device_sign,
                "device signing key",
            )?),
            unlock_auth: SigningKey::from_bytes(&*decode32(
                &stored.unlock_auth,
                "unlock-auth key",
            )?),
        }))
    }

    /// The plain `device_keys` file (0600, written atomically): a fresh
    /// device's keys until Astation is known to hold the storage key, like a
    /// step-1 device's. The key agent re-seals it at each start while it
    /// exists and deletes it at the first confirmed escrow (key_agent.rs).
    pub fn save_to(&self, path: &Path) -> Result<()> {
        let (device, device_sign, unlock_auth) = self.secret_parts();
        let (device, device_sign, unlock_auth) = (
            Zeroizing::new(STANDARD.encode(&device[..])),
            Zeroizing::new(STANDARD.encode(&device_sign[..])),
            Zeroizing::new(STANDARD.encode(&unlock_auth[..])),
        );
        let bytes = Zeroizing::new(serde_json::to_vec(&StoredDeviceKeysRef {
            version: 1,
            device: &device,
            device_sign: &device_sign,
            unlock_auth: &unlock_auth,
        })?);
        crate::memory::crypto::write_private(path, &bytes)
    }
}

#[derive(Serialize)]
struct SealedPlainRef<'a> {
    version: u8,
    device: &'a str,
    device_sign: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    account_keys: Option<&'a AccountKeysWire>,
}

#[derive(Deserialize)]
struct SealedPlain {
    version: u8,
    device: String,
    device_sign: String,
    #[serde(default)]
    account_keys: AccountKeysWire,
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
        let secret = decode32(&encoded, "unlock-auth key")?;
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
    fn account_keys_add_one_field_to_the_sealed_plaintext() {
        use crate::memory::account_keys::AccountKeys;
        let keys = DeviceKeys::generate();
        let mut accounts = AccountKeys::default();
        accounts.install("acct", "0123abcd", Zeroizing::new([1; 32]));
        let plain = keys.sealed_plaintext_with(&accounts).unwrap();
        let json: serde_json::Value = serde_json::from_slice(&plain).unwrap();
        let mut fields: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        fields.sort();
        assert_eq!(fields, ["account_keys", "device", "device_sign", "version"]);
        assert_eq!(json["version"], 2);
        assert_eq!(json["account_keys"]["acct"]["kid"], "0123abcd");
        let (back, held) =
            DeviceKeys::from_sealed_plaintext_with(&plain, keys.unlock_auth_key()).unwrap();
        assert_eq!(back.device_pub(), keys.device_pub());
        assert_eq!(held.current_kid("acct"), Some("0123abcd"));
        // No account keys: exactly the bytes of step 2a (version 1).
        let none = keys.sealed_plaintext_with(&AccountKeys::default()).unwrap();
        assert_eq!(*none, *keys.sealed_plaintext().unwrap());
        let json: serde_json::Value = serde_json::from_slice(&none).unwrap();
        assert_eq!(json["version"], 1);
        // A v1 file opens with no account keys.
        let (_, held) =
            DeviceKeys::from_sealed_plaintext_with(&none, keys.unlock_auth_key()).unwrap();
        assert!(held.is_empty());
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

//! Device verification: commit-then-reveal, a 12-character safety code both
//! sides show, then applying what a verified Astation sends.
//! See designs/e2e-encryption.md "Devices → Verification".
use anyhow::{Context, Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::path::{Path, PathBuf};

use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::memory::crypto::EncryptionContext;
use crate::memory::device_keys::DeviceKeys;
use crate::memory::encoding::{base32_prefix, enc};
use crate::memory::grant::{GrantWire, open_grant};
use crate::memory::statements::{AccountState, SignedWire};
use crate::memory::trust::TrustStore;

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

/// Every file verification reads or writes. Tests point these at a temp dir.
pub struct KeyPaths {
    pub data_keys: PathBuf,
    pub trust: PathBuf,
    pub device_keys: PathBuf,
    /// The plain X25519 key from #36; deleted once a device is verified.
    pub legacy_device_key: PathBuf,
}

impl KeyPaths {
    pub fn default_paths() -> Self {
        Self::in_dir(&crate::config::AtemConfig::config_dir())
    }

    pub fn in_dir(dir: &Path) -> Self {
        Self {
            data_keys: dir.join("data_keys.enc"),
            trust: dir.join("cred_state.json"),
            device_keys: dir.join("device_keys"),
            legacy_device_key: dir.join("device_key"),
        }
    }
}

#[derive(Debug)]
pub enum Applied {
    Ignored(&'static str),
    Unchanged,
    ModeChanged(AccountState),
    KeyInstalled(String),
}

/// Applies a signed account state from a verified Astation. Unsigned states,
/// and any state for a device that isn't verified, are ignored.
pub fn apply_account_state(
    paths: &KeyPaths,
    astation_id: &str,
    signed: Option<&SignedWire>,
) -> Result<Applied> {
    let Some(signed) = signed else {
        return Ok(Applied::Ignored("an unsigned encryption mode from the relay"));
    };
    let mut trust = TrustStore::load_from(&paths.trust)?;
    if trust.verified(astation_id).is_none() {
        return Ok(Applied::Ignored(
            "an encryption mode for a device that isn't verified",
        ));
    }
    let Some(state) = trust.accept_account_state(astation_id, signed)? else {
        return Ok(Applied::Unchanged);
    };
    // Checked before anything is saved: an invalid kid leaves the trust store
    // and data_keys untouched.
    if let Some(kid) = state.kid.as_deref()
        && !crate::memory::crypto::valid_kid(kid)
    {
        return Err(anyhow!("signed account state has an invalid key id"));
    }
    EncryptionContext::update_mode_at(
        &paths.data_keys,
        astation_id,
        &state.account,
        state.mode,
        state.kid.as_deref(),
    )?;
    trust.save_to(&paths.trust)?;
    Ok(Applied::ModeChanged(state))
}

/// Installs a signed `K` grant for this verified device.
pub fn apply_grant(
    paths: &KeyPaths,
    astation_id: &str,
    grant: Option<&GrantWire>,
) -> Result<Applied> {
    let Some(grant) = grant else {
        return Ok(Applied::Ignored("an unsigned key grant from the relay"));
    };
    let trust = TrustStore::load_from(&paths.trust)?;
    let Some(entry) = trust.verified(astation_id) else {
        return Ok(Applied::Ignored(
            "a key grant for a device that isn't verified",
        ));
    };
    let keys = DeviceKeys::load_from(&paths.device_keys)?.ok_or_else(|| {
        anyhow!("this device's keys are missing; run 'atem pair' to verify it again")
    })?;
    let opened = open_grant(entry, &keys, grant)?;
    EncryptionContext::install_grant_at(
        &paths.data_keys,
        astation_id,
        &entry.data_account,
        &opened.kid,
        opened.key,
    )?;
    Ok(Applied::KeyInstalled(opened.kid))
}

/// Finishes verification once the user confirmed the code on this device and
/// Astation sent its signed certificate: pins become final, the fresh device
/// keys are saved, the old plain key is deleted, and the signed state and
/// grants are applied.
pub fn complete_verification(
    paths: &KeyPaths,
    astation_id: &str,
    keys: DeviceKeys,
    device_verified: &SignedWire,
    account_state: &SignedWire,
    grants: &[GrantWire],
) -> Result<()> {
    let mut trust = TrustStore::load_from(&paths.trust)?;
    trust.confirm(astation_id, device_verified)?;
    keys.save_to(&paths.device_keys)?;
    trust.save_to(&paths.trust)?;
    match std::fs::remove_file(&paths.legacy_device_key) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    apply_account_state(paths, astation_id, Some(account_state))?;
    for grant in grants {
        apply_grant(paths, astation_id, Some(grant))?;
    }
    Ok(())
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

    use crate::memory::crypto::{EncryptionContext, EncryptionMode};
    use crate::memory::grant::seal_k_grant;
    use crate::memory::statements::{AccountState, DeviceVerified, FakeAstation};
    use crate::memory::trust::TrustStore;

    const ASTATION_ID: &str = "astation-1";

    fn signed_state(fake: &FakeAstation, mode: EncryptionMode, epoch: u64) -> crate::memory::statements::SignedWire {
        fake.sign(&AccountState { account: "acct".into(), sign_gen: 1, mode, kid: Some("0123abcd".into()), epoch }.encode())
    }

    /// Runs the atem side of verification against a fake Astation and returns
    /// the paths, the fake, and the device public key.
    fn verify(dir: &std::path::Path, mode: EncryptionMode) -> (KeyPaths, FakeAstation, [u8; 32]) {
        let paths = KeyPaths::in_dir(dir);
        std::fs::write(&paths.legacy_device_key, [1u8; 32]).unwrap();
        let fake = FakeAstation::new();
        let handshake = Handshake::start(DeviceKeys::generate());
        let astation = AstationKeys { sign_pub: fake.sign_pub(), enc_pub: [5; 32], recovery_sign_pub: [6; 32], nonce_s: [7; 32] };
        let code = handshake.safety_code(&astation);
        let mut trust = TrustStore::default();
        trust.set_pending(ASTATION_ID, "dev-1", handshake.keys(), &astation, &code);
        trust.save_to(&paths.trust).unwrap();
        let reveal = handshake.reveal();
        let certificate = DeviceVerified {
            account: "acct".into(), sign_gen: 1, device_id: "dev-1".into(),
            device_pub: reveal.device_pub, device_sign_pub: reveal.device_sign_pub,
            unlock_auth_pub: reveal.unlock_auth_pub, epoch: 1,
        };
        let grants = if mode.requires_key() {
            vec![seal_k_grant(&fake, "acct", "dev-1", reveal.device_pub, "0123abcd", [42; 32])]
        } else {
            vec![]
        };
        complete_verification(&paths, ASTATION_ID, handshake.into_keys(), &fake.sign(&certificate.encode()), &signed_state(&fake, mode, 1), &grants).unwrap();
        (paths, fake, reveal.device_pub)
    }

    #[test]
    fn verification_installs_signed_state_and_key() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _, _) = verify(dir.path(), EncryptionMode::On);
        let context = EncryptionContext::for_astation_at(ASTATION_ID, &paths.data_keys).unwrap();
        assert_eq!(context.mode, EncryptionMode::On);
        assert!(context.seal("mem-1", "content", b"x").is_ok());
        assert!(!paths.legacy_device_key.exists(), "old plain device_key must be deleted");
        assert!(DeviceKeys::load_from(&paths.device_keys).unwrap().is_some());
    }

    #[test]
    fn unsigned_or_forged_mode_changes_are_ignored() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _, _) = verify(dir.path(), EncryptionMode::On);
        assert!(matches!(apply_account_state(&paths, ASTATION_ID, None).unwrap(), Applied::Ignored(_)));
        let forged = signed_state(&FakeAstation::new(), EncryptionMode::Off, 9);
        assert!(apply_account_state(&paths, ASTATION_ID, Some(&forged)).is_err());
        let context = EncryptionContext::for_astation_at(ASTATION_ID, &paths.data_keys).unwrap();
        assert_eq!(context.mode, EncryptionMode::On, "K and mode must survive");
    }

    #[test]
    fn signed_newer_state_is_applied() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, fake, _) = verify(dir.path(), EncryptionMode::On);
        let disabling = signed_state(&fake, EncryptionMode::Disabling, 2);
        assert!(matches!(apply_account_state(&paths, ASTATION_ID, Some(&disabling)).unwrap(), Applied::ModeChanged(_)));
        assert_eq!(EncryptionContext::for_astation_at(ASTATION_ID, &paths.data_keys).unwrap().mode, EncryptionMode::Disabling);
    }

    #[test]
    fn signed_state_with_invalid_kid_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, fake, _) = verify(dir.path(), EncryptionMode::On);
        let bad = fake.sign(&AccountState { account: "acct".into(), sign_gen: 1, mode: EncryptionMode::Disabling, kid: Some("XYZ".into()), epoch: 2 }.encode());
        assert!(apply_account_state(&paths, ASTATION_ID, Some(&bad)).is_err());
        assert_eq!(EncryptionContext::for_astation_at(ASTATION_ID, &paths.data_keys).unwrap().mode, EncryptionMode::On);
        let trust = TrustStore::load_from(&paths.trust).unwrap();
        assert_eq!(trust.verified(ASTATION_ID).unwrap().account_epoch, 1);
    }

    #[test]
    fn unverified_devices_ignore_everything() {
        let dir = tempfile::tempdir().unwrap();
        let paths = KeyPaths::in_dir(dir.path());
        let fake = FakeAstation::new();
        assert!(matches!(apply_account_state(&paths, ASTATION_ID, Some(&signed_state(&fake, EncryptionMode::Off, 1))).unwrap(), Applied::Ignored(_)));
        let grant = seal_k_grant(&fake, "acct", "dev-1", [9; 32], "0123abcd", [42; 32]);
        assert!(matches!(apply_grant(&paths, ASTATION_ID, Some(&grant)).unwrap(), Applied::Ignored(_)));
        assert_eq!(EncryptionContext::for_astation_at(ASTATION_ID, &paths.data_keys).unwrap().mode, EncryptionMode::Off);
    }

    #[test]
    fn verified_device_without_a_state_refuses_to_build_a_context() {
        let dir = tempfile::tempdir().unwrap();
        let (paths, _, _) = verify(dir.path(), EncryptionMode::Off);
        // Simulate a verified entry that never received a state: an Option
        // field missing from the JSON deserializes as None.
        let raw = std::fs::read_to_string(&paths.trust).unwrap().replace("\"account_state\": {", "\"account_state_was\": {");
        std::fs::write(&paths.trust, raw).unwrap();
        let trust = TrustStore::load_from(&paths.trust).unwrap();
        assert!(trust.verified(ASTATION_ID).unwrap().account_state.is_none());
        let error = EncryptionContext::for_astation_at(ASTATION_ID, &paths.data_keys).unwrap_err().to_string();
        assert!(error.contains("signed encryption state"), "{error}");
    }
}

//! What this device trusts about each Astation: the keys it pinned during
//! verification, the epoch floor, and the latest signed account state.
//! Pending entries are never trusted. Stored in `cred_state.json` (0600).
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::memory::device_keys::DeviceKeys;
use crate::memory::statements::{AccountState, DeviceVerified, SignedWire, verify_astation};
use crate::memory::verification::AstationKeys;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AstationTrust {
    pub device_id: String,
    /// Empty while pending; set from the device certificate.
    pub data_account: String,
    pub sign_gen: u64,
    pub astation_sign_pub: String,
    pub astation_enc_pub: String,
    pub recovery_sign_pub: String,
    pub device_pub: String,
    pub device_sign_pub: String,
    pub unlock_auth_pub: String,
    pub safety_code: String,
    /// Base64 `transcript_for(commitment, nonce_a, nonce_s)` of the ceremony
    /// that produced this entry; the certificate must carry the same value.
    #[serde(default)]
    pub transcript: String,
    pub epoch_floor: u64,
    pub account_state: Option<SignedWire>,
    pub account_epoch: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrustStore {
    #[serde(default = "store_version")]
    version: u8,
    #[serde(default)]
    astations: HashMap<String, AstationTrust>,
    #[serde(default)]
    pending: HashMap<String, AstationTrust>,
}

fn store_version() -> u8 {
    1
}

pub fn trust_path() -> PathBuf {
    crate::config::AtemConfig::config_dir().join("cred_state.json")
}

/// The trust store that sits next to a given `data_keys.enc`.
pub fn trust_path_for(data_keys_path: &Path) -> PathBuf {
    data_keys_path.with_file_name("cred_state.json")
}

impl TrustStore {
    pub fn load_from(path: &Path) -> Result<Self> {
        let raw = match std::fs::read(path) {
            Ok(raw) => raw,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default());
            }
            Err(error) => return Err(error.into()),
        };
        let store: Self = serde_json::from_slice(&raw).context("cred_state.json is unreadable")?;
        if store.version != 1 {
            bail!("unsupported cred_state.json version {}", store.version);
        }
        Ok(store)
    }

    pub fn save_to(&mut self, path: &Path) -> Result<()> {
        self.version = 1;
        crate::memory::crypto::write_private(path, &serde_json::to_vec_pretty(self)?)
    }

    pub fn verified(&self, astation_id: &str) -> Option<&AstationTrust> {
        self.astations.get(astation_id)
    }

    pub fn set_pending(
        &mut self,
        astation_id: &str,
        device_id: &str,
        keys: &DeviceKeys,
        astation: &AstationKeys,
        code: &str,
        transcript: &[u8; 32],
    ) {
        self.pending.insert(
            astation_id.into(),
            AstationTrust {
                device_id: device_id.into(),
                data_account: String::new(),
                sign_gen: 0,
                astation_sign_pub: STANDARD.encode(&astation.sign_pub),
                astation_enc_pub: STANDARD.encode(astation.enc_pub),
                recovery_sign_pub: STANDARD.encode(astation.recovery_sign_pub),
                device_pub: STANDARD.encode(keys.device_pub()),
                device_sign_pub: STANDARD.encode(keys.device_sign_pub()),
                unlock_auth_pub: STANDARD.encode(keys.unlock_auth_pub()),
                safety_code: code.into(),
                transcript: STANDARD.encode(transcript),
                epoch_floor: 0,
                account_state: None,
                account_epoch: 0,
            },
        );
    }

    pub fn remove_pending(&mut self, astation_id: &str) {
        self.pending.remove(astation_id);
    }

    /// Promotes the pending entry once Astation's signed certificate names
    /// exactly the keys this device revealed, in this ceremony.
    ///
    /// Re-verifying an Astation this device already trusts never moves it
    /// backwards: a certificate older than the applied account state is
    /// rejected, the epoch floor only rises, and the stored signed state is
    /// kept until a newer one arrives.
    pub fn confirm(&mut self, astation_id: &str, signed: &SignedWire) -> Result<DeviceVerified> {
        let entry = self
            .pending
            .get(astation_id)
            .ok_or_else(|| anyhow!("no device verification is in progress for this Astation"))?;
        let sign_pub = STANDARD.decode(&entry.astation_sign_pub)?;
        let certificate = DeviceVerified::parse(&verify_astation(&sign_pub, signed)?)?;
        if certificate.device_id != entry.device_id
            || STANDARD.encode(certificate.device_pub) != entry.device_pub
            || STANDARD.encode(certificate.device_sign_pub) != entry.device_sign_pub
            || STANDARD.encode(certificate.unlock_auth_pub) != entry.unlock_auth_pub
        {
            bail!("Astation's device certificate names different keys than this device revealed");
        }
        if entry.transcript.is_empty()
            || STANDARD.encode(certificate.transcript) != entry.transcript
        {
            bail!("Astation's device certificate is for a different verification attempt");
        }
        // The earlier verification with this Astation, when its epochs are
        // comparable with the new certificate's (same account and signer).
        let previous = self.astations.get(astation_id).filter(|previous| {
            previous.data_account == certificate.account
                && previous.sign_gen == certificate.sign_gen
                && previous.astation_sign_pub == entry.astation_sign_pub
        });
        if let Some(previous) = previous
            && certificate.epoch < previous.account_epoch
        {
            bail!(
                "Astation's device certificate is older than the state this device already applied"
            );
        }
        let kept = previous.map(|previous| {
            (
                previous
                    .epoch_floor
                    .max(previous.account_epoch)
                    .max(certificate.epoch),
                previous.account_state.clone(),
                previous.account_epoch,
            )
        });
        let mut entry = self.pending.remove(astation_id).expect("checked above");
        entry.data_account = certificate.account.clone();
        entry.sign_gen = certificate.sign_gen;
        entry.epoch_floor = certificate.epoch;
        if let Some((floor, state, epoch)) = kept {
            entry.epoch_floor = floor;
            entry.account_state = state;
            entry.account_epoch = epoch;
        }
        self.astations.insert(astation_id.into(), entry);
        Ok(certificate)
    }

    /// Accepts a newer signed account state. Returns `None` for a repeat of the
    /// current one, and an error for anything unsigned, stale or mismatched.
    pub fn accept_account_state(
        &mut self,
        astation_id: &str,
        signed: &SignedWire,
    ) -> Result<Option<AccountState>> {
        let entry = self
            .astations
            .get_mut(astation_id)
            .ok_or_else(|| anyhow!("this device isn't verified with this Astation"))?;
        let sign_pub = STANDARD.decode(&entry.astation_sign_pub)?;
        let state = AccountState::parse(&verify_astation(&sign_pub, signed)?)?;
        if state.account != entry.data_account {
            bail!("account state is for a different account");
        }
        if state.sign_gen != entry.sign_gen {
            bail!("account state is signed by a different signing-key generation");
        }
        if state.epoch < entry.epoch_floor {
            bail!("account state is older than this device's verification");
        }
        if entry.account_state.is_some() {
            if state.epoch < entry.account_epoch {
                bail!("account state is older than the one already applied");
            }
            if state.epoch == entry.account_epoch {
                // Same statement bytes, possibly a fresh signature (CryptoKit
                // signatures are randomized): a repeat, so keep the stored one.
                let stored = entry
                    .account_state
                    .as_ref()
                    .map(|stored| stored.statement.as_str());
                if stored == Some(signed.statement.as_str()) {
                    return Ok(None);
                }
                bail!("two different account states share epoch {}", state.epoch);
            }
        }
        entry.account_state = Some(signed.clone());
        entry.account_epoch = state.epoch;
        Ok(Some(state))
    }

    pub fn verification_line(&self, astation_id: &str) -> String {
        match self.verified(astation_id) {
            Some(trust) => format!("Verified: yes  (safety code {})", trust.safety_code),
            None => "Verified: no  (run 'atem pair' to verify this device)".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::crypto::EncryptionMode;
    use crate::memory::statements::FakeAstation;

    const ASTATION: &str = "astation-1";
    const TRANSCRIPT: [u8; 32] = [8; 32];

    fn pending(fake: &FakeAstation) -> (TrustStore, DeviceKeys) {
        let keys = DeviceKeys::generate();
        let astation = AstationKeys {
            sign_pub: fake.sign_pub(),
            enc_pub: [5; 32],
            recovery_sign_pub: [6; 32],
            nonce_s: [7; 32],
        };
        let mut store = TrustStore::default();
        store.set_pending(
            ASTATION,
            "dev-1",
            &keys,
            &astation,
            "AAAA-BBBB-CCCC",
            &TRANSCRIPT,
        );
        (store, keys)
    }

    fn certificate(keys: &DeviceKeys, epoch: u64) -> DeviceVerified {
        DeviceVerified {
            account: "acct".into(),
            sign_gen: 1,
            device_id: "dev-1".into(),
            device_pub: keys.device_pub(),
            device_sign_pub: keys.device_sign_pub(),
            unlock_auth_pub: keys.unlock_auth_pub(),
            transcript: TRANSCRIPT,
            epoch,
        }
    }

    fn state(mode: EncryptionMode, epoch: u64) -> AccountState {
        AccountState {
            account: "acct".into(),
            sign_gen: 1,
            mode,
            kid: Some("0123abcd".into()),
            epoch,
        }
    }

    #[test]
    fn pending_is_not_trusted_until_a_matching_certificate_arrives() {
        let fake = FakeAstation::new();
        let (mut store, keys) = pending(&fake);
        assert!(store.verified(ASTATION).is_none());
        store
            .confirm(ASTATION, &fake.sign(&certificate(&keys, 5).encode()))
            .unwrap();
        let trust = store.verified(ASTATION).unwrap();
        assert_eq!(
            (trust.data_account.as_str(), trust.epoch_floor),
            ("acct", 5)
        );
    }

    #[test]
    fn certificate_for_other_keys_or_signer_is_rejected() {
        let fake = FakeAstation::new();
        let (mut store, keys) = pending(&fake);
        let mut other = certificate(&keys, 5);
        other.device_pub = [9; 32];
        assert!(
            store
                .confirm(ASTATION, &fake.sign(&other.encode()))
                .is_err()
        );
        assert!(
            store
                .confirm(
                    ASTATION,
                    &FakeAstation::new().sign(&certificate(&keys, 5).encode())
                )
                .is_err()
        );
        assert!(store.verified(ASTATION).is_none());
    }

    #[test]
    fn account_state_needs_verification_floor_and_order() {
        let fake = FakeAstation::new();
        let (mut store, keys) = pending(&fake);
        assert!(
            store
                .accept_account_state(ASTATION, &fake.sign(&state(EncryptionMode::On, 6).encode()))
                .is_err()
        );
        store
            .confirm(ASTATION, &fake.sign(&certificate(&keys, 5).encode()))
            .unwrap();

        assert!(
            store
                .accept_account_state(ASTATION, &fake.sign(&state(EncryptionMode::On, 4).encode()))
                .is_err()
        );
        let on = fake.sign(&state(EncryptionMode::On, 6).encode());
        assert_eq!(
            store
                .accept_account_state(ASTATION, &on)
                .unwrap()
                .unwrap()
                .mode,
            EncryptionMode::On
        );
        assert!(store.accept_account_state(ASTATION, &on).unwrap().is_none());
        assert!(
            store
                .accept_account_state(
                    ASTATION,
                    &fake.sign(&state(EncryptionMode::Off, 6).encode())
                )
                .is_err()
        );
        assert!(
            store
                .accept_account_state(
                    ASTATION,
                    &fake.sign(&state(EncryptionMode::Off, 5).encode())
                )
                .is_err()
        );

        let mut wrong_account = state(EncryptionMode::Off, 7);
        wrong_account.account = "other".into();
        assert!(
            store
                .accept_account_state(ASTATION, &fake.sign(&wrong_account.encode()))
                .is_err()
        );
        let mut wrong_gen = state(EncryptionMode::Off, 7);
        wrong_gen.sign_gen = 2;
        assert!(
            store
                .accept_account_state(ASTATION, &fake.sign(&wrong_gen.encode()))
                .is_err()
        );
    }

    #[test]
    fn re_signed_same_state_at_same_epoch_is_a_repeat() {
        let fake = FakeAstation::new();
        let (mut store, keys) = pending(&fake);
        store
            .confirm(ASTATION, &fake.sign(&certificate(&keys, 5).encode()))
            .unwrap();
        let statement = state(EncryptionMode::On, 6).encode();
        let first = fake.sign(&statement);
        let second = fake.sign_randomized(&statement);
        assert_eq!(first.statement, second.statement);
        assert_ne!(first.signature, second.signature);
        assert!(
            store
                .accept_account_state(ASTATION, &first)
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .accept_account_state(ASTATION, &second)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store.verified(ASTATION).unwrap().account_state.as_ref(),
            Some(&first)
        );
    }

    #[test]
    fn certificate_from_another_ceremony_is_rejected() {
        let fake = FakeAstation::new();
        let (mut store, keys) = pending(&fake);
        let mut replayed = certificate(&keys, 5);
        replayed.transcript = [9; 32];
        let error = store
            .confirm(ASTATION, &fake.sign(&replayed.encode()))
            .unwrap_err()
            .to_string();
        assert!(error.contains("different verification attempt"), "{error}");
        assert!(store.verified(ASTATION).is_none());
    }

    /// Re-verifies `keys` with a fresh pending entry and a certificate at `epoch`.
    fn reverify(
        store: &mut TrustStore,
        fake: &FakeAstation,
        keys: &DeviceKeys,
        epoch: u64,
    ) -> Result<DeviceVerified> {
        let astation = AstationKeys {
            sign_pub: fake.sign_pub(),
            enc_pub: [5; 32],
            recovery_sign_pub: [6; 32],
            nonce_s: [7; 32],
        };
        store.set_pending(
            ASTATION,
            "dev-1",
            keys,
            &astation,
            "DDDD-EEEE-FFFF",
            &TRANSCRIPT,
        );
        store.confirm(ASTATION, &fake.sign(&certificate(keys, epoch).encode()))
    }

    #[test]
    fn re_verification_never_lowers_the_floor_or_drops_the_state() {
        let fake = FakeAstation::new();
        let (mut store, keys) = pending(&fake);
        store
            .confirm(ASTATION, &fake.sign(&certificate(&keys, 1).encode()))
            .unwrap();
        let on = fake.sign(&state(EncryptionMode::On, 2).encode());
        store.accept_account_state(ASTATION, &on).unwrap().unwrap();

        // A certificate older than the applied state is refused outright.
        assert!(reverify(&mut store, &fake, &keys, 1).is_err());
        store.remove_pending(ASTATION);
        let trust = store.verified(ASTATION).unwrap();
        assert_eq!((trust.epoch_floor, trust.account_epoch), (1, 2));

        reverify(&mut store, &fake, &keys, 10).unwrap();
        let trust = store.verified(ASTATION).unwrap();
        assert_eq!(trust.epoch_floor, 10);
        assert_eq!(trust.account_state.as_ref(), Some(&on));
        assert_eq!(trust.account_epoch, 2);
        assert_eq!(trust.safety_code, "DDDD-EEEE-FFFF");

        // A legitimate re-verification with an older certificate epoch.
        reverify(&mut store, &fake, &keys, 5).unwrap();
        let trust = store.verified(ASTATION).unwrap();
        assert_eq!(trust.epoch_floor, 10, "the floor never goes down");
        assert_eq!(trust.account_state.as_ref(), Some(&on));
        assert_eq!(trust.account_epoch, 2);
        assert!(
            store
                .accept_account_state(
                    ASTATION,
                    &fake.sign(&state(EncryptionMode::Off, 9).encode())
                )
                .is_err()
        );
    }

    #[test]
    fn store_round_trips_and_shows_a_line() {
        let fake = FakeAstation::new();
        let (mut store, keys) = pending(&fake);
        store
            .confirm(ASTATION, &fake.sign(&certificate(&keys, 5).encode()))
            .unwrap();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cred_state.json");
        store.save_to(&path).unwrap();
        let loaded = TrustStore::load_from(&path).unwrap();
        assert!(loaded.verified(ASTATION).is_some());
        assert_eq!(
            loaded.verification_line(ASTATION),
            "Verified: yes  (safety code AAAA-BBBB-CCCC)"
        );
        assert_eq!(
            loaded.verification_line("other"),
            "Verified: no  (run 'atem pair' to verify this device)"
        );
        assert_eq!(trust_path_for(&dir.path().join("data_keys.enc")), path);
    }
}

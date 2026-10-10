//! The device's completion attestation; Astation owns durable acceptance and finalization.
use anyhow::{Result, bail};
use crate::memory::crypto::EncryptionMode;
use crate::memory::encoding::{enc, u64_field};

pub const LABEL: &str = "atem-migration-complete-v1";

pub fn proof_input(account: &str, sign_gen: u64, device: &str, target: &str, kid: &str, epoch: u64) -> Vec<u8> {
    enc(&[LABEL.as_bytes(), account.as_bytes(), &u64_field(sign_gen), device.as_bytes(), target.as_bytes(),
        kid.as_bytes(), &u64_field(epoch), &u64_field(7), &u64_field(0)])
}

/// A successful rewrite is insufficient: check every protected field on the read-back pass.
pub fn verify_field(value: &str, prefix: &str, mode: EncryptionMode, kid: &str) -> Result<()> {
    if value.is_empty() { return Ok(()); }
    match mode {
        EncryptionMode::Enabling if value.starts_with(&format!("{prefix}.{kid}.")) => Ok(()),
        EncryptionMode::Disabling if !value.starts_with("e1.") && !value.starts_with("h1.") => Ok(()),
        _ => bail!("encryption migration verification found an unmigrated field"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn migration_readback_rejects_plaintext_old_keys_and_incomplete_disabling() {
        for value in ["plain", "e1.89abcdef.ciphertext", "h1.0123abcd.hash"] {
            assert!(verify_field(value, "e1", EncryptionMode::Enabling, "0123abcd").is_err());
        }
        assert!(verify_field("e1.0123abcd.ciphertext", "e1", EncryptionMode::Enabling, "0123abcd").is_ok());
        for value in ["e1.0123abcd.ciphertext", "h1.0123abcd.hash"] {
            assert!(verify_field(value, "e1", EncryptionMode::Disabling, "0123abcd").is_err());
        }
        assert!(verify_field("plain", "e1", EncryptionMode::Disabling, "0123abcd").is_ok());
    }

    #[test]
    fn migration_key_proof_matches_the_shared_swift_vector() {
        use crate::memory::account_keys::AccountKeys;
        let mut keys = AccountKeys::default();
        keys.install("acct-1", "0123abcd", zeroize::Zeroizing::new([0x99; 32]));
        let input = proof_input("acct-1", 1, "dev-1", "on", "0123abcd", 3);
        let proof = keys.migration_proof("acct-1", "0123abcd", &input).unwrap();
        let hex: String = proof.iter().map(|byte| format!("{byte:02x}")).collect();
        assert_eq!(hex, "745f278c97169b6bf2f3e260bf6d75a960a7bcf0ead81416d3813ad8a6bcf769");
        assert!(keys.migration_proof("other-account", "0123abcd", &input).is_err());
        assert!(keys.migration_proof("acct-1", "89abcdef", &input).is_err());
    }

    #[test]
    fn migration_agent_signs_only_the_current_verified_pending_state() {
        use crate::memory::fake_astation::{ASTATION_ID, UnlockedDevice};
        use crate::memory::key_agent::KeyAgentApi;
        use crate::memory::statements::verify_device;
        use crate::memory::trust::TrustStore;
        let directory = tempfile::tempdir().unwrap();
        let mut device = UnlockedDevice::new(directory.path());
        device.set_key(EncryptionMode::Enabling, "0123abcd", [0x99; 32]);
        let epoch = TrustStore::load_from(&device.paths.trust).unwrap().verified(ASTATION_ID).unwrap().account_epoch;
        let report = device.agent.migration_completion(ASTATION_ID, epoch, "on", "0123abcd").unwrap();
        let fields = verify_device(&device.keys.device_sign_pub(), &report).unwrap();
        assert_eq!(fields[0], LABEL.as_bytes());
        assert_eq!(fields.len(), 10);
        assert_eq!(fields[7], u64_field(7));
        assert_eq!(fields[8], u64_field(0));
        assert_eq!(fields[9].len(), 32);
        assert!(device.agent.migration_completion(ASTATION_ID, epoch + 1, "on", "0123abcd").is_err());
        assert!(device.agent.migration_completion(ASTATION_ID, epoch, "off", "0123abcd").is_err());
        assert!(device.agent.migration_completion(ASTATION_ID, epoch, "on", "89abcdef").is_err());
        device.state(EncryptionMode::On, Some("0123abcd"));
        assert!(device.agent.migration_completion(ASTATION_ID, epoch, "on", "0123abcd").is_err());
        device.agent.lock_keys().unwrap();
        assert!(device.agent.migration_completion(ASTATION_ID, epoch, "on", "0123abcd").is_err());
    }
}

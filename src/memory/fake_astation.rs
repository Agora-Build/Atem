//! Test stand-in for Astation's side of unlock and storage-key rotation:
//! the pins it keeps, the storage keys it holds, the grants and acks it
//! signs. Mirrors "Astation work for step 2a" in designs/e2e-encryption.md.
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::collections::HashMap;
use std::path::Path;

use crate::memory::device_keys::DeviceKeys;
use crate::memory::encoding::dec;
use crate::memory::grant::{hpke_open, hpke_seal};
use crate::memory::statements::{
    DeviceVerified, FakeAstation, SignedWire, StorageAck, StorageConfirm, StorageRotate,
    UnlockGrant, UnlockRequest, sealed_hash, storage_key_info, unlock_info, unlock_request_hash,
    verify_device,
};
use crate::memory::storage_key::{
    SealedDeviceKeys, StorageRotation, UnlockGrantWire, new_storage_key,
};
use crate::memory::trust::TrustStore;
use crate::memory::verification::{AstationKeys, KeyPaths};

pub(crate) const ASTATION_ID: &str = "astation-1";
pub(crate) const ACCOUNT: &str = "acct";
pub(crate) const DEVICE_ID: &str = "dev-1";

/// Pins `astation` for `keys` in `paths.trust`, as a finished verification
/// does; `home` also makes it the home Astation.
pub(crate) fn pin(paths: &KeyPaths, astation: &FakeAstation, keys: &DeviceKeys, home: bool) {
    let pinned = AstationKeys {
        sign_pub: astation.sign_pub(),
        enc_pub: astation.enc_pub(),
        recovery_sign_pub: [6; 32],
        nonce_s: [7; 32],
    };
    let mut trust = TrustStore::load_from(&paths.trust).unwrap();
    trust.set_pending(
        ASTATION_ID,
        DEVICE_ID,
        keys,
        &pinned,
        "AAAA-BBBB-CCCC",
        &[8; 32],
    );
    let certificate = DeviceVerified {
        account: ACCOUNT.into(),
        sign_gen: 1,
        device_id: DEVICE_ID.into(),
        device_pub: keys.device_pub(),
        device_sign_pub: keys.device_sign_pub(),
        unlock_auth_pub: keys.unlock_auth_pub(),
        transcript: [8; 32],
        epoch: 1,
    };
    trust
        .confirm(ASTATION_ID, &astation.sign(&certificate.encode()))
        .unwrap();
    if home {
        trust.set_home(ASTATION_ID);
    }
    trust.save_to(&paths.trust).unwrap();
}

/// A verified device in `dir`: home Astation pinned, keys sealed under a
/// storage key with id `kid` that Astation holds, unlock-auth key on disk.
pub(crate) fn sealed_device(dir: &Path, kid: &str) -> (KeyPaths, FakeKeyServer, DeviceKeys) {
    let paths = KeyPaths::in_dir(dir);
    let keys = DeviceKeys::generate();
    let astation = FakeAstation::new();
    pin(&paths, &astation, &keys, true);
    let storage_key = new_storage_key();
    SealedDeviceKeys::seal(&keys, DEVICE_ID, kid, &storage_key)
        .unwrap()
        .save_to(&paths.device_keys_sealed)
        .unwrap();
    keys.unlock_auth_key()
        .save_to(&paths.unlock_auth_key)
        .unwrap();
    let server = FakeKeyServer {
        astation,
        device_sign_pub: keys.device_sign_pub(),
        unlock_auth_pub: keys.unlock_auth_pub(),
        storage_keys: HashMap::from([(kid.to_string(), *storage_key)]),
        pending: None,
        acked: Default::default(),
    };
    (paths, server, keys)
}

pub(crate) struct FakeKeyServer {
    pub astation: FakeAstation,
    pub device_sign_pub: [u8; 32],
    pub unlock_auth_pub: [u8; 32],
    /// Storage keys Astation holds for this device, by storage_kid.
    pub storage_keys: HashMap<String, [u8; 32]>,
    /// A rotated key stored as pending until the device confirms it.
    pub pending: Option<(String, [u8; 32])>,
    /// Every storage key id Astation ever acked: a replayed rotate to one is refused.
    pub acked: std::collections::HashSet<String>,
}

/// A device-signed rotate from `old` to `new` with a fresh key, as a relay
/// could have captured earlier and replay later.
#[cfg(test)]
pub(crate) fn captured_rotation(
    server: &FakeKeyServer,
    keys: &DeviceKeys,
    old: &str,
    new: &str,
) -> StorageRotation {
    let key = new_storage_key();
    let (encapped, ciphertext) = hpke_seal(
        &server.astation.enc_pub(),
        &storage_key_info(ACCOUNT, DEVICE_ID, new),
        &*key,
    )
    .unwrap();
    let rotate = StorageRotate {
        account: ACCOUNT.into(),
        device_id: DEVICE_ID.into(),
        old_storage_kid: old.into(),
        new_storage_kid: new.into(),
        sealed_hash: sealed_hash(&encapped, &ciphertext),
    };
    StorageRotation {
        rotate: keys.sign_statement(&rotate.encode()),
        encapped_key: STANDARD.encode(encapped),
        ciphertext: STANDARD.encode(ciphertext),
    }
}

impl FakeKeyServer {
    /// "Touch ID approved": releases the storage key the request names.
    pub fn grant_unlock(&self, request: &SignedWire) -> Result<UnlockGrantWire> {
        let bytes = STANDARD.decode(&request.statement)?;
        let kid = UnlockRequest::parse(&dec(&bytes)?)?.storage_kid;
        self.unlock_grant(&self.astation, request, &kid)
    }

    /// Like `grant_unlock`, but a request naming the pending key confirms it first.
    pub fn grant_unlock_confirming(&mut self, request: &SignedWire) -> Result<UnlockGrantWire> {
        let bytes = STANDARD.decode(&request.statement)?;
        let kid = UnlockRequest::parse(&dec(&bytes)?)?.storage_kid;
        // Only a request the unlock-auth key signed may settle a rotation.
        verify_device(&self.unlock_auth_pub, request).context("unlock-auth signature")?;
        if self
            .pending
            .as_ref()
            .is_some_and(|(pending, _)| *pending == kid)
        {
            self.promote_pending();
        }
        self.grant_unlock(request)
    }

    /// Releases storage key `kid` (current or pending) for `request`, with
    /// the grant signed by `signer`.
    pub fn unlock_grant(
        &self,
        signer: &FakeAstation,
        request: &SignedWire,
        kid: &str,
    ) -> Result<UnlockGrantWire> {
        let fields =
            verify_device(&self.unlock_auth_pub, request).context("unlock-auth signature")?;
        let parsed = UnlockRequest::parse(&fields)?;
        if parsed.account != ACCOUNT || parsed.device_id != DEVICE_ID {
            bail!("unlock request for another account or device");
        }
        let key = self
            .storage_keys
            .get(kid)
            .copied()
            .or_else(|| {
                self.pending
                    .as_ref()
                    .filter(|(pending, _)| pending == kid)
                    .map(|(_, key)| *key)
            })
            .ok_or_else(|| anyhow!("Astation holds no storage key {kid}"))?;
        let request_hash = unlock_request_hash(&STANDARD.decode(&request.statement)?);
        let (encapped, ciphertext) = hpke_seal(
            &parsed.e_pub,
            &unlock_info(ACCOUNT, DEVICE_ID, kid, &request_hash),
            &key,
        )?;
        let statement = UnlockGrant {
            account: ACCOUNT.into(),
            sign_gen: 1,
            device_id: DEVICE_ID.into(),
            storage_kid: kid.into(),
            request_hash,
            sealed_hash: sealed_hash(&encapped, &ciphertext),
        };
        Ok(UnlockGrantWire {
            grant: signer.sign(&statement.encode()),
            encapped_key: STANDARD.encode(encapped),
            ciphertext: STANDARD.encode(ciphertext),
        })
    }

    /// Promotes the pending key to the only current one.
    fn promote_pending(&mut self) {
        if let Some((kid, key)) = self.pending.take() {
            self.storage_keys.clear();
            self.storage_keys.insert(kid, key);
        }
    }

    /// Phase 2: checks the device signature and the seal, stores the key as
    /// pending (keeping the current one) and acks. An acked pending key is a
    /// commitment: another rotate is refused until it is confirmed, except
    /// an idempotent resend of the same key or a rotate from the pending key
    /// itself (an implicit confirm).
    pub fn accept_rotation(&mut self, rotation: &StorageRotation) -> Result<SignedWire> {
        let rotate =
            StorageRotate::parse(&verify_device(&self.device_sign_pub, &rotation.rotate)?)?;
        if rotate.account != ACCOUNT || rotate.device_id != DEVICE_ID {
            bail!("rotation for another account or device");
        }
        if !crate::memory::crypto::valid_kid(&rotate.new_storage_kid) {
            bail!("rotation has an invalid new storage key id");
        }
        if rotate.new_storage_kid == rotate.old_storage_kid {
            bail!("rotation to the same storage key id");
        }
        let encapped = STANDARD.decode(&rotation.encapped_key)?;
        let ciphertext = STANDARD.decode(&rotation.ciphertext)?;
        if sealed_hash(&encapped, &ciphertext) != rotate.sealed_hash {
            bail!("rotation seal doesn't match its signature");
        }
        let resend = self
            .pending
            .as_ref()
            .is_some_and(|(kid, _)| *kid == rotate.new_storage_kid);
        if !resend {
            if let Some((pending, _)) = &self.pending {
                if *pending == rotate.old_storage_kid {
                    self.promote_pending();
                } else {
                    bail!(
                        "a rotation to storage key {pending} is pending; it must be confirmed first"
                    );
                }
            }
            if self.acked.contains(&rotate.new_storage_kid) {
                bail!("storage key {} was acked before", rotate.new_storage_kid);
            }
            if self.storage_keys.contains_key(&rotate.new_storage_kid) {
                bail!(
                    "Astation already holds storage key {}",
                    rotate.new_storage_kid
                );
            }
            if rotate.old_storage_kid.is_empty() {
                if !self.storage_keys.is_empty() {
                    bail!("first-sealing rotation, but Astation already holds a storage key");
                }
            } else if !self.storage_keys.contains_key(&rotate.old_storage_kid) {
                bail!("rotation from a storage key Astation doesn't hold");
            }
        }
        let plain = hpke_open(
            &self.astation.enc_secret_bytes(),
            &encapped,
            &ciphertext,
            &storage_key_info(ACCOUNT, DEVICE_ID, &rotate.new_storage_kid),
        )?;
        let key: [u8; 32] = plain
            .as_slice()
            .try_into()
            .map_err(|_| anyhow!("storage key has the wrong length"))?;
        if !resend {
            self.pending = Some((rotate.new_storage_kid.clone(), key));
            self.acked.insert(rotate.new_storage_kid.clone());
        }
        Ok(self.astation.sign(
            &StorageAck {
                account: ACCOUNT.into(),
                sign_gen: 1,
                device_id: DEVICE_ID.into(),
                storage_kid: rotate.new_storage_kid,
            }
            .encode(),
        ))
    }

    /// Phase 3: the device switched; only the new key is kept. Everything is
    /// checked before anything is dropped, so a stray confirm changes nothing.
    pub fn confirm(&mut self, confirm: &SignedWire) -> Result<()> {
        let confirmed = StorageConfirm::parse(&verify_device(&self.device_sign_pub, confirm)?)?;
        if confirmed.account != ACCOUNT || confirmed.device_id != DEVICE_ID {
            bail!("confirmation for another account or device");
        }
        match &self.pending {
            Some((kid, _)) if *kid == confirmed.storage_kid => {
                self.promote_pending();
                Ok(())
            }
            // Already settled by an unlock or a later rotate.
            None if self.storage_keys.contains_key(&confirmed.storage_kid) => Ok(()),
            _ => bail!("confirmation for another storage key"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use super::captured_rotation as rotation;

    #[test]
    fn rotation_with_empty_old_kid_is_rejected_when_a_key_is_held() {
        let dir = tempfile::tempdir().unwrap();
        let (_paths, mut server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        let error = server
            .accept_rotation(&rotation(&server, &keys, "", "4e5f6a7b"))
            .unwrap_err();
        assert!(error.to_string().contains("already holds"), "{error}");
        assert!(server.pending.is_none());
        // A rotation naming the held key is accepted, then confirmed.
        let ack = server
            .accept_rotation(&rotation(&server, &keys, "0a1b2c3d", "4e5f6a7b"))
            .unwrap();
        assert!(server.pending.is_some());
        let _ = ack;
    }

    #[test]
    fn first_sealing_with_empty_old_kid_is_accepted_when_nothing_is_held() {
        let dir = tempfile::tempdir().unwrap();
        let (_paths, mut server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        server.storage_keys.clear();
        server
            .accept_rotation(&rotation(&server, &keys, "", "4e5f6a7b"))
            .unwrap();
    }

    #[test]
    fn rotation_rejects_a_bad_new_kid_an_unchanged_kid_or_a_held_kid() {
        let dir = tempfile::tempdir().unwrap();
        let (_paths, mut server, keys) = sealed_device(dir.path(), "0a1b2c3d");
        for (old, new, expected) in [
            ("0a1b2c3d", "NOPE", "invalid"),
            ("0a1b2c3d", "0a1b2c3d", "same"),
        ] {
            let error = server
                .accept_rotation(&rotation(&server, &keys, old, new))
                .unwrap_err();
            assert!(error.to_string().contains(expected), "{new}: {error}");
            assert!(server.pending.is_none());
        }
        // A kid Astation already holds (here: a second one it keeps).
        server.storage_keys.insert("4e5f6a7b".into(), [3; 32]);
        let error = server
            .accept_rotation(&rotation(&server, &keys, "0a1b2c3d", "4e5f6a7b"))
            .unwrap_err();
        assert!(error.to_string().contains("already holds"), "{error}");
        assert!(server.pending.is_none());
    }
}

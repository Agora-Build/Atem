//! Keys sealed to this device: RFC 9180 HPKE, plus Astation's signature over
//! what the seal is for and a hash of its output. The relay can carry a grant
//! but can't make one. See designs/e2e-encryption.md "Sealing a key to a device".
use anyhow::{Context, Result, anyhow, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use hpke::{
    Deserializable, Kem as KemTrait, OpModeR, aead::ChaCha20Poly1305, kdf::HkdfSha256,
    kem::X25519HkdfSha256,
};
use serde::{Deserialize, Serialize};

use crate::memory::device_keys::DeviceKeys;
use crate::memory::statements::{GrantStatement, SignedWire, sealed_hash, verify_astation};
use crate::memory::trust::AstationTrust;

type Kem = X25519HkdfSha256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantWire {
    pub signed: SignedWire,
    pub encapped_key: String,
    pub ciphertext: String,
}

pub struct OpenedGrant {
    pub kid: String,
    pub key: [u8; 32],
}

pub fn open_grant(
    trust: &AstationTrust,
    keys: &DeviceKeys,
    grant: &GrantWire,
) -> Result<OpenedGrant> {
    let sign_pub = STANDARD.decode(&trust.astation_sign_pub)?;
    let statement = GrantStatement::parse(&verify_astation(&sign_pub, &grant.signed)?)?;
    if statement.account != trust.data_account {
        bail!("key grant is for a different account");
    }
    if statement.sign_gen != trust.sign_gen {
        bail!("key grant is signed by a different signing-key generation");
    }
    if statement.kind != "K" {
        bail!("unsupported key grant type {:?}", statement.kind);
    }
    if statement.device_id != trust.device_id || statement.device_pub != keys.device_pub() {
        bail!("key grant is for a different device");
    }
    if !crate::memory::crypto::valid_kid(&statement.kid) {
        bail!("key grant has an invalid key id");
    }

    let encapped = STANDARD
        .decode(&grant.encapped_key)
        .context("grant key encapsulation is not base64")?;
    let ciphertext = STANDARD
        .decode(&grant.ciphertext)
        .context("grant ciphertext is not base64")?;
    if sealed_hash(&encapped, &ciphertext) != statement.sealed_hash {
        bail!("key grant does not match what Astation signed");
    }
    let secret = <Kem as KemTrait>::PrivateKey::from_bytes(&keys.device_secret_bytes())
        .map_err(|error| anyhow!("device key is unusable for HPKE: {error:?}"))?;
    let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&encapped)
        .map_err(|error| anyhow!("grant key encapsulation is malformed: {error:?}"))?;
    let plain = hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeR::Base,
        &secret,
        &encapped,
        &statement.info(),
        &ciphertext,
        b"",
    )
    .map_err(|_| anyhow!("key grant could not be opened"))?;
    let key: [u8; 32] = plain
        .try_into()
        .map_err(|_| anyhow!("granted key has the wrong length"))?;
    Ok(OpenedGrant {
        kid: statement.kid,
        key,
    })
}

/// Test stand-in for Astation sealing `K` to a device.
#[cfg(test)]
pub(crate) fn seal_k_grant(
    astation: &crate::memory::statements::FakeAstation,
    account: &str,
    device_id: &str,
    device_pub: [u8; 32],
    kid: &str,
    key: [u8; 32],
) -> GrantWire {
    use hpke::{OpModeS, Serializable};
    let mut statement = GrantStatement {
        account: account.into(),
        sign_gen: 1,
        kind: "K".into(),
        device_id: device_id.into(),
        device_pub,
        kid: kid.into(),
        scope_hmac: String::new(),
        sealed_hash: [0; 32],
    };
    let recipient = <Kem as KemTrait>::PublicKey::from_bytes(&device_pub).unwrap();
    let (encapped, ciphertext) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem, _>(
        &OpModeS::Base,
        &recipient,
        &statement.info(),
        &key,
        b"",
        &mut rand::rngs::OsRng,
    )
    .unwrap();
    let encapped = encapped.to_bytes().to_vec();
    statement.sealed_hash = sealed_hash(&encapped, &ciphertext);
    GrantWire {
        signed: astation.sign(&statement.encode()),
        encapped_key: STANDARD.encode(encapped),
        ciphertext: STANDARD.encode(ciphertext),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::memory::statements::{DeviceVerified, FakeAstation};
    use crate::memory::trust::TrustStore;
    use crate::memory::verification::AstationKeys;

    fn verified(fake: &FakeAstation, keys: &DeviceKeys) -> AstationTrust {
        let astation = AstationKeys {
            sign_pub: fake.sign_pub(),
            enc_pub: [5; 32],
            recovery_sign_pub: [6; 32],
            nonce_s: [7; 32],
        };
        let mut store = TrustStore::default();
        store.set_pending("astation-1", "dev-1", keys, &astation, "AAAA-BBBB-CCCC");
        let certificate = DeviceVerified {
            account: "acct".into(),
            sign_gen: 1,
            device_id: "dev-1".into(),
            device_pub: keys.device_pub(),
            device_sign_pub: keys.device_sign_pub(),
            unlock_auth_pub: keys.unlock_auth_pub(),
            epoch: 1,
        };
        store
            .confirm("astation-1", &fake.sign(&certificate.encode()))
            .unwrap();
        store.verified("astation-1").unwrap().clone()
    }

    #[test]
    fn signed_grant_opens() {
        let (fake, keys) = (FakeAstation::new(), DeviceKeys::generate());
        let trust = verified(&fake, &keys);
        let grant = seal_k_grant(
            &fake,
            "acct",
            "dev-1",
            keys.device_pub(),
            "0123abcd",
            [42; 32],
        );
        let opened = open_grant(&trust, &keys, &grant).unwrap();
        assert_eq!((opened.kid.as_str(), opened.key), ("0123abcd", [42; 32]));
    }

    #[test]
    fn relay_sealed_key_is_rejected_even_with_a_real_signature() {
        let (fake, keys) = (FakeAstation::new(), DeviceKeys::generate());
        let trust = verified(&fake, &keys);
        let real = seal_k_grant(
            &fake,
            "acct",
            "dev-1",
            keys.device_pub(),
            "0123abcd",
            [42; 32],
        );
        // The relay seals its own key to the public device key and reuses Astation's signature.
        let relay = seal_k_grant(
            &FakeAstation::new(),
            "acct",
            "dev-1",
            keys.device_pub(),
            "0123abcd",
            [66; 32],
        );
        let spliced = GrantWire {
            signed: real.signed.clone(),
            ..relay.clone()
        };
        assert!(open_grant(&trust, &keys, &spliced).is_err());
        assert!(open_grant(&trust, &keys, &relay).is_err());
    }

    #[test]
    fn grant_for_another_device_or_account_is_rejected() {
        let (fake, keys) = (FakeAstation::new(), DeviceKeys::generate());
        let trust = verified(&fake, &keys);
        let other_device = DeviceKeys::generate();
        let wrong_device = seal_k_grant(
            &fake,
            "acct",
            "dev-1",
            other_device.device_pub(),
            "0123abcd",
            [42; 32],
        );
        assert!(open_grant(&trust, &keys, &wrong_device).is_err());
        let wrong_account = seal_k_grant(
            &fake,
            "other",
            "dev-1",
            keys.device_pub(),
            "0123abcd",
            [42; 32],
        );
        assert!(open_grant(&trust, &keys, &wrong_account).is_err());
        let bad_kid = seal_k_grant(&fake, "acct", "dev-1", keys.device_pub(), "XYZ", [42; 32]);
        assert!(open_grant(&trust, &keys, &bad_kid).is_err());
    }
}

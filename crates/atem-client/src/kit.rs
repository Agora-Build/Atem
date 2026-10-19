//! Recovery Kit v2 (§R9.5): one 256-bit secret `R`, the `account_id`, the
//! account's `genesis_hash` and a `kit_tag` binding the three. Astation owns
//! the kit, its text encoding and its UI; the derivations are shared here.
//!
//! ```text
//! sign_seed    = HKDF-SHA256(salt = empty, ikm = R, info = "atem-recovery-sign-v1", 32)
//! recovery_key = Ed25519 public key of sign_seed
//! kit X25519   = secret SHA-512(sign_seed)[0..32]; public = Montgomery(recovery_key)
//! tag_key      = HKDF-SHA256(salt = empty, ikm = R, info = "atem-recovery-kit-tag-v1", 32)
//! kit_tag      = HMAC-SHA256(tag_key, enc(["atem-recovery-kit-v2", account_id, genesis_hash]))[0..16]
//! ```
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use crate::domain::{self, SigningInput};
use crate::encoding::{Hash32, ct_eq, enc};
use crate::error::{Error, Result};
use crate::keys::{Alg, PublicKey, ed25519_public_to_x25519};
use crate::provider::{KeyId, KeyProvider};

/// The kit's secret `R` with its anchor. `R` is wiped on drop.
pub struct RecoveryKit {
    r: Zeroizing<[u8; 32]>,
    account_id: String,
    genesis_hash: Hash32,
    kit_tag: [u8; 16],
}

impl RecoveryKit {
    /// A kit as read back (restore step 1): refuses one whose tag doesn't
    /// match its contents ("damaged or mistyped"; nothing is fetched).
    pub fn read(
        r: &[u8; 32],
        account_id: &str,
        genesis_hash: Hash32,
        kit_tag: &[u8; 16],
    ) -> Result<Self> {
        let kit = Self::make(r, account_id, genesis_hash);
        if !ct_eq(&kit.kit_tag, kit_tag) {
            return Err(Error::KitTagMismatch);
        }
        Ok(kit)
    }

    /// A new kit for `R`, bound to a genesis (account setup, or a
    /// replacement bound to the genesis its `set_recovery_key` names).
    pub fn make(r: &[u8; 32], account_id: &str, genesis_hash: Hash32) -> Self {
        let tag = kit_tag(r, account_id, &genesis_hash);
        RecoveryKit {
            r: Zeroizing::new(*r),
            account_id: account_id.to_owned(),
            genesis_hash,
            kit_tag: tag,
        }
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn genesis_hash(&self) -> Hash32 {
        self.genesis_hash
    }

    pub fn kit_tag(&self) -> [u8; 16] {
        self.kit_tag
    }

    /// The Ed25519 seed of the recovery key.
    pub fn sign_seed(&self) -> Zeroizing<[u8; 32]> {
        sign_seed(&self.r)
    }

    /// `recovery_key` (in the genesis or a `set_recovery_key`).
    pub fn recovery_key(&self) -> PublicKey {
        recovery_key_of_seed(&self.sign_seed())
    }

    /// The kit's X25519 secret, `SHA-512(sign_seed)[0..32]` (clamped by
    /// X25519 when used). K backups are sealed to its public half.
    pub fn x25519_secret(&self) -> Zeroizing<[u8; 32]> {
        x25519_secret_of_seed(&self.sign_seed())
    }

    /// The anchor check of a restore (§R9.5 step 2): the fetched log's
    /// genesis must be the kit's, by `entry_hash` and `account_id`.
    pub fn check_genesis(&self, genesis_entry_hash: &Hash32, account_id: &str) -> Result<()> {
        if *genesis_entry_hash != self.genesis_hash || account_id != self.account_id {
            return Err(Error::GenesisMismatch);
        }
        Ok(())
    }
}

/// A Recovery Kit is the key provider of its two keys: the recovery key
/// (signs a `recovery_add` or a `kit_sig`) and the kit's X25519 key (opens a
/// K backup). Their ids are `RecoveryKit::SIGN` and `RecoveryKit::X25519`.
impl RecoveryKit {
    pub const SIGN: &'static str = "recovery-kit/sign";
    pub const X25519: &'static str = "recovery-kit/x25519";

    pub fn sign_id() -> KeyId {
        KeyId::new(Self::SIGN)
    }

    pub fn x25519_id() -> KeyId {
        KeyId::new(Self::X25519)
    }
}

impl KeyProvider for RecoveryKit {
    fn public_key(&self, key: &KeyId) -> Result<PublicKey> {
        match key.0.as_str() {
            Self::SIGN => Ok(self.recovery_key()),
            Self::X25519 => PublicKey::new(Alg::X25519, &kit_x25519_public(&self.recovery_key())?),
            _ => Err(Error::UnknownKey),
        }
    }

    fn sign(&self, key: &KeyId, input: &SigningInput) -> Result<Vec<u8>> {
        if key.0 != Self::SIGN {
            return Err(if key.0 == Self::X25519 {
                Error::WrongAlg
            } else {
                Error::UnknownKey
            });
        }
        let signing = ed25519_dalek::SigningKey::from_bytes(&self.sign_seed());
        Ok(ed25519_dalek::Signer::sign(&signing, input.as_bytes())
            .to_bytes()
            .to_vec())
    }

    fn x25519(&self, key: &KeyId, peer: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
        if key.0 != Self::X25519 {
            return Err(Error::WrongAlg);
        }
        let secret = x25519_dalek::StaticSecret::from(*self.x25519_secret());
        let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(*peer));
        if !shared.was_contributory() {
            return Err(Error::ZeroSharedSecret);
        }
        Ok(Zeroizing::new(*shared.as_bytes()))
    }

    fn hpke_open(
        &self,
        key: &KeyId,
        enc: &[u8],
        ct: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        if key.0 != Self::X25519 {
            return Err(Error::WrongAlg);
        }
        crate::hpke::open_with_secret(&self.x25519_secret(), enc, ct, info, aad)
    }
}

/// `HKDF-SHA256(salt = empty, ikm = R, info, 32)`.
fn hkdf32(r: &[u8; 32], info: &str) -> Zeroizing<[u8; 32]> {
    let mut out = Zeroizing::new([0u8; 32]);
    Hkdf::<Sha256>::new(Some(&[]), r)
        .expand(info.as_bytes(), &mut *out)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    out
}

pub fn sign_seed(r: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf32(r, domain::RECOVERY_SIGN)
}

pub fn tag_key(r: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    hkdf32(r, domain::RECOVERY_KIT_TAG)
}

/// `enc(["atem-recovery-kit-v2", account_id, genesis_hash(32 bytes)])`.
pub fn tag_input(account_id: &str, genesis_hash: &Hash32) -> Vec<u8> {
    enc(&[
        domain::RECOVERY_KIT.as_bytes(),
        account_id.as_bytes(),
        genesis_hash.as_bytes(),
    ])
}

pub fn kit_tag(r: &[u8; 32], account_id: &str, genesis_hash: &Hash32) -> [u8; 16] {
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&*tag_key(r)).expect("HMAC takes any key length");
    mac.update(&tag_input(account_id, genesis_hash));
    let full = mac.finalize().into_bytes();
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&full[..16]);
    tag
}

pub fn recovery_key_of_seed(seed: &[u8; 32]) -> PublicKey {
    let signing = ed25519_dalek::SigningKey::from_bytes(seed);
    PublicKey::new(Alg::Ed25519, signing.verifying_key().as_bytes())
        .expect("a derived Ed25519 key is valid")
}

pub fn x25519_secret_of_seed(seed: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    let mut digest = Zeroizing::new([0u8; 64]);
    digest.copy_from_slice(&Sha512::digest(seed));
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&digest[..32]);
    secret
}

/// The kit's X25519 public key from `recovery_key` alone: anyone holding the
/// verified log can seal to the current kit.
pub fn kit_x25519_public(recovery_key: &PublicKey) -> Result<[u8; 32]> {
    ed25519_public_to_x25519(recovery_key)
}

//! RFC 9180 base mode with the one suite r9 uses for push hints and K
//! backups (§R9.5, §R9.9; the suite of atem's `grant.rs`):
//! DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20-Poly1305.
//!
//! A seal's ephemeral key is `DeriveKeyPair(ikmE)`: `seal` draws `ikmE` from
//! the OS, `seal_with_ikm` takes it (known-answer vectors). Both run the same
//! code, the `hpke` crate's own encapsulation.
use hpke::{
    Deserializable, Kem as _, OpModeR, OpModeS, Serializable, aead::ChaCha20Poly1305,
    kdf::HkdfSha256, kem::X25519HkdfSha256,
};
use rand_core::{CryptoRng, OsRng, RngCore};
use zeroize::Zeroizing;

use crate::error::{Error, Result};

type Kem = X25519HkdfSha256;

/// A sealed message: the encapsulated key (`enc`, 32 bytes) and the
/// ciphertext with its tag.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sealed {
    pub enc: [u8; 32],
    pub ct: Vec<u8>,
}

impl Sealed {
    /// `SHA-256(enc([enc, ct]))`: what a signed body names the seal by
    /// (`sealed_hash`, §R9.9).
    pub fn hash(&self) -> crate::encoding::Hash32 {
        crate::encoding::Hash32::of_enc(&[&self.enc, &self.ct])
    }
}

/// Seals `plain` to an X25519 public key with a fresh ephemeral.
pub fn seal(recipient: &[u8; 32], info: &[u8], aad: &[u8], plain: &[u8]) -> Result<Sealed> {
    let mut ikm = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *ikm);
    seal_derived(recipient, info, aad, plain, &ikm)
}

/// Seals with the ephemeral `DeriveKeyPair(ikm_e)`, for known-answer vectors
/// only (feature `test-vectors`; never part of the exported API). `ikm_e`
/// must be secret and never reused.
#[cfg(feature = "test-vectors")]
pub fn seal_with_ikm(
    recipient: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    plain: &[u8],
    ikm_e: &[u8; 32],
) -> Result<Sealed> {
    seal_derived(recipient, info, aad, plain, ikm_e)
}

/// The one seal: the ephemeral is `DeriveKeyPair(ikm_e)`.
pub(crate) fn seal_derived(
    recipient: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    plain: &[u8],
    ikm_e: &[u8; 32],
) -> Result<Sealed> {
    let public = <Kem as hpke::Kem>::PublicKey::from_bytes(recipient).map_err(|_| Error::BadKey)?;
    let mut rng = IkmOnce {
        ikm: Zeroizing::new(*ikm_e),
        used: false,
    };
    let (encapped, ct) = hpke::single_shot_seal::<ChaCha20Poly1305, HkdfSha256, Kem, _>(
        &OpModeS::Base,
        &public,
        info,
        plain,
        aad,
        &mut rng,
    )
    .map_err(|_| Error::ZeroSharedSecret)?;
    let enc: [u8; 32] = encapped
        .to_bytes()
        .as_slice()
        .try_into()
        .map_err(|_| Error::BadKey)?;
    Ok(Sealed { enc, ct })
}

/// Opens with a raw X25519 secret (software keys; platform keys go through
/// `KeyProvider::hpke_open`). The plaintext is wiped when dropped.
pub fn open_with_secret(
    secret: &[u8; 32],
    enc: &[u8],
    ct: &[u8],
    info: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    let secret = <Kem as hpke::Kem>::PrivateKey::from_bytes(secret).map_err(|_| Error::BadKey)?;
    let encapped =
        <Kem as hpke::Kem>::EncappedKey::from_bytes(enc).map_err(|_| Error::OpenFailed)?;
    hpke::single_shot_open::<ChaCha20Poly1305, HkdfSha256, Kem>(
        &OpModeR::Base,
        &secret,
        &encapped,
        info,
        ct,
        aad,
    )
    .map(Zeroizing::new)
    .map_err(|_| Error::OpenFailed)
}

/// The X25519 public key of an HPKE secret (as the KEM computes it).
pub fn public_of(secret: &[u8; 32]) -> Result<[u8; 32]> {
    let secret = <Kem as hpke::Kem>::PrivateKey::from_bytes(secret).map_err(|_| Error::BadKey)?;
    Kem::sk_to_pk(&secret)
        .to_bytes()
        .as_slice()
        .try_into()
        .map_err(|_| Error::BadKey)
}

/// Feeds the KEM's key generation exactly `ikm` (it reads 32 bytes once and
/// derives the ephemeral with `DeriveKeyPair`, RFC 9180 §4.1). Anything more
/// it asked for would come from the OS, so a seal is never weaker than random.
struct IkmOnce {
    ikm: Zeroizing<[u8; 32]>,
    used: bool,
}

impl RngCore for IkmOnce {
    fn next_u32(&mut self) -> u32 {
        OsRng.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        OsRng.next_u64()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        if !self.used && dest.len() == self.ikm.len() {
            dest.copy_from_slice(&*self.ikm);
            self.used = true;
        } else {
            OsRng.fill_bytes(dest);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for IkmOnce {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_opens_only_with_its_key_and_info() {
        let secret = [7u8; 32];
        let public = public_of(&secret).unwrap();
        let sealed = seal(&public, b"info", b"", b"secret").unwrap();
        let plain = open_with_secret(&secret, &sealed.enc, &sealed.ct, b"info", b"").unwrap();
        assert_eq!(&plain[..], b"secret");
        assert_eq!(
            open_with_secret(&secret, &sealed.enc, &sealed.ct, b"other", b""),
            Err(Error::OpenFailed)
        );
        assert_eq!(
            open_with_secret(&[8u8; 32], &sealed.enc, &sealed.ct, b"info", b""),
            Err(Error::OpenFailed)
        );
    }

    #[test]
    fn the_same_ikm_gives_the_same_seal() {
        let public = public_of(&[7u8; 32]).unwrap();
        let a = seal_derived(&public, b"i", b"", b"p", &[1u8; 32]).unwrap();
        let b = seal_derived(&public, b"i", b"", b"p", &[1u8; 32]).unwrap();
        assert_eq!(a, b);
        assert_ne!(seal(&public, b"i", b"", b"p").unwrap().enc, a.enc);
    }
}

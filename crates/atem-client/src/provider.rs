//! Secret keys stay behind `KeyProvider`: a native member's `auth_key` is
//! non-exportable (Secure Enclave, Android Keystore, WebCrypto; §R9.6), so
//! the core asks the platform to sign, to agree an X25519 secret or to open
//! an HPKE seal, and never holds those secrets itself.
use zeroize::Zeroizing;

use crate::domain::SigningInput;
use crate::error::{Error, Result};
use crate::keys::{Alg, PublicKey, normalize_signature};

/// The platform's name for a key (a keychain tag, a keystore alias, …).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyId(pub String);

impl KeyId {
    pub fn new(id: impl Into<String>) -> Self {
        KeyId(id.into())
    }
}

/// What the core needs from a platform key store. Each key has one
/// algorithm, fixed when it was created; a provider never signs with a key
/// under another algorithm.
pub trait KeyProvider {
    /// The public half of a key, with its algorithm.
    fn public_key(&self, key: &KeyId) -> Result<PublicKey>;

    /// Signs `input` with a P-256 or Ed25519 key: 64 bytes, `r‖s` for P-256
    /// (either S; `sign` below normalizes it). Owner confirmation, if the key
    /// requires one, is the provider's business (§R9.6 rules 2–4).
    fn sign(&self, key: &KeyId, input: &SigningInput) -> Result<Vec<u8>>;

    /// X25519 of an X25519 key with `peer`. Must refuse an all-zero result
    /// (`Error::ZeroSharedSecret`).
    fn x25519(&self, key: &KeyId, peer: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>>;

    /// RFC 9180 base-mode open with an X25519 key, the suite of
    /// `crate::hpke` (DHKEM(X25519, HKDF-SHA256), HKDF-SHA256,
    /// ChaCha20-Poly1305).
    fn hpke_open(
        &self,
        key: &KeyId,
        enc: &[u8],
        ct: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>>;
}

/// Signs through `provider` and returns a signature every verifier accepts:
/// P-256 normalized to low S, then checked against the key's public half (a
/// provider that returns garbage is caught here, not by the peer).
pub fn sign(provider: &dyn KeyProvider, key: &KeyId, input: &SigningInput) -> Result<Vec<u8>> {
    let public = provider.public_key(key)?;
    if public.alg() == Alg::X25519 {
        return Err(Error::WrongAlg);
    }
    let sig = normalize_signature(public.alg(), provider.sign(key, input)?)?;
    public.verify(input, &sig)?;
    Ok(sig)
}

//! `SoftwareKeys`: an in-memory `KeyProvider` (feature `software-keys`).
//! For tests and for bots: a `service` principal holds a software key in its
//! own secret store (§R9.6 rule 5). Native members must use a platform
//! provider whose keys can't be exported. Every secret is wiped on drop.
use std::collections::BTreeMap;

use p256::ecdsa::signature::Signer as _;
use zeroize::Zeroizing;

use crate::domain::SigningInput;
use crate::error::{Error, Result};
use crate::keys::{Alg, PublicKey};
use crate::provider::{KeyId, KeyProvider};

enum Secret {
    // p256 and ed25519-dalek keys wipe themselves on drop; x25519 keys are
    // kept as wiped bytes and turned into a `StaticSecret` per use.
    P256(p256::ecdsa::SigningKey),
    Ed25519(ed25519_dalek::SigningKey),
    X25519(Zeroizing<[u8; 32]>),
}

#[derive(Default)]
pub struct SoftwareKeys {
    keys: BTreeMap<KeyId, Secret>,
}

impl SoftwareKeys {
    pub fn new() -> Self {
        Self::default()
    }

    /// A P-256 key from its 32-byte scalar.
    pub fn insert_p256(&mut self, id: KeyId, secret: &[u8; 32]) -> Result<()> {
        let key = p256::ecdsa::SigningKey::from_slice(secret).map_err(|_| Error::BadKey)?;
        self.keys.insert(id, Secret::P256(key));
        Ok(())
    }

    /// An Ed25519 key from its 32-byte seed.
    pub fn insert_ed25519(&mut self, id: KeyId, seed: &[u8; 32]) {
        self.keys.insert(
            id,
            Secret::Ed25519(ed25519_dalek::SigningKey::from_bytes(seed)),
        );
    }

    /// An X25519 key from its 32 secret bytes (clamped when used).
    pub fn insert_x25519(&mut self, id: KeyId, secret: &[u8; 32]) {
        self.keys
            .insert(id, Secret::X25519(Zeroizing::new(*secret)));
    }

    /// A new random key of `alg`.
    pub fn generate(&mut self, id: KeyId, alg: Alg) -> Result<PublicKey> {
        let mut bytes = Zeroizing::new([0u8; 32]);
        loop {
            rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut *bytes);
            let inserted = match alg {
                Alg::P256 => self.insert_p256(id.clone(), &bytes),
                Alg::Ed25519 => {
                    self.insert_ed25519(id.clone(), &bytes);
                    Ok(())
                }
                Alg::X25519 => {
                    self.insert_x25519(id.clone(), &bytes);
                    Ok(())
                }
            };
            // A P-256 scalar of zero or ≥ n is refused; draw again.
            if inserted.is_ok() {
                return self.public_key(&id);
            }
        }
    }

    fn get(&self, id: &KeyId) -> Result<&Secret> {
        self.keys.get(id).ok_or(Error::UnknownKey)
    }

    fn x25519_secret(&self, id: &KeyId) -> Result<&Zeroizing<[u8; 32]>> {
        match self.get(id)? {
            Secret::X25519(secret) => Ok(secret),
            _ => Err(Error::WrongAlg),
        }
    }
}

impl KeyProvider for SoftwareKeys {
    fn public_key(&self, key: &KeyId) -> Result<PublicKey> {
        match self.get(key)? {
            Secret::P256(k) => PublicKey::new(
                Alg::P256,
                k.verifying_key().to_encoded_point(false).as_bytes(),
            ),
            Secret::Ed25519(k) => PublicKey::new(Alg::Ed25519, k.verifying_key().as_bytes()),
            Secret::X25519(s) => {
                let secret = x25519_dalek::StaticSecret::from(**s);
                PublicKey::new(
                    Alg::X25519,
                    x25519_dalek::PublicKey::from(&secret).as_bytes(),
                )
            }
        }
    }

    fn sign(&self, key: &KeyId, input: &SigningInput) -> Result<Vec<u8>> {
        match self.get(key)? {
            // RFC 6979 deterministic nonces.
            Secret::P256(k) => {
                let sig: p256::ecdsa::Signature = k.sign(input.as_bytes());
                Ok(sig.to_bytes().to_vec())
            }
            Secret::Ed25519(k) => Ok(ed25519_dalek::Signer::sign(k, input.as_bytes())
                .to_bytes()
                .to_vec()),
            Secret::X25519(_) => Err(Error::WrongAlg),
        }
    }

    fn x25519(&self, key: &KeyId, peer: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
        let secret = x25519_dalek::StaticSecret::from(**self.x25519_secret(key)?);
        let shared = secret.diffie_hellman(&x25519_dalek::PublicKey::from(*peer));
        if !shared.was_contributory() {
            return Err(Error::ZeroSharedSecret);
        }
        Ok(Zeroizing::new(shared.to_bytes()))
    }

    fn hpke_open(
        &self,
        key: &KeyId,
        enc: &[u8],
        ct: &[u8],
        info: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>> {
        crate::hpke::open_with_secret(self.x25519_secret(key)?, enc, ct, info, aad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::SignLabel;
    use crate::provider::sign;

    #[test]
    fn generated_keys_sign_and_verify_under_their_alg() {
        let mut keys = SoftwareKeys::new();
        let input = SigningInput::new(SignLabel::Seen, b"{}");
        for (name, alg) in [("p", Alg::P256), ("e", Alg::Ed25519)] {
            let public = keys.generate(KeyId::new(name), alg).unwrap();
            let sig = sign(&keys, &KeyId::new(name), &input).unwrap();
            public.verify(&input, &sig).unwrap();
        }
        keys.generate(KeyId::new("x"), Alg::X25519).unwrap();
        assert_eq!(sign(&keys, &KeyId::new("x"), &input), Err(Error::WrongAlg));
        assert_eq!(
            keys.x25519(&KeyId::new("p"), &[9u8; 32]),
            Err(Error::WrongAlg)
        );
    }

    #[test]
    fn a_low_order_peer_is_refused() {
        let mut keys = SoftwareKeys::new();
        keys.generate(KeyId::new("x"), Alg::X25519).unwrap();
        assert_eq!(
            keys.x25519(&KeyId::new("x"), &[0u8; 32]),
            Err(Error::ZeroSharedSecret)
        );
    }
}

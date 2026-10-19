//! Public keys with a pinned algorithm, and signature verification (§R9.1).
//!
//! A key's `alg` is fixed when it enters the log; the verifier takes the key
//! and its `alg` from where the body names its signer, never from the signed
//! object, and nothing here negotiates or guesses an algorithm.
use ed25519_dalek::Verifier as _;
use serde_json::Value;

use crate::domain::SigningInput;
use crate::encoding::{Hash32, b64u, b64u_decode, hex};
use crate::error::{Error, Result};

/// The algorithms of §R9.1. `X25519` keys encrypt and never sign.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Alg {
    P256,
    Ed25519,
    X25519,
}

impl Alg {
    pub fn parse(name: &str) -> Result<Self> {
        match name {
            "p256" => Ok(Alg::P256),
            "ed25519" => Ok(Alg::Ed25519),
            "x25519" => Ok(Alg::X25519),
            _ => Err(Error::Malformed("unknown alg")),
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Alg::P256 => "p256",
            Alg::Ed25519 => "ed25519",
            Alg::X25519 => "x25519",
        }
    }

    /// Public key length: SEC1 uncompressed for P-256, 32 bytes otherwise.
    pub const fn public_len(self) -> usize {
        match self {
            Alg::P256 => 65,
            Alg::Ed25519 | Alg::X25519 => 32,
        }
    }
}

/// A validated public key and the algorithm pinned for it.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct PublicKey {
    alg: Alg,
    bytes: Vec<u8>,
}

impl PublicKey {
    /// Checks length and, for signing keys, that the point is on its curve.
    pub fn new(alg: Alg, bytes: &[u8]) -> Result<Self> {
        if bytes.len() != alg.public_len() {
            return Err(Error::BadKey);
        }
        match alg {
            Alg::P256 => {
                if bytes[0] != 0x04 {
                    return Err(Error::BadKey);
                }
                p256::ecdsa::VerifyingKey::from_sec1_bytes(bytes).map_err(|_| Error::BadKey)?;
            }
            Alg::Ed25519 => {
                let raw: [u8; 32] = bytes.try_into().map_err(|_| Error::BadKey)?;
                ed25519_dalek::VerifyingKey::from_bytes(&raw).map_err(|_| Error::BadKey)?;
            }
            Alg::X25519 => {}
        }
        Ok(PublicKey {
            alg,
            bytes: bytes.to_vec(),
        })
    }

    /// The wire form `{"alg": …, "pub": "<b64u>"}`, exactly those two fields.
    pub fn from_json(value: &Value) -> Result<Self> {
        let Some(object) = value.as_object() else {
            return Err(Error::Malformed("a key must be an object"));
        };
        if object.len() != 2 {
            return Err(Error::Malformed("a key has exactly alg and pub"));
        }
        let alg = object
            .get("alg")
            .and_then(Value::as_str)
            .ok_or(Error::Malformed("key alg"))?;
        let public = object
            .get("pub")
            .and_then(Value::as_str)
            .ok_or(Error::Malformed("key pub"))?;
        Self::new(Alg::parse(alg)?, &b64u_decode(public)?)
    }

    /// `from_json`, also requiring the algorithm the field is pinned to (e.g.
    /// `recovery_key` is always Ed25519, `enc_key` always X25519).
    pub fn from_json_as(value: &Value, alg: Alg) -> Result<Self> {
        let key = Self::from_json(value)?;
        if key.alg != alg {
            return Err(Error::WrongAlg);
        }
        Ok(key)
    }

    pub fn to_json(&self) -> Value {
        serde_json::json!({"alg": self.alg.as_str(), "pub": b64u(&self.bytes)})
    }

    pub fn alg(&self) -> Alg {
        self.alg
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The 32 bytes of an Ed25519 or X25519 key.
    pub fn as_32(&self) -> Option<&[u8; 32]> {
        match self.alg {
            Alg::P256 => None,
            _ => self.bytes.as_slice().try_into().ok(),
        }
    }

    /// Verifies `sig` over `input` under this key's pinned algorithm:
    /// P-256 ECDSA/SHA-256 with a 64-byte `r‖s` and low S, or RFC 8032
    /// Ed25519 with `verify_strict`. An X25519 key never verifies anything.
    pub fn verify(&self, input: &SigningInput, sig: &[u8]) -> Result<()> {
        self.verify_raw(input.as_bytes(), sig)
    }

    /// `verify` over arbitrary bytes: for primitive known-answer vectors only.
    /// Protocol code verifies a `SigningInput`, which carries its domain label.
    pub fn verify_raw(&self, message: &[u8], sig: &[u8]) -> Result<()> {
        match self.alg {
            Alg::P256 => {
                let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&self.bytes)
                    .map_err(|_| Error::BadKey)?;
                let sig =
                    p256::ecdsa::Signature::from_slice(sig).map_err(|_| Error::BadSignature)?;
                if sig.normalize_s().is_some() {
                    return Err(Error::HighS);
                }
                key.verify(message, &sig).map_err(|_| Error::BadSignature)
            }
            Alg::Ed25519 => {
                let raw: [u8; 32] = self
                    .bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| Error::BadKey)?;
                let key =
                    ed25519_dalek::VerifyingKey::from_bytes(&raw).map_err(|_| Error::BadKey)?;
                let sig: [u8; 64] = sig.try_into().map_err(|_| Error::BadSignature)?;
                let sig = ed25519_dalek::Signature::from_bytes(&sig);
                key.verify_strict(message, &sig)
                    .map_err(|_| Error::BadSignature)
            }
            Alg::X25519 => Err(Error::WrongAlg),
        }
    }
}

impl std::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PublicKey({}:{})", self.alg.as_str(), b64u(&self.bytes))
    }
}

/// The Montgomery (X25519) form of an Ed25519 public key,
/// `u = (1 + y) / (1 − y)` as libsodium's `crypto_sign_ed25519_pk_to_curve25519`
/// (§R9.5: the kit's X25519 public key from `recovery_key` alone).
pub fn ed25519_public_to_x25519(key: &PublicKey) -> Result<[u8; 32]> {
    if key.alg != Alg::Ed25519 {
        return Err(Error::WrongAlg);
    }
    let raw: [u8; 32] = key.bytes.as_slice().try_into().map_err(|_| Error::BadKey)?;
    let verifying = ed25519_dalek::VerifyingKey::from_bytes(&raw).map_err(|_| Error::BadKey)?;
    Ok(verifying.to_montgomery().to_bytes())
}

/// `enc_kid = hex(SHA-256(enc(["atem-enc-kid-v1", x25519_pub]))[0..8])`: the
/// short id of a member's `enc_key` (§R9.9).
pub fn enc_kid(enc_key: &PublicKey) -> Result<String> {
    if enc_key.alg != Alg::X25519 {
        return Err(Error::WrongAlg);
    }
    let hash = Hash32::of_enc(&[crate::domain::ENC_KID.as_bytes(), &enc_key.bytes]);
    Ok(hex(&hash.0[..8]))
}

/// Normalizes a P-256 `r‖s` to low S (signers may produce either; §R9.1
/// accepts only low S). Other algorithms pass through.
pub(crate) fn normalize_signature(alg: Alg, sig: Vec<u8>) -> Result<Vec<u8>> {
    match alg {
        Alg::P256 => {
            let parsed =
                p256::ecdsa::Signature::from_slice(&sig).map_err(|_| Error::BadSignature)?;
            Ok(match parsed.normalize_s() {
                Some(low) => low.to_bytes().to_vec(),
                None => sig,
            })
        }
        _ => Ok(sig),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::SignLabel;

    #[test]
    fn keys_are_checked_for_length_and_curve() {
        assert_eq!(PublicKey::new(Alg::P256, &[4u8; 64]), Err(Error::BadKey));
        assert_eq!(PublicKey::new(Alg::P256, &[4u8; 65]), Err(Error::BadKey));
        assert_eq!(PublicKey::new(Alg::Ed25519, &[0u8; 31]), Err(Error::BadKey));
        assert!(PublicKey::new(Alg::X25519, &[9u8; 32]).is_ok());
    }

    #[test]
    fn a_key_object_has_exactly_alg_and_pub() {
        let x = serde_json::json!({"alg": "x25519", "pub": b64u(&[9u8; 32])});
        assert!(PublicKey::from_json(&x).is_ok());
        assert_eq!(
            PublicKey::from_json_as(&x, Alg::Ed25519),
            Err(Error::WrongAlg)
        );
        let extra = serde_json::json!({"alg": "x25519", "pub": b64u(&[9u8; 32]), "kid": "a"});
        assert!(PublicKey::from_json(&extra).is_err());
    }

    #[test]
    fn an_x25519_key_never_verifies() {
        let key = PublicKey::new(Alg::X25519, &[9u8; 32]).unwrap();
        let input = SigningInput::new(SignLabel::Seen, b"{}");
        assert_eq!(key.verify(&input, &[0u8; 64]), Err(Error::WrongAlg));
    }
}

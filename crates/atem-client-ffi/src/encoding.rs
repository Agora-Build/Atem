//! Canonical JSON, `enc`, signing inputs, signatures and hashes (§R9.1):
//! the crate's own implementations, for apps that build or check a value
//! outside the objects (and for the conformance tests).
use atem_client::SignedObject;
use atem_client::canonical::{Numbers, jcs, parse_strict};
use atem_client::domain::SigningInput;
use atem_client::encoding::{Hash32, enc};
use atem_client::keys::{PublicKey, ed25519_public_to_x25519 as to_montgomery};

use crate::error::{AtemError, Result};
use crate::types::{PublicKeyData, SignLabelKind};

/// Largest JSON value the bindings parse (one session-family message).
pub(crate) const MAX_JSON: usize = 1 << 20;

pub(crate) fn strict(text: &str) -> Result<serde_json::Value> {
    Ok(
        parse_strict(text.as_bytes(), MAX_JSON, Numbers::IntegersOnly)
            .map_err(atem_client::Error::from)?,
    )
}

/// `jcs` of a value built from caller input: outside the domain (an
/// integer ≥ 2^53, a float) is a typed error, never a panic.
pub(crate) fn canonical(value: &serde_json::Value) -> Result<String> {
    jcs(value).map_err(|e| AtemError::Invalid {
        code: "not_canonical".into(),
        detail: format!("outside the canonical JSON domain: {e:?}"),
    })
}

/// `jcs` of a value for display or storage that came from verified or
/// strictly parsed state; falls back to plain JSON text rather than
/// panicking if a peer's message held a value outside the domain.
pub(crate) fn canonical_lossy(value: &serde_json::Value) -> String {
    jcs(value).unwrap_or_else(|_| value.to_string())
}

/// The largest integer every JSON consumer reads exactly (2^53 − 1).
pub(crate) const MAX_SAFE: u64 = 9_007_199_254_740_991;

/// A caller's integer that goes into a signed body: ≤ 2^53 − 1.
pub(crate) fn safe_int(value: u64, what: &str) -> Result<u64> {
    if value > MAX_SAFE {
        return Err(AtemError::Invalid {
            code: "not_canonical".into(),
            detail: format!("{what} is above 2^53 - 1"),
        });
    }
    Ok(value)
}

pub(crate) fn hash_of(hex: &str) -> Result<Hash32> {
    Ok(Hash32::from_hex(hex)?)
}

pub(crate) fn signed(text: &str) -> Result<SignedObject> {
    Ok(SignedObject::parse(text.as_bytes())?)
}

record! {
    /// What a signed object is and the values derived from it.
    pub struct SignedObjectInfo {
        /// The body's `type`.
        pub body_type: String,
        /// `jcs(body)`.
        pub body_jcs: String,
        /// `enc([label, jcs(body)])`, exactly what was signed.
        #[cfg_attr(feature = "wasm", serde(with = "serde_bytes"))]
        pub signing_input: Vec<u8>,
        /// A membership entry's `entry_hash`.
        pub entry_hash: Option<String>,
        /// A browser grant's `grant_hash`.
        pub grant_hash: Option<String>,
        /// The object back in canonical JSON.
        pub json: String,
    }
}

/// `enc(fields)`: each field as its 4-byte big-endian length then its bytes.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn encode_fields(fields: Vec<Vec<u8>>) -> Vec<u8> {
    let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    enc(&refs)
}

/// Strict I-JSON in, RFC 8785 canonical JSON out (duplicate keys, floats,
/// unsafe integers, lone surrogates … are refused).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn canonical_json(json: String) -> Result<String> {
    canonical(&strict(&json)?)
}

/// `enc([label, payload])`: the bytes a key signs.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn signing_input(label: SignLabelKind, payload: Vec<u8>) -> Vec<u8> {
    SigningInput::new(label.into(), &payload)
        .as_bytes()
        .to_vec()
}

/// Verifies `signature` over `enc([label, payload])` under the key's pinned
/// algorithm (P-256 low S only, Ed25519 strict; X25519 never verifies).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_signature(
    key: PublicKeyData,
    label: SignLabelKind,
    payload: Vec<u8>,
    signature: Vec<u8>,
) -> Result<()> {
    let key = key.to_key()?;
    Ok(key.verify(&SigningInput::new(label.into(), &payload), &signature)?)
}

/// Verifies a signature over raw bytes: for the primitive known-answer
/// vectors only (feature `test-vectors`). Protocol values are always
/// verified with their label (`verify_signature`).
#[cfg(feature = "test-vectors")]
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_raw_signature(
    key: PublicKeyData,
    message: Vec<u8>,
    signature: Vec<u8>,
) -> Result<()> {
    Ok(key.to_key()?.verify_raw(&message, &signature)?)
}

/// Checks a public key (length, curve, weak Ed25519 keys).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn check_public_key(key: PublicKeyData) -> Result<()> {
    key.to_key().map(|_| ())
}

/// Parses a signed object strictly (§R9.1: exact fields, sets and
/// sequences, no `null`, body ≤ 4096 bytes) and derives its values. The
/// signature is not verified here (it needs the signer's key from the log).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn signed_object_info(json: String) -> Result<SignedObjectInfo> {
    let object = signed(&json)?;
    Ok(SignedObjectInfo {
        body_type: object.body_type().into(),
        body_jcs: object.jcs().into(),
        signing_input: object.signing_input().as_bytes().to_vec(),
        entry_hash: object.entry_hash().map(|h| h.to_hex()),
        grant_hash: object.grant_hash().map(|h| h.to_hex()),
        json: canonical_lossy(&object.to_json()),
    })
}

/// Verifies a signed object's `sig` with `key`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn verify_signed_object(json: String, key: PublicKeyData) -> Result<()> {
    Ok(signed(&json)?.verify(&key.to_key()?)?)
}

/// `enc_kid` of an X25519 `enc_key` (§R9.9).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn enc_kid(enc_key: PublicKeyData) -> Result<String> {
    Ok(atem_client::keys::enc_kid(&enc_key.to_key()?)?)
}

/// The X25519 (Montgomery) form of an Ed25519 public key (the kit's HPKE
/// key from `recovery_key`, §R9.5; CryptoKit lacks this conversion).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn ed25519_public_to_x25519(key: PublicKeyData) -> Result<Vec<u8>> {
    let key: PublicKey = key.to_key()?;
    Ok(to_montgomery(&key)?.to_vec())
}

/// SHA-256 of `enc(fields)` (hex), the shape of every r9 hash.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn hash_fields(fields: Vec<Vec<u8>>) -> String {
    let refs: Vec<&[u8]> = fields.iter().map(Vec::as_slice).collect();
    Hash32::of_enc(&refs).to_hex()
}

pub(crate) fn not_attached() -> AtemError {
    AtemError::request("not attached")
}

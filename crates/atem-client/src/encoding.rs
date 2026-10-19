//! Byte encodings of §R9.1: `enc` (length-prefixed fields, the same as atem's
//! `src/memory/encoding.rs`), `u64` fields, base64url without padding for
//! binary in JSON, and lowercase hex for hashes.
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::{Error, Result};

/// Each field is a 4-byte big-endian length then its bytes; the label goes
/// first. Fields are bounded by the callers (a signed body is ≤ 4096 bytes).
pub fn enc(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(fields.iter().map(|field| field.len() + 4).sum());
    for field in fields {
        let len = u32::try_from(field.len()).expect("an enc field is under 4 GiB");
        out.extend_from_slice(&len.to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

/// The fields of `enc` output; refuses truncated input.
pub fn dec(mut bytes: &[u8]) -> Result<Vec<&[u8]>> {
    let mut fields = Vec::new();
    while !bytes.is_empty() {
        let Some((len, rest)) = bytes.split_first_chunk::<4>() else {
            return Err(Error::Malformed("truncated enc field length"));
        };
        let len = u32::from_be_bytes(*len) as usize;
        if rest.len() < len {
            return Err(Error::Malformed("truncated enc field"));
        }
        let (field, rest) = rest.split_at(len);
        fields.push(field);
        bytes = rest;
    }
    Ok(fields)
}

/// An integer inside `enc`: 8 bytes, big-endian.
pub fn u64_field(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

/// base64url without padding (`b64u`).
pub fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Strict `b64u` decode: no padding, no other alphabet, no non-zero trailing
/// bits (so every value has exactly one encoding).
pub fn b64u_decode(text: &str) -> Result<Vec<u8>> {
    URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| Error::Malformed("not base64url without padding"))
}

/// `b64u_decode` of exactly `N` bytes.
pub fn b64u_decode_array<const N: usize>(text: &str) -> Result<[u8; N]> {
    b64u_decode(text)?
        .try_into()
        .map_err(|_| Error::Malformed("base64url value of the wrong length"))
}

/// Lowercase hex.
pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}

/// Strict lowercase hex of exactly `N` bytes (`2N` characters).
pub fn hex_decode_array<const N: usize>(text: &str) -> Result<[u8; N]> {
    let digits = text.as_bytes();
    if digits.len() != 2 * N {
        return Err(Error::Malformed("hex value of the wrong length"));
    }
    let nibble = |d: u8| match d {
        b'0'..=b'9' => Ok(d - b'0'),
        b'a'..=b'f' => Ok(d - b'a' + 10),
        _ => Err(Error::Malformed("not lowercase hex")),
    };
    let mut out = [0u8; N];
    for (i, pair) in digits.chunks_exact(2).enumerate() {
        out[i] = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(out)
}

/// A SHA-256 value: hashes inside `enc` are these 32 raw bytes, in JSON the
/// 64-character lowercase hex (§R9.1). Equality is constant-time.
#[derive(Clone, Copy)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    pub fn of(bytes: &[u8]) -> Self {
        Hash32(Sha256::digest(bytes).into())
    }

    /// `SHA-256(enc(fields))`.
    pub fn of_enc(fields: &[&[u8]]) -> Self {
        Self::of(&enc(fields))
    }

    pub fn from_hex(text: &str) -> Result<Self> {
        hex_decode_array(text).map(Hash32)
    }

    pub fn to_hex(&self) -> String {
        hex(&self.0)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl PartialEq for Hash32 {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for Hash32 {}

impl std::fmt::Debug for Hash32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Hash32({})", self.to_hex())
    }
}

/// Constant-time equality of two byte strings (lengths are not secret).
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && bool::from(a.ct_eq(b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enc_round_trips_and_keeps_boundaries() {
        let fields: [&[u8]; 4] = [b"label", b"", b"\x00\x01", b"abc"];
        assert_eq!(dec(&enc(&fields)).unwrap(), fields.to_vec());
        assert_ne!(enc(&[b"a/b", b"cd"]), enc(&[b"a/bc", b"d"]));
        let mut bytes = enc(&[b"label", b"value"]);
        bytes.pop();
        assert!(dec(&bytes).is_err());
        assert!(dec(&[0, 0]).is_err());
    }

    #[test]
    fn b64u_is_strict() {
        assert_eq!(b64u(b"\xfb\xff"), "-_8");
        assert_eq!(b64u_decode("-_8").unwrap(), b"\xfb\xff");
        assert!(b64u_decode("-_8=").is_err(), "padding");
        assert!(b64u_decode("+/8").is_err(), "standard alphabet");
        assert!(b64u_decode("-_9").is_err(), "non-zero trailing bits");
    }

    #[test]
    fn hex_is_lowercase_and_exact() {
        assert_eq!(hex(&[0xab, 0x01]), "ab01");
        assert_eq!(hex_decode_array::<2>("ab01").unwrap(), [0xab, 0x01]);
        assert!(hex_decode_array::<2>("AB01").is_err());
        assert!(hex_decode_array::<2>("ab0").is_err());
        assert!(hex_decode_array::<2>("ab0102").is_err());
    }
}

//! Length-prefixed encoding for every signed, hashed or bound input: each
//! field is a 4-byte big-endian length followed by its bytes, label first.
//! See designs/e2e-encryption.md "Formats".
use anyhow::{Result, anyhow, bail};

pub fn enc(fields: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(fields.iter().map(|field| field.len() + 4).sum());
    for field in fields {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field);
    }
    out
}

pub fn dec(mut bytes: &[u8]) -> Result<Vec<Vec<u8>>> {
    let mut fields = Vec::new();
    while !bytes.is_empty() {
        if bytes.len() < 4 {
            bail!("encoded statement is truncated");
        }
        let len = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        bytes = &bytes[4..];
        if bytes.len() < len {
            bail!("encoded statement is truncated");
        }
        fields.push(bytes[..len].to_vec());
        bytes = &bytes[len..];
    }
    Ok(fields)
}

pub fn u64_field(value: u64) -> [u8; 8] {
    value.to_be_bytes()
}

pub fn read_u64(field: &[u8]) -> Result<u64> {
    let bytes: [u8; 8] = field
        .try_into()
        .map_err(|_| anyhow!("expected an 8-byte number"))?;
    Ok(u64::from_be_bytes(bytes))
}

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The first `chars` base32 characters of `bytes` (RFC 4648 alphabet, no padding).
pub fn base32_prefix(bytes: &[u8], chars: usize) -> String {
    let mut out = String::with_capacity(chars);
    let (mut buffer, mut bits) = (0u32, 0u32);
    for &byte in bytes {
        buffer = (buffer << 8) | u32::from(byte);
        bits += 8;
        while bits >= 5 {
            if out.len() == chars {
                return out;
            }
            bits -= 5;
            out.push(BASE32[((buffer >> bits) & 31) as usize] as char);
        }
        buffer &= (1 << bits) - 1;
    }
    // Final partial group: zero-pad to 5 bits, as RFC 4648 does.
    if bits > 0 && out.len() < chars {
        out.push(BASE32[((buffer << (5 - bits)) & 31) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_keeps_every_field() {
        let fields: Vec<&[u8]> = vec![b"label", b"", b"\x00\x01", b"abc"];
        let bytes = enc(&fields);
        let back = dec(&bytes).unwrap();
        assert_eq!(back, fields.iter().map(|f| f.to_vec()).collect::<Vec<_>>());
    }

    #[test]
    fn field_boundaries_cannot_shift() {
        assert_ne!(enc(&[b"a/b", b"cd"]), enc(&[b"a/bc", b"d"]));
    }

    #[test]
    fn truncated_input_is_rejected() {
        let mut bytes = enc(&[b"label", b"value"]);
        bytes.pop();
        assert!(dec(&bytes).is_err());
        assert!(dec(&[0, 0]).is_err());
    }

    #[test]
    fn u64_fields_round_trip() {
        assert_eq!(
            read_u64(&u64_field(0x0102_0304_0506_0708)).unwrap(),
            0x0102_0304_0506_0708
        );
        assert!(read_u64(b"short").is_err());
    }

    #[test]
    fn base32_matches_rfc4648() {
        assert_eq!(base32_prefix(b"foobar", 10), "MZXW6YTBOI");
        assert_eq!(base32_prefix(b"foobar", 4), "MZXW");
        assert_eq!(base32_prefix(&[0xff; 32], 12), "777777777777");
    }
}

//! Binary frames for `Crypt` on the cred agent's socket: the bytes to seal
//! or hash and the opened bytes travel raw, with no base64 and no JSON pass,
//! and each buffer is allocated once at its declared length. Every other
//! request, and every connection that didn't agree to frames, stays on v2
//! JSON lines (agent_socket.rs). See designs/e2e-encryption.md "Keys on disk
//! (atem)".
//!
//! **Agreement, per connection.** An agent that reads frames says so in its
//! answer to a `status` (`"frames": 1`, [`VERSION`]) and from then on reads
//! frames on that connection, beside JSON lines. A client sends a `Crypt` as
//! a frame only on a connection whose build check got that answer, and only
//! when it fits the bounds below (else as a JSON line). A released agent
//! (v0.6.11 to v0.8.3) never says it, so a client keeps JSON lines with it;
//! a released client never asks, so the agent never reads a frame from it.
//!
//! **Layout.** A header, then the body; integers are little-endian.
//!
//! | bytes | field |
//! |---|---|
//! | 1 | [`MAGIC`] (0xFF): never the first byte of a JSON line, which is UTF-8 |
//! | 1 | kind |
//! | 4 | count: the request's ops, the reply's results (0 for `REPLY_JSON`) |
//! | 4 | body length |
//!
//! A field is a 4-byte length and its bytes; names and `e1.`/`h1.` texts are
//! UTF-8.
//! - `REQUEST_CRYPT`: `astation_id`, then `count` ops, each a tag and its
//!   fields: `SEAL` (record, field, plain), `OPEN` (record, field, `e1.`
//!   value), `HASH` (value), `HASH_UNDER` (kid, value).
//! - `REPLY_CRYPTED`: `count` results, in the order of the ops, each a tag
//!   (`SEALED`, `OPENED`, `HASHED`) and one field.
//! - `REPLY_JSON`: the v2 JSON response (a refusal, worded as on a line).
//!
//! **Bounds first.** A request names 1 to 1,024 ops and at most 2 MiB of
//! body, or 6 MiB for one op alone: the batches `EncryptionContext` makes. A
//! reply names its request's count and at most `MAX_REPLY`. Both are checked
//! on the header, before the body is allocated (once, at its declared
//! length), and every field must fit in what is left of its body. Anything
//! else is malformed: the agent closes the connection, the client drops it.
use anyhow::{Result, bail};

use crate::memory::account_keys::{CryptOp, CryptOut};
use crate::memory::crypto::{CRYPT_BATCH_BYTES, CRYPT_BATCH_OPS, CRYPT_OP_MAX_BYTES};
use crate::memory::encoding::{SecretBytes, WipingBuf};

/// The frames this build reads and writes, as its `status` names them.
pub(crate) const VERSION: u32 = 1;
pub(crate) const MAGIC: u8 = 0xFF;
pub(crate) const HEADER: usize = 10;

pub(crate) const REQUEST_CRYPT: u8 = 1;
pub(crate) const REPLY_CRYPTED: u8 = 1;
pub(crate) const REPLY_JSON: u8 = 2;

const SEAL: u8 = 1;
const OPEN: u8 = 2;
const HASH: u8 = 3;
const HASH_UNDER: u8 = 4;

const SEALED: u8 = 1;
const OPENED: u8 = 2;
const HASHED: u8 = 3;

/// A field's length prefix.
const FIELD: usize = 4;

/// The longest reply body a client reads. A reply is at most 4/3 of its
/// request (the `e1.` text of what it seals is base64) plus under 80 bytes
/// a result: every reply to a request within the bounds fits.
const MAX_REPLY: usize = CRYPT_OP_MAX_BYTES * 2;

/// A frame's header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Head {
    pub(crate) kind: u8,
    pub(crate) count: usize,
    pub(crate) len: usize,
}

fn parse_head(bytes: &[u8; HEADER]) -> Result<Head> {
    if bytes[0] != MAGIC {
        bail!("not a frame");
    }
    let number = |at: usize| {
        u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]) as usize
    };
    Ok(Head {
        kind: bytes[1],
        count: number(2),
        len: number(6),
    })
}

/// The most body a request of `count` ops may have.
fn request_limit(count: usize) -> usize {
    if count == 1 {
        CRYPT_OP_MAX_BYTES
    } else {
        CRYPT_BATCH_BYTES
    }
}

/// A request's header, within the bounds.
pub(crate) fn request_head(bytes: &[u8; HEADER]) -> Result<Head> {
    let head = parse_head(bytes)?;
    if head.kind != REQUEST_CRYPT {
        bail!("a frame of unknown kind {}", head.kind);
    }
    if head.count == 0 || head.count > CRYPT_BATCH_OPS {
        bail!("a frame of {} ops", head.count);
    }
    if head.len > request_limit(head.count) {
        bail!("a frame of {} bytes for {} ops", head.len, head.count);
    }
    Ok(head)
}

/// The header of the reply to a request of `count` ops, within the bounds.
pub(crate) fn reply_head(bytes: &[u8; HEADER], count: usize) -> Result<Head> {
    let head = parse_head(bytes)?;
    let named = match head.kind {
        REPLY_CRYPTED => count,
        REPLY_JSON => 0,
        kind => bail!("a reply frame of unknown kind {kind}"),
    };
    if head.count != named || head.len > MAX_REPLY {
        bail!(
            "a reply frame of {} results and {} bytes",
            head.count,
            head.len
        );
    }
    Ok(head)
}

/// A frame of `len` body bytes being written: allocated at its full size
/// (it grows only by wiped copies, should the size ever be wrong).
fn frame(kind: u8, count: usize, len: usize) -> WipingBuf {
    let mut out = WipingBuf::with_capacity(HEADER + len);
    out.append(&[MAGIC, kind]);
    // Within the bounds, so both fit in a u32.
    out.append(&(count as u32).to_le_bytes());
    out.append(&(len as u32).to_le_bytes());
    out
}

fn put(out: &mut WipingBuf, field: &[u8]) {
    out.append(&(field.len() as u32).to_le_bytes());
    out.append(field);
}

/// `ops` for `astation_id` as a request frame; `None` when they don't fit
/// the bounds (they then go as a JSON line).
pub(crate) fn crypt_request(astation_id: &str, ops: &[CryptOp]) -> Option<SecretBytes> {
    let mut len = FIELD + astation_id.len();
    for op in ops {
        len += 1 + match op {
            CryptOp::Seal {
                record,
                field,
                plain,
            } => 3 * FIELD + record.len() + field.len() + plain.len(),
            CryptOp::Open {
                record,
                field,
                value,
            } => 3 * FIELD + record.len() + field.len() + value.len(),
            CryptOp::KeyedHash { value, kid: None } => FIELD + value.len(),
            CryptOp::KeyedHash {
                value,
                kid: Some(kid),
            } => 2 * FIELD + kid.len() + value.len(),
        };
    }
    if ops.is_empty() || ops.len() > CRYPT_BATCH_OPS || len > request_limit(ops.len()) {
        return None;
    }
    let mut out = frame(REQUEST_CRYPT, ops.len(), len);
    put(&mut out, astation_id.as_bytes());
    for op in ops {
        match op {
            CryptOp::Seal {
                record,
                field,
                plain,
            } => {
                out.append(&[SEAL]);
                put(&mut out, record.as_bytes());
                put(&mut out, field.as_bytes());
                put(&mut out, plain);
            }
            CryptOp::Open {
                record,
                field,
                value,
            } => {
                out.append(&[OPEN]);
                put(&mut out, record.as_bytes());
                put(&mut out, field.as_bytes());
                put(&mut out, value.as_bytes());
            }
            CryptOp::KeyedHash { value, kid: None } => {
                out.append(&[HASH]);
                put(&mut out, value);
            }
            CryptOp::KeyedHash {
                value,
                kid: Some(kid),
            } => {
                out.append(&[HASH_UNDER]);
                put(&mut out, kid.as_bytes());
                put(&mut out, value);
            }
        }
    }
    Some(out.into_secret())
}

/// Reads fields off a body, refusing any that runs past its end.
struct Fields<'a>(&'a [u8]);

impl<'a> Fields<'a> {
    fn tag(&mut self) -> Result<u8> {
        let Some((&tag, rest)) = self.0.split_first() else {
            bail!("a frame ends early");
        };
        self.0 = rest;
        Ok(tag)
    }

    fn bytes(&mut self) -> Result<&'a [u8]> {
        let Some((len, rest)) = self.0.split_first_chunk::<FIELD>() else {
            bail!("a frame ends early");
        };
        let len = u32::from_le_bytes(*len) as usize;
        if len > rest.len() {
            bail!("a frame's field runs past its end");
        }
        let (field, rest) = rest.split_at(len);
        self.0 = rest;
        Ok(field)
    }

    fn text(&mut self) -> Result<String> {
        match std::str::from_utf8(self.bytes()?) {
            Ok(text) => Ok(text.to_string()),
            Err(_) => bail!("a frame's text field is not UTF-8"),
        }
    }

    fn secret(&mut self) -> Result<SecretBytes> {
        Ok(SecretBytes::copy_of(self.bytes()?))
    }

    fn end(&self) -> Result<()> {
        if !self.0.is_empty() {
            bail!("a frame has {} bytes past its last field", self.0.len());
        }
        Ok(())
    }
}

/// The `astation_id` and ops of a request frame's body.
pub(crate) fn decode_crypt(head: Head, body: &[u8]) -> Result<(String, Vec<CryptOp>)> {
    let mut body = Fields(body);
    let astation_id = body.text()?;
    // At most `CRYPT_BATCH_OPS` (`request_head`).
    let mut ops = Vec::with_capacity(head.count);
    for _ in 0..head.count {
        let op = match body.tag()? {
            tag @ (SEAL | OPEN) => {
                let record = body.text()?;
                let field = body.text()?;
                if tag == SEAL {
                    CryptOp::Seal {
                        record,
                        field,
                        plain: body.secret()?,
                    }
                } else {
                    CryptOp::Open {
                        record,
                        field,
                        value: body.text()?,
                    }
                }
            }
            HASH => CryptOp::KeyedHash {
                value: body.secret()?,
                kid: None,
            },
            HASH_UNDER => {
                let kid = body.text()?;
                CryptOp::KeyedHash {
                    value: body.secret()?,
                    kid: Some(kid),
                }
            }
            tag => bail!("a frame names unknown op {tag}"),
        };
        ops.push(op);
    }
    body.end()?;
    Ok((astation_id, ops))
}

/// `results` as a reply frame.
pub(crate) fn crypted_reply(results: &[CryptOut]) -> SecretBytes {
    let bytes = |result: &CryptOut| -> usize {
        match result {
            CryptOut::Sealed(text) | CryptOut::Hashed(text) => text.len(),
            CryptOut::Opened(plain) => plain.len(),
        }
    };
    let len = results.iter().map(|result| 1 + FIELD + bytes(result)).sum();
    let mut out = frame(REPLY_CRYPTED, results.len(), len);
    for result in results {
        match result {
            CryptOut::Sealed(text) => {
                out.append(&[SEALED]);
                put(&mut out, text.as_bytes());
            }
            CryptOut::Opened(plain) => {
                out.append(&[OPENED]);
                put(&mut out, plain);
            }
            CryptOut::Hashed(text) => {
                out.append(&[HASHED]);
                put(&mut out, text.as_bytes());
            }
        }
    }
    out.into_secret()
}

/// A JSON response (a refusal) as a reply frame.
pub(crate) fn json_reply(json: &[u8]) -> SecretBytes {
    let mut out = frame(REPLY_JSON, 0, json.len());
    out.append(json);
    out.into_secret()
}

/// The results of a `REPLY_CRYPTED` body.
pub(crate) fn decode_crypted(head: Head, body: &[u8]) -> Result<Vec<CryptOut>> {
    let mut body = Fields(body);
    // At most the request's count (`reply_head`).
    let mut results = Vec::with_capacity(head.count);
    for _ in 0..head.count {
        let result = match body.tag()? {
            SEALED => CryptOut::Sealed(body.text()?),
            OPENED => CryptOut::Opened(body.secret()?),
            HASHED => CryptOut::Hashed(body.text()?),
            tag => bail!("a reply frame names unknown result {tag}"),
        };
        results.push(result);
    }
    body.end()?;
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head_of(frame: &[u8]) -> [u8; HEADER] {
        frame[..HEADER].try_into().unwrap()
    }

    fn mixed_ops() -> Vec<CryptOp> {
        vec![
            CryptOp::seal("mem-1", "content", b"SECRET \x00\xff bytes"),
            CryptOp::open("mem-1", "content", "e1.0123abcd.AAAA"),
            CryptOp::keyed_hash(b"github.com/agora/atem"),
            CryptOp::keyed_hash_under(b"github.com/agora/atem", "89abcdef"),
            CryptOp::seal("", "", b""),
        ]
    }

    /// What an op holds, to compare ops that went through a frame.
    fn shape(op: &CryptOp) -> (u8, String, String, Vec<u8>, Option<String>) {
        match op {
            CryptOp::Seal {
                record,
                field,
                plain,
            } => (SEAL, record.clone(), field.clone(), plain.to_vec(), None),
            CryptOp::Open {
                record,
                field,
                value,
            } => (
                OPEN,
                record.clone(),
                field.clone(),
                value.clone().into(),
                None,
            ),
            CryptOp::KeyedHash { value, kid } => (
                HASH,
                String::new(),
                String::new(),
                value.to_vec(),
                kid.clone(),
            ),
        }
    }

    #[test]
    fn a_request_frame_carries_every_op_raw_and_exactly_sized() {
        let ops = mixed_ops();
        let frame = crypt_request("astation-1", &ops).unwrap();
        // Raw: the plain text is in the frame as it is, never base64.
        assert!(frame.windows(9).any(|w| w == b"SECRET \x00\xff"));
        let head = request_head(&head_of(&frame)).unwrap();
        assert_eq!((head.kind, head.count), (REQUEST_CRYPT, ops.len()));
        assert_eq!(HEADER + head.len, frame.len(), "one allocation of its size");
        let (astation, back) = decode_crypt(head, &frame[HEADER..]).unwrap();
        assert_eq!(astation, "astation-1");
        assert_eq!(
            back.iter().map(shape).collect::<Vec<_>>(),
            ops.iter().map(shape).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_reply_frame_carries_every_result() {
        let results = vec![
            CryptOut::Sealed("e1.0123abcd.AAAA".into()),
            CryptOut::Opened(SecretBytes::copy_of(b"opened \x00 bytes")),
            CryptOut::Hashed("h1.0123abcd.00".into()),
            CryptOut::Opened(SecretBytes::default()),
        ];
        let frame = crypted_reply(&results);
        let head = reply_head(&head_of(&frame), 4).unwrap();
        assert_eq!(HEADER + head.len, frame.len());
        let back = decode_crypted(head, &frame[HEADER..]).unwrap();
        let mut back = back.into_iter();
        assert_eq!(
            back.next().unwrap().into_text().unwrap(),
            "e1.0123abcd.AAAA"
        );
        assert_eq!(
            &back.next().unwrap().into_plain().unwrap()[..],
            b"opened \x00 bytes"
        );
        assert_eq!(back.next().unwrap().into_text().unwrap(), "h1.0123abcd.00");
        assert!(back.next().unwrap().into_plain().unwrap().is_empty());
        // A reply to another count, or of another kind, is refused.
        assert!(reply_head(&head_of(&frame), 3).is_err());
        let refusal = json_reply(br#"{"v":2,"ok":false,"error":"locked"}"#);
        let head = reply_head(&head_of(&refusal), 4).unwrap();
        assert_eq!((head.kind, head.count), (REPLY_JSON, 0));
        assert_eq!(
            &refusal[HEADER..],
            br#"{"v":2,"ok":false,"error":"locked"}"#
        );
    }

    #[test]
    fn the_bounds_are_the_batches_encryption_contexts_make() {
        // 1,024 keyed hashes (a tag, a length, the value each) for the
        // astation id "a" (a length and one byte): exactly 2 MiB of body.
        let op = |n: usize| CryptOp::keyed_hash(&vec![b'x'; n]);
        let batch = |last: usize| -> Vec<CryptOp> {
            let mut ops: Vec<CryptOp> = (0..1023).map(|_| op(2042)).collect();
            ops.push(op(last));
            ops
        };
        let at_limit = 2042 + (2 << 20) - (1024 * (1 + 4 + 2042) + 4 + 1);
        let frame = crypt_request("a", &batch(at_limit)).unwrap();
        assert_eq!(frame.len() - HEADER, 2 << 20, "exactly at the limit");
        let head = request_head(&head_of(&frame)).unwrap();
        assert_eq!(decode_crypt(head, &frame[HEADER..]).unwrap().1.len(), 1024);
        // One byte more, or one op more, doesn't go as a frame.
        assert!(crypt_request("a", &batch(at_limit + 1)).is_none());
        let more: Vec<CryptOp> = (0..1025).map(|_| op(1)).collect();
        assert!(crypt_request("a", &more).is_none());
        assert!(crypt_request("a", &[]).is_none(), "no empty frame");
        // One op alone may be bigger, up to 6 MiB: 20 bytes of ids, tag and
        // lengths, then the plain text.
        let big = CryptOp::seal("r", "f", &vec![7; (6 << 20) - 20]);
        let frame = crypt_request("a", std::slice::from_ref(&big)).unwrap();
        assert_eq!(frame.len() - HEADER, 6 << 20);
        let head = request_head(&head_of(&frame)).unwrap();
        let (_, back) = decode_crypt(head, &frame[HEADER..]).unwrap();
        assert_eq!(back[0].field_len(), big.field_len());
        let bigger = CryptOp::seal("r", "f", &vec![7; (6 << 20) - 19]);
        assert!(crypt_request("a", &[bigger]).is_none());
    }

    /// A header with these fields.
    fn header(kind: u8, count: u32, len: u32) -> [u8; HEADER] {
        let mut head = [0u8; HEADER];
        head[0] = MAGIC;
        head[1] = kind;
        head[2..6].copy_from_slice(&count.to_le_bytes());
        head[6..10].copy_from_slice(&len.to_le_bytes());
        head
    }

    #[test]
    fn a_header_out_of_bounds_is_refused_before_anything_is_allocated() {
        assert!(request_head(&header(REQUEST_CRYPT, 1, 6 << 20)).is_ok());
        assert!(request_head(&header(REQUEST_CRYPT, 2, 2 << 20)).is_ok());
        for (kind, count, len) in [
            (REQUEST_CRYPT, 0, 0),
            (REQUEST_CRYPT, 1025, 100),
            (REQUEST_CRYPT, 1, (6 << 20) + 1),
            (REQUEST_CRYPT, 2, (2 << 20) + 1),
            (REQUEST_CRYPT, u32::MAX, u32::MAX),
            (REQUEST_CRYPT, 1, u32::MAX),
            (0, 1, 10),
            (2, 1, 10),
            (0xFF, 1, 10),
        ] {
            assert!(
                request_head(&header(kind, count, len)).is_err(),
                "{kind} {count} {len}"
            );
        }
        let mut not_magic = header(REQUEST_CRYPT, 1, 10);
        not_magic[0] = b'{';
        assert!(request_head(&not_magic).is_err());
        assert!(reply_head(&header(REPLY_CRYPTED, 1, (12 << 20) + 1), 1).is_err());
        assert!(reply_head(&header(REPLY_JSON, 1, 10), 1).is_err());
        assert!(reply_head(&header(3, 1, 10), 1).is_err());
    }

    #[test]
    fn every_truncation_of_a_body_is_refused_without_a_panic() {
        let frame = crypt_request("astation-1", &mixed_ops()).unwrap();
        let head = request_head(&head_of(&frame)).unwrap();
        let body = &frame[HEADER..];
        for cut in 0..body.len() {
            assert!(decode_crypt(head, &body[..cut]).is_err(), "cut at {cut}");
        }
        let mut longer = body.to_vec();
        longer.push(0);
        assert!(decode_crypt(head, &longer).is_err(), "a byte past the end");
        let reply = crypted_reply(&[
            CryptOut::Sealed("e1.x".into()),
            CryptOut::Opened(SecretBytes::copy_of(b"hi")),
        ]);
        let head = reply_head(&head_of(&reply), 2).unwrap();
        for cut in 0..reply.len() - HEADER {
            assert!(decode_crypted(head, &reply[HEADER..HEADER + cut]).is_err());
        }
    }

    #[test]
    fn wrong_lengths_tags_and_counts_are_refused() {
        let frame = crypt_request("a", &[CryptOp::seal("r", "f", b"plain")]).unwrap();
        let head = request_head(&head_of(&frame)).unwrap();
        let body = frame[HEADER..].to_vec();
        // The astation id's length is 4 bytes at the start of the body.
        let mut long_field = body.clone();
        long_field[0..4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(decode_crypt(head, &long_field).is_err());
        let mut tag = body.clone();
        tag[5] = 9;
        let error = decode_crypt(head, &tag).err().unwrap();
        assert!(format!("{error:#}").contains("unknown op"), "{error:#}");
        // The header names two ops, the body holds one.
        let two = Head { count: 2, ..head };
        assert!(decode_crypt(two, &body).is_err());
        // Not UTF-8 where a name goes.
        let mut name = body.clone();
        name[4] = 0xFF;
        assert!(decode_crypt(head, &name).is_err());
        let reply = crypted_reply(&[CryptOut::Hashed("h1".into())]);
        let mut bad = reply[HEADER..].to_vec();
        bad[0] = 7;
        let head = reply_head(&head_of(&reply), 1).unwrap();
        assert!(decode_crypted(head, &bad).is_err());
    }

    #[test]
    fn random_bytes_never_panic_the_parsers() {
        // xorshift64: no dependency, the same bytes every run.
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        let valid = crypt_request("astation-1", &mixed_ops()).unwrap();
        for round in 0..20_000 {
            let len = (next() % 160) as usize;
            let mut bytes: Vec<u8> = if round % 2 == 0 {
                (0..len).map(|_| next() as u8).collect()
            } else {
                // A valid frame with a few bytes changed.
                let mut bytes = valid.to_vec();
                for _ in 0..1 + next() % 3 {
                    let at = (next() as usize) % bytes.len();
                    bytes[at] = next() as u8;
                }
                bytes
            };
            bytes.resize(bytes.len().max(HEADER), 0);
            let head = head_of(&bytes);
            if let Ok(head) = request_head(&head) {
                let body = &bytes[HEADER..];
                let _ = decode_crypt(head, &body[..body.len().min(head.len)]);
            }
            let count = (next() % 4) as usize;
            if let Ok(head) = reply_head(&head, count) {
                let body = &bytes[HEADER..];
                let _ = decode_crypted(head, &body[..body.len().min(head.len)]);
            }
            let any = Head {
                kind: REQUEST_CRYPT,
                count: 1 + (next() % 8) as usize,
                len: bytes.len(),
            };
            let _ = decode_crypt(any, &bytes);
            let _ = decode_crypted(any, &bytes);
        }
    }
}

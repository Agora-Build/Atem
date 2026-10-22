//! `atem-ch1` transport frames (§R9.7 table): JSON text frames, parsed
//! strictly (`parse_strict`: no duplicate keys, integers only) with exactly
//! the fields of their `op`. A frame without `ch` is a plain message
//! outside any channel ([`Parsed::Plain`]); a frame with another `ch`, an
//! unknown `op` or a field too many is malformed.
use serde_json::{Map, Value, json};

use super::{ClearCode, MAX_PLAINTEXT};
use crate::canonical::{StrictValue, parse_strict};
use crate::encoding::{Hash32, b64u, b64u_decode, b64u_decode_array};
use crate::membership::Head;
use crate::membership::entry::id_ok;

/// The channel name every frame carries.
pub const CH: &str = "atem-ch1";
/// Poly1305 tag.
pub const TAG_LEN: usize = 16;

/// Length of `b64u` (no padding) of `n` bytes.
pub const fn b64u_len(n: usize) -> usize {
    (n * 4).div_ceil(3)
}

/// The largest frame accepted: a `finish` or `rec` of a 1 MiB plaintext.
/// Anything longer is refused before it is parsed.
pub const MAX_FRAME_BYTES: usize = b64u_len(MAX_PLAINTEXT + TAG_LEN) + 64;

/// Longest error `code` accepted.
const MAX_CODE: usize = 64;

/// Message 1, C→H.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Init {
    pub e: [u8; 32],
    pub n: [u8; 32],
    pub genesis_hash: Hash32,
    pub host_id: String,
    pub host_trust_gen: u64,
}

/// Message 2, H→C.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Accept {
    pub e: [u8; 32],
    pub n: [u8; 32],
    pub head: Head,
    pub sig: Vec<u8>,
}

/// One channel frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Init(Init),
    Accept(Accept),
    /// Message 3: the `hello` sealed under `k_fin`.
    Finish {
        ct: Vec<u8>,
    },
    /// Messages 4…: a record.
    Rec {
        ct: Vec<u8>,
    },
    /// A clear error (before message 4), then close.
    Error {
        code: String,
    },
}

/// What a transport frame is.
#[derive(Debug, Clone, PartialEq)]
pub enum Parsed {
    Channel(Frame),
    /// A JSON object without `ch`: a session message outside any channel
    /// (refused as before `welcome`, §R9.8; the caller answers it).
    Plain(StrictValue),
}

/// Not a frame of `atem-ch1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Malformed(pub &'static str);

fn exact(object: &Map<String, Value>, fields: &[&str]) -> Result<(), Malformed> {
    if object.len() != fields.len() || fields.iter().any(|f| !object.contains_key(*f)) {
        return Err(Malformed("fields"));
    }
    Ok(())
}

fn string<'a>(object: &'a Map<String, Value>, name: &'static str) -> Result<&'a str, Malformed> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or(Malformed(name))
}

fn bytes32(object: &Map<String, Value>, name: &'static str) -> Result<[u8; 32], Malformed> {
    b64u_decode_array::<32>(string(object, name)?).map_err(|_| Malformed(name))
}

fn ciphertext(object: &Map<String, Value>) -> Result<Vec<u8>, Malformed> {
    let ct = b64u_decode(string(object, "ct")?).map_err(|_| Malformed("ct"))?;
    if ct.len() < TAG_LEN || ct.len() > MAX_PLAINTEXT + TAG_LEN {
        return Err(Malformed("ct length"));
    }
    Ok(ct)
}

fn positive(value: Option<&Value>, name: &'static str) -> Result<u64, Malformed> {
    value
        .and_then(Value::as_u64)
        .filter(|n| *n >= 1)
        .ok_or(Malformed(name))
}

fn code(text: &str) -> Result<String, Malformed> {
    let ok = !text.is_empty()
        && text.len() <= MAX_CODE
        && text.bytes().all(|b| b.is_ascii_lowercase() || b == b'_');
    ok.then(|| text.to_owned()).ok_or(Malformed("code"))
}

/// Parses one transport frame.
pub fn parse(bytes: &[u8]) -> Result<Parsed, Malformed> {
    let value =
        StrictValue::parse(bytes, MAX_FRAME_BYTES).map_err(|_| Malformed("not strict JSON"))?;
    let object = value
        .value()
        .as_object()
        .ok_or(Malformed("not an object"))?;
    let Some(ch) = object.get("ch") else {
        return Ok(Parsed::Plain(value));
    };
    if ch.as_str() != Some(CH) {
        return Err(Malformed("ch"));
    }
    Ok(Parsed::Channel(frame_of(object)?))
}

/// Parses a frame that must belong to the channel.
pub fn parse_frame(bytes: &[u8]) -> Result<Frame, Malformed> {
    match parse(bytes)? {
        Parsed::Channel(frame) => Ok(frame),
        Parsed::Plain(_) => Err(Malformed("ch")),
    }
}

/// A frame from a strictly parsed value (the restore's `init`/`accept`).
pub fn frame_of_value(value: &StrictValue) -> Result<Frame, Malformed> {
    let object = value
        .value()
        .as_object()
        .ok_or(Malformed("not an object"))?;
    if object.get("ch").and_then(Value::as_str) != Some(CH) {
        return Err(Malformed("ch"));
    }
    frame_of(object)
}

fn frame_of(object: &Map<String, Value>) -> Result<Frame, Malformed> {
    match string(object, "op")? {
        "init" => {
            exact(
                object,
                &[
                    "ch",
                    "op",
                    "e",
                    "n",
                    "genesis_hash",
                    "host_id",
                    "host_trust_gen",
                ],
            )?;
            Ok(Frame::Init(Init {
                e: bytes32(object, "e")?,
                n: bytes32(object, "n")?,
                genesis_hash: Hash32::from_hex(string(object, "genesis_hash")?)
                    .map_err(|_| Malformed("genesis_hash"))?,
                host_id: Some(string(object, "host_id")?)
                    .filter(|h| id_ok(h))
                    .ok_or(Malformed("host_id"))?
                    .to_owned(),
                host_trust_gen: positive(object.get("host_trust_gen"), "host_trust_gen")?,
            }))
        }
        "accept" => {
            exact(object, &["ch", "op", "e", "n", "head", "sig"])?;
            let head = object
                .get("head")
                .and_then(Value::as_object)
                .ok_or(Malformed("head"))?;
            exact(head, &["seq", "hash"])?;
            let sig = b64u_decode(string(object, "sig")?).map_err(|_| Malformed("sig"))?;
            if sig.len() != 64 {
                return Err(Malformed("sig"));
            }
            Ok(Frame::Accept(Accept {
                e: bytes32(object, "e")?,
                n: bytes32(object, "n")?,
                head: Head {
                    seq: positive(head.get("seq"), "head.seq")?,
                    hash: Hash32::from_hex(string(head, "hash")?)
                        .map_err(|_| Malformed("head.hash"))?,
                },
                sig,
            }))
        }
        "finish" => {
            exact(object, &["ch", "op", "ct"])?;
            Ok(Frame::Finish {
                ct: ciphertext(object)?,
            })
        }
        "rec" => {
            exact(object, &["ch", "op", "ct"])?;
            Ok(Frame::Rec {
                ct: ciphertext(object)?,
            })
        }
        "error" => {
            exact(object, &["ch", "op", "code"])?;
            Ok(Frame::Error {
                code: code(string(object, "code")?)?,
            })
        }
        _ => Err(Malformed("op")),
    }
}

impl Frame {
    /// The frame's wire bytes.
    pub fn to_bytes(&self) -> Vec<u8> {
        let value = match self {
            Frame::Init(init) => json!({
                "ch": CH, "op": "init", "e": b64u(&init.e), "n": b64u(&init.n),
                "genesis_hash": init.genesis_hash.to_hex(), "host_id": init.host_id,
                "host_trust_gen": init.host_trust_gen,
            }),
            Frame::Accept(accept) => json!({
                "ch": CH, "op": "accept", "e": b64u(&accept.e), "n": b64u(&accept.n),
                "head": {"seq": accept.head.seq, "hash": accept.head.hash.to_hex()},
                "sig": b64u(&accept.sig),
            }),
            Frame::Finish { ct } => json!({"ch": CH, "op": "finish", "ct": b64u(ct)}),
            Frame::Rec { ct } => json!({"ch": CH, "op": "rec", "ct": b64u(ct)}),
            Frame::Error { code } => json!({"ch": CH, "op": "error", "code": code}),
        };
        serde_json::to_vec(&value).expect("a frame serializes")
    }
}

/// A clear `error` frame (§R9.7 "Errors"; sent before `finish` opens, then
/// close).
pub fn clear_error(code: ClearCode) -> Vec<u8> {
    Frame::Error {
        code: code.as_str().to_owned(),
    }
    .to_bytes()
}

/// `parse_strict` of a frame (used by tests that tamper with fields).
pub fn to_value(bytes: &[u8]) -> Option<Value> {
    parse_strict(
        bytes,
        MAX_FRAME_BYTES,
        crate::canonical::Numbers::IntegersOnly,
    )
    .ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_and_are_exact() {
        let frames = [
            Frame::Init(Init {
                e: [1; 32],
                n: [2; 32],
                genesis_hash: Hash32([3; 32]),
                host_id: "host-a".into(),
                host_trust_gen: 1,
            }),
            Frame::Accept(Accept {
                e: [4; 32],
                n: [5; 32],
                head: Head {
                    seq: 6,
                    hash: Hash32([7; 32]),
                },
                sig: vec![8; 64],
            }),
            Frame::Finish { ct: vec![9; 40] },
            Frame::Rec { ct: vec![10; 16] },
            Frame::Error {
                code: "busy".into(),
            },
        ];
        for frame in frames {
            let bytes = frame.to_bytes();
            assert_eq!(parse_frame(&bytes).unwrap(), frame);
            // One field too many is malformed.
            let mut value = to_value(&bytes).unwrap();
            value["extra"] = json!(1);
            assert!(parse(value.to_string().as_bytes()).is_err());
        }
    }

    #[test]
    fn malformed_frames_are_refused() {
        for bad in [
            r#"{"ch":"atem-ch2","op":"rec","ct":"AAAAAAAAAAAAAAAAAAAAAA"}"#,
            r#"{"ch":"atem-ch1","op":"rekey"}"#,
            r#"{"ch":"atem-ch1","op":"rec","ct":"AAAA"}"#,
            r#"{"ch":"atem-ch1","op":"rec","ct":"AAAAAAAAAAAAAAAAAAAAAA","ct":"AAAAAAAAAAAAAAAAAAAAAA"}"#,
            r#"{"ch":"atem-ch1","op":"error","code":""}"#,
            r#"[1]"#,
            r#"{"ch":"atem-ch1","op":"init","e":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","n":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","genesis_hash":"00","host_id":"h","host_trust_gen":1}"#,
            r#"{"ch":"atem-ch1","op":"init","e":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","n":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","genesis_hash":"0000000000000000000000000000000000000000000000000000000000000000","host_id":"h","host_trust_gen":0}"#,
        ] {
            assert!(parse(bad.as_bytes()).is_err(), "{bad}");
        }
        assert!(matches!(
            parse(br#"{"type":"session","data":{"op":"hello"}}"#),
            Ok(Parsed::Plain(_))
        ));
        let huge = vec![b' '; MAX_FRAME_BYTES + 1];
        assert!(parse(&huge).is_err());
    }
}

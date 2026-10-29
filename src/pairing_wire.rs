//! The token-free pairing bootstrap v1 on the wire (Astation's
//! `designs/protocol/pairing-and-service-authorization.md`): a received
//! `pairing` frame is read strictly, before anything acts on it. At most
//! 4096 bytes, strict JSON (no duplicate keys), exactly `{type, data}`, and
//! per operation exactly its fields:
//!
//! - `hello{v, op, id}` (sent by Atem);
//! - `introduction{v, op, id, astation_id}`;
//! - `error{v, op, id, code}` with one of the bounded codes.
//!
//! `v` is 1, `id` a UUID v4. Anything else is invalid and never reaches the
//! pairing as a reply (`AstationMessage::PairingInvalid`).
use atem_client::canonical::{Numbers, parse_strict};
use serde_json::Value;

use crate::websocket_client::AstationMessage;

/// The largest pairing frame Atem reads (the contract's bound).
pub const MAX_PAIRING_BYTES: usize = 4096;

/// The bootstrap's version.
pub const PAIRING_V: u64 = 1;

/// Astation's bounded error codes.
pub const ERROR_CODES: &[&str] = &[
    "unsupported_version",
    "invalid_request",
    "not_signed_in",
    "pairing_cancelled",
    "pairing_expired",
];

/// Whether `text` is a `pairing` frame (the `type` alone; any size).
pub fn is_pairing(text: &str) -> bool {
    #[derive(serde::Deserialize)]
    struct Peek {
        #[serde(rename = "type")]
        kind: Option<String>,
    }
    serde_json::from_str::<Peek>(text).is_ok_and(|p| p.kind.as_deref() == Some("pairing"))
}

/// A routing id worth connecting to: 1–128 of `[A-Za-z0-9._:-]`.
pub fn valid_astation_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'-'))
}

/// Reads one received `pairing` frame strictly (see the module docs).
pub fn parse(text: &str) -> Result<AstationMessage, &'static str> {
    if text.len() > MAX_PAIRING_BYTES {
        return Err("larger than 4096 bytes");
    }
    let root = parse_strict(text.as_bytes(), MAX_PAIRING_BYTES, Numbers::IntegersOnly)
        .map_err(|_| "not strict JSON")?;
    let root = root.as_object().ok_or("not an object")?;
    if root.len() != 2 || root.get("type").and_then(Value::as_str) != Some("pairing") {
        return Err("not exactly {type, data}");
    }
    let data = root.get("data").and_then(Value::as_object).ok_or("data")?;
    let v = data.get("v").and_then(Value::as_u64).ok_or("v")?;
    if v != PAIRING_V {
        return Err("unsupported pairing version");
    }
    let id = data
        .get("id")
        .and_then(Value::as_str)
        .filter(|id| atem_client::session::wire::is_uuid_v4(id))
        .ok_or("id")?
        .to_string();
    let op = data.get("op").and_then(Value::as_str).ok_or("op")?;
    let string = |key: &str| data.get(key).and_then(Value::as_str).map(str::to_string);
    let (astation_id, code) = match op {
        "hello" if data.len() == 3 => (None, None),
        "introduction" if data.len() == 4 => (
            Some(
                string("astation_id")
                    .filter(|id| valid_astation_id(id))
                    .ok_or("astation_id")?,
            ),
            None,
        ),
        "error" if data.len() == 4 => (
            None,
            Some(
                string("code")
                    .filter(|code| ERROR_CODES.contains(&code.as_str()))
                    .ok_or("code")?,
            ),
        ),
        "hello" | "introduction" | "error" => return Err("fields"),
        _ => return Err("op"),
    };
    Ok(AstationMessage::Pairing {
        v,
        op: op.to_string(),
        id,
        astation_id,
        code,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const ID: &str = "1dc7bd24-391c-4d16-8b6e-1121e75a2af8";

    fn frame(data: Value) -> String {
        json!({"type": "pairing", "data": data}).to_string()
    }

    fn intro() -> Value {
        json!({"v": 1, "op": "introduction", "id": ID, "astation_id": "astation-46307CB4"})
    }

    #[test]
    fn exact_shapes_are_read() {
        assert!(matches!(
            parse(&frame(intro())),
            Ok(AstationMessage::Pairing { ref op, astation_id: Some(_), code: None, .. }) if op == "introduction"
        ));
        assert!(matches!(
            parse(&frame(
                json!({"v": 1, "op": "error", "id": ID, "code": "not_signed_in"})
            )),
            Ok(AstationMessage::Pairing {
                code: Some(_),
                astation_id: None,
                ..
            })
        ));
        assert!(parse(&frame(json!({"v": 1, "op": "hello", "id": ID}))).is_ok());
    }

    #[test]
    fn anything_else_is_invalid() {
        let mut with_code = intro();
        with_code["code"] = json!("pairing_cancelled");
        let mut extra = intro();
        extra["note"] = json!("x");
        let mut hello_extra = json!({"v": 1, "op": "hello", "id": ID});
        hello_extra["astation_id"] = json!("astation-x");
        for bad in [
            frame(with_code),
            frame(extra),
            frame(hello_extra),
            frame(json!({"v": 2, "op": "introduction", "id": ID, "astation_id": "a"})),
            frame(json!({"v": "1", "op": "introduction", "id": ID, "astation_id": "a"})),
            frame(json!({"v": 1, "op": "introduction", "id": "not-a-uuid", "astation_id": "a"})),
            frame(
                json!({"v": 1, "op": "introduction", "id": ID.to_uppercase(), "astation_id": "a"}),
            ),
            frame(json!({"v": 1, "op": "introduction", "id": ID, "astation_id": "a b"})),
            frame(json!({"v": 1, "op": "error", "id": ID, "code": "weird"})),
            frame(json!({"v": 1, "op": "welcome", "id": ID})),
            json!({"type": "pairing", "data": intro(), "x": 1}).to_string(),
            // A duplicate key (strict JSON).
            format!(
                r#"{{"type":"pairing","data":{{"v":1,"op":"introduction","id":"{ID}","astation_id":"a","astation_id":"b"}}}}"#
            ),
        ] {
            assert!(parse(&bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_bound_is_4096_bytes() {
        let base = frame(intro());
        let at = |len: usize| {
            // Whitespace after the object: JSON stays valid.
            format!("{base}{}", " ".repeat(len - base.len()))
        };
        assert!(parse(&at(MAX_PAIRING_BYTES)).is_ok());
        assert_eq!(
            parse(&at(MAX_PAIRING_BYTES + 1)).unwrap_err(),
            "larger than 4096 bytes"
        );
        assert!(is_pairing(&at(MAX_PAIRING_BYTES + 1)));
    }
}

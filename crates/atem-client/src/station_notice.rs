//! A Station's notice to a host on its open link (the delegated host-work
//! design III.5): `{"type":"relay","op":"service_suspended","v":1,"text"}`,
//! the account's service suspended at this Station (an account disabled at
//! Agora.Build, or no Agora.Build owner at this Station). On a relay or
//! routed host link the Station sends it after closing the host's channels
//! (`close{reason:"service_suspended"}`, session-v1 R9.7a), then closes the
//! host's socket; a host meets the same on its next connection as the
//! route proof's refusal ([`crate::host_route::RelayReply::Suspended`]).
//!
//! Relay-originated only, never forwarded between room members. Exactly
//! these fields, at most [`MAX_SERVICE_SUSPENDED_BYTES`], the `text` of
//! [`crate::host_route::service_text_ok`]'s grammar. The host shows it and
//! retries; it is never a revocation and changes no R9 state. The bound and
//! the text's grammar (nonblank included: item 3 of 7213560895) are **Atem's
//! proposal (#120 7207832274), agreed with Astation (#120 7212501350 and
//! 7213560895)**.
use serde_json::{Value, json};

use crate::canonical::{self, Numbers, StrictError};
use crate::error::{Error, Result};
use crate::host_route::service_text_ok;

/// The notice's `op`.
pub const OP_SERVICE_SUSPENDED: &str = "service_suspended";
/// A `service_suspended` message is at most this many bytes as received.
pub const MAX_SERVICE_SUSPENDED_BYTES: usize = 1024;

/// `{"type":"relay","op":"service_suspended","v":1,"text"}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSuspended {
    text: String,
}

impl ServiceSuspended {
    /// The Station's notice with `text` ([`service_text_ok`]'s, else
    /// `Malformed("text")`).
    pub fn new(text: &str) -> Result<Self> {
        if !service_text_ok(text) {
            return Err(Error::Malformed("text"));
        }
        Ok(ServiceSuspended {
            text: text.to_owned(),
        })
    }

    /// The text the host shows.
    pub fn text(&self) -> &str {
        &self.text
    }

    pub fn to_json(&self) -> Value {
        json!({"type": "relay", "op": OP_SERVICE_SUSPENDED, "v": 1, "text": self.text})
    }

    /// Exactly the notice: strict I-JSON of at most
    /// [`MAX_SERVICE_SUSPENDED_BYTES`] (`TooLarge` beyond), `type` `relay`,
    /// its `op`, `v: 1` and a valid `text`, no other field
    /// (`Malformed`); `Strict` when it isn't strict JSON.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let value =
            canonical::parse_strict(bytes, MAX_SERVICE_SUSPENDED_BYTES, Numbers::IntegersOnly)
                .map_err(|e| match e {
                    StrictError::TooLarge => Error::TooLarge,
                    e => Error::Strict(e),
                })?;
        let o = value.as_object().ok_or(Error::Malformed("not an object"))?;
        if o.get("type").and_then(Value::as_str) != Some("relay")
            || o.get("op").and_then(Value::as_str) != Some(OP_SERVICE_SUSPENDED)
        {
            return Err(Error::Malformed("op"));
        }
        if o.get("v").and_then(Value::as_u64) != Some(1) {
            return Err(Error::Malformed("v"));
        }
        if o.len() != 4
            || !o
                .keys()
                .all(|k| ["type", "op", "v", "text"].contains(&k.as_str()))
        {
            return Err(Error::Malformed("fields"));
        }
        let text = o
            .get("text")
            .and_then(Value::as_str)
            .ok_or(Error::Malformed("text"))?;
        ServiceSuspended::new(text)
    }
}

/// Whether `text` names the notice's `op` at its top level (a relay message
/// a host's reader hands to [`ServiceSuspended::parse`]): a peek, not a
/// parse.
pub fn is_service_suspended(text: &str) -> bool {
    serde_json::from_str::<Value>(text).ok().is_some_and(|v| {
        v.get("type").and_then(Value::as_str) == Some("relay")
            && v.get("op").and_then(Value::as_str) == Some(OP_SERVICE_SUSPENDED)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEXT: &str = "service suspended: account disabled at Agora.Build";

    #[test]
    fn the_notice_round_trips_and_names_its_op() {
        let notice = ServiceSuspended::new(TEXT).unwrap();
        assert_eq!(notice.text(), TEXT);
        assert_eq!(
            notice.to_json(),
            json!({"type": "relay", "op": "service_suspended", "v": 1, "text": TEXT})
        );
        let wire = notice.to_json().to_string();
        assert!(is_service_suspended(&wire));
        assert_eq!(ServiceSuspended::parse(wire.as_bytes()), Ok(notice));
        assert!(!is_service_suspended(
            r#"{"type":"relay","op":"host_route_refused","v":1,"code":"fork"}"#
        ));
        assert!(!is_service_suspended(
            r#"{"type":"channel","op":"service_suspended"}"#
        ));
    }

    #[test]
    fn the_notice_is_read_strictly() {
        let at = |rest: &str| format!(r#"{{"type":"relay","op":"service_suspended",{rest}}}"#);
        let cases: Vec<(String, &str)> = vec![
            (at(r#""v":1"#), "malformed"),
            (at(r#""v":1,"text":"""#), "malformed"),
            (at(r#""v":2,"text":"t""#), "malformed"),
            (at(r#""v":1,"text":"a\u001b[2Jb""#), "malformed"),
            (
                at(&format!(r#""v":1,"text":"a{}b""#, '\u{202e}')),
                "malformed",
            ),
            (
                at(&format!(r#""v":1,"text":"a{}b""#, '\u{2028}')),
                "malformed",
            ),
            (at(r#""v":1,"text":"a\nb""#), "malformed"),
            (at(r#""v":1,"text":7"#), "malformed"),
            (at(r#""v":1,"text":"t","code":"x""#), "malformed"),
            (
                at(&format!(r#""v":1,"text":"{}""#, "a".repeat(257))),
                "malformed",
            ),
            (at(r#""v":1,"text":"t","text":"u""#), "not_strict_json"),
            (
                at(&format!(r#""v":1,"text":"t","pad":"{}""#, "a".repeat(1000))),
                "too_large",
            ),
            (
                r#"{"type":"relay","op":"host_route_refused","v":1,"text":"t"}"#.into(),
                "malformed",
            ),
        ];
        for (text, code) in cases {
            let parsed = ServiceSuspended::parse(text.as_bytes());
            assert_eq!(parsed.map_err(|e| e.code()), Err(code), "{text}");
        }
        // Exactly 1 KiB as received reads (whitespace counts); one byte
        // more doesn't.
        let padded = format!(
            r#"{{"type":"relay","op":"service_suspended","v":1, "text":"{}"}}"#,
            "a".repeat(256)
        );
        let spaced = format!(
            "{padded}{}",
            " ".repeat(MAX_SERVICE_SUSPENDED_BYTES - padded.len())
        );
        assert_eq!(spaced.len(), MAX_SERVICE_SUSPENDED_BYTES);
        assert!(ServiceSuspended::parse(spaced.as_bytes()).is_ok());
        let over = format!("{spaced} ");
        assert_eq!(
            ServiceSuspended::parse(over.as_bytes()).map_err(|e| e.code()),
            Err("too_large")
        );
    }

    #[test]
    fn the_builder_refuses_a_text_out_of_its_grammar() {
        for bad in ["", "a\u{1b}b", "a\u{200b}", "a\u{2029}", &"a".repeat(257)] {
            assert_eq!(ServiceSuspended::new(bad), Err(Error::Malformed("text")));
        }
    }
}

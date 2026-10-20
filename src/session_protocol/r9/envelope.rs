//! The channel envelope on Atem's link (atem-session-v1.md §R9.7a): the
//! router (the relay, or Astation on :8080) wraps each client's `atem-ch1`
//! frames with a routing handle, so several clients share Atem's one
//! outbound link.
//!
//! ```text
//! {"type":"channel","event":"open","channel":"<h>","transport":"relay"|"direct"}
//! {"type":"channel","event":"frame","channel":"<h>","frame":{<atem-ch1 frame>}}
//! {"type":"channel","event":"close","channel":"<h>","reason"?:"<code>"}
//! ```
//!
//! Exactly these fields (I-JSON, `parse_strict`); the handle is a routing
//! id only, never authority (authentication is `atem-ch1`).
use atem_client::canonical::StrictValue;
use serde_json::{Map, Value, json};

/// An envelope as received, at most (§R9.7a "Bounds").
pub const MAX_ENVELOPE_BYTES: usize = 2 << 20;
/// A handle: 1–64 characters of `[A-Za-z0-9_-]`.
pub const MAX_HANDLE: usize = 64;
/// A `close` reason: 1–32 characters of `[a-z_]`.
pub const MAX_REASON: usize = 32;

/// Atem's `close` reasons.
pub mod reason {
    pub const CLOSED: &str = "closed";
    pub const UNKNOWN_CHANNEL: &str = "unknown_channel";
    pub const BUSY: &str = "busy";
    pub const TOO_LARGE: &str = "too_large";
    pub const MALFORMED: &str = "malformed";
    pub const HANDSHAKE_FAILED: &str = "handshake_failed";
    pub const EXPIRED: &str = "expired";
}

/// The router's label of the channel's route (logged, never trusted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Relay,
    Direct,
}

impl Transport {
    pub fn as_str(self) -> &'static str {
        match self {
            Transport::Relay => "relay",
            Transport::Direct => "direct",
        }
    }
}

/// One envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Open {
        channel: String,
        transport: Transport,
    },
    /// `frame`: the `atem-ch1` frame, compact JSON.
    Frame { channel: String, frame: Vec<u8> },
    Close {
        channel: String,
        reason: Option<String>,
    },
}

impl Event {
    pub fn channel(&self) -> &str {
        match self {
            Event::Open { channel, .. }
            | Event::Frame { channel, .. }
            | Event::Close { channel, .. } => channel,
        }
    }
}

/// Why an envelope was refused; `channel` when its handle could be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refused {
    /// Over [`MAX_ENVELOPE_BYTES`] (`too_large`).
    TooLarge { channel: Option<String> },
    /// Not a well-formed envelope (`malformed`).
    Malformed {
        channel: Option<String>,
        why: &'static str,
    },
}

impl Refused {
    pub fn channel(&self) -> Option<&str> {
        match self {
            Refused::TooLarge { channel } | Refused::Malformed { channel, .. } => {
                channel.as_deref()
            }
        }
    }

    pub fn reason(&self) -> &'static str {
        match self {
            Refused::TooLarge { .. } => reason::TOO_LARGE,
            Refused::Malformed { .. } => reason::MALFORMED,
        }
    }
}

pub fn is_handle(text: &str) -> bool {
    (1..=MAX_HANDLE).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

pub fn is_reason(text: &str) -> bool {
    (1..=MAX_REASON).contains(&text.len())
        && text.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
}

/// Whether `text` is a channel envelope (`type` is `channel`): such
/// messages are demultiplexed before anything else on the link.
pub fn is_envelope(text: &str) -> bool {
    #[derive(serde::Deserialize)]
    struct Peek<'a> {
        #[serde(rename = "type", borrow)]
        kind: Option<std::borrow::Cow<'a, str>>,
    }
    serde_json::from_str::<Peek>(text).is_ok_and(|p| p.kind.as_deref() == Some("channel"))
}

/// The handle of an envelope that can't be parsed strictly (a lenient
/// read, used only to address the `close`), if it is a valid handle.
fn peek_handle(text: &str) -> Option<String> {
    #[derive(serde::Deserialize)]
    struct Peek {
        channel: Option<String>,
    }
    serde_json::from_str::<Peek>(text)
        .ok()?
        .channel
        .filter(|h| is_handle(h))
}

/// Parses one envelope (§R9.7a "Fields").
pub fn parse(text: &str) -> Result<Event, Refused> {
    if text.len() > MAX_ENVELOPE_BYTES {
        return Err(Refused::TooLarge {
            channel: peek_handle(text),
        });
    }
    let malformed = |why| Refused::Malformed {
        channel: peek_handle(text),
        why,
    };
    let strict = StrictValue::parse(text.as_bytes(), MAX_ENVELOPE_BYTES)
        .map_err(|_| malformed("not strict JSON"))?;
    let object = strict
        .value()
        .as_object()
        .ok_or_else(|| malformed("not an object"))?;
    if object.get("type").and_then(Value::as_str) != Some("channel") {
        return Err(malformed("type"));
    }
    let channel = object
        .get("channel")
        .and_then(Value::as_str)
        .filter(|h| is_handle(h))
        .ok_or_else(|| Refused::Malformed {
            channel: None,
            why: "channel",
        })?
        .to_string();
    let malformed = |why| Refused::Malformed {
        channel: Some(channel.clone()),
        why,
    };
    let exactly = |fields: &[&str]| -> bool {
        object.len() == fields.len() && fields.iter().all(|f| object.contains_key(*f))
    };
    match object.get("event").and_then(Value::as_str) {
        Some("open") => {
            if !exactly(&["type", "event", "channel", "transport"]) {
                return Err(malformed("open fields"));
            }
            let transport = match object.get("transport").and_then(Value::as_str) {
                Some("relay") => Transport::Relay,
                Some("direct") => Transport::Direct,
                _ => return Err(malformed("transport")),
            };
            Ok(Event::Open { channel, transport })
        }
        Some("frame") => {
            if !exactly(&["type", "event", "channel", "frame"]) {
                return Err(malformed("frame fields"));
            }
            let frame = object
                .get("frame")
                .filter(|f| f.is_object())
                .ok_or_else(|| malformed("frame"))?;
            let frame = serde_json::to_vec(frame).map_err(|_| malformed("frame"))?;
            Ok(Event::Frame { channel, frame })
        }
        Some("close") => {
            let with_reason = object.contains_key("reason");
            let fields: &[&str] = if with_reason {
                &["type", "event", "channel", "reason"]
            } else {
                &["type", "event", "channel"]
            };
            if !exactly(fields) {
                return Err(malformed("close fields"));
            }
            let reason = match object.get("reason") {
                None => None,
                Some(r) => Some(
                    r.as_str()
                        .filter(|r| is_reason(r))
                        .ok_or_else(|| malformed("reason"))?
                        .to_string(),
                ),
            };
            Ok(Event::Close { channel, reason })
        }
        _ => Err(malformed("event")),
    }
}

/// A `frame` envelope around `frame` (an `atem-ch1` frame's JSON bytes).
pub fn frame(channel: &str, frame: &[u8]) -> String {
    let frame = std::str::from_utf8(frame).expect("atem-ch1 frames are JSON text");
    // The frame is embedded as is (it is JSON already): no re-encoding.
    format!(
        r#"{{"type":"channel","event":"frame","channel":{},"frame":{frame}}}"#,
        json!(channel)
    )
}

/// A `close` envelope.
pub fn close(channel: &str, reason: Option<&str>) -> String {
    let mut object = Map::new();
    object.insert("type".into(), json!("channel"));
    object.insert("event".into(), json!("close"));
    object.insert("channel".into(), json!(channel));
    if let Some(reason) = reason {
        object.insert("reason".into(), json!(reason));
    }
    Value::Object(object).to_string()
}

/// An `open` envelope (the router's; tests and fake routers).
pub fn open(channel: &str, transport: Transport) -> String {
    json!({"type": "channel", "event": "open", "channel": channel, "transport": transport.as_str()})
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vectors() -> Value {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("designs/protocol/fixtures/r9-envelope-vectors.json");
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn the_vectors_shapes_handles_and_refusals() {
        let v = vectors();
        for (name, event) in v["events"].as_object().unwrap() {
            let parsed = parse(&event.to_string()).unwrap_or_else(|e| panic!("{name}: {e:?}"));
            assert_eq!(
                parsed.channel(),
                event["channel"].as_str().unwrap(),
                "{name}"
            );
        }
        for h in v["handles"]["valid"].as_array().unwrap() {
            assert!(is_handle(h.as_str().unwrap()), "{h}");
        }
        for h in v["handles"]["invalid"].as_array().unwrap() {
            assert!(!is_handle(h.as_str().unwrap()), "{h}");
        }
        for r in v["reasons"]["valid"].as_array().unwrap() {
            assert!(is_reason(r.as_str().unwrap()), "{r}");
        }
        for r in v["reasons"]["invalid"].as_array().unwrap() {
            assert!(!is_reason(r.as_str().unwrap()), "{r}");
        }
        for case in v["invalid_envelopes"].as_array().unwrap() {
            let text = match case.get("raw") {
                Some(raw) => raw.as_str().unwrap().to_string(),
                None => case["envelope"].to_string(),
            };
            match parse(&text) {
                // A frame of another suite is the channel's to refuse.
                Ok(Event::Frame { .. }) if case["case"] == "frame of another suite" => {}
                Ok(event) => panic!("{}: {event:?}", case["case"]),
                Err(_) => {}
            }
        }
    }

    #[test]
    fn the_largest_legal_record_fits_and_the_bounds_hold() {
        use atem_client::encoding::b64u;
        let v = vectors();
        let b = &v["bounds"];
        let plaintext = b["plaintext_bytes"].as_u64().unwrap() as usize;
        let ct = b64u(&vec![
            0u8;
            plaintext + b["tag_bytes"].as_u64().unwrap() as usize
        ]);
        assert_eq!(ct.len() as u64, b["max_ct_chars"].as_u64().unwrap());
        let inner = json!({"ch": "atem-ch1", "op": "rec", "ct": ct}).to_string();
        assert_eq!(inner.len() as u64, b["max_frame_bytes"].as_u64().unwrap());
        let handle = b["max_record_envelope"]["handle"].as_str().unwrap();
        let outer = frame(handle, inner.as_bytes());
        assert_eq!(
            outer.len() as u64,
            b["max_record_envelope"]["bytes"].as_u64().unwrap()
        );
        assert_eq!(
            b["envelope_bytes"].as_u64().unwrap() as usize,
            MAX_ENVELOPE_BYTES
        );
        let parsed = parse(&outer).unwrap();
        assert!(matches!(&parsed, Event::Frame { frame, .. } if frame.len() == inner.len()));
        // One byte over the envelope bound: refused, its handle still read.
        let mut big = frame("ch-1", inner.as_bytes());
        big.insert_str(
            big.len() - 1,
            &" ".repeat(MAX_ENVELOPE_BYTES + 1 - big.len()),
        );
        assert_eq!(big.len(), MAX_ENVELOPE_BYTES + 1);
        assert_eq!(
            parse(&big),
            Err(Refused::TooLarge {
                channel: Some("ch-1".into())
            })
        );
        // Non-compact JSON within the bound is accepted.
        let spaced =
            format!("{{ \"type\" : \"channel\", \"event\": \"close\", \"channel\": \"ch-1\" }}");
        assert!(parse(&spaced).is_ok());
    }

    #[test]
    fn built_envelopes_round_trip() {
        let f = br#"{"ch":"atem-ch1","op":"rec","ct":"AAAAAAAAAAAAAAAAAAAAAA"}"#;
        match parse(&frame("a_b-9", f)).unwrap() {
            Event::Frame { channel, frame } => {
                assert_eq!(channel, "a_b-9");
                let back: Value = serde_json::from_slice(&frame).unwrap();
                assert_eq!(back, serde_json::from_slice::<Value>(f).unwrap());
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(
            parse(&close("x", Some("busy"))).unwrap(),
            Event::Close {
                channel: "x".into(),
                reason: Some("busy".into())
            }
        );
        assert_eq!(
            parse(&open("x", Transport::Direct)).unwrap(),
            Event::Open {
                channel: "x".into(),
                transport: Transport::Direct
            }
        );
        assert!(is_envelope(&close("x", None)));
        assert!(!is_envelope(r#"{"type":"session","data":{}}"#));
    }
}

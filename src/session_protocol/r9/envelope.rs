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

/// Only this much of an oversize message is looked at, never parsed.
const OVERSIZE_PEEK: usize = 4096;

/// What the first bytes of an oversize message (over
/// [`MAX_ENVELOPE_BYTES`], never parsed) say. Every outcome is decided
/// from the first 4 KiB alone: nothing over the bound is ever parsed in
/// full, whatever its type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Oversize {
    /// Its top-level `type` (a plain string within the first bytes) is
    /// this, not `channel`.
    Other(String),
    /// A channel envelope whose top-level `channel` (before any `frame`)
    /// names this handle: closed `too_large`.
    Channel(String),
    /// A channel envelope whose handle can't be told cheaply: dropped and
    /// logged, no channel closed.
    Unaddressed,
    /// Its type can't be told from the first bytes (not an object, an
    /// escaped key or value, or a nested value running past the first
    /// bytes before `type`): dropped and logged.
    Unreadable,
}

/// The top-level string members of a JSON object's first bytes, in order,
/// up to its `frame` member (or the end of `head`): `None` when `head`
/// isn't the start of an object. Nested values are skipped, never read.
fn top_level_strings(head: &[u8]) -> Option<Vec<(String, String)>> {
    let mut i = 0;
    let ws = |i: &mut usize| {
        while *i < head.len() && matches!(head[*i], b' ' | b'\t' | b'\n' | b'\r') {
            *i += 1;
        }
    };
    // A plain string (no escapes): its text; escaped strings are skipped.
    let string = |i: &mut usize| -> Option<Option<String>> {
        if head.get(*i) != Some(&b'"') {
            return None;
        }
        *i += 1;
        let start = *i;
        let mut escaped = false;
        while *i < head.len() {
            match head[*i] {
                b'\\' => {
                    escaped = true;
                    *i += 2;
                }
                b'"' => {
                    let text = std::str::from_utf8(&head[start..*i]).ok()?.to_string();
                    *i += 1;
                    return Some((!escaped).then_some(text));
                }
                _ => *i += 1,
            }
        }
        None
    };
    let mut out = Vec::new();
    ws(&mut i);
    if head.get(i) != Some(&b'{') {
        return None;
    }
    i += 1;
    loop {
        ws(&mut i);
        let Some(key) = string(&mut i) else {
            return Some(out);
        };
        ws(&mut i);
        if head.get(i) != Some(&b':') {
            return Some(out);
        }
        i += 1;
        ws(&mut i);
        if key.as_deref() == Some("frame") {
            return Some(out);
        }
        match head.get(i) {
            Some(b'"') => {
                let Some(value) = string(&mut i) else {
                    return Some(out);
                };
                if let (Some(k), Some(v)) = (key, value) {
                    out.push((k, v));
                }
            }
            Some(b'{') | Some(b'[') => {
                // Skip a nested value (strings inside included).
                let mut depth = 0usize;
                while i < head.len() {
                    match head[i] {
                        b'"' => {
                            if string(&mut i).is_none() {
                                // The head ends inside it: what was read stands.
                                return Some(out);
                            }
                            continue;
                        }
                        b'{' | b'[' => depth += 1,
                        b'}' | b']' => {
                            depth -= 1;
                            if depth == 0 {
                                i += 1;
                                break;
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }
            }
            _ => {
                while i < head.len() && !matches!(head[i], b',' | b'}') {
                    i += 1;
                }
            }
        }
        ws(&mut i);
        match head.get(i) {
            Some(b',') => i += 1,
            _ => return Some(out),
        }
    }
}

/// An oversize message, from its first 4 KiB only (§R9.7a: never parsed):
/// a channel envelope is told by its top-level `type`, its handle by the
/// top-level `channel` before `frame`; nested keys never count.
pub fn oversize_envelope(text: &str) -> Oversize {
    let head = &text.as_bytes()[..text.len().min(OVERSIZE_PEEK)];
    let Some(members) = top_level_strings(head) else {
        return Oversize::Unreadable;
    };
    let value = |k: &str| members.iter().find(|(key, _)| key == k).map(|(_, v)| v);
    match value("type").map(String::as_str) {
        Some("channel") => {}
        Some(other) => return Oversize::Other(other.to_string()),
        // The head ran out (or reached `frame`) before a readable `type`.
        None => return Oversize::Unreadable,
    }
    match value("channel").filter(|h| is_handle(h)) {
        Some(handle) => Oversize::Channel(handle.clone()),
        None => Oversize::Unaddressed,
    }
}

/// Parses one envelope (§R9.7a "Fields").
pub fn parse(text: &str) -> Result<Event, Refused> {
    if text.len() > MAX_ENVELOPE_BYTES {
        return Err(Refused::TooLarge {
            channel: match oversize_envelope(text) {
                Oversize::Channel(handle) => Some(handle),
                _ => None,
            },
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
        .ok_or(Refused::Malformed {
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
            "{ \"type\" : \"channel\", \"event\": \"close\", \"channel\": \"ch-1\" }".to_string();
        assert!(parse(&spaced).is_ok());
    }

    /// §R9.7a: an oversize message is never parsed; its handle comes only
    /// from its top-level members before `frame`.
    #[test]
    fn the_oversize_peek_reads_top_level_members_only() {
        let pad = "A".repeat(MAX_ENVELOPE_BYTES);
        let big = |head: &str| format!("{head}{pad}\"}}}}");
        assert_eq!(
            oversize_envelope(&big(
                r#"{"type":"channel","event":"frame","channel":"h1","frame":{"ch":"atem-ch1","op":"rec","ct":""#
            )),
            Oversize::Channel("h1".into())
        );
        // Non-compact.
        assert_eq!(
            oversize_envelope(&big(
                r#"{ "type" : "channel", "channel" : "h2", "event": "frame", "frame": {"ct": ""#
            )),
            Oversize::Channel("h2".into())
        );
        // A nested `channel` before the top-level one never counts.
        assert_eq!(
            oversize_envelope(&big(
                r#"{"type":"channel","event":"frame","frame":{"channel":"victim","ct":""#
            )),
            Oversize::Unaddressed
        );
        assert_eq!(
            oversize_envelope(&big(
                r#"{"type":"channel","x":{"channel":"victim"},"channel":"h3","frame":{"ct":""#
            )),
            Oversize::Channel("h3".into())
        );
        // An escaped value is never taken.
        assert_eq!(
            oversize_envelope(&big(
                r#"{"type":"channel","channel":"h\u0034","frame":{"ct":""#
            )),
            Oversize::Unaddressed
        );
        // Not an envelope: its type is read from the head only.
        assert_eq!(
            oversize_envelope(&big(r#"{"type":"session","data":{"x":""#)),
            Oversize::Other("session".into())
        );
        // The type out of reach: never parsed further.
        assert_eq!(
            oversize_envelope(&big(r#"{"frame":{"ct":""#)),
            Oversize::Unreadable
        );
    }

    /// N10: a message whose first 4 KiB end inside a nested value before
    /// any `type` is unreadable (dropped and logged), never handed to a
    /// parser that would read all of it; so are other heads that name no
    /// readable type.
    #[test]
    fn an_oversize_head_ending_mid_value_is_unreadable() {
        let pad = "A".repeat(MAX_ENVELOPE_BYTES);
        let big = |head: &str| format!("{head}{pad}\"}}}}");
        let nested = format!(r#"{{"x":{{"y":"{}"#, "z".repeat(OVERSIZE_PEEK));
        assert_eq!(oversize_envelope(&big(&nested)), Oversize::Unreadable);
        // A nested value over the head, then `type` past it.
        let late_type = format!(
            r#"{{"x":["{}"],"type":"channel","channel":"h1","#,
            "z".repeat(OVERSIZE_PEEK)
        );
        assert_eq!(oversize_envelope(&big(&late_type)), Oversize::Unreadable);
        assert_eq!(oversize_envelope(&big(r#"["#)), Oversize::Unreadable);
        assert_eq!(
            oversize_envelope(&big(r#"{"ty\u0070e":"channel","#)),
            Oversize::Unreadable
        );
        assert_eq!(
            oversize_envelope(&big(r#"{"type":"chan\u006eel","#)),
            Oversize::Unreadable
        );
        // A long top-level string value before `type` runs past the head.
        let long_value = format!(r#"{{"note":"{}"#, "n".repeat(OVERSIZE_PEEK));
        assert_eq!(oversize_envelope(&big(&long_value)), Oversize::Unreadable);
        // Within the head, a readable other type is named.
        assert_eq!(
            oversize_envelope(&big(r#"{"type":"terminal","data":{"bytes":""#)),
            Oversize::Other("terminal".into())
        );
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

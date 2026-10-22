//! The host route proof (§R9.7b): an r9 host proves to the relay, with no
//! Astation online, that it may hold its route.
//!
//! On every new host connection the relay sends a challenge,
//! `{"type":"relay","op":"host_challenge","v":1,"nonce":"<b64u, 32 bytes>",
//! "room":"<room code>"}`; a host with a pinned device list answers it at
//! most once with `{"type":"relay","op":"host_route","v":1,"proof":{body,
//! sig}}`. The body is
//! `{"type":"atem-host-route","v":1,"account_id","genesis_hash","host_id",
//! "atem_id","room","nonce","head":{"seq","hash"}}` and `sig` is Ed25519 by
//! the host's `host_channel_key` over `enc(["atem-host-route-v1",
//! jcs(body)])`.
//!
//! - the host builds and signs: [`HostRouteBody::at`], [`sign_host_route`],
//!   [`host_route_message`]; it reads the challenge with
//!   [`HostChallenge::parse`];
//! - the relay sends [`HostChallenge::to_json`] and verifies the answer with
//!   [`verify_host_route_message`] (the whole relay message) or
//!   [`verify_host_route`] (its `proof`), against the log it verified.
//!
//! Only a verified proof gives a route. A query-string `atem_id`, the room
//! code, a login or an old pairing never does; nothing falls back.
use serde_json::{Map, Value, json};

use crate::canonical::{self, Numbers};
use crate::encoding::{Hash32, b64u, b64u_decode_array};
use crate::error::{Error, Result};
use crate::membership::{Head, Membership};
use crate::provider::{KeyId, KeyProvider};
use crate::signed::SignedObject;

/// The challenge nonce: 32 random bytes, base64url without padding.
pub const NONCE_BYTES: usize = 32;
/// `account_id`, `host_id`, `atem_id` and `room` are 1 to this many bytes.
pub const MAX_ID_BYTES: usize = 256;
/// A `host_challenge` or `host_route` relay message at most (the proof's
/// own bounds are a signed object's: body ≤ 4096, object ≤ 16 KiB).
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024;

/// Exactly the body's fields (`sig` sits beside the body).
const BODY_FIELDS: [&str; 9] = [
    "type",
    "v",
    "account_id",
    "genesis_hash",
    "host_id",
    "atem_id",
    "room",
    "nonce",
    "head",
];

/// Why a host route proof (or a challenge) is refused. `code()` is the
/// stable name the relay logs or returns.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostRouteRefusal {
    /// Not exactly the message or body of §R9.7b (strict I-JSON, exact
    /// fields, duplicate keys, bounds, encodings); the text names the part.
    Malformed(&'static str),
    /// The verifier's log is frozen (a conflict): no route is restored.
    Frozen,
    /// `account_id` or `genesis_hash` isn't the log's.
    WrongAccount,
    /// `host_id` isn't a current host (`add_host`, not removed) at the log's
    /// head.
    UnknownHost,
    /// `sig` doesn't verify with the host's newest `host_channel_key`.
    BadSignature,
    /// `head` is beyond the verifier's head: its log is behind (fetch, then
    /// challenge again).
    StaleLog,
    /// `head.seq` is on the verifier's chain but its hash isn't: a fork.
    Fork,
    NonceMismatch,
    RoomMismatch,
    AtemIdMismatch,
}

impl HostRouteRefusal {
    pub fn code(&self) -> &'static str {
        match self {
            HostRouteRefusal::Malformed(_) => "malformed",
            HostRouteRefusal::Frozen => "frozen",
            HostRouteRefusal::WrongAccount => "wrong_account",
            HostRouteRefusal::UnknownHost => "unknown_host",
            HostRouteRefusal::BadSignature => "bad_signature",
            HostRouteRefusal::StaleLog => "stale_log",
            HostRouteRefusal::Fork => "fork",
            HostRouteRefusal::NonceMismatch => "nonce_mismatch",
            HostRouteRefusal::RoomMismatch => "room_mismatch",
            HostRouteRefusal::AtemIdMismatch => "atem_id_mismatch",
        }
    }
}

impl std::fmt::Display for HostRouteRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HostRouteRefusal::Malformed(what) => write!(f, "malformed ({what})"),
            other => f.write_str(other.code()),
        }
    }
}

impl std::error::Error for HostRouteRefusal {}

fn malformed(what: &'static str) -> HostRouteRefusal {
    HostRouteRefusal::Malformed(what)
}

/// A string field of 1..=[`MAX_ID_BYTES`] bytes.
fn id_field<'a>(
    o: &'a Map<String, Value>,
    key: &'static str,
) -> std::result::Result<&'a str, HostRouteRefusal> {
    o.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty() && s.len() <= MAX_ID_BYTES)
        .ok_or(malformed(key))
}

fn nonce_field(o: &Map<String, Value>) -> std::result::Result<[u8; NONCE_BYTES], HostRouteRefusal> {
    o.get("nonce")
        .and_then(Value::as_str)
        .and_then(|n| b64u_decode_array::<NONCE_BYTES>(n).ok())
        .ok_or(malformed("nonce"))
}

/// Strict parse of a relay message of `op` with exactly `fields` beside
/// `type`, `op` and `v: 1`.
fn relay_message(
    bytes: &[u8],
    op: &str,
    fields: &[&str],
) -> std::result::Result<Map<String, Value>, HostRouteRefusal> {
    let value =
        canonical::parse_strict(bytes, MAX_MESSAGE_BYTES, Numbers::IntegersOnly).map_err(|e| {
            match e {
                canonical::StrictError::TooLarge => malformed("too large"),
                _ => malformed("not strict JSON"),
            }
        })?;
    let o = value
        .as_object()
        .cloned()
        .ok_or(malformed("not an object"))?;
    if o.get("type").and_then(Value::as_str) != Some("relay")
        || o.get("op").and_then(Value::as_str) != Some(op)
    {
        return Err(malformed("op"));
    }
    if o.get("v").and_then(Value::as_u64) != Some(1) {
        return Err(malformed("v"));
    }
    let known = |k: &str| ["type", "op", "v"].contains(&k) || fields.contains(&k);
    if o.len() != 3 + fields.len() || !o.keys().all(|k| known(k)) {
        return Err(malformed("fields"));
    }
    Ok(o)
}

// ------------------------------------------------------------ challenge

/// `{"type":"relay","op":"host_challenge","v":1,"nonce","room"}`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostChallenge {
    pub nonce: [u8; NONCE_BYTES],
    pub room: String,
}

impl HostChallenge {
    /// A challenge with a fresh random nonce (the relay's side).
    pub fn new(room: &str) -> Self {
        let mut nonce = [0u8; NONCE_BYTES];
        rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut nonce);
        HostChallenge {
            nonce,
            room: room.to_owned(),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({"type": "relay", "op": "host_challenge", "v": 1,
               "nonce": b64u(&self.nonce), "room": self.room})
    }

    /// Exactly the challenge: strict I-JSON, these fields only, the nonce 32
    /// bytes, the room 1..=256 bytes.
    pub fn parse(bytes: &[u8]) -> std::result::Result<Self, HostRouteRefusal> {
        let o = relay_message(bytes, "host_challenge", &["nonce", "room"])?;
        Ok(HostChallenge {
            nonce: nonce_field(&o)?,
            room: id_field(&o, "room")?.to_owned(),
        })
    }
}

// ----------------------------------------------------------------- body

/// The proof's body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRouteBody {
    pub account_id: String,
    pub genesis_hash: Hash32,
    pub host_id: String,
    pub atem_id: String,
    pub room: String,
    pub nonce: [u8; NONCE_BYTES],
    pub head: Head,
}

impl HostRouteBody {
    /// The body a host signs at `log`'s head for `challenge`.
    pub fn at(log: &Membership, host_id: &str, atem_id: &str, challenge: &HostChallenge) -> Self {
        HostRouteBody {
            account_id: log.account_id().to_owned(),
            genesis_hash: log.genesis_hash(),
            host_id: host_id.to_owned(),
            atem_id: atem_id.to_owned(),
            room: challenge.room.clone(),
            nonce: challenge.nonce,
            head: log.head(),
        }
    }

    pub fn to_json(&self) -> Value {
        json!({
            "type": "atem-host-route",
            "v": 1,
            "account_id": self.account_id,
            "genesis_hash": self.genesis_hash.to_hex(),
            "host_id": self.host_id,
            "atem_id": self.atem_id,
            "room": self.room,
            "nonce": b64u(&self.nonce),
            "head": self.head.to_json(),
        })
    }

    /// Exactly the body of §R9.7b.
    fn read(body: &Value) -> std::result::Result<Self, HostRouteRefusal> {
        let o = body.as_object().ok_or(malformed("body"))?;
        if o.len() != BODY_FIELDS.len() || !o.keys().all(|k| BODY_FIELDS.contains(&k.as_str())) {
            return Err(malformed("body fields"));
        }
        if o.get("type").and_then(Value::as_str) != Some("atem-host-route") {
            return Err(malformed("type"));
        }
        Ok(HostRouteBody {
            account_id: id_field(o, "account_id")?.to_owned(),
            genesis_hash: o
                .get("genesis_hash")
                .and_then(Value::as_str)
                .and_then(|h| Hash32::from_hex(h).ok())
                .ok_or(malformed("genesis_hash"))?,
            host_id: id_field(o, "host_id")?.to_owned(),
            atem_id: id_field(o, "atem_id")?.to_owned(),
            room: id_field(o, "room")?.to_owned(),
            nonce: nonce_field(o)?,
            head: o
                .get("head")
                .and_then(Head::from_json)
                .ok_or(malformed("head"))?,
        })
    }
}

/// The host signs `body` with its `host_channel_key` (behind `provider`).
pub fn sign_host_route(
    provider: &dyn KeyProvider,
    host_key: &KeyId,
    body: &HostRouteBody,
) -> Result<SignedObject> {
    if [&body.account_id, &body.host_id, &body.atem_id, &body.room]
        .iter()
        .any(|s| s.is_empty() || s.len() > MAX_ID_BYTES)
    {
        return Err(Error::Malformed("an id of 1 to 256 bytes"));
    }
    SignedObject::sign(provider, host_key, body.to_json())
}

/// `{"type":"relay","op":"host_route","v":1,"proof":{body, sig}}`.
pub fn host_route_message(proof: &SignedObject) -> Value {
    json!({"type": "relay", "op": "host_route", "v": 1, "proof": proof.to_json()})
}

// ------------------------------------------------------- relay replies

/// The refusal codes, by `code()` (a `host_route_refused` names one).
pub const REFUSAL_CODES: [&str; 10] = [
    "malformed",
    "frozen",
    "wrong_account",
    "unknown_host",
    "bad_signature",
    "stale_log",
    "fork",
    "nonce_mismatch",
    "room_mismatch",
    "atem_id_mismatch",
];

/// The relay's answer to a proof: `host_route_ok` once it verified it
/// (the route is the host's), or `host_route_refused` with the
/// verifier's code (the relay closes the connection after it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayReply {
    /// `{"type":"relay","op":"host_route_ok","v":1,"host_id","head":{"seq","hash"}}`.
    Ok { host_id: String, head: Head },
    /// `{"type":"relay","op":"host_route_refused","v":1,"code"}`.
    Refused { code: String },
}

impl RelayReply {
    /// The relay's `host_route_ok` for a verified route.
    pub fn ok(route: &HostRoute) -> Self {
        RelayReply::Ok {
            host_id: route.host_id.clone(),
            head: route.head,
        }
    }

    /// The relay's `host_route_refused` for a refusal.
    pub fn refused(refusal: &HostRouteRefusal) -> Self {
        RelayReply::Refused {
            code: refusal.code().to_owned(),
        }
    }

    pub fn to_json(&self) -> Value {
        match self {
            RelayReply::Ok { host_id, head } => json!({"type": "relay", "op": "host_route_ok",
                "v": 1, "host_id": host_id, "head": head.to_json()}),
            RelayReply::Refused { code } => json!({"type": "relay", "op": "host_route_refused",
                "v": 1, "code": code}),
        }
    }

    /// Exactly one of the two replies (strict I-JSON, exact fields, a
    /// known refusal code); `None` for any other relay message.
    pub fn parse(bytes: &[u8]) -> Option<std::result::Result<Self, HostRouteRefusal>> {
        let op = serde_json::from_slice::<Value>(bytes)
            .ok()?
            .get("op")?
            .as_str()?
            .to_owned();
        Some(match op.as_str() {
            "host_route_ok" => relay_message(bytes, "host_route_ok", &["host_id", "head"])
                .and_then(|o| {
                    Ok(RelayReply::Ok {
                        host_id: id_field(&o, "host_id")?.to_owned(),
                        head: o
                            .get("head")
                            .and_then(Head::from_json)
                            .ok_or(malformed("head"))?,
                    })
                }),
            "host_route_refused" => {
                relay_message(bytes, "host_route_refused", &["code"]).and_then(|o| {
                    let code = o
                        .get("code")
                        .and_then(Value::as_str)
                        .filter(|c| REFUSAL_CODES.contains(c))
                        .ok_or(malformed("code"))?;
                    Ok(RelayReply::Refused {
                        code: code.to_owned(),
                    })
                })
            }
            _ => return None,
        })
    }
}

// --------------------------------------------------------- verification

/// A verified proof: the host may hold its route.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostRoute {
    pub host_id: String,
    /// The head the host signed at (the verifier's head or an ancestor).
    pub head: Head,
}

/// Verifies a `proof` (`{"body","sig"}` as received) against the
/// verifier's log and its own challenge. In this order: exact fields
/// (`malformed`); the log not frozen (`frozen`); `account_id` and
/// `genesis_hash` the log's (`wrong_account`); `host_id` a current host at
/// the log's head (`unknown_host`); `sig` by its newest `host_channel_key`
/// (`bad_signature`); `head` the log's head or one of its ancestors
/// (`stale_log` beyond it, `fork` off it); then `nonce`, `room` and
/// `atem_id` equal to the relay's (`nonce_mismatch`, `room_mismatch`,
/// `atem_id_mismatch`).
pub fn verify_host_route(
    log: &Membership,
    proof_json: &[u8],
    expected_nonce: &[u8; NONCE_BYTES],
    expected_room: &str,
    expected_atem_id: &str,
) -> std::result::Result<HostRoute, HostRouteRefusal> {
    let object = SignedObject::parse(proof_json).map_err(|e| match e {
        Error::UnknownType => malformed("type"),
        Error::TooLarge => malformed("too large"),
        Error::Strict(_) => malformed("not strict JSON"),
        Error::Malformed(what) => malformed(what),
        _ => malformed("proof"),
    })?;
    verify_object(
        log,
        &object,
        expected_nonce,
        expected_room,
        expected_atem_id,
    )
}

/// [`verify_host_route`] of a whole `host_route` relay message (exact
/// fields: `type`, `op`, `v`, `proof`).
pub fn verify_host_route_message(
    log: &Membership,
    message: &[u8],
    expected_nonce: &[u8; NONCE_BYTES],
    expected_room: &str,
    expected_atem_id: &str,
) -> std::result::Result<HostRoute, HostRouteRefusal> {
    let o = relay_message(message, "host_route", &["proof"])?;
    let object = SignedObject::from_value(&o["proof"]).map_err(|e| match e {
        Error::UnknownType => malformed("type"),
        Error::TooLarge => malformed("too large"),
        Error::Malformed(what) => malformed(what),
        _ => malformed("proof"),
    })?;
    verify_object(
        log,
        &object,
        expected_nonce,
        expected_room,
        expected_atem_id,
    )
}

fn verify_object(
    log: &Membership,
    object: &SignedObject,
    expected_nonce: &[u8; NONCE_BYTES],
    expected_room: &str,
    expected_atem_id: &str,
) -> std::result::Result<HostRoute, HostRouteRefusal> {
    if object.label() != crate::domain::SignLabel::HostRoute {
        return Err(malformed("type"));
    }
    let body = HostRouteBody::read(object.body())?;
    if log.frozen().is_some() {
        return Err(HostRouteRefusal::Frozen);
    }
    if body.account_id != log.account_id() || body.genesis_hash != log.genesis_hash() {
        return Err(HostRouteRefusal::WrongAccount);
    }
    let host = log
        .host(&body.host_id)
        .ok_or(HostRouteRefusal::UnknownHost)?;
    object
        .verify(&host.host_key)
        .map_err(|_| HostRouteRefusal::BadSignature)?;
    let ours = log.head();
    if body.head.seq > ours.seq {
        return Err(HostRouteRefusal::StaleLog);
    }
    match log.entry(body.head.seq) {
        Some(entry) if entry.hash() == body.head.hash => {}
        _ => return Err(HostRouteRefusal::Fork),
    }
    if !crate::encoding::ct_eq(&body.nonce, expected_nonce) {
        return Err(HostRouteRefusal::NonceMismatch);
    }
    if body.room != expected_room {
        return Err(HostRouteRefusal::RoomMismatch);
    }
    if body.atem_id != expected_atem_id {
        return Err(HostRouteRefusal::AtemIdMismatch);
    }
    Ok(HostRoute {
        host_id: body.host_id,
        head: body.head,
    })
}

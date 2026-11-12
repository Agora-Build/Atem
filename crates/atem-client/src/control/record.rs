//! The `atem-host-work-control` object (delegated host-work design I.5.3).
//!
//! Wire `{"body":{…},"sig":"<b64u>"}`, signing input
//! `enc(["atem-host-work-control-v1", jcs(body)])` (R9.1): a body-only
//! signed object, with no `kit_sig`, `enc` or `ct`. The body:
//!
//! ```json
//! {"type":"atem-host-work-control","v":1,
//!  "account_id":"acct-test-1","genesis_hash":"<hex>",
//!  "origin":"https://station-dev.agora.build","feed_id":"<UUID v4>",
//!  "principal":"service:svc-1","principal_key":"<hex SHA-256>",
//!  "signer":"service:svc-1",
//!  "action":"revoke","interrupt_running":false,
//!  "record_id":"<UUID v4>","issued_at":1793620800000,
//!  "about":{"integration_id":"i-…","by":"owner"}}
//! ```
//!
//! Two forms, by the principal:
//!
//! - **a service** (`service:<device_id>`): `origin` (the Station's exact
//!   origin), `feed_id` (a UUID v4), `principal_key` (lowercase hex
//!   SHA-256 of the principal's `auth_key` bytes) and
//!   `about.integration_id` are required; `action` is `cover`, `revoke`,
//!   `hold`, `release` or `interrupt_running`, and `interrupt_running` (a
//!   boolean) is present exactly on `revoke`;
//! - **a host sender** (`host:<host_id>`, II.3.1): `action` is
//!   `interrupt_running` only, with the `revoke_seq` of the device-list
//!   revoke it follows; no `origin`, `feed_id`, `principal_key`,
//!   `interrupt_running` or `about.integration_id`.
//!
//! `signer` is the principal itself or `member:<device_id>`, a native
//! member. `about` is display and audit only: `by` is a bounded label
//! (1 to 32 characters of `[a-z_]`; [`KNOWN_BY`] lists the known values,
//! and an unknown one is accepted), and nothing is decided by it.
//!
//! Absent fields are omitted, never `null`; no other field is allowed,
//! in the body or in `about`. The parse checks only the record itself: the
//! signature, which key may sign which action and whether the principal
//! exists are the verifier's, against the device list (I.5.4,
//! [`super::verify`]).
use serde_json::{Map, Value, json};

use crate::canonical::MAX_SAFE_INTEGER;
use crate::domain::{SignLabel, SigningInput};
use crate::encoding::Hash32;
use crate::error::{Error, Result};
use crate::host_principal::{host_principal, parse_host_principal};
use crate::keys::PublicKey;
use crate::membership::entry::{RECOVERY_SIGNER, id_ok};
use crate::membership::service_key_fingerprint;
use crate::provider::{KeyId, KeyProvider};
use crate::session::wire::is_uuid_v4;
use crate::signed::{SignedObject, check_body};
use crate::station_route::normalize_relay;

/// The body's `type`.
pub const CONTROL_TYPE: &str = "atem-host-work-control";

/// The known `about.by` values: who caused the record, as the Portal's
/// feed names it (least disclosure: an Agora.Build admin's change and a
/// disabled owner account both arrive as `agora_build`). `account_deleted`
/// is issued later. Others are accepted for display.
pub const KNOWN_BY: [&str; 7] = [
    "owner",
    "station",
    "agora_build",
    "member_removed",
    "station_removed",
    "reconciled",
    "account_deleted",
];

/// `about.by`: 1 to this many characters of `[a-z_]`.
pub const MAX_BY_CHARS: usize = 32;

/// `account_id`: 1 to this many bytes, as the device list's (§R9.2).
const MAX_ACCOUNT_ID_BYTES: usize = 128;

/// Exactly the body's fields; which of them a record carries depends on its
/// principal and action.
const BODY_FIELDS: [&str; 15] = [
    "type",
    "v",
    "account_id",
    "genesis_hash",
    "origin",
    "feed_id",
    "principal",
    "principal_key",
    "signer",
    "action",
    "interrupt_running",
    "revoke_seq",
    "record_id",
    "issued_at",
    "about",
];

const ABOUT_FIELDS: [&str; 2] = ["integration_id", "by"];

/// Why a record is refused. `code()` is a stable name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlError {
    /// Refused as a signed object (R9.1): not strict I-JSON, a `null`, a
    /// body over 4,096 bytes, an unknown `type`, `v` other than 1, an
    /// array, or a field beside `body` and `sig`.
    Object(Error),
    /// A signed object of another type.
    WrongType,
    /// A field outside the body's, or outside `about`'s.
    UnknownField,
    /// A required field missing, mistyped or out of its grammar; names it.
    Malformed(&'static str),
    /// A known field this record's form doesn't take: `origin`, `feed_id`,
    /// `principal_key` or `about.integration_id` on a host principal's
    /// record, `interrupt_running` beside an action other than `revoke`,
    /// `revoke_seq` on a service's record.
    FieldNotAllowed(&'static str),
    /// A host principal's record other than `interrupt_running` (its
    /// revoke and readmit are device-list entries; it has no cover, hold or
    /// release, II.3.1).
    NotForHostPrincipal,
}

impl ControlError {
    pub fn code(&self) -> &'static str {
        match self {
            ControlError::Object(e) => e.code(),
            ControlError::WrongType => "wrong_type",
            ControlError::UnknownField => "unknown_field",
            ControlError::Malformed(_) => "malformed",
            ControlError::FieldNotAllowed(_) => "field_not_allowed",
            ControlError::NotForHostPrincipal => "not_for_host_principal",
        }
    }
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlError::Object(e) => e.fmt(f),
            ControlError::Malformed(what) => write!(f, "malformed: {what}"),
            ControlError::FieldNotAllowed(what) => write!(f, "field not allowed: {what}"),
            other => f.write_str(other.code()),
        }
    }
}

impl std::error::Error for ControlError {}

impl From<ControlError> for Error {
    /// For [`build_control`]: the object layer's error as it is, any other
    /// as `Malformed`.
    fn from(e: ControlError) -> Self {
        match e {
            ControlError::Object(e) => e,
            ControlError::WrongType => Error::Malformed("not an atem-host-work-control"),
            ControlError::UnknownField => Error::Malformed("unknown field"),
            ControlError::Malformed(what) | ControlError::FieldNotAllowed(what) => {
                Error::Malformed(what)
            }
            ControlError::NotForHostPrincipal => {
                Error::Malformed("a host principal's record is interrupt_running only")
            }
        }
    }
}

/// Whom a record stops: its `principal`, by kind, with the id after the
/// prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlPrincipal {
    /// `service:<device_id>`: a service member of the device list.
    Service(String),
    /// `host:<host_id>`: a host sender (II.2.1).
    Host(String),
}

impl ControlPrincipal {
    /// `service:<id>` (a device id: `[A-Za-z0-9._:-]`, 1 to 128 bytes, never
    /// `recovery`) or `host:<host_id>` (an opaque id of the same grammar,
    /// read by [`parse_host_principal`], the one definition of a host
    /// sender's principal).
    pub fn parse(name: &str) -> Option<Self> {
        if let Some(id) = name.strip_prefix("service:") {
            device_id_ok(id).then(|| ControlPrincipal::Service(id.to_owned()))
        } else {
            parse_host_principal(name).map(|id| ControlPrincipal::Host(id.to_owned()))
        }
    }

    /// `service:<id>` or `host:<host_id>` ([`host_principal`]).
    pub fn name(&self) -> String {
        match self {
            ControlPrincipal::Service(id) => format!("service:{id}"),
            ControlPrincipal::Host(id) => host_principal(id),
        }
    }

    /// The id after the prefix.
    pub fn id(&self) -> &str {
        match self {
            ControlPrincipal::Service(id) | ControlPrincipal::Host(id) => id,
        }
    }

    pub fn is_host(&self) -> bool {
        matches!(self, ControlPrincipal::Host(_))
    }
}

/// Who the body names as its signer: the principal itself, or a native
/// member (`member:<device_id>`). The verifier takes the key from there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlSigner {
    /// `signer` equals `principal`.
    Principal,
    /// `member:<device_id>`.
    Member(String),
}

impl ControlSigner {
    /// The `signer` string of a record about `principal`.
    pub fn name(&self, principal: &ControlPrincipal) -> String {
        match self {
            ControlSigner::Principal => principal.name(),
            ControlSigner::Member(id) => format!("member:{id}"),
        }
    }

    fn parse(text: &str, principal: &ControlPrincipal) -> Option<Self> {
        if text == principal.name() {
            Some(ControlSigner::Principal)
        } else {
            text.strip_prefix("member:")
                .filter(|id| device_id_ok(id))
                .map(|id| ControlSigner::Member(id.to_owned()))
        }
    }
}

/// A record's `action`, with the field that goes with it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlAction {
    /// `cover`: the feed covers the principal from now on.
    Cover,
    /// `revoke`: final; `interrupt_running` also interrupts its started
    /// tasks.
    Revoke { interrupt_running: bool },
    /// `hold`: pause.
    Hold,
    /// `release`: resume.
    Release,
    /// `interrupt_running`: "also interrupt", chosen after the revocation.
    /// `revoke_seq` is the device-list revoke a host principal's record
    /// follows; `None` for a service.
    InterruptRunning { revoke_seq: Option<u64> },
}

impl ControlAction {
    /// The `action` string.
    pub fn name(self) -> &'static str {
        match self {
            ControlAction::Cover => "cover",
            ControlAction::Revoke { .. } => "revoke",
            ControlAction::Hold => "hold",
            ControlAction::Release => "release",
            ControlAction::InterruptRunning { .. } => "interrupt_running",
        }
    }
}

/// A service record's feed: the Station's exact `origin` and its control
/// feed's `feed_id` (I.5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlFeed {
    pub origin: String,
    pub feed_id: String,
}

/// `about`: display and audit only, never authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlAbout {
    /// The integration (Auth's `i-…` client id); required on a service's
    /// record, absent on a host principal's.
    pub integration_id: Option<String>,
    /// Who caused the record: a label of 1 to 32 characters of `[a-z_]`.
    pub by: String,
}

impl ControlAbout {
    /// Whether `by` is one of [`KNOWN_BY`] (display only: an unknown value
    /// is still a valid record).
    pub fn is_known_by(&self) -> bool {
        KNOWN_BY.contains(&self.by.as_str())
    }
}

/// A record's body, typed. [`ControlBody::to_json`] writes it, omitting what
/// is absent; [`build_control`] checks it as the parse would, then signs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlBody {
    pub account_id: String,
    pub genesis_hash: Hash32,
    /// A service's record: its feed. `None` for a host principal (bound to
    /// no feed).
    pub feed: Option<ControlFeed>,
    pub principal: ControlPrincipal,
    /// A service's record: the hex SHA-256 of the principal's `auth_key`
    /// bytes (its `r9_svc`). `None` for a host principal.
    pub principal_key: Option<Hash32>,
    pub signer: ControlSigner,
    pub action: ControlAction,
    /// A UUID v4, the record's identity.
    pub record_id: String,
    /// When it was issued (ms since the epoch; display only, I.5.3).
    pub issued_at: u64,
    pub about: ControlAbout,
}

impl ControlBody {
    /// The body object. Absent fields are omitted.
    pub fn to_json(&self) -> Value {
        let mut body = Map::new();
        body.insert("type".into(), json!(CONTROL_TYPE));
        body.insert("v".into(), json!(1));
        body.insert("account_id".into(), json!(self.account_id));
        body.insert("genesis_hash".into(), json!(self.genesis_hash.to_hex()));
        if let Some(feed) = &self.feed {
            body.insert("origin".into(), json!(feed.origin));
            body.insert("feed_id".into(), json!(feed.feed_id));
        }
        body.insert("principal".into(), json!(self.principal.name()));
        if let Some(key) = &self.principal_key {
            body.insert("principal_key".into(), json!(key.to_hex()));
        }
        body.insert("signer".into(), json!(self.signer.name(&self.principal)));
        body.insert("action".into(), json!(self.action.name()));
        match self.action {
            ControlAction::Revoke { interrupt_running } => {
                body.insert("interrupt_running".into(), json!(interrupt_running));
            }
            ControlAction::InterruptRunning {
                revoke_seq: Some(seq),
            } => {
                body.insert("revoke_seq".into(), json!(seq));
            }
            _ => {}
        }
        body.insert("record_id".into(), json!(self.record_id));
        body.insert("issued_at".into(), json!(self.issued_at));
        let mut about = Map::new();
        if let Some(id) = &self.about.integration_id {
            about.insert("integration_id".into(), json!(id));
        }
        about.insert("by".into(), json!(self.about.by));
        body.insert("about".into(), Value::Object(about));
        Value::Object(body)
    }

    /// A body from its JSON object, read exactly as [`ControlRecord::parse`]
    /// reads a record's: the signed-object checks first (R9.1: an object,
    /// a known `type`, `v: 1`, no `null`, no array, `jcs` at most 4,096
    /// bytes), then `type` must be this one's, then the body's own rules.
    /// For a builder that has the body as JSON (the bindings).
    pub fn from_json(body: &Value) -> std::result::Result<Self, ControlError> {
        let (label, _) = check_body(body).map_err(ControlError::Object)?;
        if label != SignLabel::HostWorkControl {
            return Err(ControlError::WrongType);
        }
        Self::read(body)
    }

    /// Exactly a record's body (the object layer already checked `type`,
    /// `v`, `null`, arrays and the size).
    fn read(body: &Value) -> std::result::Result<Self, ControlError> {
        use ControlError::{FieldNotAllowed, Malformed};
        let o = body.as_object().ok_or(Malformed("body"))?;
        if !o.keys().all(|k| BODY_FIELDS.contains(&k.as_str())) {
            return Err(ControlError::UnknownField);
        }
        let about = o
            .get("about")
            .ok_or(Malformed("about"))?
            .as_object()
            .ok_or(Malformed("about"))?;
        if !about.keys().all(|k| ABOUT_FIELDS.contains(&k.as_str())) {
            return Err(ControlError::UnknownField);
        }

        let account_id = str_field(o, "account_id")?;
        if account_id.is_empty() || account_id.len() > MAX_ACCOUNT_ID_BYTES {
            return Err(Malformed("account_id"));
        }
        let genesis_hash = hash_field(o, "genesis_hash")?;
        let principal =
            ControlPrincipal::parse(str_field(o, "principal")?).ok_or(Malformed("principal"))?;
        let signer =
            ControlSigner::parse(str_field(o, "signer")?, &principal).ok_or(Malformed("signer"))?;
        let action = str_field(o, "action")?;
        if !["cover", "revoke", "hold", "release", "interrupt_running"].contains(&action) {
            return Err(Malformed("action"));
        }

        let (feed, principal_key, action) = match &principal {
            ControlPrincipal::Service(_) => {
                let origin = str_field(o, "origin")?;
                if normalize_relay(origin).as_deref() != Ok(origin) {
                    return Err(Malformed("origin"));
                }
                let feed_id = str_field(o, "feed_id")?;
                if !is_uuid_v4(feed_id) {
                    return Err(Malformed("feed_id"));
                }
                let principal_key = hash_field(o, "principal_key")?;
                if o.contains_key("revoke_seq") {
                    return Err(FieldNotAllowed("revoke_seq"));
                }
                let interrupt_running = o.get("interrupt_running");
                let action = match (action, interrupt_running) {
                    ("revoke", Some(value)) => ControlAction::Revoke {
                        interrupt_running: value.as_bool().ok_or(Malformed("interrupt_running"))?,
                    },
                    ("revoke", None) => return Err(Malformed("interrupt_running")),
                    (_, Some(_)) => return Err(FieldNotAllowed("interrupt_running")),
                    ("cover", None) => ControlAction::Cover,
                    ("hold", None) => ControlAction::Hold,
                    ("release", None) => ControlAction::Release,
                    (_, None) => ControlAction::InterruptRunning { revoke_seq: None },
                };
                let feed = ControlFeed {
                    origin: origin.to_owned(),
                    feed_id: feed_id.to_owned(),
                };
                (Some(feed), Some(principal_key), action)
            }
            ControlPrincipal::Host(_) => {
                if action != "interrupt_running" {
                    return Err(ControlError::NotForHostPrincipal);
                }
                for field in ["origin", "feed_id", "principal_key", "interrupt_running"] {
                    if o.contains_key(field) {
                        return Err(FieldNotAllowed(field));
                    }
                }
                if about.contains_key("integration_id") {
                    return Err(FieldNotAllowed("about.integration_id"));
                }
                let revoke_seq = o
                    .get("revoke_seq")
                    .and_then(Value::as_u64)
                    .filter(|seq| (1..=MAX_SAFE_INTEGER).contains(seq))
                    .ok_or(Malformed("revoke_seq"))?;
                let action = ControlAction::InterruptRunning {
                    revoke_seq: Some(revoke_seq),
                };
                (None, None, action)
            }
        };

        let record_id = str_field(o, "record_id")?;
        if !is_uuid_v4(record_id) {
            return Err(Malformed("record_id"));
        }
        let issued_at = o
            .get("issued_at")
            .and_then(Value::as_u64)
            .filter(|t| *t <= MAX_SAFE_INTEGER)
            .ok_or(Malformed("issued_at"))?;

        let by = about
            .get("by")
            .and_then(Value::as_str)
            .filter(|by| by_ok(by))
            .ok_or(Malformed("about.by"))?;
        let integration_id = match (&principal, about.get("integration_id")) {
            (ControlPrincipal::Service(_), Some(id)) => Some(
                id.as_str()
                    .filter(|id| id_ok(id))
                    .ok_or(Malformed("about.integration_id"))?
                    .to_owned(),
            ),
            (ControlPrincipal::Service(_), None) => {
                return Err(Malformed("about.integration_id"));
            }
            // A host principal's was refused above.
            (ControlPrincipal::Host(_), _) => None,
        };

        Ok(ControlBody {
            account_id: account_id.to_owned(),
            genesis_hash,
            feed,
            principal,
            principal_key,
            signer,
            action,
            record_id: record_id.to_owned(),
            issued_at,
            about: ControlAbout {
                integration_id,
                by: by.to_owned(),
            },
        })
    }
}

/// A parsed, structurally valid control record. Not yet verified: its
/// signature, signer and principal are checked against the device list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlRecord {
    body: ControlBody,
    object: SignedObject,
}

impl ControlRecord {
    /// Strict parse of the wire bytes, `{"body":{…},"sig":"<b64u>"}`.
    pub fn parse(bytes: &[u8]) -> std::result::Result<Self, ControlError> {
        Self::from_signed(SignedObject::parse(bytes).map_err(ControlError::Object)?)
    }

    /// From a signed object already parsed (e.g. one record of a
    /// `control_records` message).
    pub fn from_signed(object: SignedObject) -> std::result::Result<Self, ControlError> {
        if object.label() != SignLabel::HostWorkControl {
            return Err(ControlError::WrongType);
        }
        // A body-only object: `SignedObject` refuses `kit_sig` and a sealed
        // part for this type already; this states it.
        if object.kit_sig().is_some() || object.sealed().is_some() {
            return Err(ControlError::Object(Error::Malformed(
                "unknown field beside body",
            )));
        }
        let body = ControlBody::read(object.body())?;
        Ok(ControlRecord { body, object })
    }

    /// The typed body.
    pub fn body(&self) -> &ControlBody {
        &self.body
    }

    pub fn account_id(&self) -> &str {
        &self.body.account_id
    }

    pub fn genesis_hash(&self) -> Hash32 {
        self.body.genesis_hash
    }

    /// `(origin, feed_id)` of a service's record; `None` for a host
    /// principal's, which is bound to no feed.
    pub fn feed(&self) -> Option<(&str, &str)> {
        self.body
            .feed
            .as_ref()
            .map(|feed| (feed.origin.as_str(), feed.feed_id.as_str()))
    }

    pub fn principal(&self) -> &ControlPrincipal {
        &self.body.principal
    }

    /// A service's record: the hex SHA-256 of the principal's `auth_key`
    /// bytes. `None` for a host principal's.
    pub fn principal_key(&self) -> Option<Hash32> {
        self.body.principal_key
    }

    pub fn signer(&self) -> &ControlSigner {
        &self.body.signer
    }

    pub fn action(&self) -> ControlAction {
        self.body.action
    }

    pub fn record_id(&self) -> &str {
        &self.body.record_id
    }

    pub fn issued_at(&self) -> u64 {
        self.body.issued_at
    }

    /// Display and audit only.
    pub fn about(&self) -> &ControlAbout {
        &self.body.about
    }

    /// The signed object (its `verify` takes the key the verifier pins).
    pub fn object(&self) -> &SignedObject {
        &self.object
    }
}

/// Signs `body` with `key` (behind `provider`) after checking it exactly as
/// [`ControlRecord::parse`] would, so nothing is signed that a verifier
/// refuses as malformed.
pub fn build_control(
    provider: &dyn KeyProvider,
    key: &KeyId,
    body: &ControlBody,
) -> Result<SignedObject> {
    let value = body.to_json();
    ControlBody::read(&value)?;
    SignedObject::sign(provider, key, value)
}

/// The bytes a signer signs for `body`, `enc(["atem-host-work-control-v1",
/// jcs(body)])`, after checking it exactly as [`build_control`] does: for a
/// signer that answers asynchronously (a Station's key in a KMS, WebCrypto),
/// which then hands the signature to [`control_with_signature`].
pub fn control_signing_input(body: &ControlBody) -> Result<SigningInput> {
    let value = body.to_json();
    ControlBody::read(&value)?;
    let (label, jcs) = check_body(&value)?;
    Ok(SigningInput::new(label, jcs.as_bytes()))
}

/// The record of `body` with `signature`, a signature by `signer` over
/// [`control_signing_input`]'s bytes (P-256 `r‖s`, either S: normalized to
/// low S; Ed25519). The body is checked as [`build_control`] checks it,
/// and the signature verified under `signer` before the record is
/// returned (`bad_signature` otherwise; an X25519 key is `wrong_alg`).
/// Whether `signer` may sign this record is the verifier's, against the
/// device list ([`super::verify`]).
pub fn control_with_signature(
    body: &ControlBody,
    signer: &PublicKey,
    signature: &[u8],
) -> Result<SignedObject> {
    build_control(&Given { signer, signature }, &KeyId::new("signer"), body)
}

/// A key store that holds one signature already made: `sign` hands it
/// back, and [`crate::provider::sign`] normalizes and verifies it under
/// the key as for any provider.
struct Given<'a> {
    signer: &'a PublicKey,
    signature: &'a [u8],
}

impl KeyProvider for Given<'_> {
    fn public_key(&self, _: &KeyId) -> Result<PublicKey> {
        Ok(self.signer.clone())
    }

    fn sign(&self, _: &KeyId, _: &SigningInput) -> Result<Vec<u8>> {
        Ok(self.signature.to_vec())
    }

    fn x25519(&self, _: &KeyId, _: &[u8; 32]) -> Result<zeroize::Zeroizing<[u8; 32]>> {
        Err(Error::UnknownKey)
    }

    fn hpke_open(
        &self,
        _: &KeyId,
        _: &[u8],
        _: &[u8],
        _: &[u8],
        _: &[u8],
    ) -> Result<zeroize::Zeroizing<Vec<u8>>> {
        Err(Error::UnknownKey)
    }
}

/// A service record's `principal_key` for the principal's `auth_key`: the
/// SHA-256 of the key's raw bytes, which is exactly the integration's
/// `r9Svc` ([`service_key_fingerprint`], one definition), so a Station can
/// cross-check a record against the Portal feed (decision 8). An X25519
/// key is no `auth_key` (`wrong_alg`).
pub fn principal_key_of(auth_key: &PublicKey) -> Result<Hash32> {
    Hash32::from_hex(&service_key_fingerprint(auth_key)?)
}

/// A device id: an opaque id that isn't the reserved `recovery` signer.
fn device_id_ok(id: &str) -> bool {
    id_ok(id) && id != RECOVERY_SIGNER
}

/// `about.by`: 1 to 32 characters of `[a-z_]`.
fn by_ok(by: &str) -> bool {
    (1..=MAX_BY_CHARS).contains(&by.len())
        && by.bytes().all(|b| b.is_ascii_lowercase() || b == b'_')
}

fn str_field<'a>(
    o: &'a Map<String, Value>,
    name: &'static str,
) -> std::result::Result<&'a str, ControlError> {
    o.get(name)
        .and_then(Value::as_str)
        .ok_or(ControlError::Malformed(name))
}

fn hash_field(
    o: &Map<String, Value>,
    name: &'static str,
) -> std::result::Result<Hash32, ControlError> {
    o.get(name)
        .and_then(Value::as_str)
        .and_then(|text| Hash32::from_hex(text).ok())
        .ok_or(ControlError::Malformed(name))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encoding::b64u;
    use crate::keys::Alg;
    use crate::software::SoftwareKeys;

    const FEED: &str = "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b";
    const RECORD: &str = "0b9a8c7d-6e5f-4a3b-9c2d-1e0f2a3b4c5d";
    const ORIGIN: &str = "https://station-dev.agora.build";
    const INTEGRATION: &str = "i-01jc5zq9x8w7v6t5s4r3q2p1n0";

    fn keys() -> SoftwareKeys {
        let mut keys = SoftwareKeys::new();
        keys.insert_p256(KeyId::new("svc"), &[1u8; 32]).unwrap();
        keys.insert_ed25519(KeyId::new("svc-ed"), &[2u8; 32]);
        keys.insert_p256(KeyId::new("mac"), &[3u8; 32]).unwrap();
        keys
    }

    fn service(action: ControlAction) -> ControlBody {
        ControlBody {
            account_id: "acct-test-1".into(),
            genesis_hash: Hash32([0x11; 32]),
            feed: Some(ControlFeed {
                origin: ORIGIN.into(),
                feed_id: FEED.into(),
            }),
            principal: ControlPrincipal::Service("svc-1".into()),
            principal_key: Some(Hash32([0x22; 32])),
            signer: ControlSigner::Principal,
            action,
            record_id: RECORD.into(),
            issued_at: 1_793_620_800_000,
            about: ControlAbout {
                integration_id: Some(INTEGRATION.into()),
                by: "owner".into(),
            },
        }
    }

    fn host(revoke_seq: u64) -> ControlBody {
        ControlBody {
            account_id: "acct-test-1".into(),
            genesis_hash: Hash32([0x11; 32]),
            feed: None,
            principal: ControlPrincipal::Host("host-a".into()),
            principal_key: None,
            signer: ControlSigner::Member("dev-mac".into()),
            action: ControlAction::InterruptRunning {
                revoke_seq: Some(revoke_seq),
            },
            record_id: RECORD.into(),
            issued_at: 1_793_620_800_000,
            about: ControlAbout {
                integration_id: None,
                by: "owner".into(),
            },
        }
    }

    const SERVICE_ACTIONS: [ControlAction; 6] = [
        ControlAction::Cover,
        ControlAction::Revoke {
            interrupt_running: false,
        },
        ControlAction::Revoke {
            interrupt_running: true,
        },
        ControlAction::Hold,
        ControlAction::Release,
        ControlAction::InterruptRunning { revoke_seq: None },
    ];

    /// A service revoke's body as JSON, written out (the design's example).
    fn revoke_json() -> Value {
        json!({
            "type": "atem-host-work-control", "v": 1,
            "account_id": "acct-test-1", "genesis_hash": "11".repeat(32),
            "origin": ORIGIN, "feed_id": FEED,
            "principal": "service:svc-1", "principal_key": "22".repeat(32),
            "signer": "service:svc-1",
            "action": "revoke", "interrupt_running": false,
            "record_id": RECORD, "issued_at": 1_793_620_800_000u64,
            "about": {"integration_id": INTEGRATION, "by": "owner"},
        })
    }

    /// A host principal's `interrupt_running`, written out (II.3.1).
    fn host_json() -> Value {
        json!({
            "type": "atem-host-work-control", "v": 1,
            "account_id": "acct-test-1", "genesis_hash": "11".repeat(32),
            "principal": "host:host-a", "signer": "member:dev-mac",
            "action": "interrupt_running", "revoke_seq": 7,
            "record_id": RECORD, "issued_at": 1_793_620_800_000u64,
            "about": {"by": "owner"},
        })
    }

    /// The wire object around `body` (a signature of the right shape; the
    /// parse never verifies it).
    fn wire(body: &Value) -> Vec<u8> {
        json!({"body": body, "sig": b64u(&[7u8; 64])})
            .to_string()
            .into_bytes()
    }

    fn parse(body: &Value) -> std::result::Result<ControlRecord, ControlError> {
        ControlRecord::parse(&wire(body))
    }

    fn with(mut body: Value, key: &str, value: Value) -> Value {
        body[key] = value;
        body
    }

    fn without(mut body: Value, key: &str) -> Value {
        body.as_object_mut().unwrap().remove(key);
        body
    }

    #[test]
    fn parses_each_service_action() {
        // The design's example, field for field.
        let rec = parse(&revoke_json()).unwrap();
        assert_eq!(rec.account_id(), "acct-test-1");
        assert_eq!(rec.genesis_hash(), Hash32([0x11; 32]));
        assert_eq!(rec.feed(), Some((ORIGIN, FEED)));
        assert_eq!(rec.principal(), &ControlPrincipal::Service("svc-1".into()));
        assert_eq!(rec.principal_key(), Some(Hash32([0x22; 32])));
        assert_eq!(rec.signer(), &ControlSigner::Principal);
        assert_eq!(
            rec.action(),
            ControlAction::Revoke {
                interrupt_running: false
            }
        );
        assert_eq!(rec.record_id(), RECORD);
        assert_eq!(rec.issued_at(), 1_793_620_800_000);
        assert_eq!(rec.about().integration_id.as_deref(), Some(INTEGRATION));
        assert_eq!(rec.about().by, "owner");
        assert_eq!(rec.object().label(), SignLabel::HostWorkControl);
        assert_eq!(rec.body(), &service(rec.action()));

        // Every action, signed by the principal or by a native manager.
        for action in SERVICE_ACTIONS {
            for (signer, name) in [
                (ControlSigner::Principal, "service:svc-1"),
                (ControlSigner::Member("dev-mac".into()), "member:dev-mac"),
            ] {
                let mut body = service(action);
                body.signer = signer.clone();
                let json = body.to_json();
                assert_eq!(json["signer"], name);
                let rec = parse(&json).unwrap();
                assert_eq!(rec.action(), action);
                assert_eq!(rec.signer(), &signer);
                assert_eq!(rec.body(), &body);
            }
        }

        // An action of no record, and principals of no record.
        assert_eq!(
            parse(&with(revoke_json(), "action", json!("pause"))),
            Err(ControlError::Malformed("action"))
        );
        for principal in [
            "member:svc-1",
            "browser:g-1",
            "service:",
            "service:recovery",
            "service:a b",
            "svc-1",
            "host:",
        ] {
            assert_eq!(
                parse(&with(revoke_json(), "principal", json!(principal))),
                Err(ControlError::Malformed("principal")),
                "{principal}"
            );
        }
        // The signer is the principal itself or a native member.
        for signer in [
            "service:svc-2",
            "host:host-a",
            "member:",
            "member:recovery",
            "dev-mac",
        ] {
            assert_eq!(
                parse(&with(revoke_json(), "signer", json!(signer))),
                Err(ControlError::Malformed("signer")),
                "{signer}"
            );
        }
        // Mistyped fields.
        for (key, value) in [
            ("account_id", json!("")),
            ("account_id", json!("a".repeat(129))),
            ("genesis_hash", json!("AB".repeat(32))),
            ("genesis_hash", json!("ab".repeat(31))),
            ("principal_key", json!("2".repeat(63))),
            ("issued_at", json!(-1)),
            ("issued_at", json!("1793620800000")),
        ] {
            assert_eq!(
                parse(&with(revoke_json(), key, value.clone())),
                Err(ControlError::Malformed(key)),
                "{key}: {value}"
            );
        }
        for key in [
            "account_id",
            "genesis_hash",
            "principal",
            "signer",
            "action",
            "issued_at",
        ] {
            assert_eq!(
                parse(&without(revoke_json(), key)),
                Err(ControlError::Malformed(key)),
                "{key}"
            );
        }
    }

    #[test]
    fn interrupt_running_only_on_revoke() {
        // Required on a revoke, and a boolean.
        assert_eq!(
            parse(&without(revoke_json(), "interrupt_running")),
            Err(ControlError::Malformed("interrupt_running"))
        );
        for value in [json!("true"), json!(1), json!({})] {
            assert_eq!(
                parse(&with(revoke_json(), "interrupt_running", value)),
                Err(ControlError::Malformed("interrupt_running"))
            );
        }
        // Never on another action, whatever its value.
        for action in ["cover", "hold", "release", "interrupt_running"] {
            let body = with(revoke_json(), "action", json!(action));
            for value in [false, true] {
                assert_eq!(
                    parse(&with(body.clone(), "interrupt_running", json!(value))),
                    Err(ControlError::FieldNotAllowed("interrupt_running")),
                    "{action}"
                );
            }
            assert!(
                parse(&without(body, "interrupt_running")).is_ok(),
                "{action}"
            );
        }
    }

    #[test]
    fn host_form_only_interrupt_with_revoke_seq() {
        let rec = parse(&host_json()).unwrap();
        assert_eq!(rec.principal(), &ControlPrincipal::Host("host-a".into()));
        assert_eq!(
            rec.action(),
            ControlAction::InterruptRunning {
                revoke_seq: Some(7)
            }
        );
        assert_eq!(rec.feed(), None);
        assert_eq!(rec.principal_key(), None);
        assert_eq!(rec.signer(), &ControlSigner::Member("dev-mac".into()));
        assert_eq!(rec.about().integration_id, None);
        assert_eq!(rec.body(), &host(7));
        // The host's own key signs nothing (I.5.4), but that is the
        // verifier's refusal: the object names the host as its signer.
        let self_signed = parse(&with(host_json(), "signer", json!("host:host-a"))).unwrap();
        assert_eq!(self_signed.signer(), &ControlSigner::Principal);

        // No cover, revoke, hold or release for a host principal.
        for action in ["cover", "hold", "release"] {
            assert_eq!(
                parse(&with(host_json(), "action", json!(action))),
                Err(ControlError::NotForHostPrincipal),
                "{action}"
            );
        }
        let revoke = with(host_json(), "action", json!("revoke"));
        assert_eq!(
            parse(&with(revoke, "interrupt_running", json!(true))),
            Err(ControlError::NotForHostPrincipal)
        );
        // `revoke_seq`: required, a device-list seq (≥ 1).
        assert_eq!(
            parse(&without(host_json(), "revoke_seq")),
            Err(ControlError::Malformed("revoke_seq"))
        );
        for value in [json!(0), json!(-7), json!("7"), json!(true)] {
            assert_eq!(
                parse(&with(host_json(), "revoke_seq", value.clone())),
                Err(ControlError::Malformed("revoke_seq")),
                "{value}"
            );
        }
        // ... and only on a host principal's record.
        let interrupt = with(
            without(revoke_json(), "interrupt_running"),
            "action",
            json!("interrupt_running"),
        );
        assert!(parse(&interrupt).is_ok());
        assert_eq!(
            parse(&with(interrupt, "revoke_seq", json!(7))),
            Err(ControlError::FieldNotAllowed("revoke_seq"))
        );
        assert_eq!(
            parse(&with(revoke_json(), "revoke_seq", json!(7))),
            Err(ControlError::FieldNotAllowed("revoke_seq"))
        );
    }

    #[test]
    fn host_form_refuses_feed_fields() {
        for (key, value) in [
            ("origin", json!(ORIGIN)),
            ("feed_id", json!(FEED)),
            ("principal_key", json!("22".repeat(32))),
            ("interrupt_running", json!(false)),
        ] {
            assert_eq!(
                parse(&with(host_json(), key, value)),
                Err(ControlError::FieldNotAllowed(key)),
                "{key}"
            );
        }
        let mut about = host_json();
        about["about"]["integration_id"] = json!(INTEGRATION);
        assert_eq!(
            parse(&about),
            Err(ControlError::FieldNotAllowed("about.integration_id"))
        );
    }

    #[test]
    fn unknown_field_null_oversize_wrong_v_refused() {
        // An unknown field in the body or in `about`.
        assert_eq!(
            parse(&with(revoke_json(), "note", json!("x"))),
            Err(ControlError::UnknownField)
        );
        let mut about = revoke_json();
        about["about"]["admin"] = json!("someone");
        assert_eq!(parse(&about), Err(ControlError::UnknownField));
        // `null` anywhere, even for a field the form leaves out.
        assert_eq!(
            parse(&with(revoke_json(), "revoke_seq", Value::Null)),
            Err(ControlError::Object(Error::NullValue))
        );
        let mut about = host_json();
        about["about"]["integration_id"] = Value::Null;
        assert_eq!(parse(&about), Err(ControlError::Object(Error::NullValue)));
        // A body whose jcs is over 4096 bytes.
        assert_eq!(
            parse(&with(revoke_json(), "note", json!("x".repeat(4096)))),
            Err(ControlError::Object(Error::TooLarge))
        );
        // `v` other than 1; `type` other than the record's.
        for v in [json!(2), json!(0), json!("1")] {
            assert!(matches!(
                parse(&with(revoke_json(), "v", v)),
                Err(ControlError::Object(Error::Malformed(_)))
            ));
        }
        assert!(matches!(
            parse(&without(revoke_json(), "v")),
            Err(ControlError::Object(Error::Malformed(_)))
        ));
        assert_eq!(
            parse(&with(revoke_json(), "type", json!("host_work_control"))),
            Err(ControlError::Object(Error::UnknownType))
        );
        // A signed object of another type is not a record.
        let seen = SignedObject::parse(&wire(&json!({"type": "atem-seen", "v": 1}))).unwrap();
        assert_eq!(
            ControlRecord::from_signed(seen),
            Err(ControlError::WrongType)
        );
        // No arrays, no field beside body and sig (a body-only object), no
        // duplicate keys, no floats.
        assert_eq!(
            parse(&with(revoke_json(), "record_id", json!([RECORD]))),
            Err(ControlError::Object(Error::ArrayNotCanonical))
        );
        for (key, value) in [
            ("enc", json!("AA")),
            ("kit_sig", json!("AA")),
            ("note", json!("x")),
        ] {
            let mut object = json!({"body": revoke_json(), "sig": b64u(&[7u8; 64])});
            object[key] = value;
            assert!(
                matches!(
                    ControlRecord::parse(object.to_string().as_bytes()),
                    Err(ControlError::Object(_))
                ),
                "{key}"
            );
        }
        let text = String::from_utf8(wire(&revoke_json())).unwrap();
        let doubled = text.replacen("\"v\":1", "\"v\":1,\"v\":1", 1);
        assert!(matches!(
            ControlRecord::parse(doubled.as_bytes()),
            Err(ControlError::Object(Error::Strict(_)))
        ));
        let float = text.replacen("\"v\":1", "\"v\":1.0", 1);
        assert!(matches!(
            ControlRecord::parse(float.as_bytes()),
            Err(ControlError::Object(Error::Strict(_)))
        ));
    }

    #[test]
    fn record_id_must_be_uuid_v4() {
        for (key, good) in [("record_id", RECORD), ("feed_id", FEED)] {
            assert!(parse(&with(revoke_json(), key, json!(good))).is_ok());
            for bad in [
                good.to_uppercase(),
                good.replace('-', ""),
                // Version 1, and the wrong variant.
                format!("{}1{}", &good[..14], &good[15..]),
                format!("{}c{}", &good[..19], &good[20..]),
                format!("{good}0"),
                String::new(),
            ] {
                assert_eq!(
                    parse(&with(revoke_json(), key, json!(bad))),
                    Err(ControlError::Malformed(key)),
                    "{key}: {bad}"
                );
            }
            assert_eq!(
                parse(&with(revoke_json(), key, json!(7))),
                Err(ControlError::Malformed(key))
            );
        }
        assert_eq!(
            parse(&without(revoke_json(), "record_id")),
            Err(ControlError::Malformed("record_id"))
        );
        assert_eq!(
            parse(&with(host_json(), "record_id", json!("r-1"))),
            Err(ControlError::Malformed("record_id"))
        );
    }

    #[test]
    fn about_by_is_a_bounded_label() {
        let by = |value: Value| {
            let mut body = revoke_json();
            body["about"]["by"] = value;
            parse(&body)
        };
        for good in
            KNOWN_BY
                .iter()
                .map(|s| s.to_string())
                .chain(["a".repeat(32), "_".into(), "z".into()])
        {
            assert_eq!(by(json!(good)).unwrap().about().by, good);
        }
        for bad in [
            String::new(),
            "a".repeat(33),
            "Owner".into(),
            "OWNER".into(),
            "agora-build".into(),
            "owner1".into(),
            "station owner".into(),
            "owner\n".into(),
            "é".into(),
        ] {
            assert_eq!(
                by(json!(bad)),
                Err(ControlError::Malformed("about.by")),
                "{bad:?}"
            );
        }
        assert_eq!(by(json!(7)), Err(ControlError::Malformed("about.by")));
        let mut no_by = revoke_json();
        no_by["about"].as_object_mut().unwrap().remove("by");
        assert_eq!(parse(&no_by), Err(ControlError::Malformed("about.by")));
        // `about` itself is required, and an object.
        assert_eq!(
            parse(&without(revoke_json(), "about")),
            Err(ControlError::Malformed("about"))
        );
        assert_eq!(
            parse(&with(revoke_json(), "about", json!("owner"))),
            Err(ControlError::Malformed("about"))
        );
    }

    #[test]
    fn about_by_unknown_value_still_applies() {
        let keys = keys();
        let mut body = service(ControlAction::Revoke {
            interrupt_running: true,
        });
        body.about.by = "something_new".into();
        let object = build_control(&keys, &KeyId::new("svc"), &body).unwrap();
        let rec = ControlRecord::parse(object.to_json().to_string().as_bytes()).unwrap();
        assert_eq!(rec.about().by, "something_new");
        assert!(!rec.about().is_known_by());
        assert_eq!(
            rec.action(),
            ControlAction::Revoke {
                interrupt_running: true
            }
        );
        let svc = keys.public_key(&KeyId::new("svc")).unwrap();
        rec.object().verify(&svc).unwrap();
        // The same record with a known `by` is known; display only.
        body.about.by = "agora_build".into();
        let known = build_control(&keys, &KeyId::new("svc"), &body).unwrap();
        let known = ControlRecord::from_signed(known).unwrap();
        assert!(known.about().is_known_by());
        assert_eq!(known.action(), rec.action());
    }

    #[test]
    fn service_record_needs_integration_id() {
        let mut no_integration = revoke_json();
        no_integration["about"]
            .as_object_mut()
            .unwrap()
            .remove("integration_id");
        assert_eq!(
            parse(&no_integration),
            Err(ControlError::Malformed("about.integration_id"))
        );
        for bad in [
            json!(""),
            json!("i 01"),
            json!("i/01"),
            json!(7),
            json!("a".repeat(129)),
        ] {
            let mut body = revoke_json();
            body["about"]["integration_id"] = bad.clone();
            assert_eq!(
                parse(&body),
                Err(ControlError::Malformed("about.integration_id")),
                "{bad}"
            );
        }
        // Its feed and key too.
        for key in ["origin", "feed_id", "principal_key"] {
            assert_eq!(
                parse(&without(revoke_json(), key)),
                Err(ControlError::Malformed(key)),
                "{key}"
            );
        }
        // The Station's exact origin.
        assert!(
            parse(&with(
                revoke_json(),
                "origin",
                json!("http://127.0.0.1:8443")
            ))
            .is_ok()
        );
        for bad in [
            "https://station-dev.agora.build/",
            "https://station-dev.agora.build/feed",
            "HTTPS://station-dev.agora.build",
            "https://Station-dev.agora.build",
            "https://station-dev.agora.build:443",
            "http://station-dev.agora.build",
            "https://user@station-dev.agora.build",
            "station-dev.agora.build",
            "",
        ] {
            assert_eq!(
                parse(&with(revoke_json(), "origin", json!(bad))),
                Err(ControlError::Malformed("origin")),
                "{bad}"
            );
        }
    }

    #[test]
    fn build_then_parse_round_trips() {
        let keys = keys();
        let mut bodies: Vec<(ControlBody, &str)> = Vec::new();
        for action in SERVICE_ACTIONS {
            bodies.push((service(action), "svc"));
            let mut ed = service(action);
            ed.principal = ControlPrincipal::Service("svc-ed".into());
            bodies.push((ed, "svc-ed"));
            if matches!(
                action,
                ControlAction::Revoke { .. } | ControlAction::InterruptRunning { .. }
            ) {
                let mut managed = service(action);
                managed.signer = ControlSigner::Member("dev-mac".into());
                managed.about.by = "member_removed".into();
                bodies.push((managed, "mac"));
            }
        }
        bodies.push((host(7), "mac"));
        for (body, key) in bodies {
            let object = build_control(&keys, &KeyId::new(key), &body).unwrap();
            assert_eq!(object.label(), SignLabel::HostWorkControl);
            assert_eq!(object.body_type(), "atem-host-work-control");
            assert_eq!(object.sealed(), None);
            let public = keys.public_key(&KeyId::new(key)).unwrap();
            object.verify(&public).unwrap();
            let bytes = object.to_json().to_string();
            let rec = ControlRecord::parse(bytes.as_bytes()).unwrap();
            assert_eq!(rec.body(), &body, "{key}");
            assert_eq!(rec.object(), &object);
            rec.object().verify(&public).unwrap();
            assert_eq!(ControlRecord::from_signed(object.clone()).unwrap(), rec);
        }
        // Absent fields are omitted, never null.
        let host_object = build_control(&keys, &KeyId::new("mac"), &host(7)).unwrap();
        assert_eq!(host_object.body(), &host_json());
        let revoke = service(ControlAction::Revoke {
            interrupt_running: false,
        });
        assert_eq!(revoke.to_json(), revoke_json());
        assert_eq!(
            keys.public_key(&KeyId::new("svc-ed")).unwrap().alg(),
            Alg::Ed25519
        );

        // Nothing is signed for a body the parse would refuse.
        let refused = |body: ControlBody| build_control(&keys, &KeyId::new("mac"), &body);
        let mut fed_host = host(7);
        fed_host.feed = service(ControlAction::Cover).feed;
        assert!(matches!(refused(fed_host), Err(Error::Malformed(_))));
        let mut covering_host = host(7);
        covering_host.action = ControlAction::Cover;
        assert!(matches!(refused(covering_host), Err(Error::Malformed(_))));
        let mut unbound_host = host(7);
        unbound_host.action = ControlAction::InterruptRunning { revoke_seq: None };
        assert!(matches!(refused(unbound_host), Err(Error::Malformed(_))));
        let mut seq_service = service(ControlAction::Cover);
        seq_service.action = ControlAction::InterruptRunning {
            revoke_seq: Some(3),
        };
        assert!(matches!(refused(seq_service), Err(Error::Malformed(_))));
        let mut keyless = service(ControlAction::Hold);
        keyless.principal_key = None;
        assert!(matches!(refused(keyless), Err(Error::Malformed(_))));
        let mut loud = service(ControlAction::Hold);
        loud.about.by = "OWNER".into();
        assert!(matches!(refused(loud), Err(Error::Malformed(_))));
        let mut no_uuid = service(ControlAction::Hold);
        no_uuid.record_id = "r-1".into();
        assert!(matches!(refused(no_uuid), Err(Error::Malformed(_))));
        let mut unsafe_time = service(ControlAction::Hold);
        unsafe_time.issued_at = u64::MAX;
        assert!(refused(unsafe_time).is_err());
        // An unknown key is the provider's error, after the body checks.
        assert_eq!(
            build_control(&keys, &KeyId::new("none"), &host(7)),
            Err(Error::UnknownKey)
        );
    }

    /// A signer that answers later: the signing input, then the record
    /// from its signature, equal to what `build_control` signs; a body the
    /// parse refuses, another key's signature and a garbled one never make
    /// a record.
    #[test]
    fn signing_input_then_signature_is_build_control() {
        let keys = keys();
        for (body, key) in [
            (service(ControlAction::Hold), "svc-ed"),
            (service(ControlAction::Cover), "svc"),
            (host(7), "mac"),
        ] {
            let object = build_control(&keys, &KeyId::new(key), &body).unwrap();
            let input = control_signing_input(&body).unwrap();
            assert_eq!(input, object.signing_input());
            let public = keys.public_key(&KeyId::new(key)).unwrap();
            let signature = keys.sign(&KeyId::new(key), &input).unwrap();
            let made = control_with_signature(&body, &public, &signature).unwrap();
            assert_eq!(made.to_json(), object.to_json(), "{key}");
            assert_eq!(ControlRecord::from_signed(made).unwrap().body(), &body);
            // Another key's signature, or a flipped bit, is refused.
            let other = keys.public_key(&KeyId::new("mac")).unwrap();
            if key != "mac" {
                assert_eq!(
                    control_with_signature(&body, &other, &signature),
                    Err(Error::BadSignature)
                );
            }
            let mut flipped = signature.clone();
            flipped[10] ^= 1;
            assert!(control_with_signature(&body, &public, &flipped).is_err());
        }
        let mut refused = host(7);
        refused.action = ControlAction::Hold;
        assert!(matches!(
            control_signing_input(&refused),
            Err(Error::Malformed(_))
        ));
        let public = keys.public_key(&KeyId::new("mac")).unwrap();
        assert!(matches!(
            control_with_signature(&refused, &public, &[0u8; 64]),
            Err(Error::Malformed(_))
        ));
        let mut x25519 = SoftwareKeys::new();
        x25519.insert_x25519(KeyId::new("x"), &[4u8; 32]);
        let enc = x25519.public_key(&KeyId::new("x")).unwrap();
        assert_eq!(
            control_with_signature(&host(7), &enc, &[0u8; 64]),
            Err(Error::WrongAlg)
        );
    }

    /// `from_json` reads a body exactly as the parse reads a record's,
    /// with the same refusals.
    #[test]
    fn from_json_reads_as_the_parse() {
        for json in [revoke_json(), host_json()] {
            let parsed = parse(&json).unwrap();
            assert_eq!(&ControlBody::from_json(&json).unwrap(), parsed.body());
        }
        let cases = [
            with(revoke_json(), "note", json!("x")),
            with(revoke_json(), "revoke_seq", json!(3)),
            with(host_json(), "action", json!("release")),
            with(revoke_json(), "v", json!(2)),
            with(revoke_json(), "origin", Value::Null),
            with(revoke_json(), "type", json!("atem-push-hint")),
            with(
                revoke_json(),
                "about",
                json!({"by": "Owner", "integration_id": INTEGRATION}),
            ),
        ];
        for json in cases {
            let want = parse(&json).unwrap_err();
            assert_eq!(
                ControlBody::from_json(&json).unwrap_err().code(),
                want.code(),
                "{json}"
            );
        }
        assert_eq!(
            ControlBody::from_json(&json!([])).unwrap_err().code(),
            "malformed"
        );
    }
}

//! The mailbox calls (host-work-v1 §11.5, "The mailbox calls"; delegated
//! host-work design II.4.3): the relay messages by which a sending host puts
//! a sealed object into the receiving host's mailbox on the Station, and the
//! receiving host reads its own mailbox and marks each object done.
//!
//! Every message is `{"type":"relay","op":…}` on Atem's one link, read and
//! built here and nowhere else, modelled on §11.4's Station calls
//! ([`crate::control::relay`]), whose reading helpers and errors
//! ([`RelayError`]) it shares:
//!
//! | `op` | direction | fields |
//! |---|---|---|
//! | `mailbox_put` | host → Station | `request_id`, `object` |
//! | `mailbox_stored` | Station → host | `request_id`, `id` |
//! | `mailbox_put_refused` | Station → host | `request_id`, `id`, `code` (`quota`, `id_reused`, `expired`, `forbidden`) |
//! | `mailbox_sync` | host → Station | `request_id`, `mailbox_id`, `after` |
//! | `mailbox_sync_result` | Station → host | `request_id`, `mailbox_id`, `after`, `head`, `through`, `objects:[{position, object}]` |
//! | `mailbox_done` | host → Station | `request_id`, `mailbox_id`, `position` |
//! | `mailbox_done_result` | Station → host | `request_id`, `mailbox_id`, `position` |
//! | `mailbox_sync_refused`, `mailbox_done_refused` | Station → host | `code` (`forbidden`) |
//!
//! `heads` gains the calling host's `mailbox:{mailbox_id, head}`, read only
//! where a host turns it on ([`crate::control::Accept`],
//! [`crate::control::Heads::decode_with`]); it keeps §11.4's 256 KiB bound.
//!
//! **Strict** (rule 11). A reader takes the received bytes: at most
//! [`MAX_MAILBOX_MESSAGE_BYTES`] (rule 9: these are the relay messages
//! session-v1 R9.9's drop-unread rule exempts up to 512 KiB), checked before
//! any parse, then one strict I-JSON parse. Exactly the table's fields, none
//! `null` or omitted; `request_id` and `mailbox_id` lowercase UUID v4s, `id`
//! a UUID v4; `after`, `through` and `head` from 0 and `position` from 1, to
//! 2^53 − 1; at most [`MAX_PAGE_OBJECTS`] item in `objects`, at a position in
//! `after + 1 ..= through`; `code` one of its message's codes. Each builder
//! checks what its reader checks.
//!
//! **Objects.** A put carries one `atem-envelope` or `atem-result`
//! ([`MailboxPut::mail`]: the body the Station routes, checks and charges,
//! never trusts; the sealed part it never opens). A page keeps each object
//! as the Station sent it, of any JSON type ([`MailboxEntry::raw`]), judged
//! on its own by the receiving host ([`MailboxEntry::parse_object`], then
//! [`super::open_envelope`] or [`super::accept_result`]): one that doesn't
//! parse never costs the page. A page that isn't strict I-JSON is refused
//! whole: a Station fault, as in §11.4.
//!
//! **Pages** (rule 4). A page answers on the mailbox its call named, echoing
//! `mailbox_id` and `after`, with the mailbox's `head` and a fixed scan
//! boundary `through`, `after ≤ through ≤ head`: every position in `after +
//! 1 ..= through` other than the listed object's holds none (done or
//! expired), so the host's cursor moves to `through`. A page whose `head` is
//! below its `after` is a reset ([`MailboxSyncResult::is_reset`]): no objects
//! and `through` equal to `head`; the reader refuses any other form of it.
//!
//! **Correlation** (rule 8). Every call names itself with a fresh
//! `request_id`; each answer's `answers` is the one matching decision
//! ([`MailboxStored::answers`], [`MailboxPutRefused::answers`],
//! [`MailboxSyncResult::answers`], [`MailboxDoneResult::answers`]), giving
//! the first field that differs ([`MailboxMismatch`]). The link generation,
//! account and genesis captured with the call, and which calls are live, are
//! the caller's. `mailbox_sync_refused` and `mailbox_done_refused` are §11.4's
//! refusals: exactly `code: "forbidden"`, naming a call kind, never a
//! request. `mailbox_put_refused` names its put (rule 3).
//!
//! **Who calls** (rule 1) is the link's verified association: no message
//! names its caller.
use serde_json::{Map, Value, json};

use super::{MailBody, MailKind, evidence_hash};
use crate::canonical::{MAX_SAFE_INTEGER, StrictError, StrictValue};
use crate::control::relay::{
    Fields, RefusalCode, RelayError, check_request_id, check_safe, message, op_of,
};
use crate::encoding::Hash32;
use crate::session::wire::is_uuid_v4;
use crate::signed::SignedObject;

/// The most bytes one mailbox message is, as sent (rule 9; owner choice
/// 13): checked before a reader parses anything, and by every builder. Every
/// other relay message, `heads` included, keeps
/// [`crate::control::relay::MAX_RELAY_MESSAGE_BYTES`].
pub const MAX_MAILBOX_MESSAGE_BYTES: usize = 512 * 1024;

/// The most objects one page lists in this version (one object per call,
/// owner choice 13).
pub const MAX_PAGE_OBJECTS: usize = 1;

/// The `op` of each message.
pub mod op {
    pub const MAILBOX_PUT: &str = "mailbox_put";
    pub const MAILBOX_STORED: &str = "mailbox_stored";
    pub const MAILBOX_PUT_REFUSED: &str = "mailbox_put_refused";
    pub const MAILBOX_SYNC: &str = "mailbox_sync";
    pub const MAILBOX_SYNC_RESULT: &str = "mailbox_sync_result";
    pub const MAILBOX_DONE: &str = "mailbox_done";
    pub const MAILBOX_DONE_RESULT: &str = "mailbox_done_result";
    pub const MAILBOX_SYNC_REFUSED: &str = "mailbox_sync_refused";
    pub const MAILBOX_DONE_REFUSED: &str = "mailbox_done_refused";

    /// Every mailbox `op`.
    pub const ALL: [&str; 9] = [
        MAILBOX_PUT,
        MAILBOX_STORED,
        MAILBOX_PUT_REFUSED,
        MAILBOX_SYNC,
        MAILBOX_SYNC_RESULT,
        MAILBOX_DONE,
        MAILBOX_DONE_RESULT,
        MAILBOX_SYNC_REFUSED,
        MAILBOX_DONE_REFUSED,
    ];
}

/// Whether a relay message's `op` is a mailbox message's, which keeps the
/// 512 KiB bound (rule 9): what a link reader that tells messages by their
/// top-level `type` and `op` (scanning, building no tree) checks before it
/// applies a bound.
pub fn is_mailbox_op(op: &str) -> bool {
    op::ALL.contains(&op)
}

/// An object's identity in its mailbox (rule 3): `object_hash =
/// SHA-256(enc([jcs(body), sig, enc, ct]))`, `sig`, `enc` and `ct` as
/// decoded bytes (empty when absent). It is the evidence hash of the
/// receiver's verdicts ([`evidence_hash`]): the one function the Station
/// (idempotency of puts under `(calling host_id, body.id)`) and the hosts
/// (evidence, duplicates) both use. Computed from the parsed object, so a
/// copy serialized again (whitespace, key order, escapes) is the same
/// object, and every part is length-framed, so any changed byte, or a byte
/// moved between `enc` and `ct`, is another.
pub fn object_hash(object: &SignedObject) -> Hash32 {
    evidence_hash(object)
}

type Result<T> = std::result::Result<T, RelayError>;

/// One strict parse, bounded before it starts.
fn parse(bytes: &[u8]) -> Result<StrictValue> {
    StrictValue::parse(bytes, MAX_MAILBOX_MESSAGE_BYTES).map_err(|e| match e {
        StrictError::TooLarge => RelayError::TooLarge,
        _ => RelayError::NotStrict,
    })
}

/// The finished message, within the mailbox bound.
fn finish(m: Map<String, Value>) -> Result<Value> {
    let value = Value::Object(m);
    if value.to_string().len() > MAX_MAILBOX_MESSAGE_BYTES {
        return Err(RelayError::TooLarge);
    }
    Ok(value)
}

fn check_uuid(id: &str, what: &'static str) -> Result<()> {
    if is_uuid_v4(id) {
        Ok(())
    } else {
        Err(RelayError::Malformed(what))
    }
}

fn check_position(position: u64) -> Result<()> {
    if (1..=MAX_SAFE_INTEGER).contains(&position) {
        Ok(())
    } else {
        Err(RelayError::Malformed("position"))
    }
}

/// Why an answer doesn't answer a call: the first of its echoed fields that
/// differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxMismatch {
    /// Another call's id (a retired call's, an old generation's, or none).
    RequestId,
    /// Another object's id than the put's.
    Id,
    /// Another mailbox than the call named.
    MailboxId,
    /// Another `after` than the sync's.
    After,
    /// Another position than the done's.
    Position,
}

impl MailboxMismatch {
    /// The field's name.
    pub fn code(self) -> &'static str {
        match self {
            MailboxMismatch::RequestId => "request_id",
            MailboxMismatch::Id => "id",
            MailboxMismatch::MailboxId => "mailbox_id",
            MailboxMismatch::After => "after",
            MailboxMismatch::Position => "position",
        }
    }

    pub fn from_code(code: &str) -> Option<Self> {
        [
            MailboxMismatch::RequestId,
            MailboxMismatch::Id,
            MailboxMismatch::MailboxId,
            MailboxMismatch::After,
            MailboxMismatch::Position,
        ]
        .into_iter()
        .find(|m| m.code() == code)
    }
}

// ------------------------------------------------------------ mailbox_put

/// `mailbox_put{request_id, object}` (host → Station): store `object`, one
/// `atem-envelope` or `atem-result` of the calling host, in the mailbox its
/// `recipient` names (rule 3). The Station reads the body only
/// ([`MailboxPut::mail`]); a put whose object has no body it reads (or no
/// `id`) is refused by this reader, and the Station drops it unanswered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxPut {
    pub request_id: String,
    pub object: SignedObject,
}

impl MailboxPut {
    /// The object's kind and body: the recipient it routes to, the sender
    /// rule 1 checks against the caller, the `id` of its key, the times.
    /// Never authority: the receiving host judges the object (II.4.2).
    pub fn mail(&self) -> Result<(MailKind, MailBody)> {
        MailBody::from_object(&self.object).map_err(|_| RelayError::Malformed("object"))
    }

    fn check(&self) -> Result<()> {
        check_request_id(&self.request_id)?;
        self.mail().map(drop)
    }

    /// The wire message, checked as the reader checks it.
    pub fn to_json(&self) -> Result<Value> {
        self.check()?;
        let mut m = message(op::MAILBOX_PUT);
        m.insert("request_id".into(), json!(self.request_id));
        m.insert("object".into(), self.object.to_json());
        finish(m)
    }

    /// Reads received bytes, strictly.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Self::read(parse(bytes)?.value())
    }

    fn read(root: &Value) -> Result<Self> {
        let f = Fields::message(
            root,
            op::MAILBOX_PUT,
            &["type", "op", "request_id", "object"],
        )?;
        let request_id = f.text("request_id")?.to_owned();
        // A part of the strict parse; read as a mailbox object (check 1).
        let object = SignedObject::from_value(f.get("object")?)
            .map_err(|_| RelayError::Malformed("object"))?;
        let put = MailboxPut { request_id, object };
        put.check()?;
        Ok(put)
    }

    /// The object's `id`, when its body reads.
    fn id(&self) -> Option<String> {
        self.mail().ok().map(|(_, body)| body.id)
    }
}

/// `mailbox_stored{request_id, id}` (Station → host): the put `request_id`
/// names is durably stored in its recipient's mailbox (also for a put of an
/// object already stored there with the same `object_hash`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxStored {
    pub request_id: String,
    /// The put's object's body `id`.
    pub id: String,
}

impl MailboxStored {
    const FIELDS: [&'static str; 4] = ["type", "op", "request_id", "id"];

    fn check(&self) -> Result<()> {
        check_request_id(&self.request_id)?;
        check_uuid(&self.id, "id")
    }

    /// The wire message, checked as the reader checks it.
    pub fn to_json(&self) -> Result<Value> {
        self.check()?;
        let mut m = message(op::MAILBOX_STORED);
        m.insert("request_id".into(), json!(self.request_id));
        m.insert("id".into(), json!(self.id));
        finish(m)
    }

    /// Reads received bytes, strictly.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Self::read(parse(bytes)?.value())
    }

    fn read(root: &Value) -> Result<Self> {
        let f = Fields::message(root, op::MAILBOX_STORED, &Self::FIELDS)?;
        let stored = MailboxStored {
            request_id: f.text("request_id")?.to_owned(),
            id: f.text("id")?.to_owned(),
        };
        stored.check()?;
        Ok(stored)
    }

    /// Whether this answers `put`: the same `request_id`, then the same
    /// object `id` (rule 8). An answer that answers no live put is drained
    /// or counted by the caller, never applied.
    pub fn answers(&self, put: &MailboxPut) -> std::result::Result<(), MailboxMismatch> {
        answers_put(&self.request_id, &self.id, put)
    }
}

fn answers_put(
    request_id: &str,
    id: &str,
    put: &MailboxPut,
) -> std::result::Result<(), MailboxMismatch> {
    if request_id != put.request_id {
        return Err(MailboxMismatch::RequestId);
    }
    if put.id().as_deref() != Some(id) {
        return Err(MailboxMismatch::Id);
    }
    Ok(())
}

/// Why the Station refused a put (rule 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutRefusal {
    /// A limit of design II.4.3 is reached: not stored, never counted as
    /// stored; the sender keeps the object and puts it again later.
    Quota,
    /// Another object is stored under the key `(calling host, id)`: final
    /// for those bytes; the first stays.
    IdReused,
    /// The object has expired, or its lifetime is longer than 24 h: final.
    Expired,
    /// Rule 1, or a recipient that isn't a current host at that generation:
    /// final on this link generation.
    Forbidden,
}

impl PutRefusal {
    pub const ALL: [PutRefusal; 4] = [
        PutRefusal::Quota,
        PutRefusal::IdReused,
        PutRefusal::Expired,
        PutRefusal::Forbidden,
    ];

    /// The wire name.
    pub fn code(self) -> &'static str {
        match self {
            PutRefusal::Quota => "quota",
            PutRefusal::IdReused => "id_reused",
            PutRefusal::Expired => "expired",
            PutRefusal::Forbidden => "forbidden",
        }
    }

    /// From the wire name, exactly.
    pub fn from_code(code: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.code() == code)
    }
}

/// `mailbox_put_refused{request_id, id, code}` (Station → host): it names
/// the put (its `request_id` and its object's `id`), unlike §11.4's
/// refusals: it echoes only the caller's own request and object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxPutRefused {
    pub request_id: String,
    pub id: String,
    pub code: PutRefusal,
}

impl MailboxPutRefused {
    const FIELDS: [&'static str; 5] = ["type", "op", "request_id", "id", "code"];

    fn check(&self) -> Result<()> {
        check_request_id(&self.request_id)?;
        check_uuid(&self.id, "id")
    }

    /// The wire message, checked as the reader checks it.
    pub fn to_json(&self) -> Result<Value> {
        self.check()?;
        let mut m = message(op::MAILBOX_PUT_REFUSED);
        m.insert("request_id".into(), json!(self.request_id));
        m.insert("id".into(), json!(self.id));
        m.insert("code".into(), json!(self.code.code()));
        finish(m)
    }

    /// Reads received bytes, strictly.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Self::read(parse(bytes)?.value())
    }

    fn read(root: &Value) -> Result<Self> {
        let f = Fields::message(root, op::MAILBOX_PUT_REFUSED, &Self::FIELDS)?;
        let refused = MailboxPutRefused {
            request_id: f.text("request_id")?.to_owned(),
            id: f.text("id")?.to_owned(),
            code: PutRefusal::from_code(f.text("code")?).ok_or(RelayError::Malformed("code"))?,
        };
        refused.check()?;
        Ok(refused)
    }

    /// As [`MailboxStored::answers`].
    pub fn answers(&self, put: &MailboxPut) -> std::result::Result<(), MailboxMismatch> {
        answers_put(&self.request_id, &self.id, put)
    }
}

// ----------------------------------------------------------- mailbox_sync

/// `mailbox_sync{request_id, mailbox_id, after}` (host → Station): read the
/// host's own mailbox, the one the last `heads` announced, after `after`,
/// the last position the host processed (0: none).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxSync {
    pub request_id: String,
    pub mailbox_id: String,
    pub after: u64,
}

impl MailboxSync {
    const FIELDS: [&'static str; 5] = ["type", "op", "request_id", "mailbox_id", "after"];

    fn check(&self) -> Result<()> {
        check_request_id(&self.request_id)?;
        check_uuid(&self.mailbox_id, "mailbox_id")?;
        check_safe(self.after, "after")
    }

    /// The wire message, checked as the reader checks it.
    pub fn to_json(&self) -> Result<Value> {
        self.check()?;
        let mut m = message(op::MAILBOX_SYNC);
        m.insert("request_id".into(), json!(self.request_id));
        m.insert("mailbox_id".into(), json!(self.mailbox_id));
        m.insert("after".into(), json!(self.after));
        finish(m)
    }

    /// Reads received bytes, strictly.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Self::read(parse(bytes)?.value())
    }

    fn read(root: &Value) -> Result<Self> {
        let f = Fields::message(root, op::MAILBOX_SYNC, &Self::FIELDS)?;
        let sync = MailboxSync {
            request_id: f.text("request_id")?.to_owned(),
            mailbox_id: f.text("mailbox_id")?.to_owned(),
            after: f.uint("after")?,
        };
        sync.check()?;
        Ok(sync)
    }
}

/// One object of a page at its position. The object is the value the
/// Station sent, of any JSON type, kept as it came;
/// [`MailboxEntry::parse_object`] is check 1's verdict on it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxEntry {
    pub position: u64,
    object: Value,
}

impl MailboxEntry {
    /// A Station's entry for an object it stored, at `position`.
    pub fn new(position: u64, object: &SignedObject) -> Self {
        MailboxEntry {
            position,
            object: object.to_json(),
        }
    }

    /// The object as received (nothing is known of it until
    /// [`MailboxEntry::parse_object`]).
    pub fn raw(&self) -> &Value {
        &self.object
    }

    /// The object as a mailbox object (host-work-v1 §11.5's check 1: the
    /// signed-object rules, an envelope's or a result's exact body, a
    /// sealed part of the right shape), or why not: such an object is
    /// refused with its evidence and marked done. Nothing is verified.
    pub fn parse_object(&self) -> crate::Result<SignedObject> {
        let object = SignedObject::from_value(&self.object)?;
        MailBody::from_object(&object)?;
        Ok(object)
    }
}

/// `mailbox_sync_result{request_id, mailbox_id, after, head, through,
/// objects}` (Station → host): the answer to the sync `request_id` names,
/// on the mailbox it named, echoing its `after` (rule 4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxSyncResult {
    pub request_id: String,
    pub mailbox_id: String,
    /// The call's `after`, echoed.
    pub after: u64,
    /// The mailbox's last position (0: none).
    pub head: u64,
    /// The page's scan boundary: every position in `after + 1 ..= through`
    /// but the listed object's holds no object.
    pub through: u64,
    /// At most [`MAX_PAGE_OBJECTS`], ascending, in `after + 1 ..= through`.
    pub objects: Vec<MailboxEntry>,
}

impl MailboxSyncResult {
    const FIELDS: [&'static str; 8] = [
        "type",
        "op",
        "request_id",
        "mailbox_id",
        "after",
        "head",
        "through",
        "objects",
    ];

    fn check(&self) -> Result<()> {
        if self.objects.len() > MAX_PAGE_OBJECTS {
            return Err(RelayError::TooLarge);
        }
        check_request_id(&self.request_id)?;
        check_uuid(&self.mailbox_id, "mailbox_id")?;
        check_safe(self.after, "after")?;
        check_safe(self.head, "head")?;
        check_safe(self.through, "through")?;
        if self.is_reset() {
            // The mailbox went back under the same id: nothing listed, the
            // scan boundary at the head.
            if self.through != self.head {
                return Err(RelayError::Malformed("through"));
            }
            if !self.objects.is_empty() {
                return Err(RelayError::Malformed("objects"));
            }
            return Ok(());
        }
        if self.through < self.after || self.through > self.head {
            return Err(RelayError::Malformed("through"));
        }
        let mut previous = self.after;
        for entry in &self.objects {
            check_position(entry.position)?;
            if entry.position <= previous || entry.position > self.through {
                return Err(RelayError::Malformed("position"));
            }
            previous = entry.position;
        }
        Ok(())
    }

    /// A reset (rules 4 and 7): the mailbox's `head` is below the call's
    /// `after`. The host marks it durably, reads from 0 and never moves its
    /// cursor on this page.
    pub fn is_reset(&self) -> bool {
        self.head < self.after
    }

    /// The wire message, checked as the reader checks it, and within the
    /// mailbox bound.
    pub fn to_json(&self) -> Result<Value> {
        self.check()?;
        let mut m = message(op::MAILBOX_SYNC_RESULT);
        m.insert("request_id".into(), json!(self.request_id));
        m.insert("mailbox_id".into(), json!(self.mailbox_id));
        m.insert("after".into(), json!(self.after));
        m.insert("head".into(), json!(self.head));
        m.insert("through".into(), json!(self.through));
        m.insert(
            "objects".into(),
            Value::Array(
                self.objects
                    .iter()
                    .map(|e| json!({"position": e.position, "object": e.object}))
                    .collect(),
            ),
        );
        finish(m)
    }

    /// Reads received bytes, strictly.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Self::read(parse(bytes)?.value())
    }

    fn read(root: &Value) -> Result<Self> {
        let f = Fields::message(root, op::MAILBOX_SYNC_RESULT, &Self::FIELDS)?;
        let objects = f
            .array("objects", MAX_PAGE_OBJECTS)?
            .iter()
            .map(|item| {
                let e = Fields::of(item, &["position", "object"], "objects")?;
                Ok(MailboxEntry {
                    position: e.uint("position")?,
                    // Any strict-JSON value, of any type: judged on its own.
                    object: e.get("object")?.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let page = MailboxSyncResult {
            request_id: f.text("request_id")?.to_owned(),
            mailbox_id: f.text("mailbox_id")?.to_owned(),
            after: f.uint("after")?,
            head: f.uint("head")?,
            through: f.uint("through")?,
            objects,
        };
        page.check()?;
        Ok(page)
    }

    /// Whether this page answers `call`: the same `request_id`,
    /// `mailbox_id` and `after`, in that order (rule 8). Only the live
    /// sync's answer applies; the link generation, account and genesis
    /// captured with the call are the caller's to compare.
    pub fn answers(&self, call: &MailboxSync) -> std::result::Result<(), MailboxMismatch> {
        if self.request_id != call.request_id {
            return Err(MailboxMismatch::RequestId);
        }
        if self.mailbox_id != call.mailbox_id {
            return Err(MailboxMismatch::MailboxId);
        }
        if self.after != call.after {
            return Err(MailboxMismatch::After);
        }
        Ok(())
    }
}

// ----------------------------------------------------------- mailbox_done

/// `mailbox_done{request_id, mailbox_id, position}` (host → Station): the
/// host is through with the object at `position` of its own mailbox (rule
/// 5), sent only once its commit is durable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxDone {
    pub request_id: String,
    pub mailbox_id: String,
    pub position: u64,
}

/// `mailbox_done_result{request_id, mailbox_id, position}` (Station →
/// host): the call's fields, echoed; also when nothing was there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MailboxDoneResult {
    pub request_id: String,
    pub mailbox_id: String,
    pub position: u64,
}

const DONE_FIELDS: [&str; 5] = ["type", "op", "request_id", "mailbox_id", "position"];

fn check_done(request_id: &str, mailbox_id: &str, position: u64) -> Result<()> {
    check_request_id(request_id)?;
    check_uuid(mailbox_id, "mailbox_id")?;
    check_position(position)
}

fn done_json(op: &str, request_id: &str, mailbox_id: &str, position: u64) -> Result<Value> {
    check_done(request_id, mailbox_id, position)?;
    let mut m = message(op);
    m.insert("request_id".into(), json!(request_id));
    m.insert("mailbox_id".into(), json!(mailbox_id));
    m.insert("position".into(), json!(position));
    finish(m)
}

fn read_done(root: &Value, op: &str) -> Result<(String, String, u64)> {
    let f = Fields::message(root, op, &DONE_FIELDS)?;
    let read = (
        f.text("request_id")?.to_owned(),
        f.text("mailbox_id")?.to_owned(),
        f.uint("position")?,
    );
    check_done(&read.0, &read.1, read.2)?;
    Ok(read)
}

impl MailboxDone {
    /// The wire message, checked as the reader checks it.
    pub fn to_json(&self) -> Result<Value> {
        done_json(
            op::MAILBOX_DONE,
            &self.request_id,
            &self.mailbox_id,
            self.position,
        )
    }

    /// Reads received bytes, strictly.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Self::read(parse(bytes)?.value())
    }

    fn read(root: &Value) -> Result<Self> {
        let (request_id, mailbox_id, position) = read_done(root, op::MAILBOX_DONE)?;
        Ok(MailboxDone {
            request_id,
            mailbox_id,
            position,
        })
    }
}

impl MailboxDoneResult {
    /// The wire message, checked as the reader checks it.
    pub fn to_json(&self) -> Result<Value> {
        done_json(
            op::MAILBOX_DONE_RESULT,
            &self.request_id,
            &self.mailbox_id,
            self.position,
        )
    }

    /// Reads received bytes, strictly.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Self::read(parse(bytes)?.value())
    }

    fn read(root: &Value) -> Result<Self> {
        let (request_id, mailbox_id, position) = read_done(root, op::MAILBOX_DONE_RESULT)?;
        Ok(MailboxDoneResult {
            request_id,
            mailbox_id,
            position,
        })
    }

    /// Whether this answers `done`: the same `request_id`, `mailbox_id` and
    /// `position`, in that order (rule 8).
    pub fn answers(&self, done: &MailboxDone) -> std::result::Result<(), MailboxMismatch> {
        if self.request_id != done.request_id {
            return Err(MailboxMismatch::RequestId);
        }
        if self.mailbox_id != done.mailbox_id {
            return Err(MailboxMismatch::MailboxId);
        }
        if self.position != done.position {
            return Err(MailboxMismatch::Position);
        }
        Ok(())
    }
}

// --------------------------------------------------------------- refusals

/// The call a `forbidden` refusal answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailboxRefusedCall {
    Sync,
    Done,
}

impl MailboxRefusedCall {
    /// The refusal's `op`.
    pub fn op(self) -> &'static str {
        match self {
            MailboxRefusedCall::Sync => op::MAILBOX_SYNC_REFUSED,
            MailboxRefusedCall::Done => op::MAILBOX_DONE_REFUSED,
        }
    }

    fn of_op(op: &str) -> Option<Self> {
        [MailboxRefusedCall::Sync, MailboxRefusedCall::Done]
            .into_iter()
            .find(|call| call.op() == op)
    }
}

/// `mailbox_sync_refused` or `mailbox_done_refused` `{code}` (Station →
/// host): §11.4's refusals, exactly `code: "forbidden"`, no identifier. A
/// sync refusal retires the live sync and keeps host senders' gate closed
/// until a page asked after it; a done refusal retires every live done on
/// the link (rule 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MailboxCallRefused {
    pub call: MailboxRefusedCall,
    pub code: RefusalCode,
}

impl MailboxCallRefused {
    /// The wire message.
    pub fn to_json(&self) -> Result<Value> {
        let mut m = message(self.call.op());
        m.insert("code".into(), json!(self.code.code()));
        finish(m)
    }

    /// Reads received bytes, strictly: one of the two refusals.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let root = parse(bytes)?;
        let root = root.value();
        let call = op_of(root)
            .and_then(MailboxRefusedCall::of_op)
            .ok_or(RelayError::WrongMessage)?;
        Self::read(root, call)
    }

    fn read(root: &Value, call: MailboxRefusedCall) -> Result<Self> {
        let f = Fields::message(root, call.op(), &["type", "op", "code"])?;
        let code = RefusalCode::from_code(f.text("code")?).ok_or(RelayError::Malformed("code"))?;
        Ok(MailboxCallRefused { call, code })
    }
}

// --------------------------------------------------------------- dispatch

/// A mailbox message a Station reads from a host. Any other message is
/// `WrongMessage`.
// A put carries its object; the others a few fields, read and dropped.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxToStation {
    Put(MailboxPut),
    Sync(MailboxSync),
    Done(MailboxDone),
}

impl MailboxToStation {
    /// Reads received bytes, strictly: one parse, then the reader of its
    /// `op`.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let root = parse(bytes)?;
        let root = root.value();
        match op_of(root) {
            Some(op::MAILBOX_PUT) => MailboxPut::read(root).map(Self::Put),
            Some(op::MAILBOX_SYNC) => MailboxSync::read(root).map(Self::Sync),
            Some(op::MAILBOX_DONE) => MailboxDone::read(root).map(Self::Done),
            _ => Err(RelayError::WrongMessage),
        }
    }

    /// The wire message.
    pub fn to_json(&self) -> Result<Value> {
        match self {
            Self::Put(put) => put.to_json(),
            Self::Sync(sync) => sync.to_json(),
            Self::Done(done) => done.to_json(),
        }
    }
}

/// A mailbox message a host reads from its Station. Any other message is
/// `WrongMessage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MailboxToHost {
    Stored(MailboxStored),
    PutRefused(MailboxPutRefused),
    SyncResult(MailboxSyncResult),
    DoneResult(MailboxDoneResult),
    /// The Station refused this link's `mailbox_sync`.
    SyncRefused(RefusalCode),
    /// The Station refused this link's `mailbox_done`.
    DoneRefused(RefusalCode),
}

impl MailboxToHost {
    /// Reads received bytes, strictly: one parse, then the reader of its
    /// `op`.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let root = parse(bytes)?;
        let root = root.value();
        match op_of(root) {
            Some(op::MAILBOX_STORED) => MailboxStored::read(root).map(Self::Stored),
            Some(op::MAILBOX_PUT_REFUSED) => MailboxPutRefused::read(root).map(Self::PutRefused),
            Some(op::MAILBOX_SYNC_RESULT) => MailboxSyncResult::read(root).map(Self::SyncResult),
            Some(op::MAILBOX_DONE_RESULT) => MailboxDoneResult::read(root).map(Self::DoneResult),
            Some(op) => match MailboxRefusedCall::of_op(op) {
                Some(call) => MailboxCallRefused::read(root, call).map(|r| match r.call {
                    MailboxRefusedCall::Sync => Self::SyncRefused(r.code),
                    MailboxRefusedCall::Done => Self::DoneRefused(r.code),
                }),
                None => Err(RelayError::WrongMessage),
            },
            None => Err(RelayError::WrongMessage),
        }
    }

    /// The wire message.
    pub fn to_json(&self) -> Result<Value> {
        match self {
            Self::Stored(m) => m.to_json(),
            Self::PutRefused(m) => m.to_json(),
            Self::SyncResult(m) => m.to_json(),
            Self::DoneResult(m) => m.to_json(),
            Self::SyncRefused(code) => MailboxCallRefused {
                call: MailboxRefusedCall::Sync,
                code: *code,
            }
            .to_json(),
            Self::DoneRefused(code) => MailboxCallRefused {
                call: MailboxRefusedCall::Done,
                code: *code,
            }
            .to_json(),
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, Value, json};

    use super::*;
    use crate::control::relay::{Accept, MailboxHead, ToHost};
    use crate::encoding::b64u;
    use crate::host_mail::test_support::{CREATED_AT, ID, Rig};
    use crate::host_mail::{EnvelopePlain, seal_envelope_with_ikm};

    /// Lowercase UUID v4s: calls' ids, a mailbox's.
    const REQUEST: &str = "55aa5bab-e253-4b6c-a83f-c86e6b028aa1";
    const REQUEST_2: &str = "b06daa5d-9f48-4512-8a98-c6d98b159d8e";
    const MAILBOX: &str = "9d2f6c1e-3b4a-4c5d-8e6f-7a8b9c0d1e2f";
    const MAILBOX_2: &str = "3e9fd05f-183e-4b70-be0e-3ffa66120f48";
    const TASK: &str = "e5df8ab5-b35a-40f6-8536-8e17b8634743";

    /// A cancel envelope from host A to host B, sealed and signed (a fixed
    /// ephemeral, so every call makes the same object).
    fn object() -> SignedObject {
        let rig = Rig::new();
        seal_envelope_with_ikm(
            &rig.sender,
            &rig.host_key,
            &rig.fields(),
            &EnvelopePlain::Cancel {
                task_id: TASK.into(),
            },
            &rig.enc_pub,
            &[5u8; 32],
        )
        .unwrap()
    }

    fn put() -> MailboxPut {
        MailboxPut {
            request_id: REQUEST.into(),
            object: object(),
        }
    }

    fn sync(after: u64) -> MailboxSync {
        MailboxSync {
            request_id: REQUEST.into(),
            mailbox_id: MAILBOX.into(),
            after,
        }
    }

    /// The answer to `sync(9)`: position 10 holds nothing, 11 the object.
    fn page() -> MailboxSyncResult {
        MailboxSyncResult {
            request_id: REQUEST.into(),
            mailbox_id: MAILBOX.into(),
            after: 9,
            head: 12,
            through: 11,
            objects: vec![MailboxEntry::new(11, &object())],
        }
    }

    fn done() -> MailboxDone {
        MailboxDone {
            request_id: REQUEST.into(),
            mailbox_id: MAILBOX.into(),
            position: 11,
        }
    }

    fn bytes(message: &Value) -> Vec<u8> {
        message.to_string().into_bytes()
    }

    /// Every message, as built: the host's calls, then the Station's.
    fn calls() -> Vec<Value> {
        vec![
            put().to_json().unwrap(),
            sync(9).to_json().unwrap(),
            done().to_json().unwrap(),
        ]
    }

    fn answers() -> Vec<Value> {
        let mut out = vec![
            MailboxStored {
                request_id: REQUEST.into(),
                id: ID.into(),
            }
            .to_json()
            .unwrap(),
            page().to_json().unwrap(),
            MailboxDoneResult {
                request_id: REQUEST.into(),
                mailbox_id: MAILBOX.into(),
                position: 11,
            }
            .to_json()
            .unwrap(),
        ];
        for code in PutRefusal::ALL {
            out.push(
                MailboxPutRefused {
                    request_id: REQUEST.into(),
                    id: ID.into(),
                    code,
                }
                .to_json()
                .unwrap(),
            );
        }
        for call in [MailboxRefusedCall::Sync, MailboxRefusedCall::Done] {
            out.push(
                MailboxCallRefused {
                    call,
                    code: RefusalCode::Forbidden,
                }
                .to_json()
                .unwrap(),
            );
        }
        out
    }

    // ------------------------------------------------------- round trips

    #[test]
    fn every_call_and_answer_round_trips_through_its_reader() {
        let wire = put().to_json().unwrap();
        assert_eq!(wire["type"], "relay");
        assert_eq!(wire["op"], "mailbox_put");
        assert_eq!(wire["object"], object().to_json());
        assert_eq!(MailboxPut::decode(&bytes(&wire)).unwrap(), put());
        assert_eq!(
            MailboxToStation::decode(&bytes(&wire)).unwrap(),
            MailboxToStation::Put(put())
        );
        // The put names its object's body: what the Station routes on.
        let (kind, body) = put().mail().unwrap();
        assert_eq!(kind, MailKind::Envelope);
        assert_eq!(body.id, ID);
        assert_eq!(body.recipient.host_id, "host-b");

        let wire = sync(9).to_json().unwrap();
        assert_eq!(
            wire,
            json!({"type": "relay", "op": "mailbox_sync",
            "request_id": REQUEST, "mailbox_id": MAILBOX, "after": 9})
        );
        assert_eq!(
            MailboxToStation::decode(&bytes(&wire)).unwrap(),
            MailboxToStation::Sync(sync(9))
        );
        let wire = done().to_json().unwrap();
        assert_eq!(
            wire,
            json!({"type": "relay", "op": "mailbox_done",
            "request_id": REQUEST, "mailbox_id": MAILBOX, "position": 11})
        );
        assert_eq!(
            MailboxToStation::decode(&bytes(&wire)).unwrap(),
            MailboxToStation::Done(done())
        );

        let wire = page().to_json().unwrap();
        assert_eq!(
            wire["objects"],
            json!([{"position": 11, "object": object().to_json()}])
        );
        let got = MailboxSyncResult::decode(&bytes(&wire)).unwrap();
        assert_eq!(got, page());
        assert_eq!(got.objects[0].parse_object().unwrap(), object());
        assert!(!got.is_reset());

        for wire in answers() {
            let read = MailboxToHost::decode(&bytes(&wire)).unwrap();
            assert_eq!(read.to_json().unwrap(), wire, "{wire}");
        }
        let refused = MailboxCallRefused {
            call: MailboxRefusedCall::Done,
            code: RefusalCode::Forbidden,
        };
        assert_eq!(
            refused.to_json().unwrap(),
            json!({"type": "relay", "op": "mailbox_done_refused", "code": "forbidden"})
        );
        assert_eq!(
            MailboxToHost::decode(&bytes(&refused.to_json().unwrap())).unwrap(),
            MailboxToHost::DoneRefused(RefusalCode::Forbidden)
        );
        // An empty page read to its head.
        let empty = MailboxSyncResult {
            request_id: REQUEST.into(),
            mailbox_id: MAILBOX.into(),
            after: 12,
            head: 12,
            through: 12,
            objects: vec![],
        };
        let wire = empty.to_json().unwrap();
        assert_eq!(MailboxSyncResult::decode(&bytes(&wire)).unwrap(), empty);
    }

    #[test]
    fn each_reader_takes_only_its_direction_and_its_ops() {
        for wire in calls() {
            assert_eq!(
                MailboxToHost::decode(&bytes(&wire)),
                Err(RelayError::WrongMessage),
                "{wire}"
            );
            assert!(is_mailbox_op(wire["op"].as_str().unwrap()));
        }
        for wire in answers() {
            assert_eq!(
                MailboxToStation::decode(&bytes(&wire)),
                Err(RelayError::WrongMessage),
                "{wire}"
            );
            assert!(is_mailbox_op(wire["op"].as_str().unwrap()));
        }
        for other in [
            json!({"type": "relay", "op": "heads", "feeds": [], "membership": {"seq": 1, "hash": "00".repeat(32)}}),
            json!({"type": "relay", "op": "push_hint", "hints": []}),
            json!({"type": "session", "op": "mailbox_put"}),
            json!({"type": "relay"}),
            json!([]),
        ] {
            assert_eq!(
                MailboxToStation::decode(&bytes(&other)),
                Err(RelayError::WrongMessage)
            );
            assert_eq!(
                MailboxToHost::decode(&bytes(&other)),
                Err(RelayError::WrongMessage)
            );
        }
        assert!(!is_mailbox_op("heads"));
        assert!(!is_mailbox_op("control_sync"));
        // A message's own reader refuses another op.
        assert_eq!(
            MailboxSync::decode(&bytes(&done().to_json().unwrap())),
            Err(RelayError::WrongMessage)
        );
    }

    // ------------------------------------------------------------ strict

    #[test]
    fn every_message_has_exactly_its_fields() {
        for wire in calls().into_iter().chain(answers()) {
            let op = wire["op"].as_str().unwrap().to_owned();
            let read = |w: &Value| {
                if wire_is_call(&op) {
                    MailboxToStation::decode(&bytes(w)).map(drop)
                } else {
                    MailboxToHost::decode(&bytes(w)).map(drop)
                }
            };
            let mut extra = wire.clone();
            extra["extra"] = json!(1);
            assert_eq!(read(&extra), Err(RelayError::UnknownField), "{op} extra");
            for key in wire.as_object().unwrap().keys() {
                if key == "type" || key == "op" {
                    continue;
                }
                let mut missing = wire.clone();
                missing.as_object_mut().unwrap().remove(key);
                assert!(
                    matches!(read(&missing), Err(RelayError::Malformed(_))),
                    "{op} without {key}"
                );
                let mut null = wire.clone();
                null[key] = Value::Null;
                assert!(
                    matches!(read(&null), Err(RelayError::Malformed(_))),
                    "{op} {key} null"
                );
            }
        }
        // A page's item is exactly `{position, object}`.
        let mut wire = page().to_json().unwrap();
        wire["objects"][0]["extra"] = json!(1);
        assert_eq!(
            MailboxSyncResult::decode(&bytes(&wire)),
            Err(RelayError::UnknownField)
        );
        let mut wire = page().to_json().unwrap();
        wire["objects"][0].as_object_mut().unwrap().remove("object");
        assert!(matches!(
            MailboxSyncResult::decode(&bytes(&wire)),
            Err(RelayError::Malformed(_))
        ));
    }

    fn wire_is_call(op: &str) -> bool {
        [op::MAILBOX_PUT, op::MAILBOX_SYNC, op::MAILBOX_DONE].contains(&op)
    }

    #[test]
    fn ids_are_lowercase_uuid_v4s_and_numbers_in_range() {
        let v5 = "80160896-4fcd-5e6e-adac-98bac5497321";
        for (wire, pointer, bad) in [
            (
                put().to_json().unwrap(),
                "/request_id",
                json!(REQUEST.to_uppercase()),
            ),
            (put().to_json().unwrap(), "/request_id", json!(v5)),
            (
                sync(9).to_json().unwrap(),
                "/mailbox_id",
                json!(MAILBOX.to_uppercase()),
            ),
            (
                sync(9).to_json().unwrap(),
                "/mailbox_id",
                json!("mailbox-1"),
            ),
            (sync(9).to_json().unwrap(), "/after", json!(-1)),
            (done().to_json().unwrap(), "/position", json!(0)),
            (page().to_json().unwrap(), "/head", json!("12")),
            (page().to_json().unwrap(), "/objects/0/position", json!(0)),
        ] {
            let mut changed = wire.clone();
            *changed.pointer_mut(pointer).unwrap() = bad.clone();
            let read = if wire_is_call(wire["op"].as_str().unwrap()) {
                MailboxToStation::decode(&bytes(&changed)).map(drop)
            } else {
                MailboxToHost::decode(&bytes(&changed)).map(drop)
            };
            assert!(
                matches!(read, Err(RelayError::Malformed(_))),
                "{pointer} {bad}"
            );
        }
        // The answers' `id` is a UUID v4 too.
        let mut stored = MailboxStored {
            request_id: REQUEST.into(),
            id: v5.into(),
        };
        assert!(matches!(stored.to_json(), Err(RelayError::Malformed(_))));
        stored.id = ID.into();
        stored.request_id = REQUEST.to_uppercase();
        assert!(matches!(stored.to_json(), Err(RelayError::Malformed(_))));
        // Numbers to 2^53 - 1, as the strict parse keeps them.
        let mut largest = sync(MAX_SAFE_INTEGER);
        assert_eq!(
            MailboxSync::decode(&bytes(&largest.to_json().unwrap())).unwrap(),
            largest
        );
        largest.after = MAX_SAFE_INTEGER + 1;
        assert!(matches!(largest.to_json(), Err(RelayError::Malformed(_))));
        let mut wire = sync(9).to_json().unwrap();
        wire["after"] = json!(9.0);
        assert_eq!(
            MailboxSync::decode(&bytes(&wire)),
            Err(RelayError::NotStrict)
        );
    }

    #[test]
    fn a_put_carries_one_mail_object_the_station_can_route() {
        // The object is read as a mailbox object (host-work-v1 §11.5's check
        // 1): a signed body of an envelope or a result with its sealed part.
        let good = put().to_json().unwrap();
        let mut not_mail = good.clone();
        not_mail["object"] = json!("not an object");
        let mut no_sealed = good.clone();
        let o = no_sealed["object"].as_object_mut().unwrap();
        o.remove("enc");
        o.remove("ct");
        let mut body_extra = good.clone();
        body_extra["object"]["body"]["note"] = json!("x");
        let mut no_id = good.clone();
        no_id["object"]["body"]
            .as_object_mut()
            .unwrap()
            .remove("id");
        let mut other_type = good.clone();
        other_type["object"]["body"]["type"] = json!("atem-membership-entry");
        let mut two = good.clone();
        two["object"] = json!([object().to_json(), object().to_json()]);
        for bad in [not_mail, no_sealed, body_extra, no_id, other_type, two] {
            assert_eq!(
                MailboxPut::decode(&bytes(&bad)),
                Err(RelayError::Malformed("object")),
                "{}",
                bad["object"]
            );
        }
        // A put whose object an older or newer serialization wrote reads the
        // same: the object is a value, not its bytes.
        let spaced = serde_json::to_string_pretty(&good).unwrap();
        assert_eq!(MailboxPut::decode(spaced.as_bytes()).unwrap(), put());
    }

    #[test]
    fn put_refusals_name_the_put_and_one_of_four_codes() {
        for (code, name) in
            PutRefusal::ALL
                .into_iter()
                .zip(["quota", "id_reused", "expired", "forbidden"])
        {
            assert_eq!(code.code(), name);
            assert_eq!(PutRefusal::from_code(name), Some(code));
            let refused = MailboxPutRefused {
                request_id: REQUEST.into(),
                id: ID.into(),
                code,
            };
            let wire = refused.to_json().unwrap();
            assert_eq!(
                wire,
                json!({"type": "relay", "op": "mailbox_put_refused",
                "request_id": REQUEST, "id": ID, "code": name})
            );
            assert_eq!(MailboxPutRefused::decode(&bytes(&wire)).unwrap(), refused);
        }
        let mut wire = answers()[3].clone();
        for bad in ["busy", "Quota", ""] {
            wire["code"] = json!(bad);
            assert!(matches!(
                MailboxToHost::decode(&bytes(&wire)),
                Err(RelayError::Malformed(_))
            ));
        }
    }

    #[test]
    fn sync_and_done_refusals_are_exactly_forbidden() {
        // As §11.4's refusals: no identifier, a call kind only.
        for call in [MailboxRefusedCall::Sync, MailboxRefusedCall::Done] {
            let wire = MailboxCallRefused {
                call,
                code: RefusalCode::Forbidden,
            }
            .to_json()
            .unwrap();
            for (key, value) in [
                ("request_id", json!(REQUEST)),
                ("mailbox_id", json!(MAILBOX)),
            ] {
                let mut named = wire.clone();
                named[key] = value;
                assert_eq!(
                    MailboxToHost::decode(&bytes(&named)),
                    Err(RelayError::UnknownField)
                );
            }
            let mut other = wire.clone();
            other["code"] = json!("quota");
            assert!(matches!(
                MailboxToHost::decode(&bytes(&other)),
                Err(RelayError::Malformed(_))
            ));
        }
    }

    // ------------------------------------------------------------- pages

    fn page_of(after: u64, head: u64, through: u64, positions: &[u64]) -> MailboxSyncResult {
        MailboxSyncResult {
            request_id: REQUEST.into(),
            mailbox_id: MAILBOX.into(),
            after,
            head,
            through,
            objects: positions
                .iter()
                .map(|p| MailboxEntry::new(*p, &object()))
                .collect(),
        }
    }

    #[test]
    fn a_page_holds_at_most_one_object_inside_its_scan_boundary() {
        // `after <= through <= head`, the object at `after + 1 ..= through`.
        for ok in [
            page_of(9, 12, 11, &[11]),
            page_of(9, 12, 10, &[10]),
            page_of(9, 12, 12, &[]),
            page_of(9, 12, 9, &[]),
            page_of(0, 0, 0, &[]),
            page_of(0, MAX_SAFE_INTEGER, MAX_SAFE_INTEGER, &[MAX_SAFE_INTEGER]),
        ] {
            let wire = ok.to_json().unwrap();
            assert_eq!(MailboxSyncResult::decode(&bytes(&wire)).unwrap(), ok);
            assert!(!ok.is_reset());
        }
        for (bad, code) in [
            (page_of(9, 12, 11, &[10, 11]), "too_large"),
            (page_of(9, 12, 11, &[9]), "malformed"),
            (page_of(9, 12, 11, &[12]), "malformed"),
            (page_of(9, 12, 13, &[]), "malformed"),
            (page_of(9, 12, 8, &[]), "malformed"),
            (page_of(9, MAX_SAFE_INTEGER + 1, 9, &[]), "malformed"),
        ] {
            assert_eq!(bad.to_json().unwrap_err().code(), code, "{bad:?}");
            // The reader refuses the same text a Station's fault would send.
            let mut wire = page().to_json().unwrap();
            wire["after"] = json!(bad.after);
            wire["head"] = json!(bad.head);
            wire["through"] = json!(bad.through);
            wire["objects"] = Value::Array(
                bad.objects
                    .iter()
                    .map(|e| json!({"position": e.position, "object": e.raw()}))
                    .collect(),
            );
            if bad.head <= MAX_SAFE_INTEGER {
                assert_eq!(
                    MailboxSyncResult::decode(&bytes(&wire)).unwrap_err().code(),
                    code,
                    "{bad:?}"
                );
            }
        }
    }

    #[test]
    fn a_page_whose_head_is_below_its_after_is_a_reset_and_nothing_else() {
        // Rule 4: no objects, `through` equal to `head`.
        let reset = page_of(12, 3, 3, &[]);
        let wire = reset.to_json().unwrap();
        let read = MailboxSyncResult::decode(&bytes(&wire)).unwrap();
        assert!(read.is_reset());
        assert_eq!(read, reset);
        assert!(page_of(12, 0, 0, &[]).is_reset());
        for bad in [
            page_of(12, 3, 12, &[]),
            page_of(12, 3, 2, &[]),
            page_of(12, 3, 3, &[3]),
        ] {
            assert!(
                matches!(bad.to_json(), Err(RelayError::Malformed(_))),
                "{bad:?}"
            );
        }
    }

    #[test]
    fn a_page_keeps_each_object_as_the_station_sent_it() {
        // Rule 11: an object of any JSON type, judged on its own.
        for raw in [
            json!("not an object"),
            json!({"body": {}}),
            json!([1, 2]),
            json!(7),
        ] {
            let mut wire = page().to_json().unwrap();
            wire["objects"][0]["object"] = raw.clone();
            let page = MailboxSyncResult::decode(&bytes(&wire)).unwrap();
            assert_eq!(page.objects[0].raw(), &raw);
            assert!(page.objects[0].parse_object().is_err(), "{raw}");
        }
        // A page that isn't strict I-JSON is refused whole (a Station fault).
        let text = page().to_json().unwrap().to_string();
        let duplicate = text.replacen(r#""position":11"#, r#""position":11,"position":11"#, 1);
        assert_eq!(
            MailboxSyncResult::decode(duplicate.as_bytes()),
            Err(RelayError::NotStrict)
        );
    }

    // ----------------------------------------------------------- bounds

    /// A put of exactly `size` bytes: the object's ciphertext grown to just
    /// under it, then JSON whitespace after the message.
    fn put_of_size(size: usize) -> Vec<u8> {
        let wire = put().to_json().unwrap();
        let ct = b64u_decode_len(&wire["object"]["ct"]);
        // Base64url without padding: 4 characters per 3 bytes.
        let mut extra = (size - bytes(&wire).len()) / 4 * 3;
        loop {
            let mut changed = wire.clone();
            changed["object"]["ct"] = json!(b64u(&vec![0u8; ct + extra]));
            let mut text = bytes(&changed);
            if text.len() <= size {
                text.resize(size, b' ');
                return text;
            }
            extra -= 1;
        }
    }

    fn b64u_decode_len(value: &Value) -> usize {
        crate::encoding::b64u_decode(value.as_str().unwrap())
            .unwrap()
            .len()
    }

    #[test]
    fn every_mailbox_message_is_bounded_at_512_kib_before_it_is_parsed() {
        assert_eq!(MAX_MAILBOX_MESSAGE_BYTES, 524_288);
        // One at exactly the bound is read (its object isn't judged here).
        let at = put_of_size(MAX_MAILBOX_MESSAGE_BYTES);
        assert_eq!(at.len(), MAX_MAILBOX_MESSAGE_BYTES);
        assert!(MailboxPut::decode(&at).is_ok());
        // One byte more is refused before any parse: not JSON at all.
        let mut over = vec![b'x'; MAX_MAILBOX_MESSAGE_BYTES + 1];
        assert_eq!(MailboxToStation::decode(&over), Err(RelayError::TooLarge));
        assert_eq!(MailboxToHost::decode(&over), Err(RelayError::TooLarge));
        over.truncate(MAX_MAILBOX_MESSAGE_BYTES);
        assert_eq!(MailboxToStation::decode(&over), Err(RelayError::NotStrict));
        // A builder never writes one over it.
        let mut wire: Value = serde_json::from_slice(&at).unwrap();
        let ct = b64u_decode_len(&wire["object"]["ct"]);
        wire["object"]["ct"] = json!(b64u(&vec![0u8; ct + 3]));
        let big = MailboxPut::decode(&put_of_size(MAX_MAILBOX_MESSAGE_BYTES - 4)).unwrap();
        assert!(big.to_json().is_ok());
        let over = MailboxSyncResult {
            request_id: REQUEST.into(),
            mailbox_id: MAILBOX.into(),
            after: 0,
            head: 1,
            through: 1,
            objects: vec![MailboxEntry {
                position: 1,
                object: wire["object"].clone(),
            }],
        };
        assert_eq!(over.to_json(), Err(RelayError::TooLarge));
    }

    // -------------------------------------------------------- answering

    #[test]
    fn each_answer_says_whether_it_answers_a_call_and_which_field_differs() {
        let stored = MailboxStored {
            request_id: REQUEST.into(),
            id: ID.into(),
        };
        assert_eq!(stored.answers(&put()), Ok(()));
        let other_request = MailboxStored {
            request_id: REQUEST_2.into(),
            ..stored.clone()
        };
        assert_eq!(
            other_request.answers(&put()),
            Err(MailboxMismatch::RequestId)
        );
        let other_id = MailboxStored {
            id: TASK.into(),
            ..stored.clone()
        };
        assert_eq!(other_id.answers(&put()), Err(MailboxMismatch::Id));
        let refused = MailboxPutRefused {
            request_id: REQUEST.into(),
            id: ID.into(),
            code: PutRefusal::Quota,
        };
        assert_eq!(refused.answers(&put()), Ok(()));
        assert_eq!(
            MailboxPutRefused {
                id: TASK.into(),
                ..refused.clone()
            }
            .answers(&put()),
            Err(MailboxMismatch::Id)
        );

        assert_eq!(page().answers(&sync(9)), Ok(()));
        assert_eq!(page().answers(&sync(8)), Err(MailboxMismatch::After));
        let mut other = sync(9);
        other.mailbox_id = MAILBOX_2.into();
        assert_eq!(page().answers(&other), Err(MailboxMismatch::MailboxId));
        other.request_id = REQUEST_2.into();
        assert_eq!(page().answers(&other), Err(MailboxMismatch::RequestId));

        let result = MailboxDoneResult {
            request_id: REQUEST.into(),
            mailbox_id: MAILBOX.into(),
            position: 11,
        };
        assert_eq!(result.answers(&done()), Ok(()));
        let mut other = done();
        other.position = 12;
        assert_eq!(result.answers(&other), Err(MailboxMismatch::Position));
        other.mailbox_id = MAILBOX_2.into();
        assert_eq!(result.answers(&other), Err(MailboxMismatch::MailboxId));
        for m in [
            MailboxMismatch::RequestId,
            MailboxMismatch::Id,
            MailboxMismatch::MailboxId,
            MailboxMismatch::After,
            MailboxMismatch::Position,
        ] {
            assert_eq!(MailboxMismatch::from_code(m.code()), Some(m));
        }
    }

    // ------------------------------------------------------- object_hash

    /// `SHA-256(enc([jcs(body), sig, enc, ct]))`, written out here.
    fn hash_of(body_jcs: &str, sig: &[u8], enc: &[u8], ct: &[u8]) -> Hash32 {
        use sha2::{Digest, Sha256};
        let mut framed = Vec::new();
        for part in [body_jcs.as_bytes(), sig, enc, ct] {
            framed.extend_from_slice(&(part.len() as u32).to_be_bytes());
            framed.extend_from_slice(part);
        }
        Hash32(Sha256::digest(&framed).into())
    }

    #[test]
    fn object_hash_is_the_evidence_hash_of_the_object_in_canonical_form() {
        // Rule 3: an object's identity in its mailbox, the evidence hash of
        // the receiver's verdicts, so the Station and the host agree on it.
        let obj = object();
        let sealed = obj.sealed().unwrap();
        let want = hash_of(obj.jcs(), obj.sig(), &sealed.enc, &sealed.ct);
        assert_eq!(object_hash(&obj), want);
        assert_eq!(object_hash(&obj), super::super::evidence_hash(&obj));
        // Serialized again, with whitespace and another key order, it is the
        // same object.
        let wire = obj.to_json();
        let mut reordered = Map::new();
        for key in ["sig", "ct", "body", "enc"] {
            reordered.insert(key.to_owned(), wire[key].clone());
        }
        let text = serde_json::to_string_pretty(&Value::Object(reordered)).unwrap();
        let again = SignedObject::parse(text.as_bytes()).unwrap();
        assert_eq!(object_hash(&again), want);
        // Any changed byte, or a byte moved between `enc` and `ct`, is
        // another object.
        let moved = {
            let mut enc = sealed.enc.clone();
            let mut ct = sealed.ct.clone();
            enc.push(ct.remove(0));
            hash_of(obj.jcs(), obj.sig(), &enc, &ct)
        };
        assert_ne!(moved, want);
        let mut other_sig = wire.clone();
        other_sig["sig"] = json!(b64u(&[0u8; 64]));
        let mut other_ct = wire.clone();
        other_ct["ct"] = json!(b64u(&[0u8; 48]));
        let mut other_body = wire.clone();
        other_body["body"]["created_at"] = json!(CREATED_AT + 1);
        for changed in [other_sig, other_ct, other_body] {
            let changed = SignedObject::parse(changed.to_string().as_bytes()).unwrap();
            assert_ne!(object_hash(&changed), want);
        }
    }

    #[test]
    fn the_heads_mailbox_is_read_where_accepted() {
        // Rule 6 through the Station's dispatch (the field's own rules are
        // `control::relay`'s).
        let wire = json!({"type": "relay", "op": "heads", "feeds": [],
            "membership": {"seq": 10, "hash": "00".repeat(32)},
            "mailbox": {"mailbox_id": MAILBOX, "head": 12}});
        let (heads, mailbox) =
            ToHost::decode_with(&bytes(&wire), Accept { mailbox: true }).unwrap();
        assert!(matches!(heads, ToHost::Heads(_)));
        assert_eq!(
            mailbox,
            Some(MailboxHead {
                mailbox_id: MAILBOX.into(),
                head: 12
            })
        );
        assert_eq!(ToHost::decode(&bytes(&wire)), Err(RelayError::UnknownField));
    }
}

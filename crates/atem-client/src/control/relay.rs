//! Station call wire types (delegated host-work design I.5.8, I.5.2, I.6.5;
//! the contract is `designs/protocol/atem-host-work-v1.md` §11.4):
//! the relay messages by which a host reads its Station's control feed,
//! acknowledges what it applied, and fetches the device list itself.
//!
//! Every message is `{"type":"relay","op":…}` on Atem's one link, like
//! `push_hint` ([`crate::push`]). The Station is whatever the relay is: these
//! are the shapes the two ends share, built and read here and nowhere else.
//!
//! | `op` | direction | fields |
//! |---|---|---|
//! | `control_sync` | host → Station | `request_id`, `origin`, `feed_id?`, `after` |
//! | `control_sync_result` | Station → host | `request_id`, `origin`, `feed_id`, `after`, `head`, `station_time`, `records:[{feed_seq, record}]` |
//! | `heads` | Station → host | `feeds:[{origin, feed_id, head, station_time}]`, `membership:{seq, hash}` |
//! | `control_ack` | host → Station | `account_id`, `genesis_hash`, `host_id`, `host_trust_gen`, `origin`, `feed_id`, `cursor`, `results` |
//! | `membership_fetch` | host → Station | `after` |
//! | `membership_fetch_result` | Station → host | `head`, `entries` |
//! | `control_sync_refused`, `membership_fetch_refused`, `control_ack_refused` | Station → host | `code` (`forbidden`) |
//!
//! A `mailbox` field joins `heads` in stage 3 (II.5); until then it is an
//! unknown field and refused.
//!
//! **Strict.** A reader takes the received bytes: at most
//! [`MAX_RELAY_MESSAGE_BYTES`] (R9.9: every relay message, in either
//! direction, as sent), checked before any parse, then one strict I-JSON
//! parse (no duplicate key, integers only and safe, no lone surrogate). The
//! field set is exact, an optional field is omitted and never `null`, a
//! count over its bound is refused before any item is read, and each
//! grammar (UUID v4, lowercase hex, `[A-Za-z0-9._:-]` ids, normalized
//! origins) is the one the signed objects use. Each builder checks what its
//! reader checks, so what it writes is what the reader accepts.
//!
//! **Correlation** (amended in place on Astation's request, #164 comment
//! 6858189009; unshipped, so no new version and no fallback). A
//! `control_sync` names itself with `request_id`, a lowercase UUID v4 the
//! host makes fresh for every call (a timeout's retry and a new link
//! generation's call included), and its `control_sync_result` carries the
//! same id and echoes the call's `after`; a call that names a feed is
//! answered on that feed. Cursor echoes alone can't tell two calls at the
//! same cursor apart. [`ControlSyncResult::answers`] is the one matching
//! decision the host and Astation's `:8080` proxy share; the link
//! generation, account and genesis captured with the call are the caller's
//! to compare. A page holds only records strictly after its `after`, so a
//! record at or below it is `malformed`, and a page whose `head` is below
//! its `after` (the feed went back: the host rescans) holds none.
//!
//! **Which host is calling** (I.5.8). No call has a field that names the
//! caller. The Station takes the calling host from the link's verified
//! association (its account, root, host, trust generation and connection;
//! for a call through Astation's `:8080` or a carrier-A link, the
//! authenticated transport's, else a fresh host-key challenge), and a
//! `control_ack` carries the account, root, host and trust generation it
//! claims only so the Station can refuse any that differ from the link's:
//! the claim is never the authority.
//!
//! **Delivery progress is not application** (I.5.8). A `control_ack` reports
//! the host's scan `cursor` apart from its per-effect application results,
//! and only a result of `applied` or `duplicate` is the host saying an
//! effect is in force. A result names the exact record (`record_id`), or,
//! for a host sender's revoke, the device-list entry (`seq`, `entry_hash`)
//! and host-work's applied device-list `seq`.
//!
//! **Typed reasons** (O5, Astation's review of PR 2, #120 comment
//! 6848326392). An effect `pending` or `refused` may say why: `why`, a
//! code of the shared vocabulary ([`super::state::Why`]), 1 to
//! [`super::state::MAX_WHY_BYTES`] bytes of `[a-z0-9_]`. The host writes
//! one exactly where its effect result has one (never beside `applied` or
//! `duplicate`). It is information for the Station only: it never changes
//! a result, never counts as evidence, and asks for no re-signing. A
//! reader refuses the whole ack for a `why` that is `null`, not a text,
//! empty, over the bound, outside the character set or beside an effect
//! in force; it reads a well-formed code it doesn't know as unrecognized
//! ([`EffectWhy::Unrecognized`]), the result unchanged, so a new reason
//! never breaks an older Station. Absent: no reason.
//!
//! **A feed's records are judged one at a time** (I.5.4). A
//! `control_sync_result` keeps each record's value as the Station sent it,
//! of any JSON type, and checks nothing of it: one record the control
//! parser refuses ([`FeedEntry::parse_record`]: not an object, no body, a
//! `null` inside, the wrong shape) never costs the page, the feed's position
//! or the records after it. The caller keeps such a record as evidence, and
//! whether a record is valid and what it does is [`super::state`]'s.
//!
//! **A page that isn't strict JSON is refused whole.** The page is one
//! strict I-JSON parse, so a duplicate key, a fraction, an unsafe integer, a
//! lone surrogate or nesting past the parser's depth anywhere in it, inside
//! a record too, is [`RelayError::NotStrict`] for the whole page. That is a
//! Station fault, not a bad record: a Station validates every record at
//! intake with the shared parser and serves only what it stored. The host
//! then refuses the page, keeps its cursor, leaves the gate for that origin
//! closed (fail closed) and raises a rate-limited alert; this layer only
//! says which refusal it is.
//!
//! **Refusals** (agreed with Astation, 2026-11-11, Atem #120 comment
//! 6810116314). A Station refuses a host's call on this link with
//! `{"type":"relay","op":"<call>_refused","code":"forbidden"}`
//! ([`CallRefused`]; `code` is exactly `forbidden` in this version, and
//! nothing else is carried: no account, feed, host, cursor, principal,
//! integration or record): a `control_sync` or `membership_fetch` for
//! another account, and a `control_ack` whose claimed association isn't the
//! link's ([`super::ledger::AckRefusal::reply`]). A refusal is an
//! authorization failure on that link, never an empty successful page or an
//! application acknowledgment: it advances no cursor, membership head, clock
//! floor or ledger evidence and opens no gate. It carries no request id or
//! cursor (a `control_sync`'s `request_id` included: a refusal names a call
//! kind, never a request) and never completes or correlates a request. The host keeps that link's
//! synchronization gates closed while it repairs the association and
//! resynchronizes; the transport may still fence or close the link.
//!
//! **Clocks** (I.6.5). `station_time` is the Station's unsigned word: here
//! it is only a safe integer. The host's cap on it and its clock floor are
//! the host's.
use std::collections::BTreeSet;

use serde_json::{Map, Value, json};

use crate::SignedObject;
use crate::canonical::{MAX_SAFE_INTEGER, StrictError, StrictValue};
use crate::channel::carriage::MAX_CARRIED_BYTES;
use crate::encoding::Hash32;
use crate::membership::entry::id_ok;
use crate::membership::{Head, MAX_CARRIAGE_ENTRIES};
use crate::session::wire::is_uuid_v4;
use crate::station_route::normalize_relay;

use super::record::{ControlError, ControlRecord};
use super::state::{ApplicationResult, EffectKind, EffectResult, EffectWhy};

/// The most bytes one relay message is, as sent (R9.9): checked before a
/// reader parses anything, and by every builder.
pub const MAX_RELAY_MESSAGE_BYTES: usize = 256 * 1024;
/// The most records one `control_sync_result` carries.
pub const MAX_FEED_RECORDS: usize = 64;
/// The most results one `control_ack` carries.
pub const MAX_ACK_RESULTS: usize = 64;
/// The most feeds one `heads` announces.
pub const MAX_HEAD_FEEDS: usize = 64;
/// The most entries one `membership_fetch_result` carries (R9.3's carriage).
pub const MAX_FETCH_ENTRIES: usize = MAX_CARRIAGE_ENTRIES;
/// `account_id`: 1 to this many bytes, as the device list's (§R9.2).
const MAX_ACCOUNT_ID_BYTES: usize = 128;

// The message bound includes the entries' array and more, so it is never
// looser than R9.3's carriage bound on the array alone.
const _: () = assert!(MAX_RELAY_MESSAGE_BYTES <= MAX_CARRIED_BYTES);

/// The `op` of each message.
pub mod op {
    pub const CONTROL_SYNC: &str = "control_sync";
    pub const CONTROL_SYNC_RESULT: &str = "control_sync_result";
    pub const HEADS: &str = "heads";
    pub const CONTROL_ACK: &str = "control_ack";
    pub const MEMBERSHIP_FETCH: &str = "membership_fetch";
    pub const MEMBERSHIP_FETCH_RESULT: &str = "membership_fetch_result";
    pub const CONTROL_SYNC_REFUSED: &str = "control_sync_refused";
    pub const MEMBERSHIP_FETCH_REFUSED: &str = "membership_fetch_refused";
    pub const CONTROL_ACK_REFUSED: &str = "control_ack_refused";
}

/// Why a relay message is refused. `code()` is a stable name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RelayError {
    /// Over [`MAX_RELAY_MESSAGE_BYTES`], or more records, results, feeds or
    /// entries than the message takes.
    TooLarge,
    /// Not strict I-JSON: a duplicate key, a fraction, an unsafe integer,
    /// bytes that aren't JSON.
    NotStrict,
    /// Not a relay message of the `op` this reader reads.
    WrongMessage,
    /// A field outside the message's (or the nested object's) exact set.
    UnknownField,
    /// A required field missing, `null` or mistyped, or out of its grammar;
    /// names it.
    Malformed(&'static str),
}

impl RelayError {
    pub fn code(&self) -> &'static str {
        match self {
            RelayError::TooLarge => "too_large",
            RelayError::NotStrict => "not_strict",
            RelayError::WrongMessage => "wrong_message",
            RelayError::UnknownField => "unknown_field",
            RelayError::Malformed(_) => "malformed",
        }
    }
}

impl std::fmt::Display for RelayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RelayError::Malformed(what) => write!(f, "malformed: {what}"),
            other => f.write_str(other.code()),
        }
    }
}

impl std::error::Error for RelayError {}

type Result<T> = std::result::Result<T, RelayError>;

// ------------------------------------------------------- shared reading

/// One strict parse, bounded before it starts.
fn parse(bytes: &[u8]) -> Result<StrictValue> {
    StrictValue::parse(bytes, MAX_RELAY_MESSAGE_BYTES).map_err(|e| match e {
        StrictError::TooLarge => RelayError::TooLarge,
        _ => RelayError::NotStrict,
    })
}

/// The `op` of a relay message: `type` is `relay` and `op` a string.
fn op_of(root: &Value) -> Option<&str> {
    let o = root.as_object()?;
    (o.get("type")?.as_str()? == "relay")
        .then(|| o.get("op")?.as_str())
        .flatten()
}

/// An object that holds only the fields `allowed` names.
struct Fields<'a>(&'a Map<String, Value>);

impl<'a> Fields<'a> {
    fn of(value: &'a Value, allowed: &[&str], what: &'static str) -> Result<Self> {
        let o = value.as_object().ok_or(RelayError::Malformed(what))?;
        if o.keys().any(|k| !allowed.contains(&k.as_str())) {
            return Err(RelayError::UnknownField);
        }
        Ok(Fields(o))
    }

    /// The top of a message of `op` with exactly the fields `allowed`
    /// (`type` and `op` among them).
    fn message(root: &'a Value, op: &str, allowed: &[&str]) -> Result<Self> {
        if op_of(root) != Some(op) {
            return Err(RelayError::WrongMessage);
        }
        Fields::of(root, allowed, "message")
    }

    fn get(&self, key: &'static str) -> Result<&'a Value> {
        self.0.get(key).ok_or(RelayError::Malformed(key))
    }

    fn text(&self, key: &'static str) -> Result<&'a str> {
        self.get(key)?.as_str().ok_or(RelayError::Malformed(key))
    }

    /// A text that may be absent; present, it is a text (never `null`).
    fn optional_text(&self, key: &'static str) -> Result<Option<&'a str>> {
        match self.0.get(key) {
            None => Ok(None),
            Some(value) => value.as_str().map(Some).ok_or(RelayError::Malformed(key)),
        }
    }

    /// A whole number of at least 0 (the strict parse keeps it safe).
    fn uint(&self, key: &'static str) -> Result<u64> {
        self.get(key)?.as_u64().ok_or(RelayError::Malformed(key))
    }

    /// An array of at most `max` items: over it is `TooLarge`, before any
    /// item is read.
    fn array(&self, key: &'static str, max: usize) -> Result<&'a [Value]> {
        let items = self
            .get(key)?
            .as_array()
            .ok_or(RelayError::Malformed(key))?;
        if items.len() > max {
            return Err(RelayError::TooLarge);
        }
        Ok(items)
    }
}

/// `{"type":"relay","op":op}`, to add the message's fields to.
fn message(op: &str) -> Map<String, Value> {
    let mut m = Map::new();
    m.insert("type".into(), json!("relay"));
    m.insert("op".into(), json!(op));
    m
}

/// The finished message, within the bound every relay message keeps.
fn finish(m: Map<String, Value>) -> Result<Value> {
    let value = Value::Object(m);
    if value.to_string().len() > MAX_RELAY_MESSAGE_BYTES {
        return Err(RelayError::TooLarge);
    }
    Ok(value)
}

fn check_origin(origin: &str) -> Result<()> {
    if normalize_relay(origin).as_deref() == Ok(origin) {
        Ok(())
    } else {
        Err(RelayError::Malformed("origin"))
    }
}

fn check_feed_id(feed_id: &str) -> Result<()> {
    if is_uuid_v4(feed_id) {
        Ok(())
    } else {
        Err(RelayError::Malformed("feed_id"))
    }
}

fn check_safe(n: u64, what: &'static str) -> Result<()> {
    if n <= MAX_SAFE_INTEGER {
        Ok(())
    } else {
        Err(RelayError::Malformed(what))
    }
}

/// A device-list head: exactly `{seq, hash}`, `seq` of at least 1. Unlike
/// `membership::Head::from_json` (which gives `None` for anything wrong), an
/// extra field here is `unknown_field`, as in every relay message.
fn read_head(value: &Value, what: &'static str) -> Result<Head> {
    let f = Fields::of(value, &["seq", "hash"], what)?;
    let seq = f.uint("seq").map_err(|_| RelayError::Malformed(what))?;
    let hash = Hash32::from_hex(f.text("hash").map_err(|_| RelayError::Malformed(what))?)
        .map_err(|_| RelayError::Malformed(what))?;
    let head = Head { seq, hash };
    check_head(&head, what)?;
    Ok(head)
}

fn check_head(head: &Head, what: &'static str) -> Result<()> {
    if (1..=MAX_SAFE_INTEGER).contains(&head.seq) {
        Ok(())
    } else {
        Err(RelayError::Malformed(what))
    }
}

// ---------------------------------------------------------- control_sync

fn check_request_id(request_id: &str) -> Result<()> {
    if is_uuid_v4(request_id) {
        Ok(())
    } else {
        Err(RelayError::Malformed("request_id"))
    }
}

/// `control_sync{request_id, origin, feed_id?, after}` (host → Station):
/// read the feed `feed_id` of the Station at `origin` after position
/// `after`, the last position this host has read of it (0: none). A host
/// that doesn't know the feed yet omits `feed_id` and starts at 0: a cursor
/// belongs to a feed, so there is none to continue from without one.
///
/// `request_id` names this call, so its result can be told apart from any
/// other's (correlation, amended in place on Astation's request, #164
/// comment 6858189009): a lowercase UUID v4, which the builder takes from
/// the caller. The host makes a fresh one for every call: a retry after a
/// timeout and a call on a new link generation get new ids, even at the
/// same cursor. An id is a correlation value, never authorization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlSync {
    pub request_id: String,
    pub origin: String,
    pub feed_id: Option<String>,
    pub after: u64,
}

impl ControlSync {
    fn check(&self) -> Result<()> {
        check_request_id(&self.request_id)?;
        check_origin(&self.origin)?;
        if let Some(feed_id) = &self.feed_id {
            check_feed_id(feed_id)?;
        }
        check_safe(self.after, "after")?;
        if self.feed_id.is_none() && self.after != 0 {
            return Err(RelayError::Malformed("after"));
        }
        Ok(())
    }

    /// The wire message, checked as the reader checks it.
    pub fn to_json(&self) -> Result<Value> {
        self.check()?;
        let mut m = message(op::CONTROL_SYNC);
        m.insert("request_id".into(), json!(self.request_id));
        m.insert("origin".into(), json!(self.origin));
        if let Some(feed_id) = &self.feed_id {
            m.insert("feed_id".into(), json!(feed_id));
        }
        m.insert("after".into(), json!(self.after));
        finish(m)
    }

    /// Reads received bytes, strictly.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Self::read(parse(bytes)?.value())
    }

    fn read(root: &Value) -> Result<Self> {
        let f = Fields::message(
            root,
            op::CONTROL_SYNC,
            &["type", "op", "request_id", "origin", "feed_id", "after"],
        )?;
        let sync = ControlSync {
            request_id: f.text("request_id")?.to_owned(),
            origin: f.text("origin")?.to_owned(),
            feed_id: f.optional_text("feed_id")?.map(str::to_owned),
            after: f.uint("after")?,
        };
        sync.check()?;
        Ok(sync)
    }
}

// --------------------------------------------------- control_sync_result

/// One record of a feed at its position (`feed_seq` isn't a field of the
/// record, I.5.3). The record is the value the Station sent, of any JSON
/// type, kept as it came (the host keeps one the parser refuses as
/// evidence); [`FeedEntry::parse_record`] is the control parser's verdict
/// on it, and the only judgement made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedEntry {
    pub feed_seq: u64,
    record: Value,
}

impl FeedEntry {
    /// A Station's entry for a record it holds, at `feed_seq`.
    pub fn new(feed_seq: u64, record: &ControlRecord) -> Self {
        FeedEntry {
            feed_seq,
            record: record.object().to_json(),
        }
    }

    /// The record's value as received (of any type: nothing is known of it
    /// until [`FeedEntry::parse_record`]).
    pub fn raw(&self) -> &Value {
        &self.record
    }

    /// The record the control parser makes of it, or why it refuses it
    /// (I.5.3). Valid against the device list is [`super::verify`]'s.
    pub fn parse_record(&self) -> std::result::Result<ControlRecord, ControlError> {
        // The value came out of a strict parse (the reader's) or is a
        // record's own wire object; a value that isn't an object is refused
        // by `from_value`.
        let object = SignedObject::from_value(&self.record).map_err(ControlError::Object)?;
        ControlRecord::from_signed(object)
    }
}

/// `control_sync_result{request_id, origin, feed_id, after, head,
/// station_time, records}` (Station → host): the answer to the call
/// `request_id` names, echoing its `after`: the records of the feed after
/// that position (ascending `feed_seq`, none above `head`; gaps are
/// legal), the feed's `head` and the Station's clock. Identity of the
/// feed: `(origin, feed_id)` (I.5.2). A call that named a feed is answered
/// on that feed; one that named none (from 0) learns the account's current
/// feed here. A `head` below `after` (the feed went back on the same id)
/// comes with no records: the host rescans from 0. Whether it answers a
/// given call is [`ControlSyncResult::answers`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlSyncResult {
    /// The call's id, as it sent it.
    pub request_id: String,
    pub origin: String,
    pub feed_id: String,
    /// The call's `after`, echoed.
    pub after: u64,
    /// The feed's last position (0: an empty feed).
    pub head: u64,
    /// The Station's clock, ms since the epoch (unsigned: I.6.5).
    pub station_time: u64,
    /// At most [`MAX_FEED_RECORDS`], ascending, each in `after + 1..=head`.
    pub records: Vec<FeedEntry>,
}

impl ControlSyncResult {
    const FIELDS: [&'static str; 9] = [
        "type",
        "op",
        "request_id",
        "origin",
        "feed_id",
        "after",
        "head",
        "station_time",
        "records",
    ];

    fn check(&self) -> Result<()> {
        if self.records.len() > MAX_FEED_RECORDS {
            return Err(RelayError::TooLarge);
        }
        check_request_id(&self.request_id)?;
        check_origin(&self.origin)?;
        check_feed_id(&self.feed_id)?;
        check_safe(self.after, "after")?;
        check_safe(self.head, "head")?;
        check_safe(self.station_time, "station_time")?;
        // Strictly after the echoed `after`, ascending, none above `head`:
        // with `head` below `after`, no record at all.
        let mut previous = self.after;
        for entry in &self.records {
            if entry.feed_seq <= previous || entry.feed_seq > self.head {
                return Err(RelayError::Malformed("feed_seq"));
            }
            previous = entry.feed_seq;
        }
        Ok(())
    }

    /// The wire message, checked as the reader checks it, and within the
    /// message bound.
    pub fn to_json(&self) -> Result<Value> {
        self.check()?;
        let mut m = message(op::CONTROL_SYNC_RESULT);
        m.insert("request_id".into(), json!(self.request_id));
        m.insert("origin".into(), json!(self.origin));
        m.insert("feed_id".into(), json!(self.feed_id));
        m.insert("after".into(), json!(self.after));
        m.insert("head".into(), json!(self.head));
        m.insert("station_time".into(), json!(self.station_time));
        m.insert(
            "records".into(),
            Value::Array(
                self.records
                    .iter()
                    .map(|e| json!({"feed_seq": e.feed_seq, "record": e.record}))
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
        let f = Fields::message(root, op::CONTROL_SYNC_RESULT, &Self::FIELDS)?;
        let items = f.array("records", MAX_FEED_RECORDS)?;
        let records = items
            .iter()
            .map(|item| {
                let e = Fields::of(item, &["feed_seq", "record"], "records")?;
                // Any strict-JSON value, of any type: judged per record.
                let record = e.get("record")?;
                Ok(FeedEntry {
                    feed_seq: e.uint("feed_seq")?,
                    record: record.clone(),
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let result = ControlSyncResult {
            request_id: f.text("request_id")?.to_owned(),
            origin: f.text("origin")?.to_owned(),
            feed_id: f.text("feed_id")?.to_owned(),
            after: f.uint("after")?,
            head: f.uint("head")?,
            station_time: f.uint("station_time")?,
            records,
        };
        result.check()?;
        Ok(result)
    }

    /// Whether this page answers `call`: the same `request_id`, the same
    /// `origin`, the same `feed_id` when the call named one (a call that
    /// named none, from 0, is answered on whichever feed the page names;
    /// this helper can't tell that it is the account's current feed: the
    /// caller checks it against the own feed this generation's `heads`
    /// announced) and the same `after`. `Ok(())` when it does; else the
    /// first field that differs, in that order.
    ///
    /// An answering page whose `head` is below its `after` (it has no
    /// records) says the feed went back: the caller marks a rescan from 0
    /// durably and never moves its cursor on it.
    ///
    /// The one decision the host and Astation's `:8080` proxy share. It
    /// compares the two messages only: the caller compares the rest of what
    /// it captured with the call, the authenticated link generation (a page
    /// read on another generation answers nothing), the account and the
    /// genesis; and it keeps at most one live call per link generation, so a
    /// page that answers a retired, timed-out or old-generation call (or no
    /// call) advances nothing and opens no gate. A `request_id` is a
    /// correlation value, never authorization. Refusals name a call kind,
    /// never a request: none answers or correlates a call.
    pub fn answers(&self, call: &ControlSync) -> std::result::Result<(), SyncMismatch> {
        if self.request_id != call.request_id {
            return Err(SyncMismatch::RequestId);
        }
        if self.origin != call.origin {
            return Err(SyncMismatch::Origin);
        }
        if call.feed_id.as_ref().is_some_and(|f| *f != self.feed_id) {
            return Err(SyncMismatch::FeedId);
        }
        if self.after != call.after {
            return Err(SyncMismatch::After);
        }
        Ok(())
    }
}

/// Why a `control_sync_result` doesn't answer a `control_sync`
/// ([`ControlSyncResult::answers`]): the first of its fields that differs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncMismatch {
    /// Another call's id (a retired call's, a timed-out one's, an old
    /// generation's, or no call's).
    RequestId,
    /// Another Station's.
    Origin,
    /// Another feed than the one the call named.
    FeedId,
    /// Another `after` than the call's.
    After,
}

impl SyncMismatch {
    /// The field's name, as the goldens write it.
    pub fn code(self) -> &'static str {
        match self {
            SyncMismatch::RequestId => "request_id",
            SyncMismatch::Origin => "origin",
            SyncMismatch::FeedId => "feed_id",
            SyncMismatch::After => "after",
        }
    }

    pub fn from_code(code: &str) -> Option<Self> {
        [
            SyncMismatch::RequestId,
            SyncMismatch::Origin,
            SyncMismatch::FeedId,
            SyncMismatch::After,
        ]
        .into_iter()
        .find(|m| m.code() == code)
    }
}

// ------------------------------------------------------------------ heads

/// One feed's announcement: `{origin, feed_id, head, station_time}` (I.5.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedHead {
    pub origin: String,
    pub feed_id: String,
    pub head: u64,
    /// The Station's clock, ms since the epoch (unsigned: I.6.5).
    pub station_time: u64,
}

impl FeedHead {
    fn check(&self) -> Result<()> {
        check_origin(&self.origin)?;
        check_feed_id(&self.feed_id)?;
        check_safe(self.head, "head")?;
        check_safe(self.station_time, "station_time")
    }

    fn to_json(&self) -> Value {
        json!({"origin": self.origin, "feed_id": self.feed_id, "head": self.head,
            "station_time": self.station_time})
    }

    fn read(value: &Value) -> Result<Self> {
        let f = Fields::of(
            value,
            &["origin", "feed_id", "head", "station_time"],
            "feeds",
        )?;
        let feed = FeedHead {
            origin: f.text("origin")?.to_owned(),
            feed_id: f.text("feed_id")?.to_owned(),
            head: f.uint("head")?,
            station_time: f.uint("station_time")?,
        };
        feed.check()?;
        Ok(feed)
    }
}

/// `heads{feeds, membership}` (Station → host): on every (re)connection and
/// every 30 seconds, and at once when a record is stored, each covering
/// feed's head and the Station's device-list head. The announced list head
/// is the Station's word, not signed authority (I.5.8). Stage 3 adds the
/// host's mailbox head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heads {
    /// At most [`MAX_HEAD_FEEDS`], a feed once.
    pub feeds: Vec<FeedHead>,
    /// The device list's head, `seq` of at least 1.
    pub membership: Head,
}

impl Heads {
    fn check(&self) -> Result<()> {
        if self.feeds.len() > MAX_HEAD_FEEDS {
            return Err(RelayError::TooLarge);
        }
        let mut seen = BTreeSet::new();
        for feed in &self.feeds {
            feed.check()?;
            if !seen.insert((&feed.origin, &feed.feed_id)) {
                return Err(RelayError::Malformed("feeds"));
            }
        }
        check_head(&self.membership, "membership")
    }

    /// The wire message, checked as the reader checks it.
    pub fn to_json(&self) -> Result<Value> {
        self.check()?;
        let mut m = message(op::HEADS);
        m.insert(
            "feeds".into(),
            Value::Array(self.feeds.iter().map(FeedHead::to_json).collect()),
        );
        m.insert("membership".into(), self.membership.to_json());
        finish(m)
    }

    /// Reads received bytes, strictly.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Self::read(parse(bytes)?.value())
    }

    fn read(root: &Value) -> Result<Self> {
        let f = Fields::message(root, op::HEADS, &["type", "op", "feeds", "membership"])?;
        let feeds = f
            .array("feeds", MAX_HEAD_FEEDS)?
            .iter()
            .map(FeedHead::read)
            .collect::<Result<Vec<_>>>()?;
        let heads = Heads {
            feeds,
            membership: read_head(f.get("membership")?, "membership")?,
        };
        heads.check()?;
        Ok(heads)
    }
}

// ------------------------------------------------------------ control_ack

/// A device-list entry a result names: its `seq` and `entry_hash`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EntryRef {
    pub seq: u64,
    pub entry_hash: Hash32,
}

/// The effects of a record, as its results list them (the order of
/// `EffectKind::of`; the ledger's tests check that every set it gives is
/// one of these): a `cover`, a `revoke` (with the interrupt, when it asks
/// for one), a `hold`, a `release` or an `interrupt_running`.
const RECORD_EFFECTS: [&[EffectKind]; 6] = [
    &[EffectKind::Cover],
    &[EffectKind::Revocation],
    &[EffectKind::Revocation, EffectKind::Interrupt],
    &[EffectKind::Hold],
    &[EffectKind::Release],
    &[EffectKind::Interrupt],
];

/// A host sender's revoke entry: the revocation, and the interrupt when the
/// entry asked for one.
const ENTRY_EFFECTS: [&[EffectKind]; 2] = [
    &[EffectKind::Revocation],
    &[EffectKind::Revocation, EffectKind::Interrupt],
];

fn effects_are(effects: &[EffectResult], sets: &[&[EffectKind]]) -> bool {
    sets.iter().any(|set| {
        set.len() == effects.len() && set.iter().zip(effects).all(|(kind, e)| *kind == e.effect)
    })
}

fn effects_json(effects: &[EffectResult]) -> Value {
    Value::Array(
        effects
            .iter()
            .map(|e| {
                let mut o = json!({"effect": e.effect.code(), "result": e.result.code()});
                if let Some(why) = &e.why {
                    o["why"] = json!(why.code());
                }
                o
            })
            .collect(),
    )
}

/// An effect's reason, as an ack writes and reads it (O5): only beside
/// `pending` or `refused`, and only a well-formed code (a known one, or
/// one this build doesn't know, read as unrecognized).
fn check_why(e: &EffectResult) -> Result<()> {
    let Some(why) = &e.why else {
        return Ok(());
    };
    let not_in_force = matches!(
        e.result,
        ApplicationResult::Pending | ApplicationResult::Refused
    );
    if not_in_force && EffectWhy::well_formed(why.code()) {
        Ok(())
    } else {
        Err(RelayError::Malformed("why"))
    }
}

fn read_effects(f: &Fields) -> Result<Vec<EffectResult>> {
    let items = f
        .get("effects")?
        .as_array()
        .filter(|items| (1..=2).contains(&items.len()))
        .ok_or(RelayError::Malformed("effects"))?;
    items
        .iter()
        .map(|item| {
            let e = Fields::of(item, &["effect", "result", "why"], "effects")?;
            // Absent: no reason; present, a well-formed text (never null).
            let why = match e.0.get("why") {
                None => None,
                Some(why) => Some(
                    why.as_str()
                        .and_then(EffectWhy::read)
                        .ok_or(RelayError::Malformed("why"))?,
                ),
            };
            Ok(EffectResult {
                effect: EffectKind::from_code(e.text("effect")?)
                    .ok_or(RelayError::Malformed("effects"))?,
                result: ApplicationResult::from_code(e.text("result")?)
                    .ok_or(RelayError::Malformed("effects"))?,
                why,
            })
        })
        .collect()
}

/// One result in a `control_ack`: exactly one of two forms, by what it
/// names (I.5.8, "Delivery progress is not application"). Each carries a
/// result per effect, never the cursor's progress, and each effect not in
/// force may say why (O5, the module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AckResult {
    /// A control record, by its `record_id`: the effects it carries, once
    /// each, in a record's order.
    Record {
        record_id: String,
        effects: Vec<EffectResult>,
    },
    /// A host sender's device-list revoke, by `{seq, entry_hash}`, with
    /// host-work's applied device-list `seq` (II.3.1): its revocation, and
    /// the interrupt when the entry asked for one. A result of `applied` or
    /// `duplicate` means the effect is durable, so `applied_seq` has
    /// reached `entry.seq`; behind it only `pending` or `refused` is said.
    /// Its reason, written by host-work (host-work-v1 §11.4 wire rule 10):
    /// `revoke_not_applied` beside an effect `pending` while `applied_seq`
    /// is behind the entry, and none otherwise in this version.
    Entry {
        entry: EntryRef,
        applied_seq: u64,
        effects: Vec<EffectResult>,
    },
}

impl AckResult {
    fn check(&self) -> Result<()> {
        let effects = match self {
            AckResult::Record { effects, .. } | AckResult::Entry { effects, .. } => effects,
        };
        effects.iter().try_for_each(check_why)?;
        match self {
            AckResult::Record { record_id, effects } => {
                if !is_uuid_v4(record_id) {
                    return Err(RelayError::Malformed("record_id"));
                }
                if !effects_are(effects, &RECORD_EFFECTS) {
                    return Err(RelayError::Malformed("effects"));
                }
            }
            AckResult::Entry {
                entry,
                applied_seq,
                effects,
            } => {
                if !(1..=MAX_SAFE_INTEGER).contains(&entry.seq) {
                    return Err(RelayError::Malformed("entry"));
                }
                check_safe(*applied_seq, "applied_seq")?;
                if !effects_are(effects, &ENTRY_EFFECTS) {
                    return Err(RelayError::Malformed("effects"));
                }
                let in_force = effects.iter().any(|e| {
                    matches!(
                        e.result,
                        ApplicationResult::Applied | ApplicationResult::Duplicate
                    )
                });
                if in_force && *applied_seq < entry.seq {
                    return Err(RelayError::Malformed("applied_seq"));
                }
            }
        }
        Ok(())
    }

    fn to_json(&self) -> Value {
        match self {
            AckResult::Record { record_id, effects } => {
                json!({"record_id": record_id, "effects": effects_json(effects)})
            }
            AckResult::Entry {
                entry,
                applied_seq,
                effects,
            } => json!({
                "entry": {"seq": entry.seq, "entry_hash": entry.entry_hash.to_hex()},
                "applied_seq": applied_seq,
                "effects": effects_json(effects),
            }),
        }
    }

    fn read(value: &Value) -> Result<Self> {
        let o = value.as_object().ok_or(RelayError::Malformed("results"))?;
        let result = match (o.contains_key("record_id"), o.contains_key("entry")) {
            (true, false) => {
                let f = Fields::of(value, &["record_id", "effects"], "results")?;
                AckResult::Record {
                    record_id: f.text("record_id")?.to_owned(),
                    effects: read_effects(&f)?,
                }
            }
            (false, true) => {
                let f = Fields::of(value, &["entry", "applied_seq", "effects"], "results")?;
                let e = Fields::of(f.get("entry")?, &["seq", "entry_hash"], "entry")?;
                AckResult::Entry {
                    entry: EntryRef {
                        seq: e.uint("seq")?,
                        entry_hash: Hash32::from_hex(e.text("entry_hash")?)
                            .map_err(|_| RelayError::Malformed("entry_hash"))?,
                    },
                    applied_seq: f.uint("applied_seq")?,
                    effects: read_effects(&f)?,
                }
            }
            // Both forms, or neither: never one result of two kinds.
            _ => return Err(RelayError::Malformed("results")),
        };
        result.check()?;
        Ok(result)
    }
}

/// `control_ack{account_id, genesis_hash, host_id, host_trust_gen, origin,
/// feed_id, cursor, results}` (host → Station): the host's scan `cursor` in
/// the feed `(origin, feed_id)`, and the durable application results it
/// reports (a host acknowledges a record only after its effects are
/// durable). The cursor says only how far the host has read: it moves past
/// records kept pending or refused.
///
/// The account, root, host and trust generation are the host's **claim**:
/// the Station refuses an ack whose claim differs from its link's verified
/// association (account, root, host, trust generation and connection),
/// never taking the calling host from here (I.5.8, "Which host is
/// calling").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlAck {
    pub account_id: String,
    pub genesis_hash: Hash32,
    pub host_id: String,
    pub host_trust_gen: u64,
    pub origin: String,
    pub feed_id: String,
    pub cursor: u64,
    /// At most [`MAX_ACK_RESULTS`]: one per record and one per entry.
    pub results: Vec<AckResult>,
}

impl ControlAck {
    const FIELDS: [&'static str; 10] = [
        "type",
        "op",
        "account_id",
        "genesis_hash",
        "host_id",
        "host_trust_gen",
        "origin",
        "feed_id",
        "cursor",
        "results",
    ];

    /// What the reader checks (the Station's ledger checks an ack it is
    /// handed with it, [`super::ledger::AckLedger::ack`]).
    pub(super) fn check(&self) -> Result<()> {
        if self.results.len() > MAX_ACK_RESULTS {
            return Err(RelayError::TooLarge);
        }
        if self.account_id.is_empty() || self.account_id.len() > MAX_ACCOUNT_ID_BYTES {
            return Err(RelayError::Malformed("account_id"));
        }
        if !id_ok(&self.host_id) {
            return Err(RelayError::Malformed("host_id"));
        }
        if !(1..=MAX_SAFE_INTEGER).contains(&self.host_trust_gen) {
            return Err(RelayError::Malformed("host_trust_gen"));
        }
        check_origin(&self.origin)?;
        check_feed_id(&self.feed_id)?;
        check_safe(self.cursor, "cursor")?;
        let mut records = BTreeSet::new();
        let mut entries = BTreeSet::new();
        for result in &self.results {
            result.check()?;
            let fresh = match result {
                AckResult::Record { record_id, .. } => records.insert(record_id.as_str()),
                AckResult::Entry { entry, .. } => entries.insert(entry.seq),
            };
            if !fresh {
                return Err(RelayError::Malformed("results"));
            }
        }
        Ok(())
    }

    /// The wire message, checked as the reader checks it.
    pub fn to_json(&self) -> Result<Value> {
        self.check()?;
        let mut m = message(op::CONTROL_ACK);
        m.insert("account_id".into(), json!(self.account_id));
        m.insert("genesis_hash".into(), json!(self.genesis_hash.to_hex()));
        m.insert("host_id".into(), json!(self.host_id));
        m.insert("host_trust_gen".into(), json!(self.host_trust_gen));
        m.insert("origin".into(), json!(self.origin));
        m.insert("feed_id".into(), json!(self.feed_id));
        m.insert("cursor".into(), json!(self.cursor));
        m.insert(
            "results".into(),
            Value::Array(self.results.iter().map(AckResult::to_json).collect()),
        );
        finish(m)
    }

    /// Reads received bytes, strictly.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Self::read(parse(bytes)?.value())
    }

    fn read(root: &Value) -> Result<Self> {
        let f = Fields::message(root, op::CONTROL_ACK, &Self::FIELDS)?;
        let results = f
            .array("results", MAX_ACK_RESULTS)?
            .iter()
            .map(AckResult::read)
            .collect::<Result<Vec<_>>>()?;
        let ack = ControlAck {
            account_id: f.text("account_id")?.to_owned(),
            genesis_hash: Hash32::from_hex(f.text("genesis_hash")?)
                .map_err(|_| RelayError::Malformed("genesis_hash"))?,
            host_id: f.text("host_id")?.to_owned(),
            host_trust_gen: f.uint("host_trust_gen")?,
            origin: f.text("origin")?.to_owned(),
            feed_id: f.text("feed_id")?.to_owned(),
            cursor: f.uint("cursor")?,
            results,
        };
        ack.check()?;
        Ok(ack)
    }
}

// ------------------------------------------------------- device-list fetch

/// `membership_fetch{after}` (host → Station): the host's own device-list
/// fetch (I.5.8; R9.3 allows it, and it gets no more trust than any
/// carrier). `after` is the head `seq` the host holds. The host is named by
/// the link, as for every call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MembershipFetch {
    pub after: u64,
}

impl MembershipFetch {
    /// The wire message, checked as the reader checks it.
    pub fn to_json(&self) -> Result<Value> {
        check_safe(self.after, "after")?;
        let mut m = message(op::MEMBERSHIP_FETCH);
        m.insert("after".into(), json!(self.after));
        finish(m)
    }

    /// Reads received bytes, strictly.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Self::read(parse(bytes)?.value())
    }

    fn read(root: &Value) -> Result<Self> {
        let f = Fields::message(root, op::MEMBERSHIP_FETCH, &["type", "op", "after"])?;
        Ok(MembershipFetch {
            after: f.uint("after")?,
        })
    }
}

/// `membership_fetch_result{head, entries}` (Station → host): the Station's
/// device-list `head` and the entries after the host's `after`, as an R9.3
/// carriage: at most [`MAX_FETCH_ENTRIES`] signed objects, carried as they
/// are. Whether they extend the host's list is the host's, applied as any
/// carriage is (a list shorter than `head` is fetched again from its new
/// head).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MembershipFetchResult {
    pub head: Head,
    pub entries: Vec<SignedObject>,
}

impl MembershipFetchResult {
    fn check(&self) -> Result<()> {
        if self.entries.len() > MAX_FETCH_ENTRIES {
            return Err(RelayError::TooLarge);
        }
        check_head(&self.head, "head")
    }

    /// The wire message, checked as the reader checks it, and within the
    /// message bound (which holds the entries to R9.3's 256 KiB).
    pub fn to_json(&self) -> Result<Value> {
        self.check()?;
        let mut m = message(op::MEMBERSHIP_FETCH_RESULT);
        m.insert("head".into(), self.head.to_json());
        m.insert(
            "entries".into(),
            Value::Array(self.entries.iter().map(SignedObject::to_json).collect()),
        );
        finish(m)
    }

    /// Reads received bytes, strictly.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Self::read(parse(bytes)?.value())
    }

    fn read(root: &Value) -> Result<Self> {
        let f = Fields::message(
            root,
            op::MEMBERSHIP_FETCH_RESULT,
            &["type", "op", "head", "entries"],
        )?;
        let entries = f
            .array("entries", MAX_FETCH_ENTRIES)?
            .iter()
            .map(|item| {
                // The value is a part of the strict parse.
                SignedObject::from_value(item).map_err(|_| RelayError::Malformed("entries"))
            })
            .collect::<Result<Vec<_>>>()?;
        let result = MembershipFetchResult {
            head: read_head(f.get("head")?, "head")?,
            entries,
        };
        result.check()?;
        Ok(result)
    }
}

// ------------------------------------------------------------- refusals

/// Why a Station refused a host's call: exactly `forbidden` in this
/// version.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusalCode {
    /// The call isn't authorized on this link: another account's feed or
    /// device list, or an ack whose claimed association isn't the link's.
    Forbidden,
}

impl RefusalCode {
    /// The wire name.
    pub fn code(self) -> &'static str {
        match self {
            RefusalCode::Forbidden => "forbidden",
        }
    }

    /// From the wire name, exactly.
    pub fn from_code(code: &str) -> Option<Self> {
        (code == "forbidden").then_some(RefusalCode::Forbidden)
    }
}

/// The host's call a refusal answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefusedCall {
    ControlSync,
    MembershipFetch,
    ControlAck,
}

impl RefusedCall {
    /// The refusal's `op`: `<call>_refused`.
    pub fn op(self) -> &'static str {
        match self {
            RefusedCall::ControlSync => op::CONTROL_SYNC_REFUSED,
            RefusedCall::MembershipFetch => op::MEMBERSHIP_FETCH_REFUSED,
            RefusedCall::ControlAck => op::CONTROL_ACK_REFUSED,
        }
    }

    fn of_op(op: &str) -> Option<Self> {
        [
            RefusedCall::ControlSync,
            RefusedCall::MembershipFetch,
            RefusedCall::ControlAck,
        ]
        .into_iter()
        .find(|call| call.op() == op)
    }
}

/// A Station's refusal of a host's call on this link:
/// `{"type":"relay","op":"<call>_refused","code":"forbidden"}` (Station →
/// host; agreed with Astation, 2026-11-11). Exactly those fields: it names
/// no account, feed, host, cursor, principal, integration or record. An
/// authorization failure on the link, never a page or an acknowledgment:
/// the host advances nothing on it (cursor, membership head, clock floor,
/// evidence), opens no gate, completes and correlates no request, and keeps
/// the link's synchronization gates closed while it repairs the
/// association and resynchronizes (the module docs).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CallRefused {
    pub call: RefusedCall,
    pub code: RefusalCode,
}

impl CallRefused {
    /// The wire message.
    pub fn to_json(&self) -> Result<Value> {
        let mut m = message(self.call.op());
        m.insert("code".into(), json!(self.code.code()));
        finish(m)
    }

    /// Reads received bytes, strictly: one of the three refusals.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let root = parse(bytes)?;
        let root = root.value();
        let call = op_of(root)
            .and_then(RefusedCall::of_op)
            .ok_or(RelayError::WrongMessage)?;
        Self::read(root, call)
    }

    fn read(root: &Value, call: RefusedCall) -> Result<Self> {
        let f = Fields::message(root, call.op(), &["type", "op", "code"])?;
        let code = RefusalCode::from_code(f.text("code")?).ok_or(RelayError::Malformed("code"))?;
        Ok(CallRefused { call, code })
    }
}

impl From<CallRefused> for ToHost {
    fn from(refused: CallRefused) -> Self {
        match refused.call {
            RefusedCall::ControlSync => ToHost::ControlSyncRefused(refused.code),
            RefusedCall::MembershipFetch => ToHost::MembershipFetchRefused(refused.code),
            RefusedCall::ControlAck => ToHost::ControlAckRefused(refused.code),
        }
    }
}

// ------------------------------------------------------------- dispatch

/// A message a Station reads from a host. A relay message of any other op,
/// or none, is `WrongMessage` (the link carries others: `push_hint`, …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToStation {
    ControlSync(ControlSync),
    ControlAck(ControlAck),
    MembershipFetch(MembershipFetch),
}

impl ToStation {
    /// Reads received bytes, strictly: one parse, then the reader of its
    /// `op`.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let root = parse(bytes)?;
        let root = root.value();
        match op_of(root) {
            Some(op::CONTROL_SYNC) => ControlSync::read(root).map(ToStation::ControlSync),
            Some(op::CONTROL_ACK) => ControlAck::read(root).map(ToStation::ControlAck),
            Some(op::MEMBERSHIP_FETCH) => {
                MembershipFetch::read(root).map(ToStation::MembershipFetch)
            }
            _ => Err(RelayError::WrongMessage),
        }
    }
}

/// A message a host reads from its Station. A relay message of any other
/// op, or none, is `WrongMessage`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ToHost {
    ControlSyncResult(ControlSyncResult),
    Heads(Heads),
    MembershipFetchResult(MembershipFetchResult),
    /// The Station refused this link's `control_sync` ([`CallRefused`]).
    ControlSyncRefused(RefusalCode),
    /// The Station refused this link's `membership_fetch`.
    MembershipFetchRefused(RefusalCode),
    /// The Station refused this link's `control_ack`.
    ControlAckRefused(RefusalCode),
}

impl ToHost {
    /// Reads received bytes, strictly: one parse, then the reader of its
    /// `op`.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let root = parse(bytes)?;
        let root = root.value();
        match op_of(root) {
            Some(op::CONTROL_SYNC_RESULT) => {
                ControlSyncResult::read(root).map(ToHost::ControlSyncResult)
            }
            Some(op::HEADS) => Heads::read(root).map(ToHost::Heads),
            Some(op::MEMBERSHIP_FETCH_RESULT) => {
                MembershipFetchResult::read(root).map(ToHost::MembershipFetchResult)
            }
            Some(op) => match RefusedCall::of_op(op) {
                Some(call) => CallRefused::read(root, call).map(ToHost::from),
                None => Err(RelayError::WrongMessage),
            },
            None => Err(RelayError::WrongMessage),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::state::{EffectWhy, MAX_WHY_BYTES, Why};
    use crate::control::verify::{PendingReason, RefusalReason};
    use crate::encoding::b64u;
    use serde_json::json;

    const ORIGIN: &str = "https://station-dev.agora.build";
    const FEED: &str = "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b";
    const FEED_2: &str = "7a2d3c4b-5e6f-4a71-9b8c-0d1e2f3a4b5c";
    const STATION_TIME: u64 = 1_793_620_800_000;

    fn record_id(n: u64) -> String {
        format!("0b9a8c7d-6e5f-4a3b-9c2d-{n:012x}")
    }

    /// A service's `revoke` through `ORIGIN`'s feed `FEED`: well formed, not
    /// verified (the signature has the right shape only).
    fn service_record(n: u64) -> ControlRecord {
        let body = json!({
            "type": "atem-host-work-control", "v": 1,
            "account_id": "acct-test-1", "genesis_hash": "11".repeat(32),
            "origin": ORIGIN, "feed_id": FEED,
            "principal": "service:svc-1", "principal_key": "22".repeat(32),
            "signer": "service:svc-1",
            "action": "revoke", "interrupt_running": true,
            "record_id": record_id(n), "issued_at": 1_793_620_800_000u64,
            "about": {"integration_id": "i-01jc5zq9x8w7v6t5s4r3q2p1n0", "by": "owner"},
        });
        ControlRecord::parse(
            json!({"body": body, "sig": b64u(&[7u8; 64])})
                .to_string()
                .as_bytes(),
        )
        .unwrap()
    }

    /// A device-list entry as a carried object (its chain is the host's to
    /// evaluate; this layer only carries it).
    fn entry_object(seq: u64, pad: &str) -> SignedObject {
        SignedObject::parse(
            json!({"body": {"type": "atem-membership-entry", "v": 1, "seq": seq, "pad": pad},
                "sig": "AA"})
            .to_string()
            .as_bytes(),
        )
        .unwrap()
    }

    fn hash(byte: u8) -> Hash32 {
        Hash32([byte; 32])
    }

    fn effect(effect: EffectKind, result: ApplicationResult) -> EffectResult {
        EffectResult {
            effect,
            result,
            why: None,
        }
    }

    /// An effect not in force, with its reason.
    fn effect_why(effect: EffectKind, result: ApplicationResult, why: Why) -> EffectResult {
        EffectResult {
            effect,
            result,
            why: Some(EffectWhy::Known(why)),
        }
    }

    fn bytes(message: &Value) -> Vec<u8> {
        message.to_string().into_bytes()
    }

    /// A call's `request_id`: a lowercase UUID v4.
    const REQUEST: &str = "5d0e9a3c-2b1f-4c8d-9e7a-6b5c4d3e2f10";
    /// Another call's (a retry at the same cursor, say).
    const REQUEST_2: &str = "8a1b2c3d-4e5f-4a6b-8c7d-9e0f1a2b3c4d";

    fn sync() -> ControlSync {
        ControlSync {
            request_id: REQUEST.into(),
            origin: ORIGIN.into(),
            feed_id: Some(FEED.into()),
            after: 41,
        }
    }

    /// The answer to `sync()`: `records` records from position 42.
    fn sync_result(records: u64) -> ControlSyncResult {
        ControlSyncResult {
            request_id: REQUEST.into(),
            origin: ORIGIN.into(),
            feed_id: FEED.into(),
            after: 41,
            head: 1000,
            station_time: STATION_TIME,
            records: (1..=records)
                .map(|n| FeedEntry::new(41 + n, &service_record(n)))
                .collect(),
        }
    }

    fn heads() -> Heads {
        Heads {
            feeds: vec![
                FeedHead {
                    origin: ORIGIN.into(),
                    feed_id: FEED.into(),
                    head: 100,
                    station_time: STATION_TIME,
                },
                FeedHead {
                    origin: ORIGIN.into(),
                    feed_id: FEED_2.into(),
                    head: 3,
                    station_time: STATION_TIME + 1,
                },
            ],
            membership: Head {
                seq: 20,
                hash: hash(0x33),
            },
        }
    }

    fn record_ack(n: u64) -> AckResult {
        AckResult::Record {
            record_id: record_id(n),
            effects: vec![
                effect(EffectKind::Revocation, ApplicationResult::Duplicate),
                effect(EffectKind::Interrupt, ApplicationResult::Applied),
            ],
        }
    }

    fn entry_ack() -> AckResult {
        AckResult::Entry {
            entry: EntryRef {
                seq: 20,
                entry_hash: hash(0x44),
            },
            applied_seq: 21,
            effects: vec![
                effect(EffectKind::Revocation, ApplicationResult::Applied),
                effect(EffectKind::Interrupt, ApplicationResult::Pending),
            ],
        }
    }

    fn ack(results: Vec<AckResult>) -> ControlAck {
        ControlAck {
            account_id: "acct-test-1".into(),
            genesis_hash: hash(0x11),
            host_id: "host-a".into(),
            host_trust_gen: 2,
            origin: ORIGIN.into(),
            feed_id: FEED.into(),
            cursor: 43,
            results,
        }
    }

    fn fetch_result(entries: u64) -> MembershipFetchResult {
        MembershipFetchResult {
            head: Head {
                seq: 20,
                hash: hash(0x33),
            },
            entries: (1..=entries).map(|n| entry_object(n, "")).collect(),
        }
    }

    /// The six messages, as built (name, wire message).
    fn all_messages() -> Vec<(&'static str, Value)> {
        vec![
            ("control_sync", sync().to_json().unwrap()),
            ("control_sync_result", sync_result(3).to_json().unwrap()),
            ("heads", heads().to_json().unwrap()),
            (
                "control_ack",
                ack(vec![record_ack(1), entry_ack()]).to_json().unwrap(),
            ),
            (
                "membership_fetch",
                MembershipFetch { after: 19 }.to_json().unwrap(),
            ),
            (
                "membership_fetch_result",
                fetch_result(2).to_json().unwrap(),
            ),
        ]
    }

    /// Reads `message` as its own reader does.
    fn read(op: &str, message: &[u8]) -> Result<()> {
        match op {
            "control_sync" => ControlSync::decode(message).map(drop),
            "control_sync_result" => ControlSyncResult::decode(message).map(drop),
            "heads" => Heads::decode(message).map(drop),
            "control_ack" => ControlAck::decode(message).map(drop),
            "membership_fetch" => MembershipFetch::decode(message).map(drop),
            "membership_fetch_result" => MembershipFetchResult::decode(message).map(drop),
            other => panic!("{other}"),
        }
    }

    fn with(message: &Value, pointer: &str, value: Value) -> Vec<u8> {
        let mut changed = message.clone();
        *changed.pointer_mut(pointer).expect(pointer) = value;
        bytes(&changed)
    }

    fn add(message: &Value, object: &str, key: &str) -> Vec<u8> {
        let mut changed = message.clone();
        let target = if object.is_empty() {
            &mut changed
        } else {
            changed.pointer_mut(object).expect(object)
        };
        target.as_object_mut().unwrap().insert(key.into(), json!(1));
        bytes(&changed)
    }

    fn without(message: &Value, object: &str, key: &str) -> Vec<u8> {
        let mut changed = message.clone();
        let target = if object.is_empty() {
            &mut changed
        } else {
            changed.pointer_mut(object).expect(object)
        };
        target.as_object_mut().unwrap().remove(key).expect(key);
        bytes(&changed)
    }

    fn is_malformed<T>(r: Result<T>) -> bool {
        matches!(r, Err(RelayError::Malformed(_)))
    }

    // ------------------------------------------------------- round trips

    #[test]
    fn each_message_round_trips() {
        // Every message is `{"type":"relay","op":…}`, and what the builder
        // writes the reader gives back, bytes in between.
        let sent = sync();
        let wire = sent.to_json().unwrap();
        assert_eq!(wire["type"], "relay");
        assert_eq!(wire["op"], "control_sync");
        assert_eq!(ControlSync::decode(&bytes(&wire)).unwrap(), sent);
        // A host that doesn't know the feed yet omits `feed_id`.
        let first = ControlSync {
            request_id: REQUEST.into(),
            origin: ORIGIN.into(),
            feed_id: None,
            after: 0,
        };
        let wire = first.to_json().unwrap();
        assert!(wire.get("feed_id").is_none(), "omitted, never null");
        assert_eq!(ControlSync::decode(&bytes(&wire)).unwrap(), first);

        let sent = sync_result(3);
        let wire = sent.to_json().unwrap();
        assert_eq!(wire["op"], "control_sync_result");
        let got = ControlSyncResult::decode(&bytes(&wire)).unwrap();
        assert_eq!(got, sent);
        assert_eq!(got.records[1].feed_seq, 43);
        assert_eq!(got.records[1].parse_record().unwrap(), service_record(2));
        // No records: a heartbeat of the feed's position.
        let empty = sync_result(0);
        let wire = empty.to_json().unwrap();
        assert_eq!(ControlSyncResult::decode(&bytes(&wire)).unwrap(), empty);

        let sent = heads();
        let wire = sent.to_json().unwrap();
        assert_eq!(wire["op"], "heads");
        assert_eq!(Heads::decode(&bytes(&wire)).unwrap(), sent);
        // No feed: the device-list head alone.
        let list_only = Heads {
            feeds: Vec::new(),
            membership: sent.membership,
        };
        let wire = list_only.to_json().unwrap();
        assert_eq!(Heads::decode(&bytes(&wire)).unwrap(), list_only);

        // Both result forms, and an ack that is only a cursor.
        let sent = ack(vec![
            record_ack(1),
            entry_ack(),
            AckResult::Record {
                record_id: record_id(2),
                effects: vec![effect(EffectKind::Cover, ApplicationResult::Refused)],
            },
        ]);
        let wire = sent.to_json().unwrap();
        assert_eq!(wire["op"], "control_ack");
        assert_eq!(ControlAck::decode(&bytes(&wire)).unwrap(), sent);
        let cursor_only = ack(Vec::new());
        let wire = cursor_only.to_json().unwrap();
        assert_eq!(ControlAck::decode(&bytes(&wire)).unwrap(), cursor_only);

        let sent = MembershipFetch { after: 19 };
        let wire = sent.to_json().unwrap();
        assert_eq!(wire["op"], "membership_fetch");
        assert_eq!(MembershipFetch::decode(&bytes(&wire)).unwrap(), sent);

        let sent = fetch_result(3);
        let wire = sent.to_json().unwrap();
        assert_eq!(wire["op"], "membership_fetch_result");
        assert_eq!(MembershipFetchResult::decode(&bytes(&wire)).unwrap(), sent);
        // Already at the head: nothing to carry.
        let none = fetch_result(0);
        let wire = none.to_json().unwrap();
        assert_eq!(MembershipFetchResult::decode(&bytes(&wire)).unwrap(), none);
    }

    #[test]
    fn each_direction_has_its_own_dispatch() {
        let messages = all_messages();
        let to_station = ["control_sync", "control_ack", "membership_fetch"];
        for (op, message) in &messages {
            let wire = bytes(message);
            let station = ToStation::decode(&wire);
            let host = ToHost::decode(&wire);
            if to_station.contains(op) {
                assert!(station.is_ok(), "{op} is for the Station");
                assert_eq!(host, Err(RelayError::WrongMessage), "{op} isn't for a host");
            } else {
                assert!(host.is_ok(), "{op} is for the host");
                assert_eq!(
                    station,
                    Err(RelayError::WrongMessage),
                    "{op} isn't for a Station"
                );
            }
        }
        // The dispatch gives the same value the typed reader does.
        assert_eq!(
            ToStation::decode(&bytes(&messages[0].1)),
            Ok(ToStation::ControlSync(sync()))
        );
        assert_eq!(
            ToHost::decode(&bytes(&messages[1].1)),
            Ok(ToHost::ControlSyncResult(sync_result(3)))
        );
        // Another relay message, or none, is not ours.
        for other in [
            json!({"type": "relay", "op": "push_ack", "acks": []}),
            json!({"type": "relay", "op": "mailbox_put"}),
            json!({"type": "session", "op": "control_sync"}),
            json!({"op": "control_sync"}),
            json!({"type": "relay"}),
            json!({"type": "relay", "op": 5}),
            json!([]),
        ] {
            assert_eq!(
                ToStation::decode(&bytes(&other)),
                Err(RelayError::WrongMessage)
            );
            assert_eq!(
                ToHost::decode(&bytes(&other)),
                Err(RelayError::WrongMessage)
            );
        }
    }

    // ----------------------------------------------------- strictness

    #[test]
    fn unknown_fields_and_null_refused() {
        for (op, message) in all_messages() {
            // A field beside the message's own, at the top.
            assert_eq!(
                read(op, &add(&message, "", "extra")),
                Err(RelayError::UnknownField),
                "{op}"
            );
            // Every field of the message: missing, or null, is refused
            // (an absent field is omitted, never null).
            let keys: Vec<String> = message.as_object().unwrap().keys().cloned().collect();
            for key in keys.iter().filter(|k| *k != "type" && *k != "op") {
                assert!(
                    is_malformed(read(op, &without(&message, "", key))),
                    "{op} without {key}"
                );
                assert!(
                    is_malformed(read(op, &with(&message, &format!("/{key}"), Value::Null))),
                    "{op} with {key} null"
                );
            }
        }
        // `feed_id` is optional in `control_sync` only: absent is fine, null
        // is not, and a `null` never stands for absent.
        let message = sync().to_json().unwrap();
        assert!(is_malformed(ControlSync::decode(&without(
            &message, "", "feed_id"
        )))); // after 41 needs a feed
        let first = ControlSync {
            request_id: REQUEST.into(),
            origin: ORIGIN.into(),
            feed_id: None,
            after: 0,
        }
        .to_json()
        .unwrap();
        assert!(ControlSync::decode(&bytes(&first)).is_ok());
        assert!(is_malformed(ControlSync::decode(&add(
            &first, "", "feed_id"
        ))));
        let mut with_null = first.clone();
        with_null["feed_id"] = Value::Null;
        assert!(is_malformed(ControlSync::decode(&bytes(&with_null))));

        // Nested objects take exactly their fields too.
        let result = sync_result(2).to_json().unwrap();
        let heads = heads().to_json().unwrap();
        let acks = ack(vec![record_ack(1), entry_ack()]).to_json().unwrap();
        let fetched = fetch_result(2).to_json().unwrap();
        for (op, message, object) in [
            ("control_sync_result", &result, "/records/0"),
            ("heads", &heads, "/feeds/0"),
            ("heads", &heads, "/membership"),
            ("control_ack", &acks, "/results/0/effects/0"),
            ("control_ack", &acks, "/results/1/entry"),
            ("membership_fetch_result", &fetched, "/head"),
        ] {
            assert_eq!(
                read(op, &add(message, object, "extra")),
                Err(RelayError::UnknownField),
                "{op} {object}"
            );
        }
        // …and a null inside them.
        for (op, message, field) in [
            ("control_sync_result", &result, "/records/0/feed_seq"),
            ("heads", &heads, "/feeds/0/station_time"),
            ("heads", &heads, "/membership/hash"),
            ("control_ack", &acks, "/results/0/record_id"),
            ("control_ack", &acks, "/results/0/effects/0/result"),
            ("control_ack", &acks, "/results/1/entry/entry_hash"),
            ("control_ack", &acks, "/results/1/applied_seq"),
            ("membership_fetch_result", &fetched, "/head/seq"),
            ("membership_fetch_result", &fetched, "/entries/0"),
        ] {
            assert!(
                is_malformed(read(op, &with(message, field, Value::Null))),
                "{op} {field} null"
            );
        }

        // Not strict I-JSON: a duplicate key, a fraction, an unsafe integer,
        // trailing bytes, a message that is no object.
        let good = String::from_utf8(bytes(&sync().to_json().unwrap())).unwrap();
        for bad in [
            good.replacen("\"after\":41", "\"after\":41,\"after\":42", 1),
            good.replacen("\"after\":41", "\"after\":41.5", 1),
            good.replacen("\"after\":41", "\"after\":9007199254740992", 1),
            good.replacen("\"after\":41", "\"after\":-1", 1),
            format!("{good} x"),
            "[]".to_string(),
        ] {
            assert!(ControlSync::decode(bad.as_bytes()).is_err(), "{bad}");
        }
        assert_eq!(
            ControlSync::decode(
                good.replacen("\"after\":41", "\"after\":41,\"after\":42", 1)
                    .as_bytes()
            ),
            Err(RelayError::NotStrict)
        );
        assert_eq!(
            ControlSync::decode(
                good.replacen("\"after\":41", "\"after\":9007199254740992", 1)
                    .as_bytes()
            ),
            Err(RelayError::NotStrict)
        );

        // The type and op are exact.
        assert_eq!(
            ControlSync::decode(&with(&sync().to_json().unwrap(), "/type", json!("session"))),
            Err(RelayError::WrongMessage)
        );
        assert_eq!(
            ControlSync::decode(&with(&sync().to_json().unwrap(), "/op", json!("heads"))),
            Err(RelayError::WrongMessage)
        );
        // Ids and origins are grammar-checked.
        let message = sync().to_json().unwrap();
        for (pointer, value) in [
            ("/origin", json!("https://station-dev.agora.build/")),
            ("/origin", json!("https://Station-Dev.agora.build")),
            ("/origin", json!("http://station-dev.agora.build")),
            ("/origin", json!("")),
            ("/feed_id", json!("not-a-uuid")),
            ("/feed_id", json!("6F1C2B3A-4D5E-4F60-8A7B-9C0D1E2F3A4B")),
            ("/feed_id", json!("6f1c2b3a-4d5e-5f60-8a7b-9c0d1e2f3a4b")),
        ] {
            assert!(
                is_malformed(ControlSync::decode(&with(&message, pointer, value.clone()))),
                "{pointer} {value}"
            );
        }
    }

    #[test]
    fn calls_carry_no_host_field() {
        // The Station takes the calling host from the link's verified
        // association (I.5.8, "Which host is calling"), never from a field
        // the caller picks: a call has no field to pick one with.
        for (op, message) in [
            ("control_sync", sync().to_json().unwrap()),
            (
                "membership_fetch",
                MembershipFetch { after: 1 }.to_json().unwrap(),
            ),
        ] {
            for key in [
                "host_id",
                "host_trust_gen",
                "account_id",
                "genesis_hash",
                "connection_id",
            ] {
                assert_eq!(
                    read(op, &add(&message, "", key)),
                    Err(RelayError::UnknownField),
                    "{op} with {key}"
                );
            }
        }
    }

    #[test]
    fn ack_names_the_whole_association() {
        // The ack carries the account, root, host and trust generation it
        // claims; the Station compares every one with its link's verified
        // association (with the connection, which no field can name), so a
        // host id alone is never enough: each field is required.
        let message = ack(vec![record_ack(1)]).to_json().unwrap();
        for key in [
            "account_id",
            "genesis_hash",
            "host_id",
            "host_trust_gen",
            "origin",
            "feed_id",
            "cursor",
        ] {
            assert!(
                is_malformed(read("control_ack", &without(&message, "", key))),
                "without {key}"
            );
        }
        // The grammar of each.
        for (pointer, value) in [
            ("/account_id", json!("")),
            ("/account_id", json!("a".repeat(129))),
            ("/genesis_hash", json!("11".repeat(31))),
            ("/genesis_hash", json!("AA".repeat(32))),
            ("/host_id", json!("")),
            ("/host_id", json!("has space")),
            ("/host_id", json!("h".repeat(129))),
            ("/host_trust_gen", json!(0)),
            ("/cursor", json!(-1)),
        ] {
            assert!(
                is_malformed(read("control_ack", &with(&message, pointer, value.clone()))),
                "{pointer} {value}"
            );
        }
        let decoded = ControlAck::decode(&bytes(&message)).unwrap();
        assert_eq!(decoded.account_id, "acct-test-1");
        assert_eq!(decoded.genesis_hash, hash(0x11));
        assert_eq!(decoded.host_id, "host-a");
        assert_eq!(decoded.host_trust_gen, 2);
    }

    // ---------------------------------------------------------- bounds

    /// A `control_sync_result` of exactly `len` bytes whose one record is
    /// raw (kept, not judged) and padded.
    fn padded_result(len: usize) -> Vec<u8> {
        let base = json!({"type": "relay", "op": "control_sync_result", "request_id": REQUEST,
            "origin": ORIGIN, "feed_id": FEED, "after": 0, "head": 1, "station_time": STATION_TIME,
            "records": [{"feed_seq": 1, "record": {"pad": ""}}]})
        .to_string();
        let padding = "x".repeat(len - base.len());
        base.replacen("\"pad\":\"\"", &format!("\"pad\":\"{padding}\""), 1)
            .into_bytes()
    }

    #[test]
    fn record_and_byte_bounds() {
        assert_eq!(MAX_RELAY_MESSAGE_BYTES, 256 * 1024);
        assert_eq!(MAX_FEED_RECORDS, 64);

        // Records: 64 fit, 65 don't, by the builder and by the reader.
        let sent = sync_result(64);
        assert_eq!(sent.records.len(), 64);
        let wire = sent.to_json().unwrap();
        assert!(wire.to_string().len() < MAX_RELAY_MESSAGE_BYTES);
        assert_eq!(ControlSyncResult::decode(&bytes(&wire)).unwrap(), sent);
        let too_many = sync_result(65);
        assert_eq!(too_many.to_json(), Err(RelayError::TooLarge));
        let mut wire65 = wire.clone();
        let extra = wire65["records"][0].clone();
        wire65["records"].as_array_mut().unwrap().push(extra);
        assert_eq!(
            ControlSyncResult::decode(&bytes(&wire65)),
            Err(RelayError::TooLarge)
        );

        // Bytes: exactly 256 KiB is read, one more is refused before any
        // parse (even bytes that aren't JSON).
        let at_limit = padded_result(MAX_RELAY_MESSAGE_BYTES);
        assert_eq!(at_limit.len(), MAX_RELAY_MESSAGE_BYTES);
        let got = ControlSyncResult::decode(&at_limit).unwrap();
        assert_eq!(got.records.len(), 1);
        // A decoded result is written again as it was read.
        let again = got.to_json().unwrap();
        assert_eq!(again.to_string().len(), MAX_RELAY_MESSAGE_BYTES);
        assert_eq!(again, serde_json::from_slice::<Value>(&at_limit).unwrap());
        let over = padded_result(MAX_RELAY_MESSAGE_BYTES + 1);
        assert_eq!(ControlSyncResult::decode(&over), Err(RelayError::TooLarge));
        let garbage = vec![b'{'; MAX_RELAY_MESSAGE_BYTES + 1];
        for op in [
            "control_sync",
            "control_sync_result",
            "heads",
            "control_ack",
            "membership_fetch",
            "membership_fetch_result",
        ] {
            assert_eq!(read(op, &garbage), Err(RelayError::TooLarge), "{op}");
        }
        assert_eq!(ToStation::decode(&garbage), Err(RelayError::TooLarge));
        assert_eq!(ToHost::decode(&garbage), Err(RelayError::TooLarge));

        // Acknowledgments: 64 results, not 65.
        let many = |n: u64| ack((1..=n).map(record_ack).collect());
        let wire = many(64).to_json().unwrap();
        assert_eq!(ControlAck::decode(&bytes(&wire)).unwrap(), many(64));
        assert_eq!(many(65).to_json(), Err(RelayError::TooLarge));
        let mut wire65 = wire.clone();
        let extra = wire65["results"][0].clone();
        wire65["results"].as_array_mut().unwrap().push(extra);
        // (65 results, one repeated: too many comes first.)
        assert_eq!(
            ControlAck::decode(&bytes(&wire65)),
            Err(RelayError::TooLarge)
        );

        // Heads: 64 feeds, not 65.
        let feeds = |n: u64| Heads {
            feeds: (1..=n)
                .map(|i| FeedHead {
                    origin: ORIGIN.into(),
                    feed_id: format!("7a2d3c4b-5e6f-4a71-9b8c-{i:012x}"),
                    head: i,
                    station_time: STATION_TIME,
                })
                .collect(),
            membership: Head {
                seq: 20,
                hash: hash(0x33),
            },
        };
        let wire = feeds(64).to_json().unwrap();
        assert_eq!(Heads::decode(&bytes(&wire)).unwrap(), feeds(64));
        assert_eq!(feeds(65).to_json(), Err(RelayError::TooLarge));
        let mut wire65 = wire.clone();
        let extra = wire65["feeds"][0].clone();
        wire65["feeds"].as_array_mut().unwrap().push(extra);
        assert_eq!(Heads::decode(&bytes(&wire65)), Err(RelayError::TooLarge));

        // The device-list fetch is a carriage (R9.3): 64 entries, not 65,
        // and never past the message bound.
        assert_eq!(MAX_FETCH_ENTRIES, 64);
        let wire = fetch_result(64).to_json().unwrap();
        assert_eq!(
            MembershipFetchResult::decode(&bytes(&wire)).unwrap(),
            fetch_result(64)
        );
        assert_eq!(fetch_result(65).to_json(), Err(RelayError::TooLarge));
        let mut wire65 = wire.clone();
        let extra = wire65["entries"][0].clone();
        wire65["entries"].as_array_mut().unwrap().push(extra);
        assert_eq!(
            MembershipFetchResult::decode(&bytes(&wire65)),
            Err(RelayError::TooLarge)
        );
        // 64 entries of the largest body (4,096 bytes) are over 256 KiB.
        let full = |n: u64| {
            let bare = jcs_len(entry_object(n, "").body());
            entry_object(n, &"p".repeat(4096 - bare))
        };
        let large = MembershipFetchResult {
            head: Head {
                seq: 64,
                hash: hash(0x33),
            },
            entries: (1..=64).map(full).collect(),
        };
        assert!(
            large.entries.iter().all(|e| jcs_len(e.body()) == 4096),
            "the largest body"
        );
        assert_eq!(large.to_json(), Err(RelayError::TooLarge));
        let mut fewer = large.clone();
        fewer.entries.truncate(60);
        let wire = fewer.to_json().unwrap();
        assert!(wire.to_string().len() <= MAX_RELAY_MESSAGE_BYTES);
        assert_eq!(MembershipFetchResult::decode(&bytes(&wire)).unwrap(), fewer);

        // A count is refused before any item is read: 65 items that aren't
        // even objects are `TooLarge`, where 64 of them are each malformed.
        for (op, key, message) in [
            (
                "control_sync_result",
                "records",
                sync_result(1).to_json().unwrap(),
            ),
            ("heads", "feeds", heads().to_json().unwrap()),
            (
                "control_ack",
                "results",
                ack(vec![record_ack(1)]).to_json().unwrap(),
            ),
            (
                "membership_fetch_result",
                "entries",
                fetch_result(1).to_json().unwrap(),
            ),
        ] {
            let junk = |n: usize| {
                with(
                    &message,
                    &format!("/{key}"),
                    Value::Array(vec![Value::Null; n]),
                )
            };
            assert_eq!(read(op, &junk(65)), Err(RelayError::TooLarge), "{op}");
            assert!(is_malformed(read(op, &junk(64))), "{op}");
        }
    }

    fn jcs_len(body: &Value) -> usize {
        crate::canonical::jcs(body).unwrap().len()
    }

    #[test]
    fn integers_are_whole_and_safe() {
        let max = crate::canonical::MAX_SAFE_INTEGER;
        let at = MembershipFetch { after: max };
        assert_eq!(
            MembershipFetch::decode(&bytes(&at.to_json().unwrap())).unwrap(),
            at
        );
        assert_eq!(
            MembershipFetch { after: max + 1 }.to_json(),
            Err(RelayError::Malformed("after"))
        );
        let mut late = sync_result(1);
        late.station_time = max + 1;
        assert_eq!(late.to_json(), Err(RelayError::Malformed("station_time")));
        let mut far = ack(Vec::new());
        far.cursor = max + 1;
        assert_eq!(far.to_json(), Err(RelayError::Malformed("cursor")));
        let mut gen0 = ack(Vec::new());
        gen0.host_trust_gen = 0;
        assert_eq!(gen0.to_json(), Err(RelayError::Malformed("host_trust_gen")));
    }

    // ---------------------------------------------------------- feeds

    #[test]
    fn a_bad_record_is_refused_per_record_not_per_message() {
        // A record the parser refuses is kept as evidence and refused alone
        // (I.5.4): the feed's other records, and its position, still arrive.
        let good = service_record(1).object().to_json();
        let message = json!({"type": "relay", "op": "control_sync_result", "request_id": REQUEST,
        "origin": ORIGIN, "feed_id": FEED, "after": 0, "head": 6, "station_time": STATION_TIME,
        "records": [
            {"feed_seq": 1, "record": good},
            {"feed_seq": 2, "record": {}},
            {"feed_seq": 3, "record": {"body": {"type": "atem-host-work-control", "v": 1, "x": null}, "sig": "AA"}},
            {"feed_seq": 4, "record": {"body": {"type": "atem-membership-entry", "v": 1}, "sig": "AA"}},
            {"feed_seq": 5, "record": {"body": 5, "sig": 6, "other": [1, 2]}},
            {"feed_seq": 6, "record": service_record(6).object().to_json()},
        ]});
        let got = ControlSyncResult::decode(&bytes(&message)).unwrap();
        assert_eq!(got.records.len(), 6);
        let judged: Vec<bool> = got
            .records
            .iter()
            .map(|r| r.parse_record().is_ok())
            .collect();
        assert_eq!(judged, [true, false, false, false, false, true]);
        assert_eq!(got.records[1].raw(), &json!({}));
        assert_eq!(got.records[2].raw()["body"]["x"], Value::Null);
        // Written again as received: the evidence is what the Station sent.
        assert_eq!(got.to_json().unwrap(), message);

        // A record of any other type is no signed object, and is judged like
        // any other record that isn't one: the page still reads (T14a).
        for record in [
            json!(null),
            json!(7),
            json!(true),
            json!("text"),
            json!([1]),
            json!([]),
        ] {
            let mut odd = message.clone();
            odd["records"][1]["record"] = record.clone();
            let got =
                ControlSyncResult::decode(&bytes(&odd)).unwrap_or_else(|e| panic!("{record}: {e}"));
            assert_eq!(got.records.len(), 6, "{record}");
            assert_eq!(got.records[1].raw(), &record);
            assert!(got.records[1].parse_record().is_err(), "{record}");
            // Its neighbours are read and judged on their own.
            assert!(got.records[0].parse_record().is_ok(), "{record}");
            assert!(got.records[5].parse_record().is_ok(), "{record}");
            // Kept as received.
            assert_eq!(got.to_json().unwrap(), odd, "{record}");
        }
        // A record that isn't there is no entry: the entry is malformed.
        let mut missing = message.clone();
        missing["records"][1]
            .as_object_mut()
            .unwrap()
            .remove("record");
        assert!(is_malformed(read("control_sync_result", &bytes(&missing))));
    }

    #[test]
    fn a_page_that_is_not_strict_json_is_refused_whole() {
        // The one thing a page can't survive: bytes that aren't strict I-JSON
        // anywhere, a record's included (a duplicate key, a fraction, an
        // unsafe integer, a lone surrogate, nesting past the parser's
        // depth). That is a Station fault: it relays only what it stored
        // after parsing it strictly. The host refuses the page, keeps its
        // cursor, leaves the gate closed and alerts (rate limited); this
        // layer says which refusal it is.
        let message = json!({"type": "relay", "op": "control_sync_result", "request_id": REQUEST,
        "origin": ORIGIN, "feed_id": FEED, "after": 0, "head": 3, "station_time": STATION_TIME,
        "records": [
            {"feed_seq": 1, "record": service_record(1).object().to_json()},
            {"feed_seq": 2, "record": {"pad": "PAD"}},
            {"feed_seq": 3, "record": service_record(3).object().to_json()},
        ]});
        let text = String::from_utf8(bytes(&message)).unwrap();
        assert!(ControlSyncResult::decode(text.as_bytes()).is_ok());
        let deep = format!("{}1{}", "[".repeat(200), "]".repeat(200));
        for (name, record) in [
            ("duplicate key", "{\"a\":1,\"a\":2}".to_string()),
            ("fraction", "{\"a\":1.5}".to_string()),
            ("exponent", "{\"a\":1e2}".to_string()),
            ("unsafe integer", "{\"a\":9007199254740992}".to_string()),
            ("lone surrogate", "{\"a\":\"\\ud800\"}".to_string()),
            ("too deep", deep),
            ("not even JSON", "{\"a\":}".to_string()),
        ] {
            let bad = text.replacen("{\"pad\":\"PAD\"}", &record, 1);
            assert_ne!(bad, text, "{name}");
            assert_eq!(
                ControlSyncResult::decode(bad.as_bytes()),
                Err(RelayError::NotStrict),
                "{name}"
            );
            assert_eq!(
                ToHost::decode(bad.as_bytes()),
                Err(RelayError::NotStrict),
                "{name}"
            );
        }
    }

    #[test]
    fn feed_positions_ascend_and_stay_within_the_head() {
        let message = sync_result(3).to_json().unwrap(); // feed_seq 42, 43, 44; head 1000
        let seqs = |a: u64, b: u64, c: u64| {
            let mut m = message.clone();
            for (i, s) in [a, b, c].into_iter().enumerate() {
                m["records"][i]["feed_seq"] = json!(s);
            }
            bytes(&m)
        };
        assert!(ControlSyncResult::decode(&seqs(42, 43, 44)).is_ok());
        assert!(
            ControlSyncResult::decode(&seqs(42, 50, 1000)).is_ok(),
            "gaps are the host's to judge"
        );
        for bad in [(43, 42, 44), (42, 42, 44), (0, 1, 2), (998, 999, 1001)] {
            assert!(
                is_malformed(ControlSyncResult::decode(&seqs(bad.0, bad.1, bad.2))),
                "{bad:?}"
            );
        }
        // The builder refuses what the reader would.
        let mut sent = sync_result(2);
        sent.records.swap(0, 1);
        assert!(sent.to_json().is_err());
        let mut below = sync_result(2);
        below.head = 42;
        assert!(below.to_json().is_err());
    }

    #[test]
    fn a_sync_without_a_feed_starts_at_the_beginning() {
        // A cursor belongs to a feed: with no `feed_id` there is no position
        // to continue from.
        let first = ControlSync {
            request_id: REQUEST.into(),
            origin: ORIGIN.into(),
            feed_id: None,
            after: 5,
        };
        assert_eq!(first.to_json(), Err(RelayError::Malformed("after")));
        let wire = json!({"type": "relay", "op": "control_sync", "request_id": REQUEST,
            "origin": ORIGIN, "after": 5});
        assert_eq!(
            ControlSync::decode(&bytes(&wire)),
            Err(RelayError::Malformed("after"))
        );
    }

    // ------------------------------------------------------- correlation

    /// Correlation (amended in place on Astation's request, #164 comment
    /// 6858189009): a `control_sync` names itself with `request_id`, a
    /// lowercase UUID v4 the host makes fresh for every call, and its
    /// result carries the same id and echoes the call's `after`. Both are
    /// required; a bad id is refused like any bad field.
    #[test]
    fn a_sync_and_its_result_carry_the_calls_id() {
        let call = sync().to_json().unwrap();
        assert_eq!(call["request_id"], REQUEST);
        let page = sync_result(1).to_json().unwrap();
        assert_eq!(page["request_id"], REQUEST);
        assert_eq!(page["after"], 41);
        for (op, message) in [("control_sync", &call), ("control_sync_result", &page)] {
            assert_eq!(
                read(op, &without(message, "", "request_id")),
                Err(RelayError::Malformed("request_id")),
                "{op} without request_id"
            );
            for bad in [
                json!(null),
                json!(7),
                json!(""),
                json!("not-a-uuid"),
                json!(REQUEST.to_uppercase()),
                // Version 5, the version nibble.
                json!("5d0e9a3c-2b1f-5c8d-9e7a-6b5c4d3e2f10"),
                // Not RFC 4122's variant.
                json!("5d0e9a3c-2b1f-4c8d-1e7a-6b5c4d3e2f10"),
                json!(format!("{{{REQUEST}}}")),
                json!(format!(" {REQUEST}")),
            ] {
                assert_eq!(
                    read(op, &with(message, "/request_id", bad.clone())),
                    Err(RelayError::Malformed("request_id")),
                    "{op} {bad}"
                );
            }
        }
        // The result's echoed `after` is required, a safe whole number.
        assert_eq!(
            read("control_sync_result", &without(&page, "", "after")),
            Err(RelayError::Malformed("after"))
        );
        for bad in [json!(null), json!("41"), json!(-1)] {
            assert_eq!(
                read("control_sync_result", &with(&page, "/after", bad.clone())),
                Err(RelayError::Malformed("after")),
                "{bad}"
            );
        }
        // The builders check what the readers check.
        let mut upper = sync();
        upper.request_id = REQUEST.to_uppercase();
        assert_eq!(upper.to_json(), Err(RelayError::Malformed("request_id")));
        let mut v5 = sync_result(0);
        v5.request_id = "5d0e9a3c-2b1f-5c8d-9e7a-6b5c4d3e2f10".into();
        assert_eq!(v5.to_json(), Err(RelayError::Malformed("request_id")));
        let mut unsafe_after = sync_result(0);
        unsafe_after.after = crate::canonical::MAX_SAFE_INTEGER + 1;
        unsafe_after.head = unsafe_after.after;
        assert_eq!(unsafe_after.to_json(), Err(RelayError::Malformed("after")));
    }

    /// A page holds the records strictly after its echoed `after`,
    /// ascending and none above `head`; gaps stay legal. A page whose
    /// `head` is below its `after` (the feed went back on the same id: the
    /// host rescans) holds no record: any record would be above its head.
    #[test]
    fn a_page_holds_only_records_after_its_after() {
        let page = |after: u64, head: u64, seqs: &[u64]| {
            let mut m = sync_result(0).to_json().unwrap();
            m["after"] = json!(after);
            m["head"] = json!(head);
            m["records"] = Value::Array(
                seqs.iter()
                    .map(|s| json!({"feed_seq": s, "record": 0}))
                    .collect(),
            );
            bytes(&m)
        };
        let decode = |b: Vec<u8>| ControlSyncResult::decode(&b).map(drop);
        assert_eq!(decode(page(41, 50, &[42, 45, 50])), Ok(()), "gaps legal");
        assert_eq!(decode(page(0, 3, &[1, 2, 3])), Ok(()), "from the start");
        assert_eq!(decode(page(41, 41, &[])), Ok(()), "nothing new");
        // A record at or below `after`: this page answers another call, or
        // none.
        for seqs in [&[41][..], &[40], &[40, 42], &[1, 42], &[42, 41]] {
            assert_eq!(
                decode(page(41, 50, seqs)),
                Err(RelayError::Malformed("feed_seq")),
                "{seqs:?}"
            );
        }
        // `head` below `after`: legal only with no records.
        assert_eq!(decode(page(41, 7, &[])), Ok(()));
        assert_eq!(decode(page(41, 0, &[])), Ok(()));
        for seqs in [&[8][..], &[7], &[42]] {
            assert_eq!(
                decode(page(41, 7, seqs)),
                Err(RelayError::Malformed("feed_seq")),
                "{seqs:?}"
            );
        }
        // The builder refuses what the reader refuses.
        let mut at_after = sync_result(2); // records 42, 43
        at_after.after = 42;
        assert_eq!(at_after.to_json(), Err(RelayError::Malformed("feed_seq")));
        let mut back = sync_result(0);
        back.head = 7;
        assert!(back.to_json().is_ok());
        let mut back_with_records = sync_result(1);
        back_with_records.head = 7;
        assert_eq!(
            back_with_records.to_json(),
            Err(RelayError::Malformed("feed_seq"))
        );
    }

    /// The one helper the host and Astation's `:8080` proxy share to tell
    /// whether a page answers a call: the same `request_id`, origin, feed
    /// (when the call names one) and `after`. The link generation, account
    /// and genesis captured with the call are the caller's to compare.
    #[test]
    fn a_page_answers_only_its_own_call() {
        let call = sync();
        let page = sync_result(2);
        assert_eq!(page.answers(&call), Ok(()));
        let other = |edit: &dyn Fn(&mut ControlSyncResult)| {
            let mut p = sync_result(0);
            edit(&mut p);
            p.answers(&call)
        };
        assert_eq!(
            other(&|p| p.request_id = REQUEST_2.into()),
            Err(SyncMismatch::RequestId)
        );
        assert_eq!(
            other(&|p| p.origin = "https://station.agora.build".into()),
            Err(SyncMismatch::Origin)
        );
        assert_eq!(
            other(&|p| p.feed_id = FEED_2.into()),
            Err(SyncMismatch::FeedId)
        );
        assert_eq!(other(&|p| p.after = 40), Err(SyncMismatch::After));
        assert_eq!(other(&|p| p.after = 0), Err(SyncMismatch::After));
        // The id is compared first: a page that differs in more names it.
        assert_eq!(
            other(&|p| {
                p.request_id = REQUEST_2.into();
                p.after = 0;
            }),
            Err(SyncMismatch::RequestId)
        );
        // Neither the head, the clock nor the records decide.
        assert_eq!(
            other(&|p| {
                p.head = 3;
                p.station_time = 0;
            }),
            Ok(())
        );

        // Discovery: a call that names no feed (from 0) is answered on the
        // feed the page names, the account's current one.
        let discovery = ControlSync {
            request_id: REQUEST.into(),
            origin: ORIGIN.into(),
            feed_id: None,
            after: 0,
        };
        let mut found = sync_result(0);
        found.after = 0;
        found.feed_id = FEED_2.into();
        assert_eq!(found.answers(&discovery), Ok(()));
        assert_eq!(page.answers(&discovery), Err(SyncMismatch::After));

        // Two calls at the same cursor (a timeout's retry, a new link
        // generation's call) differ only by their ids: a page answers the
        // one it names, so a late reply to a retired call is no answer to
        // the live one.
        let retired = sync();
        let live = ControlSync {
            request_id: REQUEST_2.into(),
            ..sync()
        };
        let late = sync_result(1);
        assert_eq!(late.answers(&retired), Ok(()));
        assert_eq!(late.answers(&live), Err(SyncMismatch::RequestId));
        let fresh = ControlSyncResult {
            request_id: REQUEST_2.into(),
            ..sync_result(1)
        };
        assert_eq!(fresh.answers(&live), Ok(()));
        assert_eq!(fresh.answers(&retired), Err(SyncMismatch::RequestId));

        // Each mismatch's name, as the goldens write it.
        for (m, code) in [
            (SyncMismatch::RequestId, "request_id"),
            (SyncMismatch::Origin, "origin"),
            (SyncMismatch::FeedId, "feed_id"),
            (SyncMismatch::After, "after"),
        ] {
            assert_eq!(m.code(), code);
            assert_eq!(SyncMismatch::from_code(code), Some(m));
        }
        assert_eq!(SyncMismatch::from_code("answers"), None);
    }

    #[test]
    fn heads_without_mailbox_until_stage_3() {
        // Stage 3 adds `mailbox:{mailbox_id, head}` for host senders (II.5).
        // Until then a `heads` that carries one is refused, and the builder
        // never writes one.
        let message = heads().to_json().unwrap();
        assert!(message.get("mailbox").is_none());
        let mut keys: Vec<&str> = message
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        keys.sort_unstable();
        assert_eq!(keys, ["feeds", "membership", "op", "type"]);
        for mailbox in [
            json!({"mailbox_id": FEED, "head": 3}),
            json!({"seq": 1, "hash": "00".repeat(32)}),
            json!(null),
            json!({}),
        ] {
            let mut with_mailbox = message.clone();
            with_mailbox["mailbox"] = mailbox.clone();
            assert_eq!(
                Heads::decode(&bytes(&with_mailbox)),
                Err(RelayError::UnknownField),
                "{mailbox}"
            );
            assert_eq!(
                ToHost::decode(&bytes(&with_mailbox)),
                Err(RelayError::UnknownField)
            );
        }
        // The device-list head is required, and exactly `{seq, hash}`.
        assert!(is_malformed(read(
            "heads",
            &without(&message, "", "membership")
        )));
        assert!(is_malformed(read(
            "heads",
            &without(&message, "/membership", "hash")
        )));
        assert!(is_malformed(read(
            "heads",
            &with(&message, "/membership/seq", json!(0))
        )));
        // A feed is announced once.
        let mut twice = heads();
        twice.feeds[1] = twice.feeds[0].clone();
        assert!(twice.to_json().is_err());
        let mut wire = message.clone();
        wire["feeds"][1] = wire["feeds"][0].clone();
        assert!(is_malformed(read("heads", &bytes(&wire))));
    }

    // ------------------------------------------------ acknowledgments

    #[test]
    fn ack_result_forms_exclusive() {
        let message = ack(vec![record_ack(1), entry_ack()]).to_json().unwrap();
        let record = message["results"][0].clone();
        let entry = message["results"][1].clone();
        // An ack with one result, replaced by `value`.
        let alone = ack(vec![record_ack(2)]).to_json().unwrap();
        let with_result = |value: Value| with(&alone, "/results/0", value);

        // Each form, alone, reads.
        assert!(ControlAck::decode(&with_result(record.clone())).is_ok());
        assert!(ControlAck::decode(&with_result(entry.clone())).is_ok());

        // A record's result: exactly `record_id` and `effects`.
        let mut both = record.clone();
        both["entry"] = entry["entry"].clone();
        assert!(is_malformed(read("control_ack", &with_result(both))));
        let mut both = record.clone();
        both["entry"] = entry["entry"].clone();
        both["applied_seq"] = entry["applied_seq"].clone();
        assert!(is_malformed(read("control_ack", &with_result(both))));
        let mut applied = record.clone();
        applied["applied_seq"] = json!(21);
        assert_eq!(
            read("control_ack", &with_result(applied)),
            Err(RelayError::UnknownField)
        );
        // An entry's: exactly `entry`, `applied_seq` and `effects`.
        let mut named = entry.clone();
        named["record_id"] = record["record_id"].clone();
        assert!(is_malformed(read("control_ack", &with_result(named))));
        let mut without_applied = entry.clone();
        without_applied
            .as_object_mut()
            .unwrap()
            .remove("applied_seq");
        assert!(is_malformed(read(
            "control_ack",
            &with_result(without_applied)
        )));
        let mut without_entry = entry.clone();
        without_entry.as_object_mut().unwrap().remove("entry");
        assert!(is_malformed(read(
            "control_ack",
            &with_result(without_entry)
        )));
        let mut unknown = entry.clone();
        unknown["extra"] = json!(1);
        assert_eq!(
            read("control_ack", &with_result(unknown)),
            Err(RelayError::UnknownField)
        );
        // Neither, or no effects, or no object.
        for bad in [
            json!({}),
            json!({"effects": record["effects"]}),
            json!({"applied_seq": 21, "effects": record["effects"]}),
            json!({"record_id": record["record_id"]}),
            json!({"record_id": record["record_id"], "effects": []}),
            json!({"entry": entry["entry"], "applied_seq": 21}),
            json!({"entry": entry["entry"], "applied_seq": 21, "effects": []}),
            json!(7),
            json!(null),
        ] {
            assert!(
                is_malformed(read("control_ack", &with_result(bad.clone()))),
                "{bad}"
            );
        }

        // A record's result names a UUID v4 record; an entry's a `seq` of
        // at least 1 and a hash.
        for (pointer, value) in [
            ("/results/0/record_id", json!("nope")),
            ("/results/1/entry/seq", json!(0)),
            ("/results/1/entry/entry_hash", json!("44".repeat(31))),
            ("/results/1/entry/entry_hash", json!("AB".repeat(32))),
        ] {
            assert!(
                is_malformed(read("control_ack", &with(&message, pointer, value))),
                "{pointer}"
            );
        }
        // One result per record, and per entry.
        let mut dup = message.clone();
        dup["results"][1] = dup["results"][0].clone();
        assert!(is_malformed(read("control_ack", &bytes(&dup))));
        assert!(ack(vec![record_ack(1), record_ack(1)]).to_json().is_err());
        assert!(ack(vec![entry_ack(), entry_ack()]).to_json().is_err());
        // A record's and an entry's results are kept apart.
        assert!(
            ack(vec![record_ack(1), record_ack(2), entry_ack()])
                .to_json()
                .is_ok()
        );
    }

    #[test]
    fn ack_effects_are_those_a_record_carries() {
        // Results are per effect (I.5.8): the effects a record can carry,
        // each once, in the order a record's effects are listed.
        let ok = |effects: Vec<EffectResult>| {
            ack(vec![AckResult::Record {
                record_id: record_id(1),
                effects,
            }])
            .to_json()
            .is_ok()
        };
        use ApplicationResult::*;
        use EffectKind::*;
        assert!(ok(vec![effect(Cover, Applied)]));
        assert!(ok(vec![effect(Revocation, Duplicate)]));
        assert!(ok(vec![
            effect(Revocation, Applied),
            effect(Interrupt, Pending)
        ]));
        assert!(ok(vec![effect(Hold, Refused)]));
        assert!(ok(vec![effect(Release, Pending)]));
        assert!(ok(vec![effect(Interrupt, Applied)]));
        // Never: none, twice, out of order, or a pair no record carries.
        assert!(!ok(Vec::new()));
        assert!(!ok(vec![effect(Hold, Applied), effect(Hold, Applied)]));
        assert!(!ok(vec![
            effect(Interrupt, Applied),
            effect(Revocation, Applied)
        ]));
        assert!(!ok(vec![effect(Hold, Applied), effect(Release, Applied)]));
        assert!(!ok(vec![
            effect(Cover, Applied),
            effect(Revocation, Applied)
        ]));
        // The wire words are the control module's: nothing else reads.
        let message = ack(vec![record_ack(1)]).to_json().unwrap();
        for (pointer, word) in [
            ("/results/0/effects/0/effect", "revoke"),
            ("/results/0/effects/0/effect", "Revocation"),
            ("/results/0/effects/0/result", "done"),
            ("/results/0/effects/0/result", "Applied"),
        ] {
            assert!(
                is_malformed(read("control_ack", &with(&message, pointer, json!(word)))),
                "{word}"
            );
        }
        let wire = message["results"][0]["effects"].clone();
        assert_eq!(
            wire,
            json!([{"effect": "revocation", "result": "duplicate"},
                   {"effect": "interrupt", "result": "applied"}])
        );
        // A host sender's revoke entry has a revocation, and an interrupt
        // only beside it.
        let entry_ok = |effects: Vec<EffectResult>| {
            ack(vec![AckResult::Entry {
                entry: EntryRef {
                    seq: 20,
                    entry_hash: hash(0x44),
                },
                applied_seq: 20,
                effects,
            }])
            .to_json()
            .is_ok()
        };
        assert!(entry_ok(vec![effect(Revocation, Applied)]));
        assert!(entry_ok(vec![
            effect(Revocation, Applied),
            effect(Interrupt, Applied)
        ]));
        assert!(!entry_ok(vec![effect(Interrupt, Applied)]));
        assert!(!entry_ok(vec![effect(Hold, Applied)]));
        assert!(!entry_ok(vec![effect(Cover, Applied)]));
    }

    #[test]
    fn a_revoke_is_reported_applied_only_once_host_work_reached_it() {
        // I.5.8, II.3.1: the result names the entry and host-work's applied
        // `seq`, not the downloaded head. `applied` and `duplicate` say the
        // effects are durable, so the applied `seq` has reached the entry's.
        use ApplicationResult::*;
        use EffectKind::*;
        let entry = |applied_seq: u64, result| {
            ack(vec![AckResult::Entry {
                entry: EntryRef {
                    seq: 20,
                    entry_hash: hash(0x44),
                },
                applied_seq,
                effects: vec![effect(Revocation, result)],
            }])
            .to_json()
        };
        assert!(entry(20, Applied).is_ok());
        assert!(entry(25, Duplicate).is_ok());
        assert_eq!(
            entry(19, Applied),
            Err(RelayError::Malformed("applied_seq"))
        );
        assert_eq!(
            entry(0, Duplicate),
            Err(RelayError::Malformed("applied_seq"))
        );
        // Not yet in force: behind is exactly what pending says.
        assert!(entry(19, Pending).is_ok());
        assert!(entry(0, Pending).is_ok());
        assert!(entry(19, Refused).is_ok());
        // The reader says the same.
        let wire = entry(20, Applied).unwrap();
        let behind = with(&wire, "/results/0/applied_seq", json!(19));
        assert!(is_malformed(read("control_ack", &behind)));
        // One effect applied is enough to need it.
        let mixed = ack(vec![AckResult::Entry {
            entry: EntryRef {
                seq: 20,
                entry_hash: hash(0x44),
            },
            applied_seq: 19,
            effects: vec![effect(Revocation, Pending), effect(Interrupt, Applied)],
        }]);
        assert!(mixed.to_json().is_err());
    }

    // ------------------------------------------------- device-list fetch

    #[test]
    fn a_fetch_carries_signed_objects_as_a_carriage() {
        // `membership_fetch_result{head, entries}` is R9.3's carriage: the
        // entries are signed objects, carried as they are; whether they
        // extend the host's list is the host's, as for any carrier.
        let wire = fetch_result(2).to_json().unwrap();
        assert_eq!(wire["entries"][0], entry_object(1, "").to_json());
        for bad in [
            json!(7),
            json!({}),
            json!({"body": {}}),
            json!({"body": {"type": "nope", "v": 1}, "sig": "AA"}),
            json!([]),
        ] {
            let mut m = wire.clone();
            m["entries"][1] = bad.clone();
            assert!(
                is_malformed(read("membership_fetch_result", &bytes(&m))),
                "{bad}"
            );
        }
        // An entry with a null is not a signed object (R9.1).
        let mut m = wire.clone();
        m["entries"][1]["body"]["x"] = Value::Null;
        assert!(is_malformed(read("membership_fetch_result", &bytes(&m))));
        // `after`: the head the host holds; zero is allowed.
        assert!(
            MembershipFetch::decode(&bytes(&MembershipFetch { after: 0 }.to_json().unwrap()))
                .is_ok()
        );
        assert!(is_malformed(MembershipFetch::decode(&with(
            &MembershipFetch { after: 1 }.to_json().unwrap(),
            "/after",
            json!("1")
        ))));
    }

    // ----------------------------------------------------------- refusals

    fn refusal_of(call: RefusedCall) -> ToHost {
        match call {
            RefusedCall::ControlSync => ToHost::ControlSyncRefused(RefusalCode::Forbidden),
            RefusedCall::MembershipFetch => ToHost::MembershipFetchRefused(RefusalCode::Forbidden),
            RefusedCall::ControlAck => ToHost::ControlAckRefused(RefusalCode::Forbidden),
        }
    }

    const REFUSALS: [(RefusedCall, &str); 3] = [
        (RefusedCall::ControlSync, "control_sync_refused"),
        (RefusedCall::MembershipFetch, "membership_fetch_refused"),
        (RefusedCall::ControlAck, "control_ack_refused"),
    ];

    /// The three refusals (agreed with Astation, 2026-11-11): exactly
    /// `{"type":"relay","op":"<call>_refused","code":"forbidden"}`, read
    /// back as the host's typed refusal, never a page or an ack.
    #[test]
    fn the_three_refusals_round_trip_exactly() {
        for (call, op) in REFUSALS {
            let refused = CallRefused {
                call,
                code: RefusalCode::Forbidden,
            };
            let wire = refused.to_json().unwrap();
            assert_eq!(
                wire,
                json!({"type": "relay", "op": op, "code": "forbidden"})
            );
            // Nothing but its op and code: no account, feed, host, cursor,
            // principal, integration or record.
            assert_eq!(wire.as_object().unwrap().len(), 3);
            let bytes = wire.to_string();
            assert_eq!(CallRefused::decode(bytes.as_bytes()).unwrap(), refused);
            assert_eq!(ToHost::decode(bytes.as_bytes()).unwrap(), refusal_of(call));
            // A host's reader takes it; a Station's never does.
            assert_eq!(
                ToStation::decode(bytes.as_bytes()).unwrap_err(),
                RelayError::WrongMessage
            );
            assert_eq!(call.op(), op);
            assert_eq!(
                RefusalCode::from_code("forbidden"),
                Some(RefusalCode::Forbidden)
            );
        }
        // Another relay message is not a refusal.
        let page = json!({"type": "relay", "op": "heads", "feeds": [],
            "membership": {"seq": 1, "hash": "00".repeat(32)}});
        assert_eq!(
            CallRefused::decode(page.to_string().as_bytes()).unwrap_err(),
            RelayError::WrongMessage
        );
    }

    #[test]
    fn refusals_are_read_strictly() {
        for (_, op) in REFUSALS {
            let ok = format!(r#"{{"type":"relay","op":"{op}","code":"forbidden"}}"#);
            assert!(ToHost::decode(ok.as_bytes()).is_ok());
            let cases = [
                // Unknown codes, spelt otherwise or of another type.
                (
                    r#""code":"not_found""#.to_owned(),
                    RelayError::Malformed("code"),
                ),
                (
                    r#""code":"Forbidden""#.to_owned(),
                    RelayError::Malformed("code"),
                ),
                (r#""code":1"#.to_owned(), RelayError::Malformed("code")),
                (r#""code":null"#.to_owned(), RelayError::Malformed("code")),
                // No code.
                (r#""x":"forbidden""#.to_owned(), RelayError::UnknownField),
                // A field beside the code: nothing is ever named.
                (
                    r#""code":"forbidden","feed_id":"6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b""#
                        .to_owned(),
                    RelayError::UnknownField,
                ),
                (
                    r#""code":"forbidden","account_id":"acct-test-1""#.to_owned(),
                    RelayError::UnknownField,
                ),
                (
                    r#""code":"forbidden","detail":null"#.to_owned(),
                    RelayError::UnknownField,
                ),
                // No request id and no cursor: a refusal names a call kind,
                // never a request (correlation leaves it unchanged).
                (
                    format!(r#""code":"forbidden","request_id":"{REQUEST}""#),
                    RelayError::UnknownField,
                ),
                (
                    r#""code":"forbidden","after":41"#.to_owned(),
                    RelayError::UnknownField,
                ),
                // A duplicate key: the parse refuses the message whole.
                (
                    r#""code":"forbidden","code":"forbidden""#.to_owned(),
                    RelayError::NotStrict,
                ),
            ];
            for (fields, want) in cases {
                let bytes = format!(r#"{{"type":"relay","op":"{op}",{fields}}}"#);
                assert_eq!(
                    ToHost::decode(bytes.as_bytes()).unwrap_err(),
                    want,
                    "{bytes}"
                );
                assert_eq!(CallRefused::decode(bytes.as_bytes()).unwrap_err(), want);
            }
            let missing = format!(r#"{{"type":"relay","op":"{op}"}}"#);
            assert_eq!(
                ToHost::decode(missing.as_bytes()).unwrap_err(),
                RelayError::Malformed("code")
            );
        }
        // Bounded like every relay message.
        let big = format!(
            r#"{{"type":"relay","op":"control_ack_refused","code":"forbidden","pad":"{}"}}"#,
            "x".repeat(MAX_RELAY_MESSAGE_BYTES)
        );
        assert_eq!(
            ToHost::decode(big.as_bytes()).unwrap_err(),
            RelayError::TooLarge
        );
    }

    // ------------------------------------------------ typed reasons (O5)

    /// An ack whose effects not in force say why, beside effects in force
    /// that say nothing: a record's and an entry's.
    fn reasoned_ack() -> ControlAck {
        use ApplicationResult::{Applied, Duplicate, Pending, Refused};
        ack(vec![
            AckResult::Record {
                record_id: record_id(1),
                effects: vec![effect_why(EffectKind::Release, Refused, Why::NotAfterHold)],
            },
            AckResult::Record {
                record_id: record_id(2),
                effects: vec![effect_why(
                    EffectKind::Interrupt,
                    Pending,
                    Why::Pending(PendingReason::NotRevoked),
                )],
            },
            AckResult::Record {
                record_id: record_id(3),
                effects: vec![
                    effect(EffectKind::Revocation, Duplicate),
                    effect(EffectKind::Interrupt, Applied),
                ],
            },
            AckResult::Record {
                record_id: record_id(4),
                effects: vec![
                    effect_why(
                        EffectKind::Revocation,
                        Refused,
                        Why::Refused(RefusalReason::RemovedManager),
                    ),
                    effect_why(
                        EffectKind::Interrupt,
                        Refused,
                        Why::Refused(RefusalReason::RemovedManager),
                    ),
                ],
            },
            AckResult::Entry {
                entry: EntryRef {
                    seq: 20,
                    entry_hash: hash(0x44),
                },
                applied_seq: 19,
                effects: vec![effect_why(
                    EffectKind::Revocation,
                    Pending,
                    Why::Pending(PendingReason::RevokeNotApplied),
                )],
            },
        ])
    }

    /// O5 (Astation's review of PR 2, #120 comment 6848326392): each
    /// effect result may carry `why`, a reason of the shared vocabulary,
    /// written exactly where the effect isn't in force. A reason this
    /// reader doesn't know is read as unrecognized, the result unchanged;
    /// absent is no reason.
    #[test]
    fn reasons_ride_beside_the_effects_not_in_force() {
        let sent = reasoned_ack();
        let wire = sent.to_json().unwrap();
        let results = &wire["results"];
        assert_eq!(results[0]["effects"][0]["why"], "not_after_hold");
        assert_eq!(results[1]["effects"][0]["why"], "not_revoked");
        assert_eq!(results[3]["effects"][1]["why"], "removed_manager");
        assert_eq!(results[4]["effects"][0]["why"], "revoke_not_applied");
        for e in results[2]["effects"].as_array().unwrap() {
            assert!(e.get("why").is_none(), "in force: no reason");
        }
        assert_eq!(ControlAck::decode(&bytes(&wire)).unwrap(), sent);

        // A well-formed reason this reader doesn't know: unrecognized, the
        // result and everything else unchanged, written back as it came.
        let later = "a_later_reason";
        let unknown = with(&wire, "/results/0/effects/0/why", json!(later));
        let read = ControlAck::decode(&unknown).unwrap();
        let AckResult::Record { effects, .. } = &read.results[0] else {
            panic!("a record's result")
        };
        assert_eq!(
            effects[0],
            EffectResult {
                effect: EffectKind::Release,
                result: ApplicationResult::Refused,
                why: Some(EffectWhy::Unrecognized(later.into())),
            }
        );
        assert_eq!(read.results[1..], sent.results[1..]);
        assert_eq!(bytes(&read.to_json().unwrap()), unknown);
        // At the bound, and every code of the vocabulary, is well formed.
        let longest = "z".repeat(MAX_WHY_BYTES);
        let at_bound = with(&wire, "/results/0/effects/0/why", json!(longest));
        assert!(ControlAck::decode(&at_bound).is_ok());
        for code in ["order", "not_after_hold", "possible_replay", "list_frozen"] {
            assert_eq!(
                EffectWhy::read(code),
                Some(EffectWhy::Known(Why::from_code(code).unwrap()))
            );
        }
        // Absent: no reason, as every step-3 ack.
        let bare = without(&wire, "/results/0/effects/0", "why");
        let AckResult::Record { effects, .. } = &ControlAck::decode(&bare).unwrap().results[0]
        else {
            panic!("a record's result")
        };
        assert_eq!(effects[0].why, None);
    }

    /// A reason is read strictly: `null`, a non-string, an empty string,
    /// over 64 bytes or outside `[a-z0-9_]` refuses the whole ack, and so
    /// does a reason beside `applied` or `duplicate` (a reason says why an
    /// effect isn't in force). A duplicate key is a strict parse's fault,
    /// as everywhere; an effect field other than `why` is unknown.
    #[test]
    fn a_malformed_reason_refuses_the_whole_ack() {
        let wire = reasoned_ack().to_json().unwrap();
        let at = "/results/0/effects/0/why";
        for bad in [
            json!(null),
            json!(7),
            json!(true),
            json!(["order"]),
            json!(""),
            json!("z".repeat(MAX_WHY_BYTES + 1)),
            json!("Not_after_hold"),
            json!("not after hold"),
            json!("not-after-hold"),
            json!("ordér"),
        ] {
            let r = ControlAck::decode(&with(&wire, at, bad.clone()));
            assert_eq!(r, Err(RelayError::Malformed("why")), "{bad}");
        }
        // Beside an effect in force.
        for (pointer, why) in [
            ("/results/2/effects/0", "order"),
            ("/results/2/effects/1", "a_later_reason"),
        ] {
            let mut changed = wire.clone();
            changed.pointer_mut(pointer).unwrap()["why"] = json!(why);
            assert_eq!(
                ControlAck::decode(&bytes(&changed)),
                Err(RelayError::Malformed("why")),
                "{pointer}"
            );
        }
        // A duplicate key anywhere: not strict JSON.
        let text = String::from_utf8(bytes(&wire)).unwrap();
        let doubled = text.replacen(
            "\"why\":\"not_after_hold\"",
            "\"why\":\"order\",\"why\":\"not_after_hold\"",
            1,
        );
        assert_ne!(doubled, text);
        assert_eq!(
            ControlAck::decode(doubled.as_bytes()),
            Err(RelayError::NotStrict)
        );
        // Another field beside an effect.
        let reason = add(&wire, "/results/0/effects/0", "reason");
        assert_eq!(ControlAck::decode(&reason), Err(RelayError::UnknownField));
    }

    /// The builder checks what the reader checks: a reason only beside an
    /// effect not in force, and only a well-formed one.
    #[test]
    fn the_builder_writes_a_reason_only_where_the_reader_takes_one() {
        let set = |why: EffectWhy, result: ApplicationResult| {
            ack(vec![AckResult::Record {
                record_id: record_id(1),
                effects: vec![EffectResult {
                    effect: EffectKind::Release,
                    result,
                    why: Some(why),
                }],
            }])
            .to_json()
        };
        let known = || EffectWhy::Known(Why::Order);
        for result in [ApplicationResult::Applied, ApplicationResult::Duplicate] {
            assert_eq!(set(known(), result), Err(RelayError::Malformed("why")));
        }
        for result in [ApplicationResult::Pending, ApplicationResult::Refused] {
            assert!(set(known(), result).is_ok());
        }
        let refused = ApplicationResult::Refused;
        for bad in ["", "Order", "a b", &"z".repeat(MAX_WHY_BYTES + 1)] {
            let why = EffectWhy::Unrecognized(bad.into());
            assert_eq!(
                set(why, refused),
                Err(RelayError::Malformed("why")),
                "{bad}"
            );
        }
        assert!(set(EffectWhy::Unrecognized("a_later_reason".into()), refused).is_ok());
    }

    /// The step-3 refusals stay exactly as agreed: an ack carrying reasons
    /// changes nothing about them.
    #[test]
    fn refusals_are_unchanged_by_reasons() {
        for (call, wire) in [
            (
                RefusedCall::ControlSync,
                r#"{"code":"forbidden","op":"control_sync_refused","type":"relay"}"#,
            ),
            (
                RefusedCall::MembershipFetch,
                r#"{"code":"forbidden","op":"membership_fetch_refused","type":"relay"}"#,
            ),
            (
                RefusedCall::ControlAck,
                r#"{"code":"forbidden","op":"control_ack_refused","type":"relay"}"#,
            ),
        ] {
            let refused = CallRefused {
                call,
                code: RefusalCode::Forbidden,
            };
            assert_eq!(refused.to_json().unwrap().to_string(), wire);
        }
    }
}

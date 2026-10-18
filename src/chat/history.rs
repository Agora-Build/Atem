//! r8 chat history (contract appendix §B, §C): conversations as ordered
//! streams, bounded history pages with their `history_end`, lookups by turn
//! or request, `next` continuation tokens, and coverage (truncation and
//! holes). Shared by the runtime (`runtime/host_bridge.rs`) and the fixtures'
//! fake runtime, so the shared fixtures exercise this code.
//!
//! A page is built in one step from the retained history (the snapshot) and
//! its envelopes take consecutive sequences of its conversation: no live
//! event of that conversation comes between them, and every later one has a
//! higher sequence.

use super::adapter::Part;
use super::session::{ChatMessage, ChatSession, Hole, Role, Status};
use super::wire::{self as chat_wire, ChatEnvelope, CloseReason, PageInfo};
use crate::session_protocol::host::TurnReplies;
use crate::session_protocol::wire::{self, AlwaysRule, Coverage};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::Sha256;
use std::collections::{HashMap, VecDeque};
use std::time::Instant;

/// Page bounds (every page, lookups included): messages, content bytes as
/// `ChatMessage::bytes` counts them, and serialized bytes (the sum of the
/// page's envelopes, its `history_end` included).
pub const PAGE_MESSAGES: usize = 50;
pub const PAGE_CONTENT_BYTES: usize = 256 * 1024;
pub const PAGE_WIRE_BYTES: usize = 1024 * 1024;
/// History requests a second per conversation (then `busy`).
pub const HISTORY_PER_SECOND: usize = 8;
/// Open conversations per session: a ninth closes the oldest (`evicted`).
pub const MAX_CONVERSATIONS: usize = 8;
const MAX_NEXT_BYTES: usize = 512;
const MAX_PAGE_ID_BYTES: usize = 64;

pub const INVALID_TEXT: &str = "invalid history request";
pub const STALE_TEXT: &str = "the history selection is no longer valid; start a new one";
pub const BUSY_TEXT: &str = "too many history requests; try again";

type HmacSha256 = Hmac<Sha256>;

/// The key `next` tokens are made under: random for each runtime run and
/// never stored, so a token from another run is stale.
pub struct HistoryKey([u8; 32]);

impl HistoryKey {
    pub fn random() -> Self {
        use rand::RngCore;
        let mut k = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut k);
        Self(k)
    }
}

impl std::fmt::Debug for HistoryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("HistoryKey(..)")
    }
}

/// What a `next` token is bound to besides its own content: the attachment,
/// the conversation and the full target.
#[derive(Debug, Clone, Copy)]
pub struct Context<'a> {
    pub attachment: &'a str,
    pub conversation: &'a str,
    pub session: &'a str,
    pub process_gen: &'a str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Newest = 0,
    Before = 1,
    Turn = 2,
    Request = 3,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Newest => "newest",
            Kind::Before => "before",
            Kind::Turn => "turn_id",
            Kind::Request => "request_id",
        }
    }

    fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0 => Kind::Newest,
            1 => Kind::Before,
            2 => Kind::Turn,
            3 => Kind::Request,
            _ => return None,
        })
    }

    fn backwards(self) -> bool {
        matches!(self, Kind::Newest | Kind::Before)
    }
}

/// A continuation point: the selection, the position it continues from
/// (backwards: the oldest message sent; forwards: the newest sent), the
/// turn's last position at the first page's snapshot (forwards), and the
/// history snapshot (its reload count).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Cursor {
    kind: Kind,
    at: u64,
    until: u64,
    snapshot: u64,
}

const TOKEN_VERSION: u8 = 1;
const PAYLOAD_LEN: usize = 1 + 1 + 8 + 8 + 8;
const TAG_LEN: usize = 32;

fn tagged(key: &HistoryKey, cx: &Context, payload: &[u8]) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(&key.0).expect("HMAC takes any key length");
    mac.update(b"atem-history-next-v1");
    for field in [cx.attachment, cx.conversation, cx.session, cx.process_gen] {
        mac.update(&(field.len() as u32).to_be_bytes());
        mac.update(field.as_bytes());
    }
    mac.update(payload);
    mac
}

fn make_token(key: &HistoryKey, cx: &Context, c: Cursor) -> String {
    let mut payload = Vec::with_capacity(PAYLOAD_LEN + TAG_LEN);
    payload.push(TOKEN_VERSION);
    payload.push(c.kind as u8);
    payload.extend_from_slice(&c.at.to_be_bytes());
    payload.extend_from_slice(&c.until.to_be_bytes());
    payload.extend_from_slice(&c.snapshot.to_be_bytes());
    let tag = tagged(key, cx, &payload).finalize().into_bytes();
    payload.extend_from_slice(&tag);
    URL_SAFE_NO_PAD.encode(payload)
}

/// The token's cursor if it was made under `key` for exactly `cx` (the tag
/// is compared in constant time); `None` for anything else.
fn open_token(key: &HistoryKey, cx: &Context, token: &str) -> Option<Cursor> {
    let raw = URL_SAFE_NO_PAD.decode(token).ok()?;
    if raw.len() != PAYLOAD_LEN + TAG_LEN {
        return None;
    }
    let (payload, tag) = raw.split_at(PAYLOAD_LEN);
    tagged(key, cx, payload).verify_slice(tag).ok()?;
    if payload[0] != TOKEN_VERSION {
        return None;
    }
    let u = |i: usize| u64::from_be_bytes(payload[i..i + 8].try_into().unwrap());
    Some(Cursor {
        kind: Kind::from_byte(payload[1])?,
        at: u(2),
        until: u(10),
        snapshot: u(18),
    })
}

/// A history request's selection (exactly one selector, §B).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Select {
    /// The open's page (no selector).
    Newest,
    Before(String),
    Turn(String),
    Request(String),
    Next(String),
}

/// A `history` request whose fields passed §B's rules.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HistoryRequest {
    pub page_id: String,
    pub generation: String,
    pub select: Select,
}

/// `page_id`: 1–64 bytes of `[A-Za-z0-9._:-]`, chosen by the client.
pub fn valid_page_id(s: &str) -> bool {
    s.len() <= MAX_PAGE_ID_BYTES && wire::is_opaque_id(s)
}

fn is_base64url(s: &str) -> bool {
    (1..=MAX_NEXT_BYTES).contains(&s.len())
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

/// The fields of a chat-v1 `history` (§B). `Err` carries the request's
/// `page_id` when that was valid: the request is `invalid_request`.
pub fn parse_request(data: &Value) -> Result<HistoryRequest, Option<String>> {
    let page_id = data
        .get("page_id")
        .and_then(Value::as_str)
        .filter(|p| valid_page_id(p))
        .map(str::to_string);
    let invalid = || page_id.clone();
    let page = page_id.clone().ok_or_else(invalid)?;
    let generation = data
        .get("generation")
        .and_then(Value::as_str)
        .ok_or_else(invalid)?
        .to_string();
    let present: Vec<(&str, &Value)> = ["before", "turn_id", "request_id", "next"]
        .iter()
        .filter_map(|k| data.get(*k).map(|v| (*k, v)))
        .collect();
    let [(name, value)] = present.as_slice() else {
        return Err(invalid());
    };
    let value = value.as_str().ok_or_else(invalid)?;
    let ok = match *name {
        "before" | "turn_id" => wire::is_opaque_id(value),
        "request_id" => wire::is_uuid_v4(value),
        _ => is_base64url(value),
    };
    if !ok {
        return Err(invalid());
    }
    let value = value.to_string();
    let select = match *name {
        "before" => Select::Before(value),
        "turn_id" => Select::Turn(value),
        "request_id" => Select::Request(value),
        _ => Select::Next(value),
    };
    Ok(HistoryRequest {
        page_id: page,
        generation,
        select,
    })
}

/// The selection is gone (`stale_target`): a `before` no longer retained,
/// or a `next` out of its context, altered, evicted or from another
/// snapshot or run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stale;

/// A chat-v1 approval card message.
pub fn is_card(m: &ChatMessage) -> bool {
    m.parts.iter().any(|p| matches!(p, Part::Approval(_)))
}

fn coverage_name(c: Coverage) -> &'static str {
    match c {
        Coverage::Complete => "complete",
        Coverage::Partial => "partial",
        Coverage::Unavailable => "unavailable",
    }
}

/// A turn's coverage in the retained history (§C): unavailable when nothing
/// of it is retained; partial when its oldest messages were evicted (the
/// newest evicted message was the turn's: eviction goes oldest first) or a
/// hole touches it; else complete.
pub fn turn_coverage(chat: &ChatSession, turn_id: &str) -> Coverage {
    let turns: HashMap<&str, &str> = chat
        .retained()
        .map(|m| (m.message_id.as_str(), m.turn_id.as_str()))
        .collect();
    if !turns.values().any(|t| *t == turn_id) {
        return Coverage::Unavailable;
    }
    let evicted = chat.truncated() && chat.last_evicted_turn() == Some(turn_id);
    let holed = chat.holes().iter().any(|h| {
        turns.get(h.after.as_str()) == Some(&turn_id)
            || h.before
                .as_deref()
                .is_some_and(|b| turns.get(b) == Some(&turn_id))
    });
    if evicted || holed {
        Coverage::Partial
    } else {
        Coverage::Complete
    }
}

/// A turn's replies in `chat`'s retained history (r8 §D, coverage as §C):
/// its assistant messages (approval cards aside), timeline order. Partial
/// also when an id can't be named or its user message isn't retained.
pub fn turn_replies(chat: &ChatSession, turn_id: &str, user_message_id: &str) -> TurnReplies {
    let mut ids = Vec::new();
    let mut user = false;
    let mut unnamed = false;
    for m in chat.retained().filter(|m| m.turn_id == turn_id) {
        if m.message_id == user_message_id {
            user = true;
        }
        if m.role != Role::Assistant || is_card(m) {
            continue;
        }
        if wire::is_opaque_id(&m.message_id) {
            ids.push(m.message_id.clone());
        } else {
            unnamed = true;
        }
    }
    let coverage = match turn_coverage(chat, turn_id) {
        Coverage::Complete if unnamed || !user => Coverage::Partial,
        c => c,
    };
    TurnReplies { ids, coverage }
}

/// The holes as an attachment sees them (r8 §C): with `control` as they
/// are; for a view-only one, which never sees approval cards, named by
/// their nearest visible neighbours (holes that name the same neighbours
/// are one, its count unknown). A hole with no visible message before it
/// is older than anything it sees: it is left out and counts as
/// truncation (`visible_truncated`).
pub fn visible_holes(chat: &ChatSession, control: bool) -> Vec<Hole> {
    visible_view(chat, control).0
}

/// Whether this attachment's history is truncated: anything evicted, or
/// (view-only) a hole left out because no visible message precedes it.
pub fn visible_truncated(chat: &ChatSession, control: bool) -> bool {
    visible_view(chat, control).1
}

fn visible_view(chat: &ChatSession, control: bool) -> (Vec<Hole>, bool) {
    if control {
        return (chat.holes().to_vec(), chat.truncated());
    }
    let mut dropped = false;
    let msgs: Vec<&ChatMessage> = chat.retained().collect();
    let index = |id: &str| msgs.iter().position(|m| m.message_id == id);
    let mut out: Vec<Hole> = Vec::new();
    for h in chat.holes() {
        let Some(a) = index(&h.after) else {
            dropped = true;
            continue;
        };
        let Some(after) = (0..=a).rev().find(|i| !is_card(msgs[*i])) else {
            dropped = true;
            continue;
        };
        let before = h
            .before
            .as_deref()
            .and_then(index)
            .and_then(|b| (b..msgs.len()).find(|i| !is_card(msgs[*i])))
            .map(|i| msgs[i].message_id.clone());
        let hole = Hole {
            after: msgs[after].message_id.clone(),
            before,
            count: h.count,
        };
        match out
            .iter_mut()
            .find(|o| o.after == hole.after && o.before == hole.before)
        {
            Some(same) => same.count = None,
            None => out.push(hole),
        }
    }
    (out, chat.truncated() || dropped)
}

/// The oldest retained message an attachment sees (cards aside for a
/// view-only one).
pub fn visible_oldest(chat: &ChatSession, control: bool) -> Option<String> {
    chat.retained()
        .find(|m| control || !is_card(m))
        .map(|m| m.message_id.clone())
}

/// Coverage as a `coverage` event tells this attachment (see
/// `visible_holes`).
pub fn coverage_for(chat: &ChatSession, control: bool) -> super::session::CoverageState {
    super::session::CoverageState {
        oldest_retained: visible_oldest(chat, control),
        truncated: visible_truncated(chat, control),
        holes: visible_holes(chat, control),
    }
}

/// The 16 holes that serialize largest (any page lists at most 16).
fn largest_holes(holes: &[Hole]) -> Vec<Hole> {
    let size = |h: &Hole| {
        let escaped = |s: &str| serde_json::to_string(s).map_or(0, |j| j.len());
        escaped(&h.after) + h.before.as_deref().map_or(4, escaped)
    };
    let mut sorted = holes.to_vec();
    sorted.sort_by_key(|h| std::cmp::Reverse(size(h)));
    sorted.truncate(chat_wire::MAX_HOLES);
    // A count is at most 20 digits.
    for h in &mut sorted {
        h.count = Some(u64::MAX);
    }
    sorted
}

/// Serialized size of an envelope as it travels (`{"type":"agentChat",
/// "data":…}`).
pub fn wire_size(env: &ChatEnvelope) -> usize {
    #[derive(serde::Serialize)]
    struct Wire<'a> {
        #[serde(rename = "type")]
        ty: &'static str,
        data: &'a ChatEnvelope,
    }
    serde_json::to_vec(&Wire {
        ty: "agentChat",
        data: env,
    })
    .map_or(0, |v| v.len())
}

/// Who a page is for.
#[derive(Debug, Clone, Copy)]
pub struct PageFor<'a> {
    pub cx: Context<'a>,
    /// The history request's `page_id` (`None` for the open's page).
    pub page_id: Option<&'a str>,
    /// The attachment has `control`: approval cards are in its pages (they
    /// don't count for a view-only one).
    pub control: bool,
}

enum Plan {
    Back {
        kind: Kind,
        end: usize,
    },
    Fwd {
        kind: Kind,
        turn: String,
        start: usize,
        until: usize,
    },
    Empty {
        kind: Kind,
    },
}

/// The page `select` names, as sequenced envelopes from `first_seq`: its
/// messages (oldest first) then its `history_end`.
pub fn page(
    chat: &ChatSession,
    key: &HistoryKey,
    to: &PageFor,
    select: Select,
    first_seq: u64,
) -> Result<Vec<ChatEnvelope>, Stale> {
    let msgs: Vec<&ChatMessage> = chat.retained().collect();
    let base = chat.first_pos();
    let keep = |m: &ChatMessage| to.control || !is_card(m);
    let turn_plan = |kind: Kind, turn: &str| {
        let first = msgs.iter().position(|m| m.turn_id == turn);
        let last = msgs.iter().rposition(|m| m.turn_id == turn);
        match (first, last) {
            (Some(start), Some(until)) => Plan::Fwd {
                kind,
                turn: turn.to_string(),
                start,
                until,
            },
            _ => Plan::Empty { kind },
        }
    };
    let plan = match select {
        Select::Newest => Plan::Back {
            kind: Kind::Newest,
            end: msgs.len(),
        },
        Select::Before(id) => {
            // A card id is unknown to a view-only attachment: stale.
            let end = msgs
                .iter()
                .position(|m| m.message_id == id && keep(m))
                .ok_or(Stale)?;
            Plan::Back {
                kind: Kind::Before,
                end,
            }
        }
        Select::Turn(t) => turn_plan(Kind::Turn, &t),
        Select::Request(r) => {
            let user = msgs
                .iter()
                .find(|m| m.role == Role::User && m.request_id.as_deref() == Some(r.as_str()));
            match user {
                Some(u) => turn_plan(Kind::Request, &u.turn_id),
                None => Plan::Empty {
                    kind: Kind::Request,
                },
            }
        }
        Select::Next(token) => {
            let c = open_token(key, &to.cx, &token).ok_or(Stale)?;
            if c.snapshot != chat.reloads() || c.at < base {
                return Err(Stale);
            }
            let at = usize::try_from(c.at - base).map_err(|_| Stale)?;
            if at >= msgs.len() {
                return Err(Stale);
            }
            if c.kind.backwards() {
                // The page continues with the message just older than the
                // cursor (a token means one was retained): evicted, stale.
                if at == 0 {
                    return Err(Stale);
                }
                Plan::Back {
                    kind: c.kind,
                    end: at,
                }
            } else {
                let until = c
                    .until
                    .checked_sub(base)
                    .and_then(|u| usize::try_from(u).ok())
                    .filter(|u| *u < msgs.len() && *u >= at)
                    .ok_or(Stale)?;
                Plan::Fwd {
                    kind: c.kind,
                    turn: msgs[until].turn_id.clone(),
                    start: at + 1,
                    until,
                }
            }
        }
    };
    let generation = chat.generation();
    let (conv, agent) = (to.cx.conversation, to.cx.session);
    let kind = match &plan {
        Plan::Back { kind, .. } | Plan::Fwd { kind, .. } | Plan::Empty { kind } => *kind,
    };
    let candidates: Vec<usize> = match &plan {
        Plan::Back { end, .. } => (0..*end).rev().filter(|i| keep(msgs[*i])).collect(),
        Plan::Fwd {
            turn, start, until, ..
        } => (*start..=*until)
            .filter(|i| msgs[*i].turn_id == *turn && keep(msgs[*i]))
            .collect(),
        Plan::Empty { .. } => Vec::new(),
    };
    // Holes and the oldest message as this attachment sees them.
    let (visible, truncated) = visible_view(chat, to.control);
    let oldest = visible_oldest(chat, to.control);
    // The largest `history_end` this page could have (a token, the 16
    // largest holes, seven-digit numbers): what the serialized bound must
    // leave room for.
    let reserve = {
        let probe = PageInfo {
            selector: kind.name(),
            count: PAGE_MESSAGES,
            content_bytes: 9_999_999,
            wire_bytes: 9_999_999,
            end: false,
            next: Some(make_token(
                key,
                &to.cx,
                Cursor {
                    kind,
                    at: u64::MAX,
                    until: u64::MAX,
                    snapshot: u64::MAX,
                },
            )),
            coverage: "unavailable",
            oldest_retained: oldest.clone(),
            truncated: true,
            holes: largest_holes(&visible),
        };
        wire_size(&chat_wire::history_end(
            conv,
            agent,
            generation,
            u64::MAX,
            to.page_id,
            &probe,
        ))
    };
    // Sizes are measured at the largest sequence the page can reach, so
    // they bound the real ones.
    let probe_seq = first_seq + PAGE_MESSAGES as u64 + 1;
    let mut picked: Vec<usize> = Vec::new();
    let (mut content, mut wire) = (0usize, 0usize);
    let mut exhausted = true;
    for &i in &candidates {
        let m = msgs[i];
        let c = m.bytes();
        let w = wire_size(&chat_wire::history_message(
            conv, agent, generation, probe_seq, m, to.page_id,
        ));
        if !picked.is_empty()
            && (picked.len() >= PAGE_MESSAGES
                || content + c > PAGE_CONTENT_BYTES
                || wire + w + reserve > PAGE_WIRE_BYTES)
        {
            exhausted = false;
            break;
        }
        picked.push(i);
        content += c;
        wire += w;
    }
    let next = (!exhausted).then(|| {
        let cursor = match &plan {
            Plan::Back { .. } => Cursor {
                kind,
                at: base + *picked.last().expect("a page holds a message") as u64,
                until: 0,
                snapshot: chat.reloads(),
            },
            Plan::Fwd { until, .. } => Cursor {
                kind,
                at: base + *picked.last().expect("a page holds a message") as u64,
                until: base + *until as u64,
                snapshot: chat.reloads(),
            },
            Plan::Empty { .. } => unreachable!("an empty selection is exhausted"),
        };
        make_token(key, &to.cx, cursor)
    });
    if matches!(plan, Plan::Back { .. }) {
        picked.reverse();
    }
    let index_of: HashMap<&str, usize> = msgs
        .iter()
        .enumerate()
        .map(|(i, m)| (m.message_id.as_str(), i))
        .collect();
    let coverage = match &plan {
        Plan::Back { end, .. } => {
            let selected = (0..*end).any(|i| keep(msgs[i]));
            let holed = visible.iter().any(|h| match &h.before {
                Some(b) => index_of.get(b.as_str()).is_some_and(|i| i <= end),
                None => *end == msgs.len(),
            });
            match (selected, truncated || holed) {
                (false, true) => Coverage::Unavailable,
                (false, false) => Coverage::Complete,
                (true, true) => Coverage::Partial,
                (true, false) => Coverage::Complete,
            }
        }
        Plan::Fwd { turn, .. } => turn_coverage(chat, turn),
        Plan::Empty { .. } => Coverage::Unavailable,
    };
    let newest = (0..msgs.len()).rev().find(|i| keep(msgs[*i]));
    let holes: Vec<Hole> = visible
        .iter()
        .filter(|h| match &h.before {
            Some(b) => index_of.get(b.as_str()).is_some_and(|i| picked.contains(i)),
            None => newest.is_some_and(|n| picked.contains(&n)),
        })
        .cloned()
        .collect();
    let mut envelopes: Vec<ChatEnvelope> = picked
        .iter()
        .enumerate()
        .map(|(k, &i)| {
            chat_wire::history_message(
                conv,
                agent,
                generation,
                first_seq + k as u64,
                msgs[i],
                to.page_id,
            )
        })
        .collect();
    let messages_wire: usize = envelopes.iter().map(wire_size).sum();
    let mut info = PageInfo {
        selector: kind.name(),
        count: picked.len(),
        content_bytes: content,
        wire_bytes: 0,
        end: exhausted,
        next,
        coverage: coverage_name(coverage),
        oldest_retained: oldest,
        truncated,
        holes,
    };
    let end_seq = first_seq + picked.len() as u64;
    // `wire_bytes` counts the `history_end` itself: settle the number.
    loop {
        let end = chat_wire::history_end(conv, agent, generation, end_seq, to.page_id, &info);
        let total = messages_wire + wire_size(&end);
        if total == info.wire_bytes {
            envelopes.push(end);
            return Ok(envelopes);
        }
        info.wire_bytes = total;
    }
}

/// One open conversation: its attachment and its sequenced stream.
#[derive(Debug)]
pub struct Conversation {
    pub attachment: String,
    /// Sequence of the next envelope.
    pub next: u64,
    pub opened: u64,
    pub last_heartbeat: Instant,
    /// When its last history requests came (ms), for the rate bound.
    history_times: VecDeque<u64>,
}

/// What an `open` shows (besides the history).
#[derive(Debug, Clone, Copy)]
pub struct Opening<'a> {
    pub conversation: &'a str,
    pub agent: &'a str,
    pub attachment: &'a str,
    pub control: bool,
    pub status: &'a Status,
    pub unavailable: &'a [String],
    pub rules: &'a [AlwaysRule],
}

/// A `history` request of an attachment.
#[derive(Debug, Clone, Copy)]
pub struct HistoryCall<'a> {
    pub data: &'a Value,
    pub conversation: &'a str,
    pub agent: &'a str,
    pub attachment: &'a str,
    pub control: bool,
    pub now_ms: u64,
}

/// A session's open conversations.
#[derive(Debug, Default)]
pub struct Conversations {
    pub map: HashMap<String, Conversation>,
    opens: u64,
}

impl Conversations {
    /// `conversation` (re)opens on `attachment`: `close{evicted}` for the
    /// oldest when it is a ninth, then `opened` (sequence 0), the newest
    /// page and its `history_end`.
    pub fn open(&mut self, chat: &ChatSession, key: &HistoryKey, o: &Opening) -> Vec<ChatEnvelope> {
        let mut out = Vec::new();
        if !self.map.contains_key(o.conversation)
            && self.map.len() >= MAX_CONVERSATIONS
            && let Some(oldest) = self
                .map
                .iter()
                .min_by_key(|(_, c)| c.opened)
                .map(|(id, _)| id.clone())
        {
            self.map.remove(&oldest);
            out.push(chat_wire::close(&oldest, o.agent, CloseReason::Evicted));
        }
        out.push(chat_wire::opened(
            o.conversation,
            o.agent,
            chat.generation(),
            o.status,
            o.unavailable,
            o.rules,
        ));
        let to = PageFor {
            cx: Context {
                attachment: o.attachment,
                conversation: o.conversation,
                session: o.agent,
                process_gen: chat.generation(),
            },
            page_id: None,
            control: o.control,
        };
        let page = page(chat, key, &to, Select::Newest, 1).expect("the newest page is never stale");
        let next = 1 + page.len() as u64;
        out.extend(page);
        self.opens += 1;
        self.map.insert(
            o.conversation.to_string(),
            Conversation {
                attachment: o.attachment.to_string(),
                next,
                opened: self.opens,
                last_heartbeat: Instant::now(),
                history_times: VecDeque::new(),
            },
        );
        out
    }

    /// `attachment` closes its `conversation` (another attachment's stays).
    pub fn close(&mut self, conversation: &str, attachment: &str) -> bool {
        let mine = self
            .map
            .get(conversation)
            .is_some_and(|c| c.attachment == attachment);
        mine && self.map.remove(conversation).is_some()
    }

    /// The sequence of the conversation's next envelope (`None`: not open).
    pub fn next_head(&mut self, conversation: &str) -> Option<u64> {
        let c = self.map.get_mut(conversation)?;
        let sequence = c.next;
        c.next += 1;
        Some(sequence)
    }

    /// Answers a `history` (§B): its page, or an error (sequenced when the
    /// conversation is open on this attachment, with the `page_id` when it
    /// was valid). Nothing else is sent and nothing resets.
    pub fn history(
        &mut self,
        chat: &ChatSession,
        key: &HistoryKey,
        h: &HistoryCall,
    ) -> Vec<ChatEnvelope> {
        let generation = chat.generation().to_string();
        let open = self
            .map
            .get(h.conversation)
            .is_some_and(|c| c.attachment == h.attachment);
        let error = |me: &mut Self, code: &str, text: &str, page_id: Option<&str>| {
            let head = if open {
                me.next_head(h.conversation)
            } else {
                None
            };
            vec![chat_wire::error(
                h.conversation,
                h.agent,
                head.map(|s| (generation.as_str(), s)),
                code,
                text,
                page_id,
            )]
        };
        let req = match parse_request(h.data) {
            Ok(req) => req,
            Err(page_id) => {
                return error(self, "invalid_request", INVALID_TEXT, page_id.as_deref());
            }
        };
        if !open || req.generation != chat.generation() {
            return error(self, "stale_target", STALE_TEXT, Some(&req.page_id));
        }
        let c = self.map.get_mut(h.conversation).expect("open");
        while c
            .history_times
            .front()
            .is_some_and(|t| h.now_ms.saturating_sub(*t) >= 1000)
        {
            c.history_times.pop_front();
        }
        if c.history_times.len() >= HISTORY_PER_SECOND {
            return error(self, "busy", BUSY_TEXT, Some(&req.page_id));
        }
        c.history_times.push_back(h.now_ms);
        let to = PageFor {
            cx: Context {
                attachment: h.attachment,
                conversation: h.conversation,
                session: h.agent,
                process_gen: chat.generation(),
            },
            page_id: Some(&req.page_id),
            control: h.control,
        };
        match page(chat, key, &to, req.select, c.next) {
            Ok(envelopes) => {
                c.next += envelopes.len() as u64;
                envelopes
            }
            Err(Stale) => error(self, "stale_target", STALE_TEXT, Some(&req.page_id)),
        }
    }
}

#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;

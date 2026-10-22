//! The host route proof on the host (atem-session-v1.md §R9.7b).
//!
//! On every new host connection the relay sends
//! `{"type":"relay","op":"host_challenge","v":1,"nonce","room"}`, before
//! anything is routed and before Astation (if any) authenticates the link.
//! A host with a pinned device list that can serve (not held, frozen or
//! faulted; its journal not halted; its `host_channel_key` loaded) answers
//! each challenge once with `{"type":"relay","op":"host_route","v":1,
//! "proof":{body, sig}}`, signed at its current head with the `atem_id` the
//! link was opened with and the challenge's room. Anything else gets no
//! answer: a host without a list, or one that can't serve, sends nothing
//! (one runtime.log line, never content), and so does a malformed
//! challenge or one naming another room than the link's. The challenge is
//! never authority for anything else.
//!
//! The answer is made by the link's reader task as the challenge arrives
//! (the connect-time authentication reads nothing else meanwhile), from a
//! [`RouteHandle`] the broker keeps current each pass ([`RouteState`]).
use super::HostKey;
use atem_client::encoding::Hash32;
use atem_client::host_route::{HostChallenge, HostRouteBody, host_route_message, sign_host_route};
use atem_client::membership::Head;
use std::collections::HashSet;
use std::sync::{Arc, Mutex};

/// Challenges answered on one link at most (each once); more are ignored.
pub const MAX_ANSWERS_PER_LINK: usize = 16;
/// runtime.log lines about challenges on one link at most.
const MAX_LINES_PER_LINK: u32 = 8;
/// How long a challenge that arrives while the runtime is still opening its
/// device list waits for it (the link connects while the broker starts).
pub const STARTUP_WAIT: std::time::Duration = std::time::Duration::from_secs(5);

/// What the host signs for (its pinned list's identity at its head).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteIdentity {
    pub account_id: String,
    pub genesis_hash: Hash32,
    pub host_id: String,
    pub head: Head,
}

/// Whether the host answers a challenge now.
#[derive(Clone, Default)]
pub enum RouteState {
    /// The broker hasn't opened its device list yet.
    #[default]
    Starting,
    /// No answer, and why (for the log line).
    Off(&'static str),
    Ready {
        id: RouteIdentity,
        key: Arc<HostKey>,
    },
}


impl RouteState {
    /// The same answer (identity and key) as `other`.
    pub fn same(&self, other: &RouteState) -> bool {
        match (self, other) {
            (RouteState::Starting, RouteState::Starting) => true,
            (RouteState::Off(a), RouteState::Off(b)) => a == b,
            (RouteState::Ready { id: a, key: ka }, RouteState::Ready { id: b, key: kb }) => {
                a == b && Arc::ptr_eq(ka, kb)
            }
            _ => false,
        }
    }
}

/// The broker's current [`RouteState`], shared with the link's reader.
pub type RouteHandle = Arc<Mutex<RouteState>>;

pub fn new_handle() -> RouteHandle {
    Arc::new(Mutex::new(RouteState::default()))
}

/// Sets `handle` to `state` (only when it changed).
pub fn set(handle: &RouteHandle, state: RouteState) {
    let mut current = handle.lock().unwrap_or_else(|e| e.into_inner());
    if !current.same(&state) {
        *current = state;
    }
}

/// One link's challenge state: the room and `atem_id` it was opened with,
/// the nonces answered, the lines written.
pub struct LinkRoute {
    handle: RouteHandle,
    room: String,
    atem_id: String,
    answered: HashSet<[u8; 32]>,
    lines: u32,
}

impl LinkRoute {
    pub fn new(handle: RouteHandle, room: &str, atem_id: &str) -> Self {
        LinkRoute {
            handle,
            room: room.to_owned(),
            atem_id: atem_id.to_owned(),
            answered: HashSet::new(),
            lines: 0,
        }
    }

    fn log(&mut self, line: &str) {
        if self.lines < MAX_LINES_PER_LINK {
            self.lines += 1;
            eprintln!("atem runtime: r9: host_challenge {line}");
        }
    }

    /// The `host_route` answer to `text` (a `{"type":"relay","op":
    /// "host_challenge",…}` message), or `None` (logged).
    pub fn answer(&mut self, text: &str) -> Option<String> {
        let challenge = match HostChallenge::parse(text.as_bytes()) {
            Ok(challenge) => challenge,
            Err(refusal) => {
                self.log(&format!("ignored: {refusal}"));
                return None;
            }
        };
        if challenge.room != self.room {
            self.log("ignored: another room than this link's");
            return None;
        }
        if self.answered.contains(&challenge.nonce) {
            self.log("ignored: already answered");
            return None;
        }
        if self.answered.len() >= MAX_ANSWERS_PER_LINK {
            self.log("ignored: too many challenges on this link");
            return None;
        }
        let state = self
            .handle
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let (id, key) = match state {
            RouteState::Ready { id, key } => (id, key),
            RouteState::Off(why) => {
                self.log(&format!("not answered: {why}"));
                return None;
            }
            RouteState::Starting => {
                self.log("not answered: the device list isn't open yet");
                return None;
            }
        };
        let body = HostRouteBody {
            account_id: id.account_id,
            genesis_hash: id.genesis_hash,
            host_id: id.host_id,
            atem_id: self.atem_id.clone(),
            room: challenge.room,
            nonce: challenge.nonce,
            head: id.head,
        };
        match sign_host_route(&key.keys, &key.id, &body) {
            Ok(proof) => {
                self.answered.insert(challenge.nonce);
                self.log(&format!("answered at head {}", body.head.seq));
                Some(host_route_message(&proof).to_string())
            }
            Err(e) => {
                self.log(&format!("not answered: {}", e.code()));
                None
            }
        }
    }
}

impl LinkRoute {
    /// [`LinkRoute::answer`], once the broker opened its device list (at
    /// most [`STARTUP_WAIT`]): a challenge that arrives while the runtime
    /// starts is answered from the list, not refused for its timing.
    pub async fn answer_when_open(&mut self, text: &str) -> Option<String> {
        let deadline = tokio::time::Instant::now() + STARTUP_WAIT;
        while matches!(
            *self.handle.lock().unwrap_or_else(|e| e.into_inner()),
            RouteState::Starting
        ) && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        self.answer(text)
    }
}

/// Whether `text` is a `host_challenge` relay message (by its `op`; the
/// parse itself is [`LinkRoute::answer`]'s).
pub fn is_host_challenge(text: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .is_some_and(|v| {
            v.get("type").and_then(|t| t.as_str()) == Some("relay")
                && v.get("op").and_then(|o| o.as_str()) == Some("host_challenge")
        })
}
